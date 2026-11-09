// Portions derived from ChainSafe WebZjs.
// Copyright 2024 ChainSafe Systems
// Modified by NoirWallet; see THIRD_PARTY_NOTICES.md for licensing.

use std::cell::RefCell;
use std::num::NonZeroU32;
use std::rc::Rc;
use std::str::FromStr;
use std::time::Duration;

use crate::bindgen::sign::pczt_sign_inner;
use crate::bindgen::{Pczt as WasmPczt, ProofGenerationKey, SeedFingerprint};
use crate::compact_block_source::CompactBlockCdnConfig;
use crate::wallet::{DEFAULT_ZERO_INDEXER_SEND_TIMEOUT, TransferFundingSource};
use crate::{Error, Network, PRUNING_DEPTH, Wallet};

use nonempty::NonEmpty;
use serde::{Deserialize, Serialize};
use tonic_web_wasm_client::Client;
use wasm_bindgen::prelude::*;
use zcash_address::ZcashAddress;
use zcash_client_backend::data_api::wallet::ConfirmationsPolicy;
use zcash_client_backend::fees::StandardFeeRule;
use zcash_client_backend::proto::service::ChainSpec;
use zcash_client_backend::{
    data_api::{InputSource, WalletRead, WalletWrite},
    proto::service::compact_tx_streamer_client::CompactTxStreamerClient,
};
use zcash_client_memory::MemoryWalletDb;
use zcash_primitives::transaction::TxId;

pub type MemoryWallet<T> = Wallet<MemoryWalletDb<Network>, T>;
pub type AccountId = <MemoryWalletDb<Network> as WalletRead>::AccountId;
pub type NoteRef = <MemoryWalletDb<Network> as InputSource>::NoteRef;

fn is_user_facing_shielded_address(
    address: &zcash_keys::address::UnifiedAddress,
    default_address: &zcash_keys::address::UnifiedAddress,
) -> bool {
    let has_shielded_receiver = address.has_orchard() || address.has_sapling();
    has_shielded_receiver && (address == default_address || address.transparent().is_none())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmationsPolicyOptions {
    trusted: NonZeroU32,
    untrusted: NonZeroU32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CompactBlockCdnOptions {
    base_url: String,
    request_timeout_ms: Option<u32>,
    max_chunk_bytes: Option<usize>,
    max_concurrent_chunk_requests: Option<usize>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ZeroIndexerOptions {
    urls: Vec<String>,
    send_timeout_ms: Option<NonZeroU32>,
}

impl TryFrom<CompactBlockCdnOptions> for CompactBlockCdnConfig {
    type Error = Error;

    fn try_from(options: CompactBlockCdnOptions) -> Result<Self, Self::Error> {
        Self::new(
            options.base_url,
            options.request_timeout_ms,
            options.max_chunk_bytes,
            options.max_concurrent_chunk_requests,
        )
        .map_err(|error| Error::Generic(format!("Invalid compact block CDN config: {error}")))
    }
}

impl TryFrom<ConfirmationsPolicyOptions> for ConfirmationsPolicy {
    type Error = Error;

    fn try_from(options: ConfirmationsPolicyOptions) -> Result<Self, Self::Error> {
        Self::new(
            options.trusted,
            options.untrusted,
            Self::default().allow_zero_conf_shielding(),
        )
        .map_err(|error| Error::Generic(format!("Invalid confirmations policy: {error}")))
    }
}

#[wasm_bindgen(typescript_custom_section)]
const CONFIRMATIONS_POLICY_TYPES: &str = r#"
/**
 * Configure confirmation counts for balance and status queries.
 * Input selection uses the smaller count for both trusted and untrusted funds.
 * Shielding retains the default zero-confirmation setting.
 */
export interface ConfirmationsPolicy {
    /** Positive uint32; must not exceed untrusted. */
    trusted: number;
    /** Positive uint32. */
    untrusted: number;
}

export interface CompactBlockCdnOptions {
    /** Root containing {network}/shielded-default/manifest.json. */
    baseUrl: string;
    /** Per-request timeout. Defaults to 30000. */
    requestTimeoutMs?: number;
    /** Maximum decompressed chunk size. Defaults to 128 MiB. */
    maxChunkBytes?: number;
    /** Maximum concurrent CDN chunk requests. Defaults to 4; valid range is 1 through 8. */
    maxConcurrentChunkRequests?: number;
}

/** Runtime Orchard broadcast and transaction lookup endpoints; supply again when restoring wallet bytes. */
export interface ZeroIndexerOptions {
    /** Ordered endpoints for Orchard transaction broadcast and status lookup. */
    urls: string[];
    /** Positive per-endpoint timeout for send and GetTransaction, in milliseconds. Defaults to 30000. */
    sendTimeoutMs?: number;
}
"#;

#[wasm_bindgen(typescript_custom_section)]
const TRANSFER_TYPES: &str = r#"
export type TransferOverallStatus = "success" | "partial" | "unknown" | "failed";
export type TransferSubmissionStatus =
    | "submitted"
    | "rejected"
    | "unknown"
    | "not_attempted";

export interface TransferTransactionResult {
    txId: string;
    status: TransferSubmissionStatus;
    errorCode?: number;
    errorMessage?: string;
}

export interface TransferResult {
    status: TransferOverallStatus;
    txIds: string[];
    finalTxId: string;
    transactions: TransferTransactionResult[];
}

export interface TransferEstimate {
    amountZats: string;
    feeZats: string;
    marginalFeeZats: string;
    transactionCount: number;
    stepFeesZats: string[];
}
"#;

#[wasm_bindgen]
#[derive(Clone)]
pub struct WebWallet {
    inner: MemoryWallet<tonic_web_wasm_client::Client>,
}

impl WebWallet {
    fn parse_zero_indexer_options(value: JsValue) -> Result<(Vec<Client>, Duration), Error> {
        if value.is_null_or_undefined() {
            return Ok((vec![], DEFAULT_ZERO_INDEXER_SEND_TIMEOUT));
        }
        // serde-wasm-bindgen does not reject unknown object keys on its own.
        for key in js_sys::Reflect::own_keys(&value).map_err(Error::Js)? {
            if !matches!(key.as_string().as_deref(), Some("urls" | "sendTimeoutMs")) {
                return Err(Error::Generic(
                    "Zero-indexer options contain an unsupported key".into(),
                ));
            }
        }
        let options: ZeroIndexerOptions = serde_wasm_bindgen::from_value(value)?;
        let mut urls = Vec::with_capacity(options.urls.len());
        for url in options.urls {
            let url = url.trim();
            if url.is_empty() {
                return Err(Error::Generic("Zero-indexer URL must not be empty".into()));
            }
            if !urls.iter().any(|existing| existing == url) {
                urls.push(url.to_string());
            }
        }
        let timeout = options
            .send_timeout_ms
            .map(|value| Duration::from_millis(u64::from(value.get())))
            .unwrap_or(DEFAULT_ZERO_INDEXER_SEND_TIMEOUT);
        Ok((urls.into_iter().map(Client::new).collect(), timeout))
    }

    #[cfg(feature = "voting")]
    #[allow(dead_code)]
    pub(crate) fn shared_inner(&self) -> MemoryWallet<tonic_web_wasm_client::Client> {
        self.inner.clone()
    }

    pub fn client(&self) -> CompactTxStreamerClient<tonic_web_wasm_client::Client> {
        self.inner.client.clone()
    }

    pub fn inner_mut(&mut self) -> &mut MemoryWallet<tonic_web_wasm_client::Client> {
        &mut self.inner
    }

    async fn ensure_spendability_consistent(&self, account_id: AccountId) -> Result<(), Error> {
        let diagnostics = self.inner.spendability_diagnostics(account_id).await?;
        if diagnostics.incomplete_note_count() > 0 {
            Err(Error::SpendabilityMetadataIncomplete {
                account_id: *account_id,
                note_count: diagnostics.incomplete_note_count(),
                value_zats: diagnostics.incomplete_value().into(),
            })
        } else {
            Ok(())
        }
    }

    async fn diagnose_transfer_result<T>(
        &self,
        account_id: AccountId,
        result: Result<T, Error>,
    ) -> Result<T, Error> {
        if matches!(&result, Err(Error::InsufficientTransferFunds(_))) {
            self.ensure_spendability_consistent(account_id).await?;
        }
        result
    }
}

#[wasm_bindgen]
impl WebWallet {
    /// The policy is runtime configuration. Supply it again when restoring db_bytes.
    /// Omitting it or passing null uses ConfirmationsPolicy::default().
    #[wasm_bindgen(constructor)]
    pub fn new(
        network: &str,
        lightwalletd_url: &str,
        #[wasm_bindgen(unchecked_optional_param_type = "Uint8Array | null")] db_bytes: Option<
            Box<[u8]>,
        >,
        #[wasm_bindgen(unchecked_optional_param_type = "ConfirmationsPolicy | null")]
        confirmations_policy: JsValue,
        #[wasm_bindgen(unchecked_optional_param_type = "CompactBlockCdnOptions | null")]
        compact_block_cdn: JsValue,
        #[wasm_bindgen(unchecked_optional_param_type = "ZeroIndexerOptions | null")]
        zero_indexer_options: JsValue,
    ) -> Result<WebWallet, Error> {
        let network = Network::from_str(network)?;
        let confirmations_policy = if confirmations_policy.is_null_or_undefined() {
            ConfirmationsPolicy::default()
        } else {
            // serde-wasm-bindgen's struct deserializer does not visit unknown keys.
            for key in js_sys::Reflect::own_keys(&confirmations_policy).map_err(Error::Js)? {
                if !matches!(key.as_string().as_deref(), Some("trusted" | "untrusted")) {
                    return Err(Error::Generic(
                        "Confirmations policy only accepts trusted and untrusted".into(),
                    ));
                }
            }
            let options: ConfirmationsPolicyOptions =
                serde_wasm_bindgen::from_value(confirmations_policy)?;
            options.try_into()?
        };
        let client = Client::new(lightwalletd_url.to_string());
        let compact_block_cdn = if compact_block_cdn.is_null_or_undefined() {
            None
        } else {
            Some(
                serde_wasm_bindgen::from_value::<CompactBlockCdnOptions>(compact_block_cdn)?
                    .try_into()?,
            )
        };
        let (zero_indexer_clients, zero_indexer_send_timeout) =
            Self::parse_zero_indexer_options(zero_indexer_options)?;

        let db = match db_bytes {
            Some(bytes) => {
                tracing::info!(
                    "Serialized db was provided to constructor. Attempting to deserialize"
                );
                MemoryWalletDb::decode_new(bytes.as_ref(), network, PRUNING_DEPTH)?
            }
            None => MemoryWalletDb::new(network, PRUNING_DEPTH),
        };

        Ok(Self {
            inner: Wallet::new_with_runtime_config(
                db,
                client,
                zero_indexer_clients,
                network,
                confirmations_policy,
                compact_block_cdn,
                zero_indexer_send_timeout,
            )?,
        })
    }

    pub fn set_zero_indexer_options(
        &mut self,
        #[wasm_bindgen(unchecked_param_type = "ZeroIndexerOptions | null")] options: JsValue,
    ) -> Result<(), Error> {
        let (clients, timeout) = Self::parse_zero_indexer_options(options)?;
        self.inner.set_zero_indexer_options(clients, timeout);
        Ok(())
    }

    pub async fn create_account(
        &self,
        account_name: &str,
        seed_phrase: &str,
        account_hd_index: u32,
        birthday_height: Option<u32>,
        passphrase: Option<String>,
    ) -> Result<u32, Error> {
        tracing::info!("Create account called");
        self.inner
            .create_account(
                account_name,
                seed_phrase,
                passphrase.as_deref().unwrap_or(""),
                account_hd_index,
                birthday_height,
                None,
            )
            .await
            .map(|id| *id)
    }

    pub async fn sync(&self) -> Result<(), Error> {
        // Record start time
        let start_time = js_sys::Date::now();

        self.inner.sync().await?;

        // Calculate elapsed time in seconds
        let end_time = js_sys::Date::now();
        let elapsed_seconds = (end_time - start_time) / 1000.0;
        tracing::info!("⏱️ Sync completed in {:.2} seconds", elapsed_seconds);

        Ok(())
    }

    /// Runs a single batch of the sync process without looping.
    /// Returns `true` if a scan range was processed, `false` if no scan ranges were suggested.
    pub async fn sync_next_batch(&self, batch_size: Option<u32>) -> Result<bool, Error> {
        let start_time = js_sys::Date::now();

        let processed_batch = self.inner.sync_next_batch(batch_size).await?;

        let end_time = js_sys::Date::now();
        let elapsed_seconds = (end_time - start_time) / 1000.0;
        tracing::info!(
            "⏱️ Sync next batch completed in {:.2} seconds, processed_batch: {}",
            elapsed_seconds,
            processed_batch
        );

        Ok(processed_batch)
    }

    /// Runs a single batch using the optimized scanning strategy.
    /// Returns `true` if a scan range was processed, `false` if no scan ranges were suggested.
    pub async fn sync_next_batch_optimized(&self, batch_size: Option<u32>) -> Result<bool, Error> {
        let start_time = js_sys::Date::now();

        let processed_batch = self.inner.sync_next_batch_optimized(batch_size).await?;

        let end_time = js_sys::Date::now();
        let elapsed_seconds = (end_time - start_time) / 1000.0;
        tracing::info!(
            "⏱️ Optimized sync next batch completed in {:.2} seconds, processed_batch: {}",
            elapsed_seconds,
            processed_batch
        );

        Ok(processed_batch)
    }

    pub async fn get_wallet_summary(&self) -> Result<Option<WalletSummary>, Error> {
        let Some((summary, shieldable_balances)) = self
            .inner
            .get_wallet_summary_with_shieldable_balances()
            .await?
        else {
            return Ok(None);
        };
        let mut summary = WalletSummary::try_from(summary)?;
        for (account_id, balance) in &mut summary.account_balances {
            balance.unshielded_shieldable_balance = shieldable_balances
                .get(&AccountId::from(*account_id))
                .copied()
                .unwrap_or(zcash_protocol::value::Zatoshis::ZERO)
                .into();
        }
        Ok(Some(summary))
    }

    /// Get the birthday height for a specific account
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account ID to get the birthday height for
    ///
    /// # Returns
    ///
    /// The birthday height (block height) for the specified account
    ///
    /// # Example
    ///
    /// ```javascript
    /// const accountId = 0;
    /// const birthdayHeight = await wallet.get_account_birthday(accountId);
    /// console.log(`Account ${accountId} birthday height: ${birthdayHeight}`);
    /// ```
    pub async fn get_account_birthday(&self, account_id: u32) -> Result<u32, Error> {
        self.inner
            .get_account_birthday(AccountId::from(account_id))
            .await
    }

    /// Get the Unix timestamp of a block at a given height
    ///
    /// # Arguments
    ///
    /// * `height` - The block height
    ///
    /// # Returns
    ///
    /// Unix timestamp (seconds since epoch) when the block was mined
    ///
    /// # Example
    ///
    /// ```javascript
    /// const height = 2855000;
    /// const timestamp = await wallet.get_block_time(height);
    /// const date = new Date(timestamp * 1000);
    /// console.log(`Block ${height} was mined at: ${date}`);
    /// ```
    pub async fn get_block_time(&self, height: u32) -> Result<u32, Error> {
        self.inner.get_block_time(height).await
    }

    /// Get the latest block height from the blockchain
    ///
    /// # Returns
    ///
    /// The current chain tip height
    ///
    /// # Example
    ///
    /// ```javascript
    /// const latestHeight = await wallet.get_latest_height();
    /// console.log(`Current blockchain height: ${latestHeight}`);
    /// ```
    pub async fn get_latest_height(&self) -> Result<u32, Error> {
        self.inner.get_latest_height().await
    }

    /// Returns the configured NU6.3 activation height for the selected network.
    pub fn get_ironwood_activation_height(&self) -> Option<u32> {
        self.inner.ironwood_activation_height()
    }

    /// Find the block height closest to a given Unix timestamp
    ///
    /// Uses binary search to efficiently locate the block height corresponding
    /// to a specific time. Useful for determining wallet birthday heights based
    /// on dates.
    ///
    /// # Arguments
    ///
    /// * `time` - Unix timestamp (seconds since epoch)
    ///
    /// # Returns
    ///
    /// Block height closest to the given timestamp (within ~1000 blocks precision)
    ///
    /// # Example
    ///
    /// ```javascript
    /// // Find block height for January 1, 2024
    /// const timestamp = Math.floor(new Date('2024-01-01').getTime() / 1000);
    /// const height = await wallet.get_block_by_time(timestamp);
    /// console.log(`Block height at 2024-01-01: ${height}`);
    ///
    /// // Use as birthday height when importing a wallet
    /// const birthdayTimestamp = Math.floor(new Date('2023-06-15').getTime() / 1000);
    /// const birthdayHeight = await wallet.get_block_by_time(birthdayTimestamp);
    /// ```
    pub async fn get_block_by_time(&self, time: u32) -> Result<u32, Error> {
        self.inner.get_block_by_time(time).await
    }

    pub async fn get_transaction_history(&self, account_id: u32) -> Result<JsValue, Error> {
        if let Err(error) = self.inner.process_pending_transaction_requests().await {
            tracing::warn!("Unable to enhance transaction history: {error}");
        }
        let db = self.inner.db.read().await;
        let entries = db.get_transaction_history(AccountId::from(account_id));
        serde_wasm_bindgen::to_value(&entries).map_err(Error::from)
    }

    /// Journal-aware sync: download + scan one batch, return journal data for persistence.
    /// Returns null if fully synced, or Uint8Array with journal entry data.
    /// When `refresh` is false, session setup is skipped (call `sync_session_setup`
    /// once at the start of the catch-up session first).
    pub async fn prepare_sync_batch(
        &self,
        batch_size: Option<u32>,
        refresh: bool,
    ) -> Result<Option<Box<[u8]>>, Error> {
        let start_time = js_sys::Date::now();

        let result = self.inner.prepare_sync_batch(batch_size, refresh).await?;

        let elapsed_seconds = (js_sys::Date::now() - start_time) / 1000.0;
        match &result {
            Some(data) => {
                tracing::info!(
                    "⏱️ prepare_sync_batch completed in {:.2}s, journal entry: {} bytes",
                    elapsed_seconds,
                    data.len()
                );
            }
            None => {
                tracing::info!(
                    "⏱️ prepare_sync_batch: fully synced ({:.2}s)",
                    elapsed_seconds
                );
            }
        }

        Ok(result.map(|v| v.into_boxed_slice()))
    }

    /// Benchmark helper: download a block range over gRPC-web without scanning.
    /// Returns the number of blocks fetched. Used to probe download throughput.
    pub async fn bench_download_range(&self, start_height: u32, count: u32) -> Result<u32, Error> {
        self.inner.bench_download_range(start_height, count).await
    }

    /// Run session-level setup (subtree roots, chain tip, transparent UTXOs)
    /// once before a multi-batch catch-up so subsequent batches can skip it.
    pub async fn sync_session_setup(&self) -> Result<(), Error> {
        self.inner.sync_session_setup().await
    }

    /// Benchmark helper: one baseline journal batch with per-stage timings (ms)
    /// as JSON `{"subtree","setup","download","scan"}`, or undefined when synced.
    /// When `refresh` is false, session setup is skipped (call
    /// `sync_session_setup` once first).
    pub async fn bench_prepare_sync_batch_timed(
        &self,
        batch_size: Option<u32>,
        refresh: bool,
    ) -> Result<Option<String>, Error> {
        self.inner
            .bench_prepare_sync_batch_timed(batch_size, refresh)
            .await
    }

    /// Optimized journal-aware sync: same as [`prepare_sync_batch`] but uses
    /// External-only IVK scanning for contiguous forward ranges.
    pub async fn prepare_sync_batch_optimized(
        &self,
        batch_size: Option<u32>,
    ) -> Result<Option<Box<[u8]>>, Error> {
        let start_time = js_sys::Date::now();

        let result = self.inner.prepare_sync_batch_optimized(batch_size).await?;

        let elapsed_seconds = (js_sys::Date::now() - start_time) / 1000.0;
        match &result {
            Some(data) => {
                tracing::info!(
                    "⏱️ prepare_sync_batch_optimized completed in {:.2}s, journal entry: {} bytes",
                    elapsed_seconds,
                    data.len()
                );
            }
            None => {
                tracing::info!(
                    "⏱️ prepare_sync_batch_optimized: fully synced ({:.2}s)",
                    elapsed_seconds
                );
            }
        }

        Ok(result.map(|v| v.into_boxed_slice()))
    }

    /// Scan a journal entry for recovery (replay from base snapshot + journal).
    /// Returns true if more scan ranges remain.
    pub async fn scan_journal_entry(&self, journal_data: &[u8]) -> Result<bool, Error> {
        let start_time = js_sys::Date::now();

        let has_more = self.inner.scan_journal_entry(journal_data).await?;

        let elapsed_seconds = (js_sys::Date::now() - start_time) / 1000.0;
        tracing::info!(
            "⏱️ scan_journal_entry completed in {:.2}s, has_more: {}",
            elapsed_seconds,
            has_more
        );

        Ok(has_more)
    }

    /// Replay multiple journal entries in sequence (for recovery).
    pub async fn replay_journal_entries(
        &self,
        entries: Vec<js_sys::Uint8Array>,
    ) -> Result<(), Error> {
        let entries: Vec<Vec<u8>> = entries.iter().map(|e| e.to_vec()).collect();

        let start_time = js_sys::Date::now();
        tracing::info!("Replaying {} journal entries...", entries.len());

        self.inner.replay_journal_entries(entries).await?;

        let elapsed_seconds = (js_sys::Date::now() - start_time) / 1000.0;
        tracing::info!("⏱️ Journal replay completed in {:.2}s", elapsed_seconds);

        Ok(())
    }

    pub async fn db_to_bytes(&self) -> Result<Box<[u8]>, Error> {
        let bytes = self.inner.db_to_bytes().await?;
        Ok(bytes.into_boxed_slice())
    }

    /// The callback must complete synchronously; returned Promises are not awaited.
    /// A thrown value rejects this call unchanged.
    pub async fn db_to_bytes_chunked(&self, callback: &js_sys::Function) -> Result<(), JsValue> {
        let cb = callback.clone();
        let callback_error = Rc::new(RefCell::new(None));
        let error_in_callback = Rc::clone(&callback_error);
        let result = self
            .inner
            .db_to_bytes_chunked(move |chunk: &[u8]| {
                if error_in_callback.borrow().is_some() {
                    return;
                }
                let arr = js_sys::Uint8Array::from(chunk);
                if let Err(error) = cb.call1(&JsValue::NULL, &arr) {
                    *error_in_callback.borrow_mut() = Some(error);
                }
            })
            .await;
        if let Some(error) = callback_error.borrow_mut().take() {
            Err(error)
        } else {
            result.map_err(Into::into)
        }
    }

    #[wasm_bindgen(unchecked_return_type = "TransferResult")]
    pub async fn send_authorized_transactions(&self, txids: Vec<u8>) -> Result<JsValue, Error> {
        let txids = txids
            .chunks(32)
            .map(|txid| {
                let txid_arr: [u8; 32] = txid.try_into().map_err(|_| Error::TxIdParse)?;
                Ok(TxId::from_bytes(txid_arr))
            })
            .collect::<Result<Vec<_>, Error>>()?;
        let txids = NonEmpty::from_vec(txids).ok_or(Error::TxIdParse)?;
        let result = self.inner.send_authorized_transactions(&txids).await?;
        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    /// Get account ID by account name
    ///
    /// # Arguments
    ///
    /// * `account_name` - The name of the account to find
    ///
    /// # Returns
    ///
    /// Returns the account ID as u32 if found
    ///
    /// # Example
    ///
    /// ```javascript
    /// const accountId = await wallet.get_account_id_by_name("MyAccount");
    /// console.log("Account ID:", accountId);
    /// ```
    pub async fn get_account_id_by_name(&self, account_name: &str) -> Result<u32, Error> {
        let account_id = self.inner.get_account_id_by_name(account_name).await?;
        Ok(*account_id)
    }

    /// Get the HD account index for an account.
    ///
    /// This returns the ZIP-32 account index that was used to derive this account's keys.
    /// Returns None if the account was imported and doesn't have derivation info.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account ID
    ///
    /// # Returns
    ///
    /// The HD account index (u32), or None if not available
    pub async fn get_account_hd_index(&self, account_id: u32) -> Result<Option<u32>, Error> {
        use zcash_client_backend::data_api::{Account, AccountPurpose, AccountSource};

        let db = self.inner.db.read().await;
        let account = db
            .get_account(account_id.into())?
            .ok_or(Error::AccountNotFound(account_id))?;

        // Get the derivation info from the account
        match account.source() {
            AccountSource::Derived { derivation, .. } => {
                Ok(Some(u32::from(derivation.account_index())))
            }
            AccountSource::Imported { purpose, .. } => {
                // Imported accounts can also have derivation info in their purpose
                match purpose {
                    AccountPurpose::Spending { derivation } => {
                        Ok(derivation.as_ref().map(|d| u32::from(d.account_index())))
                    }
                    AccountPurpose::ViewOnly => Ok(None),
                }
            }
        }
    }

    /// Get addresses for an account
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account ID to get addresses for
    ///
    /// # Returns
    ///
    /// Returns a UnifiedAddresses object containing:
    /// - unified: The shielded unified address (u1 format with Orchard/Sapling receivers only)
    /// - orchard: Orchard-only unified address (if available)
    /// - sapling: Sapling-only unified address (u1 format, if available)
    /// - sapling_zs: Sapling traditional address (zs format, if available)
    /// - transparent: Transparent P2PKH address (if available)
    ///
    /// # Example
    ///
    /// ```javascript
    /// const addresses = await wallet.get_unified_addresses(accountId);
    /// // Display the selected address in the wallet UI; avoid logging account addresses.
    /// ```
    pub async fn get_unified_addresses(&self, account_id: u32) -> Result<JsValue, Error> {
        use zcash_client_backend::data_api::Account;
        use zcash_keys::keys::UnifiedAddressRequest;

        let db = self.inner.db.read().await;
        let account = db
            .get_account(account_id.into())?
            .ok_or(Error::AccountNotFound(account_id))?;

        // Get the unified incoming viewing key from the account
        let uivk = account.uivk();

        // Generate the first address that includes every receiver supported by the UIVK.
        let (full_address, diversifier_index) =
            uivk.default_address(UnifiedAddressRequest::AllAvailableKeys)?;
        let address_index =
            crate::bindgen::mnemonic::transparent_address_index(&full_address, diversifier_index);
        let result = crate::bindgen::mnemonic::unified_addresses_from_full(
            &full_address,
            &self.inner.network,
            address_index,
        );

        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    /// Generate and persist the next shielded receiving address for an account.
    ///
    /// This returns a unified address containing the account's available shielded receivers
    /// (Orchard/Sapling) and no transparent receiver. It advances the wallet's stored address
    /// position, so callers should persist the wallet DB after using this method.
    ///
    /// # Arguments
    ///
    /// * `account_id` - The account ID to generate the next shielded address for
    ///
    /// # Returns
    ///
    /// Returns a UnifiedAddresses object. `transparent` and `address_index` will be null.
    pub async fn get_next_shielded_address(&self, account_id: u32) -> Result<JsValue, Error> {
        use zcash_client_backend::data_api::Account;
        use zcash_keys::keys::{ReceiverRequirement, UnifiedAddressRequest};

        let account_ref = AccountId::from(account_id);
        let mut db = self.inner.db.write().await;
        let account = db
            .get_account(account_ref)?
            .ok_or(Error::AccountNotFound(account_id))?;
        let uivk = account.uivk();

        let request = UnifiedAddressRequest::custom(
            if uivk.has_orchard() {
                ReceiverRequirement::Require
            } else {
                ReceiverRequirement::Omit
            },
            if uivk.has_sapling() {
                ReceiverRequirement::Require
            } else {
                ReceiverRequirement::Omit
            },
            ReceiverRequirement::Omit,
        )
        .map_err(|_| Error::Generic("Account has no shielded receivers".into()))?;

        let (address, _) = db
            .get_next_available_address(account_ref, request)?
            .ok_or_else(|| Error::Generic("Account cannot generate new addresses".into()))?;
        let result = crate::bindgen::mnemonic::unified_addresses_from_full(
            &address,
            &self.inner.network,
            None,
        );

        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    /// List the user-facing shielded receiving addresses generated for an account.
    ///
    /// The wallet database also stores Unified Addresses used to discover transparent
    /// receivers. Those internal records are excluded unless they are the account's default
    /// address. Results are ordered by diversifier index from oldest to newest.
    pub async fn list_shielded_addresses(&self, account_id: u32) -> Result<JsValue, Error> {
        use std::collections::HashSet;
        use zcash_client_backend::data_api::Account;
        use zcash_keys::address::Address;
        use zcash_keys::keys::UnifiedAddressRequest;

        let account_ref = AccountId::from(account_id);
        let db = self.inner.db.read().await;
        let account = db
            .get_account(account_ref)?
            .ok_or(Error::AccountNotFound(account_id))?;
        let (default_address, _) = account
            .uivk()
            .default_address(UnifiedAddressRequest::AllAvailableKeys)?;

        let mut seen = HashSet::new();
        let addresses = db
            .list_addresses(account_ref)?
            .into_iter()
            .filter_map(|info| match info.address() {
                Address::Unified(address)
                    if is_user_facing_shielded_address(address, &default_address) =>
                {
                    let result = crate::bindgen::mnemonic::unified_addresses_from_full(
                        address,
                        &self.inner.network,
                        None,
                    );
                    seen.insert(result.unified.clone()).then_some(result)
                }
                _ => None,
            })
            .collect::<Vec<_>>();

        Ok(serde_wasm_bindgen::to_value(&addresses)?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn oneclick_pczt_transfer(
        &self,
        account_id: u32,
        to_address: String,
        value: u64,
        usk: super::UnifiedSpendingKey,
        seed_fp: SeedFingerprint,
        sapling_proof_gen_key: Option<ProofGenerationKey>,
        memo: Option<Vec<u8>>,
    ) -> Result<String, Error> {
        let to_address = ZcashAddress::try_from_encoded(&to_address)?;
        let pczt = self
            .inner
            .pczt_create(AccountId::from(account_id), to_address, value, memo)
            .await?;

        self.sign_prove_and_send_pczt(pczt, usk, seed_fp, sapling_proof_gen_key)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(unchecked_return_type = "TransferResult")]
    pub async fn oneclick_transfer(
        &self,
        account_id: u32,
        to_address: String,
        value: u64,
        usk: super::UnifiedSpendingKey,
        #[wasm_bindgen(unchecked_param_type = "\"shielded\" | \"transparent\"")]
        funding_source: String,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: Option<u64>,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<JsValue, Error> {
        let account_id = AccountId::from(account_id);
        let funding_source = funding_source.parse::<TransferFundingSource>()?;
        let result = self
            .inner
            .oneclick_transfer(
                account_id,
                ZcashAddress::try_from_encoded(&to_address)?,
                value,
                usk.into(),
                funding_source,
                memo,
                marginal_fee_zats,
                expiry_delta_blocks,
            )
            .await;
        let result = if funding_source == TransferFundingSource::Shielded {
            self.diagnose_transfer_result(account_id, result).await?
        } else {
            result?
        };
        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn oneclick_pczt_transparent_transfer(
        &self,
        account_id: u32,
        to_address: String,
        value: u64,
        usk: super::UnifiedSpendingKey,
        seed_fp: SeedFingerprint,
        sapling_proof_gen_key: Option<ProofGenerationKey>,
        memo: Option<Vec<u8>>,
    ) -> Result<String, Error> {
        let to_address = ZcashAddress::try_from_encoded(&to_address)?;
        let pczt = self
            .inner
            .pczt_create_transparent(AccountId::from(account_id), to_address, value, memo)
            .await?;

        self.sign_prove_and_send_pczt(pczt, usk, seed_fp, sapling_proof_gen_key)
            .await
    }

    pub async fn oneclick_pczt_shield(
        &self,
        account_id: u32,
        usk: super::UnifiedSpendingKey,
        seed_fp: SeedFingerprint,
        sapling_proof_gen_key: Option<ProofGenerationKey>,
    ) -> Result<String, Error> {
        let pczt = self.inner.pczt_shield(account_id.into()).await?;

        self.sign_prove_and_send_pczt(pczt, usk, seed_fp, sapling_proof_gen_key)
            .await
    }

    /// Import a watch-only spending account from an encoded UFVK (hardware wallet flow).
    ///
    /// # Arguments
    /// * `account_name` - Display name for the account
    /// * `ufvk` - The encoded Unified Full Viewing Key exported by the device
    /// * `seed_fingerprint` - 32-byte ZIP-32 seed fingerprint exported by the device
    /// * `account_hd_index` - ZIP-32 account index on the device
    /// * `birthday_height` - Block height to start scanning from
    /// * `key_source` - Optional tag describing the key origin (e.g. "keystone")
    ///
    /// # Returns
    /// The new account id
    pub async fn create_account_ufvk(
        &self,
        account_name: &str,
        ufvk: &str,
        seed_fingerprint: &[u8],
        account_hd_index: u32,
        birthday_height: Option<u32>,
        key_source: Option<String>,
    ) -> Result<u32, Error> {
        let seed_fp: [u8; 32] = seed_fingerprint
            .try_into()
            .map_err(|_| Error::SeedFingerprint)?;

        self.inner
            .create_account_ufvk(
                account_name,
                ufvk,
                seed_fp,
                account_hd_index,
                birthday_height,
                key_source.as_deref(),
            )
            .await
            .map(|id| *id)
    }

    /// Create an unsigned, unproven PCZT for a transfer (hardware wallet flow).
    ///
    /// The returned PCZT carries ZIP-32 derivation metadata so an external signer
    /// (e.g. Keystone) can locate its keys. Serialize it with `Pczt.serialize()`
    /// before transporting via QR. `marginal_fee_zats` selects the ZIP-317 fee
    /// tier so hardware sends honor the same dynamic-fee tiers as software sends.
    pub async fn pczt_create(
        &self,
        account_id: u32,
        to_address: String,
        value: u64,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<WasmPczt, Error> {
        let to_address = ZcashAddress::try_from_encoded(&to_address)?;
        let account_id = AccountId::from(account_id);
        let result = self
            .inner
            .pczt_create_dynamic_fee(account_id, to_address, value, memo, marginal_fee_zats)
            .await;
        self.diagnose_transfer_result(account_id, result)
            .await
            .map(Into::into)
    }

    /// Create an unsigned, unproven PCZT funded only by transparent inputs.
    /// `marginal_fee_zats` selects the ZIP-317 fee tier, matching software sends.
    pub async fn pczt_create_transparent(
        &self,
        account_id: u32,
        to_address: String,
        value: u64,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<WasmPczt, Error> {
        let to_address = ZcashAddress::try_from_encoded(&to_address)?;
        self.inner
            .pczt_create_transparent_hardware_dynamic_fee(
                AccountId::from(account_id),
                to_address,
                value,
                memo,
                marginal_fee_zats,
            )
            .await
            .map(Into::into)
    }

    /// Create an unsigned, unproven shielding PCZT (transparent -> Orchard) for
    /// external signing (hardware wallet flow). `marginal_fee_zats` selects the
    /// ZIP-317 fee tier so hardware shields honor the dynamic-fee tiers too.
    pub async fn pczt_shield_create(
        &self,
        account_id: u32,
        marginal_fee_zats: u64,
    ) -> Result<WasmPczt, Error> {
        self.inner
            .pczt_shield_dynamic_fee(account_id.into(), marginal_fee_zats)
            .await
            .map(Into::into)
    }

    /// Create a V6 PCZT that sweeps spendable Orchard funds to this account's Ironwood pool.
    pub async fn pczt_orchard_migration_create(
        &self,
        account_id: u32,
        to_address: String,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<WasmPczt, Error> {
        let to_address = ZcashAddress::try_from_encoded(&to_address)?;
        self.inner
            .pczt_create_orchard_migration(
                account_id.into(),
                to_address,
                memo,
                marginal_fee_zats,
                expiry_delta_blocks,
            )
            .await
            .map(Into::into)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn oneclick_pczt_orchard_migration(
        &self,
        account_id: u32,
        to_address: String,
        usk: super::UnifiedSpendingKey,
        seed_fp: SeedFingerprint,
        sapling_proof_gen_key: Option<ProofGenerationKey>,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<String, Error> {
        let to_address = ZcashAddress::try_from_encoded(&to_address)?;
        let pczt = self
            .inner
            .pczt_create_orchard_migration(
                account_id.into(),
                to_address,
                memo,
                marginal_fee_zats,
                expiry_delta_blocks,
            )
            .await?;

        self.sign_prove_and_send_pczt(pczt, usk, seed_fp, sapling_proof_gen_key)
            .await
    }

    pub async fn estimate_orchard_migration_fee(
        &self,
        account_id: u32,
        to_address: String,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<u64, Error> {
        let to_address = ZcashAddress::try_from_encoded(&to_address)?;
        self.inner
            .estimate_orchard_migration_fee(account_id.into(), to_address, memo, marginal_fee_zats)
            .await
    }

    /// Prove and broadcast an externally signed PCZT (hardware wallet flow).
    ///
    /// Hardware-wallet accounts never hold Sapling notes (Keystone supports
    /// transparent + Orchard only), so no Sapling proof generation key is needed.
    ///
    /// # Returns
    /// Transaction ID string on success
    pub async fn pczt_prove_and_send(&self, pczt: WasmPczt) -> Result<String, Error> {
        self.inner.pczt_prove_and_send(pczt.into(), None).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn oneclick_pczt_transfer_dynamic_fee(
        &self,
        account_id: u32,
        to_address: String,
        value: u64,
        usk: super::UnifiedSpendingKey,
        seed_fp: SeedFingerprint,
        sapling_proof_gen_key: Option<ProofGenerationKey>,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<String, Error> {
        let to_address = ZcashAddress::try_from_encoded(&to_address)?;
        let pczt = match expiry_delta_blocks {
            Some(expiry_delta_blocks) => {
                self.inner
                    .pczt_create_dynamic_fee_with_expiry_delta(
                        AccountId::from(account_id),
                        to_address,
                        value,
                        memo,
                        marginal_fee_zats,
                        expiry_delta_blocks,
                    )
                    .await
            }
            None => {
                self.inner
                    .pczt_create_dynamic_fee(
                        AccountId::from(account_id),
                        to_address,
                        value,
                        memo,
                        marginal_fee_zats,
                    )
                    .await
            }
        };

        let pczt = self
            .diagnose_transfer_result(AccountId::from(account_id), pczt)
            .await?;

        self.sign_prove_and_send_pczt(pczt, usk, seed_fp, sapling_proof_gen_key)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn oneclick_pczt_transparent_transfer_dynamic_fee(
        &self,
        account_id: u32,
        to_address: String,
        value: u64,
        usk: super::UnifiedSpendingKey,
        seed_fp: SeedFingerprint,
        sapling_proof_gen_key: Option<ProofGenerationKey>,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<String, Error> {
        let to_address = ZcashAddress::try_from_encoded(&to_address)?;
        let pczt = match expiry_delta_blocks {
            Some(expiry_delta_blocks) => {
                self.inner
                    .pczt_create_transparent_dynamic_fee_with_expiry_delta(
                        AccountId::from(account_id),
                        to_address,
                        value,
                        memo,
                        marginal_fee_zats,
                        expiry_delta_blocks,
                    )
                    .await?
            }
            None => {
                self.inner
                    .pczt_create_transparent_dynamic_fee(
                        AccountId::from(account_id),
                        to_address,
                        value,
                        memo,
                        marginal_fee_zats,
                    )
                    .await?
            }
        };

        self.sign_prove_and_send_pczt(pczt, usk, seed_fp, sapling_proof_gen_key)
            .await
    }

    pub async fn oneclick_pczt_shield_dynamic_fee(
        &self,
        account_id: u32,
        usk: super::UnifiedSpendingKey,
        seed_fp: SeedFingerprint,
        sapling_proof_gen_key: Option<ProofGenerationKey>,
        marginal_fee_zats: u64,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<String, Error> {
        let pczt = match expiry_delta_blocks {
            Some(expiry_delta_blocks) => {
                self.inner
                    .pczt_shield_dynamic_fee_with_expiry_delta(
                        account_id.into(),
                        marginal_fee_zats,
                        expiry_delta_blocks,
                    )
                    .await?
            }
            None => {
                self.inner
                    .pczt_shield_dynamic_fee(account_id.into(), marginal_fee_zats)
                    .await?
            }
        };

        self.sign_prove_and_send_pczt(pczt, usk, seed_fp, sapling_proof_gen_key)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(unchecked_return_type = "TransferEstimate")]
    pub async fn estimate_transfer(
        &self,
        account_id: u32,
        to_address: String,
        value: u64,
        #[wasm_bindgen(unchecked_param_type = "\"shielded\" | \"transparent\"")]
        funding_source: String,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: Option<u64>,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<JsValue, Error> {
        let account_id = AccountId::from(account_id);
        let funding_source = funding_source.parse::<TransferFundingSource>()?;
        let estimate = self
            .inner
            .estimate_transfer(
                account_id,
                ZcashAddress::try_from_encoded(&to_address)?,
                value,
                funding_source,
                memo,
                marginal_fee_zats,
                expiry_delta_blocks,
            )
            .await;
        let estimate = if funding_source == TransferFundingSource::Shielded {
            self.diagnose_transfer_result(account_id, estimate).await?
        } else {
            estimate?
        };
        Ok(serde_wasm_bindgen::to_value(&estimate)?)
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn estimate_pczt_transfer_fee(
        &self,
        account_id: u32,
        to_address: String,
        value: u64,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<u64, Error> {
        let account_id = AccountId::from(account_id);
        let to_address = ZcashAddress::try_from_encoded(&to_address)?;
        let result = self
            .inner
            .estimate_pczt_transfer_fee(account_id, to_address, value, memo, marginal_fee_zats)
            .await;
        self.diagnose_transfer_result(account_id, result).await
    }

    #[allow(clippy::too_many_arguments)]
    pub async fn estimate_pczt_transparent_transfer_fee(
        &self,
        account_id: u32,
        to_address: String,
        value: u64,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<u64, Error> {
        let to_address = ZcashAddress::try_from_encoded(&to_address)?;
        self.inner
            .estimate_pczt_transparent_transfer_fee(
                AccountId::from(account_id),
                to_address,
                value,
                memo,
                marginal_fee_zats,
            )
            .await
    }

    pub async fn estimate_pczt_max_transfer(
        &self,
        account_id: u32,
        to_address: String,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<JsValue, Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct MaxTransferEstimate {
            max_amount_zats: String,
            fee_zats: String,
        }

        let account_id = AccountId::from(account_id);
        let to_address = ZcashAddress::try_from_encoded(&to_address)?;
        let result = self
            .inner
            .estimate_pczt_max_transfer(account_id, to_address, memo, marginal_fee_zats)
            .await;
        let (max_amount_zats, fee_zats) = self.diagnose_transfer_result(account_id, result).await?;

        serde_wasm_bindgen::to_value(&MaxTransferEstimate {
            max_amount_zats: max_amount_zats.to_string(),
            fee_zats: fee_zats.to_string(),
        })
        .map_err(Error::from)
    }

    pub async fn estimate_pczt_max_transparent_transfer(
        &self,
        account_id: u32,
        to_address: String,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<JsValue, Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct MaxTransferEstimate {
            max_amount_zats: String,
            fee_zats: String,
        }

        let to_address = ZcashAddress::try_from_encoded(&to_address)?;
        let (max_amount_zats, fee_zats) = self
            .inner
            .estimate_pczt_max_transparent_transfer(
                AccountId::from(account_id),
                to_address,
                memo,
                marginal_fee_zats,
            )
            .await?;

        serde_wasm_bindgen::to_value(&MaxTransferEstimate {
            max_amount_zats: max_amount_zats.to_string(),
            fee_zats: fee_zats.to_string(),
        })
        .map_err(Error::from)
    }

    pub async fn estimate_pczt_shield_fee(
        &self,
        account_id: u32,
        marginal_fee_zats: u64,
    ) -> Result<u64, Error> {
        self.inner
            .estimate_pczt_shield_fee(account_id.into(), marginal_fee_zats)
            .await
    }

    /// Sign, prove locally, and send a PCZT transaction.
    ///
    /// This helper method encapsulates the common workflow of:
    /// 1. Signing a PCZT with the provided spending key
    /// 2. Proving the PCZT locally
    /// 3. Sending the proven PCZT to the network
    ///
    /// # Arguments
    /// * `pczt` - The PCZT to process
    /// * `usk` - Unified spending key for signing
    /// * `seed_fp` - Seed fingerprint for signing
    /// * `sapling_proof_gen_key` - Optional Sapling proof generation key
    ///
    /// # Returns
    /// Transaction ID string on success
    async fn sign_prove_and_send_pczt(
        &self,
        pczt: pczt::Pczt,
        usk: super::UnifiedSpendingKey,
        seed_fp: SeedFingerprint,
        sapling_proof_gen_key: Option<ProofGenerationKey>,
    ) -> Result<String, Error> {
        let proof_gen_key = sapling_proof_gen_key.map(Into::into);

        // Sign the PCZT
        let signed_pczt =
            pczt_sign_inner(self.inner.network, pczt, usk.into(), seed_fp.into()).await?;

        // Prove the PCZT locally.
        let proved_pczt = self.inner.pczt_prove(signed_pczt, proof_gen_key).await?;

        // Send the proven PCZT
        let txid = self.inner.pczt_send(proved_pczt).await?;
        Ok(txid)
    }

    pub async fn get_latest_block(&self) -> Result<u64, Error> {
        self.client()
            .get_latest_block(ChainSpec {})
            .await
            .map(|response| response.into_inner().height)
            .map_err(Error::from)
    }
}

#[wasm_bindgen]
pub struct Proposal {
    inner: zcash_client_backend::proposal::Proposal<StandardFeeRule, NoteRef>,
}

impl From<zcash_client_backend::proposal::Proposal<StandardFeeRule, NoteRef>> for Proposal {
    fn from(inner: zcash_client_backend::proposal::Proposal<StandardFeeRule, NoteRef>) -> Self {
        Self { inner }
    }
}

impl From<Proposal> for zcash_client_backend::proposal::Proposal<StandardFeeRule, NoteRef> {
    fn from(proposal: Proposal) -> Self {
        proposal.inner
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[wasm_bindgen(inspectable)]
pub struct WalletSummary {
    account_balances: Vec<(u32, AccountBalance)>,
    pub chain_tip_height: u32,
    pub fully_scanned_height: u32,
    // scan_progress: Option<Ratio<u64>>,
    pub next_sapling_subtree_index: u64,
    pub next_orchard_subtree_index: u64,
    pub next_ironwood_subtree_index: u64,
}

#[wasm_bindgen]
impl WalletSummary {
    #[wasm_bindgen(getter)]
    pub fn account_balances(&self) -> Result<JsValue, Error> {
        serde_wasm_bindgen::to_value(&self.account_balances).map_err(Error::from)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountBalance {
    pub sapling_balance: u64,
    pub orchard_balance: u64,
    pub ironwood_balance: u64,
    pub unshielded_balance: u64,
    pub unshielded_shieldable_balance: u64,
    pub sapling_pending_balance: u64,
    pub orchard_pending_balance: u64,
    pub ironwood_pending_balance: u64,
    pub unshielded_pending_balance: u64,
    pub sapling_total_balance: u64,
    pub orchard_total_balance: u64,
    pub ironwood_total_balance: u64,
    pub unshielded_total_balance: u64,
    pub spendable_balance: u64,
    pub pending_balance: u64,
    pub total_balance: u64,
}

impl TryFrom<zcash_client_backend::data_api::AccountBalance> for AccountBalance {
    type Error = Error;

    fn try_from(balance: zcash_client_backend::data_api::AccountBalance) -> Result<Self, Error> {
        use zcash_protocol::value::Zatoshis;

        fn pending_value(
            balance: &zcash_client_backend::data_api::Balance,
        ) -> Result<Zatoshis, Error> {
            (balance.change_pending_confirmation() + balance.value_pending_spendability())
                .ok_or(zcash_protocol::value::BalanceError::Overflow)
                .map_err(Error::from)
        }

        let sapling_pending_balance = pending_value(balance.sapling_balance())?;
        let orchard_pending_balance = pending_value(balance.orchard_balance())?;
        let ironwood_pending_balance = pending_value(balance.ironwood_balance())?;
        let unshielded_pending_balance = pending_value(&balance.unshielded_balance())?;
        let pending_balance = (balance.change_pending_confirmation()
            + balance.value_pending_spendability())
        .ok_or(zcash_protocol::value::BalanceError::Overflow)
        .map_err(Error::from)?;

        Ok(AccountBalance {
            sapling_balance: balance.sapling_balance().spendable_value().into(),
            orchard_balance: balance.orchard_balance().spendable_value().into(),
            ironwood_balance: balance.ironwood_balance().spendable_value().into(),
            unshielded_balance: balance.unshielded_balance().spendable_value().into(),
            unshielded_shieldable_balance: balance.unshielded_balance().spendable_value().into(),
            sapling_pending_balance: sapling_pending_balance.into(),
            orchard_pending_balance: orchard_pending_balance.into(),
            ironwood_pending_balance: ironwood_pending_balance.into(),
            unshielded_pending_balance: unshielded_pending_balance.into(),
            sapling_total_balance: balance.sapling_balance().total().into(),
            orchard_total_balance: balance.orchard_balance().total().into(),
            ironwood_total_balance: balance.ironwood_balance().total().into(),
            unshielded_total_balance: balance.unshielded_balance().total().into(),
            spendable_balance: balance.spendable_value().into(),
            pending_balance: pending_balance.into(),
            total_balance: balance.total().into(),
        })
    }
}

impl<T> TryFrom<zcash_client_backend::data_api::WalletSummary<T>> for WalletSummary
where
    T: std::cmp::Eq + std::hash::Hash + std::ops::Deref<Target = u32> + Clone,
{
    type Error = Error;

    fn try_from(summary: zcash_client_backend::data_api::WalletSummary<T>) -> Result<Self, Error> {
        let mut account_balances: Vec<_> = summary
            .account_balances()
            .iter()
            .map(|(k, v)| {
                AccountBalance::try_from(*v).map(|balance| (*(*k).clone().deref(), balance))
            })
            .collect::<Result<_, _>>()?;

        account_balances.sort_by(|a, b| a.0.cmp(&b.0));

        Ok(WalletSummary {
            account_balances,
            chain_tip_height: summary.chain_tip_height().into(),
            fully_scanned_height: summary.fully_scanned_height().into(),
            next_sapling_subtree_index: summary.next_sapling_subtree_index(),
            next_orchard_subtree_index: summary.next_orchard_subtree_index(),
            next_ironwood_subtree_index: summary.next_ironwood_subtree_index(),
        })
    }
}

#[cfg(test)]
mod confirmations_policy_tests {
    use super::{ConfirmationsPolicy, ConfirmationsPolicyOptions, is_user_facing_shielded_address};
    use crate::bindgen::UnifiedSpendingKey;
    use zcash_keys::keys::{ReceiverRequirement, UnifiedAddressRequest};
    use zip32::DiversifierIndex;

    #[test]
    fn custom_confirmation_counts_retain_the_default_shielding_policy() {
        for (trusted, untrusted) in [(1, 2), (3, 10), (u32::MAX, u32::MAX)] {
            let policy = ConfirmationsPolicy::try_from(ConfirmationsPolicyOptions {
                trusted: trusted.try_into().unwrap(),
                untrusted: untrusted.try_into().unwrap(),
            })
            .unwrap();
            assert_eq!(u32::from(policy.trusted()), trusted);
            assert_eq!(u32::from(policy.untrusted()), untrusted);
            assert_eq!(
                policy.allow_zero_conf_shielding(),
                ConfirmationsPolicy::default().allow_zero_conf_shielding()
            );
        }
    }

    #[test]
    fn confirmation_counts_reject_trusted_greater_than_untrusted() {
        assert!(
            ConfirmationsPolicy::try_from(ConfirmationsPolicyOptions {
                trusted: 3.try_into().unwrap(),
                untrusted: 2.try_into().unwrap(),
            })
            .is_err()
        );
    }

    #[test]
    fn shielded_address_history_excludes_transparent_discovery_records() {
        let spending_key = UnifiedSpendingKey::new("main", vec![0; 32].into_boxed_slice(), 0)
            .expect("test spending key should be valid");
        let viewing_key = spending_key.to_unified_full_viewing_key();
        let incoming_viewing_key = viewing_key.as_inner().to_unified_incoming_viewing_key();
        let (default_address, _) = incoming_viewing_key
            .default_address(UnifiedAddressRequest::AllAvailableKeys)
            .expect("default address should be available");

        let shielded_request = UnifiedAddressRequest::custom(
            ReceiverRequirement::Require,
            ReceiverRequirement::Require,
            ReceiverRequirement::Omit,
        )
        .expect("shielded-only request should be valid");
        let (rotated_address, _) = incoming_viewing_key
            .find_address(DiversifierIndex::new(), shielded_request)
            .expect("shielded-only address should be available");

        let mut index = DiversifierIndex::new();
        let transparent_discovery_address = loop {
            if let Ok(address) =
                incoming_viewing_key.address(index, UnifiedAddressRequest::ALLOW_ALL)
                && address != default_address
                && address.transparent().is_some()
            {
                break address;
            }
            index
                .increment()
                .expect("test should find a transparent discovery address");
        };

        assert!(is_user_facing_shielded_address(
            &default_address,
            &default_address
        ));
        assert!(is_user_facing_shielded_address(
            &rotated_address,
            &default_address
        ));
        assert!(!is_user_facing_shielded_address(
            &transparent_discovery_address,
            &default_address
        ));
    }
}
