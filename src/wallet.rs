// Portions derived from ChainSafe WebZjs.
// Copyright 2024 ChainSafe Systems
// Modified by NoirWallet; see THIRD_PARTY_NOTICES.md for licensing.

use crate::compact_block_source::{CdnFallbackBlockSource, CompactBlockCdnConfig};
use crate::*;

use bip0039::{English, Mnemonic};
use futures_util::TryStreamExt;
use nonempty::NonEmpty;
use pczt::Pczt;
use pczt::roles::prover::Prover;
use pczt::roles::updater::Updater;
use rand::{rand_core::UnwrapErr, rngs::SysRng};
use sapling::ProofGenerationKey;
use secrecy::{ExposeSecret, SecretVec, Zeroize};
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Debug;
use std::future::Future;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::OnceLock;
use std::time::Duration;
use subtle::ConditionallySelectable;
use tokio::sync::RwLock;
use tonic::{
    client::GrpcService,
    codegen::{Body, Bytes, StdError},
};
use zcash_address::ZcashAddress;
use zcash_client_backend::data_api::error::Error as WalletError;
use zcash_client_backend::data_api::wallet::decrypt_and_store_transaction;
use zcash_client_backend::data_api::wallet::input_selection::{
    GreedyInputSelector, SpendPolicy, TransparentSpendPolicy,
};
use zcash_client_backend::data_api::wallet::{
    ConfirmationsPolicy, SpendingKeys, TargetHeight, create_pczt_from_proposal,
    create_proposed_transactions, extract_and_store_transaction_from_pczt, ordinary,
    propose_send_max_transfer, propose_send_max_transparent_transfer, propose_shielding,
    propose_transfer,
};
use zcash_client_backend::data_api::{
    Account, AccountBirthday, AccountPurpose, CoinbaseFilter, MaxSpendMode, TransactionDataRequest,
    TransactionStatus, WalletSummary, Zip32Derivation,
};
use zcash_client_backend::fees::standard::MultiOutputChangeStrategy;
use zcash_client_backend::fees::{
    DustOutputPolicy, SplitPolicy, StandardFeeRule, TransparentChangePolicy,
};
use zcash_client_backend::sync::{
    CompactBlockSource, run_next_batch_optimized_with_block_source,
    run_next_batch_with_block_source, run_with_block_source,
};
use zcash_client_backend::util::Clock;
use zcash_client_backend::wallet::OvkPolicy;
use zcash_client_backend::zip321::{Payment, TransactionRequest};
use zcash_client_backend::{
    data_api::{InputSource, WalletCommitmentTrees, WalletRead, WalletWrite},
    proto::service::{self, compact_tx_streamer_client::CompactTxStreamerClient},
};
use zcash_primitives::transaction::fees::{FeeRule, zip317 as prim_zip317};
use zcash_primitives::transaction::{Transaction, TxId, TxVersion};
use zcash_proofs::prover::LocalTxProver;

use zcash_keys::{
    encoding::AddressCodec,
    keys::{UnifiedFullViewingKey, UnifiedSpendingKey},
};
use zcash_protocol::ShieldedPool;
use zcash_protocol::consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;
use zip32::fingerprint::SeedFingerprint;

use zcash_client_backend::data_api::chain::BlockCache;
use zcash_client_memory::{MemBlockCache, MemoryWalletDb};

#[cfg(all(target_arch = "wasm32", debug_assertions))]
mod browser_fixture;

#[cfg(test)]
mod confirmations_tests;
#[cfg(test)]
mod fee_tests;
const BATCH_SIZE: u32 = 10000;
pub(crate) const DEFAULT_ZERO_INDEXER_SEND_TIMEOUT: Duration = Duration::from_secs(30);
const STANDARD_FEE_QUERY_TIMEOUT: Duration = Duration::from_secs(5);

struct WalletClock;

impl Clock for WalletClock {
    fn now(&self) -> std::time::SystemTime {
        // The time crate uses the JavaScript clock on browser WASM.
        time::OffsetDateTime::now_utc().into()
    }
}

fn consume_transparent_history_budget(remaining: &mut usize) -> Result<(), Error> {
    *remaining = remaining.checked_sub(1).ok_or_else(|| Error::Generic(
        "Transparent history query budget exhausted; retry synchronization to continue from recorded progress".to_owned(),
    ))?;
    Ok(())
}

/// constant that signals what's the minimum transparent balance for proposing a
/// shielding transaction
const SHIELDING_THRESHOLD: Zatoshis = Zatoshis::const_from_u64(100000);

fn transaction_request_is_due(request_at: Option<std::time::SystemTime>) -> bool {
    request_at.is_none_or(|request_at| {
        time::OffsetDateTime::from(request_at) <= time::OffsetDateTime::now_utc()
    })
}

fn transaction_status_from_raw_height(
    txid: TxId,
    raw_height: u64,
) -> Result<TransactionStatus, Error> {
    match raw_height {
        0 | u64::MAX => Ok(TransactionStatus::NotInMainChain),
        height => Ok(TransactionStatus::Mined(BlockHeight::from_u32(
            u32::try_from(height).map_err(|_| {
                Error::Generic(format!(
                    "Invalid mined height {height} for transaction {txid}"
                ))
            })?,
        ))),
    }
}

fn dynamic_zip317_fee_rule(marginal_fee_zats: u64) -> Result<prim_zip317::FeeRule, Error> {
    if marginal_fee_zats == 0 {
        return Err(Error::Generic(
            "marginal_fee_zats must be greater than 0".to_string(),
        ));
    }

    prim_zip317::FeeRule::non_standard(
        Zatoshis::from_u64(marginal_fee_zats)?,
        prim_zip317::GRACE_ACTIONS,
        prim_zip317::P2PKH_STANDARD_INPUT_SIZE,
        prim_zip317::P2PKH_STANDARD_OUTPUT_SIZE,
    )
    .ok_or_else(|| Error::Generic("Invalid ZIP-317 fee parameters".to_string()))
}

fn validate_expiry_delta_blocks(expiry_delta_blocks: u32) -> Result<u32, Error> {
    if expiry_delta_blocks == 0 {
        Err(Error::Generic(
            "expiry_delta_blocks must be greater than 0".to_string(),
        ))
    } else {
        Ok(expiry_delta_blocks)
    }
}

fn transfer_expiry_height(
    min_target_height: TargetHeight,
    expiry_delta_blocks: Option<u32>,
) -> Result<Option<BlockHeight>, Error> {
    expiry_delta_blocks
        .map(validate_expiry_delta_blocks)
        .transpose()
        .map(|delta| delta.map(|delta| BlockHeight::from(min_target_height) + delta))
}

fn transparent_transfer_policies() -> (SpendPolicy, TransparentChangePolicy) {
    (
        SpendPolicy::shielded_pools(std::iter::empty::<ShieldedPool>())
            .with_transparent(TransparentSpendPolicy::any_account_addr()),
        TransparentChangePolicy::TransparentChangeAllowed,
    )
}

fn hardware_orchard_ovk_policy(ufvk: &UnifiedFullViewingKey) -> Result<OvkPolicy, Error> {
    let orchard_fvk = ufvk.orchard().ok_or_else(|| {
        Error::Generic("Hardware transaction review requires an Orchard viewing key".to_owned())
    })?;

    Ok(OvkPolicy::Custom {
        external_ovk: orchard_fvk.to_ovk(orchard::keys::Scope::External).into(),
        internal_ovk: Some(orchard_fvk.to_ovk(orchard::keys::Scope::Internal).into()),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TransferFundingSource {
    Shielded,
    Transparent,
}

impl FromStr for TransferFundingSource {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "shielded" => Ok(Self::Shielded),
            "transparent" => Ok(Self::Transparent),
            other => Err(Error::InvalidTransferFundingSource(other.to_owned())),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferOverallStatus {
    Success,
    Partial,
    Unknown,
    Failed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferSubmissionStatus {
    Submitted,
    Rejected,
    Unknown,
    NotAttempted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferTransactionResult {
    pub tx_id: String,
    pub status: TransferSubmissionStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferResult {
    pub status: TransferOverallStatus,
    pub tx_ids: Vec<String>,
    pub final_tx_id: String,
    pub transactions: Vec<TransferTransactionResult>,
}

impl TransferResult {
    fn from_transactions(transactions: Vec<TransferTransactionResult>) -> Self {
        let final_tx_id = transactions
            .last()
            .expect("transfer transactions must be non-empty")
            .tx_id
            .clone();
        let tx_ids = transactions.iter().map(|tx| tx.tx_id.clone()).collect();
        let submitted = transactions
            .iter()
            .filter(|tx| tx.status == TransferSubmissionStatus::Submitted)
            .count();
        let has_unknown = transactions
            .iter()
            .any(|tx| tx.status == TransferSubmissionStatus::Unknown);
        let status = if submitted == transactions.len() {
            TransferOverallStatus::Success
        } else if has_unknown {
            TransferOverallStatus::Unknown
        } else if submitted > 0 {
            TransferOverallStatus::Partial
        } else {
            TransferOverallStatus::Failed
        };

        Self {
            status,
            tx_ids,
            final_tx_id,
            transactions,
        }
    }
}

struct TransactionToSubmit {
    txid: TxId,
    raw: service::RawTransaction,
    requires_zero_indexer: bool,
}

fn requires_zero_indexer(transaction: &Transaction) -> bool {
    transaction.orchard_bundle().is_some()
}

async fn submit_to_first_accepting_endpoint<F, Fut>(
    endpoint_count: usize,
    raw: service::RawTransaction,
    request_timeout: Duration,
    mut submit: F,
) -> Result<service::SendResponse, tonic::Status>
where
    F: FnMut(usize, service::RawTransaction) -> Fut,
    Fut: Future<Output = Result<service::SendResponse, tonic::Status>>,
{
    if endpoint_count == 0 {
        return Err(tonic::Status::failed_precondition(
            "No zero-indexer endpoints configured",
        ));
    }
    let mut failures = Vec::with_capacity(endpoint_count);
    let mut last_rejection = None;
    let mut ambiguous = false;
    for index in 0..endpoint_count {
        match tokio_with_wasm::alias::time::timeout(request_timeout, submit(index, raw.clone()))
            .await
        {
            Ok(Ok(response)) if response.error_code == 0 => return Ok(response),
            Ok(Ok(response)) => {
                failures.push(format!(
                    "endpoint {} rejected with code {}: {}",
                    index + 1,
                    response.error_code,
                    response.error_message
                ));
                last_rejection = Some(response);
            }
            Ok(Err(status)) => {
                ambiguous = true;
                failures.push(format!("endpoint {}: {status}", index + 1));
            }
            Err(_) => {
                ambiguous = true;
                failures.push(format!(
                    "endpoint {} timed out after {} ms",
                    index + 1,
                    request_timeout.as_millis()
                ));
            }
        }
    }
    let details = failures.join("; ");
    if ambiguous {
        Err(tonic::Status::unavailable(format!(
            "All zero-indexer endpoints failed: {details}"
        )))
    } else {
        let response = last_rejection.expect("at least one endpoint rejected");
        Ok(service::SendResponse {
            error_code: response.error_code,
            error_message: format!(
                "All zero-indexer endpoints rejected the transaction: {details}"
            ),
        })
    }
}

async fn submit_to_zero_indexers_with_fallback<ZF, ZFut, LF, LFut>(
    endpoint_count: usize,
    raw: service::RawTransaction,
    request_timeout: Duration,
    submit_to_zero_indexer: ZF,
    submit_to_lightwalletd: LF,
) -> Result<service::SendResponse, tonic::Status>
where
    ZF: FnMut(usize, service::RawTransaction) -> ZFut,
    ZFut: Future<Output = Result<service::SendResponse, tonic::Status>>,
    LF: FnOnce(service::RawTransaction) -> LFut,
    LFut: Future<Output = Result<service::SendResponse, tonic::Status>>,
{
    let zero_result = submit_to_first_accepting_endpoint(
        endpoint_count,
        raw.clone(),
        request_timeout,
        submit_to_zero_indexer,
    )
    .await;
    if matches!(&zero_result, Ok(response) if response.error_code == 0) {
        return zero_result;
    }
    let lightwalletd_result = submit_to_lightwalletd(raw).await;
    match (zero_result, lightwalletd_result) {
        (_, Ok(response)) if response.error_code == 0 => Ok(response),
        (Ok(_), Ok(response)) => Ok(response),
        (Err(zero_status), Ok(response)) => Err(tonic::Status::unavailable(format!(
            "Transaction submission is uncertain: zero-indexer failed ambiguously ({zero_status}); lightwalletd rejected with code {}: {}",
            response.error_code, response.error_message
        ))),
        (Ok(zero_response), Err(lightwalletd_status)) => Err(tonic::Status::unavailable(format!(
            "Transaction submission is uncertain: zero-indexer rejected with code {}; lightwalletd failed: {lightwalletd_status}",
            zero_response.error_code
        ))),
        (Err(zero_status), Err(lightwalletd_status)) => Err(tonic::Status::unavailable(format!(
            "Transaction submission is uncertain: zero-indexer failed ambiguously ({zero_status}); lightwalletd failed: {lightwalletd_status}"
        ))),
    }
}

async fn get_from_zero_indexers_with_fallback<ZF, ZFut, LF, LFut>(
    endpoint_count: usize,
    filter: service::TxFilter,
    request_timeout: Duration,
    mut get_from_zero_indexer: ZF,
    get_from_lightwalletd: LF,
) -> Result<service::RawTransaction, tonic::Status>
where
    ZF: FnMut(usize, service::TxFilter) -> ZFut,
    ZFut: Future<Output = Result<service::RawTransaction, tonic::Status>>,
    LF: FnOnce(service::TxFilter) -> LFut,
    LFut: Future<Output = Result<service::RawTransaction, tonic::Status>>,
{
    for index in 0..endpoint_count {
        match tokio_with_wasm::alias::time::timeout(
            request_timeout,
            get_from_zero_indexer(index, filter.clone()),
        )
        .await
        {
            Ok(Ok(transaction)) => return Ok(transaction),
            Ok(Err(status)) if status.code() == tonic::Code::NotFound => {
                tracing::debug!(
                    "zero-indexer endpoint {} has not indexed transaction",
                    index + 1
                );
            }
            Ok(Err(status)) => {
                tracing::warn!(
                    "zero-indexer endpoint {} GetTransaction failed: {status}",
                    index + 1
                );
            }
            Err(_) => {
                tracing::warn!(
                    "zero-indexer endpoint {} GetTransaction timed out",
                    index + 1
                );
            }
        }
    }
    get_from_lightwalletd(filter).await
}

async fn submit_transfer_transactions_with<F, Fut>(
    transactions: NonEmpty<TransactionToSubmit>,
    mut submit: F,
) -> TransferResult
where
    F: FnMut(service::RawTransaction, bool) -> Fut,
    Fut: Future<Output = Result<service::SendResponse, tonic::Status>>,
{
    let mut stopped = false;
    let mut results = Vec::with_capacity(transactions.len());

    for transaction in transactions {
        let tx_id = transaction.txid.to_string();
        let result = if stopped {
            TransferTransactionResult {
                tx_id,
                status: TransferSubmissionStatus::NotAttempted,
                error_code: None,
                error_message: None,
            }
        } else {
            match submit(transaction.raw, transaction.requires_zero_indexer).await {
                Ok(response) if response.error_code == 0 => TransferTransactionResult {
                    tx_id,
                    status: TransferSubmissionStatus::Submitted,
                    error_code: None,
                    error_message: None,
                },
                Ok(response) => {
                    stopped = true;
                    TransferTransactionResult {
                        tx_id,
                        status: TransferSubmissionStatus::Rejected,
                        error_code: Some(response.error_code),
                        error_message: Some(response.error_message),
                    }
                }
                Err(status) => {
                    stopped = true;
                    TransferTransactionResult {
                        tx_id,
                        status: TransferSubmissionStatus::Unknown,
                        error_code: None,
                        error_message: Some(status.to_string()),
                    }
                }
            }
        };
        results.push(result);
    }

    TransferResult::from_transactions(results)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TransferEstimate {
    amount_zats: String,
    fee_zats: String,
    marginal_fee_zats: String,
    transaction_count: usize,
    step_fees_zats: Vec<String>,
}

impl TransferEstimate {
    fn from_amount_and_step_fees(
        amount: Zatoshis,
        step_fees: impl IntoIterator<Item = Zatoshis>,
        marginal_fee_zats: u64,
    ) -> Result<Self, Error> {
        let mut fee = Zatoshis::ZERO;
        let mut step_fees_zats = vec![];

        for step_fee in step_fees {
            fee = (fee + step_fee).ok_or(zcash_protocol::value::BalanceError::Overflow)?;
            step_fees_zats.push(u64::from(step_fee).to_string());
        }

        Ok(Self {
            amount_zats: u64::from(amount).to_string(),
            fee_zats: u64::from(fee).to_string(),
            marginal_fee_zats: marginal_fee_zats.to_string(),
            transaction_count: step_fees_zats.len(),
            step_fees_zats,
        })
    }
}

fn transfer_policies(source: TransferFundingSource) -> (SpendPolicy, TransparentChangePolicy) {
    match source {
        TransferFundingSource::Shielded => (
            SpendPolicy::default(),
            TransparentChangePolicy::ShieldChange,
        ),
        TransferFundingSource::Transparent => transparent_transfer_policies(),
    }
}

fn allow_exact_send_max_fallback(source: TransferFundingSource, has_dynamic_fee: bool) -> bool {
    source == TransferFundingSource::Shielded && has_dynamic_fee
}

fn proposal_fee_required_zats<FeeRuleT, NoteRef>(
    proposal: &zcash_client_backend::proposal::Proposal<FeeRuleT, NoteRef>,
) -> Result<u64, Error> {
    let fee = proposal
        .steps()
        .iter()
        .try_fold(Zatoshis::ZERO, |total, step| {
            (total + step.balance().fee_required())
                .ok_or(zcash_protocol::value::BalanceError::Overflow)
        })?;

    Ok(fee.into())
}

fn proposal_payment_amount_zats<FeeRuleT, NoteRef>(
    proposal: &zcash_client_backend::proposal::Proposal<FeeRuleT, NoteRef>,
) -> Result<u64, Error> {
    let amount = proposal.steps().iter().try_fold(
        Zatoshis::ZERO,
        |step_total, step| -> Result<Zatoshis, Error> {
            step.transaction_request()
                .payments()
                .values()
                .try_fold(step_total, |total, payment| {
                    let payment_amount = payment.amount().ok_or_else(|| {
                        Error::Generic("Max-transfer proposal omitted a payment amount".to_string())
                    })?;
                    (total + payment_amount)
                        .ok_or(zcash_protocol::value::BalanceError::Overflow)
                        .map_err(Error::from)
                })
        },
    )?;

    Ok(amount.into())
}

fn transfer_estimate_from_proposal<FeeRuleT, NoteRef>(
    proposal: &zcash_client_backend::proposal::Proposal<FeeRuleT, NoteRef>,
    marginal_fee_zats: u64,
) -> Result<TransferEstimate, Error> {
    TransferEstimate::from_amount_and_step_fees(
        Zatoshis::from_u64(proposal_payment_amount_zats(proposal)?)?,
        proposal
            .steps()
            .iter()
            .map(|step| step.balance().fee_required()),
        marginal_fee_zats,
    )
}

/// Global prover instance, initialized once on first use
/// This avoids repeatedly loading the expensive Sapling parameters
static PROVER: OnceLock<LocalTxProver> = OnceLock::new();

/// Get or initialize the global prover instance
fn get_prover() -> &'static LocalTxProver {
    PROVER.get_or_init(|| {
        tracing::info!("🔧 Initializing LocalTxProver (loading Sapling parameters)...");
        LocalTxProver::bundled()
    })
}

fn create_and_store_transfer<W, FeeRuleT>(
    db: &mut W,
    network: &Network,
    usk: UnifiedSpendingKey,
    proposal: &zcash_client_backend::proposal::Proposal<FeeRuleT, <W as InputSource>::NoteRef>,
    target_expiry_height: Option<BlockHeight>,
) -> Result<NonEmpty<TxId>, Error>
where
    W: WalletWrite + WalletCommitmentTrees + InputSource,
    FeeRuleT: FeeRule,
    FeeRuleT::Error: Debug,
    <W as WalletRead>::Error: Debug,
    <W as WalletCommitmentTrees>::Error: Debug,
    <W as InputSource>::NoteRef: Debug,
{
    let prover = get_prover();
    let spending_keys = SpendingKeys::from_unified_spending_key(usk);
    let result = create_proposed_transactions::<
        _,
        _,
        <MemoryWalletDb<Network> as InputSource>::Error,
        _,
        <FeeRuleT as FeeRule>::Error,
        _,
    >(
        db,
        network,
        &WalletClock,
        &mut UnwrapErr(SysRng),
        prover,
        prover,
        &spending_keys,
        OvkPolicy::Sender,
        proposal,
        target_expiry_height,
    );

    result.map_err(|error| {
        Error::Generic(format!("Failed to create transfer transactions: {error:?}"))
    })
}

/// Global Orchard proving key instances, initialized once on first use.
/// This avoids repeatedly building the expensive Orchard proving keys.
static ORCHARD_PROVING_KEY_INSECURE_PRE_NU6_2: OnceLock<orchard::circuit::ProvingKey> =
    OnceLock::new();
static ORCHARD_PROVING_KEY_FIXED_POST_NU6_2: OnceLock<orchard::circuit::ProvingKey> =
    OnceLock::new();
static ORCHARD_PROVING_KEY_POST_NU6_3: OnceLock<orchard::circuit::ProvingKey> = OnceLock::new();

/// Global Orchard verifying key instances, initialized once on first use.
/// This avoids repeatedly building the expensive Orchard verifying keys.
static ORCHARD_VERIFYING_KEY_INSECURE_PRE_NU6_2: OnceLock<orchard::circuit::VerifyingKey> =
    OnceLock::new();
static ORCHARD_VERIFYING_KEY_FIXED_POST_NU6_2: OnceLock<orchard::circuit::VerifyingKey> =
    OnceLock::new();
static ORCHARD_VERIFYING_KEY_POST_NU6_3: OnceLock<orchard::circuit::VerifyingKey> = OnceLock::new();

fn orchard_circuit_version_for_branch(
    branch_id: BranchId,
) -> orchard::circuit::OrchardCircuitVersion {
    match branch_id {
        BranchId::Nu6_3 => orchard::circuit::OrchardCircuitVersion::PostNu6_3,
        BranchId::Nu7 => orchard::circuit::OrchardCircuitVersion::PostNu6_3,
        BranchId::Nu6_2 => orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2,
        _ => orchard::circuit::OrchardCircuitVersion::InsecurePreNu6_2,
    }
}

fn orchard_circuit_version_for_pczt(
    pczt: &Pczt,
) -> Result<orchard::circuit::OrchardCircuitVersion, Error> {
    let consensus_branch_id = *pczt.global().consensus_branch_id();
    BranchId::try_from(consensus_branch_id)
        .map(orchard_circuit_version_for_branch)
        .map_err(|_| {
            Error::Generic(format!(
                "Unsupported consensus branch ID in PCZT: 0x{consensus_branch_id:08x}"
            ))
        })
}

fn orchard_proving_key_lock(
    circuit_version: orchard::circuit::OrchardCircuitVersion,
) -> &'static OnceLock<orchard::circuit::ProvingKey> {
    match circuit_version {
        orchard::circuit::OrchardCircuitVersion::InsecurePreNu6_2 => {
            &ORCHARD_PROVING_KEY_INSECURE_PRE_NU6_2
        }
        orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2 => {
            &ORCHARD_PROVING_KEY_FIXED_POST_NU6_2
        }
        orchard::circuit::OrchardCircuitVersion::PostNu6_3 => &ORCHARD_PROVING_KEY_POST_NU6_3,
    }
}

fn orchard_verifying_key_lock(
    circuit_version: orchard::circuit::OrchardCircuitVersion,
) -> &'static OnceLock<orchard::circuit::VerifyingKey> {
    match circuit_version {
        orchard::circuit::OrchardCircuitVersion::InsecurePreNu6_2 => {
            &ORCHARD_VERIFYING_KEY_INSECURE_PRE_NU6_2
        }
        orchard::circuit::OrchardCircuitVersion::FixedPostNu6_2 => {
            &ORCHARD_VERIFYING_KEY_FIXED_POST_NU6_2
        }
        orchard::circuit::OrchardCircuitVersion::PostNu6_3 => &ORCHARD_VERIFYING_KEY_POST_NU6_3,
    }
}

/// Get or initialize the global Orchard proving key for the given circuit version.
fn get_orchard_proving_key(
    circuit_version: orchard::circuit::OrchardCircuitVersion,
) -> &'static orchard::circuit::ProvingKey {
    orchard_proving_key_lock(circuit_version).get_or_init(|| {
        tracing::info!(
            "🔧 Initializing Orchard ProvingKey for {:?}...",
            circuit_version
        );
        orchard::circuit::ProvingKey::build(circuit_version)
    })
}

/// Get or initialize the global Orchard verifying key for the given circuit version.
fn get_orchard_verifying_key(
    circuit_version: orchard::circuit::OrchardCircuitVersion,
) -> &'static orchard::circuit::VerifyingKey {
    orchard_verifying_key_lock(circuit_version).get_or_init(|| {
        tracing::info!(
            "🔧 Initializing Orchard VerifyingKey for {:?}...",
            circuit_version
        );
        orchard::circuit::VerifyingKey::build(circuit_version)
    })
}

/// Database capability required by synchronization that releases locks during RPCs.
///
/// Revisions must change before any rewind mutation, including partial rewinds,
/// and must not be reused while an earlier revision can still be held by a query.
/// Replacing a database must also invalidate outstanding revisions. Ordinary
/// forward synchronization and local transaction writes need not invalidate them.
pub trait WalletChainRevision {
    /// An owned revision that can be compared after a network await.
    type Revision: Eq;

    /// Captures the current revision while the caller holds the database lock.
    fn chain_state_revision(&self) -> Self::Revision;
}

impl<P: Parameters> WalletChainRevision for MemoryWalletDb<P> {
    type Revision = zcash_client_memory::ChainStateRevision;

    fn chain_state_revision(&self) -> Self::Revision {
        MemoryWalletDb::chain_state_revision(self)
    }
}

fn ensure_chain_revision<W: WalletChainRevision>(
    db: &W,
    expected: &W::Revision,
) -> Result<(), Error> {
    if &db.chain_state_revision() == expected {
        Ok(())
    } else {
        Err(Error::HistoryQueryStale)
    }
}

pub struct Wallet<W, T> {
    /// Internal database used to maintain wallet data (e.g. accounts, transactions, cached blocks)
    pub(crate) db: Arc<RwLock<W>>,
    // gRPC client used to connect to a lightwalletd instance for network data
    pub(crate) client: CompactTxStreamerClient<T>,
    zero_indexer_clients: Vec<CompactTxStreamerClient<T>>,
    zero_indexer_send_timeout: Duration,
    pub(crate) network: Network,
    /// The policy used for balance and status queries. Input selection derives a symmetrical
    /// policy from its minimum confirmation count.
    confirmations_policy: ConfirmationsPolicy,
    compact_block_cdn: Option<CompactBlockCdnConfig>,
    /// Note management: the number of notes to maintain in the wallet
    pub(crate) target_note_count: usize,
    /// Note management: the minimum allowed value for split change amounts
    pub(crate) min_split_output_value: u64,
}

impl<W, T> Wallet<W, T> {
    fn query_confirmations_policy(&self) -> ConfirmationsPolicy {
        self.confirmations_policy
    }

    fn selection_confirmations_policy(&self) -> ConfirmationsPolicy {
        let min_confirmations = self
            .confirmations_policy
            .trusted()
            .min(self.confirmations_policy.untrusted());

        ConfirmationsPolicy::new_symmetrical(
            min_confirmations,
            self.confirmations_policy.allow_zero_conf_shielding(),
        )
    }
}

impl<W, T: Clone> Clone for Wallet<W, T> {
    fn clone(&self) -> Self {
        Self {
            db: self.db.clone(),
            client: self.client.clone(),
            zero_indexer_clients: self.zero_indexer_clients.clone(),
            zero_indexer_send_timeout: self.zero_indexer_send_timeout,
            network: self.network,
            confirmations_policy: self.confirmations_policy,
            compact_block_cdn: self.compact_block_cdn.clone(),
            target_note_count: self.target_note_count,
            min_split_output_value: self.min_split_output_value,
        }
    }
}

impl<P, T> Wallet<MemoryWalletDb<P>, T>
where
    P: Parameters,
{
    pub async fn spendability_diagnostics(
        &self,
        account_id: <MemoryWalletDb<P> as WalletRead>::AccountId,
    ) -> Result<zcash_client_memory::SpendabilityDiagnostics, Error> {
        Ok(self
            .db
            .read()
            .await
            .spendability_diagnostics(account_id, self.selection_confirmations_policy())?)
    }

    // Encodes the MemoryWallet into protobuf bytes
    pub async fn db_to_bytes(&self) -> Result<Vec<u8>, Error> {
        let mut memory_wallet_bytes = Vec::new();
        let db = self.db.read().await;
        let encoded_len = db.encoded_len()?;
        memory_wallet_bytes
            .try_reserve_exact(encoded_len)
            .map_err(|e| {
                Error::Generic(format!(
                    "Failed to allocate {encoded_len} bytes for wallet database serialization: {e}"
                ))
            })?;
        db.encode(&mut memory_wallet_bytes)?;
        Ok(memory_wallet_bytes)
    }

    pub async fn db_to_bytes_chunked<F: FnMut(&[u8])>(&self, flush_fn: F) -> Result<(), Error> {
        let db = self.db.read().await;
        db.encode_chunked(flush_fn)?;
        Ok(())
    }
}

impl<W, T, AccountId, NoteRef> Wallet<W, T>
where
    W: WalletRead<AccountId = AccountId>
        + WalletWrite
        + InputSource<
            AccountId = <W as WalletRead>::AccountId,
            Error = <W as WalletRead>::Error,
            NoteRef = NoteRef,
        > + WalletCommitmentTrees,
    AccountId: Copy
        + Debug
        + Eq
        + Hash
        + Default
        + Send
        + Sync
        + ConditionallySelectable
        + Serialize
        + DeserializeOwned
        + 'static,
    NoteRef: Copy + Eq + Ord + Debug,
    Error: From<<W as WalletRead>::Error>,
    <W as WalletRead>::Error: std::error::Error + Send + Sync + 'static,
    <W as WalletCommitmentTrees>::Error: std::error::Error + Send + Sync + 'static,
    // GRPC connection Trait Bounds
    T: GrpcService<tonic::body::Body> + Clone,
    T::Error: Into<StdError>,
    T::ResponseBody: Body<Data = Bytes> + std::marker::Send + 'static,
    <T::ResponseBody as Body>::Error: Into<StdError> + std::marker::Send,
{
    pub fn set_zero_indexer_options(&mut self, clients: Vec<T>, send_timeout: Duration) {
        self.zero_indexer_clients = clients
            .into_iter()
            .map(CompactTxStreamerClient::new)
            .collect();
        self.zero_indexer_send_timeout = send_timeout;
    }

    async fn resolve_transfer_fee(&self, supplied_fee: Option<u64>) -> Result<Option<u64>, Error> {
        if let Some(fee) = supplied_fee {
            dynamic_zip317_fee_rule(fee)?;
            return Ok(Some(fee));
        }

        let mut client = self.client.clone();
        let recommended = tokio_with_wasm::alias::time::timeout(
            STANDARD_FEE_QUERY_TIMEOUT,
            client.get_standard_fee(service::Empty {}),
        )
        .await;
        match recommended {
            Ok(Ok(response)) => {
                let fee = response.into_inner().fee_zat;
                if dynamic_zip317_fee_rule(fee).is_ok() {
                    Ok(Some(fee))
                } else {
                    tracing::warn!(
                        fee,
                        "Invalid recommended marginal fee; using standard ZIP-317 fee"
                    );
                    Ok(None)
                }
            }
            Ok(Err(error)) => {
                tracing::warn!(%error, "Standard fee RPC unavailable; using standard ZIP-317 fee");
                Ok(None)
            }
            Err(_) => {
                tracing::warn!("Standard fee RPC timed out; using standard ZIP-317 fee");
                Ok(None)
            }
        }
    }

    fn transfer_confirmations_policy(
        &self,
        db: &W,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<ConfirmationsPolicy, Error> {
        expiry_delta_blocks
            .map(validate_expiry_delta_blocks)
            .transpose()?;
        if expiry_delta_blocks.is_some() {
            ordinary::confirmations_policy(
                db,
                &self.network,
                self.selection_confirmations_policy(),
            )?
            .ok_or_else(|| {
                Error::Generic(
                    "Wallet must be synced to an ordinary anchor for custom expiry".into(),
                )
            })
        } else {
            Ok(self.selection_confirmations_policy())
        }
    }

    pub fn new(db: W, client: T, network: Network) -> Result<Self, Error> {
        Self::new_with_confirmations_policy(db, client, network, ConfirmationsPolicy::default())
    }

    /// Creates a wallet with a runtime confirmations policy, not persisted in the database.
    /// Balance and status queries use this policy as-is; input selection uses a symmetrical policy
    /// whose trusted and untrusted values are both the minimum of this policy's values.
    pub fn new_with_confirmations_policy(
        db: W,
        client: T,
        network: Network,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<Self, Error> {
        Self::new_with_runtime_config(
            db,
            client,
            vec![],
            network,
            confirmations_policy,
            None,
            DEFAULT_ZERO_INDEXER_SEND_TIMEOUT,
        )
    }

    pub(crate) fn new_with_runtime_config(
        db: W,
        client: T,
        zero_indexer_clients: Vec<T>,
        network: Network,
        confirmations_policy: ConfirmationsPolicy,
        compact_block_cdn: Option<CompactBlockCdnConfig>,
        zero_indexer_send_timeout: Duration,
    ) -> Result<Self, Error> {
        get_prover();
        Ok(Wallet {
            db: Arc::new(RwLock::new(db)),
            client: CompactTxStreamerClient::new(client),
            zero_indexer_clients: zero_indexer_clients
                .into_iter()
                .map(CompactTxStreamerClient::new)
                .collect(),
            zero_indexer_send_timeout,
            network,
            confirmations_policy,
            compact_block_cdn,
            target_note_count: 4,
            min_split_output_value: 10000000,
        })
    }

    pub async fn create_account(
        &self,
        account_name: &str,
        seed_phrase: &str,
        passphrase: &str,
        account_hd_index: u32,
        birthday_height: Option<u32>,
        key_source: Option<&str>,
    ) -> Result<AccountId, Error> {
        // decode the mnemonic and derive the first account
        let (usk, seed_fp) =
            usk_from_seed_str(seed_phrase, passphrase, account_hd_index, &self.network)?;
        let ufvk = usk.to_unified_full_viewing_key();

        let derivation =
            Zip32Derivation::new(seed_fp, zip32::AccountId::try_from(account_hd_index)?);

        tracing::info!("Key successfully decoded. Importing into wallet");

        self.import_account_ufvk(
            account_name,
            &ufvk,
            birthday_height,
            AccountPurpose::Spending {
                derivation: Some(derivation),
            },
            key_source,
        )
        .await
    }

    /// Import a watch-only spending account from an encoded UFVK (hardware wallet flow).
    ///
    /// The ZIP-32 seed fingerprint and HD index exported by the device (e.g. Keystone
    /// `zcash-accounts` QR) are recorded as the account derivation so that PCZTs created
    /// from this account carry the metadata the device needs to locate its signing keys.
    ///
    /// This is a thin wrapper around `import_account_ufvk`; it adds no new
    /// import logic.
    pub async fn create_account_ufvk(
        &self,
        account_name: &str,
        ufvk_encoded: &str,
        seed_fingerprint: [u8; 32],
        account_hd_index: u32,
        birthday_height: Option<u32>,
        key_source: Option<&str>,
    ) -> Result<AccountId, Error> {
        let ufvk = UnifiedFullViewingKey::decode(&self.network, ufvk_encoded)
            .map_err(|error| Error::KeyDecoding(error.to_string()))?;

        let derivation = Zip32Derivation::new(
            SeedFingerprint::from_bytes(seed_fingerprint),
            zip32::AccountId::try_from(account_hd_index)?,
        );

        tracing::info!("Importing UFVK account (hd_index: {})", account_hd_index);

        self.import_account_ufvk(
            account_name,
            &ufvk,
            birthday_height,
            AccountPurpose::Spending {
                derivation: Some(derivation),
            },
            key_source,
        )
        .await
    }

    /// Prove and broadcast an externally signed PCZT (hardware wallet flow).
    ///
    /// The PCZT must already contain all required signatures (e.g. added by a Keystone
    /// device). Proof generation runs locally; `sapling_proof_gen_key` is only needed
    /// when the PCZT spends Sapling notes, which never happens for hardware-wallet
    /// accounts (Keystone supports transparent + Orchard only).
    ///
    /// This composes `pczt_prove` and `pczt_send` without modification.
    pub async fn pczt_prove_and_send(
        &self,
        pczt: Pczt,
        sapling_proof_gen_key: Option<ProofGenerationKey>,
    ) -> Result<String, Error> {
        let proved = self.pczt_prove(pczt, sapling_proof_gen_key).await?;
        self.pczt_send(proved).await
    }

    async fn import_account_ufvk(
        &self,
        account_name: &str,
        ufvk: &UnifiedFullViewingKey,
        birthday_height: Option<u32>,
        purpose: AccountPurpose,
        key_source: Option<&str>,
    ) -> Result<AccountId, Error> {
        // Check if an account with this name already exists
        match self.get_account_id_by_name(account_name).await {
            Ok(_) => {
                // Account exists
                return Err(Error::AccountExists(account_name.to_string()));
            }
            Err(Error::AccountNameNotFound) => {
                // Account doesn't exist, continue
            }
            Err(e) => {
                // Some other error occurred
                return Err(e);
            }
        }

        let mut client = self.client.clone();
        let birthday = match birthday_height {
            Some(height) => height,
            None => {
                let chain_tip: u32 = client
                    .get_latest_block(service::ChainSpec::default())
                    .await?
                    .into_inner()
                    .height
                    .try_into()
                    .map_err(|_| Error::Birthday)?;
                chain_tip.checked_sub(100).ok_or(Error::Birthday)?
            }
        };
        // Construct an `AccountBirthday` for the account's birthday.
        let birthday = {
            // Fetch the tree state corresponding to the last block prior to the wallet's
            // birthday height. NOTE: THIS APPROACH LEAKS THE BIRTHDAY TO THE SERVER!
            let request = service::BlockId {
                height: birthday.checked_sub(1).ok_or(Error::Birthday)?.into(),
                ..Default::default()
            };
            let treestate = client.get_tree_state(request).await?.into_inner();
            AccountBirthday::from_treestate(treestate, None).map_err(|_| Error::Birthday)?
        };

        // Import the account first
        let account_id = {
            let mut db = self.db.write().await;
            db.import_account_ufvk(account_name, ufvk, &birthday, purpose, key_source)?
                .id()
        };

        // IMPORTANT: Ensure that the transparent address at diversifier index 0 is stored.
        //
        // Account::new() uses AllAvailableKeys which requires ALL key types to have valid
        // receivers. When Sapling has no valid diversifier at index 0 (which is common), it
        // skips to a higher index (e.g., 7). This means the transparent address at index 0
        // is never stored in account.addresses().
        //
        // External tools (exchanges, other wallets) typically derive transparent addresses
        // starting from index 0 (BIP44 path m/44'/133'/account'/0/0). If funds were sent
        // to the index-0 transparent address, get_transparent_receivers() won't return it,
        // refresh_utxos() won't query lightwalletd for it, and the balance will show as 0.
        //
        // Fix: Explicitly store the address at diversifier 0 using ALLOW_ALL (which does
        // not require Sapling), then also generate the next available address for metadata.
        use zcash_keys::keys::UnifiedAddressRequest;
        use zip32::DiversifierIndex;

        {
            let mut db = self.db.write().await;
            // Store address at diversifier 0 to ensure low-index transparent addresses
            // are discoverable by get_transparent_receivers() during sync.
            let _ = db.get_address_for_index(
                account_id,
                DiversifierIndex::new(),
                UnifiedAddressRequest::ALLOW_ALL,
            )?;
            // Also generate the next available address for transparent address metadata
            // needed when spending transparent funds.
            let _ = db.get_next_available_address(account_id, UnifiedAddressRequest::ALLOW_ALL)?;
        }

        Ok(account_id)
    }

    pub async fn sync(&self) -> Result<(), Error>
    where
        W: WalletChainRevision,
    {
        let mut client = self.client.clone();
        // TODO: This should be held in the Wallet struct so we can download in parallel
        let db_cache = MemBlockCache::new();
        let mut block_source =
            CdnFallbackBlockSource::new(self.network, self.compact_block_cdn.clone());

        let mut db = self.db.write().await;
        run_with_block_source(
            &mut client,
            &mut block_source,
            &self.network.clone(),
            &db_cache,
            &mut *db,
            BATCH_SIZE,
        )
        .await
        .map_err(|error| -> Error { error.into() })?;
        drop(db);
        self.process_pending_transaction_requests().await
    }

    /// Runs a single batch of the sync process without looping.
    /// Returns `true` if a scan range was processed, `false` if no scan ranges were suggested.
    pub async fn sync_next_batch(&self, batch_size: Option<u32>) -> Result<bool, Error>
    where
        W: WalletChainRevision,
    {
        let mut client = self.client.clone();
        let db_cache = MemBlockCache::new();
        let mut block_source =
            CdnFallbackBlockSource::new(self.network, self.compact_block_cdn.clone());

        let mut db = self.db.write().await;
        let did_work = run_next_batch_with_block_source(
            &mut client,
            &mut block_source,
            &self.network.clone(),
            &db_cache,
            &mut *db,
            batch_size.unwrap_or(BATCH_SIZE),
        )
        .await
        .map_err(|error| -> Error { error.into() })?;
        drop(db);
        self.process_pending_transaction_requests().await?;
        Ok(did_work)
    }

    pub async fn sync_next_batch_optimized(&self, batch_size: Option<u32>) -> Result<bool, Error>
    where
        W: WalletChainRevision,
    {
        let mut client = self.client.clone();
        let db_cache = MemBlockCache::new();
        let mut block_source =
            CdnFallbackBlockSource::new(self.network, self.compact_block_cdn.clone());

        let mut db = self.db.write().await;
        let did_work = run_next_batch_optimized_with_block_source(
            &mut client,
            &mut block_source,
            &self.network.clone(),
            &db_cache,
            &mut *db,
            batch_size.unwrap_or(BATCH_SIZE),
        )
        .await
        .map_err(|error| -> Error { error.into() })?;
        drop(db);
        self.process_pending_transaction_requests().await?;
        Ok(did_work)
    }

    // The check and mutation must use the same guard: checking before acquiring
    // the write lock would leave a race with a concurrent chain rewind.
    async fn checked_history_write(
        &self,
        revision: &W::Revision,
    ) -> Result<tokio::sync::RwLockWriteGuard<'_, W>, Error>
    where
        W: WalletChainRevision,
    {
        let db = self.db.write().await;
        ensure_chain_revision(&*db, revision)?;
        Ok(db)
    }

    async fn get_transaction_with_fallback(
        &self,
        filter: service::TxFilter,
        prefer_zero_indexer: bool,
    ) -> Result<service::RawTransaction, tonic::Status> {
        let mut lightwalletd = self.client.clone();
        if prefer_zero_indexer && !self.zero_indexer_clients.is_empty() {
            let clients = self.zero_indexer_clients.clone();
            get_from_zero_indexers_with_fallback(
                clients.len(),
                filter,
                self.zero_indexer_send_timeout,
                move |index, filter| {
                    let mut client = clients[index].clone();
                    async move {
                        client
                            .get_transaction(filter)
                            .await
                            .map(tonic::Response::into_inner)
                    }
                },
                |filter| async move {
                    lightwalletd
                        .get_transaction(filter)
                        .await
                        .map(tonic::Response::into_inner)
                },
            )
            .await
        } else {
            lightwalletd
                .get_transaction(filter)
                .await
                .map(tonic::Response::into_inner)
        }
    }

    pub(crate) async fn process_pending_transaction_requests(&self) -> Result<(), Error>
    where
        W: WalletChainRevision,
    {
        // Snapshot requests and their chain revision together. Never keep a
        // database guard across an RPC or stream await. Each reply is checked
        // under its write guard so a rewind cannot be undone by an old reply.
        let (revision, transaction_requests) = {
            let db = self.db.read().await;
            let requests = db.transaction_data_requests()?.into_iter().fold(
                BTreeMap::new(),
                |mut requests, request| {
                    match request {
                        TransactionDataRequest::GetStatus(txid) => {
                            requests.entry(txid).or_insert(false);
                        }
                        TransactionDataRequest::Enhancement(txid) => {
                            requests.insert(txid, true);
                        }
                        _ => {}
                    }
                    requests
                },
            );
            (db.chain_state_revision(), requests)
        };

        let mut client = self.client.clone();
        for (requested_txid, needs_enhancement) in transaction_requests {
            let prefer_zero_indexer = if needs_enhancement {
                false
            } else {
                let db = self.db.read().await;
                matches!(db.get_transaction(requested_txid), Ok(Some(tx)) if requires_zero_indexer(&tx))
            };
            let response = self
                .get_transaction_with_fallback(
                    service::TxFilter {
                        block: None,
                        index: 0,
                        hash: requested_txid.as_ref().to_vec(),
                    },
                    prefer_zero_indexer,
                )
                .await;
            let mut db = self.checked_history_write(&revision).await?;
            let raw = match response {
                Ok(raw) => raw,
                Err(status) if !needs_enhancement && status.code() == tonic::Code::NotFound => {
                    db.set_transaction_status(
                        requested_txid,
                        TransactionStatus::TxidNotRecognized,
                    )?;
                    continue;
                }
                Err(status) => return Err(status.into()),
            };

            let status = transaction_status_from_raw_height(requested_txid, raw.height)?;
            if !needs_enhancement {
                db.set_transaction_status(requested_txid, status)?;
                continue;
            }

            let mined_height = match status {
                TransactionStatus::Mined(height) => Some(height),
                TransactionStatus::NotInMainChain => None,
                TransactionStatus::TxidNotRecognized => unreachable!(),
            };
            let parse_height = match mined_height {
                Some(height) => height,
                None => db
                    .chain_height()?
                    .map(|height| height + 1)
                    .or_else(|| self.network.activation_height(NetworkUpgrade::Sapling))
                    .ok_or_else(|| {
                        Error::Generic(format!(
                            "Unable to determine consensus branch for transaction {requested_txid}"
                        ))
                    })?,
            };
            let tx = zcash_primitives::transaction::Transaction::read(
                raw.data.as_slice(),
                BranchId::for_height(&self.network, parse_height),
            )?;
            if tx.txid() != requested_txid {
                return Err(Error::Generic(format!(
                    "Transaction data mismatch: requested {requested_txid}, received {}",
                    tx.txid()
                )));
            }

            decrypt_and_store_transaction(&self.network, &mut *db, &tx, mined_height)?;
        }

        // Processing change history may advance the recovery gap and discover
        // another window. Drain those windows before reporting sync complete.
        let mut completed_address_requests = BTreeSet::new();
        // This limits one invocation, not the account's address space. A peer
        // must not be able to grow the recovery window indefinitely in one call.
        // On exhaustion, retry with this same wallet instance to retain progress;
        // reloading an older snapshot also restores its older recovery cursors.
        let mut remaining_address_requests = 4096;
        loop {
            let address_requests = {
                let db = self.db.read().await;
                ensure_chain_revision(&*db, &revision)?;
                db.transaction_data_requests()?
                    .into_iter()
                    .filter_map(|request| match request {
                        TransactionDataRequest::TransactionsInvolvingAddress(request) => {
                            Some(request)
                        }
                        _ => None,
                    })
                    .filter(|request| !completed_address_requests.contains(request))
                    .collect::<BTreeSet<_>>()
            };

            let mut made_progress = false;
            for request in address_requests {
                if !transaction_request_is_due(request.request_at()) {
                    continue;
                }

                let chain_tip_height = {
                    let db = self.db.read().await;
                    ensure_chain_revision(&*db, &revision)?;
                    db.chain_height()?.ok_or_else(|| {
                        Error::Generic(
                        "Unable to process transparent transaction request without chain height"
                            .to_string(),
                    )
                    })?
                };
                let block_range_end = request
                    .block_range_end()
                    .unwrap_or(chain_tip_height + 1)
                    .min(chain_tip_height + 1);
                if block_range_end <= request.block_range_start() {
                    continue;
                }
                let as_of_height = block_range_end - 1;
                consume_transparent_history_budget(&mut remaining_address_requests)?;

                let mut transactions = client
                    .get_taddress_txids(service::TransparentAddressBlockFilter {
                        address: request.address().encode(&self.network),
                        range: Some(service::BlockRange {
                            start: Some(service::BlockId {
                                height: u64::from(request.block_range_start()),
                                hash: vec![],
                            }),
                            end: Some(service::BlockId {
                                height: u64::from(as_of_height),
                                hash: vec![],
                            }),
                            pool_types: vec![],
                        }),
                    })
                    .await?
                    .into_inner();

                while let Some(raw) = transactions.try_next().await? {
                    let mut db = self.checked_history_write(&revision).await?;
                    let mined_height = match raw.height {
                        0 | u64::MAX => {
                            return Err(Error::Generic(format!(
                                "Transparent transaction query returned unmined transaction at height {}",
                                raw.height
                            )));
                        }
                        height => BlockHeight::from_u32(u32::try_from(height).map_err(|_| {
                            Error::Generic(format!(
                                "Invalid mined height {height} returned for transparent transaction"
                            ))
                        })?),
                    };
                    let tx = zcash_primitives::transaction::Transaction::read(
                        raw.data.as_slice(),
                        BranchId::for_height(&self.network, mined_height),
                    )?;

                    decrypt_and_store_transaction(
                        &self.network,
                        &mut *db,
                        &tx,
                        Some(mined_height),
                    )?;
                }

                let mut db = self.checked_history_write(&revision).await?;
                db.notify_address_checked(request.clone(), as_of_height)?;
                completed_address_requests.insert(request);
                made_progress = true;
            }
            if !made_progress {
                break;
            }
        }

        Ok(())
    }

    /// Benchmark helper: download a contiguous block range over gRPC-web and
    /// discard it (no DB write, no scan). Returns the number of blocks fetched.
    /// Used to measure raw download throughput and concurrency scaling.
    pub async fn bench_download_range(&self, start_height: u32, count: u32) -> Result<u32, Error> {
        use zcash_client_backend::proto::compact_formats::CompactBlock;
        use zcash_client_backend::proto::service;

        let mut client = self.client.clone();
        let start_id = service::BlockId {
            height: start_height as u64,
            ..Default::default()
        };
        let end_id = service::BlockId {
            height: (start_height + count - 1) as u64,
            ..Default::default()
        };

        let blocks: Vec<CompactBlock> = client
            .get_block_range(service::BlockRange {
                start: Some(start_id),
                end: Some(end_id),
                pool_types: vec![],
            })
            .await
            .map_err(|e| Error::Generic(format!("gRPC error: {e}")))?
            .into_inner()
            .try_collect()
            .await
            .map_err(|e| Error::Generic(format!("Stream error: {e}")))?;

        Ok(blocks.len() as u32)
    }

    /// Execute a full journal-aware sync cycle:
    /// 1) Prepare (download from network, return journal data)
    /// 2) JS persists the journal data
    /// 3) scan_journal_entry applies the scan
    ///
    /// This method handles step 1: network operations + data capture.
    /// Returns None if fully synced, Some(journal_bytes) with captured data.
    fn scan_with_reorg_handling<CaT: zcash_client_backend::data_api::chain::BlockCache>(
        network: &crate::Network,
        db_cache: &CaT,
        db: &mut W,
        start_height: zcash_protocol::consensus::BlockHeight,
        chain_state: &zcash_client_backend::data_api::chain::ChainState,
        limit: usize,
        optimized: bool,
    ) -> Result<bool, Error>
    where
        CaT::Error: std::fmt::Display + Send,
    {
        use zcash_client_backend::data_api::chain::error::Error as ChainError;

        let scan_result = if optimized {
            zcash_client_backend::data_api::chain::scan_cached_blocks_optimized(
                network,
                db_cache,
                db,
                start_height,
                chain_state,
                limit,
            )
        } else {
            zcash_client_backend::data_api::chain::scan_cached_blocks(
                network,
                db_cache,
                db,
                start_height,
                chain_state,
                limit,
            )
        };

        match scan_result {
            Ok(_) => Ok(false),
            Err(ChainError::Scan(ref scan_err)) if scan_err.is_continuity_error() => {
                let rewind_height = scan_err.at_height().saturating_sub(10);
                tracing::warn!(
                    "Chain reorg detected at {}, rewinding to {}",
                    scan_err.at_height(),
                    rewind_height,
                );
                db.truncate_to_height(rewind_height)
                    .map_err(|e| Error::Generic(format!("Truncate failed: {e}")))?;
                Ok(true)
            }
            Err(e) => Err(Error::Generic(format!("Scan error: {e}"))),
        }
    }

    /// Prepare one journal batch. When `refresh` is false the caller must have
    /// run [`Self::sync_session_setup`] once for this catch-up session; the
    /// per-batch subtree-root / chain-tip / transparent-UTXO round-trips are then
    /// skipped, which is the dominant fixed per-batch cost.
    pub async fn prepare_sync_batch(
        &self,
        batch_size: Option<u32>,
        refresh: bool,
    ) -> Result<Option<Vec<u8>>, Error>
    where
        W: WalletChainRevision,
    {
        self.prepare_sync_batch_impl(batch_size, false, refresh, None)
            .await
    }

    /// Run the session-level setup (subtree roots, chain tip, transparent UTXOs)
    /// once before a multi-batch catch-up. Subsequent batches can then be called
    /// with `refresh = false` to skip these fixed per-batch network round-trips.
    pub async fn sync_session_setup(&self) -> Result<(), Error> {
        use zcash_client_backend::proto::service;

        let mut client = self.client.clone();
        let mut db = self.db.write().await;

        let tip_height: zcash_protocol::consensus::BlockHeight = client
            .get_latest_block(service::ChainSpec::default())
            .await
            .map_err(|e| Error::Generic(format!("gRPC error: {e}")))?
            .get_ref()
            .height
            .try_into()
            .map_err(|_| Error::Generic("Invalid tip height".into()))?;
        db.update_chain_tip(tip_height)
            .map_err(|e| Error::Generic(format!("DB error: {e}")))?;

        self.do_update_subtree_roots(&mut client, &mut *db, tip_height)
            .await?;

        self.refresh_transparent_utxos_for_all_accounts(&mut client, &mut *db)
            .await?;

        Ok(())
    }

    /// Optimized journal-aware batch: identical to [`prepare_sync_batch`] but uses
    /// External-only IVK scanning (with targeted Internal fallback) for contiguous
    /// forward ranges. Non-contiguous ranges fall back to full scanning internally.
    pub async fn prepare_sync_batch_optimized(
        &self,
        batch_size: Option<u32>,
    ) -> Result<Option<Vec<u8>>, Error>
    where
        W: WalletChainRevision,
    {
        self.prepare_sync_batch_impl(batch_size, true, true, None)
            .await
    }

    /// Benchmark helper: run one baseline journal batch and return per-stage
    /// timings (ms) as JSON `{"subtree","setup","download","scan"}`, or None when
    /// synced. When `refresh` is false the session-level setup is skipped (caller
    /// must have invoked `sync_session_setup` first).
    pub async fn bench_prepare_sync_batch_timed(
        &self,
        batch_size: Option<u32>,
        refresh: bool,
    ) -> Result<Option<String>, Error>
    where
        W: WalletChainRevision,
    {
        let mut t = [0.0f64; 4];
        let r = self
            .prepare_sync_batch_impl(batch_size, false, refresh, Some(&mut t))
            .await?;
        Ok(r.map(|_| {
            format!(
                "{{\"subtree\":{:.0},\"setup\":{:.0},\"download\":{:.0},\"scan\":{:.0}}}",
                t[0], t[1], t[2], t[3]
            )
        }))
    }

    async fn prepare_sync_batch_impl(
        &self,
        batch_size: Option<u32>,
        optimized: bool,
        refresh: bool,
        timings: Option<&mut [f64; 4]>,
    ) -> Result<Option<Vec<u8>>, Error>
    where
        W: WalletChainRevision,
    {
        use prost::Message;
        use zcash_client_backend::data_api::scanning::{ScanPriority, ScanRange};
        use zcash_client_backend::proto::compact_formats::CompactBlock;
        use zcash_client_backend::proto::service::{self, BlockId};

        let batch_size = batch_size.unwrap_or(BATCH_SIZE);
        let mut client = self.client.clone();
        let mut block_source =
            CdnFallbackBlockSource::new(self.network, self.compact_block_cdn.clone());

        // We need a write lock for update_chain_tip, suggest_scan_ranges, etc.
        let mut db = self.db.write().await;

        let t_stage0 = js_sys::Date::now();

        let tip_height = if refresh {
            Some(
                client
                    .get_latest_block(service::ChainSpec::default())
                    .await
                    .map_err(|e| Error::Generic(format!("gRPC error: {e}")))?
                    .get_ref()
                    .height
                    .try_into()
                    .map_err(|_| Error::Generic("Invalid tip height".into()))?,
            )
        } else {
            None
        };
        let t_after_tip = js_sys::Date::now();

        // Steps 1/2/2.5 are session-level state (subtree roots, chain tip,
        // transparent UTXOs) that do not change while replaying a bounded scan
        // window. When `refresh` is false the caller has run them once via
        // `sync_session_setup`, so we skip the per-batch network round-trips.
        if let Some(tip_height) = tip_height {
            // 1. Update subtree roots
            self.do_update_subtree_roots(&mut client, &mut *db, tip_height)
                .await?;
        }

        let t_sub = js_sys::Date::now();

        if let Some(tip_height) = tip_height {
            // 2. Update chain tip
            db.update_chain_tip(tip_height)
                .map_err(|e| Error::Generic(format!("DB error: {e}")))?;

            // 2.5. Refresh transparent UTXOs for all accounts
            self.refresh_transparent_utxos_for_all_accounts(&mut client, &mut *db)
                .await?;
        }

        // 3. Handle verify-priority ranges inline (not journaled, they're small)
        {
            let db_cache = MemBlockCache::new();
            loop {
                let scan_ranges = db
                    .suggest_scan_ranges()
                    .map_err(|e| Error::Generic(format!("{e}")))?;
                match scan_ranges.first() {
                    Some(scan_range) if scan_range.priority() == ScanPriority::Verify => {
                        let chain_state = Self::fetch_chain_state(
                            &mut client,
                            scan_range.block_range().start - 1,
                        )
                        .await?;
                        Self::download_and_insert_blocks(
                            &mut client,
                            &mut block_source,
                            &db_cache,
                            scan_range,
                            chain_state.block_hash(),
                        )
                        .await?;
                        let rewound = Self::scan_with_reorg_handling(
                            &self.network,
                            &db_cache,
                            &mut *db,
                            scan_range.block_range().start,
                            &chain_state,
                            scan_range.len(),
                            optimized,
                        )?;
                        db_cache
                            .delete(scan_range.clone())
                            .await
                            .map_err(|e| Error::Generic(format!("{e}")))?;
                        if rewound {
                            continue;
                        }
                    }
                    _ => break,
                }
            }
        }

        let t_stage_setup = js_sys::Date::now();

        // 4. Get next scan range
        let scan_ranges = db
            .suggest_scan_ranges()
            .map_err(|e| Error::Generic(format!("{e}")))?;
        let first_batch = scan_ranges
            .into_iter()
            .flat_map(|r| {
                (0..).scan(r, |acc, _| {
                    if acc.is_empty() {
                        None
                    } else if let Some((cur, next)) =
                        acc.split_at(acc.block_range().start + batch_size)
                    {
                        *acc = next;
                        Some(cur)
                    } else {
                        let cur = acc.clone();
                        let end_val = acc.block_range().end;
                        *acc = ScanRange::from_parts(end_val..end_val, acc.priority());
                        Some(cur)
                    }
                })
            })
            .next();

        let scan_range = match first_batch {
            Some(r) => r,
            None => {
                drop(db);
                self.process_pending_transaction_requests().await?;
                return Ok(None);
            }
        };

        // 5. Download tree state for range.start - 1. This anchors CDN data to
        // lightwalletd before the blocks are inserted or scanned.
        let tree_state_proto = client
            .get_tree_state(BlockId {
                height: (scan_range.block_range().start - 1).into(),
                hash: vec![],
            })
            .await
            .map_err(|e| Error::Generic(format!("gRPC error: {e}")))?
            .into_inner();
        let chain_state = tree_state_proto
            .to_chain_state()
            .map_err(|e| Error::Generic(format!("Failed to parse ChainState: {e}")))?;

        // 6. Download compact blocks for the range.
        let start_id = service::BlockId {
            height: scan_range.block_range().start.into(),
            ..Default::default()
        };
        let end_id = service::BlockId {
            height: (scan_range.block_range().end - 1).into(),
            ..Default::default()
        };
        let compact_blocks: Vec<CompactBlock> = block_source
            .get_block_range(
                &mut client,
                service::BlockRange {
                    start: Some(start_id),
                    end: Some(end_id),
                    pool_types: vec![],
                },
                Some(chain_state.block_hash()),
            )
            .await
            .map_err(|e| Error::Generic(format!("Block download error: {e}")))?;

        // 7. Serialize into journal entry format:
        //    [range_start:u32 | range_end:u32 | tree_state_len:u32 | tree_state_bytes | (block_len:u32 + block_bytes)*]
        let range_start: u32 = scan_range.block_range().start.into();
        let range_end: u32 = scan_range.block_range().end.into();
        let tree_state_bytes = tree_state_proto.encode_to_vec();
        let ts_len = tree_state_bytes.len() as u32;

        let mut blocks_bytes = Vec::new();
        for cb in &compact_blocks {
            let encoded = cb.encode_to_vec();
            blocks_bytes.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
            blocks_bytes.extend_from_slice(&encoded);
        }

        let mut journal_data = Vec::with_capacity(12 + tree_state_bytes.len() + blocks_bytes.len());
        journal_data.extend_from_slice(&range_start.to_le_bytes());
        journal_data.extend_from_slice(&range_end.to_le_bytes());
        journal_data.extend_from_slice(&ts_len.to_le_bytes());
        journal_data.extend_from_slice(&tree_state_bytes);
        journal_data.extend_from_slice(&blocks_bytes);

        let t_stage_dl = js_sys::Date::now();

        // 8. Now scan the blocks we just downloaded (with reorg handling)
        let db_cache = MemBlockCache::new();
        db_cache
            .insert(compact_blocks)
            .await
            .map_err(|e| Error::Generic(format!("{e}")))?;
        let rewound = Self::scan_with_reorg_handling(
            &self.network,
            &db_cache,
            &mut *db,
            scan_range.block_range().start,
            &chain_state,
            scan_range.len(),
            optimized,
        )?;
        if rewound {
            drop(db);
            self.process_pending_transaction_requests().await?;
            return Ok(None);
        }

        let t_stage_scan = js_sys::Date::now();
        if let Some(t) = timings {
            t[0] = t_sub - t_after_tip; // subtree roots
            t[1] = (t_after_tip - t_stage0) + (t_stage_setup - t_sub); // chain tip + UTXO refresh + verify
            t[2] = t_stage_dl - t_stage_setup; // block + tree-state download
            t[3] = t_stage_scan - t_stage_dl; // scan + put_blocks
        }

        drop(db);
        self.process_pending_transaction_requests().await?;
        Ok(Some(journal_data))
    }

    /// Scan a journal entry (for recovery from base snapshot + journal).
    /// This consumes the raw journal entry bytes and applies the scan to the wallet DB.
    pub async fn scan_journal_entry(&self, journal_data: &[u8]) -> Result<bool, Error>
    where
        W: WalletChainRevision,
    {
        use prost::Message;
        use zcash_client_backend::proto::compact_formats::CompactBlock;
        use zcash_client_backend::proto::service;

        if journal_data.len() < 12 {
            return Err(Error::Generic("Journal data too short".into()));
        }

        let range_start = u32::from_le_bytes(journal_data[0..4].try_into().unwrap());
        let range_end = u32::from_le_bytes(journal_data[4..8].try_into().unwrap());
        let ts_len = u32::from_le_bytes(journal_data[8..12].try_into().unwrap()) as usize;

        if journal_data.len() < 12 + ts_len {
            return Err(Error::Generic("Journal data truncated (tree state)".into()));
        }

        let tree_state_bytes = &journal_data[12..12 + ts_len];
        let blocks_data = &journal_data[12 + ts_len..];

        let tree_state_proto = service::TreeState::decode(tree_state_bytes)
            .map_err(|e| Error::Generic(format!("Failed to decode TreeState: {e}")))?;
        let chain_state = tree_state_proto
            .to_chain_state()
            .map_err(|e| Error::Generic(format!("Failed to parse ChainState: {e}")))?;

        // Deserialize compact blocks
        let mut compact_blocks = Vec::new();
        let mut offset = 0;
        while offset + 4 <= blocks_data.len() {
            let block_len =
                u32::from_le_bytes(blocks_data[offset..offset + 4].try_into().unwrap()) as usize;
            offset += 4;
            if offset + block_len > blocks_data.len() {
                return Err(Error::Generic("Journal data truncated (block)".into()));
            }
            let cb = CompactBlock::decode(&blocks_data[offset..offset + block_len])
                .map_err(|e| Error::Generic(format!("Failed to decode CompactBlock: {e}")))?;
            compact_blocks.push(cb);
            offset += block_len;
        }

        let db_cache = MemBlockCache::new();
        db_cache
            .insert(compact_blocks)
            .await
            .map_err(|e| Error::Generic(format!("{e}")))?;

        let from_height = zcash_protocol::consensus::BlockHeight::from_u32(range_start);
        let block_count = (range_end - range_start) as usize;

        let mut db = self.db.write().await;
        let rewound = Self::scan_with_reorg_handling(
            &self.network,
            &db_cache,
            &mut *db,
            from_height,
            &chain_state,
            block_count,
            false,
        )?;
        if rewound {
            return Ok(true);
        }

        // Check if more work remains
        let remaining = db
            .suggest_scan_ranges()
            .map_err(|e| Error::Generic(format!("{e}")))?;
        let has_more = remaining.iter().any(|r| !r.is_empty());

        drop(db);
        self.process_pending_transaction_requests().await?;
        Ok(has_more)
    }

    /// Replay multiple journal entries in sequence (for recovery from base snapshot + journal).
    pub async fn replay_journal_entries(&self, entries: Vec<Vec<u8>>) -> Result<(), Error>
    where
        W: WalletChainRevision,
    {
        for (i, entry) in entries.iter().enumerate() {
            tracing::info!("Replaying journal entry {}/{}", i + 1, entries.len());
            self.scan_journal_entry(entry).await?;
        }
        Ok(())
    }

    // Internal helper: download blocks and insert into cache
    async fn download_and_insert_blocks(
        client: &mut CompactTxStreamerClient<T>,
        block_source: &mut CdnFallbackBlockSource,
        db_cache: &MemBlockCache,
        scan_range: &zcash_client_backend::data_api::scanning::ScanRange,
        expected_prev_hash: zcash_primitives::block::BlockHash,
    ) -> Result<(), Error> {
        use zcash_client_backend::proto::service;

        let mut start = service::BlockId::default();
        start.height = scan_range.block_range().start.into();
        let mut end = service::BlockId::default();
        end.height = (scan_range.block_range().end - 1).into();
        let range = service::BlockRange {
            start: Some(start),
            end: Some(end),
            pool_types: vec![],
        };
        let compact_blocks = block_source
            .get_block_range(client, range, Some(expected_prev_hash))
            .await
            .map_err(|e| Error::Generic(format!("Block download error: {e}")))?;
        db_cache
            .insert(compact_blocks)
            .await
            .map_err(|e| Error::Generic(format!("{e}")))?;
        Ok(())
    }

    // Internal helper: fetch chain state at a given height
    async fn fetch_chain_state(
        client: &mut CompactTxStreamerClient<T>,
        height: zcash_protocol::consensus::BlockHeight,
    ) -> Result<zcash_client_backend::data_api::chain::ChainState, Error> {
        use zcash_client_backend::proto::service::BlockId;
        let tree_state = client
            .get_tree_state(BlockId {
                height: height.into(),
                hash: vec![],
            })
            .await
            .map_err(|e| Error::Generic(format!("gRPC error: {e}")))?;
        tree_state
            .into_inner()
            .to_chain_state()
            .map_err(|e| Error::Generic(format!("Failed to parse ChainState: {e}")))
    }

    // Internal helper: update subtree roots from lightwalletd
    async fn do_update_subtree_roots(
        &self,
        client: &mut CompactTxStreamerClient<T>,
        db: &mut W,
        tip_height: BlockHeight,
    ) -> Result<(), Error> {
        use zcash_client_backend::data_api::chain::CommitmentTreeRoot;
        use zcash_client_backend::proto::service;
        use zcash_primitives::merkle_tree::HashSer;

        let mut request = service::GetSubtreeRootsArg::default();
        request.set_shielded_protocol(service::ShieldedProtocol::Sapling);
        let sapling_roots: Vec<CommitmentTreeRoot<sapling::Node>> = client
            .get_subtree_roots(request)
            .await
            .map_err(|e| Error::Generic(format!("gRPC error: {e}")))?
            .into_inner()
            .and_then(|root| async move {
                let root_hash = sapling::Node::read(&root.root_hash[..])?;
                Ok(CommitmentTreeRoot::from_parts(
                    zcash_protocol::consensus::BlockHeight::from_u32(
                        root.completing_block_height as u32,
                    ),
                    root_hash,
                ))
            })
            .try_collect()
            .await
            .map_err(|e| Error::Generic(format!("Stream error: {e}")))?;
        db.put_sapling_subtree_roots(0, &sapling_roots)
            .map_err(|e| Error::Generic(format!("DB error: {e}")))?;

        let mut request = service::GetSubtreeRootsArg::default();
        request.set_shielded_protocol(service::ShieldedProtocol::Orchard);
        let orchard_roots: Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>> = client
            .get_subtree_roots(request)
            .await
            .map_err(|e| Error::Generic(format!("gRPC error: {e}")))?
            .into_inner()
            .and_then(|root| async move {
                let root_hash = orchard::tree::MerkleHashOrchard::read(&root.root_hash[..])?;
                Ok(CommitmentTreeRoot::from_parts(
                    zcash_protocol::consensus::BlockHeight::from_u32(
                        root.completing_block_height as u32,
                    ),
                    root_hash,
                ))
            })
            .try_collect()
            .await
            .map_err(|e| Error::Generic(format!("Stream error: {e}")))?;
        db.put_orchard_subtree_roots(0, &orchard_roots)
            .map_err(|e| Error::Generic(format!("DB error: {e}")))?;

        if self.network.is_nu_active(NetworkUpgrade::Nu6_3, tip_height) {
            let mut request = service::GetSubtreeRootsArg::default();
            request.set_shielded_protocol(service::ShieldedProtocol::Ironwood);
            let ironwood_roots: Vec<CommitmentTreeRoot<orchard::tree::MerkleHashOrchard>> = client
                .get_subtree_roots(request)
                .await
                .map_err(|e| Error::Generic(format!("gRPC error: {e}")))?
                .into_inner()
                .and_then(|root| async move {
                    let root_hash = orchard::tree::MerkleHashOrchard::read(&root.root_hash[..])?;
                    Ok(CommitmentTreeRoot::from_parts(
                        BlockHeight::from_u32(root.completing_block_height as u32),
                        root_hash,
                    ))
                })
                .try_collect()
                .await
                .map_err(|e| Error::Generic(format!("Stream error: {e}")))?;
            db.put_ironwood_subtree_roots(0, &ironwood_roots)
                .map_err(|e| Error::Generic(format!("DB error: {e}")))?;
        }

        Ok(())
    }

    async fn refresh_transparent_utxos_for_all_accounts(
        &self,
        client: &mut CompactTxStreamerClient<T>,
        db: &mut W,
    ) -> Result<(), Error> {
        let account_ids = db
            .get_account_ids()
            .map_err(|e| Error::Generic(format!("Failed to get account IDs: {e}")))?;

        for account_id in account_ids {
            let start_height = db
                .utxo_query_height(account_id)
                .map_err(|e| Error::Generic(format!("Failed to get UTXO query height: {e}")))?;

            tracing::info!(
                "Refreshing UTXOs for {:?} from height {}",
                account_id,
                start_height,
            );

            zcash_client_backend::sync::refresh_utxos(
                &self.network,
                client,
                db,
                account_id,
                start_height,
            )
            .await
            .map_err(|e: zcash_client_backend::sync::Error<(), _, ()>| {
                Error::Generic(format!("Failed to refresh UTXOs: {e:?}"))
            })?;
        }

        Ok(())
    }

    pub async fn get_wallet_summary(&self) -> Result<Option<WalletSummary<AccountId>>, Error> {
        Ok(self
            .db
            .read()
            .await
            .get_wallet_summary(self.query_confirmations_policy())?)
    }

    pub(crate) async fn get_wallet_summary_with_shieldable_balances(
        &self,
    ) -> Result<Option<(WalletSummary<AccountId>, HashMap<AccountId, Zatoshis>)>, Error> {
        let db = self.db.read().await;
        let Some(summary) = db.get_wallet_summary(self.query_confirmations_policy())? else {
            return Ok(None);
        };
        let target_height = TargetHeight::from(summary.chain_tip_height() + 1);
        let mut shieldable_balances = HashMap::new();
        for account_id in summary.account_balances().keys() {
            let balances = db.get_transparent_balances(
                *account_id,
                target_height,
                self.selection_confirmations_policy(),
            )?;
            let value = balances
                .values()
                .try_fold(Zatoshis::ZERO, |total, (_, balance)| {
                    (total + balance.spendable_value())
                        .ok_or(zcash_protocol::value::BalanceError::Overflow)
                })?;
            shieldable_balances.insert(*account_id, value);
        }
        Ok(Some((summary, shieldable_balances)))
    }

    /// Get account ID by account name
    ///
    /// # Arguments
    ///
    /// * `account_name` - The name of the account to find
    ///
    /// # Returns
    ///
    /// Returns the AccountId if an account with the given name exists, or an error if not found
    pub async fn get_account_id_by_name(&self, account_name: &str) -> Result<AccountId, Error> {
        let db = self.db.read().await;

        // Get all account IDs
        let account_ids = db.get_account_ids()?;

        // Find the account with matching name
        for account_id in account_ids {
            if let Some(account) = db.get_account(account_id)?
                && let Some(name) = account.name()
                && name == account_name
            {
                return Ok(account_id);
            }
        }

        Err(Error::AccountNameNotFound)
    }

    pub async fn get_account_birthday(&self, account_id: AccountId) -> Result<u32, Error> {
        let db = self.db.read().await;
        let birthday_height = db.get_account_birthday(account_id)?;
        Ok(birthday_height.into())
    }

    pub fn ironwood_activation_height(&self) -> Option<u32> {
        self.network
            .activation_height(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
            .map(Into::into)
    }

    /// Get the timestamp (Unix time) of a block at a given height
    pub async fn get_block_time(&self, height: u32) -> Result<u32, Error> {
        use tonic::Request;
        use zcash_client_backend::proto::service::BlockId;

        let mut client = self.client.clone();
        let block = client
            .get_block(Request::new(BlockId {
                height: height as u64,
                hash: vec![],
            }))
            .await?
            .into_inner();
        Ok(block.time)
    }

    /// Get the latest block height from the chain
    pub async fn get_latest_height(&self) -> Result<u32, Error> {
        use tonic::Request;
        use zcash_client_backend::proto::service::ChainSpec;

        let mut client = self.client.clone();
        let chainspec = ChainSpec {};
        let rep = client.get_latest_block(Request::new(chainspec)).await?;
        let block_id = rep.into_inner();
        Ok(block_id.height as u32)
    }

    /// Find the block height closest to a given Unix timestamp using binary search
    ///
    /// # Arguments
    ///
    /// * `time` - Unix timestamp (seconds since epoch)
    ///
    /// # Returns
    ///
    /// The block height closest to the given timestamp
    ///
    /// # Algorithm
    ///
    /// Uses binary search to efficiently find the block height:
    /// - If time is before Sapling activation, returns 0
    /// - If time is after the latest block, returns latest height
    /// - Otherwise, performs binary search with ~1000 block precision
    pub async fn get_block_by_time(&self, time: u32) -> Result<u32, Error> {
        use zcash_protocol::consensus::{NetworkUpgrade, Parameters};

        // Get Sapling activation height as the starting point
        let start_height = self
            .network
            .activation_height(NetworkUpgrade::Sapling)
            .ok_or(Error::Generic(
                "Sapling activation height not found".to_string(),
            ))?;
        let mut start = u32::from(start_height);
        let mut end = self.get_latest_height().await?;

        // Check boundary conditions
        let start_time = self.get_block_time(start).await?;
        if time <= start_time {
            return Ok(0);
        }

        let end_time = self.get_block_time(end).await?;
        if time >= end_time {
            return Ok(end);
        }

        // Binary search with ~1000 block precision
        while end - start >= 1000 {
            let block_mid = (start + end) / 2;
            let mid_time = self.get_block_time(block_mid).await?;

            match time.cmp(&mid_time) {
                std::cmp::Ordering::Less => {
                    end = block_mid - 1;
                }
                std::cmp::Ordering::Equal => {
                    return Ok(block_mid);
                }
                std::cmp::Ordering::Greater => {
                    start = block_mid + 1;
                }
            }
        }

        Ok(start)
    }

    async fn load_stored_transfer_transactions(
        &self,
        txids: &NonEmpty<TxId>,
    ) -> Result<NonEmpty<TransactionToSubmit>, Error> {
        let db = self.db.read().await;
        let mut transactions = Vec::with_capacity(txids.len());
        for requested_txid in txids {
            let tx = db
                .get_transaction(*requested_txid)?
                .ok_or(Error::TransactionNotFound(*requested_txid))?;
            let mut raw_tx = service::RawTransaction::default();
            tx.write(&mut raw_tx.data)?;
            transactions.push(TransactionToSubmit {
                txid: tx.txid(),
                raw: raw_tx,
                requires_zero_indexer: requires_zero_indexer(&tx),
            });
        }
        Ok(NonEmpty::from_vec(transactions).expect("txids is non-empty"))
    }

    async fn submit_raw_transaction(
        &self,
        raw: service::RawTransaction,
        requires_zero_indexer: bool,
    ) -> Result<service::SendResponse, tonic::Status> {
        if requires_zero_indexer && !self.zero_indexer_clients.is_empty() {
            let clients = self.zero_indexer_clients.clone();
            submit_to_zero_indexers_with_fallback(
                clients.len(),
                raw,
                self.zero_indexer_send_timeout,
                move |index, raw| {
                    let mut client = clients[index].clone();
                    async move {
                        client
                            .send_transaction(raw)
                            .await
                            .map(tonic::Response::into_inner)
                    }
                },
                |raw| self.submit_to_lightwalletd(raw),
            )
            .await
        } else {
            self.submit_to_lightwalletd(raw).await
        }
    }

    async fn submit_to_lightwalletd(
        &self,
        raw: service::RawTransaction,
    ) -> Result<service::SendResponse, tonic::Status> {
        let mut client = self.client.clone();
        client
            .send_transaction(raw)
            .await
            .map(tonic::Response::into_inner)
    }

    async fn submit_stored_transfer_transactions(
        &self,
        txids: &NonEmpty<TxId>,
    ) -> Result<TransferResult, Error> {
        let transactions = self.load_stored_transfer_transactions(txids).await?;
        Ok(
            submit_transfer_transactions_with(transactions, |raw, requires_zero_indexer| {
                self.submit_raw_transaction(raw, requires_zero_indexer)
            })
            .await,
        )
    }

    pub async fn send_authorized_transactions(
        &self,
        txids: &NonEmpty<TxId>,
    ) -> Result<TransferResult, Error> {
        self.submit_stored_transfer_transactions(txids).await
    }

    #[allow(clippy::too_many_arguments)]
    async fn propose_unified_transfer<FeeRuleT>(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        memo: Option<Vec<u8>>,
        fee_rule: FeeRuleT,
        funding_source: TransferFundingSource,
        allow_send_max_fallback: bool,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<
        zcash_client_backend::proposal::Proposal<FeeRuleT, <W as InputSource>::NoteRef>,
        Error,
    >
    where
        FeeRuleT: FeeRule + Clone + zcash_client_backend::fees::zip317::Zip317FeeRule,
        FeeRuleT::Error: Debug + From<zcash_protocol::value::BalanceError>,
    {
        let (spend_policy, transparent_change_policy) = transfer_policies(funding_source);
        let change_strategy =
            zcash_client_backend::fees::zip317::MultiOutputChangeStrategy::<_, W>::new(
                fee_rule.clone(),
                None,
                ShieldedPool::Orchard,
                DustOutputPolicy::default(),
                SplitPolicy::with_min_output_value(
                    NonZeroUsize::new(self.target_note_count)
                        .ok_or(Error::FailedToCreateTransaction)?,
                    Zatoshis::from_u64(self.min_split_output_value)?,
                ),
            )
            .with_transparent_change_policy(transparent_change_policy);

        let input_selector = GreedyInputSelector::new();
        let memo = memo.as_deref().map(MemoBytes::from_bytes).transpose()?;
        let payment = Payment::new(
            to_address.clone(),
            Some(Zatoshis::from_u64(value)?),
            memo.clone(),
            None,
            None,
            vec![],
        )
        .map_err(|e| Error::Zip321(e.with_index(0)))?;
        let request = TransactionRequest::new(vec![payment])?;
        let mut db = self.db.write().await;

        let confirmations_policy = self.transfer_confirmations_policy(&*db, expiry_delta_blocks)?;
        let propose = if expiry_delta_blocks.is_some() {
            ordinary::propose_transfer::<_, _, _, _, <W as WalletCommitmentTrees>::Error>
        } else {
            propose_transfer::<_, _, _, _, <W as WalletCommitmentTrees>::Error>
        };
        match propose(
            &mut *db,
            &self.network,
            account_id,
            &input_selector,
            &change_strategy,
            request,
            confirmations_policy,
            &spend_policy,
            None,
            None,
        ) {
            Ok(proposal) => Ok(proposal),
            Err(transfer_error) => {
                if allow_send_max_fallback {
                    let max_proposal =
                        propose_send_max_transfer::<_, _, _, <W as WalletCommitmentTrees>::Error>(
                            &mut *db,
                            &self.network,
                            account_id,
                            &[
                                ShieldedPool::Sapling,
                                ShieldedPool::Orchard,
                                ShieldedPool::Ironwood,
                            ],
                            &fee_rule,
                            to_address,
                            memo,
                            MaxSpendMode::MaxSpendable,
                            confirmations_policy,
                            &Default::default(),
                            None,
                        )
                        .ok();

                    if let Some(proposal) = max_proposal
                        && proposal_payment_amount_zats(&proposal)? == value
                    {
                        return Ok(proposal);
                    }
                }

                let message = format!(
                    "Failed to propose transfer. Possibly insufficient permitted funds: {transfer_error:?}"
                );
                Err(
                    if matches!(transfer_error, WalletError::InsufficientFunds { .. }) {
                        Error::InsufficientTransferFunds(message)
                    } else {
                        Error::Generic(message)
                    },
                )
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn estimate_transfer(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        funding_source: TransferFundingSource,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: Option<u64>,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<TransferEstimate, Error> {
        expiry_delta_blocks
            .map(validate_expiry_delta_blocks)
            .transpose()?;

        match self.resolve_transfer_fee(marginal_fee_zats).await? {
            Some(marginal_fee_zats) => {
                let proposal = self
                    .propose_unified_transfer(
                        account_id,
                        to_address,
                        value,
                        memo,
                        dynamic_zip317_fee_rule(marginal_fee_zats)?,
                        funding_source,
                        allow_exact_send_max_fallback(funding_source, true),
                        expiry_delta_blocks,
                    )
                    .await?;
                transfer_estimate_from_proposal(&proposal, marginal_fee_zats)
            }
            None => {
                let proposal = self
                    .propose_unified_transfer(
                        account_id,
                        to_address,
                        value,
                        memo,
                        StandardFeeRule::Zip317,
                        funding_source,
                        false,
                        expiry_delta_blocks,
                    )
                    .await?;
                transfer_estimate_from_proposal(&proposal, prim_zip317::MARGINAL_FEE.into())
            }
        }
    }

    async fn execute_unified_transfer<FeeRuleT>(
        &self,
        usk: UnifiedSpendingKey,
        proposal: zcash_client_backend::proposal::Proposal<FeeRuleT, <W as InputSource>::NoteRef>,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<TransferResult, Error>
    where
        FeeRuleT: FeeRule,
        FeeRuleT::Error: Debug,
    {
        let expiry = transfer_expiry_height(proposal.min_target_height(), expiry_delta_blocks)?;
        let txids = {
            let mut db = self.db.write().await;
            create_and_store_transfer(&mut *db, &self.network, usk, &proposal, expiry)?
        };
        self.submit_stored_transfer_transactions(&txids).await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn oneclick_transfer(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        usk: UnifiedSpendingKey,
        funding_source: TransferFundingSource,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: Option<u64>,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<TransferResult, Error> {
        match self.resolve_transfer_fee(marginal_fee_zats).await? {
            Some(marginal_fee_zats) => {
                let proposal = self
                    .propose_unified_transfer(
                        account_id,
                        to_address,
                        value,
                        memo,
                        dynamic_zip317_fee_rule(marginal_fee_zats)?,
                        funding_source,
                        allow_exact_send_max_fallback(funding_source, true),
                        expiry_delta_blocks,
                    )
                    .await?;
                self.execute_unified_transfer(usk, proposal, expiry_delta_blocks)
                    .await
            }
            None => {
                let proposal = self
                    .propose_unified_transfer(
                        account_id,
                        to_address,
                        value,
                        memo,
                        StandardFeeRule::Zip317,
                        funding_source,
                        false,
                        expiry_delta_blocks,
                    )
                    .await?;
                self.execute_unified_transfer(usk, proposal, expiry_delta_blocks)
                    .await
            }
        }
    }

    pub async fn pczt_shield(&self, account_id: AccountId) -> Result<Pczt, Error> {
        let change_strategy = MultiOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
            SplitPolicy::with_min_output_value(
                NonZeroUsize::new(self.target_note_count)
                    .ok_or(Error::FailedToCreateTransaction)?,
                Zatoshis::from_u64(self.min_split_output_value)?,
            ),
        );

        let input_selector = GreedyInputSelector::new();
        let mut db = self.db.write().await;

        // Get all transparent receivers for this account to use as shielding sources
        let max_height = match db.chain_height()? {
            Some(max_height) => max_height,
            None => {
                return Err(Error::Generic(
                    "Havent scanned yet, cant shield".to_string(),
                ));
            }
        };

        let transparent_balances = db.get_transparent_balances(
            account_id,
            (max_height + 1).into(),
            self.selection_confirmations_policy(),
        )?;
        let from_addrs = transparent_balances.into_keys().collect::<Vec<_>>();

        if from_addrs.is_empty() {
            return Err(Error::Generic(
                "No transparent addresses found for this account. Make sure the account has received funds to a transparent address.".to_string()
            ));
        }

        tracing::info!("Shielding from {} transparent addresses", from_addrs.len());

        let proposal = propose_shielding::<_, _, _, _, <W as WalletCommitmentTrees>::Error>(
            &mut *db,
            &self.network,
            &input_selector,
            &change_strategy,
            SHIELDING_THRESHOLD,
            &from_addrs,
            account_id,
            self.selection_confirmations_policy(),
            CoinbaseFilter::AllTransparentOutputs,
            None,
        )
        .map_err(|e| Error::Generic(format!("Error when shielding: {e:?}")))?;

        let pczt = create_pczt_from_proposal::<
            _,
            _,
            <MemoryWalletDb<Network> as InputSource>::Error,
            _,
            <StandardFeeRule as FeeRule>::Error,
            _,
        >(
            &mut *db,
            &self.network,
            &WalletClock,
            &mut UnwrapErr(SysRng),
            account_id,
            OvkPolicy::Sender,
            &proposal,
            None,
            zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
        )
        .map_err(|e| Error::Generic(format!("Failed to create PCZT for shielding: {e:?}")))?;

        Ok(pczt)
    }

    pub async fn pczt_create(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        memo: Option<Vec<u8>>,
    ) -> Result<Pczt, Error> {
        self.pczt_create_with_policy(
            account_id,
            to_address,
            value,
            memo,
            SpendPolicy::default(),
            TransparentChangePolicy::ShieldChange,
        )
        .await
    }

    pub async fn pczt_create_transparent(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        memo: Option<Vec<u8>>,
    ) -> Result<Pczt, Error> {
        let (spend_policy, transparent_change_policy) = transparent_transfer_policies();
        self.pczt_create_with_policy(
            account_id,
            to_address,
            value,
            memo,
            spend_policy,
            transparent_change_policy,
        )
        .await
    }

    async fn pczt_create_with_policy(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        memo: Option<Vec<u8>>,
        spend_policy: SpendPolicy,
        transparent_change_policy: TransparentChangePolicy,
    ) -> Result<Pczt, Error> {
        let change_strategy = MultiOutputChangeStrategy::new(
            StandardFeeRule::Zip317,
            None,
            ShieldedPool::Orchard,
            DustOutputPolicy::default(),
            SplitPolicy::with_min_output_value(
                NonZeroUsize::new(self.target_note_count)
                    .ok_or(Error::FailedToCreateTransaction)?,
                Zatoshis::from_u64(self.min_split_output_value)?,
            ),
        )
        .with_transparent_change_policy(transparent_change_policy);

        let input_selector = GreedyInputSelector::new();
        let memo = memo.as_deref().map(MemoBytes::from_bytes).transpose()?;
        let payment = Payment::new(
            to_address,
            Some(Zatoshis::from_u64(value)?),
            memo,
            None,
            None,
            vec![],
        )
        .map_err(|e| Error::Zip321(e.with_index(0)))?;
        let request = TransactionRequest::new(vec![payment])?;
        let mut db = self.db.write().await;
        let proposal = propose_transfer::<_, _, _, _, <W as WalletCommitmentTrees>::Error>(
            &mut *db,
            &self.network,
            account_id,
            &input_selector,
            &change_strategy,
            request,
            self.selection_confirmations_policy(),
            &spend_policy,
            None,
            None,
        )
        .map_err(|error| {
            let message = format!(
                "Failed to propose transfer. Possibly insufficient permitted funds: {error:?}"
            );
            if matches!(error, WalletError::InsufficientFunds { .. }) {
                Error::InsufficientTransferFunds(message)
            } else {
                Error::Generic(message)
            }
        })?;
        let pczt = create_pczt_from_proposal::<
            _,
            _,
            <MemoryWalletDb<Network> as InputSource>::Error,
            _,
            <StandardFeeRule as FeeRule>::Error,
            _,
        >(
            &mut *db,
            &self.network,
            &WalletClock,
            &mut UnwrapErr(SysRng),
            account_id,
            OvkPolicy::Sender,
            &proposal,
            None,
            zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
        )
        .map_err(|e| Error::Generic(format!("Failed to create PCZT for transfer: {e:?}")))?;
        Ok(pczt)
    }

    pub async fn pczt_shield_dynamic_fee(
        &self,
        account_id: AccountId,
        marginal_fee_zats: u64,
    ) -> Result<Pczt, Error> {
        self.pczt_shield_dynamic_fee_impl(account_id, marginal_fee_zats, None)
            .await
    }

    pub async fn pczt_shield_dynamic_fee_with_expiry_delta(
        &self,
        account_id: AccountId,
        marginal_fee_zats: u64,
        expiry_delta_blocks: u32,
    ) -> Result<Pczt, Error> {
        let expiry_delta_blocks = validate_expiry_delta_blocks(expiry_delta_blocks)?;
        self.pczt_shield_dynamic_fee_impl(account_id, marginal_fee_zats, Some(expiry_delta_blocks))
            .await
    }

    async fn pczt_shield_dynamic_fee_impl(
        &self,
        account_id: AccountId,
        marginal_fee_zats: u64,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<Pczt, Error> {
        let change_strategy =
            zcash_client_backend::fees::zip317::MultiOutputChangeStrategy::<_, W>::new(
                dynamic_zip317_fee_rule(marginal_fee_zats)?,
                None,
                ShieldedPool::Orchard,
                DustOutputPolicy::default(),
                SplitPolicy::with_min_output_value(
                    NonZeroUsize::new(self.target_note_count)
                        .ok_or(Error::FailedToCreateTransaction)?,
                    Zatoshis::from_u64(self.min_split_output_value)?,
                ),
            );

        let input_selector = GreedyInputSelector::new();
        let mut db = self.db.write().await;

        // Get all transparent receivers for this account to use as shielding sources
        let max_height = match db.chain_height()? {
            Some(max_height) => max_height,
            None => {
                return Err(Error::Generic(
                    "Havent scanned yet, cant shield".to_string(),
                ));
            }
        };

        let transparent_balances = db.get_transparent_balances(
            account_id,
            (max_height + 1).into(),
            self.selection_confirmations_policy(),
        )?;
        let from_addrs = transparent_balances.into_keys().collect::<Vec<_>>();

        if from_addrs.is_empty() {
            return Err(Error::Generic(
                "No transparent addresses found for this account. Make sure the account has received funds to a transparent address.".to_string()
            ));
        }

        tracing::info!(
            "Shielding from {} transparent addresses with ZIP-317 marginal fee {} zats",
            from_addrs.len(),
            marginal_fee_zats,
        );

        let proposal = propose_shielding::<_, _, _, _, <W as WalletCommitmentTrees>::Error>(
            &mut *db,
            &self.network,
            &input_selector,
            &change_strategy,
            SHIELDING_THRESHOLD,
            &from_addrs,
            account_id,
            self.selection_confirmations_policy(),
            CoinbaseFilter::AllTransparentOutputs,
            None,
        )
        .map_err(|e| Error::Generic(format!("Error when shielding: {e:?}")))?;

        let pczt = match expiry_delta_blocks {
            Some(expiry_delta_blocks) => create_pczt_from_proposal::<
                _,
                _,
                <MemoryWalletDb<Network> as InputSource>::Error,
                _,
                <prim_zip317::FeeRule as FeeRule>::Error,
                _,
            >(
                &mut *db,
                &self.network,
                &WalletClock,
                &mut UnwrapErr(SysRng),
                account_id,
                OvkPolicy::Sender,
                &proposal,
                Some(BlockHeight::from(proposal.min_target_height()) + expiry_delta_blocks),
                zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
            ),
            None => create_pczt_from_proposal::<
                _,
                _,
                <MemoryWalletDb<Network> as InputSource>::Error,
                _,
                <prim_zip317::FeeRule as FeeRule>::Error,
                _,
            >(
                &mut *db,
                &self.network,
                &WalletClock,
                &mut UnwrapErr(SysRng),
                account_id,
                OvkPolicy::Sender,
                &proposal,
                None,
                zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
            ),
        }
        .map_err(|e| Error::Generic(format!("Failed to create PCZT for shielding: {e:?}")))?;

        Ok(pczt)
    }

    pub async fn pczt_create_dynamic_fee(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<Pczt, Error> {
        self.pczt_create_dynamic_fee_impl(
            account_id,
            to_address,
            value,
            memo,
            marginal_fee_zats,
            None,
            SpendPolicy::default(),
            TransparentChangePolicy::ShieldChange,
            true,
            false,
        )
        .await
    }

    pub async fn pczt_create_dynamic_fee_with_expiry_delta(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
        expiry_delta_blocks: u32,
    ) -> Result<Pczt, Error> {
        let expiry_delta_blocks = validate_expiry_delta_blocks(expiry_delta_blocks)?;
        self.pczt_create_dynamic_fee_impl(
            account_id,
            to_address,
            value,
            memo,
            marginal_fee_zats,
            Some(expiry_delta_blocks),
            SpendPolicy::default(),
            TransparentChangePolicy::ShieldChange,
            true,
            false,
        )
        .await
    }

    pub async fn pczt_create_transparent_dynamic_fee(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<Pczt, Error> {
        let (spend_policy, transparent_change_policy) = transparent_transfer_policies();
        self.pczt_create_dynamic_fee_impl(
            account_id,
            to_address,
            value,
            memo,
            marginal_fee_zats,
            None,
            spend_policy,
            transparent_change_policy,
            false,
            false,
        )
        .await
    }

    /// Creates a transparent-funded PCZT whose shielded outputs can be reviewed by an
    /// external hardware signer. Ledger derives Orchard review keys from the ZIP-32
    /// account path, so external Ironwood outputs must use that account's Orchard OVK
    /// even though ZIP-316 would ordinarily select the transparent OVK for this input set.
    pub async fn pczt_create_transparent_hardware_dynamic_fee(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<Pczt, Error> {
        let (spend_policy, transparent_change_policy) = transparent_transfer_policies();
        self.pczt_create_dynamic_fee_impl(
            account_id,
            to_address,
            value,
            memo,
            marginal_fee_zats,
            None,
            spend_policy,
            transparent_change_policy,
            false,
            true,
        )
        .await
    }

    pub async fn pczt_create_transparent_dynamic_fee_with_expiry_delta(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
        expiry_delta_blocks: u32,
    ) -> Result<Pczt, Error> {
        let expiry_delta_blocks = validate_expiry_delta_blocks(expiry_delta_blocks)?;
        let (spend_policy, transparent_change_policy) = transparent_transfer_policies();
        self.pczt_create_dynamic_fee_impl(
            account_id,
            to_address,
            value,
            memo,
            marginal_fee_zats,
            Some(expiry_delta_blocks),
            spend_policy,
            transparent_change_policy,
            false,
            false,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn pczt_create_dynamic_fee_impl(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
        expiry_delta_blocks: Option<u32>,
        spend_policy: SpendPolicy,
        transparent_change_policy: TransparentChangePolicy,
        allow_send_max_fallback: bool,
        hardware_orchard_ovk: bool,
    ) -> Result<Pczt, Error> {
        let change_strategy =
            zcash_client_backend::fees::zip317::MultiOutputChangeStrategy::<_, W>::new(
                dynamic_zip317_fee_rule(marginal_fee_zats)?,
                None,
                ShieldedPool::Orchard,
                DustOutputPolicy::default(),
                SplitPolicy::with_min_output_value(
                    NonZeroUsize::new(self.target_note_count)
                        .ok_or(Error::FailedToCreateTransaction)?,
                    Zatoshis::from_u64(self.min_split_output_value)?,
                ),
            )
            .with_transparent_change_policy(transparent_change_policy);

        let input_selector = GreedyInputSelector::new();
        let memo = memo.as_deref().map(MemoBytes::from_bytes).transpose()?;
        let payment = Payment::new(
            to_address.clone(),
            Some(Zatoshis::from_u64(value)?),
            memo.clone(),
            None,
            None,
            vec![],
        )
        .map_err(|e| Error::Zip321(e.with_index(0)))?;
        let request = TransactionRequest::new(vec![payment])?;
        let mut db = self.db.write().await;
        let confirmations_policy = self.transfer_confirmations_policy(&*db, expiry_delta_blocks)?;
        let propose = if expiry_delta_blocks.is_some() {
            ordinary::propose_transfer::<_, _, _, _, <W as WalletCommitmentTrees>::Error>
        } else {
            propose_transfer::<_, _, _, _, <W as WalletCommitmentTrees>::Error>
        };
        let proposal = match propose(
            &mut *db,
            &self.network,
            account_id,
            &input_selector,
            &change_strategy,
            request,
            confirmations_policy,
            &spend_policy,
            None,
            None,
        ) {
            Ok(proposal) => proposal,
            Err(transfer_error) => {
                let max_proposal = if allow_send_max_fallback {
                    propose_send_max_transfer::<_, _, _, <W as WalletCommitmentTrees>::Error>(
                        &mut *db,
                        &self.network,
                        account_id,
                        &[
                            ShieldedPool::Sapling,
                            ShieldedPool::Orchard,
                            ShieldedPool::Ironwood,
                        ],
                        &dynamic_zip317_fee_rule(marginal_fee_zats)?,
                        to_address,
                        memo,
                        MaxSpendMode::MaxSpendable,
                        confirmations_policy,
                        &Default::default(),
                        None,
                    )
                    .ok()
                } else {
                    None
                };

                match max_proposal {
                    Some(proposal) if proposal_payment_amount_zats(&proposal)? == value => proposal,
                    _ => {
                        let message = format!(
                            "Failed to propose transfer. Possibly insufficient permitted funds: {transfer_error:?}"
                        );
                        return Err(
                            if matches!(transfer_error, WalletError::InsufficientFunds { .. }) {
                                Error::InsufficientTransferFunds(message)
                            } else {
                                Error::Generic(message)
                            },
                        );
                    }
                }
            }
        };
        let ovk_policy = if hardware_orchard_ovk {
            let account = db.get_account(account_id)?.ok_or_else(|| {
                Error::Generic("Hardware transaction account not found".to_owned())
            })?;
            hardware_orchard_ovk_policy(account.ufvk().ok_or_else(|| {
                Error::Generic("Hardware transaction account has no viewing key".to_owned())
            })?)?
        } else {
            OvkPolicy::Sender
        };
        let pczt = match expiry_delta_blocks {
            Some(expiry_delta_blocks) => create_pczt_from_proposal::<
                _,
                _,
                <MemoryWalletDb<Network> as InputSource>::Error,
                _,
                <prim_zip317::FeeRule as FeeRule>::Error,
                _,
            >(
                &mut *db,
                &self.network,
                &WalletClock,
                &mut UnwrapErr(SysRng),
                account_id,
                ovk_policy.clone(),
                &proposal,
                Some(BlockHeight::from(proposal.min_target_height()) + expiry_delta_blocks),
                zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
            ),
            None => create_pczt_from_proposal::<
                _,
                _,
                <MemoryWalletDb<Network> as InputSource>::Error,
                _,
                <prim_zip317::FeeRule as FeeRule>::Error,
                _,
            >(
                &mut *db,
                &self.network,
                &WalletClock,
                &mut UnwrapErr(SysRng),
                account_id,
                ovk_policy,
                &proposal,
                None,
                zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
            ),
        }
        .map_err(|e| Error::Generic(format!("Failed to create PCZT for transfer: {e:?}")))?;
        Ok(pczt)
    }

    /// Sweeps all currently spendable Orchard notes into the Ironwood pool.
    ///
    /// The destination must belong to the same wallet account. The proposal is restricted to
    /// Orchard inputs and transaction V6; after NU6.3, its Orchard receiver is carried by the
    /// Ironwood bundle.
    pub async fn pczt_create_orchard_migration(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
        expiry_delta_blocks: Option<u32>,
    ) -> Result<Pczt, Error> {
        let expiry_delta_blocks = expiry_delta_blocks
            .map(validate_expiry_delta_blocks)
            .transpose()?;
        let wallet_address = zcash_client_backend::address::Address::try_from_zcash_address(
            &self.network,
            to_address.clone(),
        )
        .map_err(|e| Error::Generic(format!("Invalid migration address: {e:?}")))?;
        let memo = memo.as_deref().map(MemoBytes::from_bytes).transpose()?;
        let fee_rule = dynamic_zip317_fee_rule(marginal_fee_zats)?;
        let mut db = self.db.write().await;

        let destination_account = db
            .find_account_for_address(&self.network, &wallet_address)
            .map_err(|e| Error::Generic(format!("Failed to validate migration address: {e:?}")))?;
        if destination_account != Some(account_id) {
            return Err(Error::Generic(
                "Orchard migration destination must belong to the source account".into(),
            ));
        }

        let target_height = db
            .chain_height()?
            .map(|height| height + 1)
            .ok_or_else(|| Error::Generic("Wallet must be synced before migration".into()))?;
        let activation_height = self
            .network
            .activation_height(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
            .ok_or_else(|| Error::Generic("NU6.3 is not configured for this network".into()))?;
        if target_height < activation_height {
            return Err(Error::Generic(format!(
                "Ironwood is not active until height {}",
                u32::from(activation_height)
            )));
        }

        let confirmations_policy = self.transfer_confirmations_policy(&*db, expiry_delta_blocks)?;
        let proposal = propose_send_max_transfer::<_, _, _, <W as WalletCommitmentTrees>::Error>(
            &mut *db,
            &self.network,
            account_id,
            &[ShieldedPool::Orchard],
            &fee_rule,
            to_address,
            memo,
            MaxSpendMode::MaxSpendable,
            confirmations_policy,
            &Default::default(),
            None,
        )
        .map_err(|e| Error::Generic(format!("Failed to propose Orchard migration: {e:?}")))?
        .with_proposed_version(Some(TxVersion::V6));

        create_pczt_from_proposal::<
            _,
            _,
            <MemoryWalletDb<Network> as InputSource>::Error,
            _,
            <prim_zip317::FeeRule as FeeRule>::Error,
            _,
        >(
            &mut *db,
            &self.network,
            &WalletClock,
            &mut UnwrapErr(SysRng),
            account_id,
            OvkPolicy::Sender,
            &proposal,
            expiry_delta_blocks
                .map(|delta| BlockHeight::from(proposal.min_target_height()) + delta),
            zcash_primitives::transaction::builder::BundlePadding::DEFAULT,
        )
        .map_err(|e| Error::Generic(format!("Failed to create migration PCZT: {e:?}")))
    }

    pub async fn estimate_orchard_migration_fee(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<u64, Error> {
        let wallet_address = zcash_client_backend::address::Address::try_from_zcash_address(
            &self.network,
            to_address.clone(),
        )
        .map_err(|e| Error::Generic(format!("Invalid migration address: {e:?}")))?;
        let memo = memo.as_deref().map(MemoBytes::from_bytes).transpose()?;
        let fee_rule = dynamic_zip317_fee_rule(marginal_fee_zats)?;
        let mut db = self.db.write().await;

        let destination_account = db
            .find_account_for_address(&self.network, &wallet_address)
            .map_err(|e| Error::Generic(format!("Failed to validate migration address: {e:?}")))?;
        if destination_account != Some(account_id) {
            return Err(Error::Generic(
                "Orchard migration destination must belong to the source account".into(),
            ));
        }

        let target_height = db
            .chain_height()?
            .map(|height| height + 1)
            .ok_or_else(|| Error::Generic("Wallet must be synced before migration".into()))?;
        let activation_height = self
            .network
            .activation_height(zcash_protocol::consensus::NetworkUpgrade::Nu6_3)
            .ok_or_else(|| Error::Generic("NU6.3 is not configured for this network".into()))?;
        if target_height < activation_height {
            return Err(Error::Generic(format!(
                "Ironwood is not active until height {}",
                u32::from(activation_height)
            )));
        }

        let proposal = propose_send_max_transfer::<_, _, _, <W as WalletCommitmentTrees>::Error>(
            &mut *db,
            &self.network,
            account_id,
            &[ShieldedPool::Orchard],
            &fee_rule,
            to_address,
            memo,
            MaxSpendMode::MaxSpendable,
            self.selection_confirmations_policy(),
            &Default::default(),
            None,
        )
        .map_err(|e| Error::Generic(format!("Failed to estimate Orchard migration: {e:?}")))?
        .with_proposed_version(Some(TxVersion::V6));

        proposal_fee_required_zats(&proposal)
    }

    pub async fn estimate_pczt_shield_fee(
        &self,
        account_id: AccountId,
        marginal_fee_zats: u64,
    ) -> Result<u64, Error> {
        let change_strategy =
            zcash_client_backend::fees::zip317::MultiOutputChangeStrategy::<_, W>::new(
                dynamic_zip317_fee_rule(marginal_fee_zats)?,
                None,
                ShieldedPool::Orchard,
                DustOutputPolicy::default(),
                SplitPolicy::with_min_output_value(
                    NonZeroUsize::new(self.target_note_count)
                        .ok_or(Error::FailedToCreateTransaction)?,
                    Zatoshis::from_u64(self.min_split_output_value)?,
                ),
            );

        let input_selector = GreedyInputSelector::new();
        let mut db = self.db.write().await;

        // Get all transparent receivers for this account to use as shielding sources.
        let max_height = match db.chain_height()? {
            Some(max_height) => max_height,
            None => {
                return Err(Error::Generic(
                    "Havent scanned yet, cant shield".to_string(),
                ));
            }
        };

        let transparent_balances = db.get_transparent_balances(
            account_id,
            (max_height + 1).into(),
            self.selection_confirmations_policy(),
        )?;
        let from_addrs = transparent_balances.into_keys().collect::<Vec<_>>();

        if from_addrs.is_empty() {
            return Err(Error::Generic(
                "No transparent addresses found for this account. Make sure the account has received funds to a transparent address.".to_string()
            ));
        }

        let proposal = propose_shielding::<_, _, _, _, <W as WalletCommitmentTrees>::Error>(
            &mut *db,
            &self.network,
            &input_selector,
            &change_strategy,
            SHIELDING_THRESHOLD,
            &from_addrs,
            account_id,
            self.selection_confirmations_policy(),
            CoinbaseFilter::AllTransparentOutputs,
            None,
        )
        .map_err(|e| Error::Generic(format!("Error when estimating shielding fee: {e:?}")))?;

        proposal_fee_required_zats(&proposal)
    }

    pub async fn estimate_pczt_transfer_fee(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<u64, Error> {
        self.estimate_pczt_transfer_fee_with_policy(
            account_id,
            to_address,
            value,
            memo,
            marginal_fee_zats,
            SpendPolicy::default(),
            TransparentChangePolicy::ShieldChange,
        )
        .await
    }

    pub async fn estimate_pczt_transparent_transfer_fee(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<u64, Error> {
        let (spend_policy, transparent_change_policy) = transparent_transfer_policies();
        self.estimate_pczt_transfer_fee_with_policy(
            account_id,
            to_address,
            value,
            memo,
            marginal_fee_zats,
            spend_policy,
            transparent_change_policy,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn estimate_pczt_transfer_fee_with_policy(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        value: u64,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
        spend_policy: SpendPolicy,
        transparent_change_policy: TransparentChangePolicy,
    ) -> Result<u64, Error> {
        let change_strategy =
            zcash_client_backend::fees::zip317::MultiOutputChangeStrategy::<_, W>::new(
                dynamic_zip317_fee_rule(marginal_fee_zats)?,
                None,
                ShieldedPool::Orchard,
                DustOutputPolicy::default(),
                SplitPolicy::with_min_output_value(
                    NonZeroUsize::new(self.target_note_count)
                        .ok_or(Error::FailedToCreateTransaction)?,
                    Zatoshis::from_u64(self.min_split_output_value)?,
                ),
            )
            .with_transparent_change_policy(transparent_change_policy);

        let input_selector = GreedyInputSelector::new();
        let memo = memo.as_deref().map(MemoBytes::from_bytes).transpose()?;
        let payment = Payment::new(
            to_address,
            Some(Zatoshis::from_u64(value)?),
            memo,
            None,
            None,
            vec![],
        )
        .map_err(|e| Error::Zip321(e.with_index(0)))?;
        let request = TransactionRequest::new(vec![payment])?;
        let mut db = self.db.write().await;
        let proposal = propose_transfer::<_, _, _, _, <W as WalletCommitmentTrees>::Error>(
            &mut *db,
            &self.network,
            account_id,
            &input_selector,
            &change_strategy,
            request,
            self.selection_confirmations_policy(),
            &spend_policy,
            None,
            None,
        )
        .map_err(|error| {
            let message = format!("Error when estimating transfer fee: {error:?}");
            if matches!(error, WalletError::InsufficientFunds { .. }) {
                Error::InsufficientTransferFunds(message)
            } else {
                Error::Generic(message)
            }
        })?;

        proposal_fee_required_zats(&proposal)
    }

    pub async fn estimate_pczt_max_transfer(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<(u64, u64), Error> {
        let fee_rule = dynamic_zip317_fee_rule(marginal_fee_zats)?;
        let memo = memo.as_deref().map(MemoBytes::from_bytes).transpose()?;
        let mut db = self.db.write().await;
        let proposal = propose_send_max_transfer::<_, _, _, <W as WalletCommitmentTrees>::Error>(
            &mut *db,
            &self.network,
            account_id,
            &[
                ShieldedPool::Sapling,
                ShieldedPool::Orchard,
                ShieldedPool::Ironwood,
            ],
            &fee_rule,
            to_address,
            memo,
            MaxSpendMode::MaxSpendable,
            self.query_confirmations_policy(),
            &Default::default(),
            None,
        )
        .map_err(|error| {
            let message = format!("Error when estimating max transfer: {error:?}");
            if matches!(error, WalletError::InsufficientFunds { .. }) {
                Error::InsufficientTransferFunds(message)
            } else {
                Error::Generic(message)
            }
        })?;

        Ok((
            proposal_payment_amount_zats(&proposal)?,
            proposal_fee_required_zats(&proposal)?,
        ))
    }

    pub async fn estimate_pczt_max_transparent_transfer(
        &self,
        account_id: AccountId,
        to_address: ZcashAddress,
        memo: Option<Vec<u8>>,
        marginal_fee_zats: u64,
    ) -> Result<(u64, u64), Error> {
        let fee_rule = dynamic_zip317_fee_rule(marginal_fee_zats)?;
        let memo = memo.as_deref().map(MemoBytes::from_bytes).transpose()?;
        let mut db = self.db.write().await;
        let proposal =
            propose_send_max_transparent_transfer::<_, _, _, <W as WalletCommitmentTrees>::Error>(
                &mut *db,
                &self.network,
                account_id,
                &fee_rule,
                to_address,
                memo,
                self.query_confirmations_policy(),
            )
            .map_err(|e| {
                Error::Generic(format!(
                    "Error when estimating max transparent transfer: {e:?}"
                ))
            })?;

        Ok((
            proposal_payment_amount_zats(&proposal)?,
            proposal_fee_required_zats(&proposal)?,
        ))
    }

    pub async fn pczt_prove(
        &self,
        pczt: Pczt,
        sapling_proof_gen_key: Option<ProofGenerationKey>,
    ) -> Result<Pczt, Error> {
        // Add Sapling proof generation key.
        // TODO: Check to see if there is any sapling in here in the first place
        let pczt = if let Some(sapling_proof_gen_key) = sapling_proof_gen_key {
            Updater::new(pczt)
                .update_sapling_with(|mut updater| {
                    let non_dummy_spends = updater
                        .bundle()
                        .spends()
                        .iter()
                        .enumerate()
                        // Dummy spends will already have a proof generation key.
                        .filter(|(_, spend)| spend.proof_generation_key().is_none())
                        .map(|(index, spend)| {
                            (
                                index,
                                spend
                                    .zip32_derivation()
                                    .as_ref()
                                    .map(|d| (*d.seed_fingerprint(), d.derivation_path().clone())),
                            )
                        })
                        .collect::<Vec<_>>();

                    // Assume all non-dummy spent notes are from the same account.
                    for (index, _) in non_dummy_spends {
                        updater.update_spend_with(index, |mut spend_updater| {
                            spend_updater.set_proof_generation_key(sapling_proof_gen_key.clone())
                        })?;
                    }

                    Ok(())
                })
                .map_err(|e| {
                    Error::PcztProve(format!("Failed to add Sapling proof generation key: {e:?}"))
                })?
                .finish()
        } else {
            pczt
        };

        let prover = get_prover();
        let orchard_circuit_version = orchard_circuit_version_for_pczt(&pczt)?;

        let total_start = js_sys::Date::now();
        let mut prover_instance = Prover::new(pczt);

        // Time Orchard proof generation
        let mut orchard_elapsed = 0.0;
        if prover_instance.requires_orchard_proof() {
            let orchard_proving_key = get_orchard_proving_key(orchard_circuit_version);

            tracing::info!("🔧 Starting Orchard proof generation...");
            let orchard_start = js_sys::Date::now();
            prover_instance = prover_instance
                .create_orchard_proof(UnwrapErr(SysRng), orchard_proving_key)
                .map_err(|e| Error::PcztProve(format!("Failed to create Orchard proof: {e:?}")))?;
            orchard_elapsed = (js_sys::Date::now() - orchard_start) / 1000.0;
            tracing::info!("✅ Orchard proof completed in {:.2}s", orchard_elapsed);
        }

        // Time Ironwood proof generation
        let mut ironwood_elapsed = 0.0;
        if prover_instance.requires_ironwood_proof() {
            let orchard_proving_key = get_orchard_proving_key(orchard_circuit_version);

            tracing::info!("🔧 Starting Ironwood proof generation...");
            let ironwood_start = js_sys::Date::now();
            prover_instance = prover_instance
                .create_ironwood_proof(UnwrapErr(SysRng), orchard_proving_key)
                .map_err(|e| Error::PcztProve(format!("Failed to create Ironwood proof: {e:?}")))?;
            ironwood_elapsed = (js_sys::Date::now() - ironwood_start) / 1000.0;
            tracing::info!("✅ Ironwood proof completed in {:.2}s", ironwood_elapsed);
        }

        // Time Sapling proof generation
        tracing::info!("🔧 Starting Sapling proofs generation...");
        let sapling_start = js_sys::Date::now();
        prover_instance = prover_instance
            .create_sapling_proofs(UnwrapErr(SysRng), prover, prover)
            .map_err(|e| Error::PcztProve(format!("Failed to create Sapling proofs: {e:?}")))?;
        let sapling_elapsed = (js_sys::Date::now() - sapling_start) / 1000.0;
        tracing::info!("✅ Sapling proofs completed in {:.2}s", sapling_elapsed);

        let pczt = prover_instance.finish();
        let total_elapsed = (js_sys::Date::now() - total_start) / 1000.0;
        tracing::info!(
            "⏱️ Total proof generation: {:.2}s (Orchard: {:.2}s, Ironwood: {:.2}s, Sapling: {:.2}s)",
            total_elapsed,
            orchard_elapsed,
            ironwood_elapsed,
            sapling_elapsed
        );
        Ok(pczt)
    }

    pub async fn pczt_send(&self, pczt: Pczt) -> Result<String, Error> {
        let prover = get_prover();
        let (spend_vk, output_vk) = prover.verifying_keys();
        let orchard_circuit_version = orchard_circuit_version_for_pczt(&pczt)?;
        let mut db = self.db.write().await;

        let orchard_verifying_key = get_orchard_verifying_key(orchard_circuit_version);
        tracing::info!("📤 Extracting and storing transaction from PCZT...");
        let start_time = js_sys::Date::now();
        let txid = extract_and_store_transaction_from_pczt::<_, ()>(
            &mut *db,
            &WalletClock,
            &mut UnwrapErr(SysRng),
            pczt,
            Some((&spend_vk, &output_vk)),
            Some(orchard_verifying_key),
        )
        .map_err(|e| {
            Error::PcztSend(format!(
                "Failed to extract and store transaction from PCZT: {e:?}"
            ))
        })?;
        let end_time = js_sys::Date::now();
        let elapsed_seconds = (end_time - start_time) / 1000.0;
        tracing::info!(
            "⏱️ extract_and_store_transaction_from_pczt completed in {:.2} seconds",
            elapsed_seconds
        );
        tracing::info!("✅ Transaction stored with txid: {:?}", txid);
        drop(db);

        tracing::info!("📡 Broadcasting transaction to network...");
        let submission = self
            .send_authorized_transactions(&NonEmpty::new(txid))
            .await?;
        let transaction = submission
            .transactions
            .into_iter()
            .next()
            .expect("a single PCZT transaction produces one submission result");
        match transaction.status {
            TransferSubmissionStatus::Submitted => {}
            TransferSubmissionStatus::Rejected => {
                return Err(Error::SendFailed {
                    code: transaction.error_code.unwrap_or_default(),
                    reason: transaction.error_message.unwrap_or_default(),
                });
            }
            TransferSubmissionStatus::Unknown => {
                return Err(Error::TransactionSubmissionUnknown {
                    txid: transaction.tx_id,
                    reason: transaction.error_message.unwrap_or_default(),
                });
            }
            TransferSubmissionStatus::NotAttempted => {
                return Err(Error::Generic(
                    "PCZT transaction submission was not attempted".to_string(),
                ));
            }
        }

        tracing::info!("🎉 Transaction broadcast successfully!");
        Ok(txid.to_string())
    }
}

pub(crate) fn usk_from_seed_str(
    seed: &str,
    passphrase: &str,
    account_id: u32,
    network: &Network,
) -> Result<(UnifiedSpendingKey, SeedFingerprint), Error> {
    let mnemonic = <Mnemonic<English>>::from_phrase(seed).map_err(|_| Error::InvalidSeedPhrase)?;
    let seed = {
        let mut seed = mnemonic.to_seed(passphrase);
        let secret = seed.to_vec();
        seed.zeroize();
        SecretVec::new(secret)
    };
    let seed_fingerprint =
        SeedFingerprint::from_seed(seed.expose_secret()).ok_or(Error::SeedFingerprint)?;
    let usk = UnifiedSpendingKey::from_seed(network, seed.expose_secret(), account_id.try_into()?)?;
    Ok((usk, seed_fingerprint))
}

#[cfg(test)]
#[path = "wallet/transparent_history_tests.rs"]
mod transparent_history_tests;

#[cfg(test)]
mod tests {
    use super::{
        OvkPolicy, TransferEstimate, TransferFundingSource, TransferOverallStatus,
        TransferSubmissionStatus, UnifiedSpendingKey, allow_exact_send_max_fallback,
        dynamic_zip317_fee_rule, get_from_zero_indexers_with_fallback, hardware_orchard_ovk_policy,
        orchard_circuit_version_for_branch, submit_to_first_accepting_endpoint,
        submit_to_zero_indexers_with_fallback, submit_transfer_transactions_with,
        transaction_request_is_due, transaction_status_from_raw_height, transfer_expiry_height,
        transfer_policies, usk_from_seed_str, validate_expiry_delta_blocks,
    };
    use crate::Network;
    use nonempty::NonEmpty;
    use std::collections::VecDeque;
    use std::time::Duration;
    use zcash_client_backend::data_api::wallet::input_selection::{
        CoinbasePolicy, TransparentSource,
    };
    use zcash_client_backend::data_api::{TransactionStatus, wallet::TargetHeight};
    use zcash_client_backend::fees::TransparentChangePolicy;
    use zcash_client_backend::proto::service;
    use zcash_primitives::transaction::TxId;
    use zcash_protocol::ShieldedPool;
    use zcash_protocol::consensus::BlockHeight;
    use zcash_protocol::value::Zatoshis;

    fn txid(value: u8) -> TxId {
        TxId::from_bytes([value; 32])
    }

    #[test]
    fn nu7_uses_the_ironwood_orchard_circuit() {
        assert_eq!(
            orchard_circuit_version_for_branch(zcash_protocol::consensus::BranchId::Nu7),
            orchard::circuit::OrchardCircuitVersion::PostNu6_3
        );
    }

    #[test]
    fn only_transactions_with_orchard_bundle_use_zero_indexer() {
        // ZIP 244 vector 0 covers an authorized Orchard bundle in serialized form.
        let orchard_bytes = hex::decode(include_str!("wallet/zip244_orchard.hex").trim()).unwrap();
        let orchard_tx = super::Transaction::read(
            orchard_bytes.as_slice(),
            zcash_protocol::consensus::BranchId::Nu5,
        )
        .unwrap();
        assert!(super::requires_zero_indexer(&orchard_tx));

        let transparent_tx = zcash_primitives::transaction::TransactionData::from_parts(
            super::TxVersion::V5,
            zcash_protocol::consensus::BranchId::Nu5,
            0,
            zcash_protocol::consensus::BlockHeight::from_u32(0),
            Some(transparent::bundle::Bundle {
                vin: vec![transparent::bundle::TxIn::from_parts(
                    transparent::bundle::OutPoint::new([7; 32], 0),
                    transparent::address::Script::default(),
                    u32::MAX,
                )],
                vout: vec![transparent::bundle::TxOut::new(
                    Zatoshis::const_from_u64(70_000),
                    transparent::address::Script::default(),
                )],
                authorization: transparent::bundle::Authorized,
            }),
            None,
            None,
            None,
        )
        .freeze()
        .unwrap();
        let mut transparent_bytes = vec![];
        transparent_tx.write(&mut transparent_bytes).unwrap();
        let parsed_transparent = super::Transaction::read(
            transparent_bytes.as_slice(),
            zcash_protocol::consensus::BranchId::Nu5,
        )
        .unwrap();
        assert!(!super::requires_zero_indexer(&parsed_transparent));
    }

    #[test]
    fn orchard_status_request_survives_wallet_restore() {
        use zcash_client_backend::data_api::{
            SentTransaction, TransactionDataRequest, WalletRead, WalletWrite,
        };

        let network = Network::MainNetwork;
        let orchard_bytes = hex::decode(include_str!("wallet/zip244_orchard.hex").trim()).unwrap();
        let vector = super::Transaction::read(
            orchard_bytes.as_slice(),
            zcash_protocol::consensus::BranchId::Nu5,
        )
        .unwrap();
        let tx = zcash_primitives::transaction::TransactionData::from_parts(
            super::TxVersion::V5,
            zcash_protocol::consensus::BranchId::Nu5,
            0,
            vector.expiry_height(),
            None,
            None,
            None,
            vector.orchard_bundle().cloned(),
        )
        .freeze()
        .unwrap();
        let mut db = super::MemoryWalletDb::new(network, 100);
        db.store_transactions_to_be_sent(&[SentTransaction::new(
            &tx,
            time::OffsetDateTime::now_utc(),
            TargetHeight::from(BlockHeight::from_u32(2_000_000)),
            Default::default(),
            &[],
            Zatoshis::ZERO,
            &[],
        )])
        .unwrap();

        let mut bytes = Vec::new();
        db.encode(&mut bytes).unwrap();
        let restored = super::MemoryWalletDb::decode_new(bytes.as_slice(), network, 100).unwrap();
        assert!(
            restored
                .transaction_data_requests()
                .unwrap()
                .contains(&TransactionDataRequest::GetStatus(tx.txid()))
        );
        assert!(super::requires_zero_indexer(
            &restored.get_transaction(tx.txid()).unwrap().unwrap()
        ));

        let mut old_snapshot =
            <zcash_client_memory::proto::memwallet::MemoryWallet as prost::Message>::decode(
                bytes.as_slice(),
            )
            .unwrap();
        old_snapshot.transaction_data_requests.clear();
        let restored_legacy = super::MemoryWalletDb::decode_new(
            <zcash_client_memory::proto::memwallet::MemoryWallet as prost::Message>::encode_to_vec(
                &old_snapshot,
            )
            .as_slice(),
            network,
            100,
        )
        .unwrap();
        assert!(
            restored_legacy
                .transaction_data_requests()
                .unwrap()
                .contains(&TransactionDataRequest::GetStatus(tx.txid()))
        );
    }

    #[tokio::test]
    async fn transparent_history_rpc_does_not_hold_the_wallet_database_lock() {
        use std::sync::Arc;
        use tonic::codegen::http;
        use zcash_client_backend::data_api::{
            AccountBirthday, AccountPurpose, WalletWrite, chain::ChainState,
        };

        #[derive(Clone)]
        struct PendingHistory(Arc<tokio::sync::Notify>);

        impl tonic::client::GrpcService<tonic::body::Body> for PendingHistory {
            type ResponseBody = tonic::body::Body;
            type Error = std::io::Error;
            type Future =
                std::future::Pending<Result<http::Response<Self::ResponseBody>, Self::Error>>;

            fn poll_ready(
                &mut self,
                _: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn call(&mut self, request: http::Request<tonic::body::Body>) -> Self::Future {
                assert!(request.uri().path().ends_with("/GetTaddressTxids"));
                self.0.notify_one();
                std::future::pending()
            }
        }

        let network = Network::MainNetwork;
        let height = BlockHeight::from_u32(3_000_000);
        let ufvk =
            super::UnifiedSpendingKey::from_seed(&network, &[42; 32], zip32::AccountId::ZERO)
                .unwrap()
                .to_unified_full_viewing_key();
        let mut db = super::MemoryWalletDb::new(network, 100);
        db.import_account_ufvk(
            "synthetic recovery test",
            &ufvk,
            &AccountBirthday::from_parts(
                ChainState::empty(height - 1, zcash_primitives::block::BlockHash([0; 32])),
                None,
            ),
            AccountPurpose::ViewOnly,
            None,
        )
        .unwrap();
        db.update_chain_tip(height + 10).unwrap();
        let request_started = Arc::new(tokio::sync::Notify::new());
        let mut wallet = super::Wallet {
            db: Arc::new(tokio::sync::RwLock::new(db)),
            client: super::CompactTxStreamerClient::new(PendingHistory(request_started.clone())),
            zero_indexer_clients: vec![],
            zero_indexer_send_timeout: super::DEFAULT_ZERO_INDEXER_SEND_TIMEOUT,
            network,
            confirmations_policy:
                zcash_client_backend::data_api::wallet::ConfirmationsPolicy::default(),
            compact_block_cdn: None,
            target_note_count: 4,
            min_split_output_value: 10_000_000,
        };
        let zero_request_started = Arc::new(tokio::sync::Notify::new());
        wallet.set_zero_indexer_options(
            vec![PendingHistory(zero_request_started.clone())],
            std::time::Duration::from_millis(50),
        );
        let processing = wallet.process_pending_transaction_requests();
        tokio::pin!(processing);
        tokio::select! {
            result = &mut processing => panic!("history RPC should remain pending: {result:?}"),
            () = request_started.notified() => {},
        }
        assert!(
            wallet.db.try_read().is_ok(),
            "a stalled history RPC must not block balance reads"
        );
        assert!(
            wallet.db.try_write().is_ok(),
            "a stalled history RPC must not block transaction creation"
        );
        use futures_util::FutureExt;
        assert!(
            zero_request_started.notified().now_or_never().is_none(),
            "broadcast settings must not redirect history RPCs"
        );
    }

    #[test]
    fn transparent_recovery_budget_stops_runaway_queries_and_allows_retry() {
        let mut remaining = 2;
        super::consume_transparent_history_budget(&mut remaining).unwrap();
        super::consume_transparent_history_budget(&mut remaining).unwrap();
        assert!(super::consume_transparent_history_budget(&mut remaining).is_err());
        assert_eq!(remaining, 0, "exhaustion must not wrap the counter");
        let mut retry_budget = 2;
        super::consume_transparent_history_budget(&mut retry_budget).unwrap();
    }

    #[test]
    fn transparent_recovery_request_timing() {
        let future = std::time::SystemTime::from(time::OffsetDateTime::now_utc())
            + std::time::Duration::from_secs(60);
        assert!(transaction_request_is_due(None));
        assert!(transaction_request_is_due(Some(
            std::time::SystemTime::UNIX_EPOCH
        )));
        assert!(!transaction_request_is_due(Some(future)));
    }
    #[test]
    fn raw_transaction_height_maps_to_wallet_status() {
        let txid = txid(9);

        assert_eq!(
            transaction_status_from_raw_height(txid, 0).unwrap(),
            TransactionStatus::NotInMainChain
        );
        assert_eq!(
            transaction_status_from_raw_height(txid, u64::MAX).unwrap(),
            TransactionStatus::NotInMainChain
        );
        assert_eq!(
            transaction_status_from_raw_height(txid, 3_472_762).unwrap(),
            TransactionStatus::Mined(BlockHeight::from_u32(3_472_762))
        );
        assert!(transaction_status_from_raw_height(txid, u64::from(u32::MAX) + 1).is_err());
    }

    fn two_raw_transactions() -> NonEmpty<super::TransactionToSubmit> {
        NonEmpty {
            head: super::TransactionToSubmit {
                txid: txid(1),
                raw: service::RawTransaction {
                    data: vec![1],
                    ..Default::default()
                },
                requires_zero_indexer: false,
            },
            tail: vec![super::TransactionToSubmit {
                txid: txid(2),
                raw: service::RawTransaction {
                    data: vec![2],
                    ..Default::default()
                },
                requires_zero_indexer: true,
            }],
        }
    }

    #[tokio::test]
    async fn transfer_submission_reports_all_successes_in_order() {
        let mut routes = vec![];
        let result = submit_transfer_transactions_with(two_raw_transactions(), |_, route| {
            routes.push(route);
            async { Ok(service::SendResponse::default()) }
        })
        .await;

        assert_eq!(result.status, TransferOverallStatus::Success);
        assert_eq!(
            result.tx_ids,
            vec![txid(1).to_string(), txid(2).to_string()]
        );
        assert_eq!(result.final_tx_id, txid(2).to_string());
        assert!(
            result
                .transactions
                .iter()
                .all(|tx| tx.status == TransferSubmissionStatus::Submitted)
        );
        assert_eq!(routes, vec![false, true]);
    }

    #[tokio::test]
    async fn zero_indexer_tries_ordered_endpoints_until_acceptance() {
        let mut attempts = vec![];
        let raw = service::RawTransaction {
            data: vec![42],
            ..Default::default()
        };
        let response =
            submit_to_first_accepting_endpoint(3, raw, Duration::from_secs(1), |index, raw| {
                attempts.push((index, raw.data));
                async move {
                    if index == 0 {
                        Err(tonic::Status::unavailable("offline"))
                    } else if index == 1 {
                        Ok(service::SendResponse {
                            error_code: -25,
                            error_message: "rejected".into(),
                        })
                    } else {
                        Ok(service::SendResponse::default())
                    }
                }
            })
            .await
            .unwrap();
        assert_eq!(response.error_code, 0);
        assert_eq!(attempts, vec![(0, vec![42]), (1, vec![42]), (2, vec![42])]);
    }

    #[tokio::test]
    async fn get_transaction_uses_next_zero_indexer_after_not_found() {
        let filter = service::TxFilter {
            hash: txid(3).as_ref().to_vec(),
            ..Default::default()
        };
        let mut attempts = Vec::new();
        let mut fallback_called = false;
        let raw = get_from_zero_indexers_with_fallback(
            2,
            filter.clone(),
            Duration::from_secs(1),
            |index, candidate| {
                attempts.push((index, candidate.hash));
                async move {
                    if index == 0 {
                        Err(tonic::Status::not_found("not indexed"))
                    } else {
                        Ok(service::RawTransaction {
                            data: vec![3],
                            ..Default::default()
                        })
                    }
                }
            },
            |_| {
                fallback_called = true;
                async { Err(tonic::Status::internal("unexpected fallback")) }
            },
        )
        .await
        .unwrap();
        assert_eq!(raw.data, vec![3]);
        assert_eq!(attempts, vec![(0, filter.hash.clone()), (1, filter.hash)]);
        assert!(!fallback_called);
    }

    #[tokio::test]
    async fn get_transaction_falls_back_after_zero_indexer_timeout_and_error() {
        let filter = service::TxFilter {
            hash: txid(4).as_ref().to_vec(),
            ..Default::default()
        };
        let attempts = std::cell::RefCell::new(Vec::new());
        let raw = get_from_zero_indexers_with_fallback(
            2,
            filter.clone(),
            Duration::from_millis(1),
            |index, candidate| {
                attempts.borrow_mut().push((index, candidate.hash));
                async move {
                    if index == 0 {
                        std::future::pending::<()>().await;
                    }
                    Err(tonic::Status::unavailable("offline"))
                }
            },
            |candidate| {
                attempts.borrow_mut().push((2, candidate.hash));
                async {
                    Ok(service::RawTransaction {
                        data: vec![4],
                        ..Default::default()
                    })
                }
            },
        )
        .await
        .unwrap();
        assert_eq!(raw.data, vec![4]);
        assert_eq!(
            attempts.into_inner(),
            vec![
                (0, filter.hash.clone()),
                (1, filter.hash.clone()),
                (2, filter.hash)
            ]
        );
    }

    #[tokio::test]
    async fn zero_indexer_timeout_advances_and_acceptance_skips_fallback() {
        let mut attempts = vec![];
        let mut fallback_called = false;
        let response = submit_to_zero_indexers_with_fallback(
            2,
            service::RawTransaction::default(),
            Duration::from_millis(1),
            |index, _| {
                attempts.push(index);
                async move {
                    if index == 0 {
                        std::future::pending::<()>().await;
                    }
                    Ok(service::SendResponse::default())
                }
            },
            |_| {
                fallback_called = true;
                async { Ok(service::SendResponse::default()) }
            },
        )
        .await
        .unwrap();
        assert_eq!(response.error_code, 0);
        assert_eq!(attempts, vec![0, 1]);
        assert!(!fallback_called);
    }

    #[tokio::test]
    async fn zero_indexer_failures_fall_back_with_same_raw_transaction() {
        let attempts = std::cell::RefCell::new(vec![]);
        let raw = service::RawTransaction {
            data: vec![42],
            ..Default::default()
        };
        let response = submit_to_zero_indexers_with_fallback(
            2,
            raw,
            Duration::from_secs(1),
            |index, raw| {
                attempts.borrow_mut().push((index, raw.data));
                async {
                    Ok(service::SendResponse {
                        error_code: -25,
                        error_message: "rejected".into(),
                    })
                }
            },
            |raw| {
                attempts.borrow_mut().push((2, raw.data));
                async { Ok(service::SendResponse::default()) }
            },
        )
        .await
        .unwrap();
        assert_eq!(response.error_code, 0);
        assert_eq!(
            attempts.into_inner(),
            vec![(0, vec![42]), (1, vec![42]), (2, vec![42])]
        );
    }

    #[tokio::test]
    async fn ambiguous_zero_indexer_outcome_is_not_reclassified_as_rejection() {
        let status = submit_to_zero_indexers_with_fallback(
            1,
            service::RawTransaction::default(),
            Duration::from_secs(1),
            |_, _| async { Err(tonic::Status::unavailable("offline")) },
            |_| async {
                Ok(service::SendResponse {
                    error_code: -26,
                    error_message: "rejected".into(),
                })
            },
        )
        .await
        .unwrap_err();
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert!(status.message().contains("endpoint 1"));
        assert!(status.message().contains("offline"));
        assert!(status.message().contains("code -26"));
    }

    #[tokio::test]
    async fn transfer_submission_stops_after_first_rejection() {
        let mut responses = VecDeque::from([
            Ok(service::SendResponse {
                error_code: -25,
                error_message: "rejected by server".to_string(),
            }),
            Ok(service::SendResponse::default()),
        ]);

        let result = submit_transfer_transactions_with(two_raw_transactions(), |_, _| {
            let response = responses.pop_front().unwrap();
            async move { response }
        })
        .await;

        assert_eq!(result.status, TransferOverallStatus::Failed);
        assert_eq!(
            result.transactions[0].status,
            TransferSubmissionStatus::Rejected
        );
        assert_eq!(result.transactions[0].error_code, Some(-25));
        assert_eq!(
            result.transactions[0].error_message.as_deref(),
            Some("rejected by server")
        );
        assert_eq!(
            result.transactions[1].status,
            TransferSubmissionStatus::NotAttempted
        );
        assert_eq!(responses.len(), 1);
    }

    #[tokio::test]
    async fn transfer_submission_reports_partial_after_later_rejection() {
        let mut responses = VecDeque::from([
            Ok(service::SendResponse::default()),
            Ok(service::SendResponse {
                error_code: -26,
                error_message: "later transaction rejected".to_string(),
            }),
        ]);

        let result = submit_transfer_transactions_with(two_raw_transactions(), |_, _| {
            let response = responses.pop_front().unwrap();
            async move { response }
        })
        .await;

        assert_eq!(result.status, TransferOverallStatus::Partial);
        assert_eq!(
            result.transactions[0].status,
            TransferSubmissionStatus::Submitted
        );
        assert_eq!(
            result.transactions[1].status,
            TransferSubmissionStatus::Rejected
        );
        assert_eq!(result.transactions[1].error_code, Some(-26));
        assert_eq!(
            result.transactions[1].error_message.as_deref(),
            Some("later transaction rejected")
        );
    }

    #[tokio::test]
    async fn transfer_submission_stops_after_transport_uncertainty() {
        let mut responses = VecDeque::from([
            Err(tonic::Status::unavailable("offline")),
            Ok(service::SendResponse::default()),
        ]);

        let result = submit_transfer_transactions_with(two_raw_transactions(), |_, _| {
            let response = responses.pop_front().unwrap();
            async move { response }
        })
        .await;

        assert_eq!(result.status, TransferOverallStatus::Unknown);
        assert_eq!(
            result.transactions[0].status,
            TransferSubmissionStatus::Unknown
        );
        assert_eq!(result.transactions[0].error_code, None);
        assert!(
            result.transactions[0]
                .error_message
                .as_deref()
                .unwrap()
                .contains("offline")
        );
        assert_eq!(
            result.transactions[1].status,
            TransferSubmissionStatus::NotAttempted
        );
        assert_eq!(responses.len(), 1);
    }

    #[test]
    fn unified_transfer_optional_values_use_existing_validation() {
        assert!(dynamic_zip317_fee_rule(0).is_err());
        assert!(dynamic_zip317_fee_rule(5_000).is_ok());
        assert!(validate_expiry_delta_blocks(0).is_err());
        assert_eq!(validate_expiry_delta_blocks(12).unwrap(), 12);
    }

    #[test]
    fn transfer_expiry_uses_the_proposal_target() {
        let min_target = TargetHeight::from(BlockHeight::from_u32(2_000_000));
        assert_eq!(
            transfer_expiry_height(min_target, Some(12)).unwrap(),
            Some(BlockHeight::from_u32(2_000_012)),
        );
        assert_eq!(transfer_expiry_height(min_target, None).unwrap(), None);
    }

    #[test]
    fn send_max_fallback_is_only_enabled_for_dynamic_shielded_transfers() {
        assert!(!allow_exact_send_max_fallback(
            TransferFundingSource::Shielded,
            false,
        ));
        assert!(allow_exact_send_max_fallback(
            TransferFundingSource::Shielded,
            true,
        ));
        assert!(!allow_exact_send_max_fallback(
            TransferFundingSource::Transparent,
            true,
        ));
    }

    #[test]
    fn transparent_transfer_policies_exclude_shielded_funds_and_allow_transparent_change() {
        let (spend_policy, change_policy) = transfer_policies(TransferFundingSource::Transparent);

        assert!(!spend_policy.permits_shielded(ShieldedPool::Sapling));
        assert!(!spend_policy.permits_shielded(ShieldedPool::Orchard));
        assert!(!spend_policy.permits_shielded(ShieldedPool::Ironwood));
        let transparent = spend_policy.transparent().unwrap();
        assert!(matches!(
            transparent.source(),
            TransparentSource::AnyAccountAddr
        ));
        assert_eq!(transparent.coinbase(), CoinbasePolicy::NonCoinbase);
        assert_eq!(
            change_policy,
            TransparentChangePolicy::TransparentChangeAllowed
        );
    }

    #[test]
    fn transfer_funding_source_accepts_only_documented_values() {
        assert_eq!(
            "shielded".parse::<TransferFundingSource>().unwrap(),
            TransferFundingSource::Shielded
        );
        assert_eq!(
            "transparent".parse::<TransferFundingSource>().unwrap(),
            TransferFundingSource::Transparent
        );
        assert!("mixed".parse::<TransferFundingSource>().is_err());
        assert!("Shielded".parse::<TransferFundingSource>().is_err());
    }

    #[test]
    fn hardware_review_policy_uses_orchard_ovks() {
        let ufvk =
            UnifiedSpendingKey::from_seed(&Network::MainNetwork, &[17; 32], zip32::AccountId::ZERO)
                .unwrap()
                .to_unified_full_viewing_key();
        let orchard_fvk = ufvk.orchard().unwrap();

        match hardware_orchard_ovk_policy(&ufvk).unwrap() {
            OvkPolicy::Custom {
                external_ovk,
                internal_ovk,
            } => {
                assert_eq!(
                    external_ovk.as_ref(),
                    orchard_fvk.to_ovk(orchard::keys::Scope::External).as_ref()
                );
                assert_eq!(
                    internal_ovk.unwrap().as_ref(),
                    orchard_fvk.to_ovk(orchard::keys::Scope::Internal).as_ref()
                );
            }
            policy => panic!("unexpected hardware review policy: {policy:?}"),
        }
    }

    #[test]
    fn shielded_transfer_policy_excludes_transparent_inputs() {
        let (spend, change) = transfer_policies(TransferFundingSource::Shielded);
        assert!(spend.permits_shielded(ShieldedPool::Sapling));
        assert!(spend.permits_shielded(ShieldedPool::Orchard));
        assert!(spend.permits_shielded(ShieldedPool::Ironwood));
        assert!(spend.transparent().is_none());
        assert_eq!(change, TransparentChangePolicy::ShieldChange);
    }

    #[test]
    fn transfer_estimate_preserves_step_fee_order_and_total() {
        let estimate = TransferEstimate::from_amount_and_step_fees(
            Zatoshis::const_from_u64(50_000),
            [
                Zatoshis::const_from_u64(15_000),
                Zatoshis::const_from_u64(10_000),
            ],
            5_000,
        )
        .unwrap();
        assert_eq!(estimate.amount_zats, "50000");
        assert_eq!(estimate.fee_zats, "25000");
        assert_eq!(estimate.marginal_fee_zats, "5000");
        assert_eq!(estimate.transaction_count, 2);
        assert_eq!(estimate.step_fees_zats, ["15000", "10000"]);
    }

    #[test]
    fn usk_from_seed_str_uses_bip39_passphrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

        let (_, empty_passphrase_fingerprint) =
            usk_from_seed_str(phrase, "", 0, &Network::MainNetwork).unwrap();
        let (_, protected_fingerprint) = usk_from_seed_str(
            phrase,
            "correct horse battery staple",
            0,
            &Network::MainNetwork,
        )
        .unwrap();

        assert_ne!(
            empty_passphrase_fingerprint.to_bytes(),
            protected_fingerprint.to_bytes()
        );
    }
}
