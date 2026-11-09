#![allow(dead_code)]

mod serialization;

use std::{
    collections::{BTreeMap, BTreeSet, btree_map::Entry},
    num::NonZeroU32,
    ops::{Range, RangeInclusive},
    sync::Arc,
};

use ::transparent::bundle::OutPoint;
#[cfg(feature = "transparent-inputs")]
use ::transparent::keys::{NonHardenedChildIndex, TransparentKeyScope};
use incrementalmerkletree::{Address, Level, Marking, Position, Retention};
use scanning::ScanQueue;
use shardtree::{
    ShardTree,
    store::{ShardStore, memory::MemoryShardStore},
};
#[cfg(feature = "transparent-inputs")]
use zcash_client_backend::wallet::TransparentAddressMetadata;
use zcash_client_backend::{
    data_api::{
        Account as _, AccountBirthday, AccountSource, InputSource, Ratio, SAPLING_SHARD_HEIGHT,
        TransactionStatus, WalletRead,
        scanning::{ScanPriority, ScanRange},
        wallet::{ConfirmationsPolicy, TargetHeight},
    },
    wallet::{NoteId, OutputRef, WalletSaplingOutput},
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_primitives::transaction::{Transaction, fees::zip317};
use zcash_protocol::{
    ShieldedPool, TxId,
    consensus::{self, BlockHeight, NetworkUpgrade, TxIndex},
    value::Zatoshis,
};
use zip32::{Scope, fingerprint::SeedFingerprint};

#[cfg(feature = "orchard")]
use zcash_client_backend::{
    data_api::ORCHARD_SHARD_HEIGHT,
    wallet::{WalletIronwoodOutput, WalletOrchardOutput},
};

#[cfg(feature = "transparent-inputs")]
use {
    ::transparent::address::TransparentAddress,
    zcash_client_backend::wallet::WalletTransparentOutput,
};

use crate::error::Error;
use crate::types::transparent::{
    TransparentReceivedOutputSpends, TransparentReceivedOutputs, TransparentSpendCache,
};
use crate::types::*;

/// An opaque, process-local revision of a wallet's chain state.
///
/// Retain a revision before releasing a database lock for a network query, then
/// compare it under the same lock used to apply the reply. Rewinds and database
/// replacement invalidate earlier revisions, even if the chain height returns
/// to its original value. Revisions are deliberately not serialized.
#[derive(Clone, Debug)]
pub struct ChainStateRevision(Arc<()>);

impl ChainStateRevision {
    pub(crate) fn new() -> Self {
        Self(Arc::new(()))
    }
}

impl PartialEq for ChainStateRevision {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}

impl Eq for ChainStateRevision {}

/// The main in-memory wallet database. Implements all the traits needed to be used as a backend.
#[derive(Debug)]
pub struct MemoryWalletDb<P: consensus::Parameters> {
    /// Runtime-only invalidation of outstanding network queries; not wallet data.
    pub(crate) chain_state_revision: ChainStateRevision,
    /// Zcash network parameters for wallet
    pub(crate) params: P,
    /// The accounts in the wallet
    pub(crate) accounts: Accounts,
    /// The wallet that have been scanned and cached that contain relevant wallet data
    pub(crate) blocks: BTreeMap<BlockHeight, MemoryWalletBlock>,
    /// Scanned transactions relevant to accounts in this wallet
    pub(crate) tx_table: TransactionTable,
    /// Notes that an account has received
    pub(crate) received_notes: ReceivedNoteTable,
    /// Notes that have been spent
    pub(crate) received_note_spends: ReceievedNoteSpends,
    /// Nullifiers for notes that have been spent
    pub(crate) nullifiers: NullifierMap,
    /// Stores the outputs of transactions created by the wallet.
    pub(crate) sent_notes: SentNoteTable,
    /// Maps transaction ids to their block height and index
    pub(crate) tx_locator: TxLocatorMap,
    /// Sapling commitment tree
    pub(crate) sapling_tree: ShardTree<
        MemoryShardStore<sapling::Node, BlockHeight>,
        { SAPLING_SHARD_HEIGHT * 2 },
        SAPLING_SHARD_HEIGHT,
    >,
    /// Stores the block height corresponding to the last note commitment in a shard
    pub(crate) sapling_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,
    /// Orchard commitment tree
    #[cfg(feature = "orchard")]
    pub(crate) orchard_tree: ShardTree<
        MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>,
        { ORCHARD_SHARD_HEIGHT * 2 },
        ORCHARD_SHARD_HEIGHT,
    >,
    #[cfg(feature = "orchard")]
    /// Stores the block height corresponding to the last note commitment in a shard
    pub(crate) orchard_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,
    /// Ironwood commitment tree.
    #[cfg(feature = "orchard")]
    pub(crate) ironwood_tree: ShardTree<
        MemoryShardStore<orchard::tree::MerkleHashOrchard, BlockHeight>,
        { ORCHARD_SHARD_HEIGHT * 2 },
        ORCHARD_SHARD_HEIGHT,
    >,
    /// Stores the block height corresponding to the last Ironwood note commitment in a shard.
    #[cfg(feature = "orchard")]
    pub(crate) ironwood_tree_shard_end_heights: BTreeMap<Address, BlockHeight>,

    /// Transparent outputs received by the wallet
    pub(crate) transparent_received_outputs: TransparentReceivedOutputs,
    /// Transparent outputs received by the wallet that have been spent
    pub(crate) transparent_received_output_spends: TransparentReceivedOutputSpends,
    /// Map between transparent outpoints and their spend transactions
    pub(crate) transparent_spend_map: TransparentSpendCache,

    /// Pending requests to the external data provider to enhance transaction data
    pub(crate) transaction_data_request_queue: TransactionDataRequestQueue,
    /// Queue of block ranges that should be scanned along with their priority
    pub(crate) scan_queue: ScanQueue,
    pub(crate) output_locks: BTreeMap<OutputRef, crate::output_locks::OutputLock>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SpendabilityDiagnostics {
    incomplete_note_count: usize,
    incomplete_value: Zatoshis,
}

impl Default for SpendabilityDiagnostics {
    fn default() -> Self {
        Self {
            incomplete_note_count: 0,
            incomplete_value: Zatoshis::ZERO,
        }
    }
}

impl SpendabilityDiagnostics {
    pub fn incomplete_note_count(&self) -> usize {
        self.incomplete_note_count
    }

    pub fn incomplete_value(&self) -> Zatoshis {
        self.incomplete_value
    }
}

impl<P: consensus::Parameters + PartialEq> PartialEq for MemoryWalletDb<P> {
    /// Tests for equality between two `MemoryWalletDb` instances.
    /// but does NOT compare the sapling_tree and orchard_tree fields.
    fn eq(&self, other: &Self) -> bool {
        #[cfg(feature = "orchard")]
        let orchard_comparisons = self.orchard_tree_shard_end_heights
            == other.orchard_tree_shard_end_heights
            && self.ironwood_tree_shard_end_heights == other.ironwood_tree_shard_end_heights;
        #[cfg(not(feature = "orchard"))]
        let orchard_comparisons = true;

        #[cfg(feature = "transparent-inputs")]
        let transparent_comparisons = {
            self.transparent_received_outputs == other.transparent_received_outputs
                && self.transparent_received_output_spends
                    == other.transparent_received_output_spends
                && self.transparent_spend_map == other.transparent_spend_map
        };
        #[cfg(not(feature = "transparent-inputs"))]
        let transparent_comparisons = true;

        self.params == other.params
            && self.accounts == other.accounts
            && self.blocks == other.blocks
            && self.tx_table == other.tx_table
            && self.received_notes == other.received_notes
            && self.received_note_spends == other.received_note_spends
            && self.nullifiers == other.nullifiers
            && self.sent_notes == other.sent_notes
            && self.tx_locator == other.tx_locator
            && self.scan_queue == other.scan_queue
            && self.output_locks == other.output_locks
            && self.sapling_tree_shard_end_heights == other.sapling_tree_shard_end_heights
            && orchard_comparisons
            && transparent_comparisons
            && self.transaction_data_request_queue == other.transaction_data_request_queue
    }
}

fn classify_transaction_history_entry(
    received_zatoshis: i64,
    sent_zatoshis: i64,
    change_zatoshis: i64,
    spent_input_zatoshis: i64,
    transparent_spent_zatoshis: i64,
    fee_zatoshis: Option<i64>,
) -> (&'static str, i64) {
    let shielded_output_zatoshis = received_zatoshis + change_zatoshis;

    if transparent_spent_zatoshis > 0 && shielded_output_zatoshis > 0 {
        ("shield", shielded_output_zatoshis)
    } else if received_zatoshis > 0 && sent_zatoshis > 0 {
        ("shield", received_zatoshis)
    } else if sent_zatoshis > 0 {
        ("send", sent_zatoshis - change_zatoshis)
    } else if spent_input_zatoshis > 0 && received_zatoshis == 0 {
        let net_send = spent_input_zatoshis - change_zatoshis - fee_zatoshis.unwrap_or(0);
        ("send", net_send.max(0))
    } else if change_zatoshis > 0 && received_zatoshis == 0 {
        ("send", 0)
    } else {
        ("receive", received_zatoshis)
    }
}

fn transparent_spent_zatoshis_for_account(
    outputs: &TransparentReceivedOutputs,
    spends: &TransparentReceivedOutputSpends,
    txid: TxId,
    account_id: AccountId,
) -> i64 {
    spends
        .iter()
        .filter(|(_, spend_txid)| **spend_txid == txid)
        .filter_map(|(outpoint, _)| {
            outputs
                .get(outpoint)
                .filter(|output| output.account_id == account_id)
                .map(|output| u64::from(output.txout.value()) as i64)
        })
        .sum()
}

impl<P: consensus::Parameters> MemoryWalletDb<P> {
    pub fn new(params: P, max_checkpoints: usize) -> Self {
        Self {
            chain_state_revision: ChainStateRevision::new(),
            accounts: Accounts::new(),
            params,
            blocks: BTreeMap::new(),
            sapling_tree: ShardTree::new(MemoryShardStore::empty(), max_checkpoints),
            sapling_tree_shard_end_heights: BTreeMap::new(),
            #[cfg(feature = "orchard")]
            orchard_tree: ShardTree::new(MemoryShardStore::empty(), max_checkpoints),
            #[cfg(feature = "orchard")]
            orchard_tree_shard_end_heights: BTreeMap::new(),
            #[cfg(feature = "orchard")]
            ironwood_tree: ShardTree::new(MemoryShardStore::empty(), max_checkpoints),
            #[cfg(feature = "orchard")]
            ironwood_tree_shard_end_heights: BTreeMap::new(),
            tx_table: TransactionTable::new(),
            received_notes: ReceivedNoteTable::new(),
            sent_notes: SentNoteTable::new(),
            nullifiers: NullifierMap::new(),
            tx_locator: TxLocatorMap::new(),
            received_note_spends: ReceievedNoteSpends::new(),
            scan_queue: ScanQueue::new(),
            output_locks: BTreeMap::new(),
            transparent_received_outputs: TransparentReceivedOutputs::new(),
            transparent_received_output_spends: TransparentReceivedOutputSpends::new(),
            transparent_spend_map: TransparentSpendCache::new(),
            transaction_data_request_queue: TransactionDataRequestQueue::new(),
        }
    }

    pub fn params(&self) -> &P {
        &self.params
    }

    /// Returns the current process-local chain revision.
    ///
    /// A retained revision remains valid across forward synchronization and local
    /// transaction creation, but not across a rewind or replacement of this database.
    /// Callers must compare revisions while holding the lock used to apply a reply.
    pub fn chain_state_revision(&self) -> ChainStateRevision {
        self.chain_state_revision.clone()
    }

    pub(crate) fn add_account(
        &mut self,
        account_name: &str,
        kind: AccountSource,
        viewing_key: UnifiedFullViewingKey,
        birthday: AccountBirthday,
    ) -> Result<(AccountId, Account), Error> {
        let (id, account) = self.accounts.new_account(
            account_name,
            kind,
            viewing_key.to_owned(),
            birthday.clone(),
        )?;

        // If a birthday frontier is available, insert it into the note commitment tree. If the
        // birthday frontier is the empty frontier, we don't need to do anything.
        if let Some(frontier) = birthday.sapling_frontier().value() {
            tracing::debug!("Inserting Sapling frontier into ShardTree: {:?}", frontier);
            self.sapling_tree.insert_frontier_nodes(
                frontier.clone(),
                Retention::Checkpoint {
                    // This subtraction is safe, because all leaves in the tree appear in blocks, and
                    // the invariant that birthday.height() always corresponds to the block for which
                    // `frontier` is the tree state at the start of the block. Together, this means
                    // there exists a prior block for which frontier is the tree state at the end of
                    // the block.
                    id: birthday.height() - 1,
                    marking: Marking::Reference,
                },
            )?;
        }

        #[cfg(feature = "orchard")]
        if let Some(frontier) = birthday.orchard_frontier().value() {
            tracing::debug!("Inserting Orchard frontier into ShardTree: {:?}", frontier);
            self.orchard_tree.insert_frontier_nodes(
                frontier.clone(),
                Retention::Checkpoint {
                    // This subtraction is safe, because all leaves in the tree appear in blocks, and
                    // the invariant that birthday.height() always corresponds to the block for which
                    // `frontier` is the tree state at the start of the block. Together, this means
                    // there exists a prior block for which frontier is the tree state at the end of
                    // the block.
                    id: birthday.height() - 1,
                    marking: Marking::Reference,
                },
            )?;
        }

        #[cfg(feature = "orchard")]
        if let Some(frontier) = birthday.prior_chain_state().final_ironwood_tree().value() {
            tracing::debug!("Inserting Ironwood frontier into ShardTree: {:?}", frontier);
            self.ironwood_tree.insert_frontier_nodes(
                frontier.clone(),
                Retention::Checkpoint {
                    id: birthday.height() - 1,
                    marking: Marking::Reference,
                },
            )?;
        }

        // The ignored range always starts at Sapling activation
        let sapling_activation_height = self
            .params
            .activation_height(NetworkUpgrade::Sapling)
            .expect("Sapling activation height must be available.");

        // Add the ignored range up to the birthday height.
        if sapling_activation_height < birthday.height() {
            let ignored_range = sapling_activation_height..birthday.height();
            self.scan_queue.replace_queue_entries(
                &ignored_range,
                Some(ScanRange::from_parts(
                    ignored_range.clone(),
                    ScanPriority::Ignored,
                ))
                .into_iter(),
                false,
            )?;
        };

        // Rewrite the scan ranges from the birthday height up to the chain tip so that we'll ensure we
        // re-scan to find any notes that might belong to the newly added account.
        if let Some(t) = self.chain_height()? {
            let rescan_range = birthday.height()..(t + 1);
            self.scan_queue.replace_queue_entries(
                &rescan_range,
                Some(ScanRange::from_parts(
                    rescan_range.clone(),
                    ScanPriority::Historic,
                ))
                .into_iter(),
                true, // force rescan
            )?;
        }

        Ok((id, account))
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn first_unsafe_index(&self, account_id: AccountId) -> Result<u32, Error> {
        let first_unmined_index = if let Some(account) = self.accounts.get(account_id) {
            let mut idx = 0;
            for (tidx, eph_addr) in account.ephemeral_addresses.iter().rev() {
                if eph_addr
                    .seen
                    .and_then(|txid| self.tx_table.get(&txid))
                    .and_then(|tx| tx.mined_height())
                    .is_some()
                {
                    idx = tidx.checked_add(1).unwrap();
                    break;
                }
            }
            idx
        } else {
            0
        };

        Ok(core::cmp::min(
            1 << 31,
            first_unmined_index
                .checked_add(account::EPHEMERAL_GAP_LIMIT)
                .unwrap(),
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn first_internal_gap_index(&self, account_id: AccountId) -> Result<u32, Error> {
        let account = self
            .accounts
            .get(account_id)
            .ok_or(Error::AccountUnknown(account_id))?;

        Ok(self
            .transparent_received_outputs
            .values()
            .filter(|output| {
                output.account_id == account_id
                    && output.key_scope == TransparentKeyScope::INTERNAL
                    && self
                        .tx_table
                        .get(&output.transaction_id)
                        .and_then(|tx| tx.mined_height())
                        .is_some()
            })
            .filter_map(|output| account.internal_address_index(&output.address))
            .max()
            .map_or(0, |index| {
                index
                    .checked_add(1)
                    .expect("internal address index is non-hardened")
            }))
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn first_internal_unsafe_index(&self, account_id: AccountId) -> Result<u32, Error> {
        Ok(core::cmp::min(
            1 << 31,
            self.first_internal_gap_index(account_id)?
                .checked_add(account::INTERNAL_GAP_LIMIT)
                .expect("internal gap limit fits in the non-hardened index range"),
        ))
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn ensure_internal_address_gaps(&mut self) -> Result<(), Error> {
        let gaps = self
            .accounts
            .account_ids()
            .map(|id| self.first_internal_gap_index(*id).map(|gap| (*id, gap)))
            .collect::<Result<Vec<_>, _>>()?;
        for (id, gap) in gaps {
            self.accounts
                .get_mut(id)
                .ok_or(Error::AccountUnknown(id))?
                .ensure_internal_gap(gap)?;
        }
        Ok(())
    }

    pub(crate) fn get_funding_accounts(
        &self,
        tx: &Transaction,
    ) -> Result<BTreeSet<AccountId>, Error> {
        let mut funding_accounts = BTreeSet::new();
        #[cfg(feature = "transparent-inputs")]
        funding_accounts.extend(
            self.transparent_received_outputs.detect_spending_accounts(
                tx.transparent_bundle()
                    .iter()
                    .flat_map(|bundle| bundle.vin.iter().map(|txin| txin.prevout())),
            )?,
        );

        funding_accounts.extend(self.received_notes.detect_sapling_spending_accounts(
            tx.sapling_bundle().iter().flat_map(|bundle| {
                bundle
                    .shielded_spends()
                    .iter()
                    .map(|spend| spend.nullifier())
            }),
        )?);

        #[cfg(feature = "orchard")]
        funding_accounts.extend(
            self.received_notes.detect_orchard_spending_accounts(
                tx.orchard_bundle()
                    .iter()
                    .flat_map(|bundle| bundle.actions().iter().map(|action| action.nullifier())),
            )?,
        );
        #[cfg(feature = "orchard")]
        funding_accounts.extend(
            self.received_notes.detect_orchard_spending_accounts(
                tx.ironwood_bundle()
                    .iter()
                    .flat_map(|bundle| bundle.actions().iter().map(|action| action.nullifier())),
            )?,
        );

        Ok(funding_accounts)
    }

    pub(crate) fn get_received_notes(&self) -> &ReceivedNoteTable {
        &self.received_notes
    }

    // TODO: Update this if we switch from using a vec to store received notes to
    // someething with more efficient lookups
    pub(crate) fn get_received_note(&self, note_id: NoteId) -> Option<&ReceivedNote> {
        self.received_notes.iter().find(|v| v.note_id() == note_id)
    }

    pub(crate) fn mark_sapling_note_spent(
        &mut self,
        nf: sapling::Nullifier,
        txid: TxId,
    ) -> Result<(), Error> {
        let note_id = self
            .received_notes
            .iter()
            .filter(|v| v.nullifier() == Some(&Nullifier::Sapling(nf)))
            .map(|v| v.note_id())
            .next()
            .ok_or(Error::NoteNotFound)?;
        self.received_note_spends.insert_spend(note_id, txid);
        self.output_locks.remove(&note_id.into());
        Ok(())
    }

    /// Returns true if the note is in the spent notes table and the transaction that spent it is
    /// in the transaction table and has either been mined or can be mined in the future
    /// (i.e. it hasn't or will not expire)
    pub(crate) fn note_is_spent(
        &self,
        note: &ReceivedNote,
        target_height: TargetHeight,
    ) -> Result<bool, Error> {
        let spend = self.received_note_spends.get(&note.note_id());

        let spent = match spend {
            Some(txid) => {
                let spending_tx = self
                    .tx_table
                    .get(txid)
                    .ok_or(Error::TransactionNotFound(*txid))?;
                match spending_tx.status() {
                    TransactionStatus::Mined(_height) => true,
                    TransactionStatus::TxidNotRecognized | TransactionStatus::NotInMainChain => {
                        // transaction either never expires, or expires in the future.
                        spending_tx
                            .expiry_height()
                            .iter()
                            .all(|h| *h >= BlockHeight::from(target_height))
                    }
                }
            }
            None => false,
        };
        Ok(spent)
    }

    /// To be spendable a note must be:
    /// - unspent (obviously)
    /// - not dust (value greater than the ZIP 317 marginal fee)
    /// - be associated with an account with a ufvk
    /// - have a recipient key scope
    /// - We know the nullifier
    /// - We know the commitment tree position
    /// - be in a block less than or equal to the anchor height
    /// - not be in the given exclude list
    ///
    /// Additionally the tree shard containing the node must not be in an unscanned range
    /// excluding ranges that start above the anchor height or end below the wallet birthday.
    /// This is determined by looking at the scan queue
    pub(crate) fn note_is_spendable(
        &self,
        note: &ReceivedNote,
        birthday_height: BlockHeight,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
        exclude: &[<MemoryWalletDb<P> as InputSource>::NoteRef],
    ) -> Result<bool, Error> {
        let note_account = self
            .get_account(note.account_id())?
            .ok_or(Error::AccountUnknown(note.account_id))?;
        let note_txn = self
            .tx_table
            .get(&note.txid())
            .ok_or_else(|| Error::TransactionNotFound(note.txid()))?;

        let unscanned_ranges = self.unscanned_ranges(note.note.pool());
        let anchor_height = target_height - u32::from(confirmations_policy.trusted());

        let note_in_unscanned_range =
            unscanned_ranges
                .iter()
                .any(|(start_height, end_height, start, end_exclusive)| {
                    let in_range = note.commitment_tree_position.is_some_and(|pos| {
                        if let (Some(start), Some(end_exclusive)) = (start, end_exclusive) {
                            pos >= *start && pos < *end_exclusive
                        } else {
                            true
                        }
                    });
                    in_range && *end_height > birthday_height && *start_height <= anchor_height
                });

        Ok(!self.note_is_spent(note, target_height)?
            && !note_in_unscanned_range
            && note.note.value() > zip317::MARGINAL_FEE
            && note_account.ufvk().is_some()
            && note.nullifier().is_some()
            && note.commitment_tree_position.is_some()
            && note_txn.mined_height().is_some()
            && match note.recipient_key_scope {
                Some(Scope::External) => {
                    target_height.saturating_sub(u32::from(confirmations_policy.untrusted()))
                        >= note_txn.mined_height().unwrap()
                }
                Some(Scope::Internal) => {
                    target_height.saturating_sub(u32::from(confirmations_policy.trusted()))
                        >= note_txn.mined_height().unwrap()
                }
                None => false,
            }
            && !exclude.contains(&note.note_id()))
    }

    pub fn spendability_diagnostics(
        &self,
        account_id: AccountId,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<SpendabilityDiagnostics, Error> {
        let chain_tip_height = match self.chain_height()? {
            Some(height) => height,
            None => return Ok(SpendabilityDiagnostics::default()),
        };
        let target_height = TargetHeight::from(chain_tip_height + 1);
        let birthday_height = match self.get_wallet_birthday()? {
            Some(height) => height,
            None => return Ok(SpendabilityDiagnostics::default()),
        };
        let mut diagnostics = SpendabilityDiagnostics::default();

        for note in self
            .received_notes
            .iter()
            .filter(|note| note.account_id() == account_id)
        {
            let transaction = self
                .tx_table
                .get(&note.txid())
                .ok_or_else(|| Error::TransactionNotFound(note.txid()))?;
            if transaction.mined_height().is_none()
                && transaction
                    .expiry_height()
                    .is_some_and(|expiry| expiry < BlockHeight::from(target_height))
            {
                continue;
            }
            if note.note.value() <= zip317::MARGINAL_FEE
                || self.note_is_spent(note, target_height)?
                || self.note_is_pending(note, target_height, confirmations_policy)?
                || self.note_is_spendable(
                    note,
                    birthday_height,
                    target_height,
                    confirmations_policy,
                    &[],
                )?
            {
                continue;
            }

            let account = self
                .get_account(note.account_id())?
                .ok_or(Error::AccountUnknown(note.account_id()))?;
            let ufvk_present = account.ufvk().is_some();
            let nullifier_present = note.nullifier().is_some();
            let position_present = note.commitment_tree_position.is_some();
            let mined_height_present = transaction.mined_height().is_some();
            let key_scope_present = note.recipient_key_scope.is_some();
            let metadata_incomplete = !ufvk_present
                || !nullifier_present
                || !position_present
                || !mined_height_present
                || !key_scope_present;

            if metadata_incomplete {
                // Support logs omit note identifiers and amounts to avoid linking wallet activity.
                tracing::warn!(
                    account_id = *account_id,
                    diagnostic_note_index = diagnostics.incomplete_note_count + 1,
                    pool = %note.pool(),
                    is_change = note.is_change,
                    ufvk_present,
                    nullifier_present,
                    position_present,
                    mined_height_present,
                    key_scope_present,
                    "WALLET_SPENDABILITY_INCONSISTENT note diagnosis"
                );
                diagnostics.incomplete_note_count += 1;
                diagnostics.incomplete_value =
                    (diagnostics.incomplete_value + note.note.value())
                        .ok_or(zcash_protocol::value::BalanceError::Overflow)?;
            }
        }

        Ok(diagnostics)
    }

    /// To be pending a note must be:
    /// - mined, but without sufficient confirmations to be spent; or
    /// - unmined and unexpired
    pub(crate) fn note_is_pending(
        &self,
        note: &ReceivedNote,
        target_height: TargetHeight,
        confirmations_policy: ConfirmationsPolicy,
    ) -> Result<bool, Error> {
        let tx = self
            .tx_table
            .get(&note.txid())
            .ok_or_else(|| Error::TransactionNotFound(note.txid()))?;

        Ok(tx.mined_height().map_or_else(
            || {
                tx.expiry_height()
                    .iter()
                    .all(|h| *h >= BlockHeight::from(target_height))
            },
            |h| match note.recipient_key_scope {
                // If we don't know the recipient key scope, we treat the note as untrusted.
                Some(Scope::External) | None => {
                    BlockHeight::from(target_height) - h
                        < u32::from(confirmations_policy.untrusted())
                }
                Some(Scope::Internal) => {
                    BlockHeight::from(target_height) - h < u32::from(confirmations_policy.trusted())
                }
            },
        ))
    }

    pub(crate) fn summary_height(
        &self,
        min_confirmations: u32,
    ) -> Result<Option<BlockHeight>, Error> {
        let chain_tip_height = match self.chain_height()? {
            Some(height) => height,
            None => return Ok(None),
        };
        let summary_height =
            (chain_tip_height + 1).saturating_sub(std::cmp::max(min_confirmations, 1));
        Ok(Some(summary_height))
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn mark_orchard_note_spent(
        &mut self,
        nf: orchard::note::Nullifier,
        txid: TxId,
    ) -> Result<(), Error> {
        let note_id = self
            .received_notes
            .iter()
            .filter(|v| v.nullifier() == Some(&Nullifier::Orchard(nf)))
            .map(|v| v.note_id())
            .next()
            .ok_or(Error::NoteNotFound)?;
        self.received_note_spends.insert_spend(note_id, txid);
        self.output_locks.remove(&note_id.into());
        Ok(())
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn mark_ironwood_note_spent(
        &mut self,
        nf: orchard::note::Nullifier,
        txid: TxId,
    ) -> Result<(), Error> {
        let note_id = self
            .received_notes
            .iter()
            .find(|v| v.nullifier() == Some(&Nullifier::Ironwood(nf)))
            .map(|v| v.note_id())
            .ok_or(Error::NoteNotFound)?;
        self.received_note_spends.insert_spend(note_id, txid);
        self.output_locks.remove(&note_id.into());
        Ok(())
    }

    pub(crate) fn max_zip32_account_index(
        &self,
        seed_fingerprint: &SeedFingerprint,
    ) -> Result<Option<zip32::AccountId>, Error> {
        Ok(self
            .accounts
            .values()
            .filter_map(|a| match a.source() {
                AccountSource::Derived { derivation, .. } => {
                    if derivation.seed_fingerprint() == seed_fingerprint {
                        Some(derivation.account_index())
                    } else {
                        None
                    }
                }
                _ => None,
            })
            .max())
    }
    pub(crate) fn insert_received_sapling_note(
        &mut self,
        note_id: NoteId,
        output: &WalletSaplingOutput<AccountId>,
        spent_in: Option<TxId>,
    ) {
        self.received_notes
            .insert_received_note(ReceivedNote::from_wallet_sapling_output(note_id, output));
        if let Some(spent_in) = spent_in {
            self.received_note_spends.insert_spend(note_id, spent_in);
            self.output_locks.remove(&note_id.into());
        }
    }
    #[cfg(feature = "orchard")]
    pub(crate) fn insert_received_orchard_note(
        &mut self,
        note_id: NoteId,
        output: &WalletOrchardOutput<AccountId>,
        spent_in: Option<TxId>,
    ) {
        self.received_notes
            .insert_received_note(ReceivedNote::from_wallet_orchard_output(note_id, output));
        if let Some(spent_in) = spent_in {
            self.received_note_spends.insert_spend(note_id, spent_in);
            self.output_locks.remove(&note_id.into());
        }
    }
    #[cfg(feature = "orchard")]
    pub(crate) fn insert_received_ironwood_note(
        &mut self,
        note_id: NoteId,
        output: &WalletIronwoodOutput<AccountId>,
        spent_in: Option<TxId>,
    ) {
        self.received_notes
            .insert_received_note(ReceivedNote::from_wallet_ironwood_output(note_id, output));
        if let Some(spent_in) = spent_in {
            self.received_note_spends.insert_spend(note_id, spent_in);
            self.output_locks.remove(&note_id.into());
        }
    }
    pub(crate) fn insert_sapling_nullifier_map(
        &mut self,
        block_height: BlockHeight,
        new_entries: &[(TxIndex, TxId, Vec<sapling::Nullifier>)],
    ) -> Result<(), Error> {
        for (tx_index, txid, nullifiers) in new_entries {
            for nf in nullifiers.iter() {
                self.nullifiers
                    .insert(block_height, u32::from(*tx_index), Nullifier::Sapling(*nf));
            }
            match self.tx_locator.entry((block_height, u32::from(*tx_index))) {
                Entry::Occupied(x) => {
                    if txid == x.get() {
                        // This is a duplicate entry
                        continue;
                    } else {
                        return Err(Error::ConflictingTxLocator);
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(*txid);
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn insert_orchard_nullifier_map(
        &mut self,
        block_height: BlockHeight,
        new_entries: &[(TxIndex, TxId, Vec<orchard::note::Nullifier>)],
    ) -> Result<(), Error> {
        for (tx_index, txid, nullifiers) in new_entries {
            for nf in nullifiers.iter() {
                self.nullifiers
                    .insert(block_height, u32::from(*tx_index), Nullifier::Orchard(*nf));
            }
            match self.tx_locator.entry((block_height, u32::from(*tx_index))) {
                Entry::Occupied(x) => {
                    if txid == x.get() {
                        // This is a duplicate entry
                        continue;
                    } else {
                        return Err(Error::ConflictingTxLocator);
                    }
                }
                Entry::Vacant(entry) => {
                    entry.insert(*txid);
                }
            }
        }
        Ok(())
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn insert_ironwood_nullifier_map(
        &mut self,
        block_height: BlockHeight,
        new_entries: &[(TxIndex, TxId, Vec<orchard::note::Nullifier>)],
    ) -> Result<(), Error> {
        for (tx_index, txid, nullifiers) in new_entries {
            for nf in nullifiers {
                self.nullifiers.insert(
                    block_height,
                    u32::from(*tx_index),
                    Nullifier::Ironwood(*nf),
                );
            }
            match self.tx_locator.entry((block_height, u32::from(*tx_index))) {
                Entry::Occupied(x) if txid == x.get() => {}
                Entry::Occupied(_) => return Err(Error::ConflictingTxLocator),
                Entry::Vacant(entry) => {
                    entry.insert(*txid);
                }
            }
        }
        Ok(())
    }

    pub(crate) fn block_height_extrema(&self) -> Option<RangeInclusive<BlockHeight>> {
        let (min, max) = self.blocks.keys().fold((None, None), |(min, max), height| {
            (
                Some(min.map_or(height, |min| std::cmp::min(min, height))),
                Some(max.map_or(height, |max| std::cmp::max(max, height))),
            )
        });
        if let (Some(min), Some(max)) = (min, max) {
            Some(*min..=*max)
        } else {
            None
        }
    }

    pub(crate) fn sapling_tip_shard_end_height(&self) -> Option<BlockHeight> {
        self.sapling_tree_shard_end_heights.values().max().copied()
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn orchard_tip_shard_end_height(&self) -> Option<BlockHeight> {
        self.orchard_tree_shard_end_heights.values().max().copied()
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn ironwood_tip_shard_end_height(&self) -> Option<BlockHeight> {
        self.ironwood_tree_shard_end_heights.values().max().copied()
    }

    pub(crate) fn get_sapling_max_checkpointed_height(
        &self,
        chain_tip_height: BlockHeight,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<BlockHeight>, Error> {
        let max_checkpoint_height =
            u32::from(chain_tip_height).saturating_sub(u32::from(min_confirmations) - 1);
        // scan backward and find the first checkpoint that matches a blockheight prior to max_checkpoint_height
        for height in (0..=max_checkpoint_height).rev() {
            let height = BlockHeight::from_u32(height);
            if self.sapling_tree.store().get_checkpoint(&height)?.is_some() {
                return Ok(Some(height));
            }
        }
        Ok(None)
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn get_orchard_max_checkpointed_height(
        &self,
        chain_tip_height: BlockHeight,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<BlockHeight>, Error> {
        let max_checkpoint_height =
            u32::from(chain_tip_height).saturating_sub(u32::from(min_confirmations) - 1);
        // scan backward and find the first checkpoint that matches a blockheight prior to max_checkpoint_height
        for height in (0..=max_checkpoint_height).rev() {
            let height = BlockHeight::from_u32(height);
            if self.orchard_tree.store().get_checkpoint(&height)?.is_some() {
                return Ok(Some(height));
            }
        }
        Ok(None)
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn get_ironwood_max_checkpointed_height(
        &self,
        chain_tip_height: BlockHeight,
        min_confirmations: NonZeroU32,
    ) -> Result<Option<BlockHeight>, Error> {
        let max_checkpoint_height =
            u32::from(chain_tip_height).saturating_sub(u32::from(min_confirmations) - 1);
        for height in (0..=max_checkpoint_height).rev() {
            let height = BlockHeight::from_u32(height);
            if self
                .ironwood_tree
                .store()
                .get_checkpoint(&height)?
                .is_some()
            {
                return Ok(Some(height));
            }
        }
        Ok(None)
    }

    /// Get the unscanned ranges from the scan queue and their corresponding tree indices.
    /// This can be used to determine if a note is in an unscanned range and therefore not spendable
    pub(crate) fn unscanned_ranges(
        &self,
        pool: ShieldedPool,
    ) -> Vec<(BlockHeight, BlockHeight, Option<Position>, Option<Position>)> {
        self.scan_queue
            .iter()
            .filter(|(_, _, priority)| priority > &ScanPriority::Scanned)
            .map(|(start, end, _)| {
                (
                    *start,
                    *end,
                    self.first_subtree_for_height(pool, start)
                        .map(|a| a.position_range_start()),
                    self.last_subtree_for_height(pool, end)
                        .map(|a| a.position_range_end()),
                )
            })
            .collect()
    }

    /// Return the last subtree in the selected tree that ended at the given block height.
    pub(crate) fn last_subtree_for_height(
        &self,
        pool: ShieldedPool,
        height: &BlockHeight,
    ) -> Option<Address> {
        let shard_end_heights = match pool {
            ShieldedPool::Sapling => &self.sapling_tree_shard_end_heights,
            #[cfg(feature = "orchard")]
            ShieldedPool::Orchard => &self.orchard_tree_shard_end_heights,
            #[cfg(feature = "orchard")]
            ShieldedPool::Ironwood => &self.ironwood_tree_shard_end_heights,
            #[cfg(not(feature = "orchard"))]
            ShieldedPool::Orchard | ShieldedPool::Ironwood => return None,
        };

        shard_end_heights
            .iter()
            .filter(|(_, h)| *h == height)
            .map(|(a, _)| *a)
            .max()
    }

    /// Return the first subtree in the selected tree for the given block height.
    pub(crate) fn first_subtree_for_height(
        &self,
        pool: ShieldedPool,
        height: &BlockHeight,
    ) -> Option<Address> {
        // The first subtree is the last subtree for the previous height
        self.last_subtree_for_height(pool, &height.saturating_sub(1))
    }

    /// Makes the required changes to the scan queue to reflect the completion of a scan
    pub(crate) fn scan_complete(
        &mut self,
        range: Range<BlockHeight>,
        wallet_note_positions: &[(ShieldedPool, Position)],
    ) -> Result<(), Error> {
        let wallet_birthday = self.get_wallet_birthday()?;

        // Determine the range of block heights for which we will be updating the scan queue.
        let extended_range = {
            // If notes have been detected in the scan, we need to extend any adjacent un-scanned
            // ranges starting from the wallet birthday to include the blocks needed to complete
            // the note commitment tree subtrees containing the positions of the discovered notes.
            // We will query by subtree index to find these bounds.
            let mut required_sapling_subtrees = BTreeSet::new();
            #[cfg(feature = "orchard")]
            let mut required_orchard_subtrees = BTreeSet::new();
            #[cfg(feature = "orchard")]
            let mut required_ironwood_subtrees = BTreeSet::new();
            for (protocol, position) in wallet_note_positions {
                match protocol {
                    ShieldedPool::Sapling => {
                        required_sapling_subtrees.insert(
                            Address::above_position(SAPLING_SHARD_HEIGHT.into(), *position).index(),
                        );
                    }
                    ShieldedPool::Orchard => {
                        #[cfg(feature = "orchard")]
                        required_orchard_subtrees.insert(
                            Address::above_position(ORCHARD_SHARD_HEIGHT.into(), *position).index(),
                        );

                        #[cfg(not(feature = "orchard"))]
                        return Err(Error::OrchardNotEnabled);
                    }
                    ShieldedPool::Ironwood => {
                        #[cfg(feature = "orchard")]
                        required_ironwood_subtrees.insert(
                            Address::above_position(ORCHARD_SHARD_HEIGHT.into(), *position).index(),
                        );

                        #[cfg(not(feature = "orchard"))]
                        return Err(Error::OrchardNotEnabled);
                    }
                }
            }

            let extended_range = self.extend_range(
                &ShieldedPool::Sapling,
                &range,
                required_sapling_subtrees,
                self.params.activation_height(NetworkUpgrade::Sapling),
                wallet_birthday,
            )?;

            #[cfg(feature = "orchard")]
            let extended_range = self
                .extend_range(
                    &ShieldedPool::Orchard,
                    extended_range.as_ref().unwrap_or(&range),
                    required_orchard_subtrees,
                    self.params.activation_height(NetworkUpgrade::Nu5),
                    wallet_birthday,
                )?
                .or(extended_range);

            #[cfg(feature = "orchard")]
            let extended_range = self
                .extend_range(
                    &ShieldedPool::Ironwood,
                    extended_range.as_ref().unwrap_or(&range),
                    required_ironwood_subtrees,
                    self.params.activation_height(NetworkUpgrade::Nu6_3),
                    wallet_birthday,
                )?
                .or(extended_range);

            #[allow(clippy::let_and_return)]
            extended_range
        };

        let query_range = extended_range.clone().unwrap_or_else(|| range.clone());

        let scanned = ScanRange::from_parts(range.clone(), ScanPriority::Scanned);

        // If any of the extended range actually extends beyond the scanned range, we need to
        // scan that extension in order to make the found note(s) spendable. We need to avoid
        // creating empty ranges here, as that acts as an optimization barrier preventing
        // `SpanningTree` from merging non-empty scanned ranges on either side.
        let extended_before = extended_range
            .as_ref()
            .map(|extended| {
                ScanRange::from_parts(extended.start..range.start, ScanPriority::FoundNote)
            })
            .filter(|range| !range.is_empty());
        let extended_after = extended_range
            .map(|extended| ScanRange::from_parts(range.end..extended.end, ScanPriority::FoundNote))
            .filter(|range| !range.is_empty());

        let replacement = Some(scanned)
            .into_iter()
            .chain(extended_before)
            .chain(extended_after);

        self.scan_queue
            .replace_queue_entries(&query_range, replacement, false)
    }

    // Given a range of block heights, extend the range to include the subtrees containing the
    // given subtree indices, bounded by the wallet birthday and the fallback start height.
    fn extend_range(
        &self,
        pool: &ShieldedPool,
        range: &Range<BlockHeight>,
        required_subtree_indices: BTreeSet<u64>,
        fallback_start_height: Option<BlockHeight>,
        birthday_height: Option<BlockHeight>,
    ) -> Result<Option<Range<BlockHeight>>, Error> {
        // we'll either have both min and max bounds, or we'll have neither
        let subtree_index_bounds = required_subtree_indices
            .iter()
            .min()
            .zip(required_subtree_indices.iter().max());

        let shard_end = |index| -> Result<_, Error> {
            match pool {
                ShieldedPool::Sapling => Ok(self
                    .sapling_tree_shard_end_heights
                    .get(&Address::from_parts(SAPLING_SHARD_HEIGHT.into(), index))
                    .cloned()),
                ShieldedPool::Orchard => {
                    #[cfg(feature = "orchard")]
                    {
                        Ok(self
                            .orchard_tree_shard_end_heights
                            .get(&Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), index))
                            .cloned())
                    }
                    #[cfg(not(feature = "orchard"))]
                    panic!("Unsupported pool")
                }
                ShieldedPool::Ironwood => {
                    #[cfg(feature = "orchard")]
                    {
                        Ok(self
                            .ironwood_tree_shard_end_heights
                            .get(&Address::from_parts(ORCHARD_SHARD_HEIGHT.into(), index))
                            .cloned())
                    }
                    #[cfg(not(feature = "orchard"))]
                    panic!("Unsupported pool")
                }
            }
        };

        // If no notes belonging to the wallet were found, we don't need to extend the scanning
        // range suggestions to include the associated subtrees, and our bounds are just the
        // scanned range. Otherwise, ensure that all shard ranges starting from the wallet
        // birthday are included.
        subtree_index_bounds
            .map(|(min_idx, max_idx)| {
                let range_min = if *min_idx > 0 {
                    // get the block height of the end of the previous shard
                    shard_end(*min_idx - 1)?
                } else {
                    // our lower bound is going to be the fallback height
                    fallback_start_height
                };

                // bound the minimum to the wallet birthday
                let range_min =
                    range_min.map(|h| birthday_height.map_or(h, |b| std::cmp::max(b, h)));

                // Get the block height for the end of the current shard, and make it an
                // exclusive end bound.
                let range_max = shard_end(*max_idx)?.map(|end| end + 1);

                Ok(Range {
                    start: range.start.min(range_min.unwrap_or(range.start)),
                    end: range.end.max(range_max.unwrap_or(range.end)),
                })
            })
            .transpose()
    }

    pub(crate) fn get_sent_notes(&self) -> &SentNoteTable {
        &self.sent_notes
    }

    pub(crate) fn sapling_scan_progress(
        &self,
        birthday_height: &BlockHeight,
        fully_scanned_height: &BlockHeight,
        chain_tip_height: &BlockHeight,
    ) -> Result<Option<Ratio<u64>>, Error> {
        if fully_scanned_height == chain_tip_height {
            let outputs_sum = self
                .blocks
                .iter()
                .filter(|(height, _)| height >= &birthday_height)
                .fold(0, |sum, (_, block)| {
                    sum + block.sapling_output_count.unwrap_or(0)
                });
            Ok(Some(Ratio::new(outputs_sum as u64, outputs_sum as u64)))
        } else {
            // Get the starting note commitment tree size from the wallet birthday, or failing that
            // from the blocks table.
            let start_size = self
                .accounts
                .values()
                .filter_map(|account| {
                    if account.birthday().height() == *birthday_height {
                        Some(account.birthday().sapling_frontier().tree_size())
                    } else {
                        None
                    }
                })
                .next()
                .or_else(|| {
                    self.blocks
                        .iter()
                        .filter(|(height, _)| height <= &birthday_height)
                        .map(|(_, block)| {
                            (block.sapling_commitment_tree_size.unwrap_or(0)
                                - block.sapling_output_count.unwrap_or(0))
                                as u64
                        })
                        .max()
                });

            // Compute the total blocks scanned so far above the starting height
            let scanned_count = self
                .blocks
                .iter()
                .filter(|(height, _)| height > &birthday_height)
                .fold(0_u64, |acc, (_, block)| {
                    acc + block.sapling_output_count.unwrap_or(0) as u64
                });

            // We don't have complete information on how many outputs will exist in the shard at
            // the chain tip without having scanned the chain tip block, so we overestimate by
            // computing the maximum possible number of notes directly from the shard indices.
            //
            // TODO: it would be nice to be able to reliably have the size of the commitment tree
            // at the chain tip without having to have scanned that block.

            let shard_index_iter = self
                .sapling_tree_shard_end_heights
                .iter()
                .filter(|(_, height)| height > &birthday_height)
                .map(|(address, _)| address.index());

            let min_idx = shard_index_iter.clone().min().unwrap_or(0);
            let max_idx = shard_index_iter.max().unwrap_or(0);

            let min_tree_size = Some(min_idx << SAPLING_SHARD_HEIGHT);
            let max_tree_size = Some((max_idx + 1) << SAPLING_SHARD_HEIGHT);

            Ok(start_size.or(min_tree_size).zip(max_tree_size).and_then(
                |(min_tree_size, max_tree_size)| {
                    max_tree_size
                        .checked_sub(min_tree_size)
                        .map(|tree_size| Ratio::new(scanned_count, tree_size))
                },
            ))
        }
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn orchard_scan_progress(
        &self,
        birthday_height: &BlockHeight,
        fully_scanned_height: &BlockHeight,
        chain_tip_height: &BlockHeight,
    ) -> Result<Option<Ratio<u64>>, Error> {
        if fully_scanned_height == chain_tip_height {
            let outputs_sum = self
                .blocks
                .iter()
                .filter(|(height, _)| height >= &birthday_height)
                .fold(0, |sum, (_, block)| {
                    sum + block.orchard_action_count.unwrap_or(0)
                });
            Ok(Some(Ratio::new(outputs_sum as u64, outputs_sum as u64)))
        } else {
            // Get the starting note commitment tree size from the wallet birthday, or failing that
            // from the blocks table.
            let start_size = self
                .accounts
                .values()
                .filter_map(|account| {
                    if account.birthday().height() == *birthday_height {
                        Some(account.birthday().orchard_frontier().tree_size())
                    } else {
                        None
                    }
                })
                .next()
                .or_else(|| {
                    self.blocks
                        .iter()
                        .filter(|(height, _)| height <= &birthday_height)
                        .map(|(_, block)| {
                            (block.orchard_commitment_tree_size.unwrap_or(0)
                                - block.orchard_action_count.unwrap_or(0))
                                as u64
                        })
                        .max()
                });

            // Compute the total blocks scanned so far above the starting height
            let scanned_count = self
                .blocks
                .iter()
                .filter(|(height, _)| height > &birthday_height)
                .fold(0_u64, |acc, (_, block)| {
                    acc + block.orchard_action_count.unwrap_or(0) as u64
                });

            // We don't have complete information on how many outputs will exist in the shard at
            // the chain tip without having scanned the chain tip block, so we overestimate by
            // computing the maximum possible number of notes directly from the shard indices.
            //
            // TODO: it would be nice to be able to reliably have the size of the commitment tree
            // at the chain tip without having to have scanned that block.

            let shard_index_iter = self
                .orchard_tree_shard_end_heights
                .iter()
                .filter(|(_, height)| height > &birthday_height)
                .map(|(address, _)| address.index());

            let min_idx = shard_index_iter.clone().min().unwrap_or(0);
            let max_idx = shard_index_iter.max().unwrap_or(0);

            let min_tree_size = Some(min_idx << ORCHARD_SHARD_HEIGHT);
            let max_tree_size = Some((max_idx + 1) << ORCHARD_SHARD_HEIGHT);

            Ok(start_size.or(min_tree_size).zip(max_tree_size).and_then(
                |(min_tree_size, max_tree_size)| {
                    max_tree_size
                        .checked_sub(min_tree_size)
                        .map(|tree_size| Ratio::new(scanned_count, tree_size))
                },
            ))
        }
    }

    #[cfg(feature = "orchard")]
    pub(crate) fn ironwood_scan_progress(
        &self,
        birthday_height: &BlockHeight,
        fully_scanned_height: &BlockHeight,
        chain_tip_height: &BlockHeight,
    ) -> Result<Option<Ratio<u64>>, Error> {
        if fully_scanned_height == chain_tip_height {
            let actions_sum = self
                .blocks
                .iter()
                .filter(|(height, _)| height >= &birthday_height)
                .fold(0, |sum, (_, block)| {
                    sum + block.ironwood_action_count.unwrap_or(0)
                });
            Ok(Some(Ratio::new(actions_sum as u64, actions_sum as u64)))
        } else {
            let start_size = self
                .accounts
                .values()
                .find_map(|account| {
                    (account.birthday().height() == *birthday_height).then(|| {
                        account
                            .birthday()
                            .prior_chain_state()
                            .final_ironwood_tree()
                            .tree_size()
                    })
                })
                .or_else(|| {
                    self.blocks
                        .iter()
                        .filter(|(height, _)| height <= &birthday_height)
                        .map(|(_, block)| {
                            (block.ironwood_commitment_tree_size.unwrap_or(0)
                                - block.ironwood_action_count.unwrap_or(0))
                                as u64
                        })
                        .max()
                });

            let scanned_count = self
                .blocks
                .iter()
                .filter(|(height, _)| height > &birthday_height)
                .fold(0_u64, |acc, (_, block)| {
                    acc + block.ironwood_action_count.unwrap_or(0) as u64
                });

            let shard_index_iter = self
                .ironwood_tree_shard_end_heights
                .iter()
                .filter(|(_, height)| height > &birthday_height)
                .map(|(address, _)| address.index());
            let min_idx = shard_index_iter.clone().min().unwrap_or(0);
            let max_idx = shard_index_iter.max().unwrap_or(0);
            let min_tree_size = Some(min_idx << ORCHARD_SHARD_HEIGHT);
            let max_tree_size = Some((max_idx + 1) << ORCHARD_SHARD_HEIGHT);

            Ok(start_size.or(min_tree_size).zip(max_tree_size).and_then(
                |(min_tree_size, max_tree_size)| {
                    max_tree_size
                        .checked_sub(min_tree_size)
                        .map(|tree_size| Ratio::new(scanned_count, tree_size))
                },
            ))
        }
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn find_account_for_transparent_address(
        &self,
        address: &TransparentAddress,
    ) -> Result<Option<AccountId>, Error> {
        self.accounts.find_account_for_transparent_address(address)
    }

    pub(crate) fn mark_transparent_output_spent(
        &mut self,
        spent_in_tx: &TxId,
        outpoint: &OutPoint,
    ) -> Result<bool, Error> {
        // TODO: Remove it from the search queue

        let known_output = self.transparent_received_outputs.contains_key(outpoint);

        if known_output {
            self.output_locks.remove(&OutputRef::new(
                *outpoint.txid(),
                zcash_protocol::PoolType::Transparent,
                outpoint.n(),
            ));
            self.transparent_received_output_spends
                .insert(outpoint.clone(), *spent_in_tx);
            self.transparent_spend_map.remove(spent_in_tx, outpoint);
        } else {
            self.transparent_spend_map
                .insert(*spent_in_tx, outpoint.clone());
        }

        Ok(known_output)
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn put_transparent_output(
        &mut self,
        output: &WalletTransparentOutput<AccountId>,
        receiving_account: &AccountId,
        known_unspent: bool,
    ) -> Result<OutPoint, Error> {
        use crate::types::transparent::ReceivedTransparentOutput;

        let address = output.recipient_address();
        let key_scope = self
            .accounts
            .get(*receiving_account)
            .ok_or(Error::AccountUnknown(*receiving_account))?
            .transparent_key_scope_for_address(address)?
            .ok_or(Error::AddressNotRecognized(*address))?;
        if key_scope == TransparentKeyScope::INTERNAL {
            let height = output
                .mined_height()
                .or(self.chain_height()?)
                .unwrap_or(self.get_account_birthday(*receiving_account)?);
            self.accounts
                .get_mut(*receiving_account)
                .ok_or(Error::AccountUnknown(*receiving_account))?
                .mark_internal_address_seen(address, height);
        }
        // get the block height of the block that mined the output only if we have it in the block table
        // otherwise return None
        let block = output
            .mined_height()
            .and_then(|h| self.blocks.get(&h).map(|b| b.height));
        let txid = TxId::from_bytes(output.outpoint().hash().to_vec().try_into().unwrap());

        // insert a new tx into the transactions table for the one that spent this output. If there is already one then do an update
        self.tx_table
            .put_tx_partial(&txid, &block, output.mined_height());

        // look for a spent_height for this output by querying transparent_received_output_spends.
        // If there isn't one then return None (this is an unspent output)
        // otherwise return the height found by joining on the tx table
        let spent_height = self
            .transparent_received_output_spends
            .get(output.outpoint())
            .and_then(|txid| {
                self.tx_table
                    .tx_status(txid)
                    .and_then(|status| match status {
                        TransactionStatus::Mined(height) => Some(height),
                        _ => None,
                    })
            });

        // The max observed unspent height is either the spending transaction's mined height - 1, or
        // the current chain tip height if the UTXO was received via a path that confirmed that it was
        // unspent, such as by querying the UTXO set of the network.
        let max_observed_unspent = match spent_height {
            Some(h) => Some(h - 1),
            None => {
                if known_unspent {
                    self.chain_height()?
                } else {
                    None
                }
            }
        };

        // insert into transparent_received_outputs table. Update if it exists
        #[allow(clippy::diverging_sub_expression)] // FIXME
        match self
            .transparent_received_outputs
            .entry(output.outpoint().clone())
        {
            Entry::Occupied(mut entry) => {
                entry.get_mut().transaction_id = txid;
                entry.get_mut().address = *address;
                entry.get_mut().account_id = *receiving_account;
                entry.get_mut().txout = output.txout().clone();
            }
            Entry::Vacant(entry) => {
                entry.insert(ReceivedTransparentOutput::new(
                    txid,
                    *receiving_account,
                    *address,
                    key_scope,
                    output.txout().clone(),
                    max_observed_unspent.unwrap_or(BlockHeight::from(0)),
                ));
            }
        }

        // look in transparent_spend_map for a record of the output already having been spent, then mark it as spent using the
        // stored reference to the spending transaction.
        if let Some(spending_txid) = self
            .transparent_spend_map
            .spending_txid_for_outpoint(output.outpoint())
        {
            self.transparent_received_output_spends
                .insert(output.outpoint().clone(), spending_txid);
            self.transparent_spend_map
                .remove(&spending_txid, output.outpoint());
        }

        self.ensure_internal_address_gaps()?;
        Ok(output.outpoint().clone())
    }

    pub fn get_transaction_history(&self, account_id: AccountId) -> Vec<TransactionHistoryEntry> {
        let mut entries: Vec<TransactionHistoryEntry> = Vec::new();
        let chain_height = self.chain_height().ok().flatten();

        for (txid, tx_entry) in self.tx_table.iter() {
            let mined_height = tx_entry.mined_height();
            let block_time = mined_height
                .and_then(|h| self.blocks.get(&h))
                .map(|b| b.block_time);

            let received_zatoshis: i64 = self
                .received_notes
                .iter()
                .filter(|n| n.txid() == *txid && n.account_id() == account_id && !n.is_change)
                .map(|n| n.note.value().into_u64() as i64)
                .sum();

            let sent_zatoshis: i64 = self
                .sent_notes
                .iter()
                .filter(|(note_id, note)| {
                    *note_id.txid() == *txid && note.from_account_id == account_id
                })
                .map(|(_, note)| note.value.into_u64() as i64)
                .sum();

            let change_zatoshis: i64 = self
                .received_notes
                .iter()
                .filter(|n| n.txid() == *txid && n.account_id() == account_id && n.is_change)
                .map(|n| n.note.value().into_u64() as i64)
                .sum();

            let spent_input_zatoshis: i64 = self
                .received_note_spends
                .iter()
                .filter(|(_, spend_txid)| **spend_txid == *txid)
                .filter_map(|(note_id, _)| {
                    self.received_notes
                        .iter()
                        .find(|n| n.note_id() == *note_id && n.account_id() == account_id)
                        .map(|n| n.note.value().into_u64() as i64)
                })
                .sum();

            let transparent_spent_zatoshis = transparent_spent_zatoshis_for_account(
                &self.transparent_received_outputs,
                &self.transparent_received_output_spends,
                *txid,
                account_id,
            );

            if received_zatoshis == 0
                && sent_zatoshis == 0
                && change_zatoshis == 0
                && spent_input_zatoshis == 0
            {
                continue;
            }

            let fee_zatoshis = tx_entry.fee().map(|f| f.into_u64() as i64);

            let (kind, amount_zatoshis) = classify_transaction_history_entry(
                received_zatoshis,
                sent_zatoshis,
                change_zatoshis,
                spent_input_zatoshis,
                transparent_spent_zatoshis,
                fee_zatoshis,
            );

            let status = match tx_entry.status() {
                TransactionStatus::Mined(_) => "mined".to_string(),
                TransactionStatus::NotInMainChain => match (tx_entry.expiry_height(), chain_height)
                {
                    (Some(expiry_height), Some(chain_height)) if expiry_height <= chain_height => {
                        "expired".to_string()
                    }
                    _ => "pending".to_string(),
                },
                TransactionStatus::TxidNotRecognized => "unknown".to_string(),
            };

            let memo = self
                .received_notes
                .iter()
                .filter(|n| n.txid() == *txid && n.account_id() == account_id && !n.is_change)
                .find_map(|n| match &n.memo {
                    zcash_protocol::memo::Memo::Text(t) => Some(t.to_string()),
                    _ => None,
                })
                .or_else(|| {
                    self.sent_notes
                        .iter()
                        .filter(|(note_id, note)| {
                            note_id.txid() == txid && note.from_account_id == account_id
                        })
                        .find_map(|(_, note)| match &note.memo {
                            zcash_protocol::memo::Memo::Text(t) => Some(t.to_string()),
                            _ => None,
                        })
                });

            entries.push(TransactionHistoryEntry {
                txid: txid.as_ref().to_vec(),
                kind: kind.to_string(),
                amount_zatoshis: amount_zatoshis.unsigned_abs(),
                fee_zatoshis: fee_zatoshis.map(|f| f.unsigned_abs()),
                mined_height: mined_height.map(u32::from),
                expiry_height: tx_entry.expiry_height().map(u32::from),
                status,
                timestamp: block_time.map(u64::from),
                memo,
            });
        }

        entries.sort_by(|a, b| {
            b.mined_height
                .unwrap_or(u32::MAX)
                .cmp(&a.mined_height.unwrap_or(u32::MAX))
        });

        entries
    }

    #[cfg(feature = "transparent-inputs")]
    pub(crate) fn get_known_ephemeral_addresses(
        &self,
        account_id: AccountId,
        index_range: Option<Range<NonHardenedChildIndex>>,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Error> {
        Ok(self
            .accounts
            .get(account_id)
            .map(Account::ephemeral_addresses)
            .unwrap_or_else(|| Ok(vec![]))?
            .into_iter()
            .filter(|(_addr, meta)| {
                index_range
                    .as_ref()
                    .is_none_or(|range| meta.address_index().is_some_and(|i| range.contains(&i)))
            })
            .collect::<Vec<_>>())
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct TransactionHistoryEntry {
    pub txid: Vec<u8>,
    pub kind: String,
    pub amount_zatoshis: u64,
    pub fee_zatoshis: Option<u64>,
    pub mined_height: Option<u32>,
    pub expiry_height: Option<u32>,
    pub status: String,
    pub timestamp: Option<u64>,
    pub memo: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::transparent::ReceivedTransparentOutput;
    use zcash_address::ZcashAddress;
    use zcash_client_backend::wallet::{Recipient, WalletTx};
    use zcash_protocol::{PoolType, memo::Memo, value::Zatoshis};

    #[cfg(feature = "orchard")]
    #[test]
    fn spendability_diagnostics_exclude_expired_notes_but_never_select_incomplete_notes() {
        use crate::{MemBlockCache, testing::TestMemDbFactory};
        use zcash_client_backend::data_api::testing::{
            TestBuilder, orchard::OrchardPoolTester, pool::dsl::TestDsl,
        };
        use zcash_primitives::block::BlockHash;

        let mut state = TestDsl::from(
            TestBuilder::new()
                .with_data_store_factory(TestMemDbFactory)
                .with_block_cache(MemBlockCache::new())
                .with_account_from_sapling_activation(BlockHash([0; 32])),
        )
        .build::<OrchardPoolTester>();
        for _ in 0..12 {
            state.add_a_single_note_checking_balance(Zatoshis::const_from_u64(100_000));
        }
        let account_id = state.get_account().id();
        let network = *state.wallet().params();
        let mut bytes = Vec::new();
        state.wallet().encode(&mut bytes).unwrap();
        let mut wallet = MemoryWalletDb::decode_new(bytes.as_slice(), network, 100).unwrap();
        let target_height = TargetHeight::from(wallet.chain_height().unwrap().unwrap() + 1);
        let birthday_height = wallet.get_wallet_birthday().unwrap().unwrap();
        let policy = ConfirmationsPolicy::default();
        wallet.received_notes.0[0].commitment_tree_position = None;
        assert_eq!(
            wallet
                .spendability_diagnostics(account_id, policy)
                .unwrap()
                .incomplete_note_count,
            1
        );
        assert!(
            !wallet
                .note_is_spendable(
                    &wallet.received_notes.0[0],
                    birthday_height,
                    target_height,
                    policy,
                    &[]
                )
                .unwrap()
        );
        assert!(
            wallet
                .note_is_spendable(
                    &wallet.received_notes.0[1],
                    birthday_height,
                    target_height,
                    policy,
                    &[]
                )
                .unwrap()
        );
        let selected = wallet
            .select_spendable_notes(
                account_id,
                zcash_client_backend::data_api::TargetValue::AtLeast(Zatoshis::const_from_u64(
                    100_000,
                )),
                &[ShieldedPool::Orchard],
                target_height,
                policy,
                &[],
                zcash_client_backend::data_api::locking::LockFilter::Unfiltered,
            )
            .unwrap();
        assert!(!selected.orchard().is_empty());
        assert!(
            selected
                .orchard()
                .iter()
                .all(|note| *note.txid() != wallet.received_notes.0[0].txid())
        );

        let txid = wallet.received_notes.0[0].txid;
        let mut transaction: crate::proto::memwallet::TransactionEntry =
            wallet.tx_table.0[&txid].clone().into();
        transaction.tx_status = crate::proto::memwallet::TransactionStatus::NotInMainChain as i32;
        transaction.mined_height = None;
        transaction.expiry_height = Some(u32::from(BlockHeight::from(target_height)) - 1);
        wallet
            .tx_table
            .0
            .insert(txid, transaction.try_into().unwrap());
        assert_eq!(
            wallet
                .spendability_diagnostics(account_id, policy)
                .unwrap()
                .incomplete_note_count,
            0
        );
        assert!(
            !wallet
                .note_is_spendable(
                    &wallet.received_notes.0[0],
                    birthday_height,
                    target_height,
                    policy,
                    &[]
                )
                .unwrap()
        );
    }

    #[test]
    fn transaction_history_uses_outgoing_memo() {
        let account_id = AccountId::from(0);
        let txid = TxId::from_bytes([9; 32]);
        let mut wallet = MemoryWalletDb::new(consensus::Network::TestNetwork, 100);
        wallet.tx_table.put_tx_meta(
            WalletTx::new(
                txid,
                TxIndex::from(0u16),
                vec![],
                vec![],
                vec![],
                vec![],
                #[cfg(feature = "orchard")]
                vec![],
                #[cfg(feature = "orchard")]
                vec![],
                #[cfg(feature = "orchard")]
                vec![],
                #[cfg(feature = "orchard")]
                vec![],
            ),
            BlockHeight::from(1_000_000),
        );
        wallet.sent_notes.0.insert(
            SentNoteId::Shielded(NoteId::new(txid, ShieldedPool::Sapling, 0)),
            SentNote {
                from_account_id: account_id,
                to: Recipient::External {
                    recipient_address: ZcashAddress::try_from_encoded("uregtest1a7mkafdn9c87xywjnyup65uker8tx3y72r9f6elcfm6uh263c9s6smcw6xm5m8k8eythcreuyqktp9z7mtpcd6jsm5xw7skgdcfjx84z").unwrap(),
                    output_pool: PoolType::Shielded(ShieldedPool::Sapling),
                },
                value: Zatoshis::from_u64(260_000).unwrap(),
                memo: "ZNS:CLAIM:test".parse::<Memo>().unwrap(),
            },
        );

        let history = wallet.get_transaction_history(account_id);
        let requests = wallet.transaction_data_requests().unwrap();

        assert_eq!(history.len(), 1);
        assert_eq!(history[0].kind, "send");
        assert_eq!(history[0].memo.as_deref(), Some("ZNS:CLAIM:test"));
        assert!(
            requests.contains(
                &zcash_client_backend::data_api::TransactionDataRequest::Enhancement(txid)
            )
        );
    }

    #[test]
    fn transaction_history_classifies_transparent_to_shielded_as_shield() {
        let account_id = AccountId::from(0);
        let funding_txid = TxId::from_bytes([7; 32]);
        let shielding_txid = TxId::from_bytes([8; 32]);
        let outpoint = OutPoint::new(*funding_txid.as_ref(), 0);
        let value = Zatoshis::const_from_u64(4_000_000);
        let address = TransparentAddress::PublicKeyHash([1; 20]);
        let txout = ::transparent::bundle::TxOut::new(value, address.script().into());

        let mut wallet = MemoryWalletDb::new(consensus::Network::TestNetwork, 100);
        wallet.transparent_received_outputs.insert(
            outpoint.clone(),
            ReceivedTransparentOutput::new(
                funding_txid,
                account_id,
                address,
                ::transparent::keys::TransparentKeyScope::EXTERNAL,
                txout,
                BlockHeight::from(999_999),
            ),
        );
        wallet
            .transparent_received_output_spends
            .insert(outpoint, shielding_txid);

        let transparent_spent_zatoshis = transparent_spent_zatoshis_for_account(
            &wallet.transparent_received_outputs,
            &wallet.transparent_received_output_spends,
            shielding_txid,
            account_id,
        );

        assert_eq!(transparent_spent_zatoshis, 4_000_000);
        assert_eq!(
            classify_transaction_history_entry(
                3_980_000,
                0,
                0,
                0,
                transparent_spent_zatoshis,
                Some(20_000),
            ),
            ("shield", 3_980_000)
        );
        assert_eq!(
            classify_transaction_history_entry(
                0,
                0,
                3_980_000,
                0,
                transparent_spent_zatoshis,
                Some(20_000),
            ),
            ("shield", 3_980_000)
        );
    }
}
