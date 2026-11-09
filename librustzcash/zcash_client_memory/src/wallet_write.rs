use std::{
    collections::{BTreeSet, HashMap, HashSet},
    ops::Range,
};

use rayon::prelude::*;
use secrecy::{ExposeSecret, SecretVec};

use ::transparent::bundle::OutPoint;
use incrementalmerkletree::{Hashable, Marking, Position, Retention};
use shardtree::{
    ShardTree,
    store::{ShardStore, TreeState, memory::MemoryShardStore},
};
use zcash_client_backend::{
    TransferType,
    address::UnifiedAddress,
    data_api::{
        AccountBirthday, DecryptedTransaction, ScannedBlock, SentTransaction,
        SentTransactionOutput, WalletRead, WalletWrite, error::RewindError,
    },
    data_api::{
        AccountPurpose, AccountSource, SAPLING_SHARD_HEIGHT, TransactionStatus,
        WalletCommitmentTrees as _, Zip32Derivation,
        chain::ChainState,
        scanning::{ScanPriority, ScanRange},
    },
    keys::{UnifiedAddressRequest, UnifiedFullViewingKey, UnifiedSpendingKey},
    wallet::{Note, NoteId, Recipient, WalletTransparentOutput},
};
use zcash_primitives::transaction::Transaction;
use zcash_protocol::{
    PoolType, ShieldedPool, TxId,
    consensus::{self, BlockHeight, NetworkUpgrade},
    value::Zatoshis,
};
use zip32::{DiversifierIndex, fingerprint::SeedFingerprint};

use crate::{
    AccountId, MemoryWalletBlock, MemoryWalletDb, Nullifier, PRUNING_DEPTH, ReceivedNote,
    VERIFY_LOOKAHEAD, error::Error,
};

fn checkpoint_can_be_truncated<H, const DEPTH: u8, const SHARD_HEIGHT: u8>(
    tree: &ShardTree<MemoryShardStore<H, BlockHeight>, DEPTH, SHARD_HEIGHT>,
    height: BlockHeight,
) -> Result<bool, Error>
where
    H: Hashable + Clone + PartialEq,
{
    let Some(checkpoint) = tree.store().get_checkpoint(&height)? else {
        return Ok(false);
    };
    Ok(match checkpoint.tree_state() {
        TreeState::Empty => true,
        TreeState::AtPosition(position) => tree
            .store()
            .get_shard(ShardTree::<
                MemoryShardStore<H, BlockHeight>,
                DEPTH,
                SHARD_HEIGHT,
            >::subtree_addr(position))?
            .and_then(|shard| shard.truncate_to_position(position))
            .is_some(),
    })
}

#[cfg(feature = "orchard")]
use {
    shardtree::error::ShardTreeError, std::collections::BTreeMap,
    zcash_client_backend::data_api::ORCHARD_SHARD_HEIGHT,
};

#[cfg(feature = "transparent-inputs")]
use {
    ::transparent::{address::TransparentAddress, bundle::TxOut, keys::TransparentKeyScope},
    zcash_client_backend::{
        data_api::TransactionsInvolvingAddress, wallet::TransparentAddressMetadata,
    },
};

impl<P: consensus::Parameters> WalletWrite for MemoryWalletDb<P> {
    type UtxoRef = OutPoint;

    fn create_account(
        &mut self,
        account_name: &str,
        seed: &SecretVec<u8>,
        birthday: &AccountBirthday,
        key_source: Option<&str>,
    ) -> Result<(AccountId, UnifiedSpendingKey), Error> {
        if cfg!(not(test)) {
            unimplemented!(
                "Memwallet does not support adding accounts from seed phrases.
    Instead derive the ufvk in the calling code and import it using `import_account_ufvk`"
            )
        } else {
            let seed_fingerprint =
                SeedFingerprint::from_seed(seed.expose_secret()).ok_or(Error::InvalidSeedLength)?;
            let account_index = self
                .max_zip32_account_index(&seed_fingerprint)?
                .map(|a| a.next().ok_or(Error::AccountOutOfRange))
                .transpose()?
                .unwrap_or(zip32::AccountId::ZERO);

            let usk =
                UnifiedSpendingKey::from_seed(&self.params, seed.expose_secret(), account_index)?;
            let ufvk = usk.to_unified_full_viewing_key();

            let (id, _account) = self.add_account(
                account_name,
                AccountSource::Derived {
                    derivation: Zip32Derivation::new(
                        seed_fingerprint,
                        account_index,
                        #[cfg(feature = "zcashd-compat")]
                        None,
                    ),
                    key_source: key_source.map(|s| s.to_string()),
                },
                ufvk,
                birthday.clone(),
            )?;

            Ok((id, usk))
        }
    }

    fn delete_account(&mut self, account: AccountId) -> Result<(), Error> {
        self.accounts.accounts.remove(&account);
        todo!("remove all transactions associated with the account")
    }

    fn set_account_name(&mut self, account: AccountId, name: &str) -> Result<(), Error> {
        self.accounts
            .get_mut(account)
            .ok_or(Error::AccountUnknown(account))?
            .set_name(name);
        Ok(())
    }

    fn get_next_available_address(
        &mut self,
        account: AccountId,
        request: UnifiedAddressRequest,
    ) -> Result<Option<(UnifiedAddress, DiversifierIndex)>, Error> {
        tracing::debug!("get_next_available_address");
        self.accounts
            .get_mut(account)
            .map(|account| account.next_available_address(request))
            .transpose()
            .map(|a| a.flatten())
    }

    fn update_chain_tip(&mut self, tip_height: BlockHeight) -> Result<(), Error> {
        tracing::debug!("update_chain_tip");
        // If the caller provided a chain tip that is before Sapling activation, do nothing.
        let sapling_activation = match self.params.activation_height(NetworkUpgrade::Sapling) {
            Some(h) if h <= tip_height => h,
            _ => return Ok(()),
        };

        let max_scanned = self.block_height_extrema().map(|range| *range.end());
        let wallet_birthday = self.get_wallet_birthday()?;

        // If the chain tip is below the prior max scanned height, then the caller has caught
        // the chain in the middle of a reorg. Do nothing; the caller will continue using the
        // old scan ranges and either:
        // - encounter an error trying to fetch the blocks (and thus trigger the same handling
        //   logic as if this happened with the old linear scanning code); or
        // - encounter a discontinuity error in `scan_cached_blocks`, at which point they will
        //   call `WalletDb::truncate_to_height` as part of their reorg handling which will
        //   resolve the problem.
        //
        // We don't check the shard height, as normal usage would have the caller update the
        // shard state prior to this call, so it is possible and expected to be in a situation
        // where we should update the tip-related scan ranges but not the shard-related ones.
        match max_scanned {
            Some(h) if tip_height < h => return Ok(()),
            _ => (),
        };

        // `ScanRange` uses an exclusive upper bound.
        let chain_end = tip_height + 1;

        let sapling_shard_tip = self.sapling_tip_shard_end_height();
        // TODO: Handle orchard case as well. See zcash_client_sqlite scanning.rs update_chain_tip
        let min_shard_tip = sapling_shard_tip;

        // Create a scanning range for the fragment of the last shard leading up to new tip.
        // We set a lower bound at the wallet birthday (if known), because account creation
        // requires specifying a tree frontier that ensures we don't need tree information
        // prior to the birthday.
        let tip_shard_entry = min_shard_tip.filter(|h| h < &chain_end).map(|h| {
            let min_to_scan = wallet_birthday.filter(|b| b > &h).unwrap_or(h);
            ScanRange::from_parts(min_to_scan..chain_end, ScanPriority::ChainTip)
        });

        // Create scan ranges to either validate potentially invalid blocks at the wallet's
        // view of the chain tip, or connect the prior tip to the new tip.
        let tip_entry = max_scanned.map_or_else(
            || {
                // No blocks have been scanned, so we need to anchor the start of the new scan
                // range to something else.
                wallet_birthday.map_or_else(
                    // We don't have a wallet birthday, which means we have no accounts yet.
                    // We can therefore ignore all blocks up to the chain tip.
                    || ScanRange::from_parts(sapling_activation..chain_end, ScanPriority::Ignored),
                    // We have a wallet birthday, so mark all blocks between that and the
                    // chain tip as `Historic` (performing wallet recovery).
                    |wallet_birthday| {
                        ScanRange::from_parts(wallet_birthday..chain_end, ScanPriority::Historic)
                    },
                )
            },
            |max_scanned| {
                // The scan range starts at the block after the max scanned height. Since
                // `scan_cached_blocks` retrieves the metadata for the block being connected to
                // (if it exists), the connectivity of the scan range to the max scanned block
                // will always be checked if relevant.
                let min_unscanned = max_scanned + 1;

                // If we don't have shard metadata, this means we're doing linear scanning, so
                // create a scan range from the prior tip to the current tip with `Historic`
                // priority.
                if tip_shard_entry.is_none() {
                    ScanRange::from_parts(min_unscanned..chain_end, ScanPriority::Historic)
                } else {
                    // Determine the height to which we expect new blocks retrieved from the
                    // block source to be stable and not subject to being reorg'ed.
                    let stable_height = tip_height.saturating_sub(PRUNING_DEPTH);

                    // If the wallet's max scanned height is above the stable height,
                    // prioritize the range between it and the new tip as `ChainTip`.
                    if max_scanned > stable_height {
                        // We are in the steady-state case, where a wallet is close to the
                        // chain tip and just needs to catch up.
                        //
                        // This overlaps the `tip_shard_entry` range and so will be coalesced
                        // with it.
                        ScanRange::from_parts(min_unscanned..chain_end, ScanPriority::ChainTip)
                    } else {
                        // In this case, the max scanned height is considered stable relative
                        // to the chain tip. However, it may be stable or unstable relative to
                        // the prior chain tip, which we could determine by looking up the
                        // prior chain tip height from the scan queue. For simplicity we merge
                        // these two cases together, and proceed as though the max scanned
                        // block is unstable relative to the prior chain tip.
                        //
                        // To confirm its stability, prioritize the `VERIFY_LOOKAHEAD` blocks
                        // above the max scanned height as `Verify`:
                        //
                        // - We use `Verify` to ensure that a connectivity check is performed,
                        //   along with any required rewinds, before any `ChainTip` ranges
                        //   (from this or any prior `update_chain_tip` call) are scanned.
                        //
                        // - We prioritize `VERIFY_LOOKAHEAD` blocks because this is expected
                        //   to be 12.5 minutes, within which it is reasonable for a user to
                        //   have potentially received a transaction (if they opened their
                        //   wallet to provide an address to someone else, or spent their own
                        //   funds creating a change output), without necessarily having left
                        //   their wallet open long enough for the transaction to be mined and
                        //   the corresponding block to be scanned.
                        //
                        // - We limit the range to at most the stable region, to prevent any
                        //   `Verify` ranges from being susceptible to reorgs, and potentially
                        //   interfering with subsequent `Verify` ranges defined by future
                        //   calls to `update_chain_tip`. Any gap between `stable_height` and
                        //   `shard_start_height` will be filled by the scan range merging
                        //   logic with a `Historic` range.
                        //
                        // If `max_scanned == stable_height` then this is a zero-length range.
                        // In this case, any non-empty `(stable_height+1)..shard_start_height`
                        // will be marked `Historic`, minimising the prioritised blocks at the
                        // chain tip and allowing for other ranges (for example, `FoundNote`)
                        // to take priority.
                        ScanRange::from_parts(
                            min_unscanned
                                ..std::cmp::min(
                                    stable_height + 1,
                                    min_unscanned + VERIFY_LOOKAHEAD,
                                ),
                            ScanPriority::Verify,
                        )
                    }
                }
            },
        );
        if let Some(entry) = &tip_shard_entry {
            tracing::debug!("{} will update latest shard", entry);
        }
        tracing::debug!("{} will connect prior scanned state to new tip", tip_entry);

        let query_range = match tip_shard_entry.as_ref() {
            Some(se) => Range {
                start: std::cmp::min(se.block_range().start, tip_entry.block_range().start),
                end: std::cmp::max(se.block_range().end, tip_entry.block_range().end),
            },
            None => tip_entry.block_range().clone(),
        };

        self.scan_queue.replace_queue_entries(
            &query_range,
            tip_shard_entry.into_iter().chain(Some(tip_entry)),
            false,
        )?;
        Ok(())
    }

    fn prune_scan_queue_below(
        &mut self,
        height: BlockHeight,
        retain_with_priority: Option<ScanPriority>,
    ) -> Result<u64, Error> {
        let is_retained = |priority| {
            retain_with_priority
                .is_some_and(|retain| priority <= ScanPriority::Scanned || priority >= retain)
        };
        let (existing, untouched): (Vec<_>, Vec<_>) = self
            .scan_queue
            .iter()
            .copied()
            .partition(|(start, _, _)| *start < height);
        let fill_from = existing
            .iter()
            .find(|(_, _, priority)| is_retained(*priority))
            .map(|(start, _, _)| *start);
        let mut ranges: Vec<(BlockHeight, BlockHeight, ScanPriority)> = Vec::new();
        for &(start, end, priority) in &existing {
            let replacements = if is_retained(priority) {
                vec![(start, end, priority)]
            } else {
                let mut replacements = Vec::new();
                if fill_from.is_some_and(|floor| end.min(height) > floor) {
                    replacements.push((start, end.min(height), ScanPriority::Ignored));
                }
                if height < end {
                    replacements.push((height, end, priority));
                }
                replacements
            };
            for range in replacements {
                match ranges.last_mut() {
                    Some(previous) if previous.1 == range.0 && previous.2 == range.2 => {
                        previous.1 = range.1;
                    }
                    _ => ranges.push(range),
                }
            }
        }
        let changed = existing
            .iter()
            .filter(|entry| !ranges.contains(entry))
            .count() as u64;
        ranges.extend(untouched);
        self.scan_queue.0 = ranges;
        Ok(changed)
    }

    fn queue_rescan(&mut self, range: Range<BlockHeight>) -> Result<(), Error> {
        if !range.is_empty() {
            self.scan_queue.replace_queue_entries(
                &range,
                Some(ScanRange::from_parts(range.clone(), ScanPriority::Historic)).into_iter(),
                true,
            )?;
        }
        Ok(())
    }

    /// Adds a sequence of blocks to the data store.
    ///
    /// Assumes blocks will be here in order.
    fn put_blocks(
        &mut self,
        from_state: &ChainState,
        blocks: Vec<ScannedBlock<AccountId>>,
    ) -> Result<(), Error> {
        tracing::debug!("put_blocks");
        let mut last_scanned_height = None;
        struct BlockPositions {
            height: BlockHeight,
            sapling_start_position: Position,
            #[cfg(feature = "orchard")]
            orchard_start_position: Position,
            #[cfg(feature = "orchard")]
            ironwood_start_position: Position,
        }
        let start_positions = blocks.first().map(|block| BlockPositions {
            height: block.height(),
            sapling_start_position: Position::from(
                u64::from(block.sapling().final_tree_size())
                    - u64::try_from(block.sapling().commitments().len()).unwrap(),
            ),
            #[cfg(feature = "orchard")]
            orchard_start_position: Position::from(
                u64::from(block.orchard().final_tree_size())
                    - u64::try_from(block.orchard().commitments().len()).unwrap(),
            ),
            #[cfg(feature = "orchard")]
            ironwood_start_position: Position::from(
                u64::from(block.ironwood().final_tree_size())
                    - u64::try_from(block.ironwood().commitments().len()).unwrap(),
            ),
        });

        let mut sapling_commitments = vec![];
        #[cfg(feature = "orchard")]
        let mut orchard_commitments = vec![];
        #[cfg(feature = "orchard")]
        let mut ironwood_commitments = vec![];
        let mut note_positions = vec![];
        for block in blocks.into_iter() {
            let mut transactions = HashMap::new();
            let mut memos = HashMap::new();
            if last_scanned_height
                .iter()
                .any(|prev| block.height() != *prev + 1)
            {
                return Err(Error::NonSequentialBlocks);
            }

            for transaction in block.transactions().iter() {
                let txid = transaction.txid();

                if self
                    .tx_table
                    .get_transaction(&txid)
                    .is_none_or(|entry| entry.raw().is_none())
                {
                    self.transaction_data_request_queue.queue_enhancement(&txid);
                }

                // Mark the Sapling nullifiers of the spent notes as spent in the `sapling_spends` map.
                for spend in transaction.sapling_spends() {
                    println!(
                        "marking note {:?} as spent in transaction {:?}",
                        spend.nf(),
                        txid
                    );
                    self.mark_sapling_note_spent(*spend.nf(), txid)?;
                }

                // Mark the Orchard nullifiers of the spent notes as spent in the `orchard_spends` map.
                #[cfg(feature = "orchard")]
                for spend in transaction.orchard_spends() {
                    self.mark_orchard_note_spent(*spend.nf(), txid)?;
                }
                #[cfg(feature = "orchard")]
                for spend in transaction.ironwood_spends() {
                    self.mark_ironwood_note_spent(*spend.nf(), txid)?;
                }

                for output in transaction.sapling_outputs() {
                    // Insert the memo into the `memos` map.
                    let note_id = NoteId::new(
                        txid,
                        ShieldedPool::Sapling,
                        u16::try_from(output.index())
                            .expect("output indices are representable as u16"),
                    );
                    if let Ok(Some(memo)) = self.get_memo(note_id) {
                        memos.insert(note_id, memo.encode());
                    }
                    // Check whether this note was spent in a later block range that
                    // we previously scanned.
                    let spent_in = output
                        .nf()
                        .and_then(|nf| self.nullifiers.get(&Nullifier::Sapling(*nf)))
                        .and_then(|(height, tx_idx)| self.tx_locator.get(*height, *tx_idx))
                        .copied();

                    self.insert_received_sapling_note(note_id, output, spent_in);
                }

                #[cfg(feature = "orchard")]
                for output in transaction.orchard_outputs().iter() {
                    // Insert the memo into the `memos` map.
                    let note_id = NoteId::new(
                        txid,
                        ShieldedPool::Orchard,
                        u16::try_from(output.index())
                            .expect("output indices are representable as u16"),
                    );
                    if let Ok(Some(memo)) = self.get_memo(note_id) {
                        memos.insert(note_id, memo.encode());
                    }
                    // Check whether this note was spent in a later block range that
                    // we previously scanned.
                    let spent_in = output
                        .nf()
                        .and_then(|nf| self.nullifiers.get(&Nullifier::Orchard(*nf)))
                        .and_then(|(height, tx_idx)| self.tx_locator.get(*height, *tx_idx))
                        .copied();

                    self.insert_received_orchard_note(note_id, output, spent_in)
                }

                #[cfg(feature = "orchard")]
                for output in transaction.ironwood_outputs() {
                    let note_id = NoteId::new(
                        txid,
                        ShieldedPool::Ironwood,
                        u16::try_from(output.index())
                            .expect("output indices are representable as u16"),
                    );
                    if let Ok(Some(memo)) = self.get_memo(note_id) {
                        memos.insert(note_id, memo.encode());
                    }
                    let spent_in = output
                        .nf()
                        .and_then(|nf| self.nullifiers.get(&Nullifier::Ironwood(*nf)))
                        .and_then(|(height, tx_idx)| self.tx_locator.get(*height, *tx_idx))
                        .copied();

                    self.insert_received_ironwood_note(note_id, output, spent_in)
                }

                transactions.insert(txid, transaction.clone());
            }

            // Insert the new nullifiers from this block into the nullifier map
            self.insert_sapling_nullifier_map(block.height(), block.sapling().nullifier_map())?;
            #[cfg(feature = "orchard")]
            self.insert_orchard_nullifier_map(block.height(), block.orchard().nullifier_map())?;
            #[cfg(feature = "orchard")]
            self.insert_ironwood_nullifier_map(block.height(), block.ironwood().nullifier_map())?;
            note_positions.extend(block.transactions().iter().flat_map(|wtx| {
                let iter = wtx
                    .sapling_outputs()
                    .iter()
                    .map(|out| (ShieldedPool::Sapling, out.note_commitment_tree_position()));
                #[cfg(feature = "orchard")]
                let iter = iter.chain(
                    wtx.orchard_outputs()
                        .iter()
                        .map(|out| (ShieldedPool::Orchard, out.note_commitment_tree_position())),
                );
                #[cfg(feature = "orchard")]
                let iter = iter.chain(
                    wtx.ironwood_outputs()
                        .iter()
                        .map(|out| (ShieldedPool::Ironwood, out.note_commitment_tree_position())),
                );

                iter
            }));

            let memory_block = MemoryWalletBlock {
                height: block.height(),
                hash: block.block_hash(),
                block_time: block.block_time(),
                _transactions: transactions.keys().cloned().collect(),
                _memos: memos,
                sapling_commitment_tree_size: Some(block.sapling().final_tree_size()),
                sapling_output_count: Some(block.sapling().commitments().len().try_into().unwrap()),
                #[cfg(feature = "orchard")]
                orchard_commitment_tree_size: Some(block.orchard().final_tree_size()),
                #[cfg(feature = "orchard")]
                orchard_action_count: Some(block.orchard().commitments().len().try_into().unwrap()),
                #[cfg(feature = "orchard")]
                ironwood_commitment_tree_size: Some(block.ironwood().final_tree_size()),
                #[cfg(feature = "orchard")]
                ironwood_action_count: Some(
                    block.ironwood().commitments().len().try_into().unwrap(),
                ),
            };

            // Insert transaction metadata into the transaction table
            transactions
                .into_iter()
                .for_each(|(_id, tx)| self.tx_table.put_tx_meta(tx, block.height()));

            // Insert the block into the block map
            self.blocks.insert(block.height(), memory_block);
            last_scanned_height = Some(block.height());

            let block_commitments = block.into_commitments();
            sapling_commitments.extend(block_commitments.sapling.into_iter().map(Some));
            #[cfg(feature = "orchard")]
            orchard_commitments.extend(block_commitments.orchard.into_iter().map(Some));
            #[cfg(feature = "orchard")]
            ironwood_commitments.extend(block_commitments.ironwood.into_iter().map(Some));
        }

        if let Some((start_positions, last_scanned_height)) =
            start_positions.zip(last_scanned_height)
        {
            // Create subtrees from the note commitments in parallel.
            const CHUNK_SIZE: usize = 1024;
            let sapling_subtrees = sapling_commitments
                .par_chunks_mut(CHUNK_SIZE)
                .enumerate()
                .filter_map(|(i, chunk)| {
                    let start = start_positions.sapling_start_position + (i * CHUNK_SIZE) as u64;
                    let end = start + chunk.len() as u64;

                    shardtree::LocatedTree::from_iter(
                        start..end,
                        SAPLING_SHARD_HEIGHT.into(),
                        chunk.iter_mut().map(|n| n.take().expect("always Some")),
                    )
                })
                .map(|res| (res.subtree, res.checkpoints))
                .collect::<Vec<_>>();

            #[cfg(feature = "orchard")]
            let orchard_subtrees = orchard_commitments
                .par_chunks_mut(CHUNK_SIZE)
                .enumerate()
                .filter_map(|(i, chunk)| {
                    let start = start_positions.orchard_start_position + (i * CHUNK_SIZE) as u64;
                    let end = start + chunk.len() as u64;

                    shardtree::LocatedTree::from_iter(
                        start..end,
                        ORCHARD_SHARD_HEIGHT.into(),
                        chunk.iter_mut().map(|n| n.take().expect("always Some")),
                    )
                })
                .map(|res| (res.subtree, res.checkpoints))
                .collect::<Vec<_>>();

            #[cfg(feature = "orchard")]
            let ironwood_subtrees = ironwood_commitments
                .par_chunks_mut(CHUNK_SIZE)
                .enumerate()
                .filter_map(|(i, chunk)| {
                    let start = start_positions.ironwood_start_position + (i * CHUNK_SIZE) as u64;
                    let end = start + chunk.len() as u64;

                    shardtree::LocatedTree::from_iter(
                        start..end,
                        ORCHARD_SHARD_HEIGHT.into(),
                        chunk.iter_mut().map(|n| n.take().expect("always Some")),
                    )
                })
                .map(|res| (res.subtree, res.checkpoints))
                .collect::<Vec<_>>();

            // Collect the complete set of Sapling checkpoints
            #[cfg(feature = "orchard")]
            let sapling_checkpoint_positions: BTreeMap<BlockHeight, Position> = sapling_subtrees
                .iter()
                .flat_map(|(_, checkpoints)| checkpoints.iter())
                .map(|(k, v)| (*k, *v))
                .collect();

            #[cfg(feature = "orchard")]
            let orchard_checkpoint_positions: BTreeMap<BlockHeight, Position> = orchard_subtrees
                .iter()
                .flat_map(|(_, checkpoints)| checkpoints.iter())
                .map(|(k, v)| (*k, *v))
                .collect();

            #[cfg(feature = "orchard")]
            let ironwood_checkpoint_positions: BTreeMap<BlockHeight, Position> = ironwood_subtrees
                .iter()
                .flat_map(|(_, checkpoints)| checkpoints.iter())
                .map(|(k, v)| (*k, *v))
                .collect();

            #[cfg(feature = "orchard")]
            let (
                missing_sapling_checkpoints,
                missing_orchard_checkpoints,
                missing_ironwood_checkpoints,
            ) = (
                ensure_checkpoints(
                    orchard_checkpoint_positions
                        .keys()
                        .chain(ironwood_checkpoint_positions.keys()),
                    &sapling_checkpoint_positions,
                    from_state.final_sapling_tree(),
                ),
                ensure_checkpoints(
                    sapling_checkpoint_positions
                        .keys()
                        .chain(ironwood_checkpoint_positions.keys()),
                    &orchard_checkpoint_positions,
                    from_state.final_orchard_tree(),
                ),
                ensure_checkpoints(
                    sapling_checkpoint_positions
                        .keys()
                        .chain(orchard_checkpoint_positions.keys()),
                    &ironwood_checkpoint_positions,
                    from_state.final_ironwood_tree(),
                ),
            );

            // Update the Sapling note commitment tree with all newly read note commitments
            {
                let mut sapling_subtrees_iter = sapling_subtrees.into_iter();
                self.with_sapling_tree_mut::<_, _, Error>(|sapling_tree| {
                    sapling_tree.insert_frontier(
                        from_state.final_sapling_tree().clone(),
                        Retention::Checkpoint {
                            id: from_state.block_height(),
                            marking: Marking::Reference,
                        },
                    )?;

                    for (tree, checkpoints) in &mut sapling_subtrees_iter {
                        sapling_tree.insert_tree(tree, checkpoints)?;
                    }

                    // Ensure we have a Sapling checkpoint for each checkpointed Orchard block height.
                    // We skip all checkpoints below the minimum retained checkpoint in the
                    // Sapling tree, because branches below this height may be pruned.
                    #[cfg(feature = "orchard")]
                    {
                        let min_checkpoint_height = sapling_tree
                            .store()
                            .min_checkpoint_id()
                            .map_err(ShardTreeError::Storage)?
                            .expect("At least one checkpoint was inserted (by insert_frontier)");

                        for (height, checkpoint) in &missing_sapling_checkpoints {
                            if *height > min_checkpoint_height {
                                sapling_tree
                                    .store_mut()
                                    .add_checkpoint(*height, checkpoint.clone())
                                    .map_err(ShardTreeError::Storage)?;
                            }
                        }
                    }

                    Ok(())
                })?;
            }

            // Update the Ironwood note commitment tree with all newly read note commitments.
            #[cfg(feature = "orchard")]
            {
                let mut ironwood_subtrees = ironwood_subtrees.into_iter();
                self.with_ironwood_tree_mut::<_, _, Error>(|ironwood_tree| {
                    ironwood_tree.insert_frontier(
                        from_state.final_ironwood_tree().clone(),
                        Retention::Checkpoint {
                            id: from_state.block_height(),
                            marking: Marking::Reference,
                        },
                    )?;

                    for (tree, checkpoints) in &mut ironwood_subtrees {
                        ironwood_tree.insert_tree(tree, checkpoints)?;
                    }

                    let min_checkpoint_height = ironwood_tree
                        .store()
                        .min_checkpoint_id()
                        .map_err(ShardTreeError::Storage)?
                        .expect("At least one checkpoint was inserted (by insert_frontier)");
                    for (height, checkpoint) in &missing_ironwood_checkpoints {
                        if *height > min_checkpoint_height {
                            ironwood_tree
                                .store_mut()
                                .add_checkpoint(*height, checkpoint.clone())
                                .map_err(ShardTreeError::Storage)?;
                        }
                    }
                    Ok(())
                })?;
            }

            // Update the Orchard note commitment tree with all newly read note commitments
            #[cfg(feature = "orchard")]
            {
                let mut orchard_subtrees = orchard_subtrees.into_iter();
                self.with_orchard_tree_mut::<_, _, Error>(|orchard_tree| {
                    orchard_tree.insert_frontier(
                        from_state.final_orchard_tree().clone(),
                        Retention::Checkpoint {
                            id: from_state.block_height(),
                            marking: Marking::Reference,
                        },
                    )?;

                    for (tree, checkpoints) in &mut orchard_subtrees {
                        orchard_tree.insert_tree(tree, checkpoints)?;
                    }

                    // Ensure we have an Orchard checkpoint for each checkpointed Sapling block height.
                    // We skip all checkpoints below the minimum retained checkpoint in the
                    // Orchard tree, because branches below this height may be pruned.
                    {
                        let min_checkpoint_height = orchard_tree
                            .store()
                            .min_checkpoint_id()
                            .map_err(ShardTreeError::Storage)?
                            .expect("At least one checkpoint was inserted (by insert_frontier)");

                        for (height, checkpoint) in &missing_orchard_checkpoints {
                            if *height > min_checkpoint_height {
                                orchard_tree
                                    .store_mut()
                                    .add_checkpoint(*height, checkpoint.clone())
                                    .map_err(ShardTreeError::Storage)?;
                            }
                        }
                    }
                    Ok(())
                })?;
            }

            self.scan_complete(
                Range {
                    start: start_positions.height,
                    end: last_scanned_height + 1,
                },
                &note_positions,
            )?;
        }

        Ok(())
    }

    /// Adds a transparent UTXO received by the wallet to the data store.
    fn put_received_transparent_utxo(
        &mut self,
        _output: &WalletTransparentOutput<AccountId>,
    ) -> Result<Self::UtxoRef, Error> {
        tracing::debug!("put_received_transparent_utxo");
        #[cfg(feature = "transparent-inputs")]
        {
            let address = _output.recipient_address();
            if let Some(account_id) = self.find_account_for_transparent_address(address)? {
                self.put_transparent_output(_output, &account_id, false)
            } else {
                Err(Error::AddressNotRecognized(*address))
            }
        }
        #[cfg(not(feature = "transparent-inputs"))]
        panic!(
            "The wallet must be compiled with the transparent-inputs feature to use this method."
        );
    }

    fn store_decrypted_tx(
        &mut self,
        d_tx: DecryptedTransaction<Transaction, AccountId>,
    ) -> Result<(), Error> {
        tracing::debug!("store_decrypted_tx");
        let fee = d_tx.tx().fee_paid(|outpoint| {
            Ok::<_, Error>(
                self.transparent_received_outputs
                    .get(outpoint)
                    .map(|output| output.txout.value()),
            )
        })?;
        self.tx_table.put_tx_data(d_tx.tx(), fee, None);
        if let Some(height) = d_tx.mined_height() {
            self.set_transaction_status(d_tx.tx().txid(), TransactionStatus::Mined(height))?
        }

        let funding_accounts = self.get_funding_accounts(d_tx.tx())?;
        // TODO(#1305): Correctly track accounts that fund each transaction output.
        let funding_account = funding_accounts.iter().next().copied();
        if funding_accounts.len() > 1 {
            tracing::warn!(
                "More than one wallet account detected as funding transaction {:?}, selecting {:?}",
                d_tx.tx().txid(),
                funding_account.unwrap()
            )
        }

        // A flag used to determine whether it is necessary to query for transactions that
        // provided transparent inputs to this transaction, in order to be able to correctly
        // recover transparent transaction history.
        #[cfg(feature = "transparent-inputs")]
        let mut tx_has_wallet_outputs = false;

        for output in d_tx.sapling_outputs() {
            #[cfg(feature = "transparent-inputs")]
            {
                tx_has_wallet_outputs = true;
            }

            match output.transfer_type() {
                TransferType::Outgoing => {
                    let recipient = {
                        let receiver = Receiver::Sapling(output.note().recipient());
                        let wallet_address = self
                            .accounts
                            .get(*output.account())
                            .map(|acc| {
                                acc.select_receiving_address(self.params.network_type(), &receiver)
                            })
                            .transpose()?
                            .flatten()
                            .unwrap_or_else(|| {
                                receiver.to_zcash_address(self.params.network_type())
                            });

                        Recipient::External {
                            recipient_address: wallet_address,
                            output_pool: PoolType::SAPLING,
                        }
                    };

                    let sent_tx_output = SentTransactionOutput::from_parts(
                        output.index(),
                        recipient,
                        output.note_value(),
                        Some(output.memo().clone()),
                    );
                    self.sent_notes.put_sent_output(
                        d_tx.tx().txid(),
                        *output.account(),
                        &sent_tx_output,
                    );
                }
                TransferType::WalletInternal | TransferType::AccountInternal => {
                    let recipient = Recipient::InternalShielded {
                        receiving_account: *output.account(),
                        external_address: None,
                        note: Box::new(Note::Sapling(output.note().clone())),
                    };
                    let sent_tx_output = SentTransactionOutput::from_parts(
                        output.index(),
                        recipient,
                        output.note_value(),
                        Some(output.memo().clone()),
                    );

                    self.received_notes
                        .insert_received_note(ReceivedNote::from_sent_tx_output(
                            d_tx.tx().txid(),
                            &sent_tx_output,
                        )?);

                    self.sent_notes.put_sent_output(
                        d_tx.tx().txid(),
                        *output.account(),
                        &sent_tx_output,
                    );
                }
                TransferType::Incoming => {
                    self.received_notes.insert_received_note(ReceivedNote {
                        note_id: NoteId::new(
                            d_tx.tx().txid(),
                            ShieldedPool::Sapling,
                            output.index().try_into()?,
                        ),
                        txid: d_tx.tx().txid(),
                        output_index: output.index().try_into()?,
                        account_id: *output.account(),
                        note: Note::Sapling(output.note().clone()),
                        nf: None,
                        is_change: false,
                        memo: zcash_protocol::memo::Memo::try_from(output.memo())?,
                        commitment_tree_position: None,
                        recipient_key_scope: Some(zip32::Scope::External),
                    });
                }
            }
        }

        #[cfg(feature = "orchard")]
        for output in d_tx.orchard_outputs().iter().chain(d_tx.ironwood_outputs()) {
            #[cfg(feature = "transparent-inputs")]
            {
                tx_has_wallet_outputs = true;
            }
            match output.transfer_type() {
                TransferType::Outgoing => {
                    let recipient = {
                        let receiver = Receiver::Orchard(output.note().0.recipient());
                        let wallet_address = self
                            .accounts
                            .get(*output.account())
                            .map(|acc| {
                                acc.select_receiving_address(self.params.network_type(), &receiver)
                            })
                            .transpose()?
                            .flatten()
                            .unwrap_or_else(|| {
                                receiver.to_zcash_address(self.params.network_type())
                            });

                        Recipient::External {
                            recipient_address: wallet_address,
                            output_pool: PoolType::Shielded(output.value_pool()),
                        }
                    };

                    let sent_tx_output = SentTransactionOutput::from_parts(
                        output.index(),
                        recipient,
                        Zatoshis::from_u64(output.note().0.value().inner())
                            .expect("Orchard-family note value is valid"),
                        Some(output.memo().clone()),
                    );
                    self.sent_notes.put_sent_output(
                        d_tx.tx().txid(),
                        *output.account(),
                        &sent_tx_output,
                    );
                }
                TransferType::WalletInternal | TransferType::AccountInternal => {
                    let recipient = Recipient::InternalShielded {
                        receiving_account: *output.account(),
                        external_address: None,
                        note: Box::new(Note::Orchard {
                            note: output.note().0,
                            pool: output.note().1,
                        }),
                    };
                    let sent_tx_output = SentTransactionOutput::from_parts(
                        output.index(),
                        recipient,
                        Zatoshis::from_u64(output.note().0.value().inner())
                            .expect("Orchard-family note value is valid"),
                        Some(output.memo().clone()),
                    );

                    self.received_notes
                        .insert_received_note(ReceivedNote::from_sent_tx_output(
                            d_tx.tx().txid(),
                            &sent_tx_output,
                        )?);

                    self.sent_notes.put_sent_output(
                        d_tx.tx().txid(),
                        *output.account(),
                        &sent_tx_output,
                    );
                }
                TransferType::Incoming => {
                    self.received_notes.insert_received_note(ReceivedNote {
                        note_id: NoteId::new(
                            d_tx.tx().txid(),
                            output.value_pool(),
                            output.index().try_into()?,
                        ),
                        txid: d_tx.tx().txid(),
                        output_index: output.index().try_into()?,
                        account_id: *output.account(),
                        note: Note::Orchard {
                            note: output.note().0,
                            pool: output.note().1,
                        },
                        nf: None,
                        is_change: false,
                        memo: zcash_protocol::memo::Memo::try_from(output.memo())?,
                        commitment_tree_position: None,
                        recipient_key_scope: Some(zip32::Scope::External),
                    });
                }
            }
        }

        // If any of the utxos spent in the transaction are ours, mark them as spent.
        #[cfg(feature = "transparent-inputs")]
        for txin in d_tx
            .tx()
            .transparent_bundle()
            .iter()
            .flat_map(|b| b.vin.iter())
        {
            self.mark_transparent_output_spent(&d_tx.tx().txid(), txin.prevout())?;
        }

        // This `if` is just an optimization for cases where we would do nothing in the loop.
        if funding_account.is_some() || cfg!(feature = "transparent-inputs") {
            for (output_index, txout) in d_tx
                .tx()
                .transparent_bundle()
                .iter()
                .flat_map(|b| b.vout.iter())
                .enumerate()
            {
                if let Some(address) = txout.recipient_address() {
                    tracing::debug!(
                        "{:?} output {} has recipient {}",
                        d_tx.tx().txid(),
                        output_index,
                        address.encode(self.params())
                    );

                    // The transaction is not necessarily mined yet, but we want to record
                    // that an output to the address was seen in this tx anyway. This will
                    // advance the gap regardless of whether it is mined, but an output in
                    // an unmined transaction won't advance the range of safe indices.
                    #[cfg(feature = "transparent-inputs")]
                    self.accounts
                        .mark_ephemeral_address_as_seen(&address, d_tx.tx().txid())?;

                    // If the output belongs to the wallet, add it to `transparent_received_outputs`.
                    #[cfg(feature = "transparent-inputs")]
                    if let Some(account_id) = self
                        .accounts
                        .find_account_for_transparent_address(&address)?
                    {
                        tracing::debug!(
                            "{:?} output {} belongs to account {:?}",
                            d_tx.tx().txid(),
                            output_index,
                            account_id
                        );
                        let recipient_key_scope = self
                            .accounts
                            .get(account_id)
                            .ok_or(Error::AccountUnknown(account_id))?
                            .transparent_key_scope_for_address(&address)?;
                        let wallet_transparent_output = WalletTransparentOutput::from_parts(
                            OutPoint::new(
                                d_tx.tx().txid().into(),
                                u32::try_from(output_index).unwrap(),
                            ),
                            txout.clone(),
                            d_tx.mined_height(),
                            Some(account_id),
                            recipient_key_scope,
                            funding_account,
                        )
                        .unwrap();
                        self.put_transparent_output(
                            &wallet_transparent_output,
                            &account_id,
                            false,
                        )?;

                        // Since the wallet created the transparent output, we need to ensure
                        // that any transparent inputs belonging to the wallet will be
                        // discovered.
                        tx_has_wallet_outputs = true;
                    } else {
                        tracing::debug!(
                            "Address {} is not recognized as belonging to any of our accounts.",
                            address.encode(self.params())
                        );
                    }

                    // If a transaction we observe contains spends from our wallet, we will
                    // store its transparent outputs in the same way they would be stored by
                    // create_spend_to_address.
                    if let Some(account_id) = funding_account {
                        let receiver = Receiver::Transparent(address);

                        #[cfg(feature = "transparent-inputs")]
                        let recipient_addr = self
                            .accounts
                            .get(account_id)
                            .map(|acc| {
                                acc.select_receiving_address(self.params.network_type(), &receiver)
                            })
                            .transpose()?
                            .flatten()
                            .unwrap_or_else(|| {
                                receiver.to_zcash_address(self.params.network_type())
                            });

                        #[cfg(not(feature = "transparent-inputs"))]
                        let recipient_addr = receiver.to_zcash_address(self.params.network_type());

                        let recipient = Recipient::External {
                            recipient_address: recipient_addr,
                            output_pool: PoolType::TRANSPARENT,
                        };

                        let sent_tx_output = SentTransactionOutput::from_parts(
                            output_index,
                            recipient,
                            txout.value(),
                            None,
                        );
                        self.sent_notes.put_sent_output(
                            d_tx.tx().txid(),
                            account_id,
                            &sent_tx_output,
                        );
                        // Even though we know the funding account, we don't know that we have
                        // information for all of the transparent inputs to the transaction.
                        #[cfg(feature = "transparent-inputs")]
                        {
                            tx_has_wallet_outputs = true;
                        }
                    }
                } else {
                    tracing::warn!(
                        "Unable to determine recipient address for tx {:?} output {}",
                        d_tx.tx().txid(),
                        output_index
                    );
                }
            }
        }

        // If the transaction has outputs that belong to the wallet as well as transparent
        // inputs, we may need to download the transactions corresponding to the transparent
        // prevout references to determine whether the transaction was created (at least in
        // part) by this wallet.
        #[cfg(feature = "transparent-inputs")]
        if tx_has_wallet_outputs && d_tx.tx().transparent_bundle().is_some() {
            // queue the transparent inputs for enhancement
            self.transaction_data_request_queue
                .queue_status_retrieval(&d_tx.tx().txid());
        }

        #[cfg(feature = "transparent-inputs")]
        {
            let detectable_via_scanning = d_tx.tx().sapling_bundle().is_some();
            #[cfg(feature = "orchard")]
            let detectable_via_scanning = detectable_via_scanning
                | d_tx.tx().orchard_bundle().is_some()
                | d_tx.tx().ironwood_bundle().is_some();

            if d_tx.mined_height().is_none() && !detectable_via_scanning {
                self.transaction_data_request_queue
                    .queue_status_retrieval(&d_tx.tx().txid());
            }
        }
        self.transaction_data_request_queue
            .remove_enhancement(&d_tx.tx().txid());
        Ok(())
    }

    fn set_tx_trust(&mut self, _txid: TxId, _trusted: bool) -> Result<(), Error> {
        todo!()
    }

    /// Truncates the database to the given height.
    ///
    /// If the requested height is greater than or equal to the height of the last scanned
    /// block, this function does nothing.
    ///
    /// This should only be executed inside a transactional context.
    fn truncate_to_height(&mut self, max_height: BlockHeight) -> Result<BlockHeight, Error> {
        let truncation_height = {
            // This is the intersection of all the checkpoint heights from the sapling and orchard tree.
            let mut checkpoint_heights = BTreeSet::new();
            self.sapling_tree.store().for_each_checkpoint(
                self.sapling_tree.store().checkpoint_count()?,
                |height, _| {
                    checkpoint_heights.insert(u32::from(*height));
                    Ok(())
                },
            )?;
            #[cfg(feature = "orchard")]
            {
                let mut orchard_checkpoint_heights = BTreeSet::new();
                self.orchard_tree.store().for_each_checkpoint(
                    self.orchard_tree.store().checkpoint_count()?,
                    |height, _| {
                        orchard_checkpoint_heights.insert(u32::from(*height));
                        Ok(())
                    },
                )?;

                checkpoint_heights = checkpoint_heights
                    .intersection(&orchard_checkpoint_heights)
                    .copied()
                    .collect();

                let mut ironwood_checkpoint_heights = BTreeSet::new();
                self.ironwood_tree.store().for_each_checkpoint(
                    self.ironwood_tree.store().checkpoint_count()?,
                    |height, _| {
                        ironwood_checkpoint_heights.insert(u32::from(*height));
                        Ok(())
                    },
                )?;
                checkpoint_heights = checkpoint_heights
                    .intersection(&ironwood_checkpoint_heights)
                    .copied()
                    .collect();
            }
            // All the checkpoints that are greater than the truncation height
            let over = checkpoint_heights.split_off(&(u32::from(max_height + 1)));
            let mut rewindable_height = None;
            for height in checkpoint_heights.iter().rev().copied() {
                let height = BlockHeight::from(height);
                if !checkpoint_can_be_truncated(&self.sapling_tree, height)? {
                    continue;
                }
                #[cfg(feature = "orchard")]
                if !checkpoint_can_be_truncated(&self.orchard_tree, height)?
                    || !checkpoint_can_be_truncated(&self.ironwood_tree, height)?
                {
                    continue;
                }
                rewindable_height = Some(height);
                break;
            }
            rewindable_height.ok_or(Error::RequestedRewindInvalid(
                over.first().copied().map(Into::into),
                max_height,
            ))
        }?;

        // Recall where we synced up to previously.
        let last_scanned_height = self.blocks.keys().max().copied().unwrap_or_else(|| {
            self.params
                .activation_height(NetworkUpgrade::Sapling)
                .expect("Sapling activation height must be available.")
                - 1
        });

        // Invalidate outstanding network replies before the first mutation. This
        // also covers rewinds of transparent history above the last scanned block,
        // and partial failure of a subsequent tree truncation.
        self.chain_state_revision = crate::ChainStateRevision::new();

        // Delete from the scanning queue any range with a start height greater than the
        // truncation height, and then truncate any remaining range by setting the end
        // equal to the truncation height + 1. This sets our view of the chain tip back
        // to the retained height.
        self.scan_queue
            .delete_starts_greater_than_equal_to(truncation_height + 1);
        self.scan_queue.truncate_ends_to(truncation_height + 1);

        #[cfg(feature = "transparent-inputs")]
        for account in self.accounts.values_mut() {
            for candidate in account.internal_address_discovery.values_mut() {
                candidate.checked_height = candidate
                    .checked_height
                    .map(|height| height.min(truncation_height));
            }
        }

        // Mark transparent utxos as un-mined. Since the TXO is now not mined, it would ideally be
        // considered to have been returned to the mempool; it _might_ be spendable in this state, but
        // we must also set its max_observed_unspent_height field to NULL because the transaction may
        // be rendered entirely invalid by a reorg that alters anchor(s) used in constructing shielded
        // spends in the transaction.
        self.transparent_received_outputs
            .iter_mut()
            .for_each(|(_, txo)| {
                if let Some(mined_height) = self
                    .tx_table
                    .get(&txo.transaction_id)
                    .and_then(|tx| tx.mined_height())
                {
                    if mined_height <= truncation_height {
                        txo.max_observed_unspent_height = Some(truncation_height)
                    } else {
                        txo.max_observed_unspent_height = None
                    }
                }
            });

        // Un-mine transactions. This must be done outside of the last_scanned_height check because
        // transaction entries may be created as a consequence of receiving transparent TXOs.
        self.tx_table
            .unmine_transactions_greater_than(truncation_height);

        // If we're removing scanned blocks, we need to truncate the note commitment tree and remove
        // affected block records from the database.
        if truncation_height < last_scanned_height {
            self.with_sapling_tree_mut(|tree| {
                tree.truncate_to_checkpoint(&truncation_height).map(|_| ())
            })?;
            #[cfg(feature = "orchard")]
            self.with_orchard_tree_mut(|tree| {
                tree.truncate_to_checkpoint(&truncation_height).map(|_| ())
            })?;
            #[cfg(feature = "orchard")]
            self.with_ironwood_tree_mut(|tree| {
                tree.truncate_to_checkpoint(&truncation_height).map(|_| ())
            })?;

            // Do not delete sent notes; this can contain data that is not recoverable
            // from the chain. Wallets must continue to operate correctly in the
            // presence of stale sent notes that link to unmined transactions.
            // Also, do not delete received notes; they may contain memo data that is
            // not recoverable; balance APIs must ensure that un-mined received notes
            // do not count towards spendability or transaction balalnce.

            // Now that they aren't depended on, delete un-mined blocks.
            self.blocks.retain(|height, _| *height <= truncation_height);

            // These maps can contain entries above the scanned block range to support
            // non-linear scanning. They must follow the selected chain across a rewind.
            self.tx_locator.truncate_to_height(truncation_height);
            self.nullifiers.truncate_to_height(truncation_height);
        }
        Ok(truncation_height)
    }

    fn truncate_to_chain_state(&mut self, _chain_state: ChainState) -> Result<(), Error> {
        todo!()
    }

    fn rewind_to_chain_state(
        &mut self,
        _chain_state: ChainState,
        _reset_account_birthdays: HashSet<AccountId>,
    ) -> Result<(), RewindError<AccountId, Error>> {
        todo!()
    }

    fn import_account_hd(
        &mut self,
        _account_name: &str,
        _seed: &SecretVec<u8>,
        _account_index: zip32::AccountId,
        _birthday: &AccountBirthday,
        _key_source: Option<&str>,
    ) -> Result<(Self::Account, UnifiedSpendingKey), Error> {
        unimplemented!(
            "Memwallet does not support adding accounts from seed phrases.
Instead derive the ufvk in the calling code and import it using `import_account_ufvk`"
        )
    }

    fn import_account_ufvk(
        &mut self,
        account_name: &str,
        unified_key: &UnifiedFullViewingKey,
        birthday: &AccountBirthday,
        purpose: AccountPurpose,
        key_source: Option<&str>,
    ) -> Result<Self::Account, Error> {
        tracing::debug!("import_account_ufvk");
        let (_id, account) = self.add_account(
            account_name,
            AccountSource::Imported {
                purpose,
                key_source: key_source.map(str::to_owned),
            },
            unified_key.to_owned(),
            birthday.clone(),
        )?;
        Ok(account)
    }

    fn store_transactions_to_be_sent(
        &mut self,
        transactions: &[SentTransaction<AccountId>],
    ) -> Result<(), Error> {
        tracing::debug!("store_transactions_to_be_sent");
        for sent_tx in transactions {
            self.tx_table.put_tx_data(
                sent_tx.tx(),
                Some(sent_tx.fee_amount()),
                Some(sent_tx.target_height()),
            );
            let mut detectable_via_scanning = false;
            // Mark sapling notes as spent
            if let Some(bundle) = sent_tx.tx().sapling_bundle() {
                detectable_via_scanning = true;
                for spend in bundle.shielded_spends() {
                    self.mark_sapling_note_spent(*spend.nullifier(), sent_tx.tx().txid())?;
                }
            }
            // Mark orchard notes as spent
            if let Some(_bundle) = sent_tx.tx().orchard_bundle() {
                #[cfg(feature = "orchard")]
                {
                    detectable_via_scanning = true;
                    for action in _bundle.actions() {
                        match self.mark_orchard_note_spent(*action.nullifier(), sent_tx.tx().txid())
                        {
                            Ok(()) => {}
                            Err(Error::NoteNotFound) => {
                                // This is expected as some of the actions will be new outputs we don't have notes for
                                // The ones we do recognize will be marked as spent
                            }
                            Err(e) => return Err(e),
                        }
                    }
                }

                #[cfg(not(feature = "orchard"))]
                panic!("Sent a transaction with Orchard Actions without `orchard` enabled?");
            }
            if let Some(_bundle) = sent_tx.tx().ironwood_bundle() {
                #[cfg(feature = "orchard")]
                {
                    detectable_via_scanning = true;
                    for action in _bundle.actions() {
                        match self
                            .mark_ironwood_note_spent(*action.nullifier(), sent_tx.tx().txid())
                        {
                            Ok(()) | Err(Error::NoteNotFound) => {}
                            Err(e) => return Err(e),
                        }
                    }
                }

                #[cfg(not(feature = "orchard"))]
                panic!("Sent a transaction with Ironwood Actions without `orchard` enabled?");
            }
            // Mark transparent UTXOs as spent
            #[cfg(feature = "transparent-inputs")]
            for utxo_outpoint in sent_tx.utxos_spent() {
                self.mark_transparent_output_spent(&sent_tx.tx().txid(), utxo_outpoint)?;
            }

            for output in sent_tx.outputs() {
                self.sent_notes.insert_sent_output(sent_tx, output);

                match output.recipient() {
                    Recipient::InternalShielded { .. } => {
                        self.received_notes.insert_received_note(
                            ReceivedNote::from_sent_tx_output(sent_tx.tx().txid(), output)?,
                        );
                    }
                    #[cfg(feature = "transparent-inputs")]
                    Recipient::EphemeralTransparent {
                        receiving_account,
                        ephemeral_address,
                        outpoint,
                    } => {
                        let txo = WalletTransparentOutput::from_parts(
                            outpoint.clone(),
                            TxOut::new(output.value(), ephemeral_address.script().into()),
                            None,
                            Some(*receiving_account),
                            Some(TransparentKeyScope::EPHEMERAL),
                            Some(*sent_tx.funding_account()),
                        )
                        .unwrap();
                        self.put_transparent_output(&txo, receiving_account, true)?;
                        if let Some(account) = self.accounts.get_mut(*receiving_account) {
                            account.mark_ephemeral_address_as_used(
                                ephemeral_address,
                                sent_tx.tx().txid(),
                            )?
                        }
                    }
                    #[cfg(feature = "transparent-inputs")]
                    Recipient::InternalTransparent {
                        receiving_account,
                        recipient_address,
                    } => {
                        let txo = WalletTransparentOutput::from_parts(
                            OutPoint::new(
                                sent_tx.tx().txid().into(),
                                u32::try_from(output.output_index())
                                    .expect("transparent output index fits into a u32"),
                            ),
                            TxOut::new(output.value(), recipient_address.script().into()),
                            None,
                            Some(*receiving_account),
                            None,
                            Some(*sent_tx.funding_account()),
                        )
                        .expect("transparent internal recipient has a standard address script");
                        self.put_transparent_output(&txo, receiving_account, true)?;
                    }
                    _ => {}
                }
            }

            // Orchard transactions may be broadcast through zero-indexer before the
            // ordinary chain scanner sees them, so query their status as well.
            if !detectable_via_scanning || sent_tx.tx().orchard_bundle().is_some() {
                self.transaction_data_request_queue
                    .queue_status_retrieval(&sent_tx.tx().txid());
            }
        }

        Ok(())
    }

    fn set_transaction_status(
        &mut self,
        txid: TxId,
        status: TransactionStatus,
    ) -> Result<(), Error> {
        tracing::debug!("set_transaction_status");
        self.tx_table.set_transaction_status(&txid, status)?;
        #[cfg(feature = "transparent-inputs")]
        self.ensure_internal_address_gaps()?;
        let request_resolved = match status {
            TransactionStatus::Mined(_) => true,
            TransactionStatus::TxidNotRecognized | TransactionStatus::NotInMainChain => {
                match (
                    self.tx_table.get(&txid).and_then(|tx| tx.expiry_height()),
                    self.chain_height()?,
                ) {
                    (Some(expiry_height), Some(chain_height)) => chain_height > expiry_height,
                    _ => false,
                }
            }
        };
        if request_resolved {
            self.transaction_data_request_queue
                .remove_status_retrieval(&txid);
        }
        Ok(())
    }

    #[cfg(feature = "transparent-inputs")]
    fn reserve_next_n_ephemeral_addresses(
        &mut self,
        account_id: AccountId,
        n: usize,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Error> {
        use zcash_keys::keys::AddressGenerationError;
        // TODO: We need to implement first_unsafe_index to make sure we dont violate gap invarient

        use transparent::keys::NonHardenedChildIndex;
        let first_unsafe = self.first_unsafe_index(account_id)?;
        if let Some(account) = self.accounts.get_mut(account_id) {
            let first_unreserved = account.first_unreserved_index()?;

            let allocation = range_from(first_unreserved, u32::try_from(n).unwrap());

            if allocation.len() < n {
                return Err(AddressGenerationError::DiversifierSpaceExhausted.into());
            }
            if allocation.end > first_unsafe {
                return Err(Error::ReachedGapLimit(
                    account_id,
                    core::cmp::max(first_unreserved, first_unsafe),
                ));
            }
            let _reserved = account.reserve_until(allocation.end)?;
            self.get_known_ephemeral_addresses(
                account_id,
                Some(
                    NonHardenedChildIndex::from_index(allocation.start).expect("Bad Index")
                        ..NonHardenedChildIndex::from_index(allocation.end).expect("Bad Index"),
                ),
            )
        } else {
            Err(Error::AccountUnknown(account_id))
        }
    }

    #[cfg(feature = "transparent-inputs")]
    fn reserve_next_n_internal_addresses(
        &mut self,
        account_id: AccountId,
        n: usize,
    ) -> Result<Vec<(TransparentAddress, TransparentAddressMetadata)>, Error> {
        use zcash_keys::keys::AddressGenerationError;

        if n == 0 {
            return Ok(vec![]);
        }

        let exposed_at_height = self.chain_height()?.ok_or(Error::ChainHeightUnknown)?;
        let first_gap_index = self.first_internal_gap_index(account_id)?;
        let first_unsafe = self.first_internal_unsafe_index(account_id)?;
        let account = self
            .accounts
            .get_mut(account_id)
            .ok_or(Error::AccountUnknown(account_id))?;
        let first_unreserved = account.next_internal_address_index()?;
        let allocation = range_from(first_unreserved, u32::try_from(n)?);

        if allocation.len() < n {
            return Err(AddressGenerationError::DiversifierSpaceExhausted.into());
        }
        if allocation.end > first_unsafe {
            return Err(Error::ReachedGapLimit(
                account_id,
                core::cmp::max(first_unreserved, first_unsafe),
            ));
        }

        account.reserve_internal_addresses(allocation.start, n, exposed_at_height, first_gap_index)
    }

    fn get_address_for_index(
        &mut self,
        account: AccountId,
        diversifier_index: DiversifierIndex,
        request: UnifiedAddressRequest,
    ) -> Result<Option<UnifiedAddress>, Error> {
        if let Some(account) = self.accounts.get_mut(account) {
            Ok(Some(account.address_at(diversifier_index, request)?))
        } else {
            Ok(None)
        }
    }

    #[cfg(feature = "transparent-inputs")]
    fn notify_address_checked(
        &mut self,
        request: TransactionsInvolvingAddress,
        as_of_height: BlockHeight,
    ) -> Result<(), Error> {
        use zcash_client_backend::data_api::{OutputStatusFilter, TransactionStatusFilter};

        // Only complete mined history proves the absence of historical uses or
        // spends. UTXO-only and mempool-only responses cannot advance this cursor.
        let full_history = request.output_status_filter() == &OutputStatusFilter::All
            && request.tx_status_filter() != &TransactionStatusFilter::Mempool;
        for account in self.accounts.values_mut() {
            let birthday = account.birthday().height();
            for candidate in account.internal_address_discovery.values_mut() {
                if full_history && candidate.address == request.address() {
                    let next = candidate
                        .checked_height
                        .map_or(birthday, |height| height + 1);
                    // Only contiguous, fully completed history ranges advance
                    // discovery. An out-of-order suffix cannot skip older use.
                    if request.block_range_start() <= next && as_of_height >= next {
                        candidate.checked_height = Some(as_of_height);
                    }
                }
            }
        }
        self.transaction_data_request_queue.0.retain(|pending| {
            !matches!(pending, zcash_client_backend::data_api::TransactionDataRequest::TransactionsInvolvingAddress(queued)
                if queued == &request && queued.block_range_end().is_some_and(|end| as_of_height >= end - 1))
        });
        for (outpoint, output) in self.transparent_received_outputs.iter_mut() {
            if full_history
                && output.address == request.address()
                && !self
                    .transparent_received_output_spends
                    .contains_key(outpoint)
            {
                output.max_observed_unspent_height = Some(
                    output
                        .max_observed_unspent_height
                        .map_or(as_of_height, |height| height.max(as_of_height)),
                );
            }
        }
        Ok(())
    }

    #[cfg(feature = "transparent-key-import")]
    fn import_standalone_transparent_pubkey(
        &mut self,
        _account: AccountId,
        _pubkey: secp256k1::PublicKey,
    ) -> Result<(), Error> {
        todo!()
    }

    #[cfg(feature = "transparent-key-import")]
    fn import_standalone_transparent_script(
        &mut self,
        _account: AccountId,
        _script: zcash_script::script::Redeem,
    ) -> Result<(), Error> {
        todo!()
    }
}

#[cfg(feature = "transparent-inputs")]
fn range_from(i: u32, n: u32) -> Range<u32> {
    let first = core::cmp::min(1 << 31, i);
    let last = core::cmp::min(1 << 31, i.saturating_add(n));
    first..last
}

use zcash_keys::address::Receiver;
use zcash_keys::encoding::AddressCodec;
#[cfg(feature = "orchard")]
use {incrementalmerkletree::frontier::Frontier, shardtree::store::Checkpoint};

#[cfg(feature = "orchard")]
fn ensure_checkpoints<'a, H, I: Iterator<Item = &'a BlockHeight>, const DEPTH: u8>(
    // An iterator of checkpoints heights for which we wish to ensure that
    // checkpoints exists.
    ensure_heights: I,
    // The map of checkpoint positions from which we will draw note commitment tree
    // position information for the newly created checkpoints.
    existing_checkpoint_positions: &BTreeMap<BlockHeight, Position>,
    // The frontier whose position will be used for an inserted checkpoint when
    // there is no preceding checkpoint in existing_checkpoint_positions.
    state_final_tree: &Frontier<H, DEPTH>,
) -> Vec<(BlockHeight, Checkpoint)> {
    ensure_heights
        .flat_map(|ensure_height| {
            existing_checkpoint_positions
                .range::<BlockHeight, _>(..=*ensure_height)
                .last()
                .map_or_else(
                    || {
                        Some((
                            *ensure_height,
                            state_final_tree
                                .value()
                                .map_or_else(Checkpoint::tree_empty, |t| {
                                    Checkpoint::at_position(t.position())
                                }),
                        ))
                    },
                    |(existing_checkpoint_height, position)| {
                        if *existing_checkpoint_height < *ensure_height {
                            Some((*ensure_height, Checkpoint::at_position(*position)))
                        } else {
                            // The checkpoint already exists, so we don't need to
                            // do anything.
                            None
                        }
                    },
                )
                .into_iter()
        })
        .collect::<Vec<_>>()
}

#[cfg(test)]
mod tests {
    use shardtree::store::{Checkpoint, ShardStore};
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::consensus::{Parameters, TxIndex};

    use super::*;

    #[test]
    fn queue_rescan_reopens_scanned_range_without_touching_neighbors() {
        let mut wallet = MemoryWalletDb::new(consensus::Network::TestNetwork, 100);
        wallet.scan_queue.0 = vec![(10.into(), 30.into(), ScanPriority::Scanned)];

        wallet.queue_rescan(15.into()..25.into()).unwrap();
        assert_eq!(
            wallet.scan_queue.0,
            vec![
                (10.into(), 15.into(), ScanPriority::Scanned),
                (15.into(), 25.into(), ScanPriority::Historic),
                (25.into(), 30.into(), ScanPriority::Scanned),
            ]
        );
        let before = wallet.scan_queue.clone();
        wallet.queue_rescan(20.into()..20.into()).unwrap();
        assert_eq!(wallet.scan_queue, before);
    }

    #[test]
    fn prune_scan_queue_preserves_bookkeeping_and_counts_ranges() {
        let mut wallet = MemoryWalletDb::new(consensus::Network::TestNetwork, 100);
        let range = |start: u32, end: u32, priority| (start.into(), end.into(), priority);
        wallet.scan_queue.0 = vec![
            range(1, 10, ScanPriority::Ignored),
            range(10, 20, ScanPriority::FoundNote),
            range(20, 30, ScanPriority::Scanned),
            range(30, 50, ScanPriority::Historic),
            range(50, 60, ScanPriority::ChainTip),
        ];
        assert_eq!(
            wallet
                .prune_scan_queue_below(40.into(), Some(ScanPriority::OpenAdjacent))
                .unwrap(),
            1
        );
        assert_eq!(
            wallet.scan_queue.0,
            vec![
                range(1, 10, ScanPriority::Ignored),
                range(10, 20, ScanPriority::FoundNote),
                range(20, 30, ScanPriority::Scanned),
                range(30, 40, ScanPriority::Ignored),
                range(40, 50, ScanPriority::Historic),
                range(50, 60, ScanPriority::ChainTip),
            ]
        );
        assert_eq!(
            wallet
                .prune_scan_queue_below(40.into(), Some(ScanPriority::OpenAdjacent))
                .unwrap(),
            0
        );
        assert_eq!(wallet.prune_scan_queue_below(40.into(), None).unwrap(), 4);
        assert_eq!(
            wallet.scan_queue.0,
            vec![
                range(40, 50, ScanPriority::Historic),
                range(50, 60, ScanPriority::ChainTip),
            ]
        );
    }

    #[test]
    fn prune_scan_queue_coalesces_ignored_ranges_and_raises_unretained_floor() {
        let mut wallet = MemoryWalletDb::new(consensus::Network::TestNetwork, 100);
        wallet.scan_queue.0 = vec![
            (1.into(), 10.into(), ScanPriority::Ignored),
            (10.into(), 30.into(), ScanPriority::Historic),
        ];
        assert_eq!(
            wallet
                .prune_scan_queue_below(20.into(), Some(ScanPriority::OpenAdjacent))
                .unwrap(),
            2
        );
        assert_eq!(
            wallet.scan_queue.0,
            vec![
                (1.into(), 20.into(), ScanPriority::Ignored),
                (20.into(), 30.into(), ScanPriority::Historic),
            ]
        );
        assert_eq!(wallet.prune_scan_queue_below(20.into(), None).unwrap(), 1);
        assert_eq!(
            wallet
                .prune_scan_queue_below(30.into(), Some(ScanPriority::OpenAdjacent))
                .unwrap(),
            1
        );
        assert!(wallet.scan_queue.0.is_empty());
    }

    fn empty_block(height: BlockHeight) -> MemoryWalletBlock {
        MemoryWalletBlock {
            height,
            hash: BlockHash([0; 32]),
            block_time: 0,
            _transactions: HashSet::new(),
            _memos: HashMap::new(),
            sapling_commitment_tree_size: Some(0),
            sapling_output_count: Some(0),
            #[cfg(feature = "orchard")]
            orchard_commitment_tree_size: Some(0),
            #[cfg(feature = "orchard")]
            orchard_action_count: Some(0),
            #[cfg(feature = "orchard")]
            ironwood_commitment_tree_size: Some(0),
            #[cfg(feature = "orchard")]
            ironwood_action_count: Some(0),
        }
    }

    #[test]
    fn truncate_removes_nullifier_locators_from_the_rewound_chain() {
        let mut wallet = MemoryWalletDb::new(consensus::Network::TestNetwork, 100);
        let retained_height = wallet
            .params
            .activation_height(NetworkUpgrade::Sapling)
            .expect("testnet has a Sapling activation height");
        let rewound_height = retained_height + 1;

        for height in [retained_height, rewound_height] {
            wallet
                .sapling_tree
                .store_mut()
                .add_checkpoint(height, Checkpoint::tree_empty())
                .expect("Sapling checkpoint insertion succeeds");
            #[cfg(feature = "orchard")]
            wallet
                .orchard_tree
                .store_mut()
                .add_checkpoint(height, Checkpoint::tree_empty())
                .expect("Orchard checkpoint insertion succeeds");
            #[cfg(feature = "orchard")]
            wallet
                .ironwood_tree
                .store_mut()
                .add_checkpoint(height, Checkpoint::tree_empty())
                .expect("Ironwood checkpoint insertion succeeds");
            wallet.blocks.insert(height, empty_block(height));
        }

        let retained_txid = TxId::from_bytes([1; 32]);
        let orphaned_txid = TxId::from_bytes([2; 32]);
        let replacement_txid = TxId::from_bytes([3; 32]);
        let retained_nullifier = sapling::Nullifier::from_slice(&[1; 32]).unwrap();
        let orphaned_nullifier = sapling::Nullifier::from_slice(&[2; 32]).unwrap();
        let replacement_nullifier = sapling::Nullifier::from_slice(&[3; 32]).unwrap();

        wallet
            .insert_sapling_nullifier_map(
                retained_height,
                &[(TxIndex::from(0u16), retained_txid, vec![retained_nullifier])],
            )
            .unwrap();
        wallet
            .insert_sapling_nullifier_map(
                rewound_height,
                &[(TxIndex::from(0u16), orphaned_txid, vec![orphaned_nullifier])],
            )
            .unwrap();

        assert_eq!(
            wallet.truncate_to_height(retained_height).unwrap(),
            retained_height
        );

        wallet
            .insert_sapling_nullifier_map(
                rewound_height,
                &[(
                    TxIndex::from(0u16),
                    replacement_txid,
                    vec![replacement_nullifier],
                )],
            )
            .expect("the replacement chain locator does not conflict after rewind");

        assert_eq!(
            wallet.tx_locator.get(retained_height, 0),
            Some(&retained_txid)
        );
        assert_eq!(
            wallet.tx_locator.get(rewound_height, 0),
            Some(&replacement_txid)
        );
        assert_eq!(
            wallet
                .nullifiers
                .get(&Nullifier::Sapling(retained_nullifier)),
            Some(&(retained_height, 0))
        );
        assert!(
            wallet
                .nullifiers
                .get(&Nullifier::Sapling(orphaned_nullifier))
                .is_none()
        );
    }
}
