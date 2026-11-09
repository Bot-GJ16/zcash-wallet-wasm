//! Owned, read-only Ironwood voting snapshots.

use incrementalmerkletree::{Marking, Position, Retention, frontier::NonEmptyFrontier};
use orchard::{NoteVersion, ValuePool, note::ExtractedNoteCommitment, tree::MerkleHashOrchard};
use shardtree::{ShardTree, store::memory::MemoryShardStore};
use zcash_client_backend::{
    data_api::{Account as _, ORCHARD_SHARD_HEIGHT, WalletRead},
    wallet::Note,
};
use zcash_keys::keys::UnifiedFullViewingKey;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zip32::{Scope, fingerprint::SeedFingerprint};

use crate::{
    AccountId, Error, MemoryWalletDb, Nullifier,
    wallet_commitment_trees::serialization::{tree_from_protobuf, tree_to_protobuf},
};

/// A selected Ironwood note and its owned viewing metadata.
#[derive(Clone)]
pub struct VotingSnapshotNote {
    pub note: orchard::note::Note,
    pub position: u64,
    pub scope: Scope,
    pub ufvk: UnifiedFullViewingKey,
}

/// Selected notes with historical authentication paths in note order.
pub struct VotingSnapshot {
    pub fully_scanned_height: BlockHeight,
    pub account_index: zip32::AccountId,
    pub seed_fingerprint: SeedFingerprint,
    pub notes: Vec<VotingSnapshotNote>,
    pub root: [u8; 32],
    pub auth_paths: Vec<Vec<[u8; 32]>>,
}

/// Eligibility metadata; collecting this value never accesses commitment trees.
pub struct VotingSnapshotNotes {
    pub fully_scanned_height: BlockHeight,
    pub account_index: zip32::AccountId,
    pub seed_fingerprint: SeedFingerprint,
    pub notes: Vec<VotingSnapshotNote>,
}

impl<P: Parameters> MemoryWalletDb<P> {
    /// Select mined V3 Ironwood notes unspent at `snapshot_height`, ignoring
    /// later and unmined spends. No tree, cache, or wallet state is mutated.
    pub fn voting_snapshot_notes(
        &self,
        account_id: AccountId,
        snapshot_height: BlockHeight,
    ) -> Result<VotingSnapshotNotes, Error> {
        let account = self
            .accounts
            .get(account_id)
            .ok_or(Error::AccountUnknown(account_id))?;
        let derivation = account
            .source()
            .key_derivation()
            .ok_or(Error::UnknownZip32Derivation)?;
        let ufvk = account
            .ufvk()
            .ok_or(Error::ViewingKeyNotFound(account_id))?;
        let orchard_fvk = ufvk
            .orchard()
            .ok_or(Error::ViewingKeyNotFound(account_id))?;
        let fully_scanned_height = self
            .block_fully_scanned()?
            .map(|b| b.block_height())
            .ok_or(Error::ChainHeightUnknown)?;
        if fully_scanned_height < snapshot_height {
            return Err(Error::Other(
                "wallet is not synced to voting snapshot".into(),
            ));
        }
        let mut notes = Vec::new();
        for received in &self.received_notes.0 {
            if received.account_id != account_id {
                continue;
            }
            let Note::Orchard {
                note,
                pool: ValuePool::Ironwood,
            } = &received.note
            else {
                continue;
            };
            if note.version() != NoteVersion::V3 {
                continue;
            }
            let Some(receipt_height) = self
                .tx_table
                .get(&received.txid)
                .and_then(|tx| tx.mined_height())
                .filter(|h| *h <= snapshot_height)
            else {
                continue;
            };
            let nf = received
                .nf
                .ok_or_else(|| Error::Missing("voting note nullifier".into()))?;
            if nf != Nullifier::Ironwood(note.nullifier(orchard_fvk)) {
                return Err(Error::CorruptedData(
                    "invalid voting note nullifier metadata".into(),
                ));
            }
            // A local conflicting spend can overwrite the note association, but
            // cannot override the canonical nullifier evidence from scanning.
            let canonical = self
                .nullifiers
                .get(&nf)
                .map(|(height, index)| {
                    let txid = self.tx_locator.get(*height, *index).ok_or_else(|| {
                        Error::CorruptedData("missing canonical voting spend locator".into())
                    })?;
                    if *height < receipt_height {
                        return Err(Error::CorruptedData(
                            "voting spend precedes note receipt".into(),
                        ));
                    }
                    Ok((*height, txid))
                })
                .transpose()?;
            if canonical.is_some_and(|(height, _)| height <= snapshot_height) {
                continue;
            }
            if let Some(spend) = self.received_note_spends.get(&received.note_id) {
                let tx = self.tx_table.get(spend).ok_or_else(|| {
                    Error::CorruptedData("missing voting note spend transaction".into())
                })?;
                if let (Some(local_height), Some((canonical_height, canonical_txid))) =
                    (tx.mined_height(), canonical)
                {
                    if local_height != canonical_height || spend != canonical_txid {
                        return Err(Error::CorruptedData(
                            "inconsistent voting spend evidence".into(),
                        ));
                    }
                }
                if tx.mined_height().is_some_and(|h| h <= snapshot_height) {
                    continue;
                }
            }
            let position = received
                .commitment_tree_position
                .ok_or_else(|| Error::Missing("voting note position".into()))?;
            if u64::from(position) >= (1u64 << orchard::NOTE_COMMITMENT_TREE_DEPTH) {
                return Err(Error::CorruptedData(
                    "voting note position exceeds tree depth".into(),
                ));
            }
            notes.push(VotingSnapshotNote {
                note: *note,
                position: position.into(),
                scope: received
                    .recipient_key_scope
                    .ok_or_else(|| Error::Missing("voting note scope".into()))?,
                ufvk: ufvk.clone(),
            });
        }
        notes.sort_by_key(|n| n.position);
        if notes
            .windows(2)
            .any(|pair| pair[0].position == pair[1].position)
        {
            return Err(Error::CorruptedData(
                "duplicate voting note position".into(),
            ));
        }
        Ok(VotingSnapshotNotes {
            fully_scanned_height,
            account_index: derivation.account_index(),
            seed_fingerprint: *derivation.seed_fingerprint(),
            notes,
        })
    }

    /// Add paths at the supplied historical frontier, validating every note's
    /// commitment and root. Tree reconstruction and caching affect only a copy.
    pub fn voting_snapshot(
        &self,
        account_id: AccountId,
        snapshot_height: BlockHeight,
        frontier: NonEmptyFrontier<MerkleHashOrchard>,
    ) -> Result<VotingSnapshot, Error> {
        let selected = self.voting_snapshot_notes(account_id, snapshot_height)?;
        let root = frontier
            .root(Some((orchard::NOTE_COMMITMENT_TREE_DEPTH as u8).into()))
            .to_bytes();
        let frontier_position = frontier.position();
        let mut encoded = tree_to_protobuf(&self.ironwood_tree)?
            .ok_or_else(|| Error::Missing("Ironwood voting tree".into()))?;
        if encoded.checkpoints.iter().any(|checkpoint| {
            checkpoint.checkpoint_id == u32::from(snapshot_height)
                && checkpoint.position != u64::from(frontier_position)
        }) {
            return Err(Error::CorruptedData(
                "voting frontier does not match snapshot checkpoint".into(),
            ));
        }
        // Only the requested checkpoint belongs on the ephemeral tree. Loading
        // later checkpoints could prune the historical checkpoint on insertion.
        encoded.checkpoints.clear();
        let mut tree: ShardTree<
            MemoryShardStore<MerkleHashOrchard, BlockHeight>,
            { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
            ORCHARD_SHARD_HEIGHT,
        > = tree_from_protobuf(encoded, 1, ORCHARD_SHARD_HEIGHT.into())?;
        tree.insert_frontier_nodes(
            frontier,
            Retention::Checkpoint {
                id: snapshot_height,
                marking: Marking::None,
            },
        )?;
        let mut auth_paths = Vec::with_capacity(selected.notes.len());
        for note in &selected.notes {
            if Position::from(note.position) > frontier_position {
                return Err(Error::CorruptedData(
                    "voting note is beyond snapshot frontier".into(),
                ));
            }
            let path = tree
                .witness_at_checkpoint_id(note.position.into(), &snapshot_height)?
                .ok_or_else(|| Error::Missing("historical voting witness".into()))?;
            let cmx: ExtractedNoteCommitment = note.note.commitment().into();
            if path.position() != Position::from(note.position)
                || path.path_elems().len() != orchard::NOTE_COMMITMENT_TREE_DEPTH
                || path.root(MerkleHashOrchard::from_cmx(&cmx)).to_bytes() != root
            {
                return Err(Error::CorruptedData(
                    "voting witness does not match snapshot root".into(),
                ));
            }
            auth_paths.push(
                path.path_elems()
                    .iter()
                    .map(MerkleHashOrchard::to_bytes)
                    .collect(),
            );
        }
        Ok(VotingSnapshot {
            fully_scanned_height: selected.fully_scanned_height,
            account_index: selected.account_index,
            seed_fingerprint: selected.seed_fingerprint,
            notes: selected.notes,
            root,
            auth_paths,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{MemBlockCache, MemoryWalletDb, testing::TestMemDbFactory};
    use incrementalmerkletree::{MerklePath, Position, Retention, frontier::Frontier};
    use orchard::{
        NoteVersion, ValuePool,
        note::{ExtractedNoteCommitment, RandomSeed, Rho},
        tree::MerkleHashOrchard,
    };
    use zcash_client_backend::{
        data_api::{
            Account as _, TransactionStatus, WalletWrite,
            testing::{TestBuilder, orchard::OrchardPoolTester, pool::dsl::TestDsl},
        },
        wallet::{Note, NoteId},
    };
    use zcash_primitives::block::BlockHash;
    use zcash_protocol::{ShieldedPool, TxId, consensus::TxIndex, value::Zatoshis};

    const DEPTH: u8 = orchard::NOTE_COMMITMENT_TREE_DEPTH as u8;

    #[test]
    fn voting_snapshot_canonical_spend_survives_local_overwrite_and_reorg() {
        let mut st = TestDsl::from(
            TestBuilder::new()
                .with_data_store_factory(TestMemDbFactory)
                .with_block_cache(MemBlockCache::new())
                .with_account_from_sapling_activation(BlockHash([0; 32])),
        )
        .build::<OrchardPoolTester>();
        let (receipt_height, _, _) =
            st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(100_000));
        let (spend_height, _, _) =
            st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(100_000));
        let (later_height, _, _) =
            st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(100_000));
        let account_id = st.get_account().id();
        let network = *st.wallet().params();
        let mut bytes = Vec::new();
        st.wallet().encode(&mut bytes).unwrap();
        drop(st);
        let mut db = MemoryWalletDb::decode_new(bytes.as_slice(), network, 100).unwrap();
        db.received_notes.0.truncate(1);
        let entry = &mut db.received_notes.0[0];
        let Note::Orchard { note, .. } = entry.note else {
            panic!("Orchard fixture")
        };
        let note = orchard::Note::from_parts(
            note.recipient(),
            note.value(),
            note.rho(),
            *note.rseed(),
            NoteVersion::V3,
        )
        .unwrap();
        let nf = note.nullifier(
            db.accounts
                .get(account_id)
                .unwrap()
                .ufvk()
                .unwrap()
                .orchard()
                .unwrap(),
        );
        entry.note = Note::Orchard {
            note,
            pool: ValuePool::Ironwood,
        };
        entry.note_id = NoteId::new(entry.txid, ShieldedPool::Ironwood, 0);
        entry.nf = Some(crate::Nullifier::Ironwood(nf));
        entry.commitment_tree_position = Some(0.into());
        let note_id = entry.note_id;
        let tx_template = db.tx_table.get(&entry.txid).unwrap().clone();
        db.ironwood_tree = MemoryWalletDb::new(network, 100).ironwood_tree;
        let cmx: ExtractedNoteCommitment = note.commitment().into();
        let leaf = MerkleHashOrchard::from_cmx(&cmx);
        let mut frontier = Frontier::<MerkleHashOrchard, DEPTH>::empty();
        frontier.append(leaf);
        db.ironwood_tree.append(leaf, Retention::Marked).unwrap();
        db.ironwood_tree.checkpoint(receipt_height).unwrap();
        db.ironwood_tree.checkpoint(spend_height).unwrap();
        db.ironwood_tree.checkpoint(later_height).unwrap();

        let canonical = TxId::from_bytes([120; 32]);
        let local = TxId::from_bytes([121; 32]);
        db.tx_table.0.insert(canonical, tx_template.clone());
        db.tx_table
            .set_transaction_status(&canonical, TransactionStatus::Mined(spend_height))
            .unwrap();
        db.insert_ironwood_nullifier_map(
            spend_height,
            &[(TxIndex::from(1u16), canonical, vec![nf])],
        )
        .unwrap();
        db.received_note_spends.insert_spend(note_id, canonical);
        db.tx_table.0.insert(local, tx_template);
        db.tx_table
            .set_transaction_status(&local, TransactionStatus::NotInMainChain)
            .unwrap();
        assert_eq!(
            db.received_note_spends.insert_spend(note_id, local),
            Some(canonical)
        );

        let assert_selection = |db: &MemoryWalletDb<_>, height, expected| {
            let mut before = Vec::new();
            db.encode(&mut before).unwrap();
            assert_eq!(
                db.voting_snapshot_notes(account_id, height)
                    .unwrap()
                    .notes
                    .len(),
                expected
            );
            assert_eq!(
                db.voting_snapshot(account_id, height, frontier.clone().take().unwrap())
                    .unwrap()
                    .notes
                    .len(),
                expected
            );
            let mut after = Vec::new();
            db.encode(&mut after).unwrap();
            assert_eq!(before, after);
        };
        // A canonical later spend does not disqualify a historical snapshot.
        assert_selection(&db, receipt_height, 1);
        assert_selection(&db, spend_height, 0);
        assert_selection(&db, later_height, 0);
        let assert_invalid = |db: &MemoryWalletDb<_>| {
            let mut before = Vec::new();
            db.encode(&mut before).unwrap();
            assert!(
                db.voting_snapshot_notes(account_id, receipt_height)
                    .is_err()
            );
            assert!(
                db.voting_snapshot(account_id, receipt_height, frontier.clone().take().unwrap())
                    .is_err()
            );
            let mut after = Vec::new();
            db.encode(&mut after).unwrap();
            assert_eq!(before, after);
        };
        db.tx_table
            .set_transaction_status(&local, TransactionStatus::Mined(receipt_height))
            .unwrap();
        assert_invalid(&db);
        db.tx_table
            .set_transaction_status(&local, TransactionStatus::NotInMainChain)
            .unwrap();
        let locator = db.tx_locator.0.remove(&(spend_height, 1)).unwrap();
        assert_invalid(&db);
        db.tx_locator.0.insert((spend_height, 1), locator);
        let mut before_rewind = Vec::new();
        db.encode(&mut before_rewind).unwrap();
        assert!(matches!(
            db.truncate_to_height(receipt_height),
            Err(crate::Error::RequestedRewindInvalid(_, _))
        ));
        let mut after_failed_rewind = Vec::new();
        db.encode(&mut after_failed_rewind).unwrap();
        assert_eq!(before_rewind, after_failed_rewind);

        // The voting reorg fixture only needs Ironwood history. Empty trees for the
        // unrelated pools keep their checkpoints rewindable under shardtree 0.8.
        db.sapling_tree = MemoryWalletDb::new(network, 100).sapling_tree;
        db.orchard_tree = MemoryWalletDb::new(network, 100).orchard_tree;
        for height in [receipt_height, spend_height, later_height] {
            db.sapling_tree.checkpoint(height).unwrap();
            db.orchard_tree.checkpoint(height).unwrap();
        }
        assert_eq!(
            db.truncate_to_height(receipt_height).unwrap(),
            receipt_height
        );
        assert!(db.nullifiers.get(&crate::Nullifier::Ironwood(nf)).is_none());
        assert!(
            db.tx_table
                .get(&canonical)
                .unwrap()
                .mined_height()
                .is_none()
        );
        assert_eq!(db.received_note_spends.get(&note_id), Some(&local));
        assert_selection(&db, receipt_height, 1);

        for invalid in [
            None,
            Some(crate::Nullifier::Orchard(nf)),
            Some(crate::Nullifier::Ironwood(
                orchard::note::Nullifier::from_bytes(&[1; 32]).unwrap(),
            )),
        ] {
            db.received_notes.0[0].nf = invalid;
            assert_invalid(&db);
        }
    }

    #[test]
    fn voting_snapshot_historical_selection_and_read_only_paths() {
        let mut st = TestDsl::from(
            TestBuilder::new()
                .with_data_store_factory(TestMemDbFactory)
                .with_block_cache(MemBlockCache::new())
                .with_account_from_sapling_activation(BlockHash([0; 32])),
        )
        .build::<OrchardPoolTester>();
        let (height, _, _) =
            st.add_a_single_note_checking_balance(Zatoshis::const_from_u64(100_000));
        let account_id = st.get_account().id();
        let mut original_bytes = Vec::new();
        st.wallet().encode(&mut original_bytes).unwrap();
        let network = *st.wallet().params();
        drop(st);
        let mut wallet =
            MemoryWalletDb::decode_new(original_bytes.as_slice(), network, 100).unwrap();
        let db = &mut wallet;
        db.ironwood_tree = MemoryWalletDb::new(network, 100).ironwood_tree;
        let template = db.received_notes.0[0].clone();
        let tx_template = db.tx_table.get(&template.txid).unwrap().clone();
        let Note::Orchard { note: original, .. } = template.note else {
            panic!("Orchard fixture")
        };
        db.received_notes.0.clear();
        let mut frontier = Frontier::<MerkleHashOrchard, DEPTH>::empty();
        // Eligible: 0 unspent, 1 later spend, 2 unmined spend. Excluded: 3
        // spent at snapshot, 4 spent before, 5 later receipt, 6 unmined receipt,
        // 7 Orchard pool, 8 V2 note in an Ironwood pool record.
        for index in 0..9u8 {
            let rho = Rho::from_bytes(&[index; 32]).unwrap();
            let rseed = (0..=255)
                .find_map(|b| RandomSeed::from_bytes([b; 32], &rho).into_option())
                .unwrap();
            let version = if index == 8 {
                NoteVersion::V2
            } else {
                NoteVersion::V3
            };
            let note = orchard::Note::from_parts(
                original.recipient(),
                original.value(),
                rho,
                rseed,
                version,
            )
            .unwrap();
            let cmx: ExtractedNoteCommitment = note.commitment().into();
            let leaf = MerkleHashOrchard::from_cmx(&cmx);
            frontier.append(leaf);
            db.ironwood_tree.append(leaf, Retention::Marked).unwrap();
            let txid = TxId::from_bytes([index + 1; 32]);
            db.tx_table.0.insert(txid, tx_template.clone());
            if index == 5 {
                db.tx_table
                    .set_transaction_status(&txid, TransactionStatus::Mined(height + 1))
                    .unwrap();
            }
            if index == 6 {
                db.tx_table
                    .set_transaction_status(&txid, TransactionStatus::NotInMainChain)
                    .unwrap();
            }
            let mut entry = template.clone();
            entry.txid = txid;
            entry.note_id = NoteId::new(txid, ShieldedPool::Ironwood, 0);
            entry.note = Note::Orchard {
                note,
                pool: if index == 7 {
                    ValuePool::Orchard
                } else {
                    ValuePool::Ironwood
                },
            };
            entry.nf = Some(crate::Nullifier::Ironwood(
                note.nullifier(
                    db.accounts
                        .get(account_id)
                        .unwrap()
                        .ufvk()
                        .unwrap()
                        .orchard()
                        .unwrap(),
                ),
            ));
            entry.commitment_tree_position = Some(Position::from(u64::from(index)));
            if (1..=4).contains(&index) {
                let spend = TxId::from_bytes([index + 100; 32]);
                db.tx_table.0.insert(spend, tx_template.clone());
                let status = match index {
                    1 => TransactionStatus::Mined(height + 1),
                    2 => TransactionStatus::NotInMainChain,
                    3 => TransactionStatus::Mined(height),
                    _ => TransactionStatus::Mined(height - 1),
                };
                db.tx_table.set_transaction_status(&spend, status).unwrap();
                db.received_note_spends.insert_spend(entry.note_id, spend);
            }
            db.received_notes.0.push(entry);
        }
        db.ironwood_tree.checkpoint(height).unwrap();
        // Retained note shards must still support an old snapshot after its
        // checkpoint is pruned by more than the configured retention depth.
        for offset in 1..=105 {
            db.ironwood_tree
                .append(
                    MerkleHashOrchard::from_bytes(&[42; 32]).unwrap(),
                    Retention::Ephemeral,
                )
                .unwrap();
            db.ironwood_tree.checkpoint(height + offset).unwrap();
        }
        let mut before = Vec::new();
        db.encode(&mut before).unwrap();
        assert!(db.voting_snapshot_notes(999.into(), height).is_err());
        assert!(db.voting_snapshot_notes(account_id, height + 1).is_err());
        let selected = db.voting_snapshot_notes(account_id, height).unwrap();
        assert_eq!(
            selected
                .notes
                .iter()
                .map(|n| n.position)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        let snapshot = db
            .voting_snapshot(account_id, height, frontier.clone().take().unwrap())
            .unwrap();
        assert_eq!(snapshot.root, frontier.root().to_bytes());
        for (note, path) in snapshot.notes.iter().zip(&snapshot.auth_paths) {
            let cmx: ExtractedNoteCommitment = note.note.commitment().into();
            let path = MerklePath::<_, DEPTH>::from_parts(
                path.iter()
                    .map(|b| MerkleHashOrchard::from_bytes(b).unwrap())
                    .collect(),
                note.position.into(),
            )
            .unwrap();
            assert_eq!(
                path.root(MerkleHashOrchard::from_cmx(&cmx)).to_bytes(),
                snapshot.root
            );
        }
        let mut wrong = Frontier::<MerkleHashOrchard, DEPTH>::empty();
        for _ in 0..9 {
            wrong.append(MerkleHashOrchard::from_bytes(&[42; 32]).unwrap());
        }
        assert!(
            db.voting_snapshot(account_id, height, wrong.take().unwrap())
                .is_err()
        );
        let leaf = MerkleHashOrchard::from_bytes(&[42; 32]).unwrap();
        let oversized = incrementalmerkletree::frontier::NonEmptyFrontier::from_parts(
            (1u64 << DEPTH).into(),
            leaf,
            vec![leaf],
        )
        .unwrap();
        assert!(db.voting_snapshot(account_id, height, oversized).is_err());
        let mut after = Vec::new();
        db.encode(&mut after).unwrap();
        assert_eq!(before, after);
        let original_note = db.received_notes.0[0].note.clone();
        let original_nf = db.received_notes.0[0].nf;
        db.received_notes.0[0].note = db.received_notes.0[1].note.clone();
        db.received_notes.0[0].nf = db.received_notes.0[1].nf;
        assert!(
            db.voting_snapshot(account_id, height, frontier.clone().take().unwrap())
                .is_err()
        );
        db.received_notes.0[0].note = original_note;
        db.received_notes.0[0].nf = original_nf;
        db.received_notes.0[0].commitment_tree_position = Some(9.into());
        assert!(
            db.voting_snapshot(account_id, height, frontier.clone().take().unwrap())
                .is_err()
        );
        db.received_notes.0[0].commitment_tree_position = Some(0.into());
        // Eligibility does not depend on a tree or create a witness cache.
        db.ironwood_tree = MemoryWalletDb::new(*db.params(), 100).ironwood_tree;
        assert_eq!(
            db.voting_snapshot_notes(account_id, height)
                .unwrap()
                .notes
                .len(),
            3
        );
        assert!(
            db.voting_snapshot(account_id, height, frontier.take().unwrap())
                .is_err()
        );
    }
}
