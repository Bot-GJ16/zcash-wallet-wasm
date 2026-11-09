#[cfg(not(target_arch = "wasm32"))]
pub(crate) use crate::backend::zcash_client_sqlite;
#[allow(unused_imports)]
pub(crate) use crate::backend::{orchard, pasta_curves, zcash_client_backend, zcash_primitives};
use std::borrow::Borrow;

use crate::{
    shielded_protocol::VotingShieldedProtocol,
    storage::{queries, VotingDb},
    types::{Network, NoteInfo, VotingError, VotingRoundParams, WitnessData},
};

use orchard::tree::MerkleHashOrchard;
use prost::Message;
use subtle::CtOption;
use voting_crypto_deps::incrementalmerkletree::{
    frontier::CommitmentTree, Hashable, Level, MerklePath, Position,
};
use zcash_client_backend::proto::service::TreeState;
#[cfg(not(target_arch = "wasm32"))]
use zcash_client_sqlite::WalletDb;
use zcash_protocol::consensus::{BlockHeight, Parameters};

pub(crate) fn snapshot_frontier(
    bytes: &[u8],
    network: Network,
    height: u64,
) -> Result<
    voting_crypto_deps::incrementalmerkletree::frontier::NonEmptyFrontier<MerkleHashOrchard>,
    VotingError,
> {
    let invalid = |message: &str| VotingError::InvalidInput {
        message: message.into(),
    };
    let height32 =
        u32::try_from(height).map_err(|_| invalid("snapshot_height does not fit in u32"))?;
    VotingShieldedProtocol::for_height(&network, BlockHeight::from_u32(height32))?;
    let state = TreeState::decode(bytes).map_err(|_| invalid("invalid TreeState protobuf"))?;
    let expected = match network {
        Network::Mainnet => "main",
        Network::Testnet => "test",
        Network::Regtest => "regtest",
    };
    if state.network != expected {
        return Err(invalid("TreeState network does not match voting network"));
    }
    if state.height != height {
        return Err(invalid(
            "cached TreeState height does not match round snapshot_height",
        ));
    }
    let tree = state
        .ironwood_tree()
        .map_err(|_| invalid("invalid Ironwood TreeState frontier"))?;
    tree.to_frontier()
        .take()
        .ok_or_else(|| invalid("empty ironwood frontier at snapshot height"))
}

/// Validate the supplied notes, historical frontier and paths, then atomically
/// replace the tree state and bundle witnesses. Repeating identical inputs is
/// idempotent; any validation or write failure leaves both caches unchanged.
pub fn store_tree_state_and_witnesses(
    db: &VotingDb,
    round_id: &str,
    bundle_index: u32,
    tree_state_bytes: &[u8],
    notes: &[NoteInfo],
    witnesses: &[WitnessData],
) -> Result<(), VotingError> {
    let invalid = |message: &str| VotingError::InvalidInput {
        message: message.into(),
    };
    let wallet_id = db.wallet_id();
    let mut conn = db.conn();
    let tx = conn
        .transaction()
        .map_err(|_| invalid("could not start witness storage transaction"))?;
    let (params, network) = queries::load_round_params_with_network(&tx, round_id, &wallet_id)?;
    let frontier = snapshot_frontier(tree_state_bytes, network, params.snapshot_height)?;
    let root = frontier
        .root(Some((orchard::NOTE_COMMITMENT_TREE_DEPTH as u8).into()))
        .to_bytes();
    if params.nc_root != root {
        return Err(invalid(
            "cached TreeState ironwood root does not match round nc_root",
        ));
    }
    crate::selection::validate_snapshot_notes(notes, network, frontier.position().into())?;
    if notes.is_empty() || notes.len() != witnesses.len() {
        return Err(invalid("witness count does not match voting notes"));
    }
    let expected: std::collections::BTreeMap<_, _> =
        notes.iter().map(|n| (n.position, &n.commitment)).collect();
    let mut seen = std::collections::BTreeSet::new();
    for witness in witnesses {
        if !seen.insert(witness.position)
            || expected.get(&witness.position).copied() != Some(&witness.note_commitment)
            || witness.root != root
            || !verify_witness(witness)?
        {
            return Err(invalid(
                "voting witness does not match note and snapshot root",
            ));
        }
    }
    let mut bundle_positions =
        queries::load_bundle_note_positions(&tx, round_id, &wallet_id, bundle_index)?;
    bundle_positions.sort_unstable();
    if bundle_positions != expected.keys().copied().collect::<Vec<_>>() {
        return Err(invalid(
            "witness positions do not match bundle note positions",
        ));
    }
    queries::store_tree_state(
        &tx,
        round_id,
        &wallet_id,
        params.snapshot_height,
        tree_state_bytes,
    )?;
    tx.execute(
        "DELETE FROM witnesses WHERE round_id = ?1 AND wallet_id = ?2 AND bundle_index = ?3",
        rusqlite::params![round_id, wallet_id, bundle_index],
    )
    .map_err(|_| invalid("could not replace voting witnesses"))?;
    queries::store_witnesses(&tx, round_id, &wallet_id, bundle_index, witnesses)?;
    tx.commit()
        .map_err(|_| invalid("could not commit voting witnesses"))
}

/// Persist a voting snapshot tree state, generate shielded note witnesses, and cache them.
///
/// SDK boundary layers provide the already-open wallet database because wallet
/// path, network, and FFI handling differ by client. This helper owns the shared
/// voting invariant: the cached tree state is the round snapshot anchor used to
/// generate and store Merkle witnesses for one bundle.
#[cfg(not(target_arch = "wasm32"))]
pub fn store_tree_state_and_generate_note_witnesses<C, P, CL, R>(
    db: &VotingDb,
    round_id: &str,
    bundle_index: u32,
    tree_state_bytes: &[u8],
    notes: &[NoteInfo],
    wallet_db: &WalletDb<C, P, CL, R>,
) -> Result<Vec<WitnessData>, VotingError>
where
    C: Borrow<rusqlite::Connection>,
    P: zcash_protocol::consensus::Parameters,
{
    observe_store_tree_state_and_generate_note_witnesses(
        db,
        round_id,
        bundle_index,
        tree_state_bytes,
        notes,
        wallet_db,
        &crate::ObservationScope::disabled(),
    )
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn observe_store_tree_state_and_generate_note_witnesses<C, P, CL, R>(
    db: &VotingDb,
    round_id: &str,
    bundle_index: u32,
    tree_state_bytes: &[u8],
    notes: &[NoteInfo],
    wallet_db: &WalletDb<C, P, CL, R>,
    observations: &crate::ObservationScope,
) -> Result<Vec<WitnessData>, VotingError>
where
    C: Borrow<rusqlite::Connection>,
    P: zcash_protocol::consensus::Parameters,
{
    observations.bind_round_id(round_id);

    let attributed_observations = observations.attributed(crate::ObservationAttribution {
        bundle_index: Some(bundle_index),
        ..Default::default()
    });
    let observation_stage =
        attributed_observations.stage("witness::store_tree_state_and_generate_note_witnesses");
    let observations = observation_stage.scope();
    let operation_result: Result<Vec<WitnessData>, VotingError> = (|| {
        validate_wallet_db_network_for_round(db, round_id, wallet_db)?;
        let witnesses = observe_generate_note_witnesses_with_tree_state(
            db,
            round_id,
            notes,
            wallet_db,
            Some(tree_state_bytes),
            observations,
        )?;
        store_tree_state_and_witnesses(
            db,
            round_id,
            bundle_index,
            tree_state_bytes,
            notes,
            &witnesses,
        )?;
        Ok(witnesses)
    })();
    let outcome = if operation_result.is_ok() {
        crate::ObservationOutcome::Succeeded
    } else {
        crate::ObservationOutcome::Failed
    };
    observation_stage.finish(
        outcome,
        operation_result
            .as_ref()
            .err()
            .map(crate::observability::voting_error_kind),
    );
    operation_result
}

/// Generate shielded Merkle witnesses for the bundle notes at the round snapshot.
///
/// The cached lightwalletd `TreeState` is validated against the stored voting
/// round height and note commitment root before the wallet source is asked for
/// historical witnesses.
#[allow(unreachable_code, unused_variables)]
#[cfg(not(target_arch = "wasm32"))]
pub fn generate_note_witnesses<C, P, CL, R>(
    db: &VotingDb,
    round_id: &str,
    notes: &[NoteInfo],
    wallet_db: &WalletDb<C, P, CL, R>,
) -> Result<Vec<WitnessData>, VotingError>
where
    C: Borrow<rusqlite::Connection>,
    P: zcash_protocol::consensus::Parameters,
{
    observe_generate_note_witnesses(
        db,
        round_id,
        notes,
        wallet_db,
        &crate::ObservationScope::disabled(),
    )
}

#[cfg(not(target_arch = "wasm32"))]
pub(crate) fn observe_generate_note_witnesses<C, P, CL, R>(
    db: &VotingDb,
    round_id: &str,
    notes: &[NoteInfo],
    wallet_db: &WalletDb<C, P, CL, R>,
    observations: &crate::ObservationScope,
) -> Result<Vec<WitnessData>, VotingError>
where
    C: Borrow<rusqlite::Connection>,
    P: zcash_protocol::consensus::Parameters,
{
    observe_generate_note_witnesses_with_tree_state(
        db,
        round_id,
        notes,
        wallet_db,
        None,
        observations,
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn observe_generate_note_witnesses_with_tree_state<C, P, CL, R>(
    db: &VotingDb,
    round_id: &str,
    notes: &[NoteInfo],
    wallet_db: &WalletDb<C, P, CL, R>,
    supplied_tree_state: Option<&[u8]>,
    observations: &crate::ObservationScope,
) -> Result<Vec<WitnessData>, VotingError>
where
    C: Borrow<rusqlite::Connection>,
    P: zcash_protocol::consensus::Parameters,
{
    observations.bind_round_id(round_id);

    let attributed_observations = observations.clone();
    let observation_stage = attributed_observations.stage("witness::generate_note_witnesses");
    let operation_result: Result<Vec<WitnessData>, VotingError> = (|| {
        let (tree_state_bytes, params, stored_network) = {
            let wallet_id = db.wallet_id();
            let conn = db.conn();
            let tree_state_bytes = match supplied_tree_state {
                Some(bytes) => bytes.to_vec(),
                None => queries::load_tree_state(&conn, round_id, &wallet_id)?,
            };
            let (params, stored_network) =
                queries::load_round_params_with_network(&conn, round_id, &wallet_id)?;
            (tree_state_bytes, params, stored_network)
        };
        validate_wallet_network(stored_network, wallet_db)?;

        let tree_state =
            TreeState::decode(tree_state_bytes.as_slice()).map_err(|e| VotingError::Internal {
                message: format!("failed to decode TreeState protobuf: {e}"),
            })?;

        let snapshot_height =
            u32::try_from(params.snapshot_height).map_err(|_| VotingError::InvalidInput {
                message: format!(
                    "snapshot_height {} does not fit in u32",
                    params.snapshot_height
                ),
            })?;
        let snapshot_block_height = BlockHeight::from_u32(snapshot_height);
        let voting_protocol =
            VotingShieldedProtocol::for_height(&stored_network, snapshot_block_height)?;

        let note_commitment_tree: CommitmentTree<
            MerkleHashOrchard,
            { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 },
        > = match voting_protocol {
            VotingShieldedProtocol::Ironwood => tree_state.ironwood_tree(),
        }
        .map_err(|e| VotingError::Internal {
            message: format!(
                "failed to parse {} tree from TreeState: {e}",
                voting_protocol.pool()
            ),
        })?;

        let frontier_root_bytes = note_commitment_tree.root().to_bytes();
        validate_cached_tree_state_for_round(
            &tree_state,
            &frontier_root_bytes[..],
            &params,
            voting_protocol,
        )?;
        let frontier = note_commitment_tree.to_frontier();
        let nonempty_frontier = frontier.take().ok_or_else(|| VotingError::InvalidInput {
            message: format!(
                "empty {} frontier at snapshot height",
                voting_protocol.pool()
            ),
        })?;

        let positions: Vec<Position> = notes
            .iter()
            .map(|note| Position::from(note.position))
            .collect();
        let merkle_paths: Vec<
            MerklePath<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
        > = match voting_protocol {
            VotingShieldedProtocol::Ironwood => {
                WalletDb::generate_ironwood_witnesses_at_historical_height(
                    wallet_db,
                    &positions,
                    nonempty_frontier,
                    snapshot_block_height,
                )
                .map_err(|e| VotingError::Internal {
                    message: format!(
                        "generate_ironwood_witnesses_at_historical_height failed: {e}"
                    ),
                })?
            }
        };

        if merkle_paths.len() != notes.len() {
            return Err(VotingError::Internal {
                message: format!(
                    "generated {} Merkle paths for {} voting notes",
                    merkle_paths.len(),
                    notes.len()
                ),
            });
        }

        let root = frontier_root_bytes.to_vec();
        Ok(merkle_paths
            .into_iter()
            .zip(notes.iter())
            .map(|(path, note)| WitnessData {
                note_commitment: note.commitment.clone(),
                position: note.position,
                root: root.clone(),
                auth_path: path
                    .path_elems()
                    .iter()
                    .map(|hash| hash.to_bytes().to_vec())
                    .collect(),
            })
            .collect())
    })();
    let outcome = if operation_result.is_ok() {
        crate::ObservationOutcome::Succeeded
    } else {
        crate::ObservationOutcome::Failed
    };
    observation_stage.finish(
        outcome,
        operation_result
            .as_ref()
            .err()
            .map(crate::observability::voting_error_kind),
    );
    operation_result
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_wallet_db_network_for_round<C, P, CL, R>(
    db: &VotingDb,
    round_id: &str,
    wallet_db: &WalletDb<C, P, CL, R>,
) -> Result<(), VotingError>
where
    P: Parameters,
{
    let wallet_id = db.wallet_id();
    let conn = db.conn();
    let stored_network = queries::load_round_network(&conn, round_id, &wallet_id)?;
    validate_wallet_network(stored_network, wallet_db)
}

#[cfg(not(target_arch = "wasm32"))]
fn validate_wallet_network<C, P, CL, R>(
    stored_network: Network,
    wallet_db: &WalletDb<C, P, CL, R>,
) -> Result<(), VotingError>
where
    P: Parameters,
{
    let wallet_network = wallet_db.params().network_type();
    if wallet_network != stored_network.network_type() {
        return Err(VotingError::InvalidInput {
            message: format!(
                "wallet DB network {:?} does not match stored round network {:?}",
                wallet_network, stored_network
            ),
        });
    }

    Ok(())
}

/// Ensure the cached wallet frontier is exactly the round snapshot anchor.
///
/// A Merkle path can be internally valid against the wrong frontier, so callers
/// must bind both the checkpoint height and protocol root to the persisted round.
fn validate_cached_tree_state_for_round(
    tree_state: &TreeState,
    commitment_root: &[u8],
    params: &VotingRoundParams,
    voting_protocol: VotingShieldedProtocol,
) -> Result<(), VotingError> {
    // Reject stale or future frontiers before asking the wallet DB for paths at
    // the round snapshot height.
    if tree_state.height != params.snapshot_height {
        return Err(VotingError::InvalidInput {
            message: format!(
                "cached TreeState height {} does not match round snapshot_height {}",
                tree_state.height, params.snapshot_height
            ),
        });
    }

    // The height check alone is not enough: the frontier root must match the
    // note-commitment root committed by the voting round parameters.
    if commitment_root != params.nc_root.as_slice() {
        return Err(VotingError::InvalidInput {
            message: format!(
                "cached TreeState {} root does not match round nc_root",
                voting_protocol.pool()
            ),
        });
    }

    Ok(())
}

/// Verify a Merkle witness by recomputing the root from leaf + auth path.
///
/// Returns true if the computed root matches the expected root in the witness.
/// Uses the level-aware Sinsemilla hash shared by supported shielded note trees.
pub fn verify_witness(witness: &WitnessData) -> Result<bool, VotingError> {
    if witness.position >= (1u64 << orchard::NOTE_COMMITMENT_TREE_DEPTH) {
        return Err(VotingError::InvalidInput {
            message: "witness position exceeds tree depth".into(),
        });
    }
    if witness.note_commitment.len() != 32 {
        return Err(VotingError::InvalidInput {
            message: format!(
                "note_commitment must be 32 bytes, got {}",
                witness.note_commitment.len()
            ),
        });
    }
    if witness.root.len() != 32 {
        return Err(VotingError::InvalidInput {
            message: format!("root must be 32 bytes, got {}", witness.root.len()),
        });
    }
    if witness.auth_path.len() != 32 {
        return Err(VotingError::InvalidInput {
            message: format!(
                "auth_path must have 32 levels, got {}",
                witness.auth_path.len()
            ),
        });
    }

    // Parse note commitment as MerkleHashOrchard
    let commitment_bytes: [u8; 32] = witness.note_commitment[..].try_into().unwrap();
    let mut current: MerkleHashOrchard = ct_option_to_result(
        MerkleHashOrchard::from_bytes(&commitment_bytes),
        "note_commitment",
    )?;

    // Parse expected root
    let root_bytes: [u8; 32] = witness.root[..].try_into().unwrap();
    let expected_root: MerkleHashOrchard =
        ct_option_to_result(MerkleHashOrchard::from_bytes(&root_bytes), "root")?;

    // Walk up the tree: at each level, combine with the sibling hash.
    // Position bit determines whether the current node is a left or right child.
    let mut pos = witness.position;

    for (level, sibling_bytes) in witness.auth_path.iter().enumerate() {
        if sibling_bytes.len() != 32 {
            return Err(VotingError::InvalidInput {
                message: format!(
                    "auth_path[{}] must be 32 bytes, got {}",
                    level,
                    sibling_bytes.len()
                ),
            });
        }

        let sibling_arr: [u8; 32] = sibling_bytes[..].try_into().unwrap();
        let sibling: MerkleHashOrchard = ct_option_to_result(
            MerkleHashOrchard::from_bytes(&sibling_arr),
            &format!("auth_path[{}]", level),
        )?;

        let tree_level = Level::from(level as u8);

        // If position bit is 0, current is a left child; if 1, current is a right child
        current = if pos & 1 == 0 {
            MerkleHashOrchard::combine(tree_level, &current, &sibling)
        } else {
            MerkleHashOrchard::combine(tree_level, &sibling, &current)
        };

        pos >>= 1;
    }

    Ok(current == expected_root)
}

/// Convert a subtle::CtOption to a Result, using the field name in the error.
fn ct_option_to_result(
    opt: CtOption<MerkleHashOrchard>,
    field: &str,
) -> Result<MerkleHashOrchard, VotingError> {
    Option::from(opt).ok_or_else(|| VotingError::InvalidInput {
        message: format!("{} is not a valid shielded note tree hash", field),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) use crate::backend::pasta_curves;
    use pasta_curves::group::ff::PrimeField;
    use pasta_curves::pallas;
    use voting_crypto_deps::incrementalmerkletree::frontier::{CommitmentTree, Frontier};
    use voting_crypto_deps::incrementalmerkletree::Retention;
    use voting_crypto_deps::zip32::{AccountId, Scope};
    use zcash_client_backend::data_api::WalletCommitmentTrees;
    use zcash_client_backend::proto::service::TreeState;
    use zcash_client_sqlite::util::SystemClock;
    use zcash_client_sqlite::wallet::init::WalletMigrator;
    use zcash_primitives::merkle_tree::write_commitment_tree;
    use zcash_protocol::consensus::Network;

    use crate::types::{Network as VotingNetwork, REGTEST_NU6_3_ACTIVATION_HEIGHT};

    const ROUND_ID: &str = "round1";
    const WALLET_ID: &str = "wallet1";
    const SNAPSHOT_HEIGHT: u64 = 100;

    fn merkle_hash(tag: u64) -> MerkleHashOrchard {
        let repr = pallas::Base::from(tag).to_repr();
        MerkleHashOrchard::from_bytes(&repr).expect("small field element is canonical")
    }

    fn test_frontier() -> Frontier<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>
    {
        let mut frontier = Frontier::empty();
        assert!(frontier.append(merkle_hash(7)));
        assert!(frontier.append(merkle_hash(8)));
        frontier
    }

    fn tree_state_from_frontier(
        height: u64,
        frontier: &Frontier<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
    ) -> TreeState {
        tree_state_from_frontiers(height, Some(frontier), None)
    }

    fn commitment_tree_hex(
        frontier: &Frontier<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
    ) -> String {
        let commitment_tree = CommitmentTree::from_frontier(frontier);
        let mut tree_bytes = Vec::new();
        write_commitment_tree(&commitment_tree, &mut tree_bytes)
            .expect("serialize note commitment tree state");
        hex::encode(tree_bytes)
    }

    fn tree_state_from_frontiers(
        height: u64,
        orchard_frontier: Option<
            &Frontier<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
        >,
        ironwood_frontier: Option<
            &Frontier<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
        >,
    ) -> TreeState {
        TreeState {
            network: if ironwood_frontier.is_some() {
                "regtest"
            } else {
                "test"
            }
            .to_string(),
            height,
            hash: String::new(),
            time: 0,
            sapling_tree: String::new(),
            orchard_tree: orchard_frontier
                .map(commitment_tree_hex)
                .unwrap_or_default(),
            ironwood_tree: ironwood_frontier
                .map(commitment_tree_hex)
                .unwrap_or_default(),
        }
    }

    fn round_params(
        snapshot_height: u64,
        frontier: &Frontier<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
    ) -> VotingRoundParams {
        VotingRoundParams {
            vote_round_id: ROUND_ID.to_string(),
            snapshot_height,
            ea_pk: vec![0; 32],
            nc_root: frontier.root().to_bytes().to_vec(),
            nullifier_imt_root: vec![1; 32],
        }
    }

    fn note(position: u64) -> NoteInfo {
        let ufvk = crate::backend::zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &VotingNetwork::Regtest,
            &[17; 32],
            AccountId::ZERO,
        )
        .unwrap()
        .to_unified_full_viewing_key();
        let rho =
            orchard::note::Rho::from_bytes(&pallas::Base::from(position + 1).to_repr()).unwrap();
        let rseed = (0..=255)
            .find_map(|b| orchard::note::RandomSeed::from_bytes([b; 32], &rho).into_option())
            .unwrap();
        let note = orchard::Note::from_parts(
            ufvk.orchard().unwrap().address_at(0u32, Scope::External),
            orchard::value::NoteValue::from_raw(1),
            rho,
            rseed,
            orchard::NoteVersion::V3,
        )
        .unwrap();
        NoteInfo::from_orchard_note(
            &note,
            position,
            Scope::External,
            &ufvk,
            &VotingNetwork::Regtest,
        )
        .unwrap()
    }

    fn voting_db_with_tree_state(
        network: crate::Network,
        params: &VotingRoundParams,
        tree_state: &TreeState,
    ) -> VotingDb {
        let db = VotingDb::open(":memory:").unwrap();
        db.set_wallet_id(WALLET_ID);
        db.init_round(network, params, None).unwrap();
        db.store_tree_state(ROUND_ID, &tree_state.encode_to_vec())
            .unwrap();
        db
    }

    fn seeded_wallet_db(
        snapshot_height: u64,
        later_height: u32,
        marked_positions: &[Position],
    ) -> (
        WalletDb<rusqlite::Connection, Network, SystemClock, voting_crypto_deps::rand::rngs::OsRng>,
        Frontier<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
    ) {
        let max_position = marked_positions
            .iter()
            .map(|position| u64::from(*position))
            .max()
            .unwrap_or(2);
        let leaf_count = max_position + 3;
        let leaves = (1u64..=leaf_count).map(merkle_hash).collect::<Vec<_>>();
        let mut frontier = Frontier::empty();
        let mut wallet_db = WalletDb::from_connection(
            rusqlite::Connection::open_in_memory().unwrap(),
            Network::TestNetwork,
            SystemClock,
            voting_crypto_deps::rand::rngs::OsRng,
        );

        WalletMigrator::new()
            .init_or_migrate(&mut wallet_db)
            .expect("initialize wallet db");
        wallet_db
            .with_orchard_tree_mut(|tree| {
                for (i, leaf) in leaves.iter().enumerate() {
                    let retention = if marked_positions
                        .iter()
                        .any(|position| u64::from(*position) == i as u64)
                    {
                        Retention::Marked
                    } else {
                        Retention::Ephemeral
                    };
                    tree.append(*leaf, retention)?;
                    frontier.append(*leaf);
                }
                tree.checkpoint(BlockHeight::from_u32(snapshot_height as u32))?;

                for tag in (leaf_count + 1)..=(leaf_count + 5) {
                    tree.append(merkle_hash(tag), Retention::Ephemeral)?;
                }
                tree.checkpoint(BlockHeight::from_u32(later_height))?;

                Ok::<(), zcash_client_sqlite::error::SqliteClientError>(())
            })
            .expect("seed wallet Orchard tree");

        (wallet_db, frontier)
    }

    fn seeded_ironwood_wallet_db(
        snapshot_height: u64,
        later_height: u32,
        marked_positions: &[Position],
    ) -> (
        WalletDb<
            rusqlite::Connection,
            VotingNetwork,
            SystemClock,
            voting_crypto_deps::rand::rngs::OsRng,
        >,
        Frontier<MerkleHashOrchard, { orchard::NOTE_COMMITMENT_TREE_DEPTH as u8 }>,
    ) {
        let max_position = marked_positions
            .iter()
            .map(|position| u64::from(*position))
            .max()
            .unwrap_or(2);
        let leaf_count = max_position + 3;
        let leaves = (0..leaf_count)
            .map(|position| {
                MerkleHashOrchard::from_bytes(&note(position).commitment.try_into().unwrap())
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut frontier = Frontier::empty();
        let mut wallet_db = WalletDb::from_connection(
            rusqlite::Connection::open_in_memory().unwrap(),
            VotingNetwork::Regtest,
            SystemClock,
            voting_crypto_deps::rand::rngs::OsRng,
        );

        WalletMigrator::new()
            .init_or_migrate(&mut wallet_db)
            .expect("initialize wallet db");
        wallet_db
            .with_ironwood_tree_mut(|tree| {
                for (i, leaf) in leaves.iter().enumerate() {
                    let retention = if marked_positions
                        .iter()
                        .any(|position| u64::from(*position) == i as u64)
                    {
                        Retention::Marked
                    } else {
                        Retention::Ephemeral
                    };
                    tree.append(*leaf, retention)?;
                    frontier.append(*leaf);
                }
                tree.checkpoint(BlockHeight::from_u32(snapshot_height as u32))?;

                for tag in (leaf_count + 1)..=(leaf_count + 5) {
                    tree.append(merkle_hash(tag), Retention::Ephemeral)?;
                }
                tree.checkpoint(BlockHeight::from_u32(later_height))?;

                Ok::<(), zcash_client_sqlite::error::SqliteClientError>(())
            })
            .expect("seed wallet Ironwood tree");

        (wallet_db, frontier)
    }

    #[test]
    fn store_tree_state_and_generate_note_witnesses_caches_bundle_witnesses() {
        let positions = vec![Position::from(1), Position::from(2)];
        let notes = positions
            .iter()
            .map(|position| note(u64::from(*position)))
            .collect::<Vec<_>>();
        let (wallet_db, frontier) = seeded_ironwood_wallet_db(SNAPSHOT_HEIGHT, 200, &positions);
        let params = round_params(SNAPSHOT_HEIGHT, &frontier);
        let tree_state = tree_state_from_frontiers(SNAPSHOT_HEIGHT, None, Some(&frontier));
        let db = VotingDb::open(":memory:").unwrap();
        db.set_wallet_id(WALLET_ID);
        db.init_round(crate::Network::Regtest, &params, None)
            .unwrap();
        queries::insert_bundle(
            &db.conn(),
            ROUND_ID,
            WALLET_ID,
            0,
            &positions
                .iter()
                .map(|position| u64::from(*position))
                .collect::<Vec<_>>(),
        )
        .expect("insert bundle");

        let witnesses = store_tree_state_and_generate_note_witnesses(
            &db,
            ROUND_ID,
            0,
            &tree_state.encode_to_vec(),
            &notes,
            &wallet_db,
        )
        .expect("store tree state and witnesses");
        let stored = queries::load_witnesses(&db.conn(), ROUND_ID, WALLET_ID, 0)
            .expect("load stored witnesses");

        assert_eq!(witnesses.len(), notes.len());
        assert_eq!(stored.len(), witnesses.len());
        for (stored_witness, witness) in stored.iter().zip(witnesses.iter()) {
            assert_eq!(stored_witness.note_commitment, witness.note_commitment);
            assert_eq!(stored_witness.position, witness.position);
            assert_eq!(stored_witness.root, witness.root);
            assert_eq!(stored_witness.auth_path, witness.auth_path);
            assert!(verify_witness(witness).expect("stored witness is parseable"));
        }
        let parts_db = VotingDb::open_in_memory().unwrap();
        parts_db.set_wallet_id(WALLET_ID);
        parts_db
            .init_round(crate::Network::Regtest, &params, None)
            .unwrap();
        queries::insert_bundle(&parts_db.conn(), ROUND_ID, WALLET_ID, 0, &[1, 2]).unwrap();
        store_tree_state_and_witnesses(
            &parts_db,
            ROUND_ID,
            0,
            &tree_state.encode_to_vec(),
            &notes,
            &witnesses,
        )
        .unwrap();
        let from_parts = queries::load_witnesses(&parts_db.conn(), ROUND_ID, WALLET_ID, 0).unwrap();
        for (native, parts) in stored.iter().zip(&from_parts) {
            assert_eq!(native.note_commitment, parts.note_commitment);
            assert_eq!(native.auth_path, parts.auth_path);
            assert_eq!(native.root, parts.root);
            assert_eq!(native.position, parts.position);
        }
        // Inject a failure after the tree UPDATE and witness DELETE. The whole
        // operation must roll back, retaining both previously committed caches.
        db.conn().execute_batch("CREATE TEMP TRIGGER fail_witness BEFORE INSERT ON witnesses BEGIN SELECT RAISE(ABORT, 'injected'); END;").unwrap();
        let mut replacement = tree_state.clone();
        replacement.time += 1;
        assert!(store_tree_state_and_witnesses(
            &db,
            ROUND_ID,
            0,
            &replacement.encode_to_vec(),
            &notes,
            &witnesses
        )
        .is_err());
        assert_eq!(
            queries::load_tree_state(&db.conn(), ROUND_ID, WALLET_ID).unwrap(),
            tree_state.encode_to_vec()
        );
        let retained = queries::load_witnesses(&db.conn(), ROUND_ID, WALLET_ID, 0).unwrap();
        assert_eq!(retained.len(), stored.len());
        assert_eq!(retained[0].auth_path, stored[0].auth_path);
    }

    #[test]
    fn store_tree_state_and_generate_note_witnesses_rejects_invalid_tree_state() {
        let positions = vec![Position::from(1)];
        let notes = positions
            .iter()
            .map(|position| note(u64::from(*position)))
            .collect::<Vec<_>>();
        let (wallet_db, frontier) = seeded_ironwood_wallet_db(SNAPSHOT_HEIGHT, 200, &positions);
        let params = round_params(SNAPSHOT_HEIGHT, &frontier);
        let db = VotingDb::open(":memory:").unwrap();
        db.set_wallet_id(WALLET_ID);
        db.init_round(crate::Network::Regtest, &params, None)
            .unwrap();
        queries::insert_bundle(&db.conn(), ROUND_ID, WALLET_ID, 0, &[1]).expect("insert bundle");
        let invalid_tree_state = TreeState {
            network: "test".to_string(),
            height: SNAPSHOT_HEIGHT,
            hash: String::new(),
            time: 0,
            sapling_tree: String::new(),
            orchard_tree: String::new(),
            ironwood_tree: String::new(),
        };

        let err = store_tree_state_and_generate_note_witnesses(
            &db,
            ROUND_ID,
            0,
            &invalid_tree_state.encode_to_vec(),
            &notes,
            &wallet_db,
        )
        .unwrap_err();

        assert!(err.to_string().contains("orchard") || err.to_string().contains("TreeState"));
    }

    #[test]
    fn generate_note_witnesses_returns_valid_witnesses() {
        let positions = vec![Position::from(1), Position::from(2)];
        let notes = positions
            .iter()
            .map(|position| note(u64::from(*position)))
            .collect::<Vec<_>>();
        let (wallet_db, frontier) = seeded_ironwood_wallet_db(SNAPSHOT_HEIGHT, 200, &positions);
        let params = round_params(SNAPSHOT_HEIGHT, &frontier);
        let tree_state = tree_state_from_frontiers(SNAPSHOT_HEIGHT, None, Some(&frontier));
        let voting_db = voting_db_with_tree_state(crate::Network::Regtest, &params, &tree_state);

        let witnesses = generate_note_witnesses(&voting_db, ROUND_ID, &notes, &wallet_db)
            .expect("generate witnesses");

        assert_eq!(witnesses.len(), notes.len());
        for (witness, note) in witnesses.iter().zip(notes.iter()) {
            assert_eq!(witness.note_commitment, note.commitment);
            assert_eq!(witness.position, note.position);
            assert_eq!(witness.root, params.nc_root);
            assert_eq!(witness.auth_path.len(), orchard::NOTE_COMMITMENT_TREE_DEPTH);
            assert!(verify_witness(witness).expect("witness is parseable"));
        }
    }

    #[test]
    fn generate_note_witnesses_rejects_wallet_network_mismatch() {
        let positions = vec![Position::from(1)];
        let notes = positions
            .iter()
            .map(|position| note(u64::from(*position)))
            .collect::<Vec<_>>();
        let (_wallet_db, frontier) = seeded_wallet_db(SNAPSHOT_HEIGHT, 200, &positions);
        let params = round_params(SNAPSHOT_HEIGHT, &frontier);
        let tree_state = tree_state_from_frontier(SNAPSHOT_HEIGHT, &frontier);
        let voting_db = voting_db_with_tree_state(crate::Network::Testnet, &params, &tree_state);
        let wrong_network_wallet_db = WalletDb::from_connection(
            rusqlite::Connection::open_in_memory().unwrap(),
            Network::MainNetwork,
            SystemClock,
            voting_crypto_deps::rand::rngs::OsRng,
        );

        let err = generate_note_witnesses(&voting_db, ROUND_ID, &notes, &wrong_network_wallet_db)
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("wallet DB network Main does not match stored round network Testnet"),
            "{err}"
        );
    }

    #[test]
    fn store_tree_state_and_generate_note_witnesses_rejects_wallet_network_mismatch_without_caching(
    ) {
        let positions = vec![Position::from(1)];
        let notes = positions
            .iter()
            .map(|position| note(u64::from(*position)))
            .collect::<Vec<_>>();
        let (_wallet_db, frontier) = seeded_wallet_db(SNAPSHOT_HEIGHT, 200, &positions);
        let params = round_params(SNAPSHOT_HEIGHT, &frontier);
        let tree_state = tree_state_from_frontier(SNAPSHOT_HEIGHT, &frontier);
        let voting_db = VotingDb::open(":memory:").unwrap();
        voting_db.set_wallet_id(WALLET_ID);
        voting_db
            .init_round(crate::Network::Testnet, &params, None)
            .unwrap();
        queries::insert_bundle(&voting_db.conn(), ROUND_ID, WALLET_ID, 0, &[1])
            .expect("insert bundle");
        let wrong_network_wallet_db = WalletDb::from_connection(
            rusqlite::Connection::open_in_memory().unwrap(),
            Network::MainNetwork,
            SystemClock,
            voting_crypto_deps::rand::rngs::OsRng,
        );

        let err = store_tree_state_and_generate_note_witnesses(
            &voting_db,
            ROUND_ID,
            0,
            &tree_state.encode_to_vec(),
            &notes,
            &wrong_network_wallet_db,
        )
        .unwrap_err();

        assert!(
            err.to_string()
                .contains("wallet DB network Main does not match stored round network Testnet"),
            "{err}"
        );
        let conn = voting_db.conn();
        assert!(queries::load_tree_state(&conn, ROUND_ID, WALLET_ID).is_err());
        assert!(queries::load_witnesses(&conn, ROUND_ID, WALLET_ID, 0)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn generate_note_witnesses_uses_ironwood_tree_at_nu6_3() {
        let snapshot_height = u64::from(REGTEST_NU6_3_ACTIVATION_HEIGHT);
        let positions = vec![Position::from(1), Position::from(2)];
        let notes = positions
            .iter()
            .map(|position| note(u64::from(*position)))
            .collect::<Vec<_>>();
        let (wallet_db, ironwood_frontier) = seeded_ironwood_wallet_db(
            snapshot_height,
            REGTEST_NU6_3_ACTIVATION_HEIGHT + 100,
            &positions,
        );
        let orchard_frontier = test_frontier();
        let params = round_params(snapshot_height, &ironwood_frontier);
        let tree_state = tree_state_from_frontiers(
            snapshot_height,
            Some(&orchard_frontier),
            Some(&ironwood_frontier),
        );
        let voting_db = voting_db_with_tree_state(crate::Network::Regtest, &params, &tree_state);

        let witnesses = generate_note_witnesses(&voting_db, ROUND_ID, &notes, &wallet_db)
            .expect("generate Ironwood witnesses");

        assert_eq!(witnesses.len(), notes.len());
        for (witness, note) in witnesses.iter().zip(notes.iter()) {
            assert_eq!(witness.note_commitment, note.commitment);
            assert_eq!(witness.position, note.position);
            assert_eq!(witness.root, params.nc_root);
            assert!(verify_witness(witness).expect("Ironwood witness is parseable"));
        }
    }

    #[test]
    fn generate_note_witnesses_rejects_stale_tree_state() {
        let frontier = test_frontier();
        let params = round_params(SNAPSHOT_HEIGHT, &frontier);
        let stale_tree_state = tree_state_from_frontier(SNAPSHOT_HEIGHT - 1, &frontier);

        let err = validate_cached_tree_state_for_round(
            &stale_tree_state,
            &params.nc_root,
            &params,
            VotingShieldedProtocol::Ironwood,
        )
        .unwrap_err();

        assert!(err.to_string().contains("snapshot_height"));
    }

    #[test]
    fn generate_note_witnesses_rejects_wrong_round_root() {
        let frontier = test_frontier();
        let mut params = round_params(SNAPSHOT_HEIGHT, &frontier);
        params.nc_root = vec![9; 32];
        let tree_state = tree_state_from_frontier(SNAPSHOT_HEIGHT, &frontier);

        let err = validate_cached_tree_state_for_round(
            &tree_state,
            &frontier.root().to_bytes(),
            &params,
            VotingShieldedProtocol::Ironwood,
        )
        .unwrap_err();

        assert!(err.to_string().contains("ironwood root"));
    }

    #[test]
    fn generate_note_witnesses_rejects_wrong_ironwood_round_root() {
        let frontier = test_frontier();
        let mut params = round_params(u64::from(REGTEST_NU6_3_ACTIVATION_HEIGHT), &frontier);
        params.nc_root = vec![9; 32];
        let tree_state =
            tree_state_from_frontier(u64::from(REGTEST_NU6_3_ACTIVATION_HEIGHT), &frontier);

        let err = validate_cached_tree_state_for_round(
            &tree_state,
            &frontier.root().to_bytes(),
            &params,
            VotingShieldedProtocol::Ironwood,
        )
        .unwrap_err();

        assert!(err.to_string().contains("ironwood root"));
    }

    #[test]
    fn generate_note_witnesses_rejects_snapshot_height_overflow() {
        let frontier = test_frontier();
        let params = round_params(u64::from(u32::MAX) + 1, &frontier);
        let tree_state = tree_state_from_frontier(u64::from(u32::MAX) + 1, &frontier);
        let voting_db = VotingDb::open(":memory:").unwrap();
        voting_db.set_wallet_id(WALLET_ID);
        voting_db
            .init_round(crate::Network::Testnet, &params, None)
            .unwrap();
        voting_db
            .store_tree_state(ROUND_ID, &tree_state.encode_to_vec())
            .unwrap();
        let wallet_db = WalletDb::from_connection(
            rusqlite::Connection::open_in_memory().unwrap(),
            Network::TestNetwork,
            SystemClock,
            voting_crypto_deps::rand::rngs::OsRng,
        );

        let err =
            generate_note_witnesses(&voting_db, ROUND_ID, &[note(3)], &wallet_db).unwrap_err();

        assert!(err.to_string().contains("does not fit in u32"));
    }

    #[test]
    fn test_verify_witness_validation() {
        // Bad commitment length
        let bad = WitnessData {
            note_commitment: vec![0; 16],
            position: 0,
            root: vec![0; 32],
            auth_path: (0..32).map(|_| vec![0u8; 32]).collect(),
        };
        assert!(verify_witness(&bad).is_err());

        // Bad auth path length
        let bad = WitnessData {
            note_commitment: vec![0; 32],
            position: 0,
            root: vec![0; 32],
            auth_path: (0..16).map(|_| vec![0u8; 32]).collect(),
        };
        assert!(verify_witness(&bad).is_err());
    }

    #[test]
    fn test_verify_witness_rejects_wrong_root() {
        // Create a witness with a valid commitment at position 0 but wrong root.
        // The empty tree hash (all zeros) as commitment with zero auth path
        // produces a specific root — giving a different root should fail verification.
        let witness = WitnessData {
            note_commitment: vec![0; 32],
            position: 0,
            root: vec![0xFF; 32], // wrong root
            auth_path: (0..32).map(|_| vec![0u8; 32]).collect(),
        };
        // Should verify without error but return false (roots don't match)
        // unless 0xFF... isn't a valid field element (would be an error)
        let result = verify_witness(&witness);
        // Either returns Ok(false) or Err (if 0xFF... isn't valid)
        match result {
            Ok(valid) => assert!(!valid),
            Err(_) => {} // 0xFF..FF may not be a valid Pallas base element
        }
    }
}
