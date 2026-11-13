//! Private boundary between the shared wallet and owned voting inputs.
#![allow(dead_code)]

use prost::Message;
use tonic_web_wasm_client::Client;
use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_client_backend::proto::service::TreeState;
use zcash_client_memory::{MemoryWalletDb, voting::VotingSnapshotNote};
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_voting::{Network, NoteInfo, VotingError, VotingHotkey, WitnessData};

use crate::bindgen::wallet::{AccountId, MemoryWallet};

pub(crate) struct BrowserWalletInputs {
    pub delegation: zcash_voting::selection::DelegationWalletInputs,
    pub witnesses: Vec<WitnessData>,
}

pub(crate) struct EligibilityWalletInputs {
    pub scanned_height: u64,
    pub notes: Vec<NoteInfo>,
}

pub(crate) struct WalletInputRequest<'a> {
    pub network: Network,
    pub snapshot_height: u64,
    pub anchor_tree_state_bytes: Vec<u8>,
    pub resolved_round_name: String,
    pub hotkey: &'a VotingHotkey,
}

#[derive(Debug)]
pub(crate) enum WalletInputError {
    AccountUnknown,
    NetworkMismatch,
    WalletNotSynced { scanned: u64, snapshot: u64 },
    Wallet(String),
    Voting(VotingError),
}

impl From<VotingError> for WalletInputError {
    fn from(error: VotingError) -> Self {
        Self::Voting(error)
    }
}

fn validate_locked(
    db: &MemoryWalletDb<crate::Network>,
    wallet_network: crate::Network,
    account_id: AccountId,
    network: Network,
    snapshot_height: u64,
) -> Result<BlockHeight, WalletInputError> {
    if !matches!(network, Network::Testnet | Network::Mainnet)
        || db.params().network_type() != network.network_type()
        || wallet_network.network_type() != network.network_type()
    {
        return Err(WalletInputError::NetworkMismatch);
    }
    let height = u32::try_from(snapshot_height)
        .map(BlockHeight::from_u32)
        .map_err(|_| WalletInputError::Wallet("snapshot height exceeds supported range".into()))?;
    let account = db
        .get_account(account_id)
        .map_err(|_| WalletInputError::Wallet("could not read voting account".into()))?
        .ok_or(WalletInputError::AccountUnknown)?;
    if account.source().key_derivation().is_none() || account.ufvk().and_then(|key| key.orchard()).is_none() {
        return Err(WalletInputError::Wallet("voting account derivation or viewing key is unavailable".into()));
    }
    let scanned = db
        .block_fully_scanned()
        .map_err(|_| WalletInputError::Wallet("could not read wallet scan height".into()))?
        .map(|b| u64::from(u32::from(b.block_height())))
        .unwrap_or(0);
    if scanned < snapshot_height {
        return Err(WalletInputError::WalletNotSynced {
            scanned,
            snapshot: snapshot_height,
        });
    }
    Ok(height)
}

fn convert_notes(notes: &[VotingSnapshotNote], network: Network) -> Result<Vec<NoteInfo>, WalletInputError> {
    notes
        .iter()
        .map(|note| NoteInfo::from_orchard_note(&note.note, note.position, note.scope, &note.ufvk, &network).map_err(WalletInputError::Voting))
        .collect()
}

pub(crate) async fn gather_eligibility_inputs(
    wallet: &MemoryWallet<Client>,
    account_id: AccountId,
    network: Network,
    snapshot_height: u64,
) -> Result<EligibilityWalletInputs, WalletInputError> {
    let snapshot = {
        let db = wallet.db.read().await;
        let height = validate_locked(&db, wallet.network, account_id, network, snapshot_height)?;
        db.voting_snapshot_notes(account_id, height)
            .map_err(|_| WalletInputError::Wallet("could not select voting snapshot notes".into()))?
    };
    Ok(EligibilityWalletInputs {
        scanned_height: u64::from(u32::from(snapshot.fully_scanned_height)),
        notes: convert_notes(&snapshot.notes, network)?,
    })
}

pub(crate) async fn gather_wallet_inputs(
    wallet: &MemoryWallet<Client>,
    account_id: AccountId,
    request: WalletInputRequest<'_>,
) -> Result<BrowserWalletInputs, WalletInputError> {
    let state = TreeState::decode(request.anchor_tree_state_bytes.as_slice()).map_err(|_| WalletInputError::Wallet("invalid snapshot TreeState".into()))?;
    let voting_network = match request.network {
        Network::Testnet => super::network::VotingNetwork::Testnet,
        Network::Mainnet => super::network::VotingNetwork::Mainnet,
        Network::Regtest => return Err(WalletInputError::NetworkMismatch),
    };
    if state.network != voting_network.tree_state_network() || request.hotkey.network() != request.network {
        return Err(WalletInputError::NetworkMismatch);
    }
    if state.height != request.snapshot_height {
        return Err(WalletInputError::Wallet("TreeState height does not match snapshot".into()));
    }
    let frontier = state
        .ironwood_tree()
        .map_err(|_| WalletInputError::Wallet("invalid Ironwood snapshot frontier".into()))?
        .to_frontier()
        .take()
        .ok_or_else(|| WalletInputError::Wallet("missing Ironwood snapshot frontier".into()))?;
    let (snapshot, account_fvk) = {
        let db = wallet.db.read().await;
        let height = validate_locked(&db, wallet.network, account_id, request.network, request.snapshot_height)?;
        let account = db
            .get_account(account_id)
            .map_err(|_| WalletInputError::Wallet("could not read voting account".into()))?
            .ok_or(WalletInputError::AccountUnknown)?;
        let fvk = account
            .ufvk()
            .and_then(|key| key.orchard())
            .ok_or_else(|| WalletInputError::Wallet("missing voting viewing key".into()))?
            .to_bytes();
        let snapshot = db
            .voting_snapshot(account_id, height, frontier)
            .map_err(|_| WalletInputError::Wallet("could not validate historical voting witnesses".into()))?;
        (snapshot, fvk)
    };
    let notes = convert_notes(&snapshot.notes, request.network)?;
    let witnesses = notes
        .iter()
        .zip(snapshot.auth_paths)
        .map(|(note, path)| WitnessData {
            position: note.position,
            note_commitment: note.commitment.clone(),
            root: snapshot.root.to_vec(),
            auth_path: path.into_iter().map(|node| node.to_vec()).collect(),
        })
        .collect();
    let delegation = zcash_voting::gather_delegation_wallet_inputs_from_parts(zcash_voting::GatherDelegationWalletInputs {
        network: request.network,
        scanned_height: u64::from(u32::from(snapshot.fully_scanned_height)),
        snapshot_height: request.snapshot_height,
        anchor_tree_state_bytes: request.anchor_tree_state_bytes,
        round_note_infos: notes,
        account_keys: zcash_voting::delegate::DelegationAccountKeys {
            account_index: snapshot.account_index.into(),
            seed_fingerprint: snapshot.seed_fingerprint.to_bytes(),
            orchard_fvk_bytes: account_fvk,
        },
        voting_hotkey: request.hotkey,
        resolved_round_name: request.resolved_round_name,
    })?;
    Ok(BrowserWalletInputs { delegation, witnesses })
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_client_backend::data_api::{AccountBirthday, AccountPurpose, WalletWrite, Zip32Derivation};
    use zcash_primitives::block::BlockHash;

    fn tree_state(network: &str, height: u64) -> TreeState {
        // Legacy CommitmentTree encoding: present left leaf, absent right leaf, no parents.
        let mut tree_bytes = vec![1];
        tree_bytes.extend_from_slice(&[42; 32]);
        tree_bytes.extend_from_slice(&[0, 0]);
        TreeState {
            network: network.into(),
            height,
            hash: hex::encode([0; 32]),
            ironwood_tree: hex::encode(tree_bytes),
            ..TreeState::default()
        }
    }

    fn wallet(network: crate::Network, seed: u8, state: Option<&TreeState>) -> (MemoryWallet<Client>, AccountId) {
        let mut db = MemoryWalletDb::new(network, 100);
        let birthday = AccountBirthday::from_parts(
            state.map_or_else(
                || zcash_client_backend::data_api::chain::ChainState::empty(BlockHeight::from_u32(3_000_000), BlockHash([0; 32])),
                |state| state.clone().to_chain_state().unwrap(),
            ),
            None,
        );
        let ufvk = zcash_keys::keys::UnifiedSpendingKey::from_seed(&network, &[seed; 32], zip32::AccountId::ZERO)
            .unwrap()
            .to_unified_full_viewing_key();
        let derivation = Zip32Derivation::new(zip32::fingerprint::SeedFingerprint::from_seed(&[seed; 32]).unwrap(), zip32::AccountId::ZERO);
        let id = db
            .import_account_ufvk("fixture", &ufvk, &birthday, AccountPurpose::Spending { derivation: Some(derivation) }, None)
            .unwrap()
            .id();
        (crate::Wallet::new(db, Client::new("https://example.invalid".into()), network).unwrap(), id)
    }

    #[tokio::test]
    async fn mainnet_wallet_and_tree_state_pass_network_validation_without_mutation() {
        let height = 3_428_143;
        let state = tree_state("main", height);
        let (wallet, account) = wallet(crate::Network::MainNetwork, 17, Some(&state));
        let hotkey = VotingHotkey::from_stored_secret(&[0x77; 64], Network::Mainnet).unwrap();
        let before = wallet.db_to_bytes().await.unwrap();

        assert!(matches!(
            gather_eligibility_inputs(&wallet, account, Network::Mainnet, height).await,
            Err(WalletInputError::WalletNotSynced {
                scanned: 0,
                snapshot: 3_428_143
            })
        ));
        assert!(matches!(
            gather_wallet_inputs(
                &wallet,
                account,
                WalletInputRequest {
                    network: Network::Mainnet,
                    snapshot_height: height,
                    anchor_tree_state_bytes: state.encode_to_vec(),
                    resolved_round_name: "mainnet fixture".into(),
                    hotkey: &hotkey,
                },
            )
            .await,
            Err(WalletInputError::WalletNotSynced {
                scanned: 0,
                snapshot: 3_428_143
            })
        ));
        assert_eq!(before, wallet.db_to_bytes().await.unwrap());
        assert!(wallet.db.try_write().is_ok());
    }

    #[tokio::test]
    async fn wallet_inputs_reject_cross_network_tree_hotkey_and_regtest_without_mutation() {
        let height = 3_428_143;
        let state = tree_state("main", height);
        let (wallet, account) = wallet(crate::Network::MainNetwork, 17, Some(&state));
        let mainnet = VotingHotkey::from_stored_secret(&[0x77; 64], Network::Mainnet).unwrap();
        let testnet = VotingHotkey::from_stored_secret(&[0x77; 64], Network::Testnet).unwrap();
        let before = wallet.db_to_bytes().await.unwrap();

        for (network, state, hotkey) in [
            (Network::Mainnet, tree_state("test", height), &mainnet),
            (Network::Mainnet, tree_state("mainnet", height), &mainnet),
            (Network::Mainnet, tree_state("main", height), &testnet),
            (Network::Regtest, tree_state("regtest", height), &mainnet),
        ] {
            assert!(matches!(
                gather_wallet_inputs(
                    &wallet,
                    account,
                    WalletInputRequest {
                        network,
                        snapshot_height: height,
                        anchor_tree_state_bytes: state.encode_to_vec(),
                        resolved_round_name: "wrong network".into(),
                        hotkey,
                    },
                )
                .await,
                Err(WalletInputError::NetworkMismatch)
            ));
        }
        assert_eq!(before, wallet.db_to_bytes().await.unwrap());
        assert!(wallet.db.try_write().is_ok());
    }

    #[tokio::test]
    async fn eligibility_rejects_network_account_and_unscanned_wallet_without_mutation() {
        let network = crate::Network::TestNetwork;
        let db = MemoryWalletDb::new(network, 100);
        let wallet = crate::Wallet::new(db, Client::new("https://example.invalid".into()), network).unwrap();
        assert!(matches!(
            gather_eligibility_inputs(&wallet, 1.into(), Network::Mainnet, 1).await,
            Err(WalletInputError::NetworkMismatch)
        ));
        assert!(matches!(
            gather_eligibility_inputs(&wallet, 1.into(), Network::Regtest, 1).await,
            Err(WalletInputError::NetworkMismatch)
        ));
        assert!(matches!(
            gather_eligibility_inputs(&wallet, 1.into(), Network::Testnet, 1).await,
            Err(WalletInputError::AccountUnknown)
        ));
        let id = {
            let mut db = wallet.db.write().await;
            let birthday = AccountBirthday::from_parts(
                zcash_client_backend::data_api::chain::ChainState::empty(BlockHeight::from_u32(3_000_000), BlockHash([0; 32])),
                None,
            );
            let ufvk = zcash_keys::keys::UnifiedSpendingKey::from_seed(&network, &[17; 32], zip32::AccountId::ZERO)
                .unwrap()
                .to_unified_full_viewing_key();
            let derivation = Zip32Derivation::new(zip32::fingerprint::SeedFingerprint::from_seed(&[17; 32]).unwrap(), zip32::AccountId::ZERO);
            db.import_account_ufvk("fixture", &ufvk, &birthday, AccountPurpose::Spending { derivation: Some(derivation) }, None)
                .unwrap()
                .id()
        };
        let before = wallet.db_to_bytes().await.unwrap();
        assert!(matches!(
            gather_eligibility_inputs(&wallet, id, Network::Testnet, 4_000_000).await,
            Err(WalletInputError::WalletNotSynced { .. })
        ));
        assert_eq!(before, wallet.db_to_bytes().await.unwrap());
        assert!(wallet.db.try_write().is_ok());
    }
}
