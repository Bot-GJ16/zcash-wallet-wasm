//! Synthetic signatures and placeholder proof bytes for orchestration tests only.
use zcash_voting::backend::zcash_protocol::consensus::{NetworkUpgrade, Parameters};
use zcash_voting::{
    backend::{orchard, pczt, zcash_keys},
    delegate,
    delegation_submission::CanonicalDelegation,
    storage::VotingDb,
};

use zcash_voting::{Network, NoteInfo, VotingRoundParams};

pub fn height() -> u64 {
    height_for(Network::Testnet)
}

pub fn height_for(network: Network) -> u64 {
    u64::from(u32::from(
        network.activation_height(NetworkUpgrade::Nu6_3).unwrap(),
    ))
}

pub fn prepare(db: &VotingDb, params: &VotingRoundParams, seed: u8) -> CanonicalDelegation {
    assert_eq!(stored_network(db, params), Network::Testnet);
    prepare_for_stored_network(db, params, seed)
}

pub fn prepare_for_stored_network(
    db: &VotingDb,
    params: &VotingRoundParams,
    seed: u8,
) -> CanonicalDelegation {
    prepare_bundles_for_stored_network(db, params, seed, 1).remove(0)
}

pub fn prepare_bundles(
    db: &VotingDb,
    params: &VotingRoundParams,
    seed: u8,
    count: u8,
) -> Vec<CanonicalDelegation> {
    assert_eq!(stored_network(db, params), Network::Testnet);
    prepare_bundles_for_stored_network(db, params, seed, count)
}

pub fn prepare_bundles_for_stored_network(
    db: &VotingDb,
    params: &VotingRoundParams,
    seed: u8,
    count: u8,
) -> Vec<CanonicalDelegation> {
    prepare_selected_bundles(db, params, seed, count, None)
}

pub fn complete_bundle(
    db: &VotingDb,
    params: &VotingRoundParams,
    seed: u8,
    count: u8,
    bundle: u32,
    canonical: &CanonicalDelegation,
) -> CanonicalDelegation {
    assert_eq!(stored_network(db, params), Network::Testnet);
    complete_bundle_for_stored_network(db, params, seed, count, bundle, canonical)
}

pub fn complete_bundle_for_stored_network(
    db: &VotingDb,
    params: &VotingRoundParams,
    seed: u8,
    count: u8,
    bundle: u32,
    canonical: &CanonicalDelegation,
) -> CanonicalDelegation {
    if db.delegation_phase(&params.vote_round_id, bundle).unwrap()
        == zcash_voting::phases::DelegationPhase::Prepared
    {
        return prepare_selected_bundles(db, params, seed, count, Some(bundle)).remove(0);
    }
    if db.delegation_phase(&params.vote_round_id, bundle).unwrap()
        == zcash_voting::phases::DelegationPhase::Proved
    {
        return canonical.clone();
    }
    use base64::Engine as _;
    let wire: zcash_voting::wire::DelegationSubmissionWire =
        serde_json::from_slice(canonical.json_bytes()).unwrap();
    let decode = |value: &str| {
        base64::engine::general_purpose::STANDARD
            .decode(value)
            .unwrap()
    };
    db.store_delegation_proof(
        &params.vote_round_id,
        bundle,
        &zcash_voting::DelegationProofResult {
            proof: decode(&wire.proof),
            public_inputs: vec![],
            nf_signed: decode(&wire.nf_signed),
            cmx_new: decode(&wire.cmx_new),
            gov_nullifiers: wire.gov_nullifiers.iter().map(|v| decode(v)).collect(),
            van_comm: decode(&wire.gov_comm),
            rk: decode(&wire.rk),
        },
    )
    .unwrap();
    canonical.clone()
}

pub fn notes(seed: u8, count: u8) -> Vec<NoteInfo> {
    notes_for(Network::Testnet, seed, count)
}

pub fn notes_for(network: Network, seed: u8, count: u8) -> Vec<NoteInfo> {
    let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
        &network,
        &[seed; 32],
        zip32::AccountId::ZERO,
    )
    .unwrap();
    let ufvk = usk.to_unified_full_viewing_key();
    let fvk = ufvk.orchard().unwrap();
    (0..count)
        .map(|index| {
            let rho = orchard::note::Rho::from_bytes(&[index + 1; 32]).unwrap();
            let rseed = (0..=255)
                .find_map(|b| orchard::note::RandomSeed::from_bytes([b; 32], &rho).into_option())
                .unwrap();
            let note = orchard::Note::from_parts(
                fvk.address_at(0u32, zip32::Scope::External),
                orchard::value::NoteValue::from_raw(100_000_000),
                rho,
                rseed,
                orchard::NoteVersion::V3,
            )
            .unwrap();
            NoteInfo::from_orchard_note(
                &note,
                u64::from(index),
                zip32::Scope::External,
                &ufvk,
                &network,
            )
            .unwrap()
        })
        .collect::<Vec<_>>()
}

fn prepare_selected_bundles(
    db: &VotingDb,
    params: &VotingRoundParams,
    seed: u8,
    count: u8,
    selected: Option<u32>,
) -> Vec<CanonicalDelegation> {
    let network = stored_network(db, params);
    let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
        &network,
        &[seed; 32],
        zip32::AccountId::ZERO,
    )
    .unwrap();
    let fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&[seed; 32]).unwrap();
    let ufvk = usk.to_unified_full_viewing_key();
    let fvk = ufvk.orchard().unwrap();
    let notes = notes_for(network, seed, count);
    let id = &params.vote_round_id;
    db.ensure_bundles_with_policy(id, &notes, zcash_voting::BundlePolicy::new(1).unwrap())
        .unwrap();
    let hotkey = db.ensure_voting_hotkey(id).unwrap();
    let keys = delegate::DelegationKeys::with_voting_hotkey(
        fvk.to_bytes().to_vec(),
        &hotkey,
        fingerprint.to_bytes(),
        0,
        "fixture".into(),
    )
    .unwrap();
    notes
        .into_iter()
        .enumerate()
        .filter(|(index, _)| selected.is_none_or(|bundle| *index as u32 == bundle))
        .map(|(index, note)| {
            let index = index as u32;
            let setup = db
                .build_governance_pczt(
                    id,
                    index,
                    &[note],
                    &keys,
                    delegate::branch_id_for_height(network, params.snapshot_height).unwrap(),
                )
                .unwrap();
            let mut signer =
                pczt::roles::signer::Signer::new(pczt::Pczt::parse(&setup.pczt_bytes).unwrap())
                    .unwrap();
            signer
                .sign_ironwood(
                    zcash_voting::backend::rand10::rand_core::UnwrapErr(
                        zcash_voting::backend::rand10::rngs::SysRng,
                    ),
                    setup.action_index,
                    &orchard::keys::SpendAuthorizingKey::from(usk.orchard()),
                )
                .unwrap();
            let signature = delegate::spend_auth_signature(
                &signer.finish().serialize().unwrap(),
                setup.action_index,
            )
            .unwrap();
            db.store_delegation_proof(
                id,
                index,
                &zcash_voting::DelegationProofResult {
                    proof: vec![1],
                    public_inputs: vec![],
                    nf_signed: setup.nf_signed,
                    cmx_new: setup.cmx_new,
                    gov_nullifiers: setup.gov_nullifiers,
                    van_comm: setup.van,
                    rk: setup.rk,
                },
            )
            .unwrap();
            let submission = delegate::submission(
                db,
                id,
                index,
                delegate::DelegationSigner::signature(
                    signature,
                    setup.pczt_sighash.try_into().unwrap(),
                ),
            )
            .unwrap();
            CanonicalDelegation::from_submission(&submission).unwrap()
        })
        .collect()
}

fn stored_network(db: &VotingDb, params: &VotingRoundParams) -> Network {
    let (stored_params, network) = db.round_params_with_network(&params.vote_round_id).unwrap();
    assert_eq!(&stored_params, params);
    network
}

pub fn event(round: &str, position: &str) -> zcash_voting::confirmation::TxEvent {
    use zcash_voting::confirmation::{TxEvent, TxEventAttribute};
    TxEvent {
        event_type: "delegate_vote".into(),
        attributes: vec![
            TxEventAttribute {
                key: "vote_round_id".into(),
                value: round.into(),
            },
            TxEventAttribute {
                key: "leaf_index".into(),
                value: position.into(),
            },
        ],
    }
}

pub fn corrupt(bytes: &[u8], sql: &str) -> Vec<u8> {
    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    conn.deserialize_read_exact(
        rusqlite::MAIN_DB,
        std::io::Cursor::new(bytes),
        bytes.len(),
        false,
    )
    .unwrap();
    conn.execute_batch(sql).unwrap();
    conn.serialize(rusqlite::MAIN_DB).unwrap().to_vec()
}

pub fn confirmed_corruptions() -> Vec<&'static str> {
    vec![
        "UPDATE bundles SET van_leaf_position=16777216 WHERE bundle_index=1; UPDATE delegation_attempts SET confirmation_van_position=16777216 WHERE bundle_index=1",
        "UPDATE bundles SET van_leaf_position=4294967295 WHERE bundle_index=1; UPDATE delegation_attempts SET confirmation_van_position=4294967295 WHERE bundle_index=1",
        "UPDATE proofs SET proof=x'02' WHERE bundle_index=1",
        "DELETE FROM proofs WHERE bundle_index=1",
        "UPDATE bundles SET pczt_sighash=zeroblob(32) WHERE bundle_index=1",
        "UPDATE delegation_attempts SET canonical_json=x'00' WHERE bundle_index=1",
        "UPDATE delegation_attempts SET tx_hash='wrong' WHERE bundle_index=1",
        "UPDATE delegation_attempts SET outcome='rejected' WHERE bundle_index=1",
        "UPDATE delegation_attempts SET outcome='prepared' WHERE bundle_index=1",
        "UPDATE delegation_attempts SET outcome='ambiguous' WHERE bundle_index=1",
        "UPDATE delegation_attempts SET outcome='dispatching' WHERE bundle_index=1",
        "DELETE FROM delegation_attempts WHERE bundle_index=1",
        "PRAGMA foreign_keys=OFF; DELETE FROM bundles WHERE bundle_index=1",
        "UPDATE bundles SET delegation_tx_hash=NULL WHERE bundle_index=1",
        "UPDATE bundles SET delegation_tx_hash='wrong' WHERE bundle_index=1",
        "UPDATE bundles SET van_leaf_position=43 WHERE bundle_index=1",
        "UPDATE bundles SET van_leaf_position=NULL WHERE bundle_index=1",
        "UPDATE delegation_attempts SET confirmation_tx_hash='wrong' WHERE bundle_index=1",
        "UPDATE delegation_attempts SET confirmation_van_position=43 WHERE bundle_index=1",
        "UPDATE delegation_attempts SET confirmation_tx_hash=NULL,confirmation_van_position=NULL WHERE bundle_index=1",
    ]
}
