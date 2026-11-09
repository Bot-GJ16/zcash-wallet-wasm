#![cfg(all(feature = "browser", not(target_arch = "wasm32")))]

#[path = "support/browser_helper_cases.rs"]
mod browser_helper_cases;
#[path = "support/browser_storage_cases.rs"]
mod browser_storage_cases;
#[path = "support/delegation_fixture.rs"]
mod delegation_fixture;
use zcash_voting as fixture_sdk;
#[path = "support/owned_proof_fixture.rs"]
mod owned_proof_fixture;

#[test]
fn delegation_tree_capacity_is_checked_atomically_and_after_reload() {
    use zcash_voting::{storage::VotingDb, Network, VotingRoundParams};
    let db = VotingDb::open_browser("owner", Network::Testnet, None).unwrap();
    let id = "01".repeat(32);
    let params = VotingRoundParams {
        vote_round_id: id.clone(),
        snapshot_height: delegation_fixture::height(),
        ea_pk: vec![0; 32],
        nc_root: vec![0; 32],
        nullifier_imt_root: vec![0; 32],
    };
    db.init_round(Network::Testnet, &params, None).unwrap();
    let canonical = delegation_fixture::prepare(&db, &params, 17);
    db.prepare_delegation_submission(&id, 0, &canonical)
        .unwrap();
    db.mark_delegation_dispatching(&id, 0).unwrap();
    let pending = db.serialize_bytes().unwrap();
    let limit = 1u64 << vote_commitment_tree::TREE_DEPTH;
    for position in [limit, u64::from(u32::MAX)] {
        assert!(db
            .confirm_journaled_delegation(
                &id,
                0,
                canonical.tx_hash(),
                &[delegation_fixture::event(&id, &position.to_string())]
            )
            .is_err());
        assert_eq!(db.serialize_bytes().unwrap(), pending);
    }
    db.confirm_journaled_delegation(
        &id,
        0,
        canonical.tx_hash(),
        &[delegation_fixture::event(&id, &(limit - 1).to_string())],
    )
    .unwrap();
    let confirmed = db.serialize_bytes().unwrap();
    for position in [limit, u64::from(u32::MAX)] {
        for sql in [
            format!("UPDATE bundles SET van_leaf_position={position}"),
            format!("UPDATE delegation_attempts SET confirmation_van_position={position}"),
            format!("UPDATE bundles SET van_leaf_position={position}; UPDATE delegation_attempts SET confirmation_van_position={position}"),
        ] {
            let bytes = delegation_fixture::corrupt(&confirmed, &sql);
            let restored = VotingDb::open_browser("owner", Network::Testnet, Some(&bytes)).unwrap();
            assert!(restored.validate_delegation_state(&id).is_err(), "{sql}");
            assert_eq!(restored.serialize_bytes().unwrap(), bytes);
        }
    }
}

#[test]
fn vote_recovery_browser_surface_uses_one_durable_driver_and_owned_jobs() {
    let bindgen = include_str!("../../../src/bindgen/voting.rs");
    let session = include_str!("../../../src/voting/session.rs");
    assert!(bindgen.contains("js_name = submitBallot"));
    assert!(bindgen.contains("js_name = resumeRound"));
    assert_eq!(session.matches("async fn drive_resume_plan").count(), 1);
    assert!(session.contains("vote_proof_job"));
    assert!(session.contains("atomic_vote_proof_job"));
    assert!(!session.contains("std::thread::"));
}

#[test]
fn delegation_restored_confirmed_corruption_blocks_all_planned_work() {
    use zcash_voting::{
        session::{delegation_resume_steps, NextStep},
        storage::VotingDb,
        Network, VotingRoundParams,
    };
    let db = VotingDb::open_browser("owner", Network::Testnet, None).unwrap();
    let id = "01".repeat(32);
    let params = VotingRoundParams {
        vote_round_id: id.clone(),
        snapshot_height: delegation_fixture::height(),
        ea_pk: vec![0; 32],
        nc_root: vec![0; 32],
        nullifier_imt_root: vec![0; 32],
    };
    db.init_round(Network::Testnet, &params, None).unwrap();
    let canonical = delegation_fixture::prepare_bundles(&db, &params, 17, 2);
    for (index, submission) in canonical.iter().enumerate() {
        db.prepare_delegation_submission(&id, index as u32, submission)
            .unwrap();
    }
    db.mark_delegation_dispatching(&id, 1).unwrap();
    db.confirm_journaled_delegation(
        &id,
        1,
        canonical[1].tx_hash(),
        &[delegation_fixture::event(&id, "42")],
    )
    .unwrap();
    let bytes = db.serialize_bytes().unwrap();
    assert_eq!(
        delegation_resume_steps(&db, &id, &[1]).unwrap(),
        [NextStep::Delegate { bundle_index: 0 }]
    );
    for sql in delegation_fixture::confirmed_corruptions() {
        let bytes = delegation_fixture::corrupt(&bytes, sql);
        let restored = VotingDb::open_browser("owner", Network::Testnet, Some(&bytes)).unwrap();
        assert!(
            delegation_resume_steps(&restored, &id, &[1]).is_err(),
            "restored corruption was omitted: {sql}"
        );
    }
}

#[test]
fn delegation_rest_events_reject_legacy_repairs_and_noncanonical_values() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use zcash_voting::{storage::VotingDb, Network, VotingRoundParams};
    // Exact plain values in vote-sdk api/handler_tx_status_test.go at 990fb1c3.
    let id = "0400".repeat(16);
    let db = VotingDb::open_browser("owner", Network::Testnet, None).unwrap();
    let params = VotingRoundParams {
        vote_round_id: id.clone(),
        snapshot_height: delegation_fixture::height(),
        ea_pk: vec![0; 32],
        nc_root: vec![0; 32],
        nullifier_imt_root: vec![0; 32],
    };
    db.init_round(Network::Testnet, &params, None).unwrap();
    let canonical = delegation_fixture::prepare(&db, &params, 17);
    db.prepare_delegation_submission(&id, 0, &canonical)
        .unwrap();
    db.mark_delegation_dispatching(&id, 0).unwrap();
    let bytes = db.serialize_bytes().unwrap();
    let repaired_round = String::from_utf8(STANDARD.decode(&id).unwrap()).unwrap();
    let repaired_position = String::from_utf8(STANDARD.decode("3753").unwrap()).unwrap();
    let mut invalid = vec![
        delegation_fixture::event(&repaired_round, "3753"),
        delegation_fixture::event(&id, &repaired_position),
    ];
    let mut repaired_event_type = delegation_fixture::event(&id, "3753");
    repaired_event_type.event_type = STANDARD.encode("delegate_vote");
    invalid.push(repaired_event_type);
    for value in [
        "",
        " 3753",
        "3753 ",
        "+3753",
        "-0",
        "00",
        "03753",
        "4294967296",
        "1.0",
        "3e3",
        "\u{ff13}\u{ff17}\u{ff15}\u{ff13}",
    ] {
        invalid.push(delegation_fixture::event(&id, value));
    }
    invalid.push(delegation_fixture::event(&(id.clone() + "00"), "3753"));
    invalid.push(delegation_fixture::event(&("0x".to_owned() + &id), "3753"));
    for event in invalid {
        let restored = VotingDb::open_browser("owner", Network::Testnet, Some(&bytes)).unwrap();
        assert!(restored
            .confirm_journaled_delegation(&id, 0, canonical.tx_hash(), &[event])
            .is_err());
        assert_ne!(
            restored.delegation_phase(&id, 0).unwrap(),
            zcash_voting::phases::DelegationPhase::Confirmed
        );
    }
    let largest_position = ((1u64 << vote_commitment_tree::TREE_DEPTH) - 1).to_string();
    for position in ["0", "3753", largest_position.as_str()] {
        let restored = VotingDb::open_browser("owner", Network::Testnet, Some(&bytes)).unwrap();
        restored
            .confirm_journaled_delegation(
                &id,
                0,
                canonical.tx_hash(),
                &[delegation_fixture::event(&id, position)],
            )
            .unwrap();
    }
}

#[test]
fn delegation_rest_events_reject_encoded_aliases_but_allow_unrelated_events() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use zcash_voting::{
        confirmation::{TxEvent, TxEventAttribute},
        storage::VotingDb,
        Network, VotingRoundParams,
    };

    let id = "01".repeat(32);
    let db = VotingDb::open_browser("owner", Network::Testnet, None).unwrap();
    let params = VotingRoundParams {
        vote_round_id: id.clone(),
        snapshot_height: delegation_fixture::height(),
        ea_pk: vec![0; 32],
        nc_root: vec![0; 32],
        nullifier_imt_root: vec![0; 32],
    };
    db.init_round(Network::Testnet, &params, None).unwrap();
    let canonical = delegation_fixture::prepare(&db, &params, 17);
    db.prepare_delegation_submission(&id, 0, &canonical)
        .unwrap();
    db.mark_delegation_dispatching(&id, 0).unwrap();
    let bytes = db.serialize_bytes().unwrap();

    let plain = delegation_fixture::event(&id, "3753");
    let mut encoded = plain.clone();
    encoded.event_type = STANDARD.encode("delegate_vote");
    let mut conflicting_encoded = delegation_fixture::event(&"02".repeat(32), "1");
    conflicting_encoded.event_type = STANDARD.encode("delegate_vote");
    for events in [
        vec![plain.clone(), encoded.clone()],
        vec![encoded.clone(), plain.clone()],
        vec![plain.clone(), conflicting_encoded.clone()],
        vec![conflicting_encoded, plain.clone()],
    ] {
        let restored = VotingDb::open_browser("owner", Network::Testnet, Some(&bytes)).unwrap();
        assert!(restored
            .confirm_journaled_delegation(&id, 0, canonical.tx_hash(), &events)
            .is_err());
    }

    let unrelated = TxEvent {
        event_type: "transfer".into(),
        attributes: vec![TxEventAttribute {
            key: "sender".into(),
            value: "unrelated".into(),
        }],
    };
    for events in [
        vec![unrelated.clone(), plain.clone()],
        vec![plain.clone(), unrelated.clone()],
    ] {
        let restored = VotingDb::open_browser("owner", Network::Testnet, Some(&bytes)).unwrap();
        restored
            .confirm_journaled_delegation(&id, 0, canonical.tx_hash(), &events)
            .unwrap();
    }
}

#[test]
fn delegation_confirmation_is_atomic_immutable_and_fail_closed() {
    use zcash_voting::{
        delegation_submission::DelegationOutcome,
        session::{delegation_resume_steps, NextStep},
        storage::VotingDb,
        Network, VotingRoundParams,
    };
    let db = VotingDb::open_browser("owner", Network::Testnet, None).unwrap();
    let id = "01".repeat(32);
    let params = VotingRoundParams {
        vote_round_id: id.clone(),
        snapshot_height: delegation_fixture::height(),
        ea_pk: vec![0; 32],
        nc_root: vec![0; 32],
        nullifier_imt_root: vec![0; 32],
    };
    db.init_round(Network::Testnet, &params, None).unwrap();
    let canonical = delegation_fixture::prepare(&db, &params, 17);
    db.prepare_delegation_submission(&id, 0, &canonical)
        .unwrap();
    db.mark_delegation_dispatching(&id, 0).unwrap();
    db.record_delegation_outcome(&id, 0, DelegationOutcome::Ambiguous)
        .unwrap();
    let pending = db.serialize_bytes().unwrap();
    assert_eq!(
        delegation_resume_steps(&db, &id, &[1]).unwrap(),
        [NextStep::AdvanceDelegation { bundle_index: 0 }]
    );
    assert_eq!(
        db.delegation_submission(&id, 0)
            .unwrap()
            .unwrap()
            .canonical
            .json_bytes(),
        canonical.json_bytes()
    );
    let blocked=VotingDb::open_browser("owner",Network::Testnet,Some(&delegation_fixture::corrupt(&pending,"CREATE TRIGGER reject_confirmation BEFORE UPDATE OF confirmation_tx_hash ON delegation_attempts BEGIN SELECT RAISE(ABORT,'fixture'); END"))).unwrap();
    assert!(blocked
        .confirm_journaled_delegation(
            &id,
            0,
            canonical.tx_hash(),
            &[delegation_fixture::event(&id, "42")]
        )
        .is_err());
    assert_eq!(
        delegation_resume_steps(&blocked, &id, &[1]).unwrap(),
        [NextStep::AdvanceDelegation { bundle_index: 0 }]
    );
    assert!(blocked.load_van_position(&id, 0).is_err());
    db.confirm_journaled_delegation(
        &id,
        0,
        canonical.tx_hash(),
        &[delegation_fixture::event(&id, "42")],
    )
    .unwrap();
    assert!(db
        .record_delegation_outcome(&id, 0, DelegationOutcome::Rejected)
        .is_err());
    assert!(db
        .confirm_journaled_delegation(
            &id,
            0,
            canonical.tx_hash(),
            &[delegation_fixture::event(&id, "41")]
        )
        .is_err());
    assert!(delegation_resume_steps(&db, &id, &[1]).unwrap().is_empty());
    assert_eq!(db.load_van_position(&id, 0).unwrap(), 42);
}

#[test]
fn delegation_planner_orders_mixed_durable_bundles_without_ballot_intent() {
    use zcash_voting::{
        session::{delegation_resume_steps, NextStep},
        storage::VotingDb,
        Network, VotingRoundParams,
    };
    let db = VotingDb::open_browser("owner", Network::Testnet, None).unwrap();
    let id = "01".repeat(32);
    db.init_round(
        Network::Testnet,
        &VotingRoundParams {
            vote_round_id: id.clone(),
            snapshot_height: delegation_fixture::height(),
            ea_pk: vec![0; 32],
            nc_root: vec![0; 32],
            nullifier_imt_root: vec![0; 32],
        },
        None,
    )
    .unwrap();
    assert!(delegation_resume_steps(&db, &id, &[1]).is_err());
    let canonical = delegation_fixture::prepare_bundles(
        &db,
        &db.round_params_with_network(&id).unwrap().0,
        17,
        3,
    );
    for index in [1, 2] {
        db.prepare_delegation_submission(&id, index, &canonical[index as usize])
            .unwrap();
        db.mark_delegation_dispatching(&id, index).unwrap();
    }
    db.confirm_journaled_delegation(
        &id,
        2,
        canonical[2].tx_hash(),
        &[delegation_fixture::event(&id, "42")],
    )
    .unwrap();
    let expected = vec![
        NextStep::Delegate { bundle_index: 0 },
        NextStep::AdvanceDelegation { bundle_index: 1 },
    ];
    assert_eq!(delegation_resume_steps(&db, &id, &[1]).unwrap(), expected);
    assert!(db.ballot_intents(&id).unwrap().is_empty());
    let restored = VotingDb::open_browser(
        "owner",
        Network::Testnet,
        Some(&db.serialize_bytes().unwrap()),
    )
    .unwrap();
    assert_eq!(
        delegation_resume_steps(&restored, &id, &[1]).unwrap(),
        expected
    );
    restored
        .prepare_delegation_submission(&id, 0, &canonical[0])
        .unwrap();
    restored.mark_delegation_dispatching(&id, 0).unwrap();
    assert!(delegation_resume_steps(&restored, &id, &[1])
        .unwrap()
        .iter()
        .all(|s| matches!(s, NextStep::AdvanceDelegation { .. })));
}

#[test]
fn delegation_journal_binds_confirmation_and_survives_reload() {
    use zcash_voting::{
        confirmation::{TxEvent, TxEventAttribute},
        delegation_submission::DelegationOutcome,
        storage::VotingDb,
        Network, VotingRoundParams,
    };
    let id = "01".repeat(32);
    let db = VotingDb::open_browser("owner", Network::Testnet, None).unwrap();
    db.init_round(
        Network::Testnet,
        &VotingRoundParams {
            vote_round_id: id.clone(),
            snapshot_height: delegation_fixture::height(),
            ea_pk: vec![0; 32],
            nc_root: vec![0; 32],
            nullifier_imt_root: vec![0; 32],
        },
        None,
    )
    .unwrap();
    let canonical =
        delegation_fixture::prepare(&db, &db.round_params_with_network(&id).unwrap().0, 17);
    db.prepare_delegation_submission(&id, 0, &canonical)
        .unwrap();
    db.mark_delegation_dispatching(&id, 0).unwrap();
    db.record_delegation_outcome(&id, 0, DelegationOutcome::Ambiguous)
        .unwrap();
    let mut tampered = rusqlite::Connection::open_in_memory().unwrap();
    let bytes = db.serialize_bytes().unwrap();
    tampered
        .deserialize_read_exact(
            rusqlite::MAIN_DB,
            std::io::Cursor::new(&bytes),
            bytes.len(),
            false,
        )
        .unwrap();
    tampered
        .execute("UPDATE proofs SET proof=x'02'", [])
        .unwrap();
    let tampered = VotingDb::open_browser(
        "owner",
        Network::Testnet,
        Some(&tampered.serialize(rusqlite::MAIN_DB).unwrap()),
    )
    .unwrap();
    assert!(tampered.delegation_submission(&id, 0).is_err());
    let restored = VotingDb::open_browser(
        "owner",
        Network::Testnet,
        Some(&db.serialize_bytes().unwrap()),
    )
    .unwrap();
    assert_eq!(
        restored
            .delegation_submission(&id, 0)
            .unwrap()
            .unwrap()
            .canonical
            .json_bytes(),
        canonical.json_bytes()
    );
    let event = |round: &str, position: &str| TxEvent {
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
    };
    for (bundle, hash, events) in [
        (1, canonical.tx_hash(), vec![event(&id, "42")]),
        (0, "wrong", vec![event(&id, "42")]),
        (0, canonical.tx_hash(), vec![event(&"02".repeat(32), "42")]),
        (0, canonical.tx_hash(), vec![event(&id, "-1")]),
        (
            0,
            canonical.tx_hash(),
            vec![event(&id, "42"), event(&id, "43")],
        ),
        (
            0,
            canonical.tx_hash(),
            vec![{
                let mut conflicting = event(&id, "42");
                conflicting.attributes.push(TxEventAttribute {
                    key: "leaf_index".into(),
                    value: "43".into(),
                });
                conflicting
            }],
        ),
        (
            0,
            canonical.tx_hash(),
            vec![{
                let mut conflicting = event(&id, "42");
                conflicting.attributes.push(TxEventAttribute {
                    key: "round_id".into(),
                    value: "02".repeat(32),
                });
                conflicting
            }],
        ),
    ] {
        assert!(restored
            .confirm_journaled_delegation(&id, bundle, hash, &events)
            .is_err());
        assert_ne!(
            restored.delegation_phase(&id, 0).unwrap(),
            zcash_voting::phases::DelegationPhase::Confirmed
        );
    }
    restored
        .confirm_journaled_delegation(&id, 0, canonical.tx_hash(), &[event(&id, "42")])
        .unwrap();
    assert_eq!(
        restored.delegation_phase(&id, 0).unwrap(),
        zcash_voting::phases::DelegationPhase::Confirmed
    );
    assert!(restored
        .confirm_journaled_delegation(&id, 0, canonical.tx_hash(), &[event(&id, "43")])
        .is_err());
}

#[test]
fn pir_preparation_hotkey_is_round_wallet_scoped_and_survives_reload() {
    use zcash_voting::{storage::VotingDb, Network, VotingRoundParams};
    let db = VotingDb::open_browser("owner", Network::Testnet, None).unwrap();
    let params = VotingRoundParams {
        vote_round_id: "01".repeat(32),
        snapshot_height: 100,
        ea_pk: vec![7; 32],
        nc_root: vec![0; 32],
        nullifier_imt_root: vec![0; 32],
    };
    assert!(db.ensure_voting_hotkey(&params.vote_round_id).is_err());
    db.init_round(Network::Testnet, &params, Some("identity"))
        .unwrap();
    let first = db.ensure_voting_hotkey(&params.vote_round_id).unwrap();
    assert_eq!(
        first.stored_secret(),
        db.ensure_voting_hotkey(&params.vote_round_id)
            .unwrap()
            .stored_secret()
    );
    let reopened = VotingDb::open_browser(
        "owner",
        Network::Testnet,
        Some(&db.serialize_bytes().unwrap()),
    )
    .unwrap();
    assert_eq!(
        first.stored_secret(),
        reopened
            .ensure_voting_hotkey(&params.vote_round_id)
            .unwrap()
            .stored_secret()
    );
    assert!(VotingDb::open_browser(
        "other",
        Network::Testnet,
        Some(&db.serialize_bytes().unwrap())
    )
    .is_err());
}

mod pir_identity {
    use serde_json::json;
    use std::sync::{Arc, Mutex};
    use zcash_voting::pir::{Transport, TransportFuture, TransportResponse};

    #[tokio::test]
    async fn pir_query_batch_never_masks_protocol_failure_with_retryable_sibling() {
        use std::collections::VecDeque;
        use valar_ypir::{
            client::YPIRClient,
            modulus_switch::expected_ct_byte_len,
            params::{GetQPrime, YPIRSPConfig},
        };
        use zcash_voting::pir::RetryableTransportError;
        struct Responses(Mutex<VecDeque<u8>>, usize);
        impl Transport for Responses {
            fn get<'a>(&'a self, url: &'a str) -> TransportFuture<'a> {
                let body = if url.ends_with("/tier0") {
                    vec![0; 2047 * 32 + 2048 * 64]
                } else if url.ends_with("/params/tier1") {
                    serde_json::to_vec(
                        &json!({"num_items":2048,"item_size_bits":24576*8,"poly_len":2048}),
                    )
                    .unwrap()
                } else {
                    serde_json::to_vec(&json!({"zcash_network":"test","nullifier_pool":"ironwood","dataset_version":2,"circuit_root":hex::encode([0;32]),"pir_root":hex::encode([0;32]),"num_ranges":1,"pir_layout":{"pir_depth":19,"tier0_layers":11,"tier1_layers":8,"poly_len":2048},"pir_depth":19,"tier1_rows":2048,"tier1_row_bytes":24576,"height":100})).unwrap()
                };
                Box::pin(async move {
                    Ok(TransportResponse {
                        status: 200,
                        headers: vec![],
                        body,
                    })
                })
            }
            fn post<'a>(&'a self, _: &'a str, _: Vec<u8>) -> TransportFuture<'a> {
                let outcome = self.0.lock().unwrap().pop_front().unwrap();
                let valid_length = self.1;
                Box::pin(async move {
                    match outcome {
                        0 => Err(RetryableTransportError.into()),
                        1 => Ok(TransportResponse {
                            status: 503,
                            headers: vec![],
                            body: b"private server diagnostic".to_vec(),
                        }),
                        2 => Ok(TransportResponse {
                            status: 200,
                            headers: vec![],
                            body: vec![0],
                        }),
                        4 => Ok(TransportResponse {
                            status: 200,
                            headers: vec![],
                            body: vec![0; valid_length],
                        }),
                        _ => Err(zcash_voting::platform::TransportError::ResponseTooLarge {
                            limit: 64 * 1024 * 1024,
                        }
                        .into()),
                    }
                })
            }
        }
        let client_params = YPIRClient::from_db_sz_simplepir_with_config(
            2048,
            24576 * 8,
            YPIRSPConfig::for_poly_len(2048),
        );
        let params = client_params.params();
        let valid_length = params.instances
            * expected_ct_byte_len(params, params.get_q_prime_1(), params.get_q_prime_2());
        let transport = Arc::new(Responses(Mutex::new(VecDeque::new()), valid_length));
        for (outcomes, retryable) in [
            ([0, 0], true),
            ([1, 1], true),
            ([0, 1], true),
            ([0, 2], false),
            ([1, 2], false),
            ([2, 0], false),
            ([1, 3], false),
            ([0, 4], false),
        ] {
            *transport.0.lock().unwrap() = outcomes.into_iter().collect();
            let mut client = zcash_voting::pir::OrderedSnapshotPir::connect(
                zcash_voting::wire::PirLayout {
                    pir_depth: 19,
                    tier0_layers: 11,
                    tier1_layers: 8,
                    poly_len: 2048,
                },
                vec!["https://pir.example".into()],
                transport.clone(),
                zcash_voting::Network::Testnet,
                &[0; 32],
                100,
            )
            .await
            .unwrap();
            let error = client
                .fetch_proofs(&[1.into(), 2.into()])
                .await
                .unwrap_err();
            assert_eq!(
                matches!(error, zcash_voting::VotingError::Internal { .. }),
                retryable,
                "outcomes {outcomes:?}: {error}"
            );
            assert!(
                transport.0.lock().unwrap().is_empty(),
                "all siblings must complete"
            );
            assert!(!error.to_string().contains("private server diagnostic"));
        }
    }

    #[tokio::test]
    async fn pir_response_shape_rejects_malformed_and_truncated_data_without_panicking() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use valar_ypir::{
            client::YPIRClient,
            modulus_switch::expected_ct_byte_len,
            params::{GetQPrime, YPIRSPConfig},
        };
        struct Responses {
            length: AtomicUsize,
            layout: zcash_voting::pir::NegotiatedPirLayout,
        }
        impl Transport for Responses {
            fn get<'a>(&'a self, url: &'a str) -> TransportFuture<'a> {
                let layout = self.layout;
                let body = if url.ends_with("/tier0") {
                    vec![0; layout.tier0_bytes().unwrap()]
                } else if url.ends_with("/params/tier1") {
                    serde_json::to_vec(&json!({"num_items":layout.tier1_rows().unwrap(), "item_size_bits":layout.tier1_item_bits().unwrap(),"poly_len":layout.poly_len})).unwrap()
                } else {
                    serde_json::to_vec(&json!({"zcash_network":"test","nullifier_pool":"ironwood","dataset_version":2,"circuit_root":hex::encode([0;32]),"pir_root":hex::encode([0;32]),"num_ranges":1,"pir_layout":layout,"pir_depth":layout.pir_depth,"tier1_rows":layout.tier1_rows().unwrap(),"tier1_row_bytes":layout.tier1_row_bytes().unwrap(),"height":100})).unwrap()
                };
                Box::pin(async move {
                    Ok(TransportResponse {
                        status: 200,
                        headers: vec![],
                        body,
                    })
                })
            }
            fn post<'a>(&'a self, _: &'a str, _: Vec<u8>) -> TransportFuture<'a> {
                let body = vec![0; self.length.load(Ordering::SeqCst)];
                Box::pin(async move {
                    Ok(TransportResponse {
                        status: 200,
                        headers: vec![],
                        body,
                    })
                })
            }
        }
        let panics = Arc::new(AtomicUsize::new(0));
        let thread = std::thread::current().id();
        let original = std::panic::take_hook();
        let count = panics.clone();
        std::panic::set_hook(Box::new(move |_| {
            if std::thread::current().id() == thread {
                count.fetch_add(1, Ordering::SeqCst);
            }
        }));
        for degree in [2048, 4096] {
            let layout = zcash_voting::wire::PirLayout {
                pir_depth: 19,
                tier0_layers: 11,
                tier1_layers: 8,
                poly_len: degree,
            };
            let negotiated = zcash_voting::pir::negotiated_pir_layout(layout).unwrap();
            let params = YPIRClient::from_db_sz_simplepir_with_config(
                2048,
                24576 * 8,
                YPIRSPConfig::for_poly_len(degree as usize),
            );
            let params = params.params();
            let length = params.instances
                * expected_ct_byte_len(params, params.get_q_prime_1(), params.get_q_prime_2());
            let server = Arc::new(Responses {
                length: AtomicUsize::new(1),
                layout: negotiated,
            });
            let client = zcash_voting::pir::connect_pir_for_snapshot(
                layout,
                "https://pir.example",
                server.clone(),
                zcash_voting::Network::Testnet,
                &[0; 32],
                100,
            )
            .await
            .unwrap();
            for bytes in [0, 1, length - 1, length + 1, length] {
                server.length.store(bytes, Ordering::SeqCst);
                assert!(client
                    .fetch_proof(zcash_voting::backend::pasta_curves::pallas::Base::from(1))
                    .await
                    .is_err());
            }
        }
        std::panic::set_hook(original);
        assert_eq!(
            panics.load(Ordering::SeqCst),
            0,
            "unwind is unavailable in browser WASM"
        );
    }

    struct Server {
        root: serde_json::Value,
        hits: Mutex<Vec<String>>,
    }
    impl Transport for Server {
        fn get<'a>(&'a self, url: &'a str) -> TransportFuture<'a> {
            self.hits.lock().unwrap().push(url.into());
            let body = serde_json::to_vec(&self.root).unwrap();
            Box::pin(async move {
                Ok(TransportResponse {
                    status: 200,
                    headers: vec![],
                    body,
                })
            })
        }
        fn post<'a>(&'a self, _: &'a str, _: Vec<u8>) -> TransportFuture<'a> {
            panic!("identity rejection must precede private queries")
        }
    }
    #[tokio::test]
    async fn pir_rejects_each_snapshot_identity_mismatch_before_assets_or_queries() {
        let layout = zcash_voting::wire::PirLayout {
            pir_depth: 19,
            tier0_layers: 11,
            tier1_layers: 8,
            poly_len: 2048,
        };
        let negotiated = zcash_voting::pir::negotiated_pir_layout(layout).unwrap();
        let root = json!({ "zcash_network": "test", "nullifier_pool": pir_types::NULLIFIER_POOL,
            "dataset_version": pir_types::DATASET_VERSION, "circuit_root": hex::encode([0;32]),
            "pir_root": hex::encode([0;32]), "num_ranges": 1, "pir_layout": negotiated,
            "pir_depth": 19, "tier1_rows": negotiated.tier1_rows().unwrap(),
            "tier1_row_bytes": negotiated.tier1_row_bytes().unwrap(), "height": 100 });
        for (field, bad) in [
            ("zcash_network", json!("main")),
            ("nullifier_pool", json!("orchard")),
            ("dataset_version", json!(999)),
            (
                "pir_layout",
                json!({"pir_depth":19,"tier0_layers":12,"tier1_layers":7,"poly_len":2048}),
            ),
            ("circuit_root", json!(hex::encode([1; 32]))),
            ("height", json!(101)),
            ("height", json!(null)),
        ] {
            let mut mutated = root.clone();
            mutated[field] = bad;
            let server = Arc::new(Server {
                root: mutated,
                hits: Mutex::new(vec![]),
            });
            assert!(
                zcash_voting::pir::connect_pir_for_snapshot(
                    layout,
                    "https://pir.example",
                    server.clone(),
                    zcash_voting::Network::Testnet,
                    &[0; 32],
                    100
                )
                .await
                .is_err(),
                "accepted {field}"
            );
            assert_eq!(*server.hits.lock().unwrap(), ["https://pir.example/root"]);
        }
    }
}

#[test]
fn round_session_context_distinguishes_absence_and_is_wallet_scoped() {
    use zcash_voting::{storage::VotingDb, Network, VotingRoundParams};
    let db = VotingDb::open(":memory:").unwrap();
    let params = VotingRoundParams {
        vote_round_id: "01".repeat(32),
        snapshot_height: 100,
        ea_pk: vec![7; 32],
        nc_root: vec![1; 32],
        nullifier_imt_root: vec![2; 32],
    };
    db.set_wallet_id("owner-a");
    assert!(db.round_session_json(&params.vote_round_id).is_err());
    db.init_round(Network::Testnet, &params, None).unwrap();
    assert_eq!(db.round_session_json(&params.vote_round_id).unwrap(), None);
    db.clear_round(&params.vote_round_id).unwrap();
    db.init_round(Network::Testnet, &params, Some("opaque caller context"))
        .unwrap();
    assert_eq!(
        db.round_session_json(&params.vote_round_id)
            .unwrap()
            .as_deref(),
        Some("opaque caller context")
    );
    db.set_wallet_id("owner-b");
    assert!(db.round_session_json(&params.vote_round_id).is_err());
    db.init_round(Network::Testnet, &params, None).unwrap();
    assert_eq!(db.round_session_json(&params.vote_round_id).unwrap(), None);
}

#[test]
fn round_protocol_params_are_complete_and_wallet_scoped() {
    use zcash_voting::{storage::VotingDb, Network, VotingRoundParams};
    let db = VotingDb::open(":memory:").unwrap();
    let params = VotingRoundParams {
        vote_round_id: "01".repeat(32),
        snapshot_height: 100,
        ea_pk: vec![7; 32],
        nc_root: vec![1; 32],
        nullifier_imt_root: vec![2; 32],
    };
    db.set_wallet_id("owner-a");
    assert!(db.round_params_with_network(&params.vote_round_id).is_err());
    db.init_round(Network::Testnet, &params, None).unwrap();
    assert_eq!(
        db.round_params_with_network(&params.vote_round_id).unwrap(),
        (params.clone(), Network::Testnet)
    );
    db.set_wallet_id("owner-b");
    assert!(db.round_params_with_network(&params.vote_round_id).is_err());
    let mut other = params.clone();
    other.snapshot_height += 1;
    other.ea_pk[0] ^= 1;
    other.nc_root[0] ^= 1;
    other.nullifier_imt_root[0] ^= 1;
    db.init_round(Network::Mainnet, &other, None).unwrap();
    assert_eq!(
        db.round_params_with_network(&params.vote_round_id).unwrap(),
        (other, Network::Mainnet)
    );
    db.set_wallet_id("owner-a");
    assert_eq!(
        db.round_params_with_network(&params.vote_round_id).unwrap(),
        (params, Network::Testnet)
    );
}

#[test]
fn authenticated_config_round_params_bind_only_the_signed_authority_key() {
    use sha2::{Digest, Sha256};
    use zcash_voting::config::{
        resolve_dynamic_voting_config, resolve_static_voting_config, ResolveVotingConfigOptions,
    };
    let static_bytes = include_bytes!("../../../src/voting/fixtures/static.json");
    let source = format!(
        "https://example.com/static.json?checksum=sha256:{}",
        hex::encode(Sha256::digest(static_bytes))
    );
    let anchor = resolve_static_voting_config(&source, static_bytes).unwrap();
    let resolved = resolve_dynamic_voting_config(
        anchor,
        include_bytes!("../../../src/voting/fixtures/dynamic.json"),
        ResolveVotingConfigOptions::default(),
    )
    .unwrap();
    let id = resolved.authenticated_rounds[0].round_id.clone();
    let params = resolved
        .trusted_voting_round_params(id, 100, vec![1; 32], vec![2; 32])
        .unwrap();
    assert_eq!(params.ea_pk, vec![7; 32]);
    assert!(resolved
        .trusted_voting_round_params("01".repeat(32), 100, vec![1; 32], vec![2; 32])
        .is_err());
    assert!(resolved
        .trusted_voting_round_params(params.vote_round_id, 100, vec![1; 31], vec![2; 32])
        .is_err());
}

mod wallet_inputs {
    use prost::Message;
    use zcash_client_backend::proto::service::TreeState;
    use zcash_voting::storage::VotingDb;
    use zcash_voting::{
        backend::zcash_client_backend,
        delegate::DelegationAccountKeys,
        selection::{DelegationWalletInputs, GatherDelegationWalletInputs},
        store_tree_state_and_witnesses, Network, NoteInfo, VotingHotkey, VotingRoundParams,
    };
    const ROUND: &str = "wallet-inputs-round";

    use super::owned_proof_fixture::{
        fixture, prepare_delegation, prove_vote_after_database_drop, HEIGHT,
    };

    fn gather(
        note: NoteInfo,
        keys: DelegationAccountKeys,
        state: TreeState,
        hotkey: &VotingHotkey,
    ) -> Result<DelegationWalletInputs, zcash_voting::VotingError> {
        DelegationWalletInputs::from_parts(GatherDelegationWalletInputs {
            network: Network::Regtest,
            scanned_height: HEIGHT,
            snapshot_height: HEIGHT,
            anchor_tree_state_bytes: state.encode_to_vec(),
            round_note_infos: vec![note],
            account_keys: keys,
            voting_hotkey: hotkey,
            resolved_round_name: "fixture".into(),
        })
    }

    #[tokio::test]
    #[ignore = "real Halo2 delegation proof"]
    async fn delegation_owned_proof_job_survives_database_drop() {
        use voting_circuits::delegation::{ImtProvider, SpacedLeafImtProvider};
        use zcash_voting::{
            backend::pasta_curves::group::ff::PrimeField,
            proof_executor::{ProofExecutor, SequentialProofExecutor},
        };
        let (note, account, tree, witness) = fixture();
        let id = "01".repeat(32);
        let imt = SpacedLeafImtProvider::new();
        let db = VotingDb::open_browser("owner", Network::Regtest, None).unwrap();
        let params = VotingRoundParams {
            vote_round_id: id.clone(),
            snapshot_height: HEIGHT,
            ea_pk: vec![7; 32],
            nc_root: witness.root.clone(),
            nullifier_imt_root: imt.root().to_repr().to_vec(),
        };
        db.init_round(Network::Regtest, &params, None).unwrap();
        let hotkey = db.ensure_voting_hotkey(&id).unwrap();
        let keys = zcash_voting::delegate::DelegationKeys::with_voting_hotkey(
            account.orchard_fvk_bytes.to_vec(),
            &hotkey,
            account.seed_fingerprint,
            account.account_index,
            "fixture".into(),
        )
        .unwrap();
        let notes = vec![note];
        db.ensure_bundles(&id, &notes).unwrap();
        db.ensure_padded_secrets(&id, 0, &notes).unwrap();
        store_tree_state_and_witnesses(&db, &id, 0, &tree.encode_to_vec(), &notes, &[witness])
            .unwrap();
        db.precompute_delegation_pir_async(&id, 0, &notes, Network::Regtest, |nullifiers| async {
            Ok(nullifiers
                .into_iter()
                .map(|nf| {
                    let p = imt.non_membership_proof(nf).unwrap();
                    zcash_voting::pir::ImtProofData {
                        root: p.root,
                        nf_bounds: p.nf_bounds,
                        leaf_pos: p.leaf_pos,
                        path: p.path,
                    }
                })
                .collect())
        })
        .await
        .unwrap();
        db.build_governance_pczt(
            &id,
            0,
            &notes,
            &keys,
            zcash_voting::delegate::branch_id_for_height(Network::Regtest, HEIGHT).unwrap(),
        )
        .unwrap();
        let job = db.delegation_proof_job(&id, 0, notes, keys).unwrap();
        let bytes = db.serialize_bytes().unwrap();
        drop(db);
        let result = SequentialProofExecutor
            .prove(job, |job| job(&zcash_voting::types::NoopProgressReporter))
            .await
            .unwrap();
        let restored = VotingDb::open_browser("owner", Network::Regtest, Some(&bytes)).unwrap();
        restored.store_delegation_proof(&id, 0, &result).unwrap();
        assert_eq!(
            restored.delegation_phase(&id, 0).unwrap(),
            zcash_voting::phases::DelegationPhase::Proved
        );
    }

    /// Deterministic real ZKP2 entry point for optimized browser proof checks.
    ///
    /// This remains ignored in normal suites because it builds both Halo2
    /// proofs, but it deliberately drops SQLite before the vote proof runs.
    #[tokio::test]
    #[ignore = "real Halo2 vote proof fixture for browser sequential/Rayon checks"]
    async fn vote_owned_proof_job_survives_database_drop() {
        use vote_commitment_tree::MemoryTreeServer;
        use zcash_voting::{proof_executor::SequentialProofExecutor, tree_sync::VoteTreeSync};

        let executor = SequentialProofExecutor;
        let context = prepare_delegation(&executor).await;
        let mut tree = MemoryTreeServer::empty();
        tree.append(context.van_commitment).unwrap();
        tree.checkpoint(HEIGHT as u32).unwrap();
        let sync = VoteTreeSync::new();
        let tree = super::async_tree_contract::AsyncServer::from_tree(tree);
        let height = sync
            .sync_with_async_api(&context.db, &context.id, &tree)
            .await
            .unwrap();
        let van_witness = sync
            .generate_van_witness(&context.db, &context.id, 0, height)
            .unwrap();
        prove_vote_after_database_drop(context, &executor, van_witness).await;
    }

    #[tokio::test]
    async fn pir_preparation_persists_witnesses_padding_cache_and_resume_plan() {
        use voting_circuits::delegation::{ImtProvider, SpacedLeafImtProvider};
        use zcash_voting::backend::pasta_curves::group::ff::PrimeField;
        let (note, _, tree, witness) = fixture();
        let imt = SpacedLeafImtProvider::new();
        let params = VotingRoundParams {
            vote_round_id: ROUND.into(),
            snapshot_height: HEIGHT,
            ea_pk: vec![7; 32],
            nc_root: witness.root.clone(),
            nullifier_imt_root: imt.root().to_repr().to_vec(),
        };
        let db = VotingDb::open_browser("owner", Network::Regtest, None).unwrap();
        db.init_round(Network::Regtest, &params, Some("durable context"))
            .unwrap();
        let hotkey = db.ensure_voting_hotkey(ROUND).unwrap();
        let notes = vec![note];
        db.ensure_bundles(ROUND, &notes).unwrap();
        let padding = db.ensure_padded_secrets(ROUND, 0, &notes).unwrap();
        store_tree_state_and_witnesses(&db, ROUND, 0, &tree.encode_to_vec(), &notes, &[witness])
            .unwrap();
        let failure = db
            .precompute_delegation_pir_async(ROUND, 0, &notes, Network::Regtest, |_| async {
                Err(zcash_voting::VotingError::InvalidInput {
                    message: "interrupted".into(),
                })
            })
            .await;
        assert!(failure.is_err());
        let fetched = db
            .precompute_delegation_pir_async(
                ROUND,
                0,
                &notes,
                Network::Regtest,
                |nullifiers| async {
                    // Serializing while the fetch is pending detects a held SQLite owner guard.
                    assert!(!db.serialize_bytes().unwrap().is_empty());
                    Ok(nullifiers
                        .into_iter()
                        .map(|nf| {
                            let p = imt.non_membership_proof(nf).unwrap();
                            zcash_voting::pir::ImtProofData {
                                root: p.root,
                                nf_bounds: p.nf_bounds,
                                leaf_pos: p.leaf_pos,
                                path: p.path,
                            }
                        })
                        .collect())
                },
            )
            .await
            .unwrap();
        assert_eq!(fetched.fetched_count, 5);
        let plan = zcash_voting::session::resume_plan(&db, ROUND, &[1]).unwrap();
        let reopened = VotingDb::open_browser(
            "owner",
            Network::Regtest,
            Some(&db.serialize_bytes().unwrap()),
        )
        .unwrap();
        assert_eq!(
            hotkey.stored_secret(),
            reopened
                .ensure_voting_hotkey(ROUND)
                .unwrap()
                .stored_secret()
        );
        assert_eq!(
            padding,
            reopened.ensure_padded_secrets(ROUND, 0, &notes).unwrap()
        );
        assert_eq!(
            plan,
            zcash_voting::session::resume_plan(&reopened, ROUND, &[1]).unwrap()
        );
        assert!(reopened.has_complete_witnesses(ROUND, 0, &notes).unwrap());
        let cached = reopened
            .precompute_delegation_pir_async(ROUND, 0, &notes, Network::Regtest, |_| async {
                panic!("reload must use verified persisted proofs")
            })
            .await
            .unwrap();
        assert_eq!(cached.cached_count, 5);
        assert_eq!(cached.fetched_count, 0);
    }

    #[test]
    fn pir_snapshot_tree_identity_rejects_protocol_root_height_and_network() {
        let (_, _, tree, witness) = fixture();
        let params = VotingRoundParams {
            vote_round_id: ROUND.into(),
            snapshot_height: HEIGHT,
            ea_pk: vec![7; 32],
            nc_root: witness.root,
            nullifier_imt_root: vec![0; 32],
        };
        zcash_voting::precompute::validate_snapshot_tree_state(
            &params,
            Network::Regtest,
            &tree.encode_to_vec(),
        )
        .unwrap();
        let mut wrong = params.clone();
        wrong.nc_root[0] ^= 1;
        assert!(zcash_voting::precompute::validate_snapshot_tree_state(
            &wrong,
            Network::Regtest,
            &tree.encode_to_vec()
        )
        .is_err());
        wrong = params.clone();
        wrong.snapshot_height += 1;
        assert!(zcash_voting::precompute::validate_snapshot_tree_state(
            &wrong,
            Network::Regtest,
            &tree.encode_to_vec()
        )
        .is_err());
        assert!(zcash_voting::precompute::validate_snapshot_tree_state(
            &params,
            Network::Testnet,
            &tree.encode_to_vec()
        )
        .is_err());
    }

    #[test]
    fn validates_note_identity_network_position_and_tree_height() {
        let (note, keys, state, _) = fixture();
        let hotkey = VotingHotkey::from_stored_secret(&[0x77; 64], Network::Regtest).unwrap();
        assert!(gather(note.clone(), keys.clone(), state.clone(), &hotkey).is_ok());
        for field in [
            "commitment",
            "nullifier",
            "rho",
            "rseed",
            "scope",
            "position",
            "ufvk",
            "value",
        ] {
            let mut invalid = note.clone();
            match field {
                "commitment" => invalid.commitment[0] ^= 1,
                "nullifier" => invalid.nullifier[0] ^= 1,
                "rho" => invalid.rho.clear(),
                "rseed" => invalid.rseed.clear(),
                "scope" => invalid.scope = 2,
                "position" => invalid.position = 1u64 << 32,
                "ufvk" => invalid.ufvk_str.clear(),
                _ => invalid.value += 1,
            }
            assert!(
                gather(invalid, keys.clone(), state.clone(), &hotkey).is_err(),
                "{field}"
            );
        }
        let mut wrong_keys = keys.clone();
        wrong_keys.orchard_fvk_bytes[0] ^= 1;
        assert!(gather(note.clone(), wrong_keys, state.clone(), &hotkey).is_err());
        let mut invalid_account = keys.clone();
        invalid_account.account_index = u32::MAX;
        assert!(gather(note.clone(), invalid_account, state.clone(), &hotkey).is_err());
        let mut stale = state.clone();
        stale.height -= 1;
        assert!(gather(note.clone(), keys.clone(), stale, &hotkey).is_err());
        let mut wrong_network = state.clone();
        wrong_network.network = "test".into();
        assert!(gather(note.clone(), keys.clone(), wrong_network, &hotkey).is_err());
        let wrong_hotkey = VotingHotkey::from_stored_secret(&[0x77; 64], Network::Testnet).unwrap();
        assert!(gather(note, keys, state, &wrong_hotkey).is_err());
    }

    #[test]
    fn rejects_invalid_paths_without_writes_and_retries_complete_cache() {
        let (note, _, state, witness) = fixture();
        let db = VotingDb::open_browser("wallet-inputs", Network::Regtest, None).unwrap();
        db.init_round(
            Network::Regtest,
            &VotingRoundParams {
                vote_round_id: ROUND.into(),
                snapshot_height: HEIGHT,
                nc_root: witness.root.clone(),
                ea_pk: vec![1; 32],
                nullifier_imt_root: vec![2; 32],
            },
            None,
        )
        .unwrap();
        db.ensure_bundles_with_policy(ROUND, &[note.clone()], Default::default())
            .unwrap();
        let before = db.serialize_bytes().unwrap();
        for field in ["root", "path", "position", "commitment", "length"] {
            let mut invalid = witness.clone();
            match field {
                "root" => invalid.root[0] ^= 1,
                "path" => invalid.auth_path[0][0] ^= 1,
                "position" => invalid.position = 1u64 << 32,
                "commitment" => invalid.note_commitment[0] ^= 1,
                _ => {
                    invalid.auth_path.pop();
                }
            }
            assert!(
                store_tree_state_and_witnesses(
                    &db,
                    ROUND,
                    0,
                    &state.encode_to_vec(),
                    &[note.clone()],
                    &[invalid]
                )
                .is_err(),
                "{field}"
            );
            assert_eq!(db.serialize_bytes().unwrap(), before);
        }
        for _ in 0..2 {
            store_tree_state_and_witnesses(
                &db,
                ROUND,
                0,
                &state.encode_to_vec(),
                &[note.clone()],
                &[witness.clone()],
            )
            .unwrap();
        }
        assert!(db.has_complete_witnesses(ROUND, 0, &[note]).unwrap());
    }
}

#[test]
fn wallet_inputs_reject_unsynced_parts_before_construction() {
    use zcash_voting::{
        delegate::DelegationAccountKeys,
        selection::{gather_delegation_wallet_inputs_from_parts, GatherDelegationWalletInputs},
        Network, VotingHotkey,
    };
    let hotkey = VotingHotkey::from_stored_secret(&[0x77; 64], Network::Testnet).unwrap();
    let result = gather_delegation_wallet_inputs_from_parts(GatherDelegationWalletInputs {
        network: Network::Testnet,
        scanned_height: 1,
        snapshot_height: 2,
        anchor_tree_state_bytes: Vec::new(),
        round_note_infos: Vec::new(),
        account_keys: DelegationAccountKeys {
            account_index: 0,
            orchard_fvk_bytes: [0; 96],
            seed_fingerprint: [0; 32],
        },
        voting_hotkey: &hotkey,
        resolved_round_name: "fixture".into(),
    });
    assert!(result.unwrap_err().to_string().contains("not synced"));
}

mod transport {
    use zcash_voting::platform::{
        HttpTransport, OwnedHttpRequest, OwnedHttpResponse, RequestKind, TransportError,
        TransportFuture,
    };

    fn request(kind: RequestKind) -> OwnedHttpRequest {
        OwnedHttpRequest {
            method: if kind == RequestKind::Idempotent {
                "GET"
            } else {
                "POST"
            }
            .into(),
            url: "https://example.com/vote".into(),
            headers: vec![("Content-Type".into(), "application/json".into())],
            body: Vec::new(),
            timeout_ms: 30_000,
            max_response_bytes: 4,
            kind,
        }
    }

    #[test]
    fn invalid_request_is_definite_before_dispatch() {
        for url in [
            "not a URL",
            "/relative",
            "ftp://example.com",
            "https://user:pass@example.com",
            "https://example.com/\n",
        ] {
            let mut req = request(RequestKind::NonIdempotent);
            req.url = url.into();
            assert_eq!(req.validate(), Err(TransportError::Definite), "{url:?}");
        }
        let mut req = request(RequestKind::NonIdempotent);
        req.method = "bad method".into();
        assert_eq!(req.validate(), Err(TransportError::Definite));
        req.method = "TRACE".into();
        assert_eq!(req.validate(), Err(TransportError::Definite));
        req.method = "POST".into();
        req.headers
            .push(("X-Test".into(), "value\r\ninjected: true".into()));
        assert_eq!(req.validate(), Err(TransportError::Definite));
        req.headers.pop();
        for timeout in [0, u32::MAX] {
            req.timeout_ms = timeout;
            assert_eq!(req.validate(), Err(TransportError::Definite));
        }
        let mut get = request(RequestKind::Idempotent);
        get.body.push(1);
        assert_eq!(get.validate(), Err(TransportError::Definite));
        assert_eq!(request(RequestKind::Idempotent).validate(), Ok(()));
    }

    #[test]
    fn rejected_get_is_retryable_but_dispatched_post_is_ambiguous() {
        let get = TransportError::after_dispatch(RequestKind::Idempotent);
        assert_eq!(get, TransportError::Definite);
        assert!(get.is_safe_to_retry());
        let post = TransportError::after_dispatch(RequestKind::NonIdempotent);
        assert_eq!(post, TransportError::Ambiguous);
        assert!(!post.is_safe_to_retry());
    }

    #[test]
    fn limits_apply_to_headers_and_actual_bytes_without_erasing_post_ambiguity() {
        for kind in [RequestKind::Idempotent, RequestKind::NonIdempotent] {
            let req = request(kind);
            let oversized = if kind == RequestKind::Idempotent {
                TransportError::ResponseTooLarge { limit: 4 }
            } else {
                TransportError::Ambiguous
            };
            assert_eq!(req.check_response_size(4), Ok(()));
            assert_eq!(req.check_response_size(5), Err(oversized.clone()));
            for length in ["5", " 5 ", "9999999999999999999999999999999999999999999"] {
                assert_eq!(
                    req.check_content_length(Some(length)),
                    Err(oversized.clone())
                );
            }
            for length in [
                None,
                Some("4"),
                Some(""),
                Some("invalid"),
                Some("-1"),
                Some("+5"),
                Some("4, 5"),
            ] {
                assert_eq!(req.check_content_length(length), Ok(()));
                // An absent, invalid or understated header cannot bypass the body limit.
                assert_eq!(req.check_response_size(5), Err(oversized.clone()));
            }
        }
        assert!(!TransportError::ResponseTooLarge { limit: 4 }.is_safe_to_retry());
    }

    #[test]
    fn owned_boundary_is_send_and_transport_is_object_safe() {
        fn send<T: Send>() {}
        fn object_safe(_: Option<&dyn HttpTransport>) {}
        send::<OwnedHttpRequest>();
        send::<OwnedHttpResponse>();
        send::<TransportError>();
        send::<TransportFuture>();
        object_safe(None);
    }

    #[test]
    fn javascript_response_lengths_are_validated_before_integer_conversion() {
        for kind in [RequestKind::Idempotent, RequestKind::NonIdempotent] {
            let req = request(kind);
            assert_eq!(req.check_response_size_number(4.0), Ok(4));
            for size in [5.0, 4_294_967_296.0, f64::MAX] {
                let expected = match kind {
                    RequestKind::Idempotent => TransportError::ResponseTooLarge { limit: 4 },
                    RequestKind::NonIdempotent => TransportError::Ambiguous,
                };
                assert_eq!(req.check_response_size_number(size), Err(expected));
            }
            for size in [-1.0, 0.5, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
                assert_eq!(
                    req.check_response_size_number(size),
                    Err(TransportError::after_dispatch(kind))
                );
            }
            let mut widest = request(kind);
            widest.max_response_bytes = usize::MAX;
            assert!(widest
                .check_response_size_number(usize::MAX as f64 + 1.0)
                .is_err());
            assert!(widest
                .check_response_size_number(isize::MAX as f64 + 1.0)
                .is_err());
        }
    }
}

#[test]
fn browser_db_file_backed_wal_snapshot_preserves_pending_rows() {
    use rusqlite::Connection;
    use zcash_voting::{
        round::{RoundParams, VotingDb},
        session::{resume_plan, Decision},
        types::Network,
    };

    struct Files(std::path::PathBuf);
    impl Drop for Files {
        fn drop(&mut self) {
            for suffix in ["", "-wal", "-shm"] {
                let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
            }
        }
    }

    for page_size in [4096, 8192] {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let files = Files(std::env::temp_dir().join(format!(
            "browser-wal-{}-{unique}.sqlite",
            std::process::id()
        )));
        let setup = Connection::open(&files.0).unwrap();
        setup.pragma_update(None, "page_size", page_size).unwrap();
        setup.execute_batch("VACUUM").unwrap();
        drop(setup);

        let source = VotingDb::open_path(&files.0).unwrap();
        source.set_wallet_id("wallet-a");
        let observer = Connection::open(&files.0).unwrap();
        // Leave the round changes in the WAL; real v17 migration uses its
        // archived schema fixture in the storage tests.
        observer
            .execute_batch("PRAGMA wal_checkpoint(TRUNCATE)")
            .unwrap();
        let params = RoundParams {
            vote_round_id: "0101010101010101010101010101010101010101010101010101010101010101"
                .into(),
            snapshot_height: 1000,
            ea_pk: vec![0xEA; 32],
            nc_root: vec![0xAA; 32],
            nullifier_imt_root: vec![0xBB; 32],
        };
        source
            .create_round(Network::Testnet, &params, Some("wal-session"))
            .unwrap();
        source
            .set_ballot_intent(&params.vote_round_id, 1, Decision::Skipped, 3)
            .unwrap();
        assert!(
            std::fs::metadata(format!("{}-wal", files.0.display()))
                .unwrap()
                .len()
                > 32
        );
        let expected = resume_plan(&source, &params.vote_round_id, &[1]).unwrap();
        let bytes = source.serialize_bytes().unwrap();
        let restored = VotingDb::open_browser("wallet-a", Network::Testnet, Some(&bytes)).unwrap();
        assert_eq!(
            resume_plan(&restored, &params.vote_round_id, &[1]).unwrap(),
            expected
        );
        assert_eq!(
            restored.ballot_intents(&params.vote_round_id).unwrap(),
            vec![(1, Decision::Skipped)]
        );
        assert_eq!(
            observer
                .pragma_query_value(None, "journal_mode", |r| r.get::<_, String>(0))
                .unwrap(),
            "wal"
        );
        assert_eq!(
            observer
                .pragma_query_value(None, "user_version", |r| r.get::<_, i64>(0))
                .unwrap(),
            25
        );
        assert_eq!(
            observer
                .pragma_query_value(None, "page_size", |r| r.get::<_, i64>(0))
                .unwrap(),
            page_size
        );
        source
            .set_ballot_intent(&params.vote_round_id, 1, Decision::Choice(1), 3)
            .unwrap();
        assert_eq!(
            restored.ballot_intents(&params.vote_round_id).unwrap(),
            vec![(1, Decision::Skipped)]
        );

        let raw_wal_bytes = observer.serialize(rusqlite::MAIN_DB).unwrap().to_vec();
        let error = VotingDb::open_browser("wallet-a", Network::Testnet, Some(&raw_wal_bytes))
            .err()
            .expect("raw WAL image must be rejected");
        assert!(
            error
                .to_string()
                .contains("WAL snapshot requires normalized export"),
            "{error}"
        );
    }
}

mod async_tree_contract {
    use crate::delegation_fixture;
    use std::{
        convert::Infallible,
        future::Future,
        pin::Pin,
        sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Mutex,
        },
    };

    use tokio::sync::oneshot;
    use vote_commitment_tree::{
        sync_api::{BlockCommitmentsPage, TreeState},
        MemoryTreeServer, TreeSyncApi,
    };
    use vote_commitment_tree_client::AsyncTreeSyncApi;
    use voting_crypto_deps::pasta_curves::{group::ff::PrimeField, Fp};
    use zcash_voting::{
        governance::BALLOT_DIVISOR, round::RoundParams, storage::VotingDb, tree_sync::VoteTreeSync,
        types::NoteInfo,
    };

    const ROUND_ID: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const WALLET_ID: &str = "browser-async-tree";

    pub(super) type TreeFuture<T> =
        Pin<Box<dyn Future<Output = Result<T, FixtureError>> + Send + 'static>>;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(super) enum FixtureError {
        Fetch,
    }

    #[derive(Clone, Copy)]
    enum CursorFault {
        None,
        NonProgressing,
        Overshooting,
        Truncated,
    }

    pub(super) struct AsyncServer {
        server: Mutex<MemoryTreeServer>,
        page_span: u32,
        calls: Mutex<Vec<(u32, u32)>>,
        page_number: AtomicUsize,
        fail_page: AtomicUsize,
        fail_state: AtomicBool,
        corrupt_root: bool,
        corrupt_state_root: bool,
        corrupt_anchor_root: bool,
        omit_empty_blocks: bool,
        root_requests: Mutex<Vec<u32>>,
        cursor_fault: CursorFault,
    }

    impl AsyncServer {
        pub(super) fn from_tree(server: MemoryTreeServer) -> Self {
            Self {
                server: Mutex::new(server),
                page_span: u32::MAX,
                calls: Mutex::new(vec![]),
                page_number: AtomicUsize::new(0),
                fail_page: AtomicUsize::new(usize::MAX),
                fail_state: AtomicBool::new(false),
                corrupt_root: false,
                corrupt_state_root: false,
                corrupt_anchor_root: false,
                omit_empty_blocks: false,
                root_requests: Mutex::new(vec![]),
                cursor_fault: CursorFault::None,
            }
        }

        fn new(blocks: u32, page_span: u32) -> Self {
            Self {
                server: Mutex::new(server(blocks)),
                page_span,
                calls: Mutex::new(Vec::new()),
                page_number: AtomicUsize::new(0),
                fail_page: AtomicUsize::new(usize::MAX),
                fail_state: AtomicBool::new(false),
                corrupt_root: false,
                corrupt_state_root: false,
                corrupt_anchor_root: false,
                omit_empty_blocks: false,
                root_requests: Mutex::new(Vec::new()),
                cursor_fault: CursorFault::None,
            }
        }

        fn append_block(&self) {
            let mut server = self.server.lock().unwrap();
            let height = server.latest_checkpoint().unwrap_or(0) + 1;
            server.append(Fp::from(u64::from(height))).unwrap();
            server.checkpoint(height).unwrap();
        }

        fn append_empty_block(&self) {
            let mut server = self.server.lock().unwrap();
            let height = server.latest_checkpoint().unwrap_or(0) + 1;
            server.checkpoint(height).unwrap();
        }

        fn fail_once_on_page(&self, page: usize) {
            self.fail_page.store(page, Ordering::SeqCst);
        }

        fn requests(&self) -> Vec<(u32, u32)> {
            self.calls.lock().unwrap().clone()
        }

        fn root_requests(&self) -> Vec<u32> {
            self.root_requests.lock().unwrap().clone()
        }
    }

    impl AsyncTreeSyncApi for AsyncServer {
        type Error = FixtureError;

        fn get_tree_state(&self) -> TreeFuture<TreeState> {
            if self.fail_state.swap(false, Ordering::SeqCst) {
                return Box::pin(async { Err(FixtureError::Fetch) });
            }
            let mut state = TreeSyncApi::get_tree_state(&*self.server.lock().unwrap()).unwrap();
            if self.corrupt_state_root {
                state.root += Fp::one();
            }
            Box::pin(async move { Ok(state) })
        }

        fn get_root_at_height(&self, height: u32) -> TreeFuture<Option<Fp>> {
            self.root_requests.lock().unwrap().push(height);
            let mut root =
                TreeSyncApi::get_root_at_height(&*self.server.lock().unwrap(), height).unwrap();
            if self.corrupt_anchor_root {
                root = root.map(|root| root + Fp::one());
            }
            Box::pin(async move { Ok(root) })
        }

        fn get_block_commitments(
            &self,
            from_height: u32,
            to_height: u32,
        ) -> TreeFuture<BlockCommitmentsPage> {
            self.calls.lock().unwrap().push((from_height, to_height));
            let page_number = self.page_number.fetch_add(1, Ordering::SeqCst);
            if self
                .fail_page
                .compare_exchange(page_number, usize::MAX, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
            {
                return Box::pin(async { Err(FixtureError::Fetch) });
            }
            let page_to = from_height
                .saturating_add(self.page_span.saturating_sub(1))
                .min(to_height);
            let mut page = TreeSyncApi::get_block_commitments(
                &*self.server.lock().unwrap(),
                from_height,
                page_to,
            )
            .unwrap();
            if self.omit_empty_blocks {
                page.blocks.retain(|block| !block.leaves.is_empty());
            }
            page.next_from_height = if page_to < to_height { page_to + 1 } else { 0 };
            if self.corrupt_root {
                if let Some(block) = page.blocks.last_mut() {
                    block.root += Fp::one();
                }
            }
            page.next_from_height = match self.cursor_fault {
                CursorFault::None => page.next_from_height,
                CursorFault::NonProgressing => from_height,
                CursorFault::Overshooting => to_height.saturating_add(1),
                CursorFault::Truncated => 0,
            };
            Box::pin(async move { Ok(page) })
        }
    }

    fn server(blocks: u32) -> MemoryTreeServer {
        let mut server = MemoryTreeServer::empty();
        if blocks == 0 {
            server.checkpoint(0).unwrap();
        }
        for height in 1..=blocks {
            server.append(Fp::from(u64::from(height))).unwrap();
            server.checkpoint(height).unwrap();
        }
        server
    }

    fn db(expected: Option<(u32, Fp)>) -> VotingDb {
        let db = VotingDb::open_browser(WALLET_ID, zcash_voting::Network::Testnet, None).unwrap();
        db.create_round(
            zcash_voting::Network::Testnet,
            &RoundParams {
                vote_round_id: ROUND_ID.into(),
                snapshot_height: 100,
                ea_pk: vec![1; 32],
                nc_root: vec![2; 32],
                nullifier_imt_root: vec![3; 32],
            },
            None,
        )
        .unwrap();
        if let Some((position, commitment)) = expected {
            db.ensure_bundles(
                ROUND_ID,
                &[NoteInfo {
                    commitment: vec![1; 32],
                    nullifier: vec![2; 32],
                    value: BALLOT_DIVISOR + 500_000,
                    position: 0,
                    diversifier: vec![3; 11],
                    rho: vec![4; 32],
                    rseed: vec![5; 32],
                    scope: 0,
                    ufvk_str: "uviewtest".into(),
                }],
            )
            .unwrap();
            db.store_van_position(ROUND_ID, 0, position).unwrap();
            let sql = format!(
                "UPDATE bundles SET gov_comm = X'{}' WHERE round_id = '{}' AND wallet_id = '{}'",
                hex::encode(commitment.to_repr()),
                ROUND_ID,
                WALLET_ID
            );
            let bytes = delegation_fixture::corrupt(&db.serialize_bytes().unwrap(), &sql);
            return VotingDb::open_browser(WALLET_ID, zcash_voting::Network::Testnet, Some(&bytes))
                .unwrap();
        }
        db
    }

    #[tokio::test]
    async fn async_tree_initial_paged_and_incremental_sync_produce_valid_witnesses() {
        let db = db(Some((0, Fp::from(1))));
        let api = AsyncServer::new(3, 1);
        let sync = VoteTreeSync::new();

        let height = sync.sync_with_async_api(&db, ROUND_ID, &api).await.unwrap();
        assert_eq!(height, 3);
        assert_eq!(
            sync.generate_van_witness(&db, ROUND_ID, 0, 3)
                .unwrap()
                .position,
            0
        );
        assert!(api.requests().len() >= 3);

        api.append_block();
        let height = sync.sync_with_async_api(&db, ROUND_ID, &api).await.unwrap();
        assert_eq!(height, 4);
        assert!(api
            .requests()
            .iter()
            .any(|(from, to)| *from == 4 && *to == 4));
    }

    #[tokio::test]
    async fn async_tree_binds_same_size_empty_height_advancement() {
        let db = db(Some((0, Fp::from(1))));
        let mut api = AsyncServer::new(1, 1);
        api.omit_empty_blocks = true;
        let sync = VoteTreeSync::new();
        assert_eq!(
            sync.sync_with_async_api(&db, ROUND_ID, &api).await.unwrap(),
            1
        );

        api.append_empty_block();
        assert_eq!(
            sync.sync_with_async_api(&db, ROUND_ID, &api).await.unwrap(),
            2
        );
        assert_eq!(api.requests().last(), Some(&(2, 2)));
        assert_eq!(api.root_requests().last(), Some(&2));
        assert_eq!(
            sync.generate_van_witness(&db, ROUND_ID, 0, 2)
                .unwrap()
                .anchor_height,
            2
        );
    }

    #[tokio::test]
    async fn async_tree_authenticates_initial_empty_checkpoint() {
        let db = db(None);
        let mut valid = AsyncServer::new(0, 1);
        valid.omit_empty_blocks = true;
        valid.append_empty_block();
        let sync = VoteTreeSync::new();
        assert_eq!(
            sync.sync_with_async_api(&db, ROUND_ID, &valid)
                .await
                .unwrap(),
            1
        );
        assert_eq!(valid.root_requests(), vec![1]);

        let mut mismatched = AsyncServer::new(0, 1);
        mismatched.omit_empty_blocks = true;
        mismatched.append_empty_block();
        mismatched.corrupt_state_root = true;
        let sync = VoteTreeSync::new();
        assert!(sync
            .sync_with_async_api(&db, ROUND_ID, &mismatched)
            .await
            .is_err());
    }

    #[tokio::test]
    async fn async_tree_rejects_root_or_confirmed_leaf_mismatch_and_withholds_witness() {
        let mismatched_db = db(Some((0, Fp::from(9))));
        let api = AsyncServer::new(1, 1);
        let sync = VoteTreeSync::new();
        assert!(sync
            .sync_with_async_api(&mismatched_db, ROUND_ID, &api)
            .await
            .is_err());
        assert!(sync
            .generate_van_witness(&mismatched_db, ROUND_ID, 0, 1)
            .is_err());

        let db = db(Some((0, Fp::from(1))));
        let mut api = AsyncServer::new(1, 1);
        api.corrupt_root = true;
        let sync = VoteTreeSync::new();
        assert!(sync.sync_with_async_api(&db, ROUND_ID, &api).await.is_err());
        assert!(sync.generate_van_witness(&db, ROUND_ID, 0, 1).is_err());

        let mut api = AsyncServer::new(1, 1);
        api.corrupt_anchor_root = true;
        let sync = VoteTreeSync::new();
        assert!(sync.sync_with_async_api(&db, ROUND_ID, &api).await.is_err());
        assert!(sync.generate_van_witness(&db, ROUND_ID, 0, 1).is_err());
    }

    #[tokio::test]
    async fn async_tree_position_beyond_tip_and_fetch_failure_retain_incremental_progress() {
        let db = db(Some((2, Fp::from(3))));
        let api = AsyncServer::new(2, 1);
        let sync = VoteTreeSync::new();
        assert!(sync.sync_with_async_api(&db, ROUND_ID, &api).await.is_err());
        assert!(sync.generate_van_witness(&db, ROUND_ID, 0, 2).is_err());
        api.append_block();
        assert_eq!(
            sync.sync_with_async_api(&db, ROUND_ID, &api).await.unwrap(),
            3
        );
        assert_eq!(
            sync.generate_van_witness(&db, ROUND_ID, 0, 3)
                .unwrap()
                .position,
            2
        );

        api.append_block();
        api.append_block();
        api.fail_once_on_page(api.page_number.load(Ordering::SeqCst) + 1);
        assert!(sync.sync_with_async_api(&db, ROUND_ID, &api).await.is_err());
        assert!(sync.generate_van_witness(&db, ROUND_ID, 0, 3).is_err());
        assert_eq!(
            sync.sync_with_async_api(&db, ROUND_ID, &api).await.unwrap(),
            5
        );
        assert!(api.requests().iter().filter(|(from, _)| *from == 5).count() >= 2);
    }

    #[tokio::test]
    async fn async_tree_state_fetch_failure_preserves_previously_validated_tree() {
        let db = db(Some((0, Fp::from(1))));
        let api = AsyncServer::new(1, 1);
        let sync = VoteTreeSync::new();
        assert_eq!(
            sync.sync_with_async_api(&db, ROUND_ID, &api).await.unwrap(),
            1
        );

        api.fail_state.store(true, Ordering::SeqCst);
        assert!(sync.sync_with_async_api(&db, ROUND_ID, &api).await.is_err());
        assert_eq!(
            sync.generate_van_witness(&db, ROUND_ID, 0, 1)
                .unwrap()
                .position,
            0
        );
    }

    #[tokio::test]
    async fn async_tree_rejects_malformed_and_truncated_pagination() {
        {
            let db = db(Some((0, Fp::from(1))));
            let mut api = AsyncServer::new(1, 1);
            let sync = VoteTreeSync::new();
            assert_eq!(
                sync.sync_with_async_api(&db, ROUND_ID, &api).await.unwrap(),
                1
            );
            api.append_block();
            api.cursor_fault = CursorFault::NonProgressing;
            assert!(sync.sync_with_async_api(&db, ROUND_ID, &api).await.is_err());
            assert!(sync.generate_van_witness(&db, ROUND_ID, 0, 1).is_err());
        }
        for fault in [CursorFault::Overshooting, CursorFault::Truncated] {
            let db = db(Some((0, Fp::from(1))));
            let mut api = AsyncServer::new(2, 1);
            api.cursor_fault = fault;
            let sync = VoteTreeSync::new();
            assert!(sync.sync_with_async_api(&db, ROUND_ID, &api).await.is_err());
            assert!(sync.generate_van_witness(&db, ROUND_ID, 0, 1).is_err());
        }
    }

    struct ExcessivePagesApi(AtomicUsize);

    impl AsyncTreeSyncApi for ExcessivePagesApi {
        type Error = Infallible;

        fn get_tree_state(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<TreeState, Infallible>> + Send>> {
            Box::pin(async {
                Ok(TreeState {
                    next_index: 1,
                    root: Fp::one(),
                    height: 10_000,
                })
            })
        }

        fn get_root_at_height(
            &self,
            _height: u32,
        ) -> Pin<Box<dyn Future<Output = Result<Option<Fp>, Infallible>> + Send>> {
            unreachable!()
        }

        fn get_block_commitments(
            &self,
            from_height: u32,
            _to_height: u32,
        ) -> Pin<Box<dyn Future<Output = Result<BlockCommitmentsPage, Infallible>> + Send>>
        {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async move {
                Ok(BlockCommitmentsPage {
                    blocks: Vec::new(),
                    next_from_height: from_height + 1,
                })
            })
        }
    }

    #[tokio::test]
    async fn async_tree_page_count_is_bounded() {
        let db = db(None);
        let api = ExcessivePagesApi(AtomicUsize::new(0));
        let error = VoteTreeSync::new()
            .sync_with_async_api(&db, ROUND_ID, &api)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("page limit"), "{error}");
        assert_eq!(
            api.0.load(Ordering::SeqCst),
            vote_commitment_tree::SyncLimits::default().max_pages
        );
    }

    struct PendingStateApi(Mutex<Option<oneshot::Receiver<()>>>);

    impl AsyncTreeSyncApi for PendingStateApi {
        type Error = Infallible;

        fn get_tree_state(
            &self,
        ) -> Pin<Box<dyn Future<Output = Result<TreeState, Infallible>> + Send>> {
            let receiver = self.0.lock().unwrap().take().unwrap();
            Box::pin(async move {
                let _ = receiver.await;
                Ok(TreeSyncApi::get_tree_state(&MemoryTreeServer::empty()).unwrap())
            })
        }

        fn get_root_at_height(
            &self,
            _height: u32,
        ) -> Pin<Box<dyn Future<Output = Result<Option<Fp>, Infallible>> + Send>> {
            unreachable!()
        }

        fn get_block_commitments(
            &self,
            _from_height: u32,
            _to_height: u32,
        ) -> Pin<Box<dyn Future<Output = Result<BlockCommitmentsPage, Infallible>> + Send>>
        {
            unreachable!()
        }
    }

    #[tokio::test]
    async fn async_tree_cancellation_releases_lease_and_reset_invalidates_in_flight_sync() {
        let db = db(None);
        let sync = VoteTreeSync::new();
        let (_release, receiver) = oneshot::channel();
        let api = PendingStateApi(Mutex::new(Some(receiver)));
        {
            let future = sync.sync_with_async_api(&db, ROUND_ID, &api);
            futures_util::pin_mut!(future);
            assert!(futures_util::poll!(future.as_mut()).is_pending());
            assert!(sync
                .sync_with_async_api(&db, ROUND_ID, &AsyncServer::new(0, 1))
                .await
                .is_err());
        }
        assert_eq!(
            sync.sync_with_async_api(&db, ROUND_ID, &AsyncServer::new(0, 1))
                .await
                .unwrap(),
            0
        );

        let (release, receiver) = oneshot::channel();
        let api = PendingStateApi(Mutex::new(Some(receiver)));
        let future = sync.sync_with_async_api(&db, ROUND_ID, &api);
        futures_util::pin_mut!(future);
        assert!(futures_util::poll!(future.as_mut()).is_pending());
        sync.reset(ROUND_ID).unwrap();
        release.send(()).unwrap();
        assert!(future.await.is_err());
        assert_eq!(
            sync.sync_with_async_api(&db, ROUND_ID, &AsyncServer::new(0, 1))
                .await
                .unwrap(),
            0
        );
    }
}
