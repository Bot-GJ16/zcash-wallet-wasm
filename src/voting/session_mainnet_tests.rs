use super::*;
use std::cell::RefCell;
use zcash_voting::delegation_submission::CanonicalDelegation;

// These protocol fixtures carry real signatures but placeholder proof bytes;
// they exercise orchestration and durability, not ZKP validity or live voting.

struct DelegationChain {
    canonical: CanonicalDelegation,
    requests: Mutex<Vec<OwnedHttpRequest>>,
}

impl HttpTransport for DelegationChain {
    fn execute(&self, request: OwnedHttpRequest) -> TransportFuture {
        let post = request.method == "POST";
        if post {
            assert_eq!(request.body, self.canonical.json_bytes());
            assert!(request.url.ends_with("/shielded-vote/v1/delegate-vote"));
        } else {
            assert_eq!(request.method, "GET");
            assert!(request.url.ends_with(self.canonical.tx_hash()));
        }
        self.requests.lock().unwrap().push(request);
        let body = if post {
            serde_json::json!({"code": 0, "tx_hash": self.canonical.tx_hash()})
        } else {
            serde_json::json!({
                "height": "42",
                "code": 0,
                "events": [{
                    "type": "delegate_vote",
                    "attributes": [
                        {"key": "vote_round_id", "value": ID},
                        {"key": "leaf_index", "value": "41"}
                    ]
                }]
            })
        };
        Box::pin(std::future::ready(Ok(OwnedHttpResponse {
            status: 200,
            content_type: None,
            body: serde_json::to_vec(&body).unwrap(),
        })))
    }
}

#[tokio::test]
async fn legacy_delegation_hash_without_a_journal_is_polled_without_reposting() {
    use crate::voting::network::VotingNetwork;

    let (initial, round) = BallotFixture::session_and_round(VotingNetwork::Testnet, false).await;
    let envelope = VotingSessionEnvelope::encode(initial.network, &round.identity()).unwrap();
    initial
        .db
        .init_round(
            VotingNetwork::Testnet.network(),
            &round.params,
            Some(&envelope),
        )
        .unwrap();
    let canonical = delegation_fixture::prepare_for_stored_network(&initial.db, &round.params, 17);
    let old_bytes = delegation_fixture::corrupt(
        &initial.db.serialize_bytes().unwrap(),
        &format!(
            "UPDATE bundles SET delegation_tx_hash='{0}';
             INSERT INTO legacy_delegation_evidence
             SELECT round_id,wallet_id,bundle_index,delegation_tx_hash FROM bundles",
            canonical.tx_hash()
        ),
    );
    let session = VotingSessionInner::open(
        initial.wallet.clone(),
        initial.account_id,
        Some(&old_bytes),
        Persistence::default(),
    )
    .unwrap();
    session
        .trusted_rounds
        .borrow_mut()
        .insert(ID.into(), round.clone());
    let chain = DelegationChain {
        canonical,
        requests: Mutex::new(Vec::new()),
    };
    let durable = Arc::new(Mutex::new(old_bytes));
    session
        .submit_ballot_with(
            ID,
            None,
            &chain,
            || std::future::ready(Ok(round.clone())),
            |_, _, _| async { panic!("legacy delegation must not build a vote") },
            || async {
                *durable.lock().unwrap() = session.db.serialize_bytes().unwrap();
                Ok(())
            },
            || Ok(1500),
        )
        .await
        .unwrap();
    assert_eq!(session.db.load_van_position(ID, 0).unwrap(), 41);
    session.validate_submission_state(ID).unwrap();
    assert_eq!(
        chain
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.method.as_str())
            .collect::<Vec<_>>(),
        vec!["GET"]
    );
}

#[tokio::test]
async fn mainnet_prepare_delegation_ballot_confirmation_and_reload_stay_bound() {
    use crate::voting::network::VotingNetwork;

    let (session, round) = BallotFixture::session_and_round(VotingNetwork::Mainnet, false).await;
    let durable = Arc::new(Mutex::new(Vec::new()));
    let generated = RefCell::new(None);
    let prepared = session
        .prepare_round_with(
            ID,
            |trusted| {
                assert_eq!(trusted.network, VotingNetwork::Mainnet);
                let envelope =
                    VotingSessionEnvelope::encode(session.network, &trusted.identity()).unwrap();
                session
                    .db
                    .init_round(session.network.network(), &trusted.params, Some(&envelope))
                    .unwrap();
                let canonical = delegation_fixture::prepare_for_stored_network(
                    &session.db,
                    &trusted.params,
                    17,
                );
                generated.replace(Some(canonical));
                std::future::ready(Ok(PreparedVotingRound {
                    round_id: ID.into(),
                    bundle_count: 1,
                    selected_note_count: 1,
                    voting_power: "1".into(),
                    state: VotingRoundPhase::RoundPrepared,
                }))
            },
            || async {
                *durable.lock().unwrap() = session.export_state().unwrap();
                Ok(())
            },
            || Ok(1500),
        )
        .await
        .unwrap();
    assert_eq!(prepared.state, VotingRoundPhase::RoundPrepared);
    let canonical = generated.into_inner().unwrap();
    let chain = DelegationChain {
        canonical: canonical.clone(),
        requests: Mutex::new(Vec::new()),
    };
    let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
        &crate::Network::MainNetwork,
        &[17; 32],
        zip32::AccountId::ZERO,
    )
    .unwrap();
    let fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&[17; 32]).unwrap();
    let delegated = session
        .submit_delegation_with(
            ID,
            usk,
            fingerprint,
            &chain,
            || std::future::ready(Ok(round.clone())),
            |_, _| std::future::ready(Ok(canonical.clone())),
            || async {
                *durable.lock().unwrap() = session.export_state().unwrap();
                Ok(())
            },
            || Ok(1500),
        )
        .await
        .unwrap();
    assert_eq!(delegated.phase, VotingRoundPhase::DelegationConfirmed);
    let delegation_requests = chain.requests.lock().unwrap();
    assert_eq!(delegation_requests.len(), 2);
    assert!(
        delegation_requests
            .iter()
            .all(|request| fixture_url(&round.vote_server_urls, &request.url))
    );
    drop(delegation_requests);

    let fixture = BallotFixture::from_confirmed_delegation(session, round, false);
    let mut transport = fixture.transport(durable.clone(), Stop::None);
    transport.confirm_helpers = true;
    let result = fixture
        .session
        .submit_ballot_with(
            ID,
            Some(vec![BallotDecision::Choice {
                proposal_id: 1,
                option: 0,
            }]),
            &transport,
            || std::future::ready(Ok(fixture.round.clone())),
            |_, _, _| {
                std::future::ready(Ok(BallotFixture::store(
                    &fixture.session.db,
                    &fixture.recoveries,
                )))
            },
            || async {
                *durable.lock().unwrap() = fixture.session.export_state().unwrap();
                Ok(())
            },
            || Ok(1500),
        )
        .await
        .unwrap();
    assert_eq!(result.phase, VotingRoundPhase::SharesConfirmed);
    assert!(
        transport
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|request| fixture_url(&fixture.round.vote_server_urls, &request.url))
    );
    let helper_requests = transport.helper_requests.lock().unwrap();
    assert!(!helper_requests.is_empty());
    assert!(
        helper_requests
            .iter()
            .all(|request| fixture_url(&fixture.round.vote_server_urls, &request.url))
    );

    let exported = durable.lock().unwrap().clone();
    let reopened = fixture.reopen(&exported);
    assert_eq!(reopened.network, VotingNetwork::Mainnet);
    assert_eq!(
        reopened.round_status_at(ID, 1500).unwrap().phase,
        VotingRoundPhase::SharesConfirmed
    );
    assert_eq!(
        reopened.saved_identity(ID).unwrap(),
        Some(fixture.round.identity())
    );
}

fn fixture_url(bases: &[String], url: &str) -> bool {
    bases.iter().any(|base| url.starts_with(base))
}

#[tokio::test]
async fn mainnet_atomic_batch_confirmation_and_reload_use_the_stored_network() {
    use crate::voting::network::VotingNetwork;

    let fixture = BallotFixture::new_for(VotingNetwork::Mainnet, true).await;
    assert!(fixture.canonical.is_batch());
    let durable = Arc::new(Mutex::new(fixture.session.export_state().unwrap()));
    let mut transport = fixture.transport(durable.clone(), Stop::None);
    transport.confirm_helpers = true;
    let decisions = fixture
        .roster()
        .into_iter()
        .map(|proposal_id| BallotDecision::Choice {
            proposal_id,
            option: 0,
        })
        .collect();
    let result = fixture
        .session
        .submit_ballot_with(
            ID,
            Some(decisions),
            &transport,
            || std::future::ready(Ok(fixture.round.clone())),
            |_, _, _| {
                std::future::ready(Ok(BallotFixture::store(
                    &fixture.session.db,
                    &fixture.recoveries,
                )))
            },
            || async {
                *durable.lock().unwrap() = fixture.session.export_state().unwrap();
                Ok(())
            },
            || Ok(1500),
        )
        .await
        .unwrap();
    assert_eq!(result.phase, VotingRoundPhase::SharesConfirmed);
    assert_eq!(
        fixture
            .reopen(&durable.lock().unwrap())
            .round_status_at(ID, 1500)
            .unwrap()
            .confirmed_helpers,
        32
    );
}

#[tokio::test]
async fn mainnet_failed_checkpoint_before_vote_dispatch_has_no_network_effect() {
    use crate::voting::network::VotingNetwork;

    let fixture = BallotFixture::new_for(VotingNetwork::Mainnet, false).await;
    let durable = Arc::new(Mutex::new(fixture.session.export_state().unwrap()));
    let transport = fixture.transport(durable.clone(), Stop::None);
    let checkpoints = Cell::new(0);
    let error = fixture
        .session
        .submit_ballot_with(
            ID,
            Some(vec![BallotDecision::Choice {
                proposal_id: 1,
                option: 0,
            }]),
            &transport,
            || std::future::ready(Ok(fixture.round.clone())),
            |_, _, _| {
                std::future::ready(Ok(BallotFixture::store(
                    &fixture.session.db,
                    &fixture.recoveries,
                )))
            },
            || async {
                checkpoints.set(checkpoints.get() + 1);
                if checkpoints.get() == 3 {
                    return Err(VotingApiError::new(VotingErrorCode::PersistenceFailed));
                }
                *durable.lock().unwrap() = fixture.session.export_state().unwrap();
                Ok(())
            },
            || Ok(1500),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code, VotingErrorCode::SubmissionUnknown);
    assert_eq!(checkpoints.get(), 3);
    assert!(transport.requests.lock().unwrap().is_empty());
}

#[tokio::test]
async fn mainnet_unknown_vote_post_resumes_by_polling_without_reposting() {
    use crate::voting::network::VotingNetwork;

    let fixture = BallotFixture::new_for(VotingNetwork::Mainnet, false).await;
    let durable = Arc::new(Mutex::new(fixture.session.export_state().unwrap()));
    let transport = fixture.transport(durable.clone(), Stop::UnknownPost);
    let pending = fixture
        .session
        .submit_ballot_with(
            ID,
            Some(vec![BallotDecision::Choice {
                proposal_id: 1,
                option: 0,
            }]),
            &transport,
            || std::future::ready(Ok(fixture.round.clone())),
            |_, _, _| {
                std::future::ready(Ok(BallotFixture::store(
                    &fixture.session.db,
                    &fixture.recoveries,
                )))
            },
            || async {
                *durable.lock().unwrap() = fixture.session.export_state().unwrap();
                Ok(())
            },
            || Ok(1500),
        )
        .await
        .unwrap();
    assert_eq!(pending.next_action, "poll_vote");
    assert_eq!(
        transport
            .requests
            .lock()
            .unwrap()
            .iter()
            .filter(|request| request.method == "POST")
            .count(),
        1
    );

    let reopened = fixture.reopen(&durable.lock().unwrap());
    let mut resumed = fixture.transport(durable.clone(), Stop::None);
    resumed.confirm_helpers = true;
    let result = reopened
        .submit_ballot_with(
            ID,
            None,
            &resumed,
            || std::future::ready(Ok(fixture.round.clone())),
            |_, _, _| async { panic!("ambiguous vote resume regenerated a vote") },
            || async {
                *durable.lock().unwrap() = reopened.export_state().unwrap();
                Ok(())
            },
            || Ok(1500),
        )
        .await
        .unwrap();
    assert_eq!(result.phase, VotingRoundPhase::SharesConfirmed);
    let requests = resumed.requests.lock().unwrap();
    assert_eq!(requests[0].method, "GET");
    assert!(requests.iter().all(|request| {
        request.method != "POST" || !request.url.ends_with("/shielded-vote/v1/cast-vote")
    }));
}

#[tokio::test]
async fn mainnet_corrupted_recovery_bindings_fail_closed_on_reopen() {
    use crate::voting::network::VotingNetwork;

    let fixture = BallotFixture::new_for(VotingNetwork::Mainnet, false).await;
    let bytes = fixture.session.export_state().unwrap();
    for sql in [
        "UPDATE rounds SET network='testnet'",
        "UPDATE rounds SET session_json=json_set(session_json,'$.network','testnet')",
        "UPDATE rounds SET session_json=json_set(session_json,'$.environment','stage')",
        "UPDATE rounds SET session_json=json_set(session_json,'$.staticConfigDigest','00')",
        "UPDATE rounds SET session_json=json_set(session_json,'$.version',1)",
    ] {
        let corrupted = delegation_fixture::corrupt(&bytes, sql);
        let error = VotingSessionInner::open(
            fixture.session.wallet.clone(),
            fixture.session.account_id,
            Some(&corrupted),
            Persistence::default(),
        )
        .err()
        .unwrap();
        assert_eq!(error.code, VotingErrorCode::RecoveryConflict, "{sql}");
    }
}
