//! Actual ballot driver tests with SQLite checkpoints and cancellable transport.
use super::*;
use futures_util::{future::pending, poll};
use std::sync::{Arc, Mutex};
use zcash_voting::{
    platform::{HttpTransport, OwnedHttpRequest, OwnedHttpResponse, TransportFuture},
    vote::{self, DraftVote, VoteRecoveryBundle},
    vote_submission::{CanonicalVoteSubmission, VoteSubmissionOutcome},
};

const ID: &str = "0000000000000000000000000000000000000000000000000000000000000001";

#[path = "session_helper_tests.rs"]
mod helper_recovery;

#[path = "session_mainnet_tests.rs"]
mod mainnet_workflow;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stop {
    None,
    Checkpoint { number: usize, saved: bool },
    Post,
    UnknownPost,
    ConfirmationResponse,
}

struct RecordingTransport {
    wallet_id: String,
    durable: Arc<Mutex<Vec<u8>>>,
    requests: Mutex<Vec<OwnedHttpRequest>>,
    helper_requests: Mutex<Vec<OwnedHttpRequest>>,
    canonical: CanonicalVoteSubmission,
    confirmation: Vec<u8>,
    network: zcash_voting::Network,
    stop: Stop,
    confirm_helpers: bool,
}

impl HttpTransport for RecordingTransport {
    fn execute(&self, request: OwnedHttpRequest) -> TransportFuture {
        if request.url.ends_with("/status")
            || request.url.contains("/share-status/")
            || request.url.ends_with("/shares")
        {
            let status = if request.url.ends_with("/shares") {
                "queued"
            } else if request.url.ends_with("/status") {
                "ok"
            } else if self.confirm_helpers {
                "confirmed"
            } else {
                "pending"
            };
            self.helper_requests.lock().unwrap().push(request);
            return Box::pin(std::future::ready(Ok(OwnedHttpResponse {
                status: 200,
                body: serde_json::to_vec(&serde_json::json!({ "status": status })).unwrap(),
                content_type: Some("application/json".into()),
            })));
        }
        let post = request.method == "POST";
        // Fetch may dispatch when its future is constructed: inspect the last
        // acknowledged host checkpoint at this boundary, not the live database.
        let db = VotingDb::open_browser(
            &self.wallet_id,
            self.network,
            Some(&self.durable.lock().unwrap()),
        )
        .unwrap();
        let attempt = db.vote_submission(ID, 0, 1).unwrap().unwrap();
        assert!(attempt.canonical.json_bytes() == self.canonical.json_bytes());
        if post {
            assert_eq!(attempt.outcome, VoteSubmissionOutcome::Dispatching);
            assert!(request.body == self.canonical.json_bytes());
            assert!(request.url.ends_with(if self.canonical.is_batch() {
                "/shielded-vote/v1/cast-vote-batch"
            } else {
                "/shielded-vote/v1/cast-vote"
            }));
        } else {
            assert_eq!(request.method, "GET");
            assert!(request.url.ends_with(&format!(
                "/shielded-vote/v1/tx/{}",
                self.canonical.tx_hash()
            )));
        }
        self.requests.lock().unwrap().push(request);
        if post && self.stop == Stop::UnknownPost {
            return Box::pin(std::future::ready(Err(
                zcash_voting::platform::TransportError::Ambiguous,
            )));
        }
        if !post && self.stop == Stop::UnknownPost {
            return Box::pin(std::future::ready(Ok(OwnedHttpResponse {
                content_type: None,
                status: 404,
                body: Vec::new(),
            })));
        }
        if (post && self.stop == Stop::Post) || (!post && self.stop == Stop::ConfirmationResponse) {
            return Box::pin(pending());
        }
        let body = if post {
            serde_json::to_vec(&serde_json::json!({"tx_hash": self.canonical.tx_hash(), "code": 0}))
                .unwrap()
        } else {
            self.confirmation.clone()
        };
        Box::pin(std::future::ready(Ok(OwnedHttpResponse {
            content_type: None,
            status: 200,
            body,
        })))
    }
}

struct BallotFixture {
    session: VotingSessionInner,
    round: TrustedRound,
    recoveries: Vec<VoteRecoveryBundle>,
    canonical: CanonicalVoteSubmission,
    confirmation: Vec<u8>,
}

impl BallotFixture {
    async fn new(batch: bool) -> Self {
        Self::new_for(super::super::network::VotingNetwork::Testnet, batch).await
    }

    async fn session_and_round(
        network: super::super::network::VotingNetwork,
        batch: bool,
    ) -> (VotingSessionInner, TrustedRound) {
        let (session, mut round) = super::tests::session_for(network).await;
        round.helpers = (1..=2)
            .map(|index| HelperEndpoint {
                id: format!("helper-{index}"),
                url: format!("https://helper-{index}.example"),
                public_key: vec![index; 32],
            })
            .collect();
        if network == super::super::network::VotingNetwork::Mainnet {
            round.vote_server_urls = round
                .helpers
                .iter()
                .map(|helper| helper.url.clone())
                .collect();
        }
        round.params.snapshot_height = delegation_fixture::height_for(network.network());
        round.summary.snapshot_height = round.params.snapshot_height;
        if batch {
            let mut proposal = round.proposals[0].clone();
            proposal.proposal_id = 2;
            round.proposals.push(proposal);
        }
        session
            .trusted_rounds
            .borrow_mut()
            .insert(ID.into(), round.clone());
        (session, round)
    }

    async fn new_for(network: super::super::network::VotingNetwork, batch: bool) -> Self {
        let (session, round) = Self::session_and_round(network, batch).await;
        let envelope = VotingSessionEnvelope::encode(network, &round.identity()).unwrap();
        session
            .db
            .init_round(network.network(), &round.params, Some(&envelope))
            .unwrap();
        let delegation =
            delegation_fixture::prepare_for_stored_network(&session.db, &round.params, 17);
        session
            .db
            .prepare_delegation_submission(ID, 0, &delegation)
            .unwrap();
        session.db.mark_delegation_dispatching(ID, 0).unwrap();
        session
            .db
            .confirm_journaled_delegation(
                ID,
                0,
                delegation.tx_hash(),
                &[delegation_fixture::event(ID, "41")],
            )
            .unwrap();
        Self::from_confirmed_delegation(session, round, batch)
    }

    fn from_confirmed_delegation(
        session: VotingSessionInner,
        round: TrustedRound,
        batch: bool,
    ) -> Self {
        let drafts = round
            .proposals
            .iter()
            .map(|p| DraftVote {
                proposal_id: p.proposal_id,
                choice: 0,
                num_options: 2,
                single_share: false,
                vc_tree_position: 0,
            })
            .collect::<Vec<_>>();
        let recoveries = vote::synthetic_recovery_fixtures(&session.db, ID, 0, &drafts).unwrap();
        let mut attributes = vec![serde_json::json!({"key":"vote_round_id", "value":ID})];
        if batch {
            let digest = recoveries[0].batch.as_ref().unwrap().digest;
            for (key, value) in [
                ("batch_digest", hex::encode(digest)),
                ("batch_size", "2".into()),
                ("final_van_leaf_index", "50".into()),
                ("vote_commitment_leaf_indices", "51,52".into()),
                ("proposal_ids", "1,2".into()),
                (
                    "van_nullifiers",
                    format!("{},{}", hex::encode([1; 32]), hex::encode([2; 32])),
                ),
            ] {
                attributes.push(serde_json::json!({"key":key,"value":value}));
            }
        } else {
            attributes.push(serde_json::json!({"key":"leaf_index","value":"50,51"}));
        }
        let confirmation = serde_json::to_vec(&serde_json::json!({
            "height":"1", "code":0, "log":"", "events":[{
                "type": if batch { "cast_vote_batch" } else { "cast_vote" }, "attributes":attributes
            }]
        }))
        .unwrap();
        // Generate the expected canonical bytes in a separate database. The
        // submitted session starts with confirmed delegation and no vote rows.
        let expected = VotingDb::open_browser(
            &session.wallet_id,
            round.network.network(),
            Some(&session.db.serialize_bytes().unwrap()),
        )
        .unwrap();
        let canonical = Self::store(&expected, &recoveries);
        Self {
            session,
            round,
            recoveries,
            canonical,
            confirmation,
        }
    }

    fn store(db: &VotingDb, recoveries: &[VoteRecoveryBundle]) -> CanonicalVoteSubmission {
        for recovery in recoveries {
            vote::insert_recovery_fixture(db, recovery).unwrap();
        }
        if recoveries.len() == 1 {
            CanonicalVoteSubmission::from_singleton(&vote::submission(db, ID, 0, 1).unwrap())
                .unwrap()
        } else {
            CanonicalVoteSubmission::from_batch(
                &vote::recover_atomic_vote_batch(db, ID, 0, 1).unwrap(),
            )
            .unwrap()
        }
    }

    fn reopen(&self, bytes: &[u8]) -> VotingSessionInner {
        let session = VotingSessionInner::open(
            self.session.wallet.clone(),
            self.session.account_id,
            Some(bytes),
            Persistence::default(),
        )
        .unwrap();
        session
            .trusted_rounds
            .borrow_mut()
            .insert(ID.into(), self.round.clone());
        session
    }

    fn transport(&self, durable: Arc<Mutex<Vec<u8>>>, stop: Stop) -> RecordingTransport {
        RecordingTransport {
            wallet_id: self.session.wallet_id.clone(),
            durable,
            requests: Mutex::new(vec![]),
            helper_requests: Mutex::new(vec![]),
            canonical: self.canonical.clone(),
            confirmation: self.confirmation.clone(),
            network: self.round.network.network(),
            stop,
            confirm_helpers: false,
        }
    }

    fn roster(&self) -> Vec<u32> {
        self.round.proposals.iter().map(|p| p.proposal_id).collect()
    }

    fn assert_canonical(&self, session: &VotingSessionInner) {
        let attempt = session.db.vote_submission(ID, 0, 1).unwrap().unwrap();
        assert!(attempt.canonical.json_bytes() == self.canonical.json_bytes());
        assert!(attempt.canonical.tx_hash() == self.canonical.tx_hash());
        session.validate_submission_state(ID).unwrap();
    }
}

async fn interruption_matrix(batch: bool) {
    let fixture = BallotFixture::new(batch).await;
    let initial = fixture.session.db.serialize_bytes().unwrap();
    let submit = if batch {
        "submit_vote_batch"
    } else {
        "submit_vote"
    };
    let poll_vote = if batch {
        "poll_vote_batch"
    } else {
        "poll_vote"
    };
    for (stop, expected_next, sent, resumed) in [
        (
            Stop::Checkpoint {
                number: 2,
                saved: true,
            },
            submit,
            0,
            vec!["POST", "GET"],
        ),
        (
            Stop::Checkpoint {
                number: 3,
                saved: false,
            },
            submit,
            0,
            vec!["POST", "GET"],
        ),
        (
            Stop::Checkpoint {
                number: 3,
                saved: true,
            },
            poll_vote,
            0,
            vec!["GET"],
        ),
        (Stop::Post, poll_vote, 1, vec!["GET"]),
        (
            Stop::Checkpoint {
                number: 4,
                saved: false,
            },
            poll_vote,
            1,
            vec!["GET"],
        ),
        (
            Stop::Checkpoint {
                number: 4,
                saved: true,
            },
            poll_vote,
            1,
            vec!["GET"],
        ),
        (Stop::ConfirmationResponse, poll_vote, 2, vec!["GET"]),
        (
            Stop::Checkpoint {
                number: 5,
                saved: false,
            },
            poll_vote,
            2,
            vec!["GET"],
        ),
        (
            Stop::Checkpoint {
                number: 5,
                saved: true,
            },
            "submit_shares",
            2,
            vec![],
        ),
        (Stop::None, "confirm_share", 2, vec![]),
    ] {
        let session = fixture.reopen(&initial);
        let durable = Arc::new(Mutex::new(initial.clone()));
        let transport = fixture.transport(durable.clone(), stop);
        let checkpoints = Cell::new(0);
        let builds = Cell::new(0);
        let decisions = fixture
            .roster()
            .into_iter()
            .map(|proposal_id| BallotDecision::Choice {
                proposal_id,
                option: 0,
            })
            .collect();
        let mut future = Box::pin(session.submit_ballot_with(
            ID,
            Some(decisions),
            &transport,
            || std::future::ready(Ok(fixture.round.clone())),
            |_, bundle, drafts: Vec<DraftVote>| {
                builds.set(builds.get() + 1);
                assert_eq!(bundle, 0);
                assert_eq!(
                    drafts.iter().map(|d| d.proposal_id).collect::<Vec<_>>(),
                    fixture.roster()
                );
                assert!(
                    drafts
                        .iter()
                        .all(|d| d.choice == 0 && d.num_options == 2 && !d.single_share)
                );
                std::future::ready(Ok(BallotFixture::store(&session.db, &fixture.recoveries)))
            },
            || async {
                checkpoints.set(checkpoints.get() + 1);
                let number = checkpoints.get();
                let durable = &durable;
                session
                    .persistence
                    .revision
                    .checkpoint(
                        || Ok(session.db.serialize_bytes().unwrap()),
                        |bytes, _| async move {
                            if stop
                                == (Stop::Checkpoint {
                                    number,
                                    saved: false,
                                })
                            {
                                pending::<()>().await;
                            }
                            *durable.lock().unwrap() = bytes;
                            if stop
                                == (Stop::Checkpoint {
                                    number,
                                    saved: true,
                                })
                            {
                                pending::<()>().await;
                            }
                            Ok(())
                        },
                    )
                    .await
            },
            || Ok(1500),
        ));
        if stop == Stop::None {
            assert_eq!(
                future.as_mut().await.unwrap().phase,
                VotingRoundPhase::VoteConfirmed
            );
        } else {
            assert!(poll!(&mut future).is_pending(), "{stop:?}");
        }
        drop(future);
        assert!(!session.mutation_active.get());
        assert_eq!(builds.get(), 1);
        assert_eq!(transport.requests.lock().unwrap().len(), sent, "{stop:?}");
        drop(session);
        let reopened = fixture.reopen(&durable.lock().unwrap());
        fixture.assert_canonical(&reopened);
        let plan = resume_plan(&reopened.db, ID, &fixture.roster()).unwrap();
        assert_eq!(
            browser_step_kind(&reopened.db, ID, &plan.next_steps[0]).unwrap(),
            expected_next,
            "{stop:?}"
        );
        let transport = fixture.transport(durable.clone(), Stop::None);
        let result = reopened
            .submit_ballot_with(
                ID,
                None,
                &transport,
                || std::future::ready(Ok(fixture.round.clone())),
                |_, _, _| async { panic!("resume must not regenerate a persisted vote") },
                || async {
                    *durable.lock().unwrap() = reopened.db.serialize_bytes().unwrap();
                    Ok(())
                },
                || Ok(1500),
            )
            .await
            .unwrap();
        assert_eq!(result.phase, VotingRoundPhase::VoteConfirmed);
        assert_eq!(
            transport
                .requests
                .lock()
                .unwrap()
                .iter()
                .map(|r| r.method.as_str())
                .collect::<Vec<_>>(),
            resumed,
            "{stop:?}"
        );
        fixture.assert_canonical(&reopened);
        assert_eq!(
            browser_step_kind(
                &reopened.db,
                ID,
                &resume_plan(&reopened.db, ID, &fixture.roster())
                    .unwrap()
                    .next_steps[0],
            )
            .unwrap(),
            "confirm_share"
        );
    }
}

#[tokio::test]
async fn singleton_submit_and_resume_reopen_at_every_dispatch_and_confirmation_boundary() {
    interruption_matrix(false).await;
}

#[tokio::test]
async fn legacy_vote_hash_without_a_journal_is_polled_without_reposting() {
    let fixture = BallotFixture::new(false).await;
    BallotFixture::store(&fixture.session.db, &fixture.recoveries);
    let old_bytes = delegation_fixture::corrupt(
        &fixture.session.db.serialize_bytes().unwrap(),
        &format!(
            "UPDATE votes SET tx_hash='{0}';
             INSERT INTO legacy_vote_evidence
             SELECT round_id,wallet_id,bundle_index,proposal_id,tx_hash FROM votes",
            fixture.canonical.tx_hash()
        ),
    );
    let session = fixture.reopen(&old_bytes);
    let plan = resume_plan(&session.db, ID, &fixture.roster()).unwrap();
    assert!(matches!(
        plan.next_steps.first(),
        Some(NextStep::AdvanceVote { .. })
    ));
    let durable = Arc::new(Mutex::new(old_bytes));
    let transport = fixture.transport(durable.clone(), Stop::None);
    let result = session
        .submit_ballot_with(
            ID,
            None,
            &transport,
            || std::future::ready(Ok(fixture.round.clone())),
            |_, _, _| async { panic!("legacy vote must not be rebuilt") },
            || async {
                *durable.lock().unwrap() = session.db.serialize_bytes().unwrap();
                Ok(())
            },
            || Ok(1500),
        )
        .await
        .unwrap();
    assert!(matches!(
        result.phase,
        VotingRoundPhase::VotePending | VotingRoundPhase::VoteConfirmed
    ));
    assert_eq!(
        transport
            .requests
            .lock()
            .unwrap()
            .iter()
            .map(|request| request.method.as_str())
            .collect::<Vec<_>>(),
        vec!["GET"]
    );
    let attempt = session.db.vote_submission(ID, 0, 1).unwrap().unwrap();
    assert_eq!(attempt.outcome, VoteSubmissionOutcome::Accepted);
    assert_eq!(attempt.confirmation_vc_positions, Some(vec![51]));
}

#[tokio::test]
async fn helper_recovery_completes_the_durable_ballot_lifecycle() {
    for batch in [false, true] {
        let fixture = BallotFixture::new(batch).await;
        let session = &fixture.session;
        let durable = Arc::new(Mutex::new(session.db.serialize_bytes().unwrap()));
        let mut transport = fixture.transport(durable.clone(), Stop::None);
        transport.confirm_helpers = true;
        let result = session
            .submit_ballot_with(
                ID,
                Some(
                    fixture
                        .roster()
                        .into_iter()
                        .map(|proposal_id| BallotDecision::Choice {
                            proposal_id,
                            option: 0,
                        })
                        .collect(),
                ),
                &transport,
                || std::future::ready(Ok(fixture.round.clone())),
                |_, _, _| {
                    std::future::ready(Ok(BallotFixture::store(&session.db, &fixture.recoveries)))
                },
                || async {
                    *durable.lock().unwrap() = session.db.serialize_bytes().unwrap();
                    Ok(())
                },
                || Ok(1500),
            )
            .await
            .unwrap();
        assert_eq!(result.phase, VotingRoundPhase::SharesConfirmed);
        assert_eq!(
            session.round_status_at(ID, 1500).unwrap().confirmed_helpers,
            (fixture.roster().len() * 16) as u32
        );
    }
}

#[tokio::test]
async fn atomic_batch_submit_and_resume_reopen_at_every_dispatch_and_confirmation_boundary() {
    interruption_matrix(true).await;
}

#[tokio::test]
async fn restored_singleton_and_batch_confirmation_without_evidence_fail_before_effects() {
    for batch in [false, true] {
        let fixture = BallotFixture::new(batch).await;
        let db = &fixture.session.db;
        for proposal in fixture.roster() {
            db.set_ballot_intent(ID, proposal, zcash_voting::session::Decision::Choice(0), 2)
                .unwrap();
        }
        BallotFixture::store(db, &fixture.recoveries);
        db.prepare_vote_submission(ID, 0, &fixture.canonical)
            .unwrap();
        db.mark_vote_dispatching(ID, 0, 1).unwrap();
        let dispatched = db.serialize_bytes().unwrap();
        for outcome in ["dispatching", "accepted"] {
            for members in if batch {
                vec!["proposal_id=1", "proposal_id=2", "1=1"]
            } else {
                vec!["1=1"]
            } {
                let bytes = delegation_fixture::corrupt(&dispatched, &format!(
                    "UPDATE vote_attempts SET outcome='{outcome}';
                     UPDATE votes SET vc_tree_position=50+proposal_id,
                       commitment_bundle_json=json_set(commitment_bundle_json,'$.vc_tree_position',50+proposal_id)
                     WHERE {members};"
                ));
                // Exercise the driver's own integrity gate even for partial
                // batches that the public session constructor also rejects.
                let mut restored = fixture.reopen(&dispatched);
                restored.db = VotingDb::open_browser(
                    &fixture.session.wallet_id,
                    zcash_voting::Network::Testnet,
                    Some(&bytes),
                )
                .unwrap();
                let before = restored.db.serialize_bytes().unwrap();
                let effects = Cell::new(0);
                let transport = fixture.transport(Arc::new(Mutex::new(bytes)), Stop::None);
                let error = restored
                    .submit_ballot_with(
                        ID,
                        None,
                        &transport,
                        || {
                            effects.set(effects.get() + 1);
                            std::future::ready(Ok(fixture.round.clone()))
                        },
                        |_, _, _| {
                            effects.set(effects.get() + 1);
                            std::future::ready(Ok(fixture.canonical.clone()))
                        },
                        || {
                            effects.set(effects.get() + 1);
                            std::future::ready(Ok(()))
                        },
                        || Ok(1500),
                    )
                    .await
                    .unwrap_err();
                assert_eq!(error.code, VotingErrorCode::RecoveryConflict);
                assert_eq!(effects.get(), 0);
                assert!(transport.requests.lock().unwrap().is_empty());
                assert!(restored.db.serialize_bytes().unwrap() == before);
            }
        }
    }
}

#[tokio::test]
async fn driver_rejects_malformed_tree_positions_without_checkpointing_and_accepts_capacity_edge() {
    for batch in [false, true] {
        let fixture = BallotFixture::new(batch).await;
        let db = &fixture.session.db;
        for proposal in fixture.roster() {
            db.set_ballot_intent(ID, proposal, zcash_voting::session::Decision::Choice(0), 2)
                .unwrap();
        }
        BallotFixture::store(db, &fixture.recoveries);
        db.prepare_vote_submission(ID, 0, &fixture.canonical)
            .unwrap();
        db.mark_vote_dispatching(ID, 0, 1).unwrap();
        db.record_vote_outcome(ID, 0, 1, VoteSubmissionOutcome::Accepted)
            .unwrap();
        let accepted = db.serialize_bytes().unwrap();
        let cases = if batch {
            vec![
                ("50", "51,51"),
                ("50", "52,51"),
                ("50", "50,52"),
                ("41", "51,52"),
                ("50", "51,16777216"),
                ("16777216", "16777217,16777218"),
                ("16777213", "16777214,16777215"),
            ]
        } else {
            vec![
                ("50", "49"),
                ("50", "50"),
                ("41", "42"),
                ("50", "16777216"),
                ("16777216", "16777217"),
                ("16777214", "16777215"),
            ]
        };
        for (index, (van, positions)) in cases.iter().enumerate() {
            let valid = index == cases.len() - 1;
            let restored = fixture.reopen(&accepted);
            let before = restored.db.serialize_bytes().unwrap();
            let durable = Arc::new(Mutex::new(accepted.clone()));
            let mut transport = fixture.transport(durable.clone(), Stop::None);
            let mut response: serde_json::Value =
                serde_json::from_slice(&transport.confirmation).unwrap();
            for attribute in response["events"][0]["attributes"].as_array_mut().unwrap() {
                match attribute["key"].as_str().unwrap() {
                    "leaf_index" => attribute["value"] = format!("{van},{positions}").into(),
                    "final_van_leaf_index" => attribute["value"] = (*van).into(),
                    "vote_commitment_leaf_indices" => attribute["value"] = (*positions).into(),
                    _ => (),
                }
            }
            transport.confirmation = serde_json::to_vec(&response).unwrap();
            let checkpoints = Cell::new(0);
            let result = restored
                .submit_ballot_with(
                    ID,
                    None,
                    &transport,
                    || std::future::ready(Ok(fixture.round.clone())),
                    |_, _, _| async { panic!("polling must not build a vote") },
                    || async {
                        checkpoints.set(checkpoints.get() + 1);
                        *durable.lock().unwrap() = restored.db.serialize_bytes().unwrap();
                        Ok(())
                    },
                    || Ok(1500),
                )
                .await;
            assert_eq!(transport.requests.lock().unwrap().len(), 1);
            if valid {
                assert_eq!(result.unwrap().phase, VotingRoundPhase::VoteConfirmed);
                assert!(checkpoints.get() > 0);
                fixture.assert_canonical(&restored);
                let events: Vec<zcash_voting::confirmation::TxEvent> =
                    serde_json::from_value(response["events"].clone()).unwrap();
                restored
                    .db
                    .confirm_journaled_vote(ID, 0, 1, fixture.canonical.tx_hash(), &events)
                    .unwrap();
                fixture.assert_canonical(&fixture.reopen(&restored.db.serialize_bytes().unwrap()));
            } else {
                assert_eq!(result.unwrap_err().code, VotingErrorCode::RecoveryConflict);
                assert_eq!(checkpoints.get(), 0);
                assert!(restored.db.serialize_bytes().unwrap() == before);
            }
        }
    }
}

#[tokio::test]
async fn dispatch_checkpoint_crossing_expiry_never_constructs_a_vote_post() {
    let fixture = BallotFixture::new(false).await;
    let session = &fixture.session;
    let durable = Arc::new(Mutex::new(session.db.serialize_bytes().unwrap()));
    let transport = fixture.transport(durable.clone(), Stop::None);
    let checkpoints = Cell::new(0);
    let now = Cell::new(1500);
    let ends_at = fixture.round.summary.ends_at.parse().unwrap();
    let result = session
        .submit_ballot_with(
            ID,
            Some(vec![BallotDecision::Choice {
                proposal_id: 1,
                option: 0,
            }]),
            &transport,
            || std::future::ready(Ok(fixture.round.clone())),
            |_, _, _| {
                std::future::ready(Ok(BallotFixture::store(&session.db, &fixture.recoveries)))
            },
            || async {
                checkpoints.set(checkpoints.get() + 1);
                *durable.lock().unwrap() = session.db.serialize_bytes().unwrap();
                if checkpoints.get() == 3 {
                    now.set(ends_at);
                }
                Ok(())
            },
            || Ok(now.get()),
        )
        .await
        .unwrap_err();
    assert_eq!(result.code, VotingErrorCode::RoundExpired);
    assert!(transport.requests.lock().unwrap().is_empty());
    let reopened = fixture.reopen(&durable.lock().unwrap());
    let attempt = reopened.db.vote_submission(ID, 0, 1).unwrap().unwrap();
    assert_eq!(attempt.outcome, VoteSubmissionOutcome::Dispatching);
    assert_eq!(
        reopened.round_status_at(ID, ends_at).unwrap().phase,
        VotingRoundPhase::Expired
    );
    let result = reopened
        .submit_ballot_with(
            ID,
            None,
            &transport,
            || std::future::ready(Ok(fixture.round.clone())),
            |_, _, _| async { panic!("expired vote must not rebuild") },
            || async { panic!("expired vote must not checkpoint") },
            || Ok(ends_at),
        )
        .await
        .unwrap_err();
    assert_eq!(result.code, VotingErrorCode::RoundExpired);
    assert!(transport.requests.lock().unwrap().is_empty());
}
