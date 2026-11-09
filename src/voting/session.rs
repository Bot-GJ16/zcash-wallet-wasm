//! One local owner for voting state and authenticated discovery.
#![allow(dead_code)]
use super::{config, persistence::Persistence, types::*};
use crate::bindgen::wallet::{AccountId, MemoryWallet};
use secrecy::{ExposeSecret, SecretString};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    future::Future,
    rc::Rc,
};
use tonic_web_wasm_client::Client;
use zcash_client_backend::data_api::{Account as _, WalletRead};
use zcash_protocol::consensus::Parameters;
use zcash_voting::{
    phases::{DelegationPhase, SharePhase, VotePhase},
    session::{NextStep, resume_plan},
    storage::VotingDb,
};

pub(crate) struct VotingSessionInner {
    pub(crate) wallet: MemoryWallet<Client>,
    pub(crate) account_id: AccountId,
    pub(crate) wallet_id: String,
    pub(crate) network: super::network::VotingNetwork,
    pub(crate) db: VotingDb,
    #[cfg(target_arch = "wasm32")]
    pub(crate) transport: super::transport::BrowserFetchTransport,
    pub(crate) persistence: Persistence,
    pub(crate) trusted_rounds: RefCell<BTreeMap<String, TrustedRound>>,
    pub(crate) selected_round_id: RefCell<Option<String>>,
    pub(crate) mutation_active: Rc<Cell<bool>>,
    pub(crate) vote_tree_sync: zcash_voting::tree_sync::VoteTreeSync,
    eligibility: RefCell<BTreeMap<String, VotingEligibility>>,
    helper_health: zcash_voting::helper::health::HelperHealth,
}

fn conflict(_: impl Sized) -> VotingApiError {
    VotingApiError::new(VotingErrorCode::RecoveryConflict)
}

fn browser_step_kind(
    db: &VotingDb,
    round_id: &str,
    step: &NextStep,
) -> Result<&'static str, VotingApiError> {
    use zcash_voting::vote_submission::VoteSubmissionOutcome;
    Ok(match step {
        NextStep::Delegate { .. } => "delegate",
        NextStep::AdvanceDelegation { .. } | NextStep::AdvanceImportedDelegation { .. } => {
            "poll_delegation"
        }
        NextStep::CastVote { .. } => "cast_vote",
        NextStep::AdvanceVote {
            bundle_index,
            proposal_id,
        }
        | NextStep::AdvanceVoteBatch {
            bundle_index,
            proposal_id,
        } => {
            let attempt = db
                .vote_submission(round_id, *bundle_index, *proposal_id)
                .map_err(conflict)?;
            let pending =
                attempt.is_some_and(|attempt| attempt.outcome != VoteSubmissionOutcome::Prepared);
            match (matches!(step, NextStep::AdvanceVoteBatch { .. }), pending) {
                (false, false) => "submit_vote",
                (true, false) => "submit_vote_batch",
                (false, true) => "poll_vote",
                (true, true) => "poll_vote_batch",
            }
        }
        NextStep::SubmitShares { .. } => "submit_shares",
        NextStep::ConfirmShare { .. } => "confirm_share",
        _ => return Err(conflict(())),
    })
}

fn browser_round_action(
    action: zcash_voting::session::RoundPlanAction,
) -> Result<&'static str, VotingApiError> {
    use zcash_voting::session::RoundPlanAction;
    Ok(match action {
        RoundPlanAction::Idle => "idle",
        RoundPlanAction::Delegate => "delegate",
        RoundPlanAction::Vote => "vote",
        RoundPlanAction::SubmitShares => "submit_shares",
        RoundPlanAction::Done => "done",
        _ => return Err(conflict(())),
    })
}

fn all_expected_votes_confirmed(confirmed: u32, expected: u32) -> bool {
    expected > 0 && confirmed == expected
}
pub(crate) fn now_secs() -> Result<u64, VotingApiError> {
    u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).map_err(conflict)
}

impl VotingSessionInner {
    fn validate_delegation_round(
        &self,
        id: &str,
        round: &TrustedRound,
        now: u64,
    ) -> Result<(), VotingApiError> {
        if round.summary.round_id != id
            || !self.db.has_round(id).map_err(conflict)?
            || self
                .selected_round_id
                .borrow()
                .as_ref()
                .is_some_and(|selected| selected != id)
        {
            return Err(conflict(()));
        }
        if now >= round.summary.ends_at.parse::<u64>().map_err(conflict)? {
            return Err(VotingApiError::new(VotingErrorCode::RoundExpired));
        }
        self.validate_saved_identity(round)?;
        *self.selected_round_id.borrow_mut() = Some(id.into());
        Ok(())
    }
    fn delegation_progress(
        &self,
        id: &str,
        now: u64,
    ) -> Result<VotingActionResult, VotingApiError> {
        let status = self.round_status_at(id, now)?;
        Ok(VotingActionResult {
            round_id: status.round_id,
            phase: status.phase,
            completed_bundles: status.completed_bundles,
            total_bundles: status.total_bundles,
            next_action: status.next_action,
        })
    }

    pub(crate) async fn submit_delegation_with<A, B, C>(
        &self,
        id: &str,
        usk: zcash_keys::keys::UnifiedSpendingKey,
        fingerprint: zip32::fingerprint::SeedFingerprint,
        transport: &impl zcash_voting::platform::HttpTransport,
        authenticate: impl Fn() -> A,
        mut build: impl FnMut(TrustedRound, u32) -> B,
        checkpoint: impl Fn() -> C,
        now: impl Fn() -> Result<u64, VotingApiError>,
    ) -> Result<VotingActionResult, VotingApiError>
    where
        A: Future<Output = Result<TrustedRound, VotingApiError>>,
        B: Future<
            Output = Result<
                zcash_voting::delegation_submission::CanonicalDelegation,
                VotingApiError,
            >,
        >,
        C: Future<Output = Result<(), VotingApiError>>,
    {
        use zcash_voting::delegation_submission::*;
        let _guard = self.mutation_guard()?;
        self.validate_delegation_key(&usk, fingerprint)?;
        drop(usk);
        let id = config::normalize_round_id(id)?;
        self.db.validate_delegation_state(&id).map_err(conflict)?;
        self.db
            .validate_vote_submission_state(&id)
            .map_err(conflict)?;
        let checkpoint = || self.persistence.checkpoint_with(&checkpoint);
        if self.persistence.has_pending_checkpoint() {
            checkpoint().await?;
        }
        let round = authenticate().await?;
        self.validate_delegation_round(&id, &round, now()?)?;
        let roster = round
            .proposals
            .iter()
            .map(|p| p.proposal_id)
            .collect::<Vec<_>>();
        loop {
            let steps = zcash_voting::session::delegation_resume_steps(&self.db, &id, &roster)
                .map_err(conflict)?;
            let Some(step) = steps.first() else {
                checkpoint()
                    .await
                    .map_err(|_| VotingApiError::new(VotingErrorCode::SubmissionUnknown))?;
                return self.delegation_progress(&id, now()?);
            };
            let bundle = match step {
                NextStep::Delegate { bundle_index }
                | NextStep::AdvanceDelegation { bundle_index }
                | NextStep::AdvanceImportedDelegation { bundle_index } => *bundle_index,
                _ => unreachable!(),
            };
            let mut attempt = self
                .db
                .delegation_submission(&id, bundle)
                .map_err(conflict)?;
            if attempt.is_none() {
                if matches!(
                    step,
                    NextStep::AdvanceDelegation { .. } | NextStep::AdvanceImportedDelegation { .. }
                ) {
                    return Err(conflict(()));
                }
                let round = authenticate().await?;
                self.validate_delegation_round(&id, &round, now()?)?;
                let canonical = build(round, bundle).await?;
                self.db
                    .prepare_delegation_submission(&id, bundle, &canonical)
                    .map_err(conflict)?;
                attempt = self
                    .db
                    .delegation_submission(&id, bundle)
                    .map_err(conflict)?;
            }
            let attempt = attempt.ok_or_else(|| conflict(()))?;
            let canonical = attempt.canonical;
            if attempt.outcome == DelegationOutcome::Rejected {
                checkpoint()
                    .await
                    .map_err(|_| VotingApiError::new(VotingErrorCode::SubmissionUnknown))?;
                return Err(VotingApiError::new(VotingErrorCode::SubmissionRejected));
            }
            if attempt.outcome == DelegationOutcome::Prepared {
                checkpoint().await?;
                let round = authenticate().await?;
                self.validate_delegation_round(&id, &round, now()?)?;
                let base = round.vote_server_urls.first().ok_or_else(|| conflict(()))?;
                self.db
                    .mark_delegation_dispatching(&id, bundle)
                    .map_err(conflict)?;
                // From this checkpoint onward cancellation can only recover by lookup.
                checkpoint()
                    .await
                    .map_err(|_| VotingApiError::new(VotingErrorCode::SubmissionUnknown))?;
                self.validate_delegation_round(&id, &round, now()?)?;
                // The request and its future are deliberately created after checkpoint resolution.
                let outcome = transport
                    .execute(delegation_request(base, &canonical))
                    .await
                    .and_then(|r| parse_delegation_result(r, &canonical));
                let recorded = match outcome {
                    Ok(outcome) => outcome,
                    Err(zcash_voting::platform::TransportError::Definite) => {
                        DelegationOutcome::Rejected
                    }
                    Err(_) => DelegationOutcome::Ambiguous,
                };
                self.db
                    .record_delegation_outcome(&id, bundle, recorded)
                    .map_err(|_| VotingApiError::new(VotingErrorCode::SubmissionUnknown))?;
                checkpoint()
                    .await
                    .map_err(|_| VotingApiError::new(VotingErrorCode::SubmissionUnknown))?;
                match recorded {
                    DelegationOutcome::Ambiguous => {
                        return Err(VotingApiError::new(VotingErrorCode::SubmissionUnknown));
                    }
                    DelegationOutcome::Rejected => {
                        return Err(VotingApiError::new(VotingErrorCode::SubmissionRejected));
                    }
                    _ => continue,
                }
            }
            // Flush the authoritative in-memory state after a failed result checkpoint.
            checkpoint()
                .await
                .map_err(|_| VotingApiError::new(VotingErrorCode::SubmissionUnknown))?;
            let round = authenticate().await?;
            self.validate_delegation_round(&id, &round, now()?)?;
            let mut confirmed = false;
            for base in &round.vote_server_urls {
                self.validate_delegation_round(&id, &round, now()?)?;
                let response = match transport
                    .execute(delegation_status_request(base, &canonical))
                    .await
                {
                    Ok(response) => response,
                    Err(zcash_voting::platform::TransportError::Definite) => continue,
                    Err(_) => return Err(conflict(())),
                };
                match parse_delegation_status(response).map_err(conflict)? {
                    DelegationStatus::Pending => continue,
                    DelegationStatus::Rejected => {
                        self.db
                            .record_delegation_outcome(&id, bundle, DelegationOutcome::Rejected)
                            .map_err(conflict)?;
                        checkpoint()
                            .await
                            .map_err(|_| VotingApiError::new(VotingErrorCode::SubmissionUnknown))?;
                        return Err(VotingApiError::new(VotingErrorCode::SubmissionRejected));
                    }
                    DelegationStatus::Confirmed(events) => {
                        self.validate_delegation_round(&id, &round, now()?)?;
                        self.db
                            .confirm_journaled_delegation(&id, bundle, canonical.tx_hash(), &events)
                            .map_err(conflict)?;
                        checkpoint()
                            .await
                            .map_err(|_| VotingApiError::new(VotingErrorCode::SubmissionUnknown))?;
                        confirmed = true;
                        break;
                    }
                }
            }
            if !confirmed {
                return self.delegation_progress(&id, now()?);
            }
        }
    }
    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn submit_delegation(
        &self,
        id: &str,
        usk: zcash_keys::keys::UnifiedSpendingKey,
        fingerprint: zip32::fingerprint::SeedFingerprint,
    ) -> Result<VotingActionResult, VotingApiError> {
        self.submit_delegation_with(
            id,
            usk.clone(),
            fingerprint,
            &self.transport,
            || self.ensure_trusted_round(id),
            |round, bundle| self.build_delegation(round, bundle, usk.clone(), fingerprint),
            || self.persistence.checkpoint(&self.db),
            now_secs,
        )
        .await
    }

    #[cfg(target_arch = "wasm32")]
    async fn build_delegation(
        &self,
        round: TrustedRound,
        bundle: u32,
        usk: zcash_keys::keys::UnifiedSpendingKey,
        fingerprint: zip32::fingerprint::SeedFingerprint,
    ) -> Result<zcash_voting::delegation_submission::CanonicalDelegation, VotingApiError> {
        use zcash_voting::{delegate, proof_executor::ProofExecutor};
        let id = &round.summary.round_id;
        let account = self.validate_delegation_key(&usk, fingerprint)?;
        let input = super::wallet_adapter::gather_eligibility_inputs(
            &self.wallet,
            self.account_id,
            round.network.network(),
            round.params.snapshot_height,
        )
        .await?;
        let trusted = self.ensure_trusted_round(id).await?;
        self.validate_delegation_round(id, &trusted, now_secs()?)?;
        let hotkey = self
            .db
            .load_voting_hotkey(id)
            .map_err(conflict)?
            .ok_or_else(|| conflict(()))?;
        let keys = delegate::DelegationKeys::with_voting_hotkey(
            account.orchard_fvk_bytes.to_vec(),
            &hotkey,
            account.seed_fingerprint,
            account.account_index,
            round.summary.name.clone(),
        )
        .map_err(conflict)?;
        let policy = self
            .db
            .effective_bundle_policy(id, zcash_voting::BundlePolicy::default())
            .map_err(conflict)?;
        self.db
            .ensure_bundles_with_policy(id, &input.notes, policy)
            .map_err(conflict)?;
        let notes = zcash_voting::round::note_bundles_with_policy(&input.notes, policy)
            .map_err(conflict)?
            .into_iter()
            .nth(bundle as usize)
            .ok_or_else(|| conflict(()))?;
        if !self
            .db
            .has_complete_witnesses(id, bundle, &notes)
            .map_err(conflict)?
        {
            return Err(conflict(()));
        }
        let phase = self.db.delegation_phase(id, bundle).map_err(conflict)?;
        if phase == DelegationPhase::Prepared {
            self.db
                .build_governance_pczt(
                    id,
                    bundle,
                    &notes,
                    &keys,
                    delegate::branch_id_for_height(
                        round.network.network(),
                        round.params.snapshot_height,
                    )
                    .map_err(conflict)?,
                )
                .map_err(conflict)?;
        }
        self.validate_delegation_round(id, &round, now_secs()?)?;
        let (signature, sighash) =
            self.sign_stored_delegation(&round, bundle, &usk, fingerprint, &keys, &notes)?;
        drop(usk);
        if phase != DelegationPhase::Proved {
            let job = self
                .db
                .delegation_proof_job(id, bundle, notes, keys)
                .map_err(conflict)?;
            self.ensure_trusted_round(id).await?;
            #[cfg(feature = "wasm-parallel")]
            let executor = super::proof_executor::RayonProofExecutor;
            #[cfg(not(feature = "wasm-parallel"))]
            let executor = zcash_voting::proof_executor::SequentialProofExecutor;
            let result = executor
                .prove(job, |job| job(&zcash_voting::types::NoopProgressReporter))
                .await
                .map_err(|_| VotingApiError::new(VotingErrorCode::ProofFailed))?;
            let trusted = self.ensure_trusted_round(id).await?;
            self.validate_delegation_round(id, &trusted, now_secs()?)?;
            self.db
                .store_delegation_proof(id, bundle, &result)
                .map_err(conflict)?;
        }
        let submission = delegate::submission(
            &self.db,
            id,
            bundle,
            delegate::DelegationSigner::signature(signature, sighash),
        )
        .map_err(conflict)?;
        zcash_voting::delegation_submission::CanonicalDelegation::from_submission(&submission)
            .map_err(conflict)
    }

    fn sign_stored_delegation(
        &self,
        round: &TrustedRound,
        bundle: u32,
        usk: &zcash_keys::keys::UnifiedSpendingKey,
        fingerprint: zip32::fingerprint::SeedFingerprint,
        keys: &zcash_voting::delegate::DelegationKeys,
        notes: &[zcash_voting::NoteInfo],
    ) -> Result<([u8; 64], [u8; 32]), VotingApiError> {
        use zcash_voting::backend::pasta_curves::{group::ff::PrimeField, pallas};
        let account = self.validate_delegation_key(usk, fingerprint)?;
        self.validate_saved_identity(round)?;
        let (request, rk) = self
            .db
            .get_delegation_resume_signing_request(&round.summary.round_id, bundle, keys, notes)
            .map_err(conflict)?;
        if request.network != round.network.network()
            || request.account_index != account.account_index
            || request.seed_fingerprint != account.seed_fingerprint
        {
            return Err(conflict(()));
        }
        let alpha = Option::<pallas::Scalar>::from(pallas::Scalar::from_repr(request.alpha))
            .ok_or_else(|| conflict(()))?;
        let ask = orchard::keys::SpendAuthorizingKey::from(usk.orchard());
        let signing_key = ask.randomize(&alpha);
        let expected: [u8; 32] =
            (&orchard::primitives::redpallas::VerificationKey::from(&signing_key)).into();
        if expected != rk {
            return Err(conflict(()));
        }
        Ok((
            (&signing_key.sign(
                rand::rand_core::UnwrapErr(rand::rngs::SysRng),
                &request.sighash,
            ))
                .into(),
            request.sighash,
        ))
    }

    fn validate_submission_state(&self, id: &str) -> Result<(), VotingApiError> {
        self.db.validate_delegation_state(id).map_err(conflict)?;
        self.db.validate_vote_submission_state(id).map_err(conflict)
    }

    pub(crate) async fn submit_ballot_with<A, B, C>(
        &self,
        id: &str,
        decisions: Option<Vec<BallotDecision>>,
        transport: &impl zcash_voting::platform::HttpTransport,
        authenticate: impl Fn() -> A,
        build: impl FnMut(TrustedRound, u32, Vec<zcash_voting::vote::DraftVote>) -> B,
        checkpoint: impl Fn() -> C,
        now: impl Fn() -> Result<u64, VotingApiError>,
    ) -> Result<VotingActionResult, VotingApiError>
    where
        A: Future<Output = Result<TrustedRound, VotingApiError>>,
        B: Future<
            Output = Result<zcash_voting::vote_submission::CanonicalVoteSubmission, VotingApiError>,
        >,
        C: Future<Output = Result<(), VotingApiError>>,
    {
        let _guard = self.mutation_guard()?;
        let id = config::normalize_round_id(id)?;
        self.validate_submission_state(&id)?;
        let checkpoint = || self.persistence.checkpoint_with(&checkpoint);
        if self.persistence.has_pending_checkpoint() {
            checkpoint().await?;
        }
        let round = authenticate().await?;
        self.validate_delegation_round(&id, &round, now()?)?;
        if let Some(decisions) = decisions {
            let roster = round
                .proposals
                .iter()
                .map(|proposal| {
                    Ok((
                        proposal.proposal_id,
                        u32::try_from(proposal.options.len()).map_err(conflict)?,
                    ))
                })
                .collect::<Result<Vec<_>, VotingApiError>>()?;
            let decisions = decisions
                .into_iter()
                .map(|decision| match decision {
                    BallotDecision::Choice {
                        proposal_id,
                        option,
                    } => (proposal_id, zcash_voting::session::Decision::Choice(option)),
                    BallotDecision::Skip { proposal_id } => {
                        (proposal_id, zcash_voting::session::Decision::Skipped)
                    }
                })
                .collect::<Vec<_>>();
            self.db
                .set_complete_ballot_intents(&id, &roster, &decisions)
                .map_err(conflict)?;
            checkpoint()
                .await
                .map_err(|_| VotingApiError::new(VotingErrorCode::PersistenceFailed))?;
        }
        self.drive_resume_plan(&id, transport, authenticate, build, checkpoint, now)
            .await
    }

    async fn drive_resume_plan<A, B, C>(
        &self,
        id: &str,
        transport: &impl zcash_voting::platform::HttpTransport,
        authenticate: impl Fn() -> A,
        mut build: impl FnMut(TrustedRound, u32, Vec<zcash_voting::vote::DraftVote>) -> B,
        checkpoint: impl Fn() -> C,
        now: impl Fn() -> Result<u64, VotingApiError>,
    ) -> Result<VotingActionResult, VotingApiError>
    where
        A: Future<Output = Result<TrustedRound, VotingApiError>>,
        B: Future<
            Output = Result<zcash_voting::vote_submission::CanonicalVoteSubmission, VotingApiError>,
        >,
        C: Future<Output = Result<(), VotingApiError>>,
    {
        use zcash_voting::{
            delegation_submission::{
                DelegationOutcome, DelegationStatus, delegation_status_request,
                legacy_delegation_status_request, parse_delegation_status,
            },
            platform::TransportError,
            vote_submission::{
                CanonicalVoteSubmission, VoteStatus, VoteSubmissionOutcome, parse_vote_result,
                parse_vote_status, vote_request, vote_status_request,
            },
        };
        let mut visited_helpers = std::collections::BTreeSet::new();
        let mut tracked_helpers = false;
        let timer = super::timer::HelperTimer::default();
        loop {
            self.validate_submission_state(id)?;
            let round = authenticate().await?;
            self.validate_delegation_round(id, &round, now()?)?;
            let roster = round
                .proposals
                .iter()
                .map(|proposal| proposal.proposal_id)
                .collect::<Vec<_>>();
            let plan = resume_plan(&self.db, id, &roster).map_err(conflict)?;
            let Some(step) = plan
                .next_steps
                .iter()
                .find(|step| match step {
                    NextStep::SubmitShares {
                        bundle_index,
                        proposal_id,
                        share_index,
                    }
                    | NextStep::ConfirmShare {
                        bundle_index,
                        proposal_id,
                        share_index,
                    } => !visited_helpers.contains(&(
                        if matches!(step, NextStep::SubmitShares { .. }) {
                            "submit_shares"
                        } else {
                            "confirm_share"
                        },
                        *bundle_index,
                        *proposal_id,
                        *share_index,
                    )),
                    _ => true,
                })
                .cloned()
            else {
                return self.delegation_progress(id, now()?);
            };
            match step {
                NextStep::Delegate { .. } => return self.delegation_progress(id, now()?),
                NextStep::AdvanceDelegation { bundle_index }
                | NextStep::AdvanceImportedDelegation { bundle_index } => {
                    let attempt = self
                        .db
                        .delegation_submission(id, bundle_index)
                        .map_err(conflict)?;
                    let legacy_hash = if attempt.is_none()
                        && matches!(step, NextStep::AdvanceDelegation { .. })
                    {
                        self.db
                            .get_delegation_tx_hash(id, bundle_index)
                            .map_err(conflict)?
                    } else {
                        None
                    };
                    let mut confirmed = false;
                    for base in &round.vote_server_urls {
                        let request = if let Some(attempt) = &attempt {
                            delegation_status_request(base, &attempt.canonical)
                        } else {
                            legacy_delegation_status_request(
                                base,
                                legacy_hash.as_deref().ok_or_else(|| conflict(()))?,
                            )
                            .map_err(conflict)?
                        };
                        let response = match transport.execute(request).await {
                            Ok(response) => response,
                            Err(TransportError::Definite) => continue,
                            Err(_) => return Err(conflict(())),
                        };
                        match parse_delegation_status(response).map_err(conflict)? {
                            DelegationStatus::Pending => continue,
                            DelegationStatus::Rejected => {
                                if attempt.is_some() {
                                    self.db
                                        .record_delegation_outcome(
                                            id,
                                            bundle_index,
                                            DelegationOutcome::Rejected,
                                        )
                                        .map_err(conflict)?;
                                    checkpoint().await.map_err(|_| {
                                        VotingApiError::new(VotingErrorCode::SubmissionUnknown)
                                    })?;
                                }
                                return Err(VotingApiError::new(
                                    VotingErrorCode::SubmissionRejected,
                                ));
                            }
                            DelegationStatus::Confirmed(events) => {
                                if let Some(attempt) = &attempt {
                                    self.db
                                        .confirm_journaled_delegation(
                                            id,
                                            bundle_index,
                                            attempt.canonical.tx_hash(),
                                            &events,
                                        )
                                        .map_err(conflict)?;
                                } else {
                                    self.db
                                        .confirm_legacy_delegation(
                                            id,
                                            bundle_index,
                                            legacy_hash.as_deref().ok_or_else(|| conflict(()))?,
                                            &events,
                                        )
                                        .map_err(conflict)?;
                                }
                                checkpoint().await.map_err(|_| {
                                    VotingApiError::new(VotingErrorCode::SubmissionUnknown)
                                })?;
                                confirmed = true;
                                break;
                            }
                        }
                    }
                    if !confirmed {
                        return self.delegation_progress(id, now()?);
                    }
                }
                NextStep::SubmitShares {
                    bundle_index,
                    proposal_id,
                    share_index,
                }
                | NextStep::ConfirmShare {
                    bundle_index,
                    proposal_id,
                    share_index,
                } => {
                    use zcash_voting::helper::client::local::{CheckpointHook, LocalHelperClient};
                    use zcash_voting::share_tracking::*;
                    struct Hook<'a, F>(&'a F, &'a Cell<bool>);
                    impl<F, C> CheckpointHook for Hook<'_, F>
                    where
                        F: Fn() -> C,
                        C: Future<Output = Result<(), VotingApiError>>,
                    {
                        fn checkpoint(
                            &self,
                        ) -> futures_util::future::LocalBoxFuture<
                            '_,
                            Result<(), zcash_voting::VotingError>,
                        > {
                            Box::pin(async {
                                (self.0)().await.map_err(|_| {
                                    self.1.set(true);
                                    zcash_voting::VotingError::Internal {
                                        message: "helper checkpoint failed".into(),
                                    }
                                })
                            })
                        }
                    }
                    let persistence_failed = Cell::new(false);
                    let hook = Hook(&checkpoint, &persistence_failed);
                    let wall_time = || now().unwrap_or(u64::MAX);
                    let vote_end = round.summary.ends_at.parse::<u64>().map_err(conflict)?;
                    let client =
                        LocalHelperClient::new(transport, &timer, &hook, &wall_time, vote_end)
                            .with_health(self.helper_health.clone());
                    let helper_error = |_| {
                        VotingApiError::new(if persistence_failed.get() {
                            if client.has_dispatched() {
                                VotingErrorCode::SubmissionUnknown
                            } else {
                                VotingErrorCode::PersistenceFailed
                            }
                        } else {
                            VotingErrorCode::RecoveryConflict
                        })
                    };
                    let fleet = round.helper_urls();
                    visited_helpers.insert((
                        browser_step_kind(&self.db, id, &step)?,
                        bundle_index,
                        proposal_id,
                        share_index,
                    ));
                    if matches!(step, NextStep::SubmitShares { .. }) {
                        let committed = zcash_voting::vote::CommittedVote::recover(
                            &self.db,
                            id,
                            bundle_index,
                            proposal_id,
                        )
                        .map_err(conflict)?;
                        let preflight = client.preflight_fleet(&fleet).await.map_err(conflict)?;
                        self.validate_delegation_round(id, &round, now()?)?;
                        committed
                            .prepare_share_delivery(
                                &self.db,
                                ShareDeliveryPlanningParams {
                                    fleet: &preflight,
                                    now_seconds: now()?,
                                    vote_end_time_seconds: vote_end,
                                    last_moment_buffer_seconds:
                                        zcash_voting::share_policy::last_moment_buffer_seconds(
                                            round
                                                .summary
                                                .starts_at
                                                .parse::<u64>()
                                                .map_err(conflict)?,
                                            vote_end,
                                        ),
                                    proposal_ids: &roster,
                                },
                            )
                            .map_err(conflict)?;
                        let delivery_started =
                            zcash_voting::helper::client::local::Timer::now(&timer);
                        let delivery = committed
                            .submit_prepared_shares_local(
                                &self.db,
                                &client,
                                ShareDeliverySubmissionParams {
                                    configured_server_urls: &fleet,
                                    now_seconds: now()?,
                                },
                                &|| false,
                            )
                            .await
                            .map_err(helper_error)?;
                        let budget_exhausted = zcash_voting::helper::client::local::Timer::now(&timer)
                            .saturating_sub(delivery_started).as_millis() >= u128::from(zcash_voting::share_policy::SHARE_INITIAL_DELIVERY_TIMEOUT_MILLISECONDS);
                        if delivery.cancelled || budget_exhausted || now()? >= vote_end {
                            return self.delegation_progress(id, now()?);
                        }
                    } else {
                        if !tracked_helpers {
                            let report = track_pending_shares_local(
                                &self.db,
                                &ShareTrackingParams {
                                    round_id: id,
                                    configured_server_urls: &fleet,
                                    now_seconds: now()?,
                                    vote_end_time_seconds: Some(vote_end),
                                    policy: zcash_voting::share_policy::ShareTimingPolicy::default(
                                    ),
                                },
                                &client,
                                &|| false,
                            )
                            .await
                            .map_err(helper_error)?;
                            tracked_helpers = true;
                            if !report.unrecoverable.is_empty() {
                                return Err(conflict(()));
                            }
                        }
                        confirm_pending_share_local(
                            &self.db,
                            &ShareConfirmationParams {
                                round_id: id,
                                share: ShareKey {
                                    bundle_index,
                                    proposal_id,
                                    share_index,
                                },
                                configured_server_urls: &fleet,
                                now_seconds: now()?,
                            },
                            &client,
                            &|| false,
                        )
                        .await
                        .map_err(helper_error)?;
                    }
                }
                NextStep::CastVote { bundle_index, .. } => {
                    let before_share = plan.next_steps.iter().take_while(|step| {
                        !matches!(
                            step,
                            NextStep::SubmitShares { .. } | NextStep::ConfirmShare { .. }
                        )
                    });
                    let drafts = before_share
                        .filter_map(|step| match step {
                            NextStep::CastVote {
                                bundle_index: candidate,
                                proposal_id,
                                choice,
                            } if *candidate == bundle_index => {
                                let options = round
                                    .proposals
                                    .iter()
                                    .find(|proposal| proposal.proposal_id == *proposal_id)?
                                    .options
                                    .len();
                                Some(zcash_voting::vote::DraftVote {
                                    proposal_id: *proposal_id,
                                    choice: *choice,
                                    num_options: u32::try_from(options).ok()?,
                                    single_share: false,
                                    vc_tree_position: 0,
                                })
                            }
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    if drafts.is_empty() {
                        return Err(conflict(()));
                    }
                    let canonical = build(round.clone(), bundle_index, drafts).await?;
                    self.db
                        .prepare_vote_submission(id, bundle_index, &canonical)
                        .map_err(conflict)?;
                    checkpoint()
                        .await
                        .map_err(|_| VotingApiError::new(VotingErrorCode::PersistenceFailed))?;
                }
                NextStep::AdvanceVote {
                    bundle_index,
                    proposal_id,
                }
                | NextStep::AdvanceVoteBatch {
                    bundle_index,
                    proposal_id,
                } => {
                    let mut attempt = self
                        .db
                        .vote_submission(id, bundle_index, proposal_id)
                        .map_err(conflict)?;
                    if attempt.is_none() {
                        let canonical = match step {
                            NextStep::AdvanceVote { .. } => {
                                CanonicalVoteSubmission::from_singleton(
                                    &zcash_voting::vote::submission(
                                        &self.db,
                                        id,
                                        bundle_index,
                                        proposal_id,
                                    )
                                    .map_err(conflict)?,
                                )
                                .map_err(conflict)?
                            }
                            _ => CanonicalVoteSubmission::from_batch(
                                &zcash_voting::vote::recover_atomic_vote_batch(
                                    &self.db,
                                    id,
                                    bundle_index,
                                    proposal_id,
                                )
                                .map_err(conflict)?,
                            )
                            .map_err(conflict)?,
                        };
                        if !self
                            .db
                            .adopt_legacy_vote_submission(id, bundle_index, &canonical)
                            .map_err(conflict)?
                        {
                            self.db
                                .prepare_vote_submission(id, bundle_index, &canonical)
                                .map_err(conflict)?;
                        }
                        checkpoint()
                            .await
                            .map_err(|_| VotingApiError::new(VotingErrorCode::PersistenceFailed))?;
                        attempt = self
                            .db
                            .vote_submission(id, bundle_index, proposal_id)
                            .map_err(conflict)?;
                    }
                    let attempt = attempt.ok_or_else(|| conflict(()))?;
                    if attempt.outcome == VoteSubmissionOutcome::Rejected {
                        return Err(VotingApiError::new(VotingErrorCode::SubmissionRejected));
                    }
                    if attempt.outcome == VoteSubmissionOutcome::Prepared {
                        self.db
                            .mark_vote_dispatching(id, bundle_index, proposal_id)
                            .map_err(conflict)?;
                        checkpoint()
                            .await
                            .map_err(|_| VotingApiError::new(VotingErrorCode::SubmissionUnknown))?;
                        self.validate_delegation_round(id, &round, now()?)?;
                        let outcome = transport
                            .execute(vote_request(
                                round.vote_server_urls.first().ok_or_else(|| conflict(()))?,
                                &attempt.canonical,
                            ))
                            .await
                            .and_then(|response| parse_vote_result(response, &attempt.canonical));
                        let recorded = match outcome {
                            Ok(outcome) => outcome,
                            Err(TransportError::Definite) => VoteSubmissionOutcome::Rejected,
                            Err(_) => VoteSubmissionOutcome::Ambiguous,
                        };
                        self.db
                            .record_vote_outcome(id, bundle_index, proposal_id, recorded)
                            .map_err(|_| VotingApiError::new(VotingErrorCode::SubmissionUnknown))?;
                        checkpoint()
                            .await
                            .map_err(|_| VotingApiError::new(VotingErrorCode::SubmissionUnknown))?;
                        if recorded == VoteSubmissionOutcome::Rejected {
                            return Err(VotingApiError::new(VotingErrorCode::SubmissionRejected));
                        }
                        continue;
                    }
                    let mut confirmed = false;
                    for base in &round.vote_server_urls {
                        let response = match transport
                            .execute(vote_status_request(base, &attempt.canonical))
                            .await
                        {
                            Ok(response) => response,
                            Err(TransportError::Definite) => continue,
                            Err(_) => return Err(conflict(())),
                        };
                        match parse_vote_status(response).map_err(conflict)? {
                            VoteStatus::Pending => continue,
                            VoteStatus::Rejected => {
                                self.db
                                    .record_vote_outcome(
                                        id,
                                        bundle_index,
                                        proposal_id,
                                        VoteSubmissionOutcome::Rejected,
                                    )
                                    .map_err(conflict)?;
                                checkpoint().await.map_err(|_| {
                                    VotingApiError::new(VotingErrorCode::SubmissionUnknown)
                                })?;
                                return Err(VotingApiError::new(
                                    VotingErrorCode::SubmissionRejected,
                                ));
                            }
                            VoteStatus::Confirmed(events) => {
                                self.db
                                    .confirm_journaled_vote(
                                        id,
                                        bundle_index,
                                        proposal_id,
                                        attempt.canonical.tx_hash(),
                                        &events,
                                    )
                                    .map_err(conflict)?;
                                checkpoint().await.map_err(|_| {
                                    VotingApiError::new(VotingErrorCode::SubmissionUnknown)
                                })?;
                                confirmed = true;
                                break;
                            }
                        }
                    }
                    if !confirmed {
                        return self.delegation_progress(id, now()?);
                    }
                }
                _ => return Err(conflict(())),
            }
        }
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn submit_ballot(
        &self,
        id: &str,
        decisions: Option<Vec<BallotDecision>>,
    ) -> Result<VotingActionResult, VotingApiError> {
        self.submit_ballot_with(
            id,
            decisions,
            &self.transport,
            || self.ensure_trusted_round(id),
            |round, bundle, drafts| self.build_vote_submission(round, bundle, drafts),
            || self.persistence.checkpoint(&self.db),
            now_secs,
        )
        .await
    }

    async fn build_vote_submission_with<H, J, O, R, S, P>(
        &self,
        round: &TrustedRound,
        sync: impl FnOnce() -> S,
        job: impl FnOnce(H) -> Result<J, VotingApiError>,
        prove: impl FnOnce(J) -> P,
        persist: impl FnOnce(O) -> Result<R, VotingApiError>,
        now: impl Fn() -> Result<u64, VotingApiError>,
    ) -> Result<R, VotingApiError>
    where
        S: Future<Output = Result<H, VotingApiError>>,
        P: Future<Output = Result<O, VotingApiError>>,
    {
        self.validate_delegation_round(&round.summary.round_id, round, now()?)?;
        let height = sync().await?;
        self.validate_delegation_round(&round.summary.round_id, round, now()?)?;
        let job = job(height)?;
        self.validate_delegation_round(&round.summary.round_id, round, now()?)?;
        let prepared = prove(job).await?;
        self.validate_delegation_round(&round.summary.round_id, round, now()?)?;
        persist(prepared)
    }

    #[cfg(target_arch = "wasm32")]
    async fn build_vote_submission(
        &self,
        round: TrustedRound,
        bundle_index: u32,
        drafts: Vec<zcash_voting::vote::DraftVote>,
    ) -> Result<zcash_voting::vote_submission::CanonicalVoteSubmission, VotingApiError> {
        use zcash_voting::proof_executor::ProofExecutor;
        let api = zcash_voting::tree_sync::AsyncHttpTreeSyncApi::new(
            round.tree_url.clone(),
            round.summary.round_id.clone(),
            std::sync::Arc::new(self.transport),
        )
        .map_err(conflict)?;
        let sync = || async {
            self.vote_tree_sync
                .sync_with_async_api(&self.db, &round.summary.round_id, &api)
                .await
                .map_err(conflict)
        };
        let inputs = |height| {
            let witness = self
                .vote_tree_sync
                .generate_van_witness(&self.db, &round.summary.round_id, bundle_index, height)
                .map_err(conflict)?;
            let hotkey = self
                .db
                .load_voting_hotkey(&round.summary.round_id)
                .map_err(conflict)?
                .ok_or_else(|| conflict(()))?;
            Ok::<_, VotingApiError>((witness, hotkey))
        };
        #[cfg(feature = "wasm-parallel")]
        let executor = super::proof_executor::RayonProofExecutor;
        #[cfg(not(feature = "wasm-parallel"))]
        let executor = zcash_voting::proof_executor::SequentialProofExecutor;
        if drafts.len() == 1 {
            return self
                .build_vote_submission_with(
                    &round,
                    sync,
                    |height| {
                        let (witness, hotkey) = inputs(height)?;
                        self.db
                            .vote_proof_job(
                                zcash_voting::vote::VoteSigner::hotkey(&hotkey),
                                &round.summary.round_id,
                                bundle_index,
                                &drafts[0],
                                &witness,
                            )
                            .map_err(conflict)
                    },
                    |job| async {
                        executor
                            .prove(job, |job| {
                                job.prove(&zcash_voting::types::NoopProgressReporter)
                            })
                            .await
                            .map_err(|_| VotingApiError::new(VotingErrorCode::ProofFailed))
                    },
                    |prepared| {
                        let committed =
                            zcash_voting::vote::persist_prepared_commit(&self.db, prepared)
                                .map_err(conflict)?;
                        let signed = committed.signed_commitment(&self.db).map_err(conflict)?;
                        zcash_voting::vote_submission::CanonicalVoteSubmission::from_singleton(
                            &zcash_voting::vote::submission(
                                &self.db,
                                &round.summary.round_id,
                                bundle_index,
                                signed.proposal_id,
                            )
                            .map_err(conflict)?,
                        )
                        .map_err(conflict)
                    },
                    now_secs,
                )
                .await;
        }
        self.build_vote_submission_with(
            &round,
            sync,
            |height| {
                let (witness, hotkey) = inputs(height)?;
                let batch = zcash_voting::vote::AtomicVoteBatch::new(
                    &round.summary.round_id,
                    bundle_index,
                    &drafts,
                    &witness,
                    &zcash_voting::types::NoopProgressReporter,
                );
                self.db
                    .atomic_vote_proof_job(zcash_voting::vote::VoteSigner::hotkey(&hotkey), batch)
                    .map_err(conflict)
            },
            |job| async {
                executor
                    .prove(job, |job| {
                        job.prove(&zcash_voting::types::NoopProgressReporter)
                    })
                    .await
                    .map_err(|_| VotingApiError::new(VotingErrorCode::ProofFailed))
            },
            |prepared| {
                let signed =
                    zcash_voting::vote::persist_prepared_atomic_vote_batch(&self.db, prepared)
                        .map_err(conflict)?;
                zcash_voting::vote_submission::CanonicalVoteSubmission::from_batch(&signed)
                    .map_err(conflict)
            },
            now_secs,
        )
        .await
    }

    pub(crate) fn validate_delegation_key(
        &self,
        usk: &zcash_keys::keys::UnifiedSpendingKey,
        fingerprint: zip32::fingerprint::SeedFingerprint,
    ) -> Result<zcash_voting::delegate::DelegationAccountKeys, VotingApiError> {
        let db = self
            .wallet
            .db
            .try_read()
            .map_err(|_| VotingApiError::new(VotingErrorCode::OperationInProgress))?;
        let account = db
            .get_account(self.account_id)
            .map_err(conflict)?
            .ok_or_else(|| conflict(()))?;
        let derivation = account
            .source()
            .key_derivation()
            .ok_or_else(|| conflict(()))?;
        let ufvk = account.ufvk().ok_or_else(|| conflict(()))?;
        if super::network::VotingNetwork::for_wallet(self.wallet.network) != self.network
            || db.params().network_type() != self.network.network().network_type()
            || *derivation.seed_fingerprint() != fingerprint
            || ufvk.encode(&self.wallet.network).map_err(conflict)?
                != usk
                    .to_unified_full_viewing_key()
                    .encode(&self.wallet.network)
                    .map_err(conflict)?
        {
            return Err(conflict(()));
        }
        let mut digest = Sha256::new();
        digest.update(b"zcash-wallet-wasm/voting-wallet-id/v1");
        digest.update(self.network.label().as_bytes());
        let encoding = SecretString::new(ufvk.encode(&self.wallet.network).map_err(conflict)?);
        digest.update(encoding.expose_secret().as_bytes());
        if hex::encode(digest.finalize()) != self.wallet_id {
            return Err(conflict(()));
        }
        Ok(zcash_voting::delegate::DelegationAccountKeys {
            account_index: derivation.account_index().into(),
            seed_fingerprint: fingerprint.to_bytes(),
            orchard_fvk_bytes: ufvk.orchard().ok_or_else(|| conflict(()))?.to_bytes(),
        })
    }
    pub(crate) fn open(
        wallet: MemoryWallet<Client>,
        account_id: AccountId,
        bytes: Option<&[u8]>,
        persistence: Persistence,
    ) -> Result<Self, VotingApiError> {
        let network = super::network::VotingNetwork::for_wallet(wallet.network);
        let wallet_id = {
            let db = wallet
                .db
                .try_read()
                .map_err(|_| VotingApiError::new(VotingErrorCode::OperationInProgress))?;
            if db.params().network_type() != wallet.network.network_type() {
                return Err(VotingApiError::new(VotingErrorCode::NetworkMismatch));
            }
            let account = db
                .get_account(account_id)
                .map_err(|_| VotingApiError::new(VotingErrorCode::NotEligible))?
                .ok_or_else(|| VotingApiError::new(VotingErrorCode::NotEligible))?;
            if account.source().key_derivation().is_none() {
                return Err(VotingApiError::new(VotingErrorCode::NotEligible));
            }
            let ufvk = account
                .ufvk()
                .filter(|key| key.orchard().is_some())
                .ok_or_else(|| VotingApiError::new(VotingErrorCode::NotEligible))?;
            let encoding = SecretString::new(ufvk.encode(&wallet.network).map_err(conflict)?);
            let mut digest = Sha256::new();
            digest.update(b"zcash-wallet-wasm/voting-wallet-id/v1");
            digest.update(network.label().as_bytes());
            digest.update(encoding.expose_secret().as_bytes());
            hex::encode(digest.finalize())
        };
        let db = VotingDb::open_browser(&wallet_id, network.network(), bytes).map_err(conflict)?;
        let session = Self {
            helper_health: zcash_voting::helper::health::HelperHealth::default(),
            wallet,
            account_id,
            wallet_id,
            network,
            db,
            persistence,
            #[cfg(target_arch = "wasm32")]
            transport: super::transport::BrowserFetchTransport,
            trusted_rounds: RefCell::new(BTreeMap::new()),
            selected_round_id: RefCell::new(None),
            mutation_active: Rc::new(Cell::new(false)),
            vote_tree_sync: zcash_voting::tree_sync::VoteTreeSync::new(),
            eligibility: RefCell::new(BTreeMap::new()),
        };
        let mut pending = None;
        for round in session.db.list_rounds().map_err(conflict)? {
            let id = config::normalize_round_id(&round.round_id).map_err(conflict)?;
            if id != round.round_id {
                return Err(conflict(()));
            }
            // Without a complete caller roster we cannot prove terminality.
            let terminal = if let Some(saved) = session.saved_identity(&id)? {
                let roster = saved
                    .proposals
                    .iter()
                    .map(|p| p.proposal_id)
                    .collect::<Vec<_>>();
                let plan = resume_plan(&session.db, &id, &roster).map_err(conflict)?;
                !roster.is_empty() && plan.all_decided && !plan.pending_recovery
            } else {
                false
            };
            if !terminal && pending.replace(id).is_some() {
                return Err(conflict(()));
            }
        }
        *session.selected_round_id.borrow_mut() = pending;
        Ok(session)
    }
    pub(crate) fn storage_key(&self) -> String {
        format!("zcash-voting:{}:{}", self.network.label(), self.wallet_id)
    }
    pub(crate) fn export_state(&self) -> Result<Vec<u8>, VotingApiError> {
        self.db
            .serialize_bytes()
            .map_err(|_| VotingApiError::new(VotingErrorCode::PersistenceFailed))
    }
    pub(crate) fn mutation_guard(&self) -> Result<MutationGuard, VotingApiError> {
        MutationGuard::acquire(&self.mutation_active)
    }
    pub(crate) fn replace_discovery(
        &self,
        discovery: VotingDiscovery,
        rounds: BTreeMap<String, TrustedRound>,
    ) -> VotingDiscovery {
        self.eligibility.borrow_mut().clear();
        *self.trusted_rounds.borrow_mut() = rounds;
        discovery
    }
    pub(crate) async fn discover_with<F>(&self, fetch: F) -> Result<VotingDiscovery, VotingApiError>
    where
        F: Future<
            Output = Result<(VotingDiscovery, BTreeMap<String, TrustedRound>), VotingApiError>,
        >,
    {
        let _guard = self.mutation_guard()?;
        let (discovery, rounds) = fetch.await?;
        Ok(self.replace_discovery(discovery, rounds))
    }
    pub(crate) fn cached_round_at(
        &self,
        id: &str,
        now: u64,
    ) -> Result<TrustedRound, VotingApiError> {
        let id = config::normalize_round_id(id)?;
        let round = self
            .trusted_rounds
            .borrow()
            .get(&id)
            .cloned()
            .ok_or_else(|| VotingApiError::new(VotingErrorCode::RoundUnauthenticated))?;
        if round.network != self.network {
            return Err(conflict(()));
        }
        if now >= round.summary.ends_at.parse::<u64>().map_err(conflict)? {
            return Err(VotingApiError::new(VotingErrorCode::RoundExpired));
        }
        Ok(round)
    }
    fn saved_identity(
        &self,
        id: &str,
    ) -> Result<Option<AuthenticatedRoundIdentity>, VotingApiError> {
        if !self.db.has_round(id).map_err(conflict)? {
            return Ok(None);
        }
        let json = self.db.round_session_json(id).map_err(conflict)?;
        let Some(json) = json else {
            return if self.network == super::network::VotingNetwork::Mainnet {
                Err(conflict(()))
            } else {
                Ok(None)
            };
        };
        let identity = VotingSessionEnvelope::decode(self.network, &json)?;
        if identity.summary.round_id != id || identity.params.vote_round_id != id {
            return Err(conflict(()));
        }
        Ok(Some(identity))
    }
    pub(crate) fn validate_saved_identity(
        &self,
        round: &TrustedRound,
    ) -> Result<(), VotingApiError> {
        if round.network != self.network {
            return Err(conflict(()));
        }
        let id = &round.summary.round_id;
        if !self.db.has_round(id).map_err(conflict)? {
            return Ok(());
        }
        let saved = self.saved_identity(id)?.ok_or_else(|| conflict(()))?;
        let (params, network) = self.db.round_params_with_network(id).map_err(conflict)?;
        if network != self.network.network() || params != saved.params {
            return Err(conflict(()));
        }
        round.compare_identity(&saved)?;
        Ok(())
    }
    /// Call under the mutation guard before every future network/proof action.
    /// Restored caller data never establishes authentication on its own.
    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn ensure_trusted_round(
        &self,
        id: &str,
    ) -> Result<TrustedRound, VotingApiError> {
        self.ensure_trusted_round_with(
            id,
            config::discover_rounds(&self.transport, self.network),
            now_secs,
        )
        .await
    }
    pub(crate) async fn ensure_trusted_round_with<F>(
        &self,
        id: &str,
        fetch: F,
        now: impl Fn() -> Result<u64, VotingApiError>,
    ) -> Result<TrustedRound, VotingApiError>
    where
        F: Future<
            Output = Result<(VotingDiscovery, BTreeMap<String, TrustedRound>), VotingApiError>,
        >,
    {
        let id = config::normalize_round_id(id)?;
        if !self.trusted_rounds.borrow().contains_key(&id) {
            let (discovery, rounds) = fetch.await?;
            self.replace_discovery(discovery, rounds);
        }
        let round = self.cached_round_at(&id, now()?)?;
        self.validate_saved_identity(&round)?;
        Ok(round)
    }
    pub(crate) async fn round_proposals_with<F>(
        &self,
        id: &str,
        fetch: F,
        now: impl Fn() -> Result<u64, VotingApiError>,
    ) -> Result<Vec<super::types::Proposal>, VotingApiError>
    where
        F: Future<
            Output = Result<(VotingDiscovery, BTreeMap<String, TrustedRound>), VotingApiError>,
        >,
    {
        let _guard = self.mutation_guard()?;
        Ok(self
            .ensure_trusted_round_with(id, fetch, now)
            .await?
            .proposals)
    }
    pub(crate) async fn check_eligibility_at(
        &self,
        id: &str,
        now: impl Fn() -> Result<u64, VotingApiError>,
    ) -> Result<VotingEligibility, VotingApiError> {
        let _guard = self.mutation_guard()?;
        let round = self.cached_round_at(id, now()?)?;
        self.validate_saved_identity(&round)?;
        let eligibility = config::check_eligibility(&self.wallet, self.account_id, &round).await?;
        self.cached_round_at(id, now()?)?;
        self.eligibility
            .borrow_mut()
            .insert(round.summary.round_id, eligibility.clone());
        Ok(eligibility)
    }
    pub(crate) fn round_status_at(
        &self,
        id: &str,
        now: u64,
    ) -> Result<VotingRoundStatus, VotingApiError> {
        let id = config::normalize_round_id(id)?;
        let mut status = VotingRoundStatus {
            round_id: id.clone(),
            phase: VotingRoundPhase::Uninitialized,
            completed_bundles: 0,
            total_bundles: 0,
            confirmed_votes: 0,
            total_votes: 0,
            confirmed_helpers: 0,
            required_helpers: 0,
            next_action: "discover_rounds".into(),
        };
        let cached = self.trusted_rounds.borrow().get(&id).cloned();
        if let Some(round) = cached.as_ref() {
            self.validate_saved_identity(round)?;
        }
        let saved = self.saved_identity(&id)?;
        let identity = cached.as_ref().map(TrustedRound::identity).or(saved);
        if self.db.has_round(&id).map_err(conflict)? {
            status.phase = VotingRoundPhase::RoundPrepared;
            status.total_bundles = self.db.get_bundle_count(&id).map_err(conflict)?;
            let Some(identity) = identity.as_ref() else {
                if status.total_bundles == 0 {
                    status.phase = VotingRoundPhase::Uninitialized;
                }
                return Ok(status);
            };
            let roster = identity
                .proposals
                .iter()
                .map(|p| p.proposal_id)
                .collect::<Vec<_>>();
            let plan = resume_plan(&self.db, &id, &roster).map_err(conflict)?;
            status.completed_bundles = plan
                .delegation_statuses
                .iter()
                .filter(|d| d.phase == DelegationPhase::Confirmed)
                .count() as u32;
            let votes = self.db.vote_phases(&id).map_err(conflict)?;
            status.confirmed_votes = votes
                .iter()
                .filter(|(_, p, phase)| roster.contains(p) && *phase == VotePhase::Confirmed)
                .count() as u32;
            let intents = self.db.ballot_intents(&id).map_err(conflict)?;
            status.total_votes = status
                .total_bundles
                .checked_mul(
                    intents
                        .iter()
                        .filter(|(p, d)| {
                            roster.contains(p)
                                && matches!(d, zcash_voting::session::Decision::Choice(_))
                        })
                        .count() as u32,
                )
                .ok_or_else(|| conflict(()))?;
            let shares = self.db.share_phases(&id).map_err(conflict)?;
            status.confirmed_helpers = shares
                .iter()
                .filter(|(_, p, _, phase)| roster.contains(p) && *phase == SharePhase::Confirmed)
                .count() as u32;
            status.required_helpers = shares
                .iter()
                .filter(|(_, p, _, _)| roster.contains(p))
                .count() as u32
                + plan
                    .next_steps
                    .iter()
                    .filter(|step| matches!(step, NextStep::SubmitShares { .. }))
                    .count() as u32;
            status.next_action = if let Some(step) = plan.next_steps.first() {
                browser_step_kind(&self.db, &id, step)?
            } else if plan.needs_draft_setup {
                "submit_ballot"
            } else {
                browser_round_action(plan.primary_action)?
            }
            .into();
            status.phase = if !roster.is_empty() && plan.all_decided && !plan.pending_recovery {
                VotingRoundPhase::SharesConfirmed
            } else if status.total_bundles == 0 {
                status.next_action = if cached.is_some() {
                    "prepare_round"
                } else {
                    "discover_rounds"
                }
                .into();
                if cached.is_some() {
                    VotingRoundPhase::ConfigAuthenticated
                } else {
                    VotingRoundPhase::Uninitialized
                }
            } else if all_expected_votes_confirmed(status.confirmed_votes, status.total_votes) {
                VotingRoundPhase::VoteConfirmed
            } else if !votes.is_empty() {
                VotingRoundPhase::VotePending
            } else if status.total_bundles > 0 && status.completed_bundles == status.total_bundles {
                VotingRoundPhase::DelegationConfirmed
            } else if plan
                .delegation_statuses
                .iter()
                .any(|d| d.phase != DelegationPhase::Prepared)
            {
                VotingRoundPhase::DelegationPending
            } else {
                VotingRoundPhase::RoundPrepared
            };
            if matches!(
                status.phase,
                VotingRoundPhase::RoundPrepared | VotingRoundPhase::DelegationPending
            ) && zcash_voting::session::delegation_resume_steps(&self.db, &id, &roster)
                .map_err(conflict)?
                .iter()
                .any(|step| matches!(step, NextStep::Delegate { .. }))
            {
                status.next_action = "submit_delegation".into();
            }
            if self.db.load_voting_hotkey(&id).map_err(conflict)?.is_some()
                && self.db.get_round_state(&id).map_err(conflict)?.phase
                    == zcash_voting::storage::RoundPhase::Initialized
            {
                status.phase = VotingRoundPhase::ConfigAuthenticated;
                status.next_action = "prepare_round".into();
            }
        } else if let Some(round) = cached.as_ref() {
            status.phase = VotingRoundPhase::ConfigAuthenticated;
            status.next_action = "check_eligibility".into();
            if let Some(eligibility) = self.eligibility.borrow().get(&id) {
                status.total_bundles = eligibility.bundle_count;
                status.phase = if eligibility.eligible {
                    VotingRoundPhase::Eligible
                } else {
                    VotingRoundPhase::NotEligible
                };
                status.next_action = if eligibility.eligible {
                    "prepare_round"
                } else {
                    "none"
                }
                .into();
            }
            if now >= round.summary.ends_at.parse::<u64>().map_err(conflict)? {
                status.phase = VotingRoundPhase::Expired;
                status.next_action = "none".into();
            }
        } else {
            return Err(VotingApiError::new(VotingErrorCode::RoundUnauthenticated));
        }
        if status.phase != VotingRoundPhase::SharesConfirmed
            && identity.as_ref().is_some_and(|identity| {
                identity
                    .summary
                    .ends_at
                    .parse::<u64>()
                    .is_ok_and(|end| now >= end)
            })
        {
            status.phase = VotingRoundPhase::Expired;
            status.next_action = "none".into();
        }
        if status.phase == VotingRoundPhase::SharesConfirmed
            && self.persistence.has_pending_checkpoint()
        {
            return Err(VotingApiError::new(VotingErrorCode::PersistenceFailed));
        }
        Ok(status)
    }
    pub(crate) async fn clear_round_with<F>(
        &self,
        id: &str,
        checkpoint: impl FnOnce() -> F,
    ) -> Result<(), VotingApiError>
    where
        F: Future<Output = Result<(), VotingApiError>>,
    {
        let id = config::normalize_round_id(id)?;
        let _guard = self.mutation_guard()?;
        self.db.clear_round(&id).map_err(conflict)?;
        // Cleanup runs on success, callback failure, and future cancellation.
        let _cleanup = ClearedRound { session: self, id };
        self.persistence.checkpoint_with(checkpoint).await
    }

    pub(crate) async fn prepare_round_with<P, C>(
        &self,
        id: &str,
        prepare: impl FnOnce(TrustedRound) -> P,
        checkpoint: impl Fn() -> C,
        now: impl Fn() -> Result<u64, VotingApiError>,
    ) -> Result<PreparedVotingRound, VotingApiError>
    where
        P: Future<Output = Result<PreparedVotingRound, VotingApiError>>,
        C: Future<Output = Result<(), VotingApiError>>,
    {
        let _mutation = self.mutation_guard()?;
        let round = self.cached_round_at(id, now()?)?;
        self.validate_saved_identity(&round)?;
        let checkpoint = || self.persistence.checkpoint_with(&checkpoint);
        if self.persistence.has_pending_checkpoint() {
            checkpoint().await?;
            self.cached_round_at(id, now()?)?;
            self.validate_saved_identity(&round)?;
        }
        let id = round.summary.round_id.clone();
        if self
            .selected_round_id
            .borrow()
            .as_ref()
            .is_some_and(|selected| selected != &id)
        {
            return Err(conflict(()));
        }
        *self.selected_round_id.borrow_mut() = Some(id.clone());
        let _selection = PreparingRound {
            session: self,
            id: id.clone(),
        };
        let prepared = prepare(round.clone()).await?;
        self.cached_round_at(&id, now()?)?;
        self.validate_saved_identity(&round)?;
        checkpoint().await?;
        Ok(prepared)
    }

    #[cfg(target_arch = "wasm32")]
    pub(crate) async fn prepare_round(
        &self,
        id: &str,
    ) -> Result<PreparedVotingRound, VotingApiError> {
        use prost::Message;
        use zcash_voting::proof_executor::ProofExecutor;
        let mismatch = |_| VotingApiError::new(VotingErrorCode::PirSnapshotMismatch);
        self.prepare_round_with(
            id,
            |round| async move {
                // This read is public, and releases its client before any wallet access.
                let tree = self
                    .wallet
                    .client
                    .clone()
                    .get_tree_state(zcash_client_backend::proto::service::BlockId {
                        height: round.params.snapshot_height,
                        hash: vec![],
                    })
                    .await
                    .map_err(|_| VotingApiError::new(VotingErrorCode::PirSnapshotMismatch))?
                    .into_inner()
                    .encode_to_vec();
                zcash_voting::precompute::validate_snapshot_tree_state(
                    &round.params,
                    round.network.network(),
                    &tree,
                )
                .map_err(mismatch)?;
                let mut client = zcash_voting::pir::OrderedSnapshotPir::connect(
                    round.pir_layout,
                    round.pir_urls.clone(),
                    std::sync::Arc::new(self.transport),
                    round.network.network(),
                    &round.params.nullifier_imt_root,
                    round.params.snapshot_height,
                )
                .await
                .map_err(mismatch)?;
                self.cached_round_at(&round.summary.round_id, now_secs()?)?;
                let eligibility =
                    config::check_eligibility(&self.wallet, self.account_id, &round).await?;
                self.cached_round_at(&round.summary.round_id, now_secs()?)?;
                if !eligibility.eligible {
                    return Err(VotingApiError::new(VotingErrorCode::NotEligible));
                }
                if !self
                    .db
                    .has_round(&round.summary.round_id)
                    .map_err(conflict)?
                {
                    let envelope = VotingSessionEnvelope::encode(self.network, &round.identity())?;
                    self.db
                        .init_round(self.network.network(), &round.params, Some(&envelope))
                        .map_err(conflict)?;
                }
                let hotkey = self
                    .db
                    .ensure_voting_hotkey(&round.summary.round_id)
                    .map_err(conflict)?;
                let input = super::wallet_adapter::gather_wallet_inputs(
                    &self.wallet,
                    self.account_id,
                    super::wallet_adapter::WalletInputRequest {
                        network: round.network.network(),
                        snapshot_height: round.params.snapshot_height,
                        anchor_tree_state_bytes: tree,
                        resolved_round_name: round.summary.name.clone(),
                        hotkey: &hotkey,
                    },
                )
                .await?;
                self.cached_round_at(&round.summary.round_id, now_secs()?)?;
                // Executors receive owned Rust data only. Reads precede execution; writes follow it.
                #[cfg(feature = "wasm-parallel")]
                let executor = super::proof_executor::RayonProofExecutor;
                #[cfg(not(feature = "wasm-parallel"))]
                let executor = zcash_voting::proof_executor::SequentialProofExecutor;
                let input = executor
                    .prove(input, |input| {
                        for witness in &input.witnesses {
                            zcash_voting::precompute::verify_witness(witness)?;
                        }
                        Ok(input)
                    })
                    .await
                    .map_err(|_| VotingApiError::new(VotingErrorCode::ProofFailed))?;
                self.cached_round_at(&round.summary.round_id, now_secs()?)?;
                let notes = &input.delegation.round_note_infos;
                let policy = self
                    .db
                    .effective_bundle_policy(
                        &round.summary.round_id,
                        zcash_voting::BundlePolicy::default(),
                    )
                    .map_err(conflict)?;
                let bundles = zcash_voting::round::note_bundles_with_policy(notes, policy)
                    .map_err(conflict)?;
                let layout = self
                    .db
                    .ensure_bundles_with_policy(&round.summary.round_id, notes, policy)
                    .map_err(conflict)?;
                if bundles.is_empty() {
                    return Err(VotingApiError::new(VotingErrorCode::NotEligible));
                }
                for (index, notes) in bundles.iter().enumerate() {
                    self.db
                        .ensure_padded_secrets(&round.summary.round_id, index as u32, notes)
                        .map_err(conflict)?;
                    let witnesses = input
                        .witnesses
                        .iter()
                        .filter(|w| notes.iter().any(|n| n.position == w.position))
                        .cloned()
                        .collect::<Vec<_>>();
                    zcash_voting::store_tree_state_and_witnesses(
                        &self.db,
                        &round.summary.round_id,
                        index as u32,
                        &input.delegation.anchor_tree_state_bytes,
                        notes,
                        &witnesses,
                    )
                    .map_err(conflict)?;
                }
                for (index, notes) in bundles.iter().enumerate() {
                    self.cached_round_at(&round.summary.round_id, now_secs()?)?;
                    let client = &mut client;
                    self.db
                        .precompute_delegation_pir_async(
                            &round.summary.round_id,
                            index as u32,
                            notes,
                            round.network.network(),
                            |nullifiers| async move { client.fetch_proofs(&nullifiers).await },
                        )
                        .await
                        .map_err(mismatch)?;
                }
                self.db
                    .advance_round_phase(
                        &round.summary.round_id,
                        zcash_voting::storage::RoundPhase::HotkeyGenerated,
                    )
                    .map_err(conflict)?;
                Ok(PreparedVotingRound {
                    round_id: round.summary.round_id,
                    bundle_count: layout.bundle_count,
                    selected_note_count: bundles.iter().map(Vec::len).sum::<usize>() as u32,
                    voting_power: layout.eligible_weight.to_string(),
                    state: VotingRoundPhase::RoundPrepared,
                })
            },
            || self.persistence.checkpoint(&self.db),
            now_secs,
        )
        .await
    }
}

struct PreparingRound<'a> {
    session: &'a VotingSessionInner,
    id: String,
}
impl Drop for PreparingRound<'_> {
    fn drop(&mut self) {
        // A partial durable round is explicit recovery state, including on cancellation.
        if matches!(self.session.db.has_round(&self.id), Ok(false)) {
            *self.session.selected_round_id.borrow_mut() = None;
        }
    }
}

struct ClearedRound<'a> {
    session: &'a VotingSessionInner,
    id: String,
}
impl Drop for ClearedRound<'_> {
    fn drop(&mut self) {
        self.session.trusted_rounds.borrow_mut().remove(&self.id);
        self.session.eligibility.borrow_mut().remove(&self.id);
        if self.session.selected_round_id.borrow().as_ref() == Some(&self.id) {
            *self.session.selected_round_id.borrow_mut() = None;
        }
    }
}

pub(crate) struct MutationGuard(Rc<Cell<bool>>);
impl MutationGuard {
    pub(crate) fn acquire(active: &Rc<Cell<bool>>) -> Result<Self, VotingApiError> {
        if active.replace(true) {
            return Err(VotingApiError::new(VotingErrorCode::OperationInProgress));
        }
        Ok(Self(active.clone()))
    }
}
impl Drop for MutationGuard {
    fn drop(&mut self) {
        self.0.set(false);
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "../../zcash_voting/zcash_voting/tests/support/delegation_fixture.rs"]
mod delegation_fixture;

#[cfg(all(test, not(target_arch = "wasm32")))]
#[path = "session_ballot_tests.rs"]
mod ballot_driver_tests;

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use futures_util::{future::pending, poll};
    use zcash_client_backend::data_api::{
        AccountBirthday, AccountPurpose, WalletWrite, Zip32Derivation,
    };
    use zcash_protocol::consensus::BlockHeight;
    const ID: &str = "0000000000000000000000000000000000000000000000000000000000000001";

    #[test]
    fn multi_bundle_partial_confirmation_is_not_round_vote_confirmation() {
        // One choice across two bundles requires two independently confirmed votes.
        assert!(!all_expected_votes_confirmed(1, 2));
        assert!(all_expected_votes_confirmed(2, 2));
        assert!(!all_expected_votes_confirmed(1, 0));
    }

    #[tokio::test]
    async fn vote_orchestration_rechecks_expiry_after_sync_and_proof_without_writes() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Transport(AtomicUsize);
        impl zcash_voting::platform::HttpTransport for Transport {
            fn execute(
                &self,
                _: zcash_voting::platform::OwnedHttpRequest,
            ) -> zcash_voting::platform::TransportFuture {
                self.0.fetch_add(1, Ordering::SeqCst);
                Box::pin(std::future::ready(Err(
                    zcash_voting::platform::TransportError::Ambiguous,
                )))
            }
        }
        for proposals in [1, 2] {
            for expire_during_sync in [true, false] {
                let (session, mut round) = session().await;
                round.params.snapshot_height = delegation_fixture::height();
                round.summary.snapshot_height = round.params.snapshot_height;
                if proposals == 2 {
                    let mut proposal = round.proposals[0].clone();
                    proposal.proposal_id = 2;
                    round.proposals.push(proposal);
                }
                session
                    .trusted_rounds
                    .borrow_mut()
                    .insert(ID.into(), round.clone());
                let envelope = serde_json::to_string(&VotingSessionEnvelope {
                    version: 1,
                    authenticated_round: round.identity(),
                })
                .unwrap();
                session
                    .db
                    .init_round(
                        zcash_voting::Network::Testnet,
                        &round.params,
                        Some(&envelope),
                    )
                    .unwrap();
                let delegation = delegation_fixture::prepare(&session.db, &round.params, 17);
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
                session
                    .db
                    .set_complete_ballot_intents(
                        ID,
                        &round
                            .proposals
                            .iter()
                            .map(|p| (p.proposal_id, p.options.len() as u32))
                            .collect::<Vec<_>>(),
                        &round
                            .proposals
                            .iter()
                            .map(|p| (p.proposal_id, zcash_voting::session::Decision::Choice(0)))
                            .collect::<Vec<_>>(),
                    )
                    .unwrap();
                let before = session.export_state().unwrap();
                let clock = Cell::new(1500);
                let jobs = Cell::new(0);
                let proofs = Cell::new(0);
                let writes = Cell::new(0);
                let transport = Transport(AtomicUsize::new(0));
                let (sync_tx, sync_rx) = tokio::sync::oneshot::channel();
                let (proof_tx, proof_rx) = tokio::sync::oneshot::channel();
                let mut proof_tx = Some(proof_tx);
                let mut sync_rx = Some(sync_rx);
                let mut proof_rx = Some(proof_rx);
                let mut work = Box::pin(session.submit_ballot_with(
                    ID,
                    None,
                    &transport,
                    || std::future::ready(Ok(round.clone())),
                    |_, bundle, drafts| {
                        assert_eq!(bundle, 0);
                        assert_eq!(drafts.len(), proposals);
                        let sync_rx = sync_rx.take().unwrap();
                        let proof_rx = proof_rx.take().unwrap();
                        session.build_vote_submission_with(
                            &round,
                            || async move {
                                sync_rx.await.unwrap();
                                Ok(drafts)
                            },
                            |drafts| {
                                jobs.set(jobs.get() + 1);
                                Ok(drafts)
                            },
                            |drafts| {
                                proofs.set(proofs.get() + 1);
                                async move {
                                    proof_rx.await.unwrap();
                                    Ok(drafts)
                                }
                            },
                            |_| {
                                writes.set(writes.get() + 1);
                                Err::<zcash_voting::vote_submission::CanonicalVoteSubmission, _>(
                                    conflict(()),
                                )
                            },
                            || Ok(clock.get()),
                        )
                    },
                    || std::future::ready(Ok(())),
                    || Ok(clock.get()),
                ));
                assert!(poll!(work.as_mut()).is_pending());
                if expire_during_sync {
                    clock.set(2000);
                    proof_tx.take().unwrap().send(()).unwrap();
                }
                sync_tx.send(()).unwrap();
                if !expire_during_sync {
                    assert!(poll!(work.as_mut()).is_pending());
                    assert_eq!(proofs.get(), 1);
                    clock.set(2000);
                    // The sync-expiry case already released its proof result.
                    proof_tx.take().unwrap().send(()).unwrap();
                }
                let result = work.await;
                assert_eq!(result.unwrap_err().code, VotingErrorCode::RoundExpired);
                assert_eq!(jobs.get(), usize::from(!expire_during_sync));
                assert_eq!(proofs.get(), usize::from(!expire_during_sync));
                assert_eq!(writes.get(), 0);
                assert_eq!(transport.0.load(Ordering::SeqCst), 0);
                assert_eq!(session.export_state().unwrap(), before);
                assert!(session.db.vote_phases(ID).unwrap().is_empty());
                assert!(session.db.vote_submission(ID, 0, 1).unwrap().is_none());
            }
        }
    }

    #[tokio::test]
    async fn delegation_continuation_survives_pending_reload_and_unsigned_phases() {
        use std::sync::Mutex;
        use zcash_voting::platform::{
            HttpTransport, OwnedHttpRequest, OwnedHttpResponse, TransportFuture,
        };
        struct Chain {
            calls: Mutex<Vec<OwnedHttpRequest>>,
            confirm: std::sync::atomic::AtomicBool,
        }
        impl HttpTransport for Chain {
            fn execute(&self, request: OwnedHttpRequest) -> TransportFuture {
                let body = if request.method == "POST" {
                    let value: serde_json::Value = serde_json::from_slice(&request.body).unwrap();
                    let _ = value;
                    // A lost response is poll-only, regardless of whether the chain accepted it.
                    self.calls.lock().unwrap().push(request);
                    return Box::pin(std::future::ready(Err(
                        zcash_voting::platform::TransportError::Ambiguous,
                    )));
                } else if self.confirm.load(std::sync::atomic::Ordering::SeqCst) {
                    serde_json::json!({"height":"42","code":0,"events":[{"type":"delegate_vote","attributes":[{"key":"vote_round_id","value":ID},{"key":"leaf_index","value":"42"}]}]})
                } else {
                    serde_json::json!({})
                };
                self.calls.lock().unwrap().push(request);
                let status = if self.confirm.load(std::sync::atomic::Ordering::SeqCst) {
                    200
                } else {
                    404
                };
                Box::pin(std::future::ready(Ok(OwnedHttpResponse {
                    status,
                    content_type: None,
                    body: serde_json::to_vec(&body).unwrap(),
                })))
            }
        }
        for phase in [
            DelegationPhase::Prepared,
            DelegationPhase::PcztBuilt,
            DelegationPhase::Proved,
        ] {
            let (session, mut round) = session().await;
            round.params.snapshot_height = delegation_fixture::height();
            round.summary.snapshot_height = round.params.snapshot_height;
            let envelope = serde_json::to_string(&VotingSessionEnvelope {
                version: 1,
                authenticated_round: round.identity(),
            })
            .unwrap();
            session
                .db
                .init_round(
                    zcash_voting::Network::Testnet,
                    &round.params,
                    Some(&envelope),
                )
                .unwrap();
            let canonical = delegation_fixture::prepare_bundles(&session.db, &round.params, 17, 2);
            let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
                &crate::Network::TestNetwork,
                &[17; 32],
                zip32::AccountId::ZERO,
            )
            .unwrap();
            let fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&[17; 32]).unwrap();
            let chain = Chain {
                calls: Mutex::new(vec![]),
                confirm: std::sync::atomic::AtomicBool::new(false),
            };
            let builds = RefCell::new(Vec::new());
            let error = session
                .submit_delegation_with(
                    ID,
                    usk.clone(),
                    fingerprint,
                    &chain,
                    || std::future::ready(Ok(round.clone())),
                    |_, bundle| {
                        builds.borrow_mut().push(bundle);
                        std::future::ready(Ok(canonical[bundle as usize].clone()))
                    },
                    || std::future::ready(Ok(())),
                    || Ok(1500),
                )
                .await
                .unwrap_err();
            assert_eq!(error.code, VotingErrorCode::SubmissionUnknown);
            let bytes = session.export_state().unwrap();
            let session = open(session.wallet.clone(), session.account_id, Some(&bytes)).unwrap();
            chain
                .confirm
                .store(true, std::sync::atomic::Ordering::SeqCst);
            session
                .submit_ballot_with(
                    ID,
                    None,
                    &chain,
                    || std::future::ready(Ok(round.clone())),
                    |_, _, _| {
                        panic!("keyless Resume must not build a vote");
                        #[allow(unreachable_code)]
                        std::future::ready(Err(conflict(())))
                    },
                    || std::future::ready(Ok(())),
                    || Ok(1500),
                )
                .await
                .unwrap();
            assert_eq!(
                session.db.delegation_phase(ID, 0).unwrap(),
                DelegationPhase::Confirmed
            );
            let sql = match phase {
                DelegationPhase::Prepared => {
                    "UPDATE proofs SET success=0 WHERE bundle_index=1; UPDATE bundles SET pczt_sighash=NULL,rk=NULL,tx1_effects=NULL,delegation_pczt=NULL WHERE bundle_index=1"
                }
                DelegationPhase::PcztBuilt => "UPDATE proofs SET success=0 WHERE bundle_index=1",
                _ => "SELECT 1",
            };
            let bytes = delegation_fixture::corrupt(&session.export_state().unwrap(), sql);
            let session = open(session.wallet.clone(), session.account_id, Some(&bytes)).unwrap();
            assert_eq!(session.db.delegation_phase(ID, 1).unwrap(), phase);
            assert!(session.db.ballot_intents(ID).unwrap().is_empty());
            let status = session.round_status_at(ID, 1500).unwrap();
            assert_eq!(status.completed_bundles, 1);
            assert_eq!(status.next_action, "submit_delegation");
            let error = session.submit_delegation_with(ID,usk.clone(),fingerprint,&chain,
                || std::future::ready(Ok(round.clone())),
                |_, bundle| {
                    builds.borrow_mut().push(bundle);
                    assert_eq!(bundle,1);
                    // Restore synthetic completed build artifacts for this unsigned bundle only.
                    let completed = delegation_fixture::complete_bundle(&session.db,&round.params,17,2,bundle,&canonical[bundle as usize]);
                    let hotkey = session.db.load_voting_hotkey(ID).unwrap().unwrap();
                    let account = session.validate_delegation_key(&usk,fingerprint).unwrap();
                    let keys = zcash_voting::delegate::DelegationKeys::with_voting_hotkey(account.orchard_fvk_bytes.to_vec(),&hotkey,account.seed_fingerprint,account.account_index,round.summary.name.clone()).unwrap();
                    let before_signing = session.export_state().unwrap();
                    let signing_notes = vec![delegation_fixture::notes(17,2)[bundle as usize].clone()];
                    let other = zcash_keys::keys::UnifiedSpendingKey::from_seed(&crate::Network::TestNetwork,&[18;32],zip32::AccountId::ZERO).unwrap();
                    let wrong_fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&[18;32]).unwrap();
                    assert!(session.sign_stored_delegation(&round,bundle,&other,fingerprint,&keys,&signing_notes).is_err());
                    assert!(session.sign_stored_delegation(&round,bundle,&usk,wrong_fingerprint,&keys,&signing_notes).is_err());
                    for (fvk,index,fp) in [
                        (account.orchard_fvk_bytes.to_vec(),1,account.seed_fingerprint),
                        (account.orchard_fvk_bytes.to_vec(),0,wrong_fingerprint.to_bytes()),
                        (orchard::keys::FullViewingKey::from(other.orchard()).to_bytes().to_vec(),0,account.seed_fingerprint),
                    ] {
                        let wrong = zcash_voting::delegate::DelegationKeys::with_voting_hotkey(fvk,&hotkey,fp,index,round.summary.name.clone()).unwrap();
                        assert!(session.sign_stored_delegation(&round,bundle,&usk,fingerprint,&wrong,&signing_notes).is_err());
                    }
                    for sql in [
                        "UPDATE bundles SET pczt_sighash=zeroblob(32) WHERE bundle_index=1",
                        "UPDATE bundles SET alpha=zeroblob(32) WHERE bundle_index=1",
                        "UPDATE bundles SET rk=zeroblob(32) WHERE bundle_index=1",
                        "UPDATE bundles SET nf_signed=zeroblob(32) WHERE bundle_index=1",
                        "UPDATE bundles SET cmx_new=zeroblob(32) WHERE bundle_index=1",
                        "UPDATE bundles SET tx1_effects=zeroblob(821) WHERE bundle_index=1",
                    ] {
                        let tampered = delegation_fixture::corrupt(&before_signing,sql);
                        let restored = open(session.wallet.clone(),session.account_id,Some(&tampered)).unwrap();
                        assert!(restored.sign_stored_delegation(&round,bundle,&usk,fingerprint,&keys,&signing_notes).is_err(),"{sql}");
                        assert_eq!(restored.export_state().unwrap(),tampered);
                    }
                    let wire: zcash_voting::wire::DelegationSubmissionWire = serde_json::from_slice(completed.json_bytes()).unwrap();
                    for (offset,column) in [(33,"nf_signed"),(97,"cmx_new")] {
                        use base64::{Engine,engine::general_purpose::STANDARD};
                        let mut effects=STANDARD.decode(&wire.tx1_effects).unwrap();
                        effects[offset..offset+32].fill(2);
                        let digest=zcash_voting::tx1::tx1_sighash(&effects,zcash_protocol::consensus::BranchId::Nu6_3).unwrap();
                        let sql=format!("UPDATE bundles SET tx1_effects=x'{}',pczt_sighash=x'{}',{column}=x'{}' WHERE bundle_index=1",hex::encode(effects),hex::encode(digest),hex::encode([2;32]));
                        let tampered=delegation_fixture::corrupt(&before_signing,&sql);
                        let restored=open(session.wallet.clone(),session.account_id,Some(&tampered)).unwrap();
                        assert!(restored.sign_stored_delegation(&round,bundle,&usk,fingerprint,&keys,&signing_notes).is_err());
                        assert_eq!(restored.export_state().unwrap(),tampered);
                    }
                    let (signature,sighash) = session.sign_stored_delegation(&round,bundle,&usk,fingerprint,&keys,&signing_notes).unwrap();
                    assert_eq!(session.export_state().unwrap(),before_signing);
                    assert!(session.sign_stored_delegation(&round,0,&usk,fingerprint,&keys,&signing_notes).is_err());
                    let submission = zcash_voting::delegate::submission(&session.db,ID,bundle,zcash_voting::delegate::DelegationSigner::signature(signature,sighash)).unwrap();
                    std::future::ready(zcash_voting::delegation_submission::CanonicalDelegation::from_submission(&submission).map_err(conflict))
                },|| std::future::ready(Ok(())),|| Ok(1500)).await.unwrap_err();
            assert_eq!(error.code, VotingErrorCode::SubmissionUnknown);
            assert_eq!(*builds.borrow(), [0, 1]);
            let calls = chain.calls.lock().unwrap();
            assert_eq!(calls.iter().filter(|r| r.method == "POST").count(), 2);
            assert_eq!(
                calls
                    .iter()
                    .filter(|r| r.method == "POST" && r.body == canonical[0].json_bytes())
                    .count(),
                1
            );
            assert!(
                calls
                    .iter()
                    .filter(|r| r.method == "GET")
                    .all(|r| r.url.ends_with(canonical[0].tx_hash()))
            );
        }
    }

    #[tokio::test]
    async fn complete_ballot_checkpoints_before_any_vote_build_or_network_effect() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use zcash_voting::platform::{
            HttpTransport, OwnedHttpRequest, TransportError, TransportFuture,
        };
        struct Transport(AtomicUsize);
        impl HttpTransport for Transport {
            fn execute(&self, _: OwnedHttpRequest) -> TransportFuture {
                self.0.fetch_add(1, Ordering::SeqCst);
                Box::pin(std::future::ready(Err(TransportError::Ambiguous)))
            }
        }
        let (session, mut round) = session().await;
        round.params.snapshot_height = delegation_fixture::height();
        round.summary.snapshot_height = round.params.snapshot_height;
        session
            .db
            .init_round(
                zcash_voting::Network::Testnet,
                &round.params,
                Some(
                    &serde_json::to_string(&VotingSessionEnvelope {
                        version: 1,
                        authenticated_round: round.identity(),
                    })
                    .unwrap(),
                ),
            )
            .unwrap();
        let canonical = delegation_fixture::prepare_bundles(&session.db, &round.params, 17, 2);
        for (bundle, submission) in canonical.iter().enumerate() {
            session
                .db
                .prepare_delegation_submission(ID, bundle as u32, submission)
                .unwrap();
            session
                .db
                .mark_delegation_dispatching(ID, bundle as u32)
                .unwrap();
            session
                .db
                .confirm_journaled_delegation(
                    ID,
                    bundle as u32,
                    submission.tx_hash(),
                    &[delegation_fixture::event(ID, &(41 + bundle).to_string())],
                )
                .unwrap();
        }
        let decisions = round
            .proposals
            .iter()
            .map(|proposal| BallotDecision::Choice {
                proposal_id: proposal.proposal_id,
                option: 0,
            })
            .collect::<Vec<_>>();
        let transport = Transport(AtomicUsize::new(0));
        let builds = Cell::new(0);
        let result = session
            .submit_ballot_with(
                ID,
                Some(decisions),
                &transport,
                || std::future::ready(Ok(round.clone())),
                |_, _, _| {
                    builds.set(builds.get() + 1);
                    std::future::ready(Err(VotingApiError::new(VotingErrorCode::ProofFailed)))
                },
                || std::future::ready(Err(VotingApiError::new(VotingErrorCode::PersistenceFailed))),
                || Ok(1500),
            )
            .await
            .unwrap_err();
        assert_eq!(result.code, VotingErrorCode::PersistenceFailed);
        assert_eq!(builds.get(), 0);
        assert_eq!(transport.0.load(Ordering::SeqCst), 0);
        assert_eq!(
            session.db.ballot_intents(ID).unwrap().len(),
            round.proposals.len()
        );
    }

    #[tokio::test]
    async fn delegation_signing_rejects_wrong_fingerprint_and_account_before_work() {
        let (session, _) = session().await;
        let fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&[17; 32]).unwrap();
        let usk = |index| {
            zcash_keys::keys::UnifiedSpendingKey::from_seed(
                &crate::Network::TestNetwork,
                &[17; 32],
                zip32::AccountId::try_from(index).unwrap(),
            )
            .unwrap()
        };
        let wrong = zip32::fingerprint::SeedFingerprint::from_seed(&[18; 32]).unwrap();
        assert_eq!(
            session
                .validate_delegation_key(&usk(0), wrong)
                .unwrap_err()
                .code,
            VotingErrorCode::RecoveryConflict
        );
        assert_eq!(
            session
                .validate_delegation_key(&usk(1), fingerprint)
                .unwrap_err()
                .code,
            VotingErrorCode::RecoveryConflict
        );
        assert_eq!(
            session
                .validate_delegation_key(&usk(0), fingerprint)
                .unwrap()
                .account_index,
            0
        );
        assert!(session.wallet.db.try_write().is_ok());
    }

    #[tokio::test]
    async fn delegation_restored_corruption_is_global_before_network() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use zcash_voting::platform::{
            HttpTransport, OwnedHttpRequest, TransportError, TransportFuture,
        };
        struct Transport(AtomicUsize);
        impl HttpTransport for Transport {
            fn execute(&self, _: OwnedHttpRequest) -> TransportFuture {
                self.0.fetch_add(1, Ordering::SeqCst);
                Box::pin(std::future::ready(Err(TransportError::Ambiguous)))
            }
        }
        let (session, mut round) = session().await;
        round.params.snapshot_height = delegation_fixture::height();
        round.summary.snapshot_height = round.params.snapshot_height;
        let envelope = serde_json::to_string(&VotingSessionEnvelope {
            version: 1,
            authenticated_round: round.identity(),
        })
        .unwrap();
        session
            .db
            .init_round(
                zcash_voting::Network::Testnet,
                &round.params,
                Some(&envelope),
            )
            .unwrap();
        let canonical = delegation_fixture::prepare_bundles(&session.db, &round.params, 17, 2);
        for (index, submission) in canonical.iter().enumerate() {
            session
                .db
                .prepare_delegation_submission(ID, index as u32, submission)
                .unwrap();
        }
        session.db.mark_delegation_dispatching(ID, 1).unwrap();
        session
            .db
            .confirm_journaled_delegation(
                ID,
                1,
                canonical[1].tx_hash(),
                &[delegation_fixture::event(ID, "42")],
            )
            .unwrap();
        let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &crate::Network::TestNetwork,
            &[17; 32],
            zip32::AccountId::ZERO,
        )
        .unwrap();
        let fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&[17; 32]).unwrap();
        for all_confirmed in [false, true] {
            if all_confirmed {
                session.db.mark_delegation_dispatching(ID, 0).unwrap();
                session
                    .db
                    .confirm_journaled_delegation(
                        ID,
                        0,
                        canonical[0].tx_hash(),
                        &[delegation_fixture::event(ID, "41")],
                    )
                    .unwrap();
            }
            let bytes = session.export_state().unwrap();
            for sql in delegation_fixture::confirmed_corruptions() {
                let bytes = delegation_fixture::corrupt(&bytes, sql);
                let restored =
                    open(session.wallet.clone(), session.account_id, Some(&bytes)).unwrap();
                let transport = Transport(AtomicUsize::new(0));
                let authentication = Cell::new(0);
                let checkpoints = Cell::new(0);
                let builds = Cell::new(0);
                let error = restored
                    .submit_delegation_with(
                        ID,
                        usk.clone(),
                        fingerprint,
                        &transport,
                        || {
                            authentication.set(authentication.get() + 1);
                            std::future::ready(Ok(round.clone()))
                        },
                        |_, _| {
                            builds.set(builds.get() + 1);
                            std::future::ready(Err(conflict(())))
                        },
                        || {
                            checkpoints.set(checkpoints.get() + 1);
                            std::future::ready(Ok(()))
                        },
                        || Ok(1500),
                    )
                    .await
                    .unwrap_err();
                assert_eq!(error.code, VotingErrorCode::RecoveryConflict);
                assert_eq!(authentication.get(), 0);
                assert_eq!(transport.0.load(Ordering::SeqCst), 0);
                assert_eq!(checkpoints.get(), 0);
                assert_eq!(builds.get(), 0);
                assert!(restored.mutation_guard().is_ok());
            }
        }
    }

    #[tokio::test]
    async fn delegation_checkpoint_failure_has_no_post_and_ambiguity_resumes_by_polling() {
        use std::sync::Mutex;
        use zcash_voting::platform::{
            HttpTransport, OwnedHttpRequest, OwnedHttpResponse, TransportError, TransportFuture,
        };
        struct Transport(Mutex<Vec<OwnedHttpRequest>>);
        impl HttpTransport for Transport {
            fn execute(&self, request: OwnedHttpRequest) -> TransportFuture {
                let post = request.method == "POST";
                self.0.lock().unwrap().push(request);
                Box::pin(async move {
                    if post {
                        Err(TransportError::Ambiguous)
                    } else {
                        Ok(OwnedHttpResponse {
                            content_type: None,
                            status: 404,
                            body: vec![],
                        })
                    }
                })
            }
        }
        let (session, mut round) = session().await;
        round.params.snapshot_height = delegation_fixture::height();
        round.summary.snapshot_height = round.params.snapshot_height;
        session
            .trusted_rounds
            .borrow_mut()
            .insert(ID.into(), round.clone());
        let envelope = serde_json::to_string(&VotingSessionEnvelope {
            version: 1,
            authenticated_round: round.identity(),
        })
        .unwrap();
        session
            .db
            .init_round(
                zcash_voting::Network::Testnet,
                &round.params,
                Some(&envelope),
            )
            .unwrap();
        let canonical = delegation_fixture::prepare(&session.db, &round.params, 17);
        let builds = Cell::new(0);
        let transport = Transport(Mutex::new(vec![]));
        let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &crate::Network::TestNetwork,
            &[17; 32],
            zip32::AccountId::ZERO,
        )
        .unwrap();
        let fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&[17; 32]).unwrap();
        let authenticate = || std::future::ready(Ok(round.clone()));
        let build = |_, _| {
            builds.set(builds.get() + 1);
            std::future::ready(Ok(canonical.clone()))
        };
        let error = session
            .submit_delegation_with(
                ID,
                usk.clone(),
                fingerprint,
                &transport,
                authenticate,
                build,
                || std::future::ready(Err(VotingApiError::new(VotingErrorCode::PersistenceFailed))),
                || Ok(1500),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, VotingErrorCode::PersistenceFailed);
        assert!(transport.0.lock().unwrap().is_empty());
        let prepared_bytes = session.export_state().unwrap();
        struct RejectedTransport;
        impl HttpTransport for RejectedTransport {
            fn execute(&self, _: OwnedHttpRequest) -> TransportFuture {
                Box::pin(std::future::ready(Err(TransportError::Definite)))
            }
        }
        let rejected = open(
            session.wallet.clone(),
            session.account_id,
            Some(&prepared_bytes),
        )
        .unwrap();
        let checkpoints = Cell::new(0);
        let fail_result = || {
            checkpoints.set(checkpoints.get() + 1);
            std::future::ready(if checkpoints.get() == 3 {
                Err(VotingApiError::new(VotingErrorCode::PersistenceFailed))
            } else {
                Ok(())
            })
        };
        assert_eq!(
            rejected
                .submit_delegation_with(
                    ID,
                    usk.clone(),
                    fingerprint,
                    &RejectedTransport,
                    authenticate,
                    build,
                    fail_result,
                    || Ok(1500)
                )
                .await
                .unwrap_err()
                .code,
            VotingErrorCode::SubmissionUnknown
        );
        assert_eq!(
            rejected
                .submit_delegation_with(
                    ID,
                    usk.clone(),
                    fingerprint,
                    &RejectedTransport,
                    authenticate,
                    build,
                    fail_result,
                    || Ok(1500)
                )
                .await
                .unwrap_err()
                .code,
            VotingErrorCode::SubmissionRejected
        );
        // The retry first acknowledges the rejected outcome before planning again.
        assert_eq!(checkpoints.get(), 5);
        struct PendingPost(Mutex<Vec<String>>);
        impl HttpTransport for PendingPost {
            fn execute(&self, request: OwnedHttpRequest) -> TransportFuture {
                let post = request.method == "POST";
                self.0.lock().unwrap().push(request.method);
                Box::pin(async move {
                    if post {
                        pending::<()>().await;
                    }
                    Ok(OwnedHttpResponse {
                        content_type: None,
                        status: 404,
                        body: vec![],
                    })
                })
            }
        }
        let pending_post = PendingPost(Mutex::new(vec![]));
        let cancelled = open(
            session.wallet.clone(),
            session.account_id,
            Some(&prepared_bytes),
        )
        .unwrap();
        let mut operation = Box::pin(cancelled.submit_delegation_with(
            ID,
            usk.clone(),
            fingerprint,
            &pending_post,
            authenticate,
            build,
            || std::future::ready(Ok(())),
            || Ok(1500),
        ));
        assert!(poll!(operation.as_mut()).is_pending());
        assert!(cancelled.mutation_guard().is_err());
        drop(operation);
        assert!(cancelled.mutation_guard().is_ok());
        let restored = open(
            session.wallet.clone(),
            session.account_id,
            Some(&cancelled.export_state().unwrap()),
        )
        .unwrap();
        restored
            .submit_delegation_with(
                ID,
                usk.clone(),
                fingerprint,
                &pending_post,
                authenticate,
                build,
                || std::future::ready(Ok(())),
                || Ok(1500),
            )
            .await
            .unwrap();
        assert_eq!(*pending_post.0.lock().unwrap(), ["POST", "GET"]);
        for cancel_at in [1, 2, 3] {
            let cancelled = open(
                session.wallet.clone(),
                session.account_id,
                Some(&prepared_bytes),
            )
            .unwrap();
            let checkpoints = Cell::new(0);
            let checkpoint = || async {
                checkpoints.set(checkpoints.get() + 1);
                if checkpoints.get() == cancel_at {
                    pending::<()>().await;
                }
                Ok(())
            };
            let mut operation = Box::pin(cancelled.submit_delegation_with(
                ID,
                usk.clone(),
                fingerprint,
                &transport,
                authenticate,
                build,
                checkpoint,
                || Ok(1500),
            ));
            assert!(poll!(operation.as_mut()).is_pending());
            assert!(cancelled.mutation_guard().is_err());
            drop(operation);
            assert!(cancelled.mutation_guard().is_ok());
            assert!(cancelled.persistence.has_pending_checkpoint());
            assert_eq!(
                cancelled
                    .submit_delegation_with(
                        ID,
                        usk.clone(),
                        fingerprint,
                        &transport,
                        || async { panic!("pending persistence must precede authentication") },
                        |_, _| async { panic!("pending persistence must precede proving") },
                        || async { Err(VotingApiError::new(VotingErrorCode::PersistenceFailed)) },
                        || Ok(1500),
                    )
                    .await
                    .unwrap_err()
                    .code,
                VotingErrorCode::PersistenceFailed
            );
            assert!(cancelled.persistence.has_pending_checkpoint());
            assert_eq!(
                transport.0.lock().unwrap().len(),
                usize::from(cancel_at == 3)
            );
            if cancel_at >= 2 {
                cancelled
                    .submit_delegation_with(
                        ID,
                        usk.clone(),
                        fingerprint,
                        &transport,
                        authenticate,
                        build,
                        || std::future::ready(Ok(())),
                        || Ok(1500),
                    )
                    .await
                    .unwrap();
                assert_eq!(
                    transport.0.lock().unwrap().len(),
                    1 + usize::from(cancel_at == 3)
                );
                assert_eq!(transport.0.lock().unwrap().last().unwrap().method, "GET");
                transport.0.lock().unwrap().clear();
            }
        }
        let failed_result = open(
            session.wallet.clone(),
            session.account_id,
            Some(&prepared_bytes),
        )
        .unwrap();
        let checkpoints = Cell::new(0);
        let error = failed_result
            .submit_delegation_with(
                ID,
                usk.clone(),
                fingerprint,
                &transport,
                authenticate,
                build,
                || {
                    checkpoints.set(checkpoints.get() + 1);
                    std::future::ready(if checkpoints.get() == 3 {
                        Err(VotingApiError::new(VotingErrorCode::PersistenceFailed))
                    } else {
                        Ok(())
                    })
                },
                || Ok(1500),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, VotingErrorCode::SubmissionUnknown);
        failed_result
            .submit_delegation_with(
                ID,
                usk.clone(),
                fingerprint,
                &transport,
                authenticate,
                build,
                || std::future::ready(Ok(())),
                || Ok(1500),
            )
            .await
            .unwrap();
        assert_eq!(
            transport
                .0
                .lock()
                .unwrap()
                .iter()
                .map(|r| r.method.as_str())
                .collect::<Vec<_>>(),
            ["POST", "GET"]
        );
        transport.0.lock().unwrap().clear();
        let error = session
            .submit_delegation_with(
                ID,
                usk.clone(),
                fingerprint,
                &transport,
                authenticate,
                build,
                || std::future::ready(Ok(())),
                || Ok(1500),
            )
            .await
            .unwrap_err();
        assert_eq!(error.code, VotingErrorCode::SubmissionUnknown);
        assert_eq!(builds.get(), 1);
        let reopened = open(
            session.wallet.clone(),
            session.account_id,
            Some(&session.export_state().unwrap()),
        )
        .unwrap();
        let progress = reopened
            .submit_delegation_with(
                ID,
                usk.clone(),
                fingerprint,
                &transport,
                authenticate,
                build,
                || std::future::ready(Ok(())),
                || Ok(1500),
            )
            .await
            .unwrap();
        assert_eq!(progress.completed_bundles, 0);
        assert_eq!(builds.get(), 1);
        let calls = transport.0.lock().unwrap();
        assert_eq!(
            calls.iter().map(|r| r.method.as_str()).collect::<Vec<_>>(),
            ["POST", "GET"]
        );
        assert_eq!(calls[0].body, canonical.json_bytes());
        assert!(calls.iter().all(|r| {
            r.url
                .starts_with("https://vote.example.com/shielded-vote/v1/")
        }));
        assert!(calls[1].url.ends_with(canonical.tx_hash()));
        assert!(!session.mutation_active.get());
        drop(calls);
        struct ConfirmedTransport(Mutex<Vec<String>>, String);
        impl HttpTransport for ConfirmedTransport {
            fn execute(&self, request: OwnedHttpRequest) -> TransportFuture {
                let post = request.method == "POST";
                self.0.lock().unwrap().push(request.method);
                let body = if post {
                    serde_json::json!({"code":0,"tx_hash":self.1})
                } else {
                    serde_json::json!({"height":"42","code":0,"events":[{"type":"delegate_vote","attributes":[{"key":"vote_round_id","value":ID},{"key":"leaf_index","value":"42"}]}]})
                };
                Box::pin(async move {
                    Ok(OwnedHttpResponse {
                        content_type: None,
                        status: 200,
                        body: serde_json::to_vec(&body).unwrap(),
                    })
                })
            }
        }
        let confirmed = open(
            session.wallet.clone(),
            session.account_id,
            Some(&prepared_bytes),
        )
        .unwrap();
        let chain = ConfirmedTransport(Mutex::new(vec![]), canonical.tx_hash().into());
        for _ in 0..2 {
            let result = confirmed
                .submit_delegation_with(
                    ID,
                    usk.clone(),
                    fingerprint,
                    &chain,
                    authenticate,
                    build,
                    || std::future::ready(Ok(())),
                    || Ok(1500),
                )
                .await
                .unwrap();
            assert_eq!(result.completed_bundles, 1);
            assert_eq!(result.phase, VotingRoundPhase::DelegationConfirmed);
        }
        assert_eq!(*chain.0.lock().unwrap(), ["POST", "GET"]);
        assert_eq!(builds.get(), 1);
    }

    #[tokio::test]
    async fn prepare_round_rejects_before_work_and_clears_predurable_selection() {
        let (session, _) = session().await;
        let calls = Cell::new(0);
        let work = |_| {
            calls.set(calls.get() + 1);
            std::future::ready(Err::<super::super::types::PreparedVotingRound, _>(
                conflict(()),
            ))
        };
        let checkpoint = || std::future::ready(Ok(()));
        let err = session
            .prepare_round_with("02".repeat(32).as_str(), work, checkpoint, || Ok(1500))
            .await
            .unwrap_err();
        assert_eq!(err.code, VotingErrorCode::RoundUnauthenticated);
        assert_eq!(calls.get(), 0);
        *session.selected_round_id.borrow_mut() = Some("02".repeat(32));
        assert_eq!(
            session
                .prepare_round_with(ID, work, checkpoint, || Ok(1500))
                .await
                .unwrap_err()
                .code,
            VotingErrorCode::RecoveryConflict
        );
        assert_eq!(calls.get(), 0);
        *session.selected_round_id.borrow_mut() = None;
        assert!(
            session
                .prepare_round_with(ID, work, checkpoint, || Ok(1500))
                .await
                .is_err()
        );
        assert_eq!(calls.get(), 1);
        assert!(session.selected_round_id.borrow().is_none());
        assert!(!session.mutation_active.get());
    }

    #[tokio::test]
    async fn prepare_round_cancellation_releases_gate_and_preserves_only_durable_selection() {
        let (session, round) = session().await;
        let mut preparing = Box::pin(session.prepare_round_with(
            ID,
            |_| pending(),
            || std::future::ready(Ok(())),
            || Ok(1500),
        ));
        assert!(poll!(preparing.as_mut()).is_pending());
        assert_eq!(
            session.mutation_guard().err().unwrap().code,
            VotingErrorCode::OperationInProgress
        );
        drop(preparing);
        assert!(session.selected_round_id.borrow().is_none());
        let envelope = serde_json::to_string(&VotingSessionEnvelope {
            version: 1,
            authenticated_round: round.identity(),
        })
        .unwrap();
        let mut preparing = Box::pin(session.prepare_round_with(
            ID,
            |_| {
                session
                    .db
                    .init_round(
                        zcash_voting::Network::Testnet,
                        &round.params,
                        Some(&envelope),
                    )
                    .unwrap();
                session.db.ensure_voting_hotkey(ID).unwrap();
                pending()
            },
            || std::future::ready(Ok(())),
            || Ok(1500),
        ));
        assert!(poll!(preparing.as_mut()).is_pending());
        drop(preparing);
        assert_eq!(*session.selected_round_id.borrow(), Some(ID.into()));
        assert!(session.mutation_guard().is_ok());
        assert_eq!(
            session.round_status_at(ID, 1500).unwrap().next_action,
            "prepare_round"
        );
    }

    #[tokio::test]
    async fn prepare_round_checkpoint_rejection_retains_authoritative_hotkey_and_identity() {
        let (session, round) = session().await;
        let builds = Cell::new(0);
        let prepare = |round: TrustedRound| {
            builds.set(builds.get() + 1);
            let envelope = serde_json::to_string(&VotingSessionEnvelope {
                version: 1,
                authenticated_round: round.identity(),
            })
            .unwrap();
            if !session.db.has_round(ID).unwrap() {
                session
                    .db
                    .init_round(
                        zcash_voting::Network::Testnet,
                        &round.params,
                        Some(&envelope),
                    )
                    .unwrap();
            }
            session.db.ensure_voting_hotkey(ID).unwrap();
            std::future::ready(Ok(super::super::types::PreparedVotingRound {
                round_id: ID.into(),
                bundle_count: 1,
                selected_note_count: 1,
                voting_power: "1".into(),
                state: VotingRoundPhase::RoundPrepared,
            }))
        };
        let failed = session
            .prepare_round_with(
                ID,
                prepare,
                || std::future::ready(Err(VotingApiError::new(VotingErrorCode::PersistenceFailed))),
                || Ok(1500),
            )
            .await
            .unwrap_err();
        assert_eq!(failed.code, VotingErrorCode::PersistenceFailed);
        assert!(session.persistence.has_pending_checkpoint());
        assert_eq!(
            session
                .prepare_round_with(
                    ID,
                    prepare,
                    || async { Err(VotingApiError::new(VotingErrorCode::PersistenceFailed)) },
                    || Ok(1500),
                )
                .await
                .unwrap_err()
                .code,
            VotingErrorCode::PersistenceFailed
        );
        assert_eq!(builds.get(), 1);
        let now = Cell::new(1500);
        assert_eq!(
            session
                .prepare_round_with(
                    ID,
                    prepare,
                    || async {
                        now.set(2000);
                        Ok(())
                    },
                    || Ok(now.get()),
                )
                .await
                .unwrap_err()
                .code,
            VotingErrorCode::RoundExpired
        );
        assert_eq!(builds.get(), 1);
        assert!(!session.persistence.has_pending_checkpoint());
        let hotkey = session.db.ensure_voting_hotkey(ID).unwrap();
        assert_eq!(*session.selected_round_id.borrow(), Some(ID.into()));
        session
            .prepare_round_with(ID, prepare, || std::future::ready(Ok(())), || Ok(1500))
            .await
            .unwrap();
        assert_eq!(
            hotkey.stored_secret(),
            session.db.ensure_voting_hotkey(ID).unwrap().stored_secret()
        );
        let restored = open(
            session.wallet.clone(),
            session.account_id,
            Some(&session.export_state().unwrap()),
        )
        .unwrap();
        restored.validate_saved_identity(&round).unwrap();
        assert_eq!(
            hotkey.stored_secret(),
            restored
                .db
                .ensure_voting_hotkey(ID)
                .unwrap()
                .stored_secret()
        );
    }

    fn wallet(
        network: crate::Network,
        seed: u8,
        derived: bool,
    ) -> (MemoryWallet<Client>, AccountId, String) {
        let mut db = zcash_client_memory::MemoryWalletDb::new(network, 100);
        let birthday = AccountBirthday::from_parts(
            zcash_client_backend::data_api::chain::ChainState::empty(
                BlockHeight::from_u32(3_000_000),
                zcash_primitives::block::BlockHash([0; 32]),
            ),
            None,
        );
        let ufvk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &network,
            &[seed; 32],
            zip32::AccountId::ZERO,
        )
        .unwrap()
        .to_unified_full_viewing_key();
        let encoding = ufvk.encode(&network);
        let derivation = derived.then(|| {
            Zip32Derivation::new(
                zip32::fingerprint::SeedFingerprint::from_seed(&[seed; 32]).unwrap(),
                zip32::AccountId::ZERO,
            )
        });
        let id = db
            .import_account_ufvk(
                "fixture",
                &ufvk,
                &birthday,
                AccountPurpose::Spending { derivation },
                None,
            )
            .unwrap()
            .id();
        (
            crate::Wallet::new(db, Client::new("https://example.invalid".into()), network).unwrap(),
            id,
            encoding.unwrap(),
        )
    }
    fn open(
        wallet: MemoryWallet<Client>,
        account: AccountId,
        bytes: Option<&[u8]>,
    ) -> Result<VotingSessionInner, VotingApiError> {
        VotingSessionInner::open(wallet, account, bytes, Persistence::default())
    }

    async fn authenticated_round(
        network: super::super::network::VotingNetwork,
        snapshot_height: u64,
        with_helper: bool,
    ) -> TrustedRound {
        use base64::Engine as _;

        let mut entry = super::super::config::tests::active();
        entry["snapshot_height"] = serde_json::json!(snapshot_height);
        if network == super::super::network::VotingNetwork::Mainnet {
            entry.as_object_mut().unwrap().remove("network");
        }
        if with_helper {
            entry["helpers"] = serde_json::json!([{
                "id": "round-supplied",
                "url": "https://round-helper.example",
                "public_key": base64::engine::general_purpose::STANDARD.encode([7; 32]),
            }]);
        }
        let (discovery, rounds) =
            super::super::config::tests::discover_for(network, vec![entry], 1500).await;
        assert_eq!(discovery.accepted.len(), 1);
        rounds[ID].clone()
    }

    #[tokio::test]
    async fn helper_urls_are_selected_by_the_authenticated_round_network() {
        use super::super::network::VotingNetwork;

        let mut mainnet_without_helpers =
            authenticated_round(VotingNetwork::Mainnet, 100, false).await;
        assert!(mainnet_without_helpers.helpers.is_empty());
        mainnet_without_helpers
            .vote_server_urls
            .push("https://vote-2.example.com".to_string());
        assert_eq!(
            mainnet_without_helpers.helper_urls(),
            mainnet_without_helpers.vote_server_urls
        );

        let mainnet = authenticated_round(VotingNetwork::Mainnet, 100, true).await;
        assert_eq!(mainnet.helpers.len(), 1);
        assert_eq!(
            mainnet.helper_urls(),
            vec!["https://vote.example.com".to_string()]
        );
        assert_eq!(mainnet.helper_urls(), mainnet.vote_server_urls);
        assert_ne!(mainnet.helper_urls()[0], mainnet.helpers[0].url);

        let testnet = authenticated_round(VotingNetwork::Testnet, 100, true).await;
        assert_eq!(
            testnet.helper_urls(),
            vec!["https://round-helper.example".to_string()]
        );
    }

    #[tokio::test]
    async fn network_specific_delegation_identity_branch_hotkey_and_signature_are_bound() {
        use orchard::primitives::redpallas::{Signature, SpendAuth, VerificationKey};
        use zcash_protocol::consensus::{BranchId, NetworkConstants, Parameters};

        for (wallet_network, voting_network, coin_type) in [
            (
                crate::Network::MainNetwork,
                zcash_voting::Network::Mainnet,
                133,
            ),
            (
                crate::Network::TestNetwork,
                zcash_voting::Network::Testnet,
                1,
            ),
        ] {
            let (wallet, account, _) = wallet(wallet_network, 17, true);
            let session = open(wallet, account, None).unwrap();
            let fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&[17; 32]).unwrap();
            let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
                &wallet_network,
                &[17; 32],
                zip32::AccountId::ZERO,
            )
            .unwrap();
            let account_keys = session.validate_delegation_key(&usk, fingerprint).unwrap();
            assert_eq!(voting_network.network_type().coin_type(), coin_type);
            assert_eq!(account_keys.account_index, 0);
            assert_eq!(
                account_keys.orchard_fvk_bytes,
                usk.to_unified_full_viewing_key()
                    .orchard()
                    .unwrap()
                    .to_bytes()
            );
        }

        for (network, activation_height) in [
            (zcash_voting::Network::Mainnet, 3_428_143),
            (zcash_voting::Network::Testnet, 4_134_000),
        ] {
            assert_eq!(
                zcash_voting::delegate::branch_id_for_height(network, activation_height - 1)
                    .unwrap(),
                u32::from(BranchId::Nu6_2)
            );
            assert_eq!(
                zcash_voting::delegate::branch_id_for_height(network, activation_height).unwrap(),
                u32::from(BranchId::Nu6_3)
            );
        }

        let height = delegation_fixture::height_for(zcash_voting::Network::Mainnet);
        let (wallet, account, _) = wallet(crate::Network::MainNetwork, 17, true);
        let session = open(wallet, account, None).unwrap();
        let round =
            authenticated_round(super::super::network::VotingNetwork::Mainnet, height, false).await;
        let envelope = VotingSessionEnvelope::encode(session.network, &round.identity()).unwrap();
        session
            .db
            .init_round(session.network.network(), &round.params, Some(&envelope))
            .unwrap();
        delegation_fixture::prepare_for_stored_network(&session.db, &round.params, 17);
        let hotkey = session.db.load_voting_hotkey(ID).unwrap().unwrap();
        assert_eq!(hotkey.network(), zcash_voting::Network::Mainnet);
        let fingerprint = zip32::fingerprint::SeedFingerprint::from_seed(&[17; 32]).unwrap();
        let usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &crate::Network::MainNetwork,
            &[17; 32],
            zip32::AccountId::ZERO,
        )
        .unwrap();
        let account_keys = session.validate_delegation_key(&usk, fingerprint).unwrap();
        let keys = zcash_voting::delegate::DelegationKeys::with_voting_hotkey(
            account_keys.orchard_fvk_bytes.to_vec(),
            &hotkey,
            account_keys.seed_fingerprint,
            account_keys.account_index,
            "fixture".into(),
        )
        .unwrap();
        let notes = delegation_fixture::notes_for(zcash_voting::Network::Mainnet, 17, 1);
        let (_, rk) = session
            .db
            .get_delegation_resume_signing_request(ID, 0, &keys, &notes)
            .unwrap();
        let wallet_before = session.wallet.db_to_bytes().await.unwrap();
        let voting_before = session.export_state().unwrap();

        let testnet_usk = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &crate::Network::TestNetwork,
            &[17; 32],
            zip32::AccountId::ZERO,
        )
        .unwrap();
        let other_account = zcash_keys::keys::UnifiedSpendingKey::from_seed(
            &crate::Network::MainNetwork,
            &[17; 32],
            zip32::AccountId::try_from(1).unwrap(),
        )
        .unwrap();
        assert!(
            session
                .sign_stored_delegation(&round, 0, &testnet_usk, fingerprint, &keys, &notes)
                .is_err()
        );
        assert!(
            session
                .sign_stored_delegation(&round, 0, &other_account, fingerprint, &keys, &notes)
                .is_err()
        );
        struct NoNetwork;
        impl zcash_voting::platform::HttpTransport for NoNetwork {
            fn execute(
                &self,
                _: zcash_voting::platform::OwnedHttpRequest,
            ) -> zcash_voting::platform::TransportFuture {
                panic!("wrong-network signer reached submission transport")
            }
        }
        let authentications = Cell::new(0);
        assert_eq!(
            session
                .submit_delegation_with(
                    ID,
                    testnet_usk,
                    fingerprint,
                    &NoNetwork,
                    || {
                        authentications.set(authentications.get() + 1);
                        std::future::ready(Ok(round.clone()))
                    },
                    |_, _| async { panic!("wrong-network signer reached delegation build") },
                    || std::future::ready(Ok(())),
                    || Ok(1500),
                )
                .await
                .unwrap_err()
                .code,
            VotingErrorCode::RecoveryConflict
        );
        assert_eq!(authentications.get(), 0);

        let (signature, sighash) = session
            .sign_stored_delegation(&round, 0, &usk, fingerprint, &keys, &notes)
            .unwrap();
        VerificationKey::<SpendAuth>::try_from(rk)
            .unwrap()
            .verify(&sighash, &Signature::<SpendAuth>::from(signature))
            .unwrap();
        assert_eq!(wallet_before, session.wallet.db_to_bytes().await.unwrap());
        assert_eq!(voting_before, session.export_state().unwrap());
    }
    #[tokio::test]
    async fn mainnet_session_reopens_without_rebinding_testnet() {
        let (wallet, account, encoding) = wallet(crate::Network::MainNetwork, 17, true);
        let session = open(wallet.clone(), account, None).unwrap();
        assert_eq!(
            session.wallet_id,
            hex::encode(Sha256::digest(
                [
                    b"zcash-wallet-wasm/voting-wallet-id/v1".as_slice(),
                    b"mainnet",
                    encoding.as_bytes()
                ]
                .concat()
            ))
        );
        assert!(session.storage_key().starts_with("zcash-voting:mainnet:"));
        let bytes = session.export_state().unwrap();
        assert_eq!(
            open(wallet, account, Some(&bytes)).unwrap().wallet_id,
            session.wallet_id
        );

        let (testnet, account, _) = self::wallet(crate::Network::TestNetwork, 17, true);
        assert_eq!(
            open(testnet, account, Some(&bytes)).err().unwrap().code,
            VotingErrorCode::RecoveryConflict
        );
    }
    #[tokio::test]
    async fn voting_session_envelopes_are_strict_and_network_bound() {
        use super::super::network::VotingNetwork;

        let (_, round) = session().await;
        let identity = round.identity();
        let legacy = serde_json::to_string(&VotingSessionEnvelope {
            version: 1,
            authenticated_round: identity.clone(),
        })
        .unwrap();
        assert_eq!(
            VotingSessionEnvelope::encode(VotingNetwork::Testnet, &identity).unwrap(),
            legacy
        );
        assert_eq!(
            VotingSessionEnvelope::decode(VotingNetwork::Testnet, &legacy).unwrap(),
            identity
        );
        assert!(VotingSessionEnvelope::decode(VotingNetwork::Mainnet, &legacy).is_err());

        let mainnet = VotingSessionEnvelope::encode(VotingNetwork::Mainnet, &identity).unwrap();
        let value: serde_json::Value = serde_json::from_str(&mainnet).unwrap();
        assert_eq!(value["version"], 2);
        assert_eq!(value["network"], "mainnet");
        assert_eq!(value["environment"], "prod");
        assert_eq!(
            value["staticConfigDigest"],
            "28fc9b631091ae8bc2f8635d8930489238ce144174cbd15a03efb0530b301ebe"
        );
        assert_eq!(
            VotingSessionEnvelope::decode(VotingNetwork::Mainnet, &mainnet).unwrap(),
            identity
        );
        assert!(VotingSessionEnvelope::decode(VotingNetwork::Testnet, &mainnet).is_err());

        for field in ["version", "network", "environment", "staticConfigDigest"] {
            let mut value: serde_json::Value = serde_json::from_str(&mainnet).unwrap();
            value.as_object_mut().unwrap().remove(field);
            assert!(
                VotingSessionEnvelope::decode(VotingNetwork::Mainnet, &value.to_string()).is_err(),
                "missing {field}"
            );
        }
        for (field, replacement) in [
            ("version", serde_json::json!(1)),
            ("version", serde_json::json!(3)),
            ("network", serde_json::json!("testnet")),
            ("environment", serde_json::json!("stage")),
            ("staticConfigDigest", serde_json::json!("00")),
        ] {
            let mut value: serde_json::Value = serde_json::from_str(&mainnet).unwrap();
            value[field] = replacement;
            assert!(
                VotingSessionEnvelope::decode(VotingNetwork::Mainnet, &value.to_string()).is_err(),
                "wrong {field}"
            );
        }
        let mut unknown: serde_json::Value = serde_json::from_str(&mainnet).unwrap();
        unknown["unknown"] = true.into();
        assert!(
            VotingSessionEnvelope::decode(VotingNetwork::Mainnet, &unknown.to_string()).is_err()
        );
        for (binding, duplicate_binding) in [
            ("\"version\":2", "\"version\":2,\"version\":2"),
            (
                "\"network\":\"mainnet\"",
                "\"network\":\"mainnet\",\"network\":\"mainnet\"",
            ),
            (
                "\"environment\":\"prod\"",
                "\"environment\":\"prod\",\"environment\":\"prod\"",
            ),
            (
                "\"staticConfigDigest\":\"28fc9b631091ae8bc2f8635d8930489238ce144174cbd15a03efb0530b301ebe\"",
                "\"staticConfigDigest\":\"28fc9b631091ae8bc2f8635d8930489238ce144174cbd15a03efb0530b301ebe\",\"staticConfigDigest\":\"28fc9b631091ae8bc2f8635d8930489238ce144174cbd15a03efb0530b301ebe\"",
            ),
        ] {
            let duplicate = mainnet.replacen(binding, duplicate_binding, 1);
            assert!(VotingSessionEnvelope::decode(VotingNetwork::Mainnet, &duplicate).is_err());
        }
    }
    #[tokio::test]
    async fn mainnet_round_recovery_requires_a_bound_envelope() {
        use super::super::network::VotingNetwork;

        let (wallet, account, _) = wallet(crate::Network::MainNetwork, 17, true);
        let session = open(wallet.clone(), account, None).unwrap();
        let mut entry = super::super::config::tests::active();
        entry.as_object_mut().unwrap().remove("network");
        let (_, rounds) =
            super::super::config::tests::discover_for(VotingNetwork::Mainnet, vec![entry], 1500)
                .await;
        let round = rounds[ID].clone();
        let envelope = VotingSessionEnvelope::encode(session.network, &round.identity()).unwrap();
        session
            .db
            .init_round(session.network.network(), &round.params, Some(&envelope))
            .unwrap();
        let bytes = session.export_state().unwrap();
        let restored = open(wallet.clone(), account, Some(&bytes)).unwrap();
        assert_eq!(restored.saved_identity(ID).unwrap(), Some(round.identity()));

        session.db.clear_round(ID).unwrap();
        let legacy =
            VotingSessionEnvelope::encode(VotingNetwork::Testnet, &round.identity()).unwrap();
        session
            .db
            .init_round(session.network.network(), &round.params, Some(&legacy))
            .unwrap();
        assert_eq!(
            open(wallet, account, Some(&session.export_state().unwrap()))
                .err()
                .unwrap()
                .code,
            VotingErrorCode::RecoveryConflict
        );

        session.db.clear_round(ID).unwrap();
        session
            .db
            .init_round(session.network.network(), &round.params, None)
            .unwrap();
        assert_eq!(
            open(
                session.wallet.clone(),
                session.account_id,
                Some(&session.export_state().unwrap())
            )
            .err()
            .unwrap()
            .code,
            VotingErrorCode::RecoveryConflict
        );
    }
    #[tokio::test]
    async fn cached_rounds_from_the_other_network_are_rejected() {
        use super::super::network::VotingNetwork;

        let (testnet, testnet_round) = session().await;
        let (wallet, account, _) = wallet(crate::Network::MainNetwork, 17, true);
        let mainnet = open(wallet, account, None).unwrap();
        mainnet
            .trusted_rounds
            .borrow_mut()
            .insert(ID.into(), testnet_round);
        assert_eq!(
            mainnet.cached_round_at(ID, 1500).unwrap_err().code,
            VotingErrorCode::RecoveryConflict
        );

        let mut entry = super::super::config::tests::active();
        entry.as_object_mut().unwrap().remove("network");
        let (_, rounds) =
            super::super::config::tests::discover_for(VotingNetwork::Mainnet, vec![entry], 1500)
                .await;
        testnet
            .trusted_rounds
            .borrow_mut()
            .insert(ID.into(), rounds[ID].clone());
        assert_eq!(
            testnet.cached_round_at(ID, 1500).unwrap_err().code,
            VotingErrorCode::RecoveryConflict
        );
    }
    pub(super) async fn session_for(
        network: super::super::network::VotingNetwork,
    ) -> (VotingSessionInner, TrustedRound) {
        let wallet_network = match network {
            super::super::network::VotingNetwork::Testnet => crate::Network::TestNetwork,
            super::super::network::VotingNetwork::Mainnet => crate::Network::MainNetwork,
        };
        let (wallet, account, _) = wallet(wallet_network, 17, true);
        let session = open(wallet, account, None).unwrap();
        let mut entry = super::super::config::tests::active();
        if network == super::super::network::VotingNetwork::Mainnet {
            entry.as_object_mut().unwrap().remove("network");
        }
        let (discovery, rounds) =
            super::super::config::tests::discover_for(network, vec![entry], 1500).await;
        let round = rounds[ID].clone();
        session.replace_discovery(discovery, rounds);
        (session, round)
    }
    pub(super) async fn session() -> (VotingSessionInner, TrustedRound) {
        session_for(super::super::network::VotingNetwork::Testnet).await
    }
    #[tokio::test]
    async fn constructor_validates_identity_and_fails_without_blocking_wallet_writer() {
        let (wallet, account, encoding) = wallet(crate::Network::TestNetwork, 17, true);
        let guard = wallet.db.write().await;
        assert_eq!(
            open(wallet.clone(), account, None).err().unwrap().code,
            VotingErrorCode::OperationInProgress
        );
        drop(guard);
        assert_eq!(
            open(wallet.clone(), 999.into(), None).err().unwrap().code,
            VotingErrorCode::NotEligible
        );
        let session = open(wallet.clone(), account, None).unwrap();
        assert_eq!(
            session.wallet_id,
            hex::encode(Sha256::digest(
                [
                    b"zcash-wallet-wasm/voting-wallet-id/v1".as_slice(),
                    b"testnet",
                    encoding.as_bytes()
                ]
                .concat()
            ))
        );
        assert_eq!(
            session.storage_key(),
            format!("zcash-voting:testnet:{}", session.wallet_id)
        );
        assert!(!session.storage_key().contains(&encoding));
        let bytes = session.export_state().unwrap();
        assert_eq!(
            open(wallet, account, Some(&bytes)).unwrap().wallet_id,
            session.wallet_id
        );
        for (network, seed, derived, code) in [
            (
                crate::Network::MainNetwork,
                17,
                true,
                VotingErrorCode::RecoveryConflict,
            ),
            (
                crate::Network::TestNetwork,
                18,
                true,
                VotingErrorCode::RecoveryConflict,
            ),
            (
                crate::Network::TestNetwork,
                17,
                false,
                VotingErrorCode::NotEligible,
            ),
        ] {
            let (other, account, _) = self::wallet(network, seed, derived);
            assert_eq!(open(other, account, Some(&bytes)).err().unwrap().code, code);
        }
        let (mut mismatched, account, _) = self::wallet(crate::Network::TestNetwork, 17, true);
        mismatched.network = crate::Network::MainNetwork;
        assert_eq!(
            open(mismatched, account, None).err().unwrap().code,
            VotingErrorCode::NetworkMismatch
        );
    }
    #[tokio::test]
    async fn restored_selection_requires_exactly_one_nonterminal_round() {
        let (session, round) = session().await;
        session
            .db
            .init_round(zcash_voting::Network::Testnet, &round.params, None)
            .unwrap();
        let restore = || {
            open(
                session.wallet.clone(),
                session.account_id,
                Some(&session.export_state().unwrap()),
            )
        };
        assert_eq!(
            *restore().unwrap().selected_round_id.borrow(),
            Some(ID.into())
        );
        let mut other = round.params.clone();
        other.vote_round_id = "01".repeat(32);
        session
            .db
            .init_round(zcash_voting::Network::Testnet, &other, None)
            .unwrap();
        assert_eq!(
            restore().err().unwrap().code,
            VotingErrorCode::RecoveryConflict
        );
    }
    #[tokio::test]
    async fn cached_status_is_available_during_mutation_and_ids_fail_closed() {
        let (session, _) = session().await;
        let _guard = session.mutation_guard().unwrap();
        assert_eq!(
            session.round_status_at(ID, 1500).unwrap().phase,
            VotingRoundPhase::ConfigAuthenticated
        );
        assert_eq!(
            session.round_status_at(ID, 2000).unwrap().phase,
            VotingRoundPhase::Expired
        );
        assert_eq!(
            session.cached_round_at("ff", 1500).unwrap_err().code,
            VotingErrorCode::RoundUnauthenticated
        );
        assert_eq!(
            session
                .cached_round_at(&"01".repeat(32), 1500)
                .unwrap_err()
                .code,
            VotingErrorCode::RoundUnauthenticated
        );
        assert_eq!(
            session.cached_round_at(ID, 2000).unwrap_err().code,
            VotingErrorCode::RoundExpired
        );
    }
    #[tokio::test]
    async fn discovery_replaces_only_on_success_and_unknown_ids_never_wait_for_wallet() {
        let (session, _) = session().await;
        let guard = session.wallet.db.write().await;
        let unknown_id = "01".repeat(32);
        let mut eligibility = Box::pin(session.check_eligibility_at(&unknown_id, || Ok(1500)));
        assert!(matches!(
            poll!(&mut eligibility),
            std::task::Poll::Ready(Err(VotingApiError {
                code: VotingErrorCode::RoundUnauthenticated,
                ..
            }))
        ));
        drop(guard);
        assert!(
            session
                .discover_with(async {
                    Err(VotingApiError::new(VotingErrorCode::ConfigFetchFailed))
                })
                .await
                .is_err()
        );
        assert!(session.cached_round_at(ID, 1500).is_ok());
        session
            .discover_with(async {
                Ok((
                    VotingDiscovery {
                        accepted: vec![],
                        rejected: vec![],
                        config_fingerprint: "new".into(),
                    },
                    BTreeMap::new(),
                ))
            })
            .await
            .unwrap();
        assert!(session.cached_round_at(ID, 1500).is_err());
    }
    #[tokio::test]
    async fn round_proposals_require_authenticated_unexpired_round() {
        let (session, round) = session().await;
        assert_eq!(
            session
                .round_proposals_with(ID, async { panic!("cached") }, || Ok(1500))
                .await
                .unwrap(),
            round.proposals
        );
        assert_eq!(
            session
                .round_proposals_with(ID, async { panic!("cached") }, || Ok(2000))
                .await
                .unwrap_err()
                .code,
            VotingErrorCode::RoundExpired
        );
        session.trusted_rounds.borrow_mut().clear();
        let rejected = VotingDiscovery {
            accepted: vec![],
            rejected: vec![super::super::types::RejectedRound {
                round_id: ID.into(),
                code: VotingErrorCode::RoundUnauthenticated,
                message: "unauthenticated".into(),
            }],
            config_fingerprint: "fixture".into(),
        };
        assert_eq!(
            session
                .round_proposals_with(ID, async { Ok((rejected, BTreeMap::new())) }, || Ok(1500))
                .await
                .unwrap_err()
                .code,
            VotingErrorCode::RoundUnauthenticated
        );
    }
    #[tokio::test]
    async fn ensure_uses_current_cache_but_restored_state_must_rediscover() {
        let (session, round) = session().await;
        session
            .ensure_trusted_round_with(ID, async { panic!("cached round fetched") }, || Ok(1500))
            .await
            .unwrap();
        let envelope = VotingSessionEnvelope {
            version: 1,
            authenticated_round: round.identity(),
        };
        session
            .db
            .init_round(
                zcash_voting::Network::Testnet,
                &round.params,
                Some(&serde_json::to_string(&envelope).unwrap()),
            )
            .unwrap();
        let restored = open(
            session.wallet.clone(),
            session.account_id,
            Some(&session.export_state().unwrap()),
        )
        .unwrap();
        let fetched = Cell::new(false);
        restored
            .ensure_trusted_round_with(
                ID,
                async {
                    fetched.set(true);
                    Ok(super::super::config::tests::discover(
                        vec![super::super::config::tests::active()],
                        1500,
                    )
                    .await)
                },
                || Ok(1500),
            )
            .await
            .unwrap();
        assert!(fetched.get());
        assert_eq!(
            restored
                .ensure_trusted_round_with(ID, async { panic!("cached round fetched") }, || Ok(
                    2000
                ))
                .await
                .unwrap_err()
                .code,
            VotingErrorCode::RoundExpired
        );
    }
    #[tokio::test]
    async fn authorization_requires_identity_for_existing_cached_round() {
        let (session, round) = session().await;
        session
            .db
            .init_round(zcash_voting::Network::Testnet, &round.params, None)
            .unwrap();
        let err = session
            .ensure_trusted_round_with(ID, async { panic!("cached round fetched") }, || Ok(1500))
            .await
            .unwrap_err();
        assert_eq!(err.code, VotingErrorCode::RecoveryConflict);
        let _writer = session.wallet.db.write().await;
        let mut eligibility = Box::pin(session.check_eligibility_at(ID, || Ok(1500)));
        assert!(matches!(
            poll!(&mut eligibility),
            std::task::Poll::Ready(Err(VotingApiError {
                code: VotingErrorCode::RecoveryConflict,
                ..
            }))
        ));
    }
    #[tokio::test]
    async fn authorization_requires_identity_after_rediscovery_of_restored_round() {
        let (session, round) = session().await;
        session
            .db
            .init_round(zcash_voting::Network::Testnet, &round.params, None)
            .unwrap();
        let restored = open(
            session.wallet.clone(),
            session.account_id,
            Some(&session.export_state().unwrap()),
        )
        .unwrap();
        let fetched = Cell::new(false);
        let err = restored
            .ensure_trusted_round_with(
                ID,
                async {
                    fetched.set(true);
                    Ok(super::super::config::tests::discover(
                        vec![super::super::config::tests::active()],
                        1500,
                    )
                    .await)
                },
                || Ok(1500),
            )
            .await
            .unwrap_err();
        assert!(fetched.get());
        assert_eq!(err.code, VotingErrorCode::RecoveryConflict);
        assert!(!restored.export_state().unwrap().is_empty());
        restored
            .clear_round_with(ID, || async { Ok(()) })
            .await
            .unwrap();
        assert!(!restored.db.has_round(ID).unwrap());
    }
    #[tokio::test]
    async fn authorization_allows_new_round_after_authenticated_discovery() {
        let (session, _) = session().await;
        assert!(!session.db.has_round(ID).unwrap());
        session
            .ensure_trusted_round_with(ID, async { panic!("cached round fetched") }, || Ok(1500))
            .await
            .unwrap();
        session.trusted_rounds.borrow_mut().clear();
        session
            .ensure_trusted_round_with(
                ID,
                async {
                    Ok(super::super::config::tests::discover(
                        vec![super::super::config::tests::active()],
                        1500,
                    )
                    .await)
                },
                || Ok(1500),
            )
            .await
            .unwrap();
        assert!(!session.db.has_round(ID).unwrap());
    }
    async fn reject_stored_protocol_mismatch(field: &str) {
        let (mut session, round) = session().await;
        let mut params = round.params.clone();
        let mut network = zcash_voting::Network::Testnet;
        match field {
            "snapshot" => params.snapshot_height += 1,
            "authority" => params.ea_pk[0] ^= 1,
            "commitment_root" => params.nc_root[0] ^= 1,
            "nullifier_root" => params.nullifier_imt_root[0] ^= 1,
            "network" => network = zcash_voting::Network::Mainnet,
            _ => panic!("unknown fixture field"),
        }
        // A native DB allows testing the authorization boundary's network check
        // independently of open_browser's earlier owner/network rejection.
        session.db = VotingDb::open(":memory:").unwrap();
        session.db.set_wallet_id(&session.wallet_id);
        let envelope = VotingSessionEnvelope {
            version: 1,
            authenticated_round: round.identity(),
        };
        session
            .db
            .init_round(
                network,
                &params,
                Some(&serde_json::to_string(&envelope).unwrap()),
            )
            .unwrap();
        for cached in [true, false] {
            if !cached {
                session.trusted_rounds.borrow_mut().clear();
            }
            let err = session
                .ensure_trusted_round_with(
                    ID,
                    async {
                        assert!(!cached, "current authenticated cache should be reused");
                        Ok(super::super::config::tests::discover(
                            vec![super::super::config::tests::active()],
                            1500,
                        )
                        .await)
                    },
                    || Ok(1500),
                )
                .await
                .unwrap_err();
            assert_eq!(err.code, VotingErrorCode::RecoveryConflict, "{field}");
            assert_eq!(
                err.message,
                VotingApiError::new(VotingErrorCode::RecoveryConflict).message
            );
        }
    }
    #[tokio::test]
    async fn authorization_rejects_stored_snapshot_mismatch() {
        reject_stored_protocol_mismatch("snapshot").await;
    }
    #[tokio::test]
    async fn authorization_rejects_stored_authority_mismatch() {
        reject_stored_protocol_mismatch("authority").await;
    }
    #[tokio::test]
    async fn authorization_rejects_stored_commitment_root_mismatch() {
        reject_stored_protocol_mismatch("commitment_root").await;
    }
    #[tokio::test]
    async fn authorization_rejects_stored_nullifier_root_mismatch() {
        reject_stored_protocol_mismatch("nullifier_root").await;
    }
    #[tokio::test]
    async fn authorization_rejects_stored_network_mismatch() {
        reject_stored_protocol_mismatch("network").await;
    }
    #[tokio::test]
    async fn restored_empty_roster_is_never_complete_even_after_expiry() {
        let (session, round) = session().await;
        let mut identity = round.identity();
        identity.proposals.clear();
        let envelope = VotingSessionEnvelope {
            version: 1,
            authenticated_round: identity,
        };
        session
            .db
            .init_round(
                zcash_voting::Network::Testnet,
                &round.params,
                Some(&serde_json::to_string(&envelope).unwrap()),
            )
            .unwrap();
        let restored = open(
            session.wallet.clone(),
            session.account_id,
            Some(&session.export_state().unwrap()),
        )
        .unwrap();
        assert!(restored.trusted_rounds.borrow().is_empty());
        assert_eq!(*restored.selected_round_id.borrow(), Some(ID.into()));
        for now in [1500, 2000, 2001] {
            let status = restored.round_status_at(ID, now).unwrap();
            assert_ne!(status.phase, VotingRoundPhase::SharesConfirmed);
            assert_eq!(
                status.phase,
                if now < 2000 {
                    VotingRoundPhase::Uninitialized
                } else {
                    VotingRoundPhase::Expired
                }
            );
        }
    }
    #[tokio::test]
    async fn durable_status_uses_proposal_roster_and_terminal_rounds_do_not_conflict() {
        let (session, round) = session().await;
        let envelope = VotingSessionEnvelope {
            version: 1,
            authenticated_round: round.identity(),
        };
        session
            .db
            .init_round(
                zcash_voting::Network::Testnet,
                &round.params,
                Some(&serde_json::to_string(&envelope).unwrap()),
            )
            .unwrap();
        let status = session.round_status_at(ID, 1500).unwrap();
        assert_eq!(status.phase, VotingRoundPhase::ConfigAuthenticated);
        assert_eq!(status.next_action, "prepare_round");
        assert_eq!(
            session.round_status_at(ID, 2000).unwrap().phase,
            VotingRoundPhase::Expired
        );
        session
            .db
            .set_ballot_intent(ID, 1, zcash_voting::session::Decision::Skipped, 2)
            .unwrap();
        assert_eq!(
            session.round_status_at(ID, 1500).unwrap().phase,
            VotingRoundPhase::SharesConfirmed
        );
        let mut other = round.params.clone();
        other.vote_round_id = "01".repeat(32);
        session
            .db
            .init_round(zcash_voting::Network::Testnet, &other, None)
            .unwrap();
        let restored = open(
            session.wallet.clone(),
            session.account_id,
            Some(&session.export_state().unwrap()),
        )
        .unwrap();
        assert_eq!(
            *restored.selected_round_id.borrow(),
            Some(other.vote_round_id)
        );
        assert_eq!(
            restored.round_status_at(ID, 1500).unwrap().phase,
            VotingRoundPhase::SharesConfirmed
        );
    }
    #[tokio::test]
    async fn malformed_versioned_envelopes_fail_closed_without_echoing_json() {
        let (session, round) = session().await;
        for json in [
            "private invalid JSON".to_owned(),
            "{}".into(),
            serde_json::to_string(&VotingSessionEnvelope {
                version: 2,
                authenticated_round: round.identity(),
            })
            .unwrap(),
            {
                let mut value = serde_json::to_value(VotingSessionEnvelope {
                    version: 1,
                    authenticated_round: round.identity(),
                })
                .unwrap();
                value["unknown"] = true.into();
                value.to_string()
            },
        ] {
            session
                .db
                .init_round(zcash_voting::Network::Testnet, &round.params, Some(&json))
                .unwrap();
            let err = open(
                session.wallet.clone(),
                session.account_id,
                Some(&session.export_state().unwrap()),
            )
            .err()
            .unwrap();
            assert_eq!(err.code, VotingErrorCode::RecoveryConflict);
            assert!(!err.message.contains("private"));
            session.db.clear_round(ID).unwrap();
        }
    }
    #[tokio::test]
    async fn restored_identity_requires_discovery_and_exact_envelope_match() {
        let (session, round) = session().await;
        let envelope = VotingSessionEnvelope {
            version: 1,
            authenticated_round: round.identity(),
        };
        session
            .db
            .init_round(
                zcash_voting::Network::Testnet,
                &round.params,
                Some(&serde_json::to_string(&envelope).unwrap()),
            )
            .unwrap();
        let restored = open(
            session.wallet.clone(),
            session.account_id,
            Some(&session.export_state().unwrap()),
        )
        .unwrap();
        assert!(restored.cached_round_at(ID, 1500).is_err());
        assert!(restored.validate_saved_identity(&round).is_ok());
        let mut changed = round.clone();
        changed.proposals[0].title.push('!');
        assert_eq!(
            restored.validate_saved_identity(&changed).unwrap_err().code,
            VotingErrorCode::RecoveryConflict
        );
        assert_eq!(
            session.db.round_session_json(ID).unwrap(),
            Some(serde_json::to_string(&envelope).unwrap())
        );
        assert!(session.db.round_session_json(&"01".repeat(32)).is_err());
    }
    #[tokio::test]
    async fn clear_failure_keeps_deleted_db_authoritative_and_allows_checkpoint_retry() {
        let (session, round) = session().await;
        session
            .db
            .init_round(zcash_voting::Network::Testnet, &round.params, None)
            .unwrap();
        session
            .db
            .set_ballot_intent(ID, 1, zcash_voting::session::Decision::Skipped, 2)
            .unwrap();
        *session.selected_round_id.borrow_mut() = Some(ID.into());
        let result = session
            .clear_round_with(ID, || async {
                Err(VotingApiError::new(VotingErrorCode::PersistenceFailed))
            })
            .await;
        assert_eq!(result.unwrap_err().code, VotingErrorCode::PersistenceFailed);
        assert!(!session.db.has_round(ID).unwrap());
        assert!(session.db.ballot_intents(ID).unwrap().is_empty());
        assert!(session.trusted_rounds.borrow().is_empty());
        assert!(session.selected_round_id.borrow().is_none());
        session
            .clear_round_with(ID, || async { Ok(()) })
            .await
            .unwrap();
        assert!(
            open(
                session.wallet.clone(),
                session.account_id,
                Some(&session.export_state().unwrap())
            )
            .unwrap()
            .db
            .list_rounds()
            .unwrap()
            .is_empty()
        );
    }
    #[tokio::test]
    async fn cancelled_clear_releases_gate_and_does_not_reuse_checkpoint_revision() {
        let (session, round) = session().await;
        session
            .db
            .init_round(zcash_voting::Network::Testnet, &round.params, None)
            .unwrap();
        let revisions = RefCell::new(Vec::new());
        let mut clearing = Box::pin(session.clear_round_with(ID, || {
            session.persistence.revision.checkpoint(
                || session.export_state(),
                |_, revision| {
                    revisions.borrow_mut().push(revision);
                    pending::<Result<(), VotingApiError>>()
                },
            )
        }));
        assert!(poll!(&mut clearing).is_pending());
        assert!(!session.db.has_round(ID).unwrap());
        assert_eq!(
            session.mutation_guard().err().unwrap().code,
            VotingErrorCode::OperationInProgress
        );
        // A read can use the last authenticated cache during the pending callback.
        assert_eq!(
            session.round_status_at(ID, 1500).unwrap().phase,
            VotingRoundPhase::ConfigAuthenticated
        );
        drop(clearing);
        assert!(session.persistence.has_pending_checkpoint());
        assert!(session.trusted_rounds.borrow().is_empty());
        session
            .clear_round_with(ID, || {
                session.persistence.revision.checkpoint(
                    || session.export_state(),
                    |_, revision| {
                        revisions.borrow_mut().push(revision);
                        std::future::ready(Ok(()))
                    },
                )
            })
            .await
            .unwrap();
        assert_eq!(*revisions.borrow(), [1, 2]);
        assert!(!session.persistence.has_pending_checkpoint());
    }
    #[tokio::test]
    #[ignore = "generates public synthetic inputs for the Chrome session harness"]
    async fn write_browser_session_fixtures() {
        let path = std::path::Path::new("/tmp/task-8-browser-fixtures");
        std::fs::create_dir_all(path).unwrap();
        let (session, round) = session().await;
        std::fs::write(
            path.join("wallet.bin"),
            session.wallet.db_to_bytes().await.unwrap(),
        )
        .unwrap();
        let (other, _, _) = wallet(crate::Network::TestNetwork, 18, true);
        std::fs::write(
            path.join("other-wallet.bin"),
            other.db_to_bytes().await.unwrap(),
        )
        .unwrap();
        let (mainnet, _) = session_for(super::super::network::VotingNetwork::Mainnet).await;
        std::fs::write(
            path.join("mainnet-wallet.bin"),
            mainnet.wallet.db_to_bytes().await.unwrap(),
        )
        .unwrap();
        let envelope = VotingSessionEnvelope {
            version: 1,
            authenticated_round: round.identity(),
        };
        session
            .db
            .init_round(
                zcash_voting::Network::Testnet,
                &round.params,
                Some(&serde_json::to_string(&envelope).unwrap()),
            )
            .unwrap();
        std::fs::write(path.join("voting.bin"), session.export_state().unwrap()).unwrap();
        std::fs::write(path.join("metadata.json"),serde_json::to_vec(&serde_json::json!({"accountId":*session.account_id,"mainnetAccountId":*mainnet.account_id,"roundId":ID,"storageKey":session.storage_key()})).unwrap()).unwrap();
        session.db.clear_round(ID).unwrap();
        let mut round = round;
        round.params.snapshot_height = delegation_fixture::height();
        round.summary.snapshot_height = round.params.snapshot_height;
        let envelope = serde_json::to_string(&VotingSessionEnvelope {
            version: 1,
            authenticated_round: round.identity(),
        })
        .unwrap();
        session
            .db
            .init_round(
                zcash_voting::Network::Testnet,
                &round.params,
                Some(&envelope),
            )
            .unwrap();
        let canonical = delegation_fixture::prepare_bundles(&session.db, &round.params, 17, 2);
        for (bundle, submission) in canonical.iter().enumerate() {
            session
                .db
                .prepare_delegation_submission(ID, bundle as u32, submission)
                .unwrap();
        }
        for bundle in [1, 0] {
            session.db.mark_delegation_dispatching(ID, bundle).unwrap();
            session
                .db
                .confirm_journaled_delegation(
                    ID,
                    bundle,
                    canonical[bundle as usize].tx_hash(),
                    &[delegation_fixture::event(ID, &(41 + bundle).to_string())],
                )
                .unwrap();
            let corrupt = delegation_fixture::corrupt(
                &session.export_state().unwrap(),
                "UPDATE proofs SET proof=x'02' WHERE bundle_index=1",
            );
            std::fs::write(
                path.join(if bundle == 1 {
                    "delegation-mixed-corrupt.bin"
                } else {
                    "delegation-confirmed-corrupt.bin"
                }),
                corrupt,
            )
            .unwrap();
        }
        std::fs::write(
            path.join("delegation-confirmed.bin"),
            session.export_state().unwrap(),
        )
        .unwrap();
    }
    #[tokio::test]
    async fn mutation_gate_rejects_overlap_and_releases_on_cancellation() {
        let active = Rc::new(Cell::new(false));
        let mut operation = Box::pin(async {
            let _guard = MutationGuard::acquire(&active).unwrap();
            pending::<()>().await;
        });
        assert!(poll!(&mut operation).is_pending());
        assert!(matches!(
            MutationGuard::acquire(&active),
            Err(VotingApiError {
                code: VotingErrorCode::OperationInProgress,
                ..
            })
        ));
        drop(operation);
        assert!(MutationGuard::acquire(&active).is_ok());
    }
}
