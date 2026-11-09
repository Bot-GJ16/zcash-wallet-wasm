//! Durable ballot intent + resumable voting-session planner.
//!
//! `resume_plan` reads a round once, as one [`RoundSnapshot`] taken in a
//! single read transaction, and derives the ordered remaining work for the
//! round from that snapshot alone. The wallet executes each step with its
//! own network/proof/sign plumbing.

use rusqlite::named_params;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

use crate::chain_submission::ChainSubmissionDiagnostic;
use crate::phases::DelegationPhase;
use crate::share_policy::ImmediateShareKey;
use crate::storage::{queries, VotingDb};
use crate::types::{
    validate_proposal_id, validate_vote_decision, validate_vote_options, VotingError,
};
use crate::vote::{validate_draft_vote, DraftVote};

/// The voter's terminal decision for one proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Choice(u32),
    Skipped,
}

/// Durable ballot-intent classification shared by resume and helper planning.
pub(crate) struct BallotIntentClassification {
    pub(crate) roster: BTreeSet<u32>,
    pub(crate) choice_proposals: Vec<u32>,
    pub(crate) open_proposals: Vec<u32>,
    /// Durable intents for proposals outside the authenticated roster.
    pub(crate) unrostered_intents: Vec<u32>,
}

pub(crate) fn classify_ballot_intents(
    proposal_ids: &[u32],
    intents: &BTreeMap<u32, Decision>,
) -> Result<BallotIntentClassification, VotingError> {
    let mut roster = BTreeSet::new();
    for &proposal_id in proposal_ids {
        validate_proposal_id(proposal_id)?;
        if !roster.insert(proposal_id) {
            return Err(VotingError::InvalidInput {
                message: format!("proposal roster contains duplicate id {proposal_id}"),
            });
        }
    }

    let mut choice_proposals = Vec::new();
    let mut open_proposals = Vec::new();
    for &proposal_id in &roster {
        match intents.get(&proposal_id) {
            Some(Decision::Choice(_)) => choice_proposals.push(proposal_id),
            Some(Decision::Skipped) => {}
            None => open_proposals.push(proposal_id),
        }
    }

    let unrostered_intents = intents
        .keys()
        .copied()
        .filter(|proposal_id| !roster.contains(proposal_id))
        .collect();

    Ok(BallotIntentClassification {
        roster,
        choice_proposals,
        open_proposals,
        unrostered_intents,
    })
}

pub(crate) use crate::round_planning::vote_phase_is_lifecycle_owned;

impl VotingDb {
    /// Atomically records one terminal decision for every authenticated proposal.
    ///
    /// `proposal_options` is the complete authenticated proposal roster as
    /// `(proposal_id, num_options)`. Validation of both inputs finishes before
    /// any ballot, vote-recovery, or helper-share row is changed.
    pub fn set_complete_ballot_intents(
        &self,
        round_id: &str,
        proposal_options: &[(u32, u32)],
        decisions: &[(u32, Decision)],
    ) -> Result<(), VotingError> {
        let mut roster = BTreeMap::new();
        for &(proposal_id, num_options) in proposal_options {
            validate_proposal_id(proposal_id)?;
            validate_vote_options(num_options)?;
            if roster.insert(proposal_id, num_options).is_some() {
                return Err(VotingError::InvalidInput {
                    message: format!("proposal roster contains duplicate id {proposal_id}"),
                });
            }
        }
        if roster.is_empty() {
            return Err(VotingError::InvalidInput {
                message: "proposal roster must not be empty".to_string(),
            });
        }

        let mut validated = BTreeMap::new();
        for &(proposal_id, decision) in decisions {
            validate_proposal_id(proposal_id)?;
            let num_options =
                roster
                    .get(&proposal_id)
                    .ok_or_else(|| VotingError::InvalidInput {
                        message: format!("ballot contains unknown proposal id {proposal_id}"),
                    })?;
            validate_ballot_intent_decision(decision, *num_options)?;
            if validated.insert(proposal_id, decision).is_some() {
                return Err(VotingError::InvalidInput {
                    message: format!("ballot contains duplicate proposal id {proposal_id}"),
                });
            }
        }
        if validated.len() != roster.len() {
            return Err(VotingError::InvalidInput {
                message: "ballot must contain exactly one decision for every proposal".to_string(),
            });
        }

        let now = now_secs();
        let wallet_id = self.wallet_id();
        self.write_transaction("set_complete_ballot_intents transaction failed", |tx| {
            for (proposal_id, decision) in validated {
                write_ballot_intent_in_tx(tx, &wallet_id, round_id, proposal_id, decision, now)?;
            }
            Ok(())
        })
    }

    /// Record (insert or replace) the voter's decision for one proposal.
    ///
    /// `num_options` must be the proposal's declared option count. Choice
    /// decisions are validated against it before any durable intent is written.
    /// Written on each selection, before any per-proposal vote artifact exists.
    pub fn set_ballot_intent(
        &self,
        round_id: &str,
        proposal_id: u32,
        decision: Decision,
        num_options: u32,
    ) -> Result<(), VotingError> {
        validate_proposal_id(proposal_id)?;
        validate_ballot_intent_decision(decision, num_options)?;

        self.write_ballot_intent(round_id, proposal_id, decision)
    }

    /// Retires committed but undispatched votes on `bundle_index` for
    /// proposals outside `roster`, returning the retired proposal ids.
    ///
    /// Such a vote can never be submitted once its proposal left the
    /// authenticated roster, but its commitment keeps the bundle's VAN
    /// reserved and blocks every later cast on the bundle; its intent cannot
    /// be cleared while a sibling bundle's vote for the same proposal is on
    /// the chain lifecycle. The executor retires them before casting. Votes
    /// the chain lifecycle owns or has finished are left untouched.
    pub fn retire_undispatched_votes_outside_roster(
        &self,
        round_id: &str,
        bundle_index: u32,
        roster: &[u32],
    ) -> Result<Vec<u32>, VotingError> {
        let wallet_id = self.wallet_id();
        self.write_transaction("retire undispatched votes transaction failed", |tx| {
            crate::vote::retire_undispatched_votes_outside_roster_with_conn(
                tx,
                &wallet_id,
                round_id,
                bundle_index,
                roster,
            )
        })
    }

    /// Removes the durable decision for one proposal.
    ///
    /// A decision that survives a roster change refers to a proposal the
    /// authenticated configuration no longer lists; the planner reports it in
    /// `RoundPlan::unrostered_intents` and withholds `CastVote` until it is
    /// cleared. Clearing an intent that does not exist is not an error.
    ///
    /// The canonical vote phase, read inside the same write transaction as
    /// the deletion, decides whether clearing is allowed. A vote
    /// for the proposal that the chain lifecycle owns or has finished
    /// (submitted, managed, hashless, rejected, or confirmed) may already be
    /// on chain, so its intent cannot be cleared. A vote that is signed but
    /// not dispatched has its unsubmitted recovery invalidated, exactly as a
    /// changed intent does.
    ///
    /// # Errors
    ///
    /// Returns [`VotingError::InvalidInput`] for an out-of-range proposal id
    /// or a proposal whose vote is on or past the chain lifecycle.
    pub fn clear_ballot_intent(&self, round_id: &str, proposal_id: u32) -> Result<(), VotingError> {
        validate_proposal_id(proposal_id)?;
        let wallet_id = self.wallet_id();
        self.write_transaction("clear_ballot_intent transaction failed", |tx| {
            // Evaluated under the write transaction, so a submission that
            // becomes terminal between a read and the delete cannot slip past.
            if let Some((bundle_index, phase)) =
                crate::phases::vote_phases_for_proposal(tx, &wallet_id, round_id, proposal_id)?
                    .into_iter()
                    .find(|(_, phase)| vote_phase_is_lifecycle_owned(*phase))
            {
                return Err(VotingError::InvalidInput {
                    message: format!(
                        "round {round_id} bundle {bundle_index} proposal {proposal_id} vote is {} on the chain lifecycle; its intent cannot be cleared",
                        phase.as_str()
                    ),
                });
            }
            crate::vote::invalidate_unsubmitted_vote_recoveries_for_intent(
                tx,
                &wallet_id,
                round_id,
                proposal_id,
                None,
            )?;
            tx.execute(
                "DELETE FROM ballot_intent
                 WHERE round_id = :round_id AND wallet_id = :wallet_id AND proposal_id = :proposal_id",
                named_params! {
                    ":round_id": round_id,
                    ":wallet_id": wallet_id,
                    ":proposal_id": proposal_id as i64,
                },
            )
            .map_err(|e| VotingError::from_sqlite("clear ballot intent", &e))?;
            Ok(())
        })
    }

    /// Record the voter's decisions for several proposals atomically.
    ///
    /// Each entry is `(proposal_id, decision, num_options)`, where
    /// `num_options` is that proposal's declared option count. Every entry is
    /// validated, and the batch is rejected if it names one proposal twice,
    /// before any durable intent is written; the writes then share one
    /// transaction, so a conflict raised by a later entry — a submitted vote
    /// that contradicts it, for instance — leaves none of the batch applied.
    ///
    /// # Errors
    ///
    /// Returns [`VotingError::InvalidInput`] for an out-of-range proposal id,
    /// a decision that does not fit its option count, or a repeated proposal
    /// id.
    /// A round already stored under `round_id` must be stored for
    /// `expected_network`; the check runs inside the write transaction, and
    /// a mismatch is [`VotingError::InvalidInput`] with no intent written.
    pub fn set_ballot_intents(
        &self,
        round_id: &str,
        expected_network: crate::types::Network,
        intents: &[(u32, Decision, u32)],
    ) -> Result<(), VotingError> {
        let mut seen = BTreeSet::new();
        for &(proposal_id, decision, num_options) in intents {
            validate_proposal_id(proposal_id)?;
            validate_ballot_intent_decision(decision, num_options)?;
            if !seen.insert(proposal_id) {
                return Err(VotingError::InvalidInput {
                    message: format!("ballot intent batch decides proposal {proposal_id} twice"),
                });
            }
        }

        let now = now_secs();
        let wallet_id = self.wallet_id();
        self.write_transaction("set_ballot_intents transaction failed", |tx| {
            // Checked under the write lock so a round created for another
            // network between the caller's check and this write cannot take
            // choices resolved against a different network's roster.
            if crate::storage::queries::has_round(tx, round_id, &wallet_id)? {
                let stored = crate::storage::queries::load_round_network(tx, round_id, &wallet_id)?;
                if stored != expected_network {
                    return Err(VotingError::InvalidInput {
                        message: format!(
                            "round {round_id} is stored for network {stored:?} but the ballot intents are for {expected_network:?}"
                        ),
                    });
                }
            }
            for &(proposal_id, decision, _) in intents {
                write_ballot_intent_in_tx(tx, &wallet_id, round_id, proposal_id, decision, now)?;
            }
            Ok(())
        })
    }

    /// Record a choice intent from a fully validated draft vote.
    pub fn set_ballot_intent_for_draft_vote(
        &self,
        round_id: &str,
        draft: &DraftVote,
    ) -> Result<(), VotingError> {
        validate_draft_vote(draft)?;
        self.write_ballot_intent(round_id, draft.proposal_id, Decision::Choice(draft.choice))
    }

    fn write_ballot_intent(
        &self,
        round_id: &str,
        proposal_id: u32,
        decision: Decision,
    ) -> Result<(), VotingError> {
        let now = now_secs();
        let wallet_id = self.wallet_id();
        self.write_transaction("set_ballot_intent transaction failed", |tx| {
            write_ballot_intent_in_tx(tx, &wallet_id, round_id, proposal_id, decision, now)
        })
    }
}

/// Writes one durable ballot intent inside a caller-owned transaction.
///
/// Resolves the conflicting-vote and stale-share side effects of the decision
/// alongside the intent row, so a batch of intents can commit atomically.
fn write_ballot_intent_in_tx(
    tx: &rusqlite::Transaction<'_>,
    wallet_id: &str,
    round_id: &str,
    proposal_id: u32,
    decision: Decision,
    now: i64,
) -> Result<(), VotingError> {
    let (skipped, choice): (i64, Option<i64>) = match decision {
        Decision::Choice(c) => (0, Some(c as i64)),
        Decision::Skipped => (1, None),
    };
    let skipped_bool = skipped != 0;
    let choice_u32 = choice.map(|c| c as u32);
    queries::ensure_no_submitted_vote_conflict_for_intent(
        tx,
        round_id,
        wallet_id,
        proposal_id,
        skipped_bool,
        choice_u32,
    )?;
    crate::vote::invalidate_unsubmitted_vote_recoveries_for_intent(
        tx,
        wallet_id,
        round_id,
        proposal_id,
        choice_u32,
    )?;
    // A decision that differs from the stored one changes what the next
    // combined batch will contain, so any rejection streak counted against the
    // old batch stops describing it. The streak is keyed on the delegation
    // generation, which this edit does not touch, so nothing else would lift a
    // block whose cause was a vote member rather than the delegation. Read
    // before the upsert below, which is what makes the decision the stored one.
    let stored_intent: Option<(i64, Option<i64>)> = tx
        .query_row(
            "SELECT skipped, choice FROM ballot_intent
              WHERE round_id = :round_id AND wallet_id = :wallet_id
                AND proposal_id = :proposal_id",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":proposal_id": proposal_id as i64,
            },
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .map(Some)
        .or_else(|error| match error {
            rusqlite::Error::QueryReturnedNoRows => Ok(None),
            other => Err(other),
        })
        .map_err(|e| VotingError::from_sqlite("read ballot intent before update", &e))?;
    let intent_changed = stored_intent != Some((skipped, choice));
    tx.execute(
        "INSERT INTO ballot_intent
            (round_id, wallet_id, proposal_id, skipped, choice, created_at, updated_at)
         VALUES (:round_id, :wallet_id, :proposal_id, :skipped, :choice, :now, :now)
         ON CONFLICT(round_id, wallet_id, proposal_id)
         DO UPDATE SET skipped = :skipped, choice = :choice, updated_at = :now",
        named_params! {
            ":round_id": round_id,
            ":wallet_id": wallet_id,
            ":proposal_id": proposal_id as i64,
            ":skipped": skipped,
            ":choice": choice,
            ":now": now,
        },
    )
    .map_err(|e| VotingError::from_sqlite("set_ballot_intent", &e))?;
    if intent_changed {
        queries::clear_combined_rejection_ledger_for_proposal(
            tx,
            wallet_id,
            round_id,
            proposal_id,
        )?;
    }
    if skipped_bool {
        tx.execute(
            "DELETE FROM share_delegations
             WHERE round_id = :round_id
               AND wallet_id = :wallet_id
               AND proposal_id = :proposal_id",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":proposal_id": proposal_id as i64,
            },
        )
    } else if let Some(choice) = choice_u32 {
        tx.execute(
            "DELETE FROM share_delegations
             WHERE round_id = :round_id
               AND wallet_id = :wallet_id
               AND proposal_id = :proposal_id
               AND NOT EXISTS (
                   SELECT 1 FROM votes
                   WHERE votes.round_id = share_delegations.round_id
                     AND votes.wallet_id = share_delegations.wallet_id
                     AND votes.bundle_index = share_delegations.bundle_index
                     AND votes.proposal_id = share_delegations.proposal_id
                     AND votes.choice = :choice
               )",
            named_params! {
                ":round_id": round_id,
                ":wallet_id": wallet_id,
                ":proposal_id": proposal_id as i64,
                ":choice": choice as i64,
            },
        )
    } else {
        Ok(0)
    }
    .map_err(|e| VotingError::from_sqlite("clear stale share delegations", &e))?;
    Ok(())
}

impl VotingDb {
    /// Load the voter's decisions for a round, sorted by proposal id.
    pub fn ballot_intents(&self, round_id: &str) -> Result<Vec<(u32, Decision)>, VotingError> {
        let conn = self.conn();
        let wallet_id = self.wallet_id();
        load_ballot_intents(&conn, round_id, &wallet_id)
    }
}

/// [`VotingDb::ballot_intents`] on `conn`, so a caller can read it inside one
/// transaction with the rest of a round's state.
pub(crate) fn load_ballot_intents(
    conn: &rusqlite::Connection,
    round_id: &str,
    wallet_id: &str,
) -> Result<Vec<(u32, Decision)>, VotingError> {
    {
        let mut stmt = conn
            .prepare(
                "SELECT proposal_id, skipped, choice FROM ballot_intent
                 WHERE round_id = :round_id AND wallet_id = :wallet_id
                 ORDER BY proposal_id",
            )
            .map_err(|e| VotingError::from_sqlite("prepare ballot_intents", &e))?;
        let rows = stmt
            .query_map(
                named_params! { ":round_id": round_id, ":wallet_id": wallet_id },
                |row| {
                    let pid = row.get::<_, i64>(0)? as u32;
                    let skipped: i64 = row.get(1)?;
                    let choice: Option<i64> = row.get(2)?;
                    let decision = if skipped != 0 {
                        Decision::Skipped
                    } else {
                        Decision::Choice(choice.ok_or_else(|| {
                            rusqlite::Error::InvalidQuery
                        })? as u32)
                    };
                    Ok((pid, decision))
                },
            )
            .map_err(|e| VotingError::from_sqlite("query ballot_intents", &e))?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| VotingError::from_sqlite("collect ballot_intents", &e))
    }
}

fn validate_ballot_intent_decision(
    decision: Decision,
    num_options: u32,
) -> Result<(), VotingError> {
    match decision {
        Decision::Choice(choice) => validate_vote_decision(choice, num_options),
        Decision::Skipped => validate_vote_options(num_options),
    }
}

fn now_secs() -> i64 {
    crate::clock::system_time_now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Explicit delegation does not create ballot choices. Ordinary resume planning
/// continues to start new delegations only when a chosen vote requires one.
pub fn delegation_resume_steps(
    db: &VotingDb,
    round_id: &str,
    proposal_ids: &[u32],
) -> Result<Vec<NextStep>, VotingError> {
    db.validate_delegation_state(round_id)?;
    let plan = resume_plan(db, round_id, proposal_ids)?;
    if plan.delegation_statuses.is_empty()
        || plan
            .delegation_statuses
            .iter()
            .enumerate()
            .any(|(index, status)| {
                status.bundle_index as usize != index
                    || matches!(
                        status.phase,
                        DelegationPhase::Submitted | DelegationPhase::Confirmed
                    ) != status.tx_hash.is_some()
            })
    {
        return Err(VotingError::InvalidInput {
            message: "incomplete prepared delegation state".into(),
        });
    }
    let mut steps = Vec::new();
    for status in plan.delegation_statuses {
        match status.phase {
            DelegationPhase::Confirmed => {}
            DelegationPhase::Submitted => steps.push(NextStep::AdvanceDelegation {
                bundle_index: status.bundle_index,
            }),
            _ => steps.push(NextStep::Delegate {
                bundle_index: status.bundle_index,
            }),
        }
    }
    steps.sort_by_key(|step| match step {
        NextStep::AdvanceDelegation { bundle_index } | NextStep::Delegate { bundle_index } => {
            *bundle_index
        }
        _ => unreachable!("delegation resume only plans delegation steps"),
    });
    Ok(steps)
}

/// One unit of remaining work for a round. Ordered deterministically within a
/// `RoundPlan`, so a restart yields the same sequence.
#[non_exhaustive]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum NextStep {
    /// Run the delegation flow: this bundle still needs a signed delegation
    /// before anything can be dispatched.
    Delegate { bundle_index: u32 },
    /// Advance one delegation that is already durably in flight.
    ///
    /// Call `ChainSubmissionClient::advance_delegation_with_recovery` with
    /// `ChainRecoveryMode::ExactTree`. Emitted while the authoritative
    /// generation is `Submitting`, `Tracking`, or `Recovering`, and requires
    /// the wallet to restore signing material for the locked generation.
    AdvanceDelegation { bundle_index: u32 },
    /// Poll one already-broadcast delegation imported from a capability.
    ///
    /// Call `ChainSubmissionClient::advance_imported_delegation`. The lifecycle
    /// adopts the package hash on the first pass and never asks the voter for a
    /// signer or dispatches the transaction again.
    AdvanceImportedDelegation { bundle_index: u32 },
    /// Cast a vote using the recorded ballot intent choice.
    ///
    /// Only planned once every proposal in the roster has a terminal decision,
    /// a choice or a skip. Casting persists the vote and then derives the
    /// round's immediate helper share from the complete set of choices, so an
    /// undecided proposal would make the step fail after the proof was
    /// generated and the vote written. While the ballot is still open the plan
    /// reports the remaining proposals through `RoundPlan::open_proposals` and
    /// plans the bundle's `Delegate` prerequisite instead.
    ///
    /// A changed choice is recoverable only until a cast-vote transaction has
    /// been submitted. Once submitted, the proposal authority for that bundle
    /// has moved on-chain and `resume_plan` reports the conflict as invalid
    /// state instead of returning a non-actionable recast step.
    CastVote {
        bundle_index: u32,
        proposal_id: u32,
        choice: u32,
    },
    /// Advance one singleton vote's chain submission by one bounded pass.
    ///
    /// Call `ChainSubmissionClient::advance_vote_with_recovery` with
    /// `ChainRecoveryMode::ExactTree`. The lifecycle owns transaction
    /// construction, dispatch, polling, recovery, and confirmation, so
    /// reserving, submitting, and reconciling are one host call rather than
    /// separate submit and poll steps. Re-invoke while the result is pending.
    ///
    /// Recover the `CommittedVote`, preflight the complete helper fleet, and
    /// call `CommittedVote::prepare_share_delivery` to create or reload its
    /// complete persisted plan. After confirmation, convert it with
    /// `CommittedVote::confirmed` and submit through
    /// `ConfirmedVote::submit_prepared_shares` with the current fleet. A
    /// reloaded plan retains its original target while delivery excludes
    /// helpers removed from the current fleet. The typed method rebuilds
    /// payloads with the confirmed commitment-tree position and journals each
    /// POST before dispatch.
    AdvanceVote { bundle_index: u32, proposal_id: u32 },
    /// Advance one atomic vote batch's chain submission by one bounded pass.
    ///
    /// `proposal_id` identifies the batch's first ordered action and is only a
    /// recovery anchor. Call
    /// `ChainSubmissionClient::advance_vote_batch_with_recovery` with
    /// `ChainRecoveryMode::ExactTree`; the lifecycle confirms every member
    /// atomically.
    AdvanceVoteBatch { bundle_index: u32, proposal_id: u32 },
    /// Resume helper-share submission for a committed vote.
    ///
    /// This covers the crash boundary after the cast-vote transaction confirms
    /// and before every helper-share row has been durably recorded. The
    /// `share_index` identifies one missing share for stable recovery UI and
    /// FFI routing. The host should recover the `CommittedVote`, call
    /// `CommittedVote::prepare_share_delivery` to load or create the
    /// SDK-persisted complete plan, convert it with `CommittedVote::confirmed`,
    /// and then call `ConfirmedVote::submit_prepared_shares` with the current
    /// helper fleet.
    /// Submission validates the immutable plan against its persisted planning
    /// fleet, contacts only current helpers, validates the whole batch before
    /// network I/O, journals every attempt and outcome, and resumes only the
    /// remaining definite-delivery deficits.
    SubmitShares {
        bundle_index: u32,
        proposal_id: u32,
        share_index: u32,
    },
    ConfirmShare {
        bundle_index: u32,
        proposal_id: u32,
        share_index: u32,
    },
}

impl NextStep {
    /// Typed discriminator exposed to hosts through [`crate::wire::NextStepView`].
    ///
    /// Hosts match on the enum rather than a string, so a new step kind is a
    /// compile-time event for them instead of a silently unmatched label:
    ///
    /// ```compile_fail
    /// let step = zcash_voting::session::NextStep::Delegate { bundle_index: 0 };
    /// let _: &str = step.kind();
    /// ```
    pub fn kind_view(&self) -> crate::wire::NextStepKind {
        use crate::wire::NextStepKind as Kind;
        match self {
            Self::Delegate { .. } => Kind::Delegate,
            Self::AdvanceDelegation { .. } => Kind::AdvanceDelegation,
            Self::AdvanceImportedDelegation { .. } => Kind::AdvanceImportedDelegation,
            Self::CastVote { .. } => Kind::CastVote,
            Self::AdvanceVote { .. } => Kind::AdvanceVote,
            Self::AdvanceVoteBatch { .. } => Kind::AdvanceVoteBatch,
            Self::SubmitShares { .. } => Kind::SubmitShares,
            Self::ConfirmShare { .. } => Kind::ConfirmShare,
        }
    }
}

/// High-level work area a wallet should show or resume for a round.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RoundPlanAction {
    /// No crate-owned recovery or submitted vote artifact is present.
    Idle,
    /// Delegation must be submitted or polled before fresh vote work can finish.
    Delegate,
    /// Cast-vote, vote-submission, vote-polling, or helper-share submission work remains.
    Vote,
    /// Only blocking helper-share confirmation work remains.
    SubmitShares,
    /// A vote artifact exists and no blocking recovery work remains.
    Done,
}

impl From<RoundPlanAction> for crate::wire::RoundPlanActionKind {
    fn from(action: RoundPlanAction) -> Self {
        match action {
            RoundPlanAction::Idle => Self::Idle,
            RoundPlanAction::Delegate => Self::Delegate,
            RoundPlanAction::Vote => Self::Vote,
            RoundPlanAction::SubmitShares => Self::SubmitShares,
            RoundPlanAction::Done => Self::Done,
        }
    }
}

/// Kind of delegation recovery work grouped from `NextStep`s.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DelegationRecoveryWorkKind {
    /// Run the delegation flow for this bundle.
    Delegate,
    /// Advance a delegation transaction that is already in flight.
    AdvanceDelegation,
    /// Advance an imported, already-broadcast delegation without signing.
    AdvanceImportedDelegation,
}

impl From<DelegationRecoveryWorkKind> for crate::wire::DelegationRecoveryWorkKindView {
    fn from(kind: DelegationRecoveryWorkKind) -> Self {
        match kind {
            DelegationRecoveryWorkKind::Delegate => Self::Delegate,
            DelegationRecoveryWorkKind::AdvanceDelegation => Self::AdvanceDelegation,
            DelegationRecoveryWorkKind::AdvanceImportedDelegation => {
                Self::AdvanceImportedDelegation
            }
        }
    }
}

/// Grouped delegation recovery work for one bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationRecoveryWork {
    pub kind: DelegationRecoveryWorkKind,
    pub bundle_index: u32,
    pub phase: DelegationPhase,
    /// Present for either delegation-advancement kind when a hash is known.
    pub tx_hash: Option<String>,
}

/// Durable delegation state for one eligible bundle.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DelegationStatus {
    pub bundle_index: u32,
    pub phase: DelegationPhase,
    pub tx_hash: Option<String>,
    /// Diagnostic stored on the bundle's authoritative lifecycle row.
    ///
    /// Always present for `SubmittedWithoutHash` and `SubmissionRejected`.
    /// Those phases are terminal and schedule no `next_steps`, so after a
    /// restart this field is how a host surfaces why the delegation needs
    /// manual handling. May also be present while `SubmissionManaged`
    /// recovers from an ambiguous dispatch.
    pub submission_diagnostic: Option<ChainSubmissionDiagnostic>,
    /// True when this bundle's delegation ended without a confirmation and no
    /// further delegation step will ever be planned for it: a terminal
    /// failure, not a terminal state.
    ///
    /// Such a bundle needs manual handling, not a retry: it was either
    /// rejected, or dispatched without a usable transaction hash and must not
    /// be resubmitted. `submission_diagnostic` says which. A `Confirmed`
    /// bundle is not terminal in this sense: it succeeded, and `phase` says
    /// so. Hosts cannot derive the failure from `phase` alone, because the
    /// wallet-facing phase reports a hashless dispatch and a healthy
    /// submission the same way.
    pub terminal: bool,
}

/// Kind of vote recovery work grouped from `NextStep`s.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VoteRecoveryWorkKind {
    /// Advance a committed singleton vote using persisted recovery material.
    AdvanceVote,
    /// Advance a committed atomic vote batch using persisted recovery material.
    AdvanceVoteBatch,
    /// Submit one or more missing helper shares for a confirmed vote.
    SubmitShares,
}

impl From<VoteRecoveryWorkKind> for crate::wire::VoteRecoveryWorkKindView {
    fn from(kind: VoteRecoveryWorkKind) -> Self {
        match kind {
            VoteRecoveryWorkKind::AdvanceVote => Self::AdvanceVote,
            VoteRecoveryWorkKind::AdvanceVoteBatch => Self::AdvanceVoteBatch,
            VoteRecoveryWorkKind::SubmitShares => Self::SubmitShares,
        }
    }
}

/// Grouped vote recovery work keyed by one singleton action or batch anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VoteRecoveryWork {
    pub kind: VoteRecoveryWorkKind,
    pub bundle_index: u32,
    /// Proposal key for singleton work, or the first ordered action used as the
    /// recovery anchor for batch work.
    pub proposal_id: u32,
    /// Transaction hash the lifecycle already knows for `AdvanceVote` or
    /// `AdvanceVoteBatch`: the confirmed hash, else the candidate hash of the
    /// in-flight generation. Absent before the first accepted POST, after a
    /// hashless recovery, and always for `SubmitShares`.
    pub tx_hash: Option<String>,
    /// Present only when `kind == VoteRecoveryWorkKind::SubmitShares`.
    pub vc_tree_position: Option<u64>,
    /// Empty unless `kind == VoteRecoveryWorkKind::SubmitShares`.
    pub share_indexes: Vec<u32>,
}

/// Display choice for one proposal in a completed round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedVoteChoice {
    pub proposal_id: u32,
    /// `None` when the proposal was skipped or bundles disagree.
    pub choice: Option<u32>,
}

/// Read-only display summary for a locally completed vote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedVoteDisplay {
    pub choices: Vec<CompletedVoteChoice>,
    /// Latest helper-share delegation timestamp, in Unix seconds.
    pub voted_at: Option<u64>,
}

/// Derived resume state for one round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoundPlan {
    pub round_id: String,
    /// True iff any recovery step remains (`!next_steps.is_empty()`).
    pub pending_recovery: bool,
    /// Ordered remaining recovery work.
    pub next_steps: Vec<NextStep>,
    /// Proposals with no terminal decision yet.
    ///
    /// `Decision::Skipped` is terminal for this plan, so skipped proposals are
    /// not returned here.
    pub open_proposals: Vec<u32>,
    /// Durable ballot intents for proposals the authenticated roster does not
    /// list, such as a decision recorded before a proposal was removed.
    /// Helper-plan derivation rejects them, so `CastVote` is withheld until
    /// the host clears them with `VotingDb::clear_ballot_intent`.
    ///
    /// An unrostered intent whose vote the chain lifecycle owns or has
    /// finished is omitted: it cannot be cleared, its vote is still driven to
    /// resolution, and it does not withhold casting for the current roster.
    pub unrostered_intents: Vec<u32>,
    /// The round's single immediate helper-share submission, if designated.
    ///
    /// Reports the round's durable designation whenever one exists, since
    /// that is what delivery executes; only while none exists is it derived
    /// from the current ballot choices.
    pub immediate_share_key: Option<ImmediateShareKey>,
    /// True when the designated immediate share has durable helper-quorum confirmation.
    pub immediate_share_confirmed: bool,
    /// Informational: every proposal is either a confirmed Choice or Skipped.
    pub all_decided: bool,
    /// Durable delegation status for every eligible bundle in the round.
    pub delegation_statuses: Vec<DelegationStatus>,
    /// True when the plan contains work that should keep the foreground vote flow open.
    ///
    /// Unconfirmed helper shares with an acceptance or an outcome-unknown
    /// attempt remain in `next_steps` as `ConfirmShare`, but they are
    /// non-blocking because background tracking can confirm, reconcile, or
    /// replenish them later.
    pub blocking_recovery: bool,
    /// True when an unconfirmed helper-share row has no accepted, ambiguous,
    /// or in-flight helper and therefore still needs foreground delivery.
    pub blocking_share_work: bool,
    /// True when any helper-share row is still unconfirmed, whether or not a
    /// helper has accepted it or may hold it after an outcome-unknown attempt.
    ///
    /// Hosts schedule background share tracking from this rather than holding
    /// share rows themselves; `blocking_share_work` is the stricter subset
    /// that must block the foreground vote flow.
    pub has_unconfirmed_shares: bool,
    /// True once round artifacts require the same voting hotkey to be reused.
    pub hotkey_bound: bool,
    /// True once the local DB contains a vote or helper-share artifact for the round.
    pub completed_vote_artifact: bool,
    /// True when a vote artifact exists and no blocking recovery work remains.
    pub completed_for_display: bool,
    /// Display data for a completed vote, present only when `completed_for_display`.
    pub completed_vote_display: Option<CompletedVoteDisplay>,
    /// True when a wallet should collect or restore draft choices for open proposals.
    pub needs_draft_setup: bool,
    /// True when the round holds a ballot choice but no bundle rows yet.
    ///
    /// Eligibility checks do not persist bundles, so a host that records a
    /// ballot before running bundle setup sees this instead of an error. The
    /// remedy is to persist the bundle plan for the round (`ensure_bundles`,
    /// or the pipeline's setup/precompute entry points) and plan again; no
    /// vote work can be planned until then.
    pub needs_bundle_setup: bool,
    /// Primary work area derived from the crate-owned recovery state.
    pub primary_action: RoundPlanAction,
    /// True when delegation work needs fresh or restored wallet signing material.
    ///
    /// Hosts should read this instead of scanning `next_steps` for a kind.
    /// Every derived predicate below is computed from an exhaustive match over
    /// [`NextStep`], so a new step variant is a compile error here rather than
    /// silently reading as "no work" in a downstream allowlist.
    pub needs_delegation_signing: bool,
    /// True when a delegation is durably in flight. Consult
    /// `needs_delegation_signing` to learn whether its next pass also needs
    /// signing material.
    pub has_in_flight_delegation: bool,
    /// Bundles this plan owes any delegation step for, ascending.
    ///
    /// The per-bundle form of `needs_delegation_signing` and
    /// `has_in_flight_delegation`. A host that shows delegation progress per
    /// bundle would otherwise rebuild this by filtering `delegation_statuses`
    /// against rules the planner already applied, and would drift from them.
    pub delegation_bundles_needing_work: Vec<u32>,
    /// Bundles whose delegation still needs the voter's signing material,
    /// ascending.
    ///
    /// The per-bundle form of `needs_delegation_signing`, and a subset of
    /// `delegation_bundles_needing_work`. A delegation in flight is not signed
    /// and done — advancing one re-signs its locked generation — so it belongs
    /// here too. The exclusion is `AdvanceImportedDelegation`: an imported
    /// capability is already broadcast and never asks the voter for a signer.
    pub delegation_bundles_needing_signing: Vec<u32>,
    /// True when vote or helper-share work remains that the host should keep
    /// driving: casting, advancing a chain submission, or submitting shares.
    ///
    /// Excludes helper-share confirmation, which background polling completes.
    pub needs_vote_polling: bool,
    /// True when any vote or share work remains, counting share confirmation
    /// only when it is blocking.
    pub has_remaining_vote_or_share_work: bool,
    /// True when any vote or share work remains that is actionable from
    /// persisted state, counting share confirmation unconditionally.
    pub has_recoverable_vote_or_share_work: bool,
    /// Delegation recovery work grouped from `next_steps` for wallet orchestration.
    pub recovered_delegation_work: Vec<DelegationRecoveryWork>,
    /// Vote recovery work grouped from `next_steps` for wallet orchestration.
    pub recovered_vote_work: Vec<VoteRecoveryWork>,
}

/// Build the resume plan for `round_id`.
///
/// `proposal_ids` is the round's full set of proposal ids (from the wallet's
/// round config); the crate cannot enumerate "never decided" proposals on its
/// own. The plan is a best-effort snapshot over the durable phase tables.
/// Wallets should execute one returned step, persist that step's result, then
/// call `resume_plan` again; later steps may depend on earlier on-chain
/// confirmations.
///
/// A proposal in `proposal_ids` with no durable ballot intent is reported in
/// `RoundPlan::open_proposals` and suppresses [`NextStep::CastVote`] for the
/// whole round; see that variant for why the ballot must be terminal first.
/// Delegation and the advancement of votes already on the wire are planned
/// regardless.
pub fn resume_plan(
    db: &VotingDb,
    round_id: &str,
    proposal_ids: &[u32],
) -> Result<RoundPlan, VotingError> {
    crate::round_planning::plan_round(db, round_id, proposal_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phases::VotePhase;
    use crate::round::RoundParams;
    use crate::types::{EncryptedShare, NoteInfo};
    use crate::vote::{DraftVote, VoteBatchRecovery, VoteRecoveryBundle};

    const ROUND: &str = "0101010101010101010101010101010101010101010101010101010101010101";
    const W: &str = "wallet";

    fn round_params() -> RoundParams {
        RoundParams {
            vote_round_id: ROUND.to_string(),
            snapshot_height: 1000,
            ea_pk: vec![0xEA; 32],
            nc_root: vec![0xAA; 32],
            nullifier_imt_root: vec![0xBB; 32],
        }
    }

    fn note(position: u64) -> NoteInfo {
        NoteInfo {
            commitment: vec![0x01; 32],
            nullifier: vec![position as u8 + 0x02; 32],
            value: crate::governance::BALLOT_DIVISOR,
            position,
            diversifier: vec![0x03; 11],
            rho: vec![0x04; 32],
            rseed: vec![0x05; 32],
            scope: 0,
            ufvk_str: "uview1test".to_string(),
        }
    }

    fn db_with_bundle() -> VotingDb {
        let db = VotingDb::open_in_memory().unwrap();
        db.set_wallet_id(W);
        db.create_round(crate::Network::Testnet, &round_params(), None)
            .unwrap();
        db.ensure_bundles(ROUND, &[note(0)]).unwrap();
        db
    }

    fn store_vote_recovery_fixture(
        db: &VotingDb,
        bundle_index: u32,
        proposal_id: u32,
        choice: u32,
        vc_tree_position: Option<u64>,
    ) {
        let recovery = recovery_bundle_fixture(
            bundle_index,
            proposal_id,
            choice,
            vc_tree_position.unwrap_or(0),
        );
        store_recovery_bundle_fixture(db, &recovery, vc_tree_position);
    }

    fn store_recovery_bundle_fixture(
        db: &VotingDb,
        recovery: &VoteRecoveryBundle,
        vc_tree_position: Option<u64>,
    ) {
        let conn = db.conn();
        let rows = conn
            .execute(
                "UPDATE votes SET commitment_bundle_json = :json, vc_tree_position = :pos
                 WHERE round_id = :round_id
                   AND wallet_id = :wallet_id
                   AND bundle_index = :bundle_index
                   AND proposal_id = :proposal_id",
                named_params! {
                    ":json": crate::vote::serialize_recovery(&recovery).unwrap(),
                    ":pos": vc_tree_position.map(|position| position as i64),
                    ":round_id": ROUND,
                    ":wallet_id": W,
                    ":bundle_index": recovery.bundle_index as i64,
                    ":proposal_id": recovery.proposal_id as i64,
                },
            )
            .unwrap();
        assert_eq!(rows, 1);
    }

    fn confirm_vote_fixture(db: &VotingDb, bundle_index: u32, proposal_id: u32, choice: u32) {
        crate::storage::queries::store_vote(
            &db.conn(),
            ROUND,
            W,
            bundle_index,
            proposal_id,
            choice,
            &[0xCC; 16],
        )
        .unwrap();
        store_vote_recovery_fixture(db, bundle_index, proposal_id, choice, Some(42));
        db.record_vote_submission(ROUND, bundle_index, proposal_id, "tx")
            .unwrap();
    }

    fn recovery_bundle_fixture(
        bundle_index: u32,
        proposal_id: u32,
        choice: u32,
        vc_tree_position: u64,
    ) -> VoteRecoveryBundle {
        VoteRecoveryBundle {
            vote_round_id: ROUND.to_string(),
            bundle_index,
            proposal_id,
            vote_decision: choice,
            anchor_height: 123,
            vc_tree_position,
            single_share: false,
            num_options: 3,
            van_nullifier: [0x10; 32],
            vote_authority_note_new: [0x11; 32],
            vote_commitment: [0x12; 32],
            proof: vec![0x13; 96],
            shares_hash: [0x14; 32],
            r_vpk: [0x15; 32],
            alpha_v: [0x16; 32],
            vote_auth_sig: [0x17; 64],
            encrypted_shares: vec![
                EncryptedShare {
                    c1: vec![0x21; 32],
                    c2: vec![0x22; 32],
                    share_index: 0,
                    plaintext_value: 5,
                    randomness: vec![0x23; 32],
                },
                EncryptedShare {
                    c1: vec![0x31; 32],
                    c2: vec![0x32; 32],
                    share_index: 1,
                    plaintext_value: 6,
                    randomness: vec![0x33; 32],
                },
            ],
            share_blinds: vec![[0x41; 32], [0x42; 32]],
            share_comms: vec![[0x51; 32], [0x52; 32]],
            batch: None,
        }
    }

    fn store_two_action_batch_recovery_fixture(db: &VotingDb) -> [u8; 32] {
        store_two_action_batch_recovery_fixture_for(db, (1, 0), (2, 1))
    }

    fn store_two_action_batch_recovery_fixture_for(
        db: &VotingDb,
        first_vote: (u32, u32),
        second_vote: (u32, u32),
    ) -> [u8; 32] {
        let mut first = recovery_bundle_fixture(0, first_vote.0, first_vote.1, 0);
        first.vote_commitment = [0x61; 32];
        let mut second = recovery_bundle_fixture(0, second_vote.0, second_vote.1, 0);
        second.van_nullifier = [0x20; 32];
        second.vote_authority_note_new = [0x21; 32];
        second.vote_commitment = [0x62; 32];
        second.r_vpk = [0x25; 32];
        let actions = [&first, &second]
            .into_iter()
            .map(
                |recovery| crate::vote_commitment::CastVoteBatchSighashAction {
                    r_vpk: &recovery.r_vpk,
                    van_nullifier: &recovery.van_nullifier,
                    vote_authority_note_new: &recovery.vote_authority_note_new,
                    vote_commitment: &recovery.vote_commitment,
                    proposal_id: recovery.proposal_id,
                },
            )
            .collect::<Vec<_>>();
        let digest = crate::vote_commitment::cast_vote_batch_sighash(
            ROUND,
            first.anchor_height as u64,
            &actions,
        )
        .unwrap();
        first.batch = Some(VoteBatchRecovery {
            digest,
            index: 0,
            size: 2,
            delegation_van: None,
        });
        second.batch = Some(VoteBatchRecovery {
            digest,
            index: 1,
            size: 2,
            delegation_van: None,
        });

        for recovery in [&first, &second] {
            crate::storage::queries::store_vote(
                &db.conn(),
                ROUND,
                W,
                recovery.bundle_index,
                recovery.proposal_id,
                recovery.vote_decision,
                &recovery.vote_commitment,
            )
            .unwrap();
            store_recovery_bundle_fixture(db, recovery, None);
        }

        digest
    }

    fn record_confirmed_share_fixture(
        db: &VotingDb,
        bundle_index: u32,
        proposal_id: u32,
        share_index: u32,
    ) {
        let nullifier = vec![share_index as u8; 32];
        db.record_share_delegation(
            ROUND,
            bundle_index,
            proposal_id,
            share_index,
            &["https://helper.example".to_string()],
            &nullifier,
            0,
        )
        .unwrap();
        db.mark_share_confirmed(ROUND, bundle_index, proposal_id, share_index)
            .unwrap();
    }

    fn record_submitted_share_fixture(
        db: &VotingDb,
        bundle_index: u32,
        proposal_id: u32,
        share_index: u32,
        sent_to_urls: &[String],
    ) {
        let nullifier = vec![share_index as u8; 32];
        db.record_share_delegation(
            ROUND,
            bundle_index,
            proposal_id,
            share_index,
            sent_to_urls,
            &nullifier,
            0,
        )
        .unwrap();
    }

    fn record_all_confirmed_share_fixtures(db: &VotingDb, bundle_index: u32, proposal_id: u32) {
        record_confirmed_share_fixture(db, bundle_index, proposal_id, 0);
        record_confirmed_share_fixture(db, bundle_index, proposal_id, 1);
    }

    #[test]
    fn ballot_intent_round_trip() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 1, Decision::Choice(0), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 2, Decision::Skipped, 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 1, Decision::Choice(3), 4)
            .unwrap(); // upsert

        let intents = db.ballot_intents(ROUND).unwrap();
        assert_eq!(
            intents,
            vec![(1, Decision::Choice(3)), (2, Decision::Skipped)]
        );
    }

    #[test]
    fn ballot_intent_rejects_invalid_proposal_id() {
        let db = db_with_bundle();

        assert!(db
            .set_ballot_intent(ROUND, 0, Decision::Choice(0), 3)
            .is_err());
        assert!(db
            .set_ballot_intent(
                ROUND,
                crate::types::MAX_PROPOSAL_ID + 1,
                Decision::Skipped,
                3,
            )
            .is_err());
    }

    #[test]
    fn ballot_intent_rejects_choice_outside_proposal_option_count() {
        let db = db_with_bundle();

        db.set_ballot_intent(ROUND, 1, Decision::Choice(1), 2)
            .unwrap();
        assert!(db
            .set_ballot_intent(ROUND, 1, Decision::Choice(2), 2)
            .is_err());
        assert!(db
            .set_ballot_intent(ROUND, 1, Decision::Choice(0), 1)
            .is_err());
    }

    #[test]
    fn ballot_intent_for_draft_vote_validates_choice_and_options() {
        let db = db_with_bundle();
        let draft = DraftVote {
            proposal_id: 1,
            choice: 1,
            num_options: 2,
            single_share: false,
            vc_tree_position: 0,
        };

        db.set_ballot_intent_for_draft_vote(ROUND, &draft).unwrap();
        assert_eq!(
            db.ballot_intents(ROUND).unwrap(),
            vec![(1, Decision::Choice(1))]
        );

        assert!(db
            .set_ballot_intent_for_draft_vote(
                ROUND,
                &DraftVote {
                    choice: 2,
                    ..draft.clone()
                },
            )
            .is_err());
        assert!(db
            .set_ballot_intent_for_draft_vote(
                ROUND,
                &DraftVote {
                    num_options: 9,
                    ..draft
                },
            )
            .is_err());
    }

    #[test]
    fn complete_ballot_intents_are_atomic_and_require_the_exact_roster() {
        let db = db_with_bundle();
        let roster = [(1, 2), (2, 3), (3, 2)];

        for decisions in [
            vec![(1, Decision::Choice(0)), (2, Decision::Skipped)],
            vec![
                (1, Decision::Choice(0)),
                (2, Decision::Skipped),
                (3, Decision::Choice(1)),
                (4, Decision::Skipped),
            ],
            vec![
                (1, Decision::Choice(0)),
                (2, Decision::Skipped),
                (2, Decision::Choice(1)),
            ],
            vec![
                (1, Decision::Choice(0)),
                (2, Decision::Choice(3)),
                (3, Decision::Skipped),
            ],
        ] {
            assert!(db
                .set_complete_ballot_intents(ROUND, &roster, &decisions)
                .is_err());
            assert!(db.ballot_intents(ROUND).unwrap().is_empty());
        }

        db.set_complete_ballot_intents(
            ROUND,
            &roster,
            &[
                (3, Decision::Skipped),
                (1, Decision::Choice(1)),
                (2, Decision::Choice(2)),
            ],
        )
        .unwrap();
        assert_eq!(
            db.ballot_intents(ROUND).unwrap(),
            vec![
                (1, Decision::Choice(1)),
                (2, Decision::Choice(2)),
                (3, Decision::Skipped),
            ]
        );
    }

    #[test]
    fn complete_ballot_rejects_an_invalid_or_duplicate_authenticated_roster() {
        let db = db_with_bundle();
        for roster in [vec![], vec![(0, 2)], vec![(1, 1)], vec![(1, 2), (1, 2)]] {
            assert!(db
                .set_complete_ballot_intents(ROUND, &roster, &[(1, Decision::Choice(0))])
                .is_err());
            assert!(db.ballot_intents(ROUND).unwrap().is_empty());
        }
    }

    #[test]
    fn resume_plan_rejects_invalid_proposal_ids() {
        let db = db_with_bundle();

        assert!(resume_plan(&db, ROUND, &[1, 0]).is_err());
        assert!(resume_plan(&db, ROUND, &[1, crate::types::MAX_PROPOSAL_ID + 1]).is_err());
        assert!(resume_plan(&db, ROUND, &[1, 1]).is_err());
    }

    #[test]
    fn fresh_round_with_no_choices_has_no_recovery() {
        let db = db_with_bundle();
        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();
        assert!(!plan.pending_recovery);
        assert!(plan.next_steps.is_empty());
        assert_eq!(plan.open_proposals, vec![1, 2, 3]);
        assert!(!plan.all_decided);
        assert_eq!(
            plan.delegation_statuses,
            vec![DelegationStatus {
                bundle_index: 0,
                phase: DelegationPhase::Prepared,
                tx_hash: None,
                submission_diagnostic: None,
                terminal: false,
            }]
        );
        assert!(!plan.blocking_recovery);
        assert!(!plan.hotkey_bound);
        assert!(!plan.completed_vote_artifact);
        assert!(!plan.completed_for_display);
        assert_eq!(plan.completed_vote_display, None);
        assert!(plan.needs_draft_setup);
        assert_eq!(plan.primary_action, RoundPlanAction::Idle);
        assert!(plan.recovered_delegation_work.is_empty());
        assert!(plan.recovered_vote_work.is_empty());
    }

    #[test]
    fn answered_but_incomplete_ballot_waits_for_the_rest_of_the_roster() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();
        assert!(plan.pending_recovery);
        // Bundle 0 is only Prepared, and proposal 2 needs casting on it, so the
        // delegate prerequisite is emitted, ordered before the cast.
        assert_eq!(
            plan.next_steps,
            vec![NextStep::Delegate { bundle_index: 0 }]
        );
        assert_eq!(plan.open_proposals, vec![1, 3]);
        assert_eq!(
            plan.recovered_delegation_work,
            vec![DelegationRecoveryWork {
                kind: DelegationRecoveryWorkKind::Delegate,
                bundle_index: 0,
                phase: DelegationPhase::Prepared,
                tx_hash: None,
            }]
        );
        db.set_ballot_intent(ROUND, 1, Decision::Skipped, 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 3, Decision::Skipped, 3)
            .unwrap();
        assert_eq!(
            resume_plan(&db, ROUND, &[1, 2, 3]).unwrap().next_steps,
            vec![
                NextStep::Delegate { bundle_index: 0 },
                NextStep::CastVote {
                    bundle_index: 0,
                    proposal_id: 2,
                    choice: 1,
                },
            ]
        );
    }

    #[test]
    fn submitted_but_unconfirmed_vote_yields_poll() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        crate::storage::queries::store_vote(&db.conn(), ROUND, W, 0, 2, 1, &[0xCC; 16]).unwrap();
        store_vote_recovery_fixture(&db, 0, 2, 1, None);
        db.record_vote_submission(ROUND, 0, 2, "vtx").unwrap();
        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();
        assert_eq!(
            plan.next_steps,
            vec![NextStep::AdvanceVote {
                bundle_index: 0,
                proposal_id: 2
            }]
        );
        assert_eq!(
            plan.recovered_vote_work,
            vec![VoteRecoveryWork {
                kind: VoteRecoveryWorkKind::AdvanceVote,
                bundle_index: 0,
                proposal_id: 2,
                tx_hash: Some("vtx".to_string()),
                vc_tree_position: None,
                share_indexes: Vec::new(),
            }]
        );
    }

    #[cfg(feature = "browser")]
    #[test]
    fn legacy_vote_hash_is_adopted_without_a_prepared_post() {
        let db = db_with_bundle();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        crate::storage::queries::store_vote(&db.conn(), ROUND, W, 0, 2, 1, &[0xCC; 16]).unwrap();
        store_vote_recovery_fixture(&db, 0, 2, 1, None);
        let canonical = crate::vote_submission::CanonicalVoteSubmission::from_singleton(
            &crate::vote::submission(&db, ROUND, 0, 2).unwrap(),
        )
        .unwrap();
        assert!(!db
            .adopt_legacy_vote_submission(ROUND, 0, &canonical)
            .unwrap());
        assert!(db.vote_submission(ROUND, 0, 2).unwrap().is_none());

        crate::storage::queries::record_vote_submission(
            &db.conn(),
            ROUND,
            W,
            0,
            2,
            canonical.tx_hash(),
        )
        .unwrap();
        assert!(db
            .adopt_legacy_vote_submission(ROUND, 0, &canonical)
            .is_err());
        db.conn()
            .execute(
                "INSERT INTO legacy_vote_evidence VALUES (?1,?2,0,2,?3)",
                rusqlite::params![ROUND, W, canonical.tx_hash()],
            )
            .unwrap();
        assert!(db
            .adopt_legacy_vote_submission(ROUND, 0, &canonical)
            .unwrap());
        let attempt = db.vote_submission(ROUND, 0, 2).unwrap().unwrap();
        assert_eq!(
            attempt.outcome,
            crate::vote_submission::VoteSubmissionOutcome::Dispatching
        );
        assert_eq!(attempt.canonical.tx_hash(), canonical.tx_hash());
    }

    #[cfg(feature = "browser")]
    #[test]
    fn partial_legacy_batch_hashes_are_not_adopted_or_resent() {
        let db = db_with_bundle();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        let digest = store_two_action_batch_recovery_fixture(&db);
        let canonical = crate::vote_submission::CanonicalVoteSubmission::from_batch(
            &crate::vote::recover_atomic_vote_batch(&db, ROUND, 0, 1).unwrap(),
        )
        .unwrap();
        crate::storage::queries::record_vote_submission(
            &db.conn(),
            ROUND,
            W,
            0,
            1,
            canonical.tx_hash(),
        )
        .unwrap();
        db.conn()
            .execute(
                "INSERT INTO legacy_vote_evidence VALUES (?1,?2,0,1,?3)",
                rusqlite::params![ROUND, W, canonical.tx_hash()],
            )
            .unwrap();
        assert!(db
            .adopt_legacy_vote_submission(ROUND, 0, &canonical)
            .is_err());
        assert!(db.vote_submission(ROUND, 0, 1).unwrap().is_none());
        crate::storage::queries::record_vote_submission(
            &db.conn(),
            ROUND,
            W,
            0,
            2,
            canonical.tx_hash(),
        )
        .unwrap();
        db.conn()
            .execute(
                "INSERT INTO legacy_vote_evidence VALUES (?1,?2,0,2,?3)",
                rusqlite::params![ROUND, W, canonical.tx_hash()],
            )
            .unwrap();
        assert!(db
            .adopt_legacy_vote_submission(ROUND, 0, &canonical)
            .unwrap());
        assert_eq!(
            db.vote_submission(ROUND, 0, 1).unwrap().unwrap().outcome,
            crate::vote_submission::VoteSubmissionOutcome::Dispatching
        );
        assert_eq!(
            crate::vote::recover_atomic_vote_batch(&db, ROUND, 0, 1)
                .unwrap()
                .batch_digest,
            digest
        );
    }

    #[test]
    fn submitted_vote_without_recovery_bundle_is_invalid() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        crate::storage::queries::store_vote(&db.conn(), ROUND, W, 0, 2, 1, &[0xCC; 16]).unwrap();
        db.record_vote_submission(ROUND, 0, 2, "vtx").unwrap();

        let err = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap_err();

        assert!(
            err.to_string()
                .contains("submitted vote without recovery material"),
            "{err}"
        );
    }

    #[test]
    fn blocking_share_retry_waits_for_submitted_vote_confirmation() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        crate::storage::queries::store_vote(&db.conn(), ROUND, W, 0, 2, 1, &[0xCC; 16]).unwrap();
        store_vote_recovery_fixture(&db, 0, 2, 1, None);
        db.record_vote_submission(ROUND, 0, 2, "vtx").unwrap();
        record_submitted_share_fixture(&db, 0, 2, 0, &[]);

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert_eq!(
            plan.next_steps,
            vec![
                NextStep::AdvanceVote {
                    bundle_index: 0,
                    proposal_id: 2,
                },
                NextStep::ConfirmShare {
                    bundle_index: 0,
                    proposal_id: 2,
                    share_index: 0,
                },
            ]
        );
        assert!(plan.blocking_recovery);
        assert!(plan.blocking_share_work);
        assert_eq!(plan.primary_action, RoundPlanAction::Vote);
        assert_eq!(
            plan.recovered_vote_work,
            vec![VoteRecoveryWork {
                kind: VoteRecoveryWorkKind::AdvanceVote,
                bundle_index: 0,
                proposal_id: 2,
                tx_hash: Some("vtx".to_string()),
                vc_tree_position: None,
                share_indexes: Vec::new(),
            }]
        );
    }

    #[test]
    fn non_anchor_share_retry_waits_for_submitted_batch_confirmation() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 1, Decision::Choice(0), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        let digest = store_two_action_batch_recovery_fixture(&db);
        crate::vote::record_batch_submission(&db, ROUND, 0, &digest, "batch-tx").unwrap();
        record_submitted_share_fixture(&db, 0, 2, 0, &[]);

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert_eq!(
            plan.next_steps,
            vec![
                NextStep::AdvanceVoteBatch {
                    bundle_index: 0,
                    proposal_id: 1,
                },
                NextStep::ConfirmShare {
                    bundle_index: 0,
                    proposal_id: 2,
                    share_index: 0,
                },
            ]
        );
        assert!(plan.blocking_recovery);
        assert!(plan.blocking_share_work);
        assert_eq!(plan.primary_action, RoundPlanAction::Vote);
        assert_eq!(
            plan.recovered_vote_work,
            vec![VoteRecoveryWork {
                kind: VoteRecoveryWorkKind::AdvanceVoteBatch,
                bundle_index: 0,
                proposal_id: 1,
                tx_hash: Some("batch-tx".to_string()),
                vc_tree_position: None,
                share_indexes: Vec::new(),
            }]
        );
    }

    #[test]
    fn committed_vote_yields_submit_not_rebuild() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        crate::storage::queries::store_vote(&db.conn(), ROUND, W, 0, 2, 1, &[0xCC; 16]).unwrap();
        store_vote_recovery_fixture(&db, 0, 2, 1, None);

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert_eq!(
            plan.next_steps,
            vec![NextStep::AdvanceVote {
                bundle_index: 0,
                proposal_id: 2
            }]
        );
        assert!(plan.blocking_recovery);
        assert_eq!(plan.primary_action, RoundPlanAction::Vote);
        assert_eq!(
            plan.recovered_vote_work,
            vec![VoteRecoveryWork {
                kind: VoteRecoveryWorkKind::AdvanceVote,
                bundle_index: 0,
                proposal_id: 2,
                tx_hash: None,
                vc_tree_position: None,
                share_indexes: Vec::new(),
            }]
        );
    }

    #[test]
    fn committed_batch_yields_one_batch_submit_step() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 1, Decision::Choice(0), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        let digest = store_two_action_batch_recovery_fixture(&db);

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert_eq!(
            plan.next_steps,
            vec![NextStep::AdvanceVoteBatch {
                bundle_index: 0,
                proposal_id: 1,
            }]
        );
        assert_eq!(
            plan.recovered_vote_work,
            vec![VoteRecoveryWork {
                kind: VoteRecoveryWorkKind::AdvanceVoteBatch,
                bundle_index: 0,
                proposal_id: 1,
                tx_hash: None,
                vc_tree_position: None,
                share_indexes: Vec::new(),
            }]
        );
        let recovered = crate::vote::recover_atomic_vote_batch(&db, ROUND, 0, 1).unwrap();
        assert_eq!(recovered.batch_digest, digest);
        assert_eq!(recovered.commitments.len(), 2);
        assert!(recovered.batch_json.starts_with("{\"votes\":["));
    }

    #[test]
    fn changing_choice_invalidates_the_whole_unsubmitted_batch() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 1, Decision::Choice(0), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        store_two_action_batch_recovery_fixture(&db);

        db.set_ballot_intent(ROUND, 2, Decision::Choice(2), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 3, Decision::Skipped, 3)
            .unwrap();

        assert!(crate::vote::recovery_bundle(&db, ROUND, 0, 1)
            .unwrap()
            .is_none());
        assert!(crate::vote::recovery_bundle(&db, ROUND, 0, 2)
            .unwrap()
            .is_none());
        assert_eq!(db.vote_phase(ROUND, 0, 1).unwrap(), VotePhase::Prepared);
        assert_eq!(db.vote_phase(ROUND, 0, 2).unwrap(), VotePhase::Prepared);
        assert_eq!(
            resume_plan(&db, ROUND, &[1, 2, 3]).unwrap().next_steps,
            vec![
                NextStep::CastVote {
                    bundle_index: 0,
                    proposal_id: 1,
                    choice: 0,
                },
                NextStep::CastVote {
                    bundle_index: 0,
                    proposal_id: 2,
                    choice: 2,
                },
            ]
        );
    }

    #[test]
    fn skipping_choice_invalidates_the_whole_unsubmitted_batch() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 1, Decision::Choice(0), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        store_two_action_batch_recovery_fixture(&db);

        db.set_ballot_intent(ROUND, 2, Decision::Skipped, 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 3, Decision::Skipped, 3)
            .unwrap();

        assert!(crate::vote::recovery_bundle(&db, ROUND, 0, 1)
            .unwrap()
            .is_none());
        assert!(crate::vote::recovery_bundle(&db, ROUND, 0, 2)
            .unwrap()
            .is_none());
        assert_eq!(
            resume_plan(&db, ROUND, &[1, 2, 3]).unwrap().next_steps,
            vec![NextStep::CastVote {
                bundle_index: 0,
                proposal_id: 1,
                choice: 0,
            }]
        );
    }

    #[test]
    fn skipping_an_unsubmitted_singleton_clears_its_recovery() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 1, Decision::Choice(0), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        crate::storage::queries::store_vote(&db.conn(), ROUND, W, 0, 1, 0, &[0xCC; 16]).unwrap();
        store_vote_recovery_fixture(&db, 0, 1, 0, None);

        db.set_ballot_intent(ROUND, 1, Decision::Skipped, 3)
            .unwrap();

        assert!(crate::vote::recovery_bundle(&db, ROUND, 0, 1)
            .unwrap()
            .is_none());
        assert_eq!(
            resume_plan(&db, ROUND, &[1, 2]).unwrap().next_steps,
            vec![NextStep::CastVote {
                bundle_index: 0,
                proposal_id: 2,
                choice: 1,
            }]
        );
    }

    #[test]
    fn changing_one_member_rejects_a_partially_submitted_batch_atomically() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 1, Decision::Choice(0), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        store_two_action_batch_recovery_fixture(&db);
        db.conn()
            .execute(
                "UPDATE votes SET tx_hash = 'batch-tx'
                 WHERE round_id = :round_id
                   AND wallet_id = :wallet_id
                   AND bundle_index = 0
                   AND proposal_id = 1",
                named_params! {
                    ":round_id": ROUND,
                    ":wallet_id": W,
                },
            )
            .unwrap();

        let error = db
            .set_ballot_intent(ROUND, 2, Decision::Choice(2), 3)
            .unwrap_err();

        assert!(error.to_string().contains("submitted atomic vote batch"));
        assert_eq!(
            db.ballot_intents(ROUND).unwrap(),
            vec![(1, Decision::Choice(0)), (2, Decision::Choice(1))]
        );
        assert!(crate::vote::recovery_bundle(&db, ROUND, 0, 1)
            .unwrap()
            .is_some());
        assert!(crate::vote::recovery_bundle(&db, ROUND, 0, 2)
            .unwrap()
            .is_some());
    }

    #[test]
    fn submitted_batch_yields_one_batch_poll_step() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 1, Decision::Choice(0), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        let digest = store_two_action_batch_recovery_fixture(&db);
        crate::vote::record_batch_submission(&db, ROUND, 0, &digest, "batch-tx").unwrap();

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert_eq!(
            plan.next_steps,
            vec![NextStep::AdvanceVoteBatch {
                bundle_index: 0,
                proposal_id: 1,
            }]
        );
        assert_eq!(
            plan.recovered_vote_work,
            vec![VoteRecoveryWork {
                kind: VoteRecoveryWorkKind::AdvanceVoteBatch,
                bundle_index: 0,
                proposal_id: 1,
                tx_hash: Some("batch-tx".to_string()),
                vc_tree_position: None,
                share_indexes: Vec::new(),
            }]
        );
    }

    #[test]
    fn pending_batch_defers_a_new_lower_proposal_cast_until_confirmation() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 1, Decision::Choice(0), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 3, Decision::Choice(2), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        let digest = store_two_action_batch_recovery_fixture_for(&db, (2, 1), (3, 2));

        let committed_plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();
        assert_eq!(
            committed_plan.next_steps,
            vec![NextStep::AdvanceVoteBatch {
                bundle_index: 0,
                proposal_id: 2,
            }]
        );

        crate::vote::record_batch_submission(&db, ROUND, 0, &digest, "batch-tx").unwrap();

        let submitted_plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert_eq!(
            submitted_plan.next_steps,
            vec![NextStep::AdvanceVoteBatch {
                bundle_index: 0,
                proposal_id: 2,
            }]
        );
    }

    #[test]
    fn changed_choice_after_submission_is_invalid_recovery_state() {
        let db = db_with_bundle();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();

        confirm_vote_fixture(&db, 0, 2, 0);
        db.conn()
            .execute(
                "INSERT INTO ballot_intent
                    (round_id, wallet_id, proposal_id, skipped, choice, created_at, updated_at)
                 VALUES (:round_id, :wallet_id, :proposal_id, 0, 1, 1, 1)",
                named_params! {
                    ":round_id": ROUND,
                    ":wallet_id": W,
                    ":proposal_id": 2_i64,
                },
            )
            .unwrap();

        let err = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap_err();

        assert!(
            err.to_string()
                .contains("submitted vote that conflicts with ballot intent"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn conflicting_intent_after_submission_is_rejected_before_share_cleanup() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(0), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        confirm_vote_fixture(&db, 0, 2, 0);
        record_all_confirmed_share_fixtures(&db, 0, 2);

        for decision in [Decision::Choice(1), Decision::Skipped] {
            let err = db.set_ballot_intent(ROUND, 2, decision, 3).unwrap_err();
            assert!(
                err.to_string()
                    .contains("submitted vote that conflicts with ballot intent"),
                "unexpected error for {decision:?}: {err}"
            );
            assert_eq!(
                db.ballot_intents(ROUND).unwrap(),
                vec![(2, Decision::Choice(0))]
            );
            let shares = db.get_share_delegations(ROUND).unwrap();
            assert_eq!(shares.len(), 2);
            let share_indexes = shares
                .iter()
                .map(|share| share.share_index)
                .collect::<BTreeSet<_>>();
            assert_eq!(share_indexes, BTreeSet::from([0, 1]));
            assert!(shares.iter().all(|share| {
                share.bundle_index == 0 && share.proposal_id == 2 && share.confirmed
            }));
        }
    }

    #[test]
    fn stale_vote_submission_after_choice_change_is_rejected() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(0), 3)
            .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        crate::storage::queries::store_vote(&db.conn(), ROUND, W, 0, 2, 0, &[0xCC; 16]).unwrap();

        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        let err = db
            .record_vote_submission(ROUND, 0, 2, "old-vtx")
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("vote submission conflicts with ballot intent"),
            "unexpected error: {err}"
        );
        assert_eq!(db.get_vote_tx_hash(ROUND, 0, 2).unwrap(), None);
        db.set_ballot_intent(ROUND, 1, Decision::Skipped, 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 3, Decision::Skipped, 3)
            .unwrap();
        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();
        assert_eq!(
            plan.next_steps,
            vec![NextStep::CastVote {
                bundle_index: 0,
                proposal_id: 2,
                choice: 1,
            }]
        );
    }

    #[test]
    fn stale_vote_submission_after_skip_is_rejected() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(0), 3)
            .unwrap();
        crate::storage::queries::store_vote(&db.conn(), ROUND, W, 0, 2, 0, &[0xCC; 16]).unwrap();

        db.set_ballot_intent(ROUND, 2, Decision::Skipped, 3)
            .unwrap();
        let err = db
            .record_vote_submission(ROUND, 0, 2, "old-vtx")
            .unwrap_err();

        assert!(
            err.to_string()
                .contains("cannot record vote submission for skipped proposal"),
            "unexpected error: {err}"
        );
        assert_eq!(db.get_vote_tx_hash(ROUND, 0, 2).unwrap(), None);
        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();
        assert!(!plan.pending_recovery);
        assert_eq!(plan.open_proposals, vec![1, 3]);
        assert!(!plan.completed_vote_artifact);
        assert!(!plan.completed_for_display);
        assert_eq!(plan.primary_action, RoundPlanAction::Idle);
    }

    #[test]
    fn round_plan_selects_share_zero_of_lowest_voted_proposal() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 1, Decision::Skipped, 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 3, Decision::Choice(1), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(0), 3)
            .unwrap();

        assert_eq!(
            resume_plan(&db, ROUND, &[1, 2, 3])
                .unwrap()
                .immediate_share_key,
            Some(ImmediateShareKey {
                bundle_index: 0,
                proposal_id: 2,
                share_index: 0,
            })
        );
    }

    #[test]
    fn round_plan_has_no_immediate_share_before_a_vote_choice() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 1, Decision::Skipped, 3)
            .unwrap();

        assert_eq!(
            resume_plan(&db, ROUND, &[1, 2, 3])
                .unwrap()
                .immediate_share_key,
            None
        );
    }

    #[test]
    fn round_plan_reports_immediate_share_confirmation() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(0), 3)
            .unwrap();
        assert!(
            !resume_plan(&db, ROUND, &[1, 2, 3])
                .unwrap()
                .immediate_share_confirmed
        );

        confirm_vote_fixture(&db, 0, 2, 0);
        record_confirmed_share_fixture(&db, 0, 2, 0);

        assert!(
            resume_plan(&db, ROUND, &[1, 2, 3])
                .unwrap()
                .immediate_share_confirmed
        );
    }

    #[test]
    fn round_plan_immediate_share_is_stable_after_vote_completion() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 1, Decision::Choice(1), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(0), 3)
            .unwrap();
        let before = resume_plan(&db, ROUND, &[1, 2, 3])
            .unwrap()
            .immediate_share_key;

        confirm_vote_fixture(&db, 0, 1, 1);

        assert_eq!(
            resume_plan(&db, ROUND, &[1, 2, 3])
                .unwrap()
                .immediate_share_key,
            before
        );
    }

    #[test]
    fn changed_choice_ignores_stale_share_confirmations() {
        let db = db_with_bundle();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();

        crate::storage::queries::store_vote(&db.conn(), ROUND, W, 0, 2, 0, &[0xCC; 16]).unwrap();
        db.record_share_delegation(
            ROUND,
            0,
            2,
            0,
            &["https://helper.example".to_string()],
            &[0x44; 32],
            0,
        )
        .unwrap();

        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 1, Decision::Skipped, 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 3, Decision::Skipped, 3)
            .unwrap();
        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert_eq!(
            plan.next_steps,
            vec![NextStep::CastVote {
                bundle_index: 0,
                proposal_id: 2,
                choice: 1,
            }]
        );
    }

    #[test]
    fn recast_choice_keeps_old_share_confirmations_suppressed() {
        let db = db_with_bundle();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();

        crate::storage::queries::store_vote(&db.conn(), ROUND, W, 0, 2, 0, &[0xCC; 16]).unwrap();
        db.record_share_delegation(
            ROUND,
            0,
            2,
            0,
            &["https://helper.example".to_string()],
            &[0x44; 32],
            0,
        )
        .unwrap();

        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 1, Decision::Skipped, 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 3, Decision::Skipped, 3)
            .unwrap();
        crate::storage::queries::store_vote(&db.conn(), ROUND, W, 0, 2, 1, &[0xDD; 16]).unwrap();

        assert!(
            db.get_share_delegations(ROUND).unwrap().is_empty(),
            "recasting must clear helper-share rows for the old vote"
        );

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();
        assert_eq!(
            plan.next_steps,
            vec![NextStep::CastVote {
                bundle_index: 0,
                proposal_id: 2,
                choice: 1,
            }]
        );
    }

    #[test]
    fn skipped_intent_clears_and_blocks_stale_share_rows() {
        let db = db_with_bundle();
        crate::storage::queries::store_vote(&db.conn(), ROUND, W, 0, 2, 0, &[0xCC; 16]).unwrap();
        db.record_share_delegation(
            ROUND,
            0,
            2,
            0,
            &["https://helper.example".to_string()],
            &[0x44; 32],
            0,
        )
        .unwrap();

        db.set_ballot_intent(ROUND, 2, Decision::Skipped, 3)
            .unwrap();

        assert!(db.get_share_delegations(ROUND).unwrap().is_empty());
        let err = db
            .record_share_delegation(
                ROUND,
                0,
                2,
                0,
                &["https://helper.example".to_string()],
                &[0x44; 32],
                0,
            )
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("cannot record share delegation for skipped proposal"),
            "{err}"
        );
    }

    #[test]
    fn skipped_proposal_is_terminal_not_recovery() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 1, Decision::Skipped, 3)
            .unwrap();
        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();
        assert!(!plan.pending_recovery);
        assert_eq!(plan.open_proposals, vec![2, 3]);
    }

    #[test]
    fn choice_intent_without_bundles_requests_bundle_setup() {
        let db = VotingDb::open_in_memory().unwrap();
        db.set_wallet_id(W);
        db.create_round(crate::Network::Testnet, &round_params(), None)
            .unwrap();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();
        assert!(plan.needs_bundle_setup);
        assert!(plan.next_steps.is_empty());
    }

    #[test]
    fn midflight_delegation_is_recovery_without_votes() {
        let db = db_with_bundle();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap(); // Submitted, no VAN
        let plan = resume_plan(&db, ROUND, &[1]).unwrap();
        assert_eq!(
            plan.next_steps,
            vec![NextStep::AdvanceDelegation { bundle_index: 0 }]
        );
        assert!(plan.hotkey_bound);
        assert_eq!(
            plan.recovered_delegation_work,
            vec![DelegationRecoveryWork {
                kind: DelegationRecoveryWorkKind::AdvanceDelegation,
                bundle_index: 0,
                phase: DelegationPhase::Submitted,
                tx_hash: Some("dtx".to_string()),
            }]
        );
    }

    #[cfg(feature = "browser")]
    #[test]
    fn legacy_delegation_hash_is_confirmed_without_a_journal() {
        let db = db_with_bundle();
        let hash = "ab".repeat(32);
        db.store_delegation_tx_hash(ROUND, 0, &hash).unwrap();
        assert!(db.validate_delegation_state(ROUND).is_err());
        db.conn()
            .execute(
                "INSERT INTO legacy_delegation_evidence VALUES (?1,?2,0,?3)",
                rusqlite::params![ROUND, W, hash],
            )
            .unwrap();
        db.validate_delegation_state(ROUND).unwrap();
        assert!(db.delegation_submission(ROUND, 0).unwrap().is_none());
        let event = crate::confirmation::TxEvent {
            event_type: "delegate_vote".into(),
            attributes: vec![
                crate::confirmation::TxEventAttribute {
                    key: "vote_round_id".into(),
                    value: ROUND.into(),
                },
                crate::confirmation::TxEventAttribute {
                    key: "leaf_index".into(),
                    value: "7".into(),
                },
            ],
        };
        assert!(db
            .confirm_legacy_delegation(ROUND, 0, &"cd".repeat(32), &[event.clone()])
            .is_err());
        assert!(db.confirm_legacy_delegation(ROUND, 0, &hash, &[]).is_err());
        db.confirm_legacy_delegation(ROUND, 0, &hash, &[event])
            .unwrap();
        assert_eq!(db.load_van_position(ROUND, 0).unwrap(), 7);
        db.validate_delegation_state(ROUND).unwrap();
        assert!(db.delegation_submission(ROUND, 0).unwrap().is_none());
    }

    #[test]
    fn confirmed_delegation_without_votes_still_binds_hotkey() {
        let db = db_with_bundle();
        db.store_delegation_tx_hash(ROUND, 0, "dtx").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert!(!plan.pending_recovery);
        assert!(plan.next_steps.is_empty());
        assert!(plan.hotkey_bound);
        assert!(!plan.completed_vote_artifact);
        assert!(plan.needs_draft_setup);
        assert_eq!(
            plan.delegation_statuses,
            vec![DelegationStatus {
                bundle_index: 0,
                phase: DelegationPhase::Confirmed,
                tx_hash: Some("dtx".to_string()),
                submission_diagnostic: None,
                terminal: false,
            }]
        );
        assert!(plan.recovered_delegation_work.is_empty());
    }

    #[test]
    fn multi_bundle_orders_vote_steps_by_proposal() {
        let db = VotingDb::open_in_memory().unwrap();
        db.set_wallet_id(W);
        db.create_round(crate::Network::Testnet, &round_params(), None)
            .unwrap();
        db.ensure_bundles(
            ROUND,
            &[note(0), note(1), note(2), note(3), note(4), note(5)],
        )
        .unwrap();

        // Verify the actual bundle count before asserting; 6 notes with
        // BALLOT_DIVISOR value each should produce 2 bundles (indices 0 and 1).
        let phases = db.delegation_phases(ROUND).unwrap();
        let bundle_count = phases.len();
        assert_eq!(
            bundle_count,
            2,
            "expected 6 notes → 2 bundles, got {bundle_count}; adjust this test if bundling rules changed"
        );

        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 1, Decision::Skipped, 3)
            .unwrap();
        db.set_ballot_intent(ROUND, 3, Decision::Skipped, 3)
            .unwrap();
        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        // Delegation prerequisites come first, then vote work is ordered by
        // proposal before bundle.
        assert_eq!(
            plan.next_steps,
            vec![
                NextStep::Delegate { bundle_index: 0 },
                NextStep::Delegate { bundle_index: 1 },
                NextStep::CastVote {
                    bundle_index: 0,
                    proposal_id: 2,
                    choice: 1,
                },
                NextStep::CastVote {
                    bundle_index: 1,
                    proposal_id: 2,
                    choice: 1,
                },
            ]
        );
    }

    #[test]
    fn interrupted_second_bundle_vote_defers_its_later_proposals() {
        let db = VotingDb::open_in_memory().unwrap();
        db.set_wallet_id(W);
        db.create_round(crate::Network::Testnet, &round_params(), None)
            .unwrap();
        db.ensure_bundles(
            ROUND,
            &[note(0), note(1), note(2), note(3), note(4), note(5)],
        )
        .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx-0").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        db.store_delegation_tx_hash(ROUND, 1, "dtx-1").unwrap();
        db.store_van_position(ROUND, 1, 8).unwrap();

        for (proposal_id, choice) in [(1, 0), (2, 1), (3, 0)] {
            db.set_ballot_intent(ROUND, proposal_id, Decision::Choice(choice), 3)
                .unwrap();
        }
        confirm_vote_fixture(&db, 0, 1, 0);
        record_all_confirmed_share_fixtures(&db, 0, 1);
        crate::storage::queries::store_vote(&db.conn(), ROUND, W, 1, 1, 0, &[0xCC; 16]).unwrap();
        store_vote_recovery_fixture(&db, 1, 1, 0, None);

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert_eq!(
            plan.next_steps,
            vec![
                NextStep::AdvanceVote {
                    bundle_index: 1,
                    proposal_id: 1,
                },
                NextStep::CastVote {
                    bundle_index: 0,
                    proposal_id: 2,
                    choice: 1,
                },
                NextStep::CastVote {
                    bundle_index: 0,
                    proposal_id: 3,
                    choice: 0,
                },
            ]
        );
    }

    #[test]
    fn confirmed_vote_without_recorded_shares_yields_submit_shares() {
        let db = VotingDb::open_in_memory().unwrap();
        db.set_wallet_id(W);
        db.create_round(crate::Network::Testnet, &round_params(), None)
            .unwrap();
        db.ensure_bundles(
            ROUND,
            &[note(0), note(1), note(2), note(3), note(4), note(5)],
        )
        .unwrap();
        db.store_delegation_tx_hash(ROUND, 0, "dtx-0").unwrap();
        db.store_van_position(ROUND, 0, 7).unwrap();
        db.store_delegation_tx_hash(ROUND, 1, "dtx-1").unwrap();
        db.store_van_position(ROUND, 1, 8).unwrap();

        for (proposal_id, choice) in [(1, 0), (2, 1)] {
            db.set_ballot_intent(ROUND, proposal_id, Decision::Choice(choice), 3)
                .unwrap();
        }
        confirm_vote_fixture(&db, 0, 1, 0);
        record_all_confirmed_share_fixtures(&db, 0, 1);
        confirm_vote_fixture(&db, 1, 1, 0);

        let plan = resume_plan(&db, ROUND, &[1, 2]).unwrap();

        assert_eq!(
            plan.next_steps,
            vec![
                NextStep::SubmitShares {
                    bundle_index: 1,
                    proposal_id: 1,
                    share_index: 0,
                },
                NextStep::SubmitShares {
                    bundle_index: 1,
                    proposal_id: 1,
                    share_index: 1,
                },
                NextStep::CastVote {
                    bundle_index: 0,
                    proposal_id: 2,
                    choice: 1,
                },
                NextStep::CastVote {
                    bundle_index: 1,
                    proposal_id: 2,
                    choice: 1,
                },
            ]
        );
        assert_eq!(
            plan.recovered_vote_work,
            vec![VoteRecoveryWork {
                kind: VoteRecoveryWorkKind::SubmitShares,
                bundle_index: 1,
                proposal_id: 1,
                tx_hash: None,
                vc_tree_position: Some(42),
                share_indexes: vec![0, 1],
            }]
        );
    }

    #[test]
    fn confirmed_vote_with_partial_recorded_shares_yields_submit_shares() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        confirm_vote_fixture(&db, 0, 2, 1);
        record_confirmed_share_fixture(&db, 0, 2, 0);

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert_eq!(
            plan.next_steps,
            vec![NextStep::SubmitShares {
                bundle_index: 0,
                proposal_id: 2,
                share_index: 1,
            }]
        );
    }

    #[test]
    fn confirmed_vote_with_all_recorded_shares_has_no_share_submission_step() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        confirm_vote_fixture(&db, 0, 2, 1);
        record_all_confirmed_share_fixtures(&db, 0, 2);

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert!(plan.next_steps.is_empty(), "got {:?}", plan.next_steps);
        assert!(plan.completed_vote_artifact);
        assert!(plan.completed_for_display);
        assert_eq!(
            plan.completed_vote_display
                .as_ref()
                .map(|display| &display.choices),
            Some(&vec![
                CompletedVoteChoice {
                    proposal_id: 1,
                    choice: None,
                },
                CompletedVoteChoice {
                    proposal_id: 2,
                    choice: Some(1),
                },
                CompletedVoteChoice {
                    proposal_id: 3,
                    choice: None,
                },
            ])
        );
        assert!(plan
            .completed_vote_display
            .as_ref()
            .and_then(|display| display.voted_at)
            .is_some());
        assert!(plan.needs_draft_setup);
        assert_eq!(plan.primary_action, RoundPlanAction::Done);
        assert!(plan.recovered_vote_work.is_empty());
    }

    #[test]
    fn confirmed_single_share_vote_with_recorded_payload_has_no_share_submission_step() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        confirm_vote_fixture(&db, 0, 2, 1);
        let mut recovery = recovery_bundle_fixture(0, 2, 1, 42);
        recovery.single_share = true;
        store_recovery_bundle_fixture(&db, &recovery, Some(42));
        record_confirmed_share_fixture(&db, 0, 2, 0);

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert!(plan.next_steps.is_empty(), "got {:?}", plan.next_steps);
    }

    #[test]
    fn delegate_suppressed_when_vote_confirmed() {
        let db = db_with_bundle();
        confirm_vote_fixture(&db, 0, 2, 1);
        record_all_confirmed_share_fixtures(&db, 0, 2);

        // Bundle 0 delegation is still only Prepared — but the vote is Confirmed,
        // so no Delegate step should appear and the plan has no work left.
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert!(
            plan.next_steps.is_empty(),
            "expected no steps, got: {:?}",
            plan.next_steps
        );
        assert!(!plan.pending_recovery);
    }

    #[test]
    fn confirm_share_emitted_for_unconfirmed_share() {
        let db = db_with_bundle();
        db.record_share_delegation(
            ROUND,
            0,
            2,
            0,
            &["https://helper.example".to_string()],
            &[0x44; 32],
            0,
        )
        .unwrap();

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert!(
            plan.next_steps.contains(&NextStep::ConfirmShare {
                bundle_index: 0,
                proposal_id: 2,
                share_index: 0
            }),
            "expected ConfirmShare in steps, got: {:?}",
            plan.next_steps
        );
    }

    #[test]
    fn accepted_helper_share_confirmation_is_nonblocking_display_work() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        confirm_vote_fixture(&db, 0, 2, 1);
        let mut recovery = recovery_bundle_fixture(0, 2, 1, 42);
        recovery.single_share = true;
        store_recovery_bundle_fixture(&db, &recovery, Some(42));
        record_submitted_share_fixture(&db, 0, 2, 0, &["https://helper.example".to_string()]);

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert_eq!(
            plan.next_steps,
            vec![NextStep::ConfirmShare {
                bundle_index: 0,
                proposal_id: 2,
                share_index: 0
            }]
        );
        assert!(plan.pending_recovery);
        assert!(!plan.blocking_recovery);
        assert!(!plan.blocking_share_work);
        assert!(plan.completed_vote_artifact);
        assert!(plan.completed_for_display);
        assert!(plan.needs_draft_setup);
        assert_eq!(plan.primary_action, RoundPlanAction::Done);
    }

    #[test]
    fn unaccepted_helper_share_confirmation_blocks_foreground_recovery() {
        let db = db_with_bundle();
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();
        confirm_vote_fixture(&db, 0, 2, 1);
        let mut recovery = recovery_bundle_fixture(0, 2, 1, 42);
        recovery.single_share = true;
        store_recovery_bundle_fixture(&db, &recovery, Some(42));
        record_submitted_share_fixture(&db, 0, 2, 0, &[]);

        let plan = resume_plan(&db, ROUND, &[1, 2, 3]).unwrap();

        assert_eq!(
            plan.next_steps,
            vec![NextStep::ConfirmShare {
                bundle_index: 0,
                proposal_id: 2,
                share_index: 0
            }]
        );
        assert!(plan.pending_recovery);
        assert!(plan.blocking_recovery);
        assert!(plan.blocking_share_work);
        assert!(plan.completed_vote_artifact);
        assert!(!plan.completed_for_display);
        assert!(!plan.needs_draft_setup);
        assert_eq!(plan.primary_action, RoundPlanAction::SubmitShares);
        assert_eq!(
            plan.recovered_vote_work,
            vec![VoteRecoveryWork {
                kind: VoteRecoveryWorkKind::SubmitShares,
                bundle_index: 0,
                proposal_id: 2,
                tx_hash: None,
                vc_tree_position: Some(42),
                share_indexes: vec![0],
            }]
        );
    }

    #[test]
    fn all_decided_true_with_confirmed_choice_and_skip() {
        let db = db_with_bundle();

        // Proposal 2: drive to Confirmed.
        confirm_vote_fixture(&db, 0, 2, 1);
        record_all_confirmed_share_fixtures(&db, 0, 2);
        db.set_ballot_intent(ROUND, 2, Decision::Choice(1), 3)
            .unwrap();

        // Proposal 1: skipped.
        db.set_ballot_intent(ROUND, 1, Decision::Skipped, 3)
            .unwrap();

        let plan = resume_plan(&db, ROUND, &[1, 2]).unwrap();

        assert!(plan.all_decided, "expected all_decided == true");
        assert!(!plan.pending_recovery, "expected pending_recovery == false");
    }
}
