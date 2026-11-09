//! Canonical Valar cast-vote wire identity and durable submission recovery.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use prost::Message;
use rusqlite::{params, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{
    confirmation::{TxEvent, TxEventAttribute},
    platform::{OwnedHttpRequest, OwnedHttpResponse, RequestKind, TransportError, API_LIMIT},
    storage::{queries, VotingDb},
    types::{validate_proposal_id, validate_vote_round_id_hex, VotingError},
    vote::{SignedVoteBatch, VoteRecoveryBundle, VoteSubmission},
    wire::{VoteCommitmentBatchWire, VoteCommitmentWire},
};

const CAST_VOTE_EVENT: &str = "cast_vote";
const CAST_VOTE_BATCH_EVENT: &str = "cast_vote_batch";

fn invalid() -> VotingError {
    VotingError::InvalidInput {
        message: "invalid vote recovery state".to_string(),
    }
}

// Exact MsgCastVote field mapping from Valar's pinned tx.proto.
#[derive(Clone, PartialEq, Message)]
struct MsgCastVote {
    #[prost(bytes = "vec", tag = "1")]
    van_nullifier: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    vote_authority_note_new: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    vote_commitment: Vec<u8>,
    #[prost(uint32, tag = "4")]
    proposal_id: u32,
    #[prost(bytes = "vec", tag = "5")]
    proof: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    vote_round_id: Vec<u8>,
    #[prost(uint64, tag = "7")]
    vote_comm_tree_anchor_height: u64,
    #[prost(bytes = "vec", tag = "10")]
    vote_auth_sig: Vec<u8>,
    #[prost(bytes = "vec", tag = "12")]
    r_vpk: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct MsgCastVoteBatch {
    #[prost(message, repeated, tag = "1")]
    votes: Vec<MsgCastVote>,
}

/// Exact immutable request bytes and transaction identity for one vote POST.
#[derive(Clone, Debug)]
pub struct CanonicalVoteSubmission {
    json: Vec<u8>,
    tx_hash: String,
    anchor_proposal_id: u32,
    proposal_ids: Vec<u32>,
    round_id: String,
    anchor_height: u32,
    batch_digest: Option<[u8; 32]>,
    batch: bool,
}

impl CanonicalVoteSubmission {
    pub fn from_singleton(submission: &VoteSubmission) -> Result<Self, VotingError> {
        validate_proposal_id(submission.proposal_id)?;
        validate_vote_round_id_hex(&submission.vote_round_id)?;
        if submission.proof.is_empty() {
            return Err(invalid());
        }
        let vote_round_id = hex::decode(&submission.vote_round_id).map_err(|_| invalid())?;
        let wire = VoteCommitmentWire {
            van_nullifier: STANDARD.encode(submission.van_nullifier),
            vote_authority_note_new: STANDARD.encode(submission.vote_authority_note_new),
            vote_commitment: STANDARD.encode(submission.vote_commitment),
            proposal_id: submission.proposal_id,
            proof: STANDARD.encode(&submission.proof),
            vote_round_id: STANDARD.encode(&vote_round_id),
            anchor_height: submission.anchor_height,
            r_vpk: STANDARD.encode(submission.r_vpk),
            vote_auth_sig: STANDARD.encode(submission.vote_auth_sig),
        };
        let json = wire.to_json()?.into_bytes();
        let message = MsgCastVote {
            van_nullifier: submission.van_nullifier.to_vec(),
            vote_authority_note_new: submission.vote_authority_note_new.to_vec(),
            vote_commitment: submission.vote_commitment.to_vec(),
            proposal_id: submission.proposal_id,
            proof: submission.proof.clone(),
            vote_round_id,
            vote_comm_tree_anchor_height: u64::from(submission.anchor_height),
            vote_auth_sig: submission.vote_auth_sig.to_vec(),
            r_vpk: submission.r_vpk.to_vec(),
        };
        let mut tx_bytes = vec![0x03];
        message.encode(&mut tx_bytes).map_err(|_| invalid())?;
        Ok(Self {
            json,
            tx_hash: hex::encode_upper(Sha256::digest(tx_bytes)),
            anchor_proposal_id: submission.proposal_id,
            proposal_ids: vec![submission.proposal_id],
            round_id: submission.vote_round_id.clone(),
            anchor_height: submission.anchor_height,
            batch_digest: None,
            batch: false,
        })
    }

    pub fn from_batch(batch: &SignedVoteBatch) -> Result<Self, VotingError> {
        if batch.commitments.is_empty() {
            return Err(invalid());
        }
        let first = &batch.commitments[0];
        if batch.commitments.iter().any(|commitment| {
            commitment.vote_round_id != first.vote_round_id
                || commitment.anchor_height != first.anchor_height
        }) {
            return Err(invalid());
        }
        let actions = batch
            .commitments
            .iter()
            .map(
                |commitment| crate::vote_commitment::CastVoteBatchSighashAction {
                    r_vpk: &commitment.r_vpk,
                    van_nullifier: &commitment.van_nullifier,
                    vote_authority_note_new: &commitment.vote_authority_note_new,
                    vote_commitment: &commitment.vote_commitment,
                    proposal_id: commitment.proposal_id,
                },
            )
            .collect::<Vec<_>>();
        if crate::vote_commitment::cast_vote_batch_sighash(
            &first.vote_round_id,
            u64::from(first.anchor_height),
            &actions,
        )? != batch.batch_digest
        {
            return Err(invalid());
        }
        let votes = batch
            .commitments
            .iter()
            .map(VoteCommitmentWire::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        let canonical_json = VoteCommitmentBatchWire {
            votes: votes.clone(),
        }
        .to_json()?;
        if canonical_json != batch.batch_json {
            return Err(invalid());
        }
        let messages = votes
            .iter()
            .map(message_from_wire)
            .collect::<Result<Vec<_>, _>>()?;
        let proposal_ids = messages
            .iter()
            .map(|message| message.proposal_id)
            .collect::<Vec<_>>();
        if proposal_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(invalid());
        }
        let mut tx_bytes = vec![0x06];
        MsgCastVoteBatch { votes: messages }
            .encode(&mut tx_bytes)
            .map_err(|_| invalid())?;
        Ok(Self {
            json: canonical_json.into_bytes(),
            tx_hash: hex::encode_upper(Sha256::digest(tx_bytes)),
            anchor_proposal_id: proposal_ids[0],
            proposal_ids,
            round_id: first.vote_round_id.clone(),
            anchor_height: first.anchor_height,
            batch_digest: Some(batch.batch_digest),
            batch: true,
        })
    }

    pub fn json_bytes(&self) -> &[u8] {
        &self.json
    }

    pub fn tx_hash(&self) -> &str {
        &self.tx_hash
    }

    pub fn anchor_proposal_id(&self) -> u32 {
        self.anchor_proposal_id
    }

    pub fn proposal_ids(&self) -> &[u32] {
        &self.proposal_ids
    }

    pub fn is_batch(&self) -> bool {
        self.batch
    }

    fn parse(
        json: Vec<u8>,
        proposal_ids: Vec<u32>,
        batch_digest: Option<[u8; 32]>,
    ) -> Result<Self, VotingError> {
        if proposal_ids.is_empty() || proposal_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(invalid());
        }
        let (messages, canonical_json) = if batch_digest.is_some() {
            let wire: VoteCommitmentBatchWire =
                serde_json::from_slice(&json).map_err(|_| invalid())?;
            let canonical_json = wire.to_json()?;
            let messages = wire
                .votes
                .iter()
                .map(message_from_wire)
                .collect::<Result<Vec<_>, _>>()?;
            (messages, canonical_json)
        } else {
            let wire: VoteCommitmentWire = serde_json::from_slice(&json).map_err(|_| invalid())?;
            let canonical_json = wire.to_json()?;
            (vec![message_from_wire(&wire)?], canonical_json)
        };
        if canonical_json.as_bytes() != json
            || messages
                .iter()
                .map(|msg| msg.proposal_id)
                .collect::<Vec<_>>()
                != proposal_ids
        {
            return Err(invalid());
        }
        let round_id = messages
            .first()
            .map(|msg| hex::encode(&msg.vote_round_id))
            .ok_or_else(invalid)?;
        validate_vote_round_id_hex(&round_id)?;
        let anchor_height =
            u32::try_from(messages[0].vote_comm_tree_anchor_height).map_err(|_| invalid())?;
        if messages.iter().any(|msg| {
            msg.vote_round_id != messages[0].vote_round_id
                || msg.vote_comm_tree_anchor_height != messages[0].vote_comm_tree_anchor_height
        }) {
            return Err(invalid());
        }
        if let Some(expected_digest) = batch_digest {
            let actions = messages
                .iter()
                .map(
                    |message| crate::vote_commitment::CastVoteBatchSighashAction {
                        r_vpk: &message.r_vpk,
                        van_nullifier: &message.van_nullifier,
                        vote_authority_note_new: &message.vote_authority_note_new,
                        vote_commitment: &message.vote_commitment,
                        proposal_id: message.proposal_id,
                    },
                )
                .collect::<Vec<_>>();
            if crate::vote_commitment::cast_vote_batch_sighash(
                &round_id,
                u64::from(anchor_height),
                &actions,
            )? != expected_digest
            {
                return Err(invalid());
            }
        }
        let is_batch = batch_digest.is_some();
        let mut tx_bytes = vec![if is_batch { 0x06 } else { 0x03 }];
        if is_batch {
            MsgCastVoteBatch { votes: messages }
                .encode(&mut tx_bytes)
                .map_err(|_| invalid())?;
        } else {
            messages[0].encode(&mut tx_bytes).map_err(|_| invalid())?;
        }
        Ok(Self {
            json,
            tx_hash: hex::encode_upper(Sha256::digest(tx_bytes)),
            anchor_proposal_id: proposal_ids[0],
            proposal_ids,
            round_id,
            anchor_height,
            batch_digest,
            batch: is_batch,
        })
    }

    fn validate_with_conn(
        &self,
        conn: &rusqlite::Connection,
        wallet_id: &str,
        round_id: &str,
        bundle_index: u32,
    ) -> Result<(), VotingError> {
        if self.round_id != round_id {
            return Err(invalid());
        }
        let recoveries = if let Some(digest) = self.batch_digest {
            crate::vote::load_vote_batch_recoveries_with_conn(
                conn,
                wallet_id,
                round_id,
                bundle_index,
                digest,
            )?
        } else {
            vec![crate::vote::recovery_bundle_with_conn(
                conn,
                wallet_id,
                round_id,
                bundle_index,
                self.anchor_proposal_id,
            )?
            .ok_or_else(invalid)?]
        };
        if recoveries
            .iter()
            .map(|recovery| recovery.proposal_id)
            .collect::<Vec<_>>()
            != self.proposal_ids
            || recoveries.iter().any(|recovery| {
                recovery.vote_round_id != self.round_id
                    || recovery.anchor_height != self.anchor_height
            })
        {
            return Err(invalid());
        }
        let votes = recoveries
            .iter()
            .map(wire_from_recovery)
            .collect::<Result<Vec<_>, _>>()?;
        let expected = if self.batch {
            VoteCommitmentBatchWire { votes }.to_json()?
        } else {
            votes[0].to_json()?
        };
        if expected.as_bytes() != self.json {
            return Err(invalid());
        }
        Ok(())
    }
}

fn wire_from_recovery(recovery: &VoteRecoveryBundle) -> Result<VoteCommitmentWire, VotingError> {
    validate_vote_round_id_hex(&recovery.vote_round_id)?;
    Ok(VoteCommitmentWire {
        van_nullifier: STANDARD.encode(recovery.van_nullifier),
        vote_authority_note_new: STANDARD.encode(recovery.vote_authority_note_new),
        vote_commitment: STANDARD.encode(recovery.vote_commitment),
        proposal_id: recovery.proposal_id,
        proof: STANDARD.encode(&recovery.proof),
        vote_round_id: STANDARD
            .encode(hex::decode(&recovery.vote_round_id).map_err(|_| invalid())?),
        anchor_height: recovery.anchor_height,
        r_vpk: STANDARD.encode(recovery.r_vpk),
        vote_auth_sig: STANDARD.encode(recovery.vote_auth_sig),
    })
}

fn message_from_wire(wire: &VoteCommitmentWire) -> Result<MsgCastVote, VotingError> {
    let decode = |value: &str| STANDARD.decode(value).map_err(|_| invalid());
    validate_proposal_id(wire.proposal_id)?;
    let message = MsgCastVote {
        van_nullifier: decode(&wire.van_nullifier)?,
        vote_authority_note_new: decode(&wire.vote_authority_note_new)?,
        vote_commitment: decode(&wire.vote_commitment)?,
        proposal_id: wire.proposal_id,
        proof: decode(&wire.proof)?,
        vote_round_id: decode(&wire.vote_round_id)?,
        vote_comm_tree_anchor_height: u64::from(wire.anchor_height),
        vote_auth_sig: decode(&wire.vote_auth_sig)?,
        r_vpk: decode(&wire.r_vpk)?,
    };
    if message.van_nullifier.len() != 32
        || message.vote_authority_note_new.len() != 32
        || message.vote_commitment.len() != 32
        || message.vote_round_id.len() != 32
        || message.r_vpk.len() != 32
        || message.vote_auth_sig.len() != 64
        || message.proof.is_empty()
    {
        return Err(invalid());
    }
    Ok(message)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VoteSubmissionOutcome {
    Prepared,
    Dispatching,
    Accepted,
    Ambiguous,
    Rejected,
}

impl VoteSubmissionOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepared => "prepared",
            Self::Dispatching => "dispatching",
            Self::Accepted => "accepted",
            Self::Ambiguous => "ambiguous",
            Self::Rejected => "rejected",
        }
    }

    fn parse(value: &str) -> Result<Self, VotingError> {
        match value {
            "prepared" => Ok(Self::Prepared),
            "dispatching" => Ok(Self::Dispatching),
            "accepted" => Ok(Self::Accepted),
            "ambiguous" => Ok(Self::Ambiguous),
            "rejected" => Ok(Self::Rejected),
            _ => Err(invalid()),
        }
    }
}

pub struct VoteSubmissionAttempt {
    pub canonical: CanonicalVoteSubmission,
    pub outcome: VoteSubmissionOutcome,
    pub confirmation_tx_hash: Option<String>,
    pub confirmation_van_position: Option<u32>,
    pub confirmation_vc_positions: Option<Vec<u64>>,
}

impl VotingDb {
    /// Adopt pre-journal browser votes that already have a durable transaction hash.
    /// The row is never left Prepared, which would authorize a duplicate POST
    /// if persistence fails between two separate writes.
    #[cfg(feature = "browser")]
    pub fn adopt_legacy_vote_submission(
        &self,
        round_id: &str,
        bundle_index: u32,
        canonical: &CanonicalVoteSubmission,
    ) -> Result<bool, VotingError> {
        let wallet_id = self.wallet_id();
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| invalid())?;
        canonical.validate_with_conn(&tx, &wallet_id, round_id, bundle_index)?;
        if load_attempt_with_conn(
            &tx,
            &wallet_id,
            round_id,
            bundle_index,
            canonical.anchor_proposal_id,
        )?
        .is_some()
        {
            return Err(invalid());
        }
        let hashes = canonical
            .proposal_ids
            .iter()
            .map(|proposal_id| {
                queries::get_vote_tx_hash(&tx, round_id, &wallet_id, bundle_index, *proposal_id)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if hashes.iter().all(Option::is_none) {
            return Ok(false);
        }
        if hashes
            .iter()
            .any(|hash| hash.as_deref() != Some(canonical.tx_hash.as_str()))
        {
            return Err(invalid());
        }
        for proposal_id in &canonical.proposal_ids {
            let preserved: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM legacy_vote_evidence
                     WHERE round_id=?1 AND wallet_id=?2 AND bundle_index=?3
                       AND proposal_id=?4 AND tx_hash=?5)",
                    params![
                        round_id,
                        wallet_id,
                        bundle_index,
                        proposal_id,
                        canonical.tx_hash
                    ],
                    |row| row.get(0),
                )
                .map_err(|_| invalid())?;
            if !preserved {
                return Err(invalid());
            }
        }
        tx.execute(
            "INSERT INTO vote_attempts
             (round_id,wallet_id,bundle_index,anchor_proposal_id,canonical_json,tx_hash,proposal_ids_json,batch_digest,outcome)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'dispatching')",
            params![
                round_id,
                wallet_id,
                bundle_index,
                canonical.anchor_proposal_id,
                canonical.json,
                canonical.tx_hash,
                serde_json::to_string(&canonical.proposal_ids).map_err(|_| invalid())?,
                canonical.batch_digest.map(|digest| digest.to_vec()),
            ],
        )
        .map_err(|_| invalid())?;
        for proposal_id in &canonical.proposal_ids {
            let removed = tx
                .execute(
                    "DELETE FROM legacy_vote_evidence WHERE round_id=?1 AND wallet_id=?2
                     AND bundle_index=?3 AND proposal_id=?4",
                    params![round_id, wallet_id, bundle_index, proposal_id],
                )
                .map_err(|_| invalid())?;
            if removed != 1 {
                return Err(invalid());
            }
        }
        tx.commit().map_err(|_| invalid())?;
        Ok(true)
    }

    pub fn prepare_vote_submission(
        &self,
        round_id: &str,
        bundle_index: u32,
        canonical: &CanonicalVoteSubmission,
    ) -> Result<(), VotingError> {
        let wallet_id = self.wallet_id();
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| invalid())?;
        canonical.validate_with_conn(&tx, &wallet_id, round_id, bundle_index)?;
        if let Some(existing) = load_attempt_with_conn(
            &tx,
            &wallet_id,
            round_id,
            bundle_index,
            canonical.anchor_proposal_id,
        )? {
            return if existing.canonical.json == canonical.json
                && existing.canonical.tx_hash == canonical.tx_hash
            {
                Ok(())
            } else {
                Err(invalid())
            };
        }
        tx.execute(
            "INSERT INTO vote_attempts
             (round_id,wallet_id,bundle_index,anchor_proposal_id,canonical_json,tx_hash,proposal_ids_json,batch_digest,outcome)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,'prepared')",
            params![
                round_id,
                wallet_id,
                bundle_index,
                canonical.anchor_proposal_id,
                canonical.json,
                canonical.tx_hash,
                serde_json::to_string(&canonical.proposal_ids).map_err(|_| invalid())?,
                canonical.batch_digest.map(|digest| digest.to_vec()),
            ],
        )
        .map_err(|_| invalid())?;
        tx.commit().map_err(|_| invalid())
    }

    pub fn vote_submission(
        &self,
        round_id: &str,
        bundle_index: u32,
        anchor_proposal_id: u32,
    ) -> Result<Option<VoteSubmissionAttempt>, VotingError> {
        let wallet_id = self.wallet_id();
        let conn = self.conn();
        let attempt = load_attempt_with_conn(
            &conn,
            &wallet_id,
            round_id,
            bundle_index,
            anchor_proposal_id,
        )?;
        if let Some(attempt) = &attempt {
            attempt
                .canonical
                .validate_with_conn(&conn, &wallet_id, round_id, bundle_index)?;
            validate_attempt_vote_hashes(&conn, &wallet_id, round_id, bundle_index, attempt)?;
        }
        Ok(attempt)
    }

    pub fn mark_vote_dispatching(
        &self,
        round_id: &str,
        bundle_index: u32,
        anchor_proposal_id: u32,
    ) -> Result<(), VotingError> {
        let wallet_id = self.wallet_id();
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| invalid())?;
        let attempt =
            load_attempt_with_conn(&tx, &wallet_id, round_id, bundle_index, anchor_proposal_id)?
                .ok_or_else(invalid)?;
        attempt
            .canonical
            .validate_with_conn(&tx, &wallet_id, round_id, bundle_index)?;
        if attempt.outcome != VoteSubmissionOutcome::Prepared {
            return Err(invalid());
        }
        for proposal_id in &attempt.canonical.proposal_ids {
            queries::record_vote_submission(
                &tx,
                round_id,
                &wallet_id,
                bundle_index,
                *proposal_id,
                &attempt.canonical.tx_hash,
            )?;
        }
        let changed = tx
            .execute(
                "UPDATE vote_attempts SET outcome='dispatching'
                 WHERE round_id=?1 AND wallet_id=?2 AND bundle_index=?3 AND anchor_proposal_id=?4 AND outcome='prepared'",
                params![round_id, wallet_id, bundle_index, anchor_proposal_id],
            )
            .map_err(|_| invalid())?;
        if changed != 1 {
            return Err(invalid());
        }
        tx.commit().map_err(|_| invalid())
    }

    pub fn record_vote_outcome(
        &self,
        round_id: &str,
        bundle_index: u32,
        anchor_proposal_id: u32,
        outcome: VoteSubmissionOutcome,
    ) -> Result<(), VotingError> {
        if matches!(
            outcome,
            VoteSubmissionOutcome::Prepared | VoteSubmissionOutcome::Dispatching
        ) {
            return Err(invalid());
        }
        let wallet_id = self.wallet_id();
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| invalid())?;
        let attempt =
            load_attempt_with_conn(&tx, &wallet_id, round_id, bundle_index, anchor_proposal_id)?
                .ok_or_else(invalid)?;
        attempt
            .canonical
            .validate_with_conn(&tx, &wallet_id, round_id, bundle_index)?;
        if attempt.outcome == VoteSubmissionOutcome::Prepared
            || (attempt.outcome == VoteSubmissionOutcome::Rejected
                && outcome != VoteSubmissionOutcome::Rejected)
        {
            return Err(invalid());
        }
        tx.execute(
            "UPDATE vote_attempts SET outcome=?5
             WHERE round_id=?1 AND wallet_id=?2 AND bundle_index=?3 AND anchor_proposal_id=?4",
            params![
                round_id,
                wallet_id,
                bundle_index,
                anchor_proposal_id,
                outcome.as_str()
            ],
        )
        .map_err(|_| invalid())?;
        tx.commit().map_err(|_| invalid())
    }

    /// Validates canonical plain-text chain events and records the complete
    /// journal evidence plus all affected tree positions in one transaction.
    pub fn confirm_journaled_vote(
        &self,
        round_id: &str,
        bundle_index: u32,
        anchor_proposal_id: u32,
        tx_hash: &str,
        events: &[TxEvent],
    ) -> Result<(), VotingError> {
        let wallet_id = self.wallet_id();
        let mut conn = self.conn();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|_| invalid())?;
        let attempt =
            load_attempt_with_conn(&tx, &wallet_id, round_id, bundle_index, anchor_proposal_id)?
                .ok_or_else(invalid)?;
        attempt
            .canonical
            .validate_with_conn(&tx, &wallet_id, round_id, bundle_index)?;
        validate_attempt_vote_hashes(&tx, &wallet_id, round_id, bundle_index, &attempt)?;
        if tx_hash != attempt.canonical.tx_hash
            || attempt.outcome == VoteSubmissionOutcome::Rejected
        {
            return Err(invalid());
        }
        let parsed = parse_strict_confirmation(events, &attempt.canonical)?;
        let current_van = queries::load_van_position(&tx, round_id, &wallet_id, bundle_index)?;
        let replay = attempt.confirmation_tx_hash.as_deref() == Some(tx_hash)
            && attempt.confirmation_van_position == Some(parsed.van_position)
            && attempt.confirmation_vc_positions.as_ref() == Some(&parsed.vc_positions);
        if !replay && parsed.van_position <= current_van {
            return Err(invalid());
        }
        if !replay {
            validate_confirmation_positions(&tx, &wallet_id, round_id, bundle_index, &parsed)?;
        }
        for (proposal_id, vc_position) in attempt
            .canonical
            .proposal_ids
            .iter()
            .zip(parsed.vc_positions.iter())
        {
            crate::vote::record_vc_position_with_conn(
                &tx,
                &wallet_id,
                round_id,
                bundle_index,
                *proposal_id,
                *vc_position,
            )?;
        }
        if !replay || current_van < parsed.van_position {
            queries::store_van_position_u64(
                &tx,
                round_id,
                &wallet_id,
                bundle_index,
                u64::from(parsed.van_position),
            )?;
        }
        let vc_json = serde_json::to_string(&parsed.vc_positions).map_err(|_| invalid())?;
        let changed = tx
            .execute(
                "UPDATE vote_attempts
             SET outcome='accepted', confirmation_tx_hash=?5,
                 confirmation_van_position=?6, confirmation_vc_positions_json=?7
             WHERE round_id=?1 AND wallet_id=?2 AND bundle_index=?3 AND anchor_proposal_id=?4
               AND (confirmation_tx_hash IS NULL OR
                    (confirmation_tx_hash=?5 AND confirmation_van_position=?6
                     AND confirmation_vc_positions_json=?7))",
                params![
                    round_id,
                    wallet_id,
                    bundle_index,
                    anchor_proposal_id,
                    tx_hash,
                    parsed.van_position,
                    vc_json
                ],
            )
            .map_err(|_| invalid())?;
        if changed != 1 {
            return Err(invalid());
        }
        tx.commit().map_err(|_| invalid())
    }

    /// Validates all durable vote attempts and their relationship to the
    /// original delegation evidence before restored state can drive effects.
    pub fn validate_vote_submission_state(&self, round_id: &str) -> Result<(), VotingError> {
        let wallet_id = self.wallet_id();
        let hotkey = self.load_voting_hotkey(round_id)?;
        let conn = self.conn();
        let orphan: bool = conn
            .query_row(
                "SELECT EXISTS(
                SELECT 1 FROM vote_attempts a
                LEFT JOIN votes v ON v.round_id=a.round_id AND v.wallet_id=a.wallet_id
                  AND v.bundle_index=a.bundle_index AND v.proposal_id=a.anchor_proposal_id
                WHERE a.round_id=?1 AND a.wallet_id=?2 AND v.id IS NULL)",
                params![round_id, wallet_id],
                |row| row.get(0),
            )
            .map_err(|_| invalid())?;
        if orphan {
            return Err(invalid());
        }

        let mut statement = conn
            .prepare(
                "SELECT bundle_index,anchor_proposal_id FROM vote_attempts
             WHERE round_id=?1 AND wallet_id=?2 ORDER BY bundle_index,anchor_proposal_id",
            )
            .map_err(|_| invalid())?;
        let keys = statement
            .query_map(params![round_id, wallet_id], |row| {
                Ok((row.get::<_, u32>(0)?, row.get::<_, u32>(1)?))
            })
            .map_err(|_| invalid())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        drop(statement);

        let mut attempts = Vec::with_capacity(keys.len());
        for (bundle, anchor) in keys {
            let attempt = load_attempt_with_conn(&conn, &wallet_id, round_id, bundle, anchor)?
                .ok_or_else(invalid)?;
            attempt
                .canonical
                .validate_with_conn(&conn, &wallet_id, round_id, bundle)?;
            validate_attempt_vote_hashes(&conn, &wallet_id, round_id, bundle, &attempt)?;
            attempts.push((bundle, attempt));
        }

        let mut submitted = conn
            .prepare(
                "SELECT bundle_index,proposal_id,tx_hash FROM votes
             WHERE round_id=?1 AND wallet_id=?2 AND tx_hash IS NOT NULL",
            )
            .map_err(|_| invalid())?;
        let submitted = submitted
            .query_map(params![round_id, wallet_id], |row| {
                Ok((
                    row.get::<_, u32>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(|_| invalid())?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        for (bundle, proposal, hash) in submitted {
            if !attempts.iter().any(|(attempt_bundle, attempt)| {
                *attempt_bundle == bundle
                    && attempt.canonical.tx_hash == hash
                    && attempt.canonical.proposal_ids.contains(&proposal)
            }) {
                #[cfg(feature = "browser")]
                {
                    let state = queries::load_vote_row_state(
                        &conn, round_id, &wallet_id, bundle, proposal,
                    )?
                    .ok_or_else(invalid)?;
                    let preserved: bool = conn
                        .query_row(
                            "SELECT EXISTS(SELECT 1 FROM legacy_vote_evidence
                             WHERE round_id=?1 AND wallet_id=?2 AND bundle_index=?3
                               AND proposal_id=?4 AND tx_hash=?5)",
                            params![round_id, wallet_id, bundle, proposal, hash],
                            |row| row.get(0),
                        )
                        .map_err(|_| invalid())?;
                    let confirmed = state.vc_tree_position.is_some_and(|position| {
                        u64::try_from(position)
                            .ok()
                            .is_some_and(|position| position < vote_commitment_tree::TREE_CAPACITY)
                    });
                    if preserved
                        && (confirmed
                            || crate::vote::recovery_bundle_with_conn(
                                &conn, &wallet_id, round_id, bundle, proposal,
                            )?
                            .is_some())
                    {
                        continue;
                    }
                }
                return Err(invalid());
            }
        }

        let bundle_count: u32 = conn
            .query_row(
                "SELECT COUNT(*) FROM bundles WHERE round_id=?1 AND wallet_id=?2",
                params![round_id, wallet_id],
                |row| row.get(0),
            )
            .map_err(|_| invalid())?;
        for bundle in 0..bundle_count {
            let bundle_attempts = attempts
                .iter()
                .filter(|(index, _)| *index == bundle)
                .map(|(_, attempt)| attempt)
                .collect::<Vec<_>>();
            if bundle_attempts.is_empty() {
                continue;
            }
            let original: u32 = conn
                .query_row(
                    "SELECT a.confirmation_van_position FROM delegation_attempts a
                 JOIN bundles b ON b.round_id=a.round_id AND b.wallet_id=a.wallet_id
                   AND b.bundle_index=a.bundle_index
                 WHERE a.round_id=?1 AND a.wallet_id=?2 AND a.bundle_index=?3
                   AND a.outcome='accepted' AND a.confirmation_tx_hash=a.tx_hash
                   AND b.delegation_tx_hash=a.tx_hash",
                    params![round_id, wallet_id, bundle],
                    |row| row.get(0),
                )
                .map_err(|_| invalid())?;
            let hotkey = hotkey.as_ref().ok_or_else(invalid)?;
            let zkp2 = queries::load_zkp2_inputs(&conn, round_id, &wallet_id, bundle)?;
            let network = queries::load_round_network(&conn, round_id, &wallet_id)?;
            let round_bytes = hex::decode(round_id).map_err(|_| invalid())?;
            let original_van: Vec<u8> = conn.query_row(
                "SELECT gov_comm FROM bundles WHERE round_id=?1 AND wallet_id=?2 AND bundle_index=?3",
                params![round_id, wallet_id, bundle], |row| row.get(0),
            ).map_err(|_| invalid())?;
            let mut authority = voting_circuits::MAX_PROPOSAL_AUTHORITY;
            let mut expected_old_van: [u8; 32] = original_van.try_into().map_err(|_| invalid())?;
            let mut last_proposal = None;
            let mut latest_van = original;
            let mut tree_frontier = u64::from(original);
            let mut saw_unconfirmed = false;
            for attempt in bundle_attempts {
                if last_proposal.is_some_and(|last| last >= attempt.canonical.proposal_ids[0]) {
                    return Err(invalid());
                }
                last_proposal = attempt.canonical.proposal_ids.last().copied();
                if saw_unconfirmed {
                    return Err(invalid());
                }
                for message in canonical_messages(&attempt.canonical)? {
                    let transition = crate::zkp2::plan_vote_authority_transition(
                        hotkey.stored_secret(),
                        network,
                        zkp2.address_index,
                        zkp2.total_note_value,
                        &zkp2.gov_comm_rand,
                        &round_bytes,
                        message.proposal_id,
                        authority,
                    )?;
                    if transition.vote_authority_note_old != expected_old_van
                        || message.vote_authority_note_new != transition.vote_authority_note_new
                    {
                        return Err(invalid());
                    }
                    authority = transition.proposal_authority_new;
                    expected_old_van = transition.vote_authority_note_new;
                }
                let evidence_complete = attempt.confirmation_tx_hash.is_some()
                    && attempt.confirmation_van_position.is_some()
                    && attempt.confirmation_vc_positions.is_some();
                let evidence_empty = attempt.confirmation_tx_hash.is_none()
                    && attempt.confirmation_van_position.is_none()
                    && attempt.confirmation_vc_positions.is_none();
                if (!evidence_complete && !evidence_empty)
                    || (evidence_complete && attempt.outcome != VoteSubmissionOutcome::Accepted)
                {
                    return Err(invalid());
                }
                if let (Some(hash), Some(van), Some(vc_positions)) = (
                    attempt.confirmation_tx_hash.as_deref(),
                    attempt.confirmation_van_position,
                    attempt.confirmation_vc_positions.as_ref(),
                ) {
                    if hash != attempt.canonical.tx_hash
                        || vc_positions.len() != attempt.canonical.proposal_ids.len()
                        || u64::from(van) <= tree_frontier
                        || u64::from(van) >= (1u64 << vote_commitment_tree::TREE_DEPTH)
                        || vc_positions.iter().any(|position| {
                            *position <= u64::from(van)
                                || *position >= (1u64 << vote_commitment_tree::TREE_DEPTH)
                        })
                        || vc_positions
                            .windows(2)
                            .any(|positions| positions[0] >= positions[1])
                    {
                        return Err(invalid());
                    }
                    for (proposal, position) in
                        attempt.canonical.proposal_ids.iter().zip(vc_positions)
                    {
                        let stored: Option<u64> = conn.query_row(
                            "SELECT vc_tree_position FROM votes WHERE round_id=?1 AND wallet_id=?2 AND bundle_index=?3 AND proposal_id=?4",
                            params![round_id, wallet_id, bundle, proposal], |row| row.get(0)
                        ).map_err(|_| invalid())?;
                        if stored != Some(*position) {
                            return Err(invalid());
                        }
                    }
                    latest_van = van;
                    tree_frontier = *vc_positions.last().ok_or_else(invalid)?;
                } else {
                    for proposal in &attempt.canonical.proposal_ids {
                        let stored: Option<u64> = conn.query_row(
                            "SELECT vc_tree_position FROM votes WHERE round_id=?1 AND wallet_id=?2 AND bundle_index=?3 AND proposal_id=?4",
                            params![round_id, wallet_id, bundle, proposal], |row| row.get(0)
                        ).map_err(|_| invalid())?;
                        if stored.is_some() {
                            return Err(invalid());
                        }
                    }
                    saw_unconfirmed = true;
                }
            }
            if queries::load_van_position(&conn, round_id, &wallet_id, bundle)? != latest_van {
                return Err(invalid());
            }
        }
        Ok(())
    }
}

pub fn vote_request(base: &str, canonical: &CanonicalVoteSubmission) -> OwnedHttpRequest {
    OwnedHttpRequest {
        method: "POST".into(),
        url: format!(
            "{}/shielded-vote/v1/{}",
            base.trim_end_matches('/'),
            if canonical.batch {
                "cast-vote-batch"
            } else {
                "cast-vote"
            }
        ),
        headers: vec![("content-type".into(), "application/json".into())],
        body: canonical.json.clone(),
        timeout_ms: 30_000,
        max_response_bytes: API_LIMIT,
        kind: RequestKind::NonIdempotent,
    }
}

pub fn vote_status_request(base: &str, canonical: &CanonicalVoteSubmission) -> OwnedHttpRequest {
    OwnedHttpRequest {
        method: "GET".into(),
        url: format!(
            "{}/shielded-vote/v1/tx/{}",
            base.trim_end_matches('/'),
            canonical.tx_hash
        ),
        headers: vec![],
        body: vec![],
        timeout_ms: 30_000,
        max_response_bytes: API_LIMIT,
        kind: RequestKind::Idempotent,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BroadcastResult {
    tx_hash: String,
    code: u32,
    #[serde(rename = "log")]
    _log: Option<String>,
    batch_digest: Option<String>,
}

pub fn parse_vote_result(
    response: OwnedHttpResponse,
    expected: &CanonicalVoteSubmission,
) -> Result<VoteSubmissionOutcome, TransportError> {
    if response.body.len() > API_LIMIT || (response.status != 200 && response.status != 422) {
        return Err(TransportError::Ambiguous);
    }
    let result: BroadcastResult =
        serde_json::from_slice(&response.body).map_err(|_| TransportError::Ambiguous)?;
    let expected_digest = expected.batch_digest.map(hex::encode);
    if result.tx_hash != expected.tx_hash || result.batch_digest != expected_digest {
        return Err(TransportError::Ambiguous);
    }
    match (response.status, result.code) {
        (200, 0) => Ok(VoteSubmissionOutcome::Accepted),
        (422, 1..) => Ok(VoteSubmissionOutcome::Rejected),
        _ => Err(TransportError::Ambiguous),
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TxStatusBody {
    height: String,
    code: u32,
    log: String,
    events: Option<Vec<TxEvent>>,
}

pub enum VoteStatus {
    Pending,
    Rejected,
    Confirmed(Vec<TxEvent>),
}

pub fn parse_vote_status(response: OwnedHttpResponse) -> Result<VoteStatus, TransportError> {
    if response.body.len() > API_LIMIT {
        return Err(TransportError::ResponseTooLarge { limit: API_LIMIT });
    }
    if response.status == 404 {
        return Ok(VoteStatus::Pending);
    }
    if response.status != 200 && response.status != 422 {
        return Err(TransportError::Definite);
    }
    let status: TxStatusBody =
        serde_json::from_slice(&response.body).map_err(|_| TransportError::Definite)?;
    let _ = status.log;
    if !canonical_decimal(&status.height)
        || status
            .height
            .parse::<u64>()
            .ok()
            .filter(|height| *height > 0)
            .is_none()
    {
        return Err(TransportError::Definite);
    }
    match (response.status, status.code) {
        (200, 0) => Ok(VoteStatus::Confirmed(
            status.events.ok_or(TransportError::Definite)?,
        )),
        (422, 1..) => Ok(VoteStatus::Rejected),
        _ => Err(TransportError::Definite),
    }
}

struct ParsedConfirmation {
    van_position: u32,
    vc_positions: Vec<u64>,
}

fn parse_strict_confirmation(
    events: &[TxEvent],
    canonical: &CanonicalVoteSubmission,
) -> Result<ParsedConfirmation, VotingError> {
    let target = if canonical.batch {
        CAST_VOTE_BATCH_EVENT
    } else {
        CAST_VOTE_EVENT
    };
    let encoded_target = STANDARD.encode(target.as_bytes());
    if events
        .iter()
        .any(|event| event.event_type == encoded_target)
    {
        return Err(invalid());
    }
    let matching = events
        .iter()
        .filter(|event| event.event_type == target)
        .collect::<Vec<_>>();
    if matching.len() != 1 {
        return Err(invalid());
    }
    let event = matching[0];
    let expected_keys: &[&str] = if canonical.batch {
        &[
            "vote_round_id",
            "batch_digest",
            "batch_size",
            "final_van_leaf_index",
            "vote_commitment_leaf_indices",
            "proposal_ids",
            "van_nullifiers",
        ]
    } else {
        &["vote_round_id", "leaf_index"]
    };
    if event.attributes.len() != expected_keys.len() {
        return Err(invalid());
    }
    let mut values = std::collections::BTreeMap::new();
    for TxEventAttribute { key, value } in &event.attributes {
        if !expected_keys.contains(&key.as_str())
            || values.insert(key.as_str(), value.as_str()).is_some()
        {
            return Err(invalid());
        }
    }
    if values.get("vote_round_id").copied() != Some(canonical.round_id.as_str()) {
        return Err(invalid());
    }
    if !canonical.batch {
        let positions = strict_csv_u64(values.get("leaf_index").copied().ok_or_else(invalid)?)?;
        if positions.len() != 2 || positions[0] > u64::from(u32::MAX) {
            return Err(invalid());
        }
        return Ok(ParsedConfirmation {
            van_position: positions[0] as u32,
            vc_positions: vec![positions[1]],
        });
    }
    let expected_digest = canonical.batch_digest.ok_or_else(invalid)?;
    let expected_digest_hex = hex::encode(expected_digest);
    if values.get("batch_digest").copied() != Some(expected_digest_hex.as_str()) {
        return Err(invalid());
    }
    let size = strict_u32(values.get("batch_size").copied().ok_or_else(invalid)?)? as usize;
    let proposal_ids = strict_csv_u32(values.get("proposal_ids").copied().ok_or_else(invalid)?)?;
    let vc_positions = strict_csv_u64(
        values
            .get("vote_commitment_leaf_indices")
            .copied()
            .ok_or_else(invalid)?,
    )?;
    let nullifiers = values
        .get("van_nullifiers")
        .copied()
        .ok_or_else(invalid)?
        .split(',')
        .collect::<Vec<_>>();
    let messages = canonical_messages(canonical)?;
    let expected_nullifiers = messages
        .iter()
        .map(|message| hex::encode(&message.van_nullifier))
        .collect::<Vec<_>>();
    if size != canonical.proposal_ids.len()
        || proposal_ids != canonical.proposal_ids
        || vc_positions.len() != size
        || nullifiers != expected_nullifiers
    {
        return Err(invalid());
    }
    Ok(ParsedConfirmation {
        van_position: strict_u32(
            values
                .get("final_van_leaf_index")
                .copied()
                .ok_or_else(invalid)?,
        )?,
        vc_positions,
    })
}

fn canonical_messages(
    canonical: &CanonicalVoteSubmission,
) -> Result<Vec<MsgCastVote>, VotingError> {
    if canonical.batch {
        let wire: VoteCommitmentBatchWire =
            serde_json::from_slice(&canonical.json).map_err(|_| invalid())?;
        wire.votes.iter().map(message_from_wire).collect()
    } else {
        let wire: VoteCommitmentWire =
            serde_json::from_slice(&canonical.json).map_err(|_| invalid())?;
        Ok(vec![message_from_wire(&wire)?])
    }
}

fn canonical_decimal(raw: &str) -> bool {
    !raw.is_empty()
        && raw.bytes().all(|byte| byte.is_ascii_digit())
        && (raw.len() == 1 || !raw.starts_with('0'))
}
fn strict_u32(raw: &str) -> Result<u32, VotingError> {
    if !canonical_decimal(raw) {
        return Err(invalid());
    }
    raw.parse().map_err(|_| invalid())
}
fn strict_u64(raw: &str) -> Result<u64, VotingError> {
    if !canonical_decimal(raw) {
        return Err(invalid());
    }
    raw.parse().map_err(|_| invalid())
}
fn strict_csv_u32(raw: &str) -> Result<Vec<u32>, VotingError> {
    if raw.is_empty() {
        return Err(invalid());
    }
    raw.split(',').map(strict_u32).collect()
}
fn strict_csv_u64(raw: &str) -> Result<Vec<u64>, VotingError> {
    if raw.is_empty() {
        return Err(invalid());
    }
    raw.split(',').map(strict_u64).collect()
}

fn validate_confirmation_positions(
    conn: &rusqlite::Connection,
    wallet_id: &str,
    round_id: &str,
    bundle_index: u32,
    parsed: &ParsedConfirmation,
) -> Result<(), VotingError> {
    let tree_limit = 1u64 << vote_commitment_tree::TREE_DEPTH;
    if u64::from(parsed.van_position) >= tree_limit
        || parsed.vc_positions.is_empty()
        || parsed.vc_positions.iter().any(|position| {
            *position <= u64::from(parsed.van_position)
                || *position >= tree_limit
                || *position > i64::MAX as u64
        })
        || parsed
            .vc_positions
            .windows(2)
            .any(|positions| positions[0] >= positions[1])
    {
        return Err(invalid());
    }
    // A new VAN must follow every persisted tree position, not merely the
    // current VAN pointer, so a later confirmation cannot overlap history.
    let frontier: Option<u64> = conn
        .query_row(
            "SELECT MAX(vc_tree_position) FROM votes
             WHERE round_id=?1 AND wallet_id=?2 AND bundle_index=?3",
            params![round_id, wallet_id, bundle_index],
            |row| row.get(0),
        )
        .map_err(|_| invalid())?;
    if frontier.is_some_and(|position| u64::from(parsed.van_position) <= position) {
        return Err(invalid());
    }
    Ok(())
}

fn load_attempt_with_conn(
    conn: &rusqlite::Connection,
    wallet_id: &str,
    round_id: &str,
    bundle_index: u32,
    anchor_proposal_id: u32,
) -> Result<Option<VoteSubmissionAttempt>, VotingError> {
    let row: Option<(
        Vec<u8>,
        String,
        String,
        Option<Vec<u8>>,
        String,
        Option<String>,
        Option<i64>,
        Option<String>,
    )> = conn
        .query_row(
            "SELECT canonical_json,tx_hash,proposal_ids_json,batch_digest,outcome,
                    confirmation_tx_hash,confirmation_van_position,confirmation_vc_positions_json
             FROM vote_attempts
             WHERE round_id=?1 AND wallet_id=?2 AND bundle_index=?3 AND anchor_proposal_id=?4",
            params![round_id, wallet_id, bundle_index, anchor_proposal_id],
            |row| {
                Ok((
                    row.get(0)?,
                    row.get(1)?,
                    row.get(2)?,
                    row.get(3)?,
                    row.get(4)?,
                    row.get(5)?,
                    row.get(6)?,
                    row.get(7)?,
                ))
            },
        )
        .optional()
        .map_err(|_| invalid())?;
    row.map(
        |(
            json,
            tx_hash,
            proposal_ids_json,
            batch_digest,
            outcome,
            confirmation_tx_hash,
            confirmation_van_position,
            confirmation_vc_positions_json,
        )| {
            let proposal_ids: Vec<u32> =
                serde_json::from_str(&proposal_ids_json).map_err(|_| invalid())?;
            let batch_digest = batch_digest
                .map(|digest| digest.try_into().map_err(|_| invalid()))
                .transpose()?;
            let canonical = CanonicalVoteSubmission::parse(json, proposal_ids, batch_digest)?;
            if canonical.tx_hash != tx_hash || canonical.anchor_proposal_id != anchor_proposal_id {
                return Err(invalid());
            }
            Ok(VoteSubmissionAttempt {
                canonical,
                outcome: VoteSubmissionOutcome::parse(&outcome)?,
                confirmation_tx_hash,
                confirmation_van_position: confirmation_van_position
                    .map(|position| u32::try_from(position).map_err(|_| invalid()))
                    .transpose()?,
                confirmation_vc_positions: confirmation_vc_positions_json
                    .map(|positions| serde_json::from_str(&positions).map_err(|_| invalid()))
                    .transpose()?,
            })
        },
    )
    .transpose()
}

fn validate_attempt_vote_hashes(
    conn: &rusqlite::Connection,
    wallet_id: &str,
    round_id: &str,
    bundle_index: u32,
    attempt: &VoteSubmissionAttempt,
) -> Result<(), VotingError> {
    for proposal_id in &attempt.canonical.proposal_ids {
        let state =
            queries::load_vote_row_state(conn, round_id, wallet_id, bundle_index, *proposal_id)?
                .ok_or_else(invalid)?;
        match attempt.outcome {
            VoteSubmissionOutcome::Prepared if state.tx_hash.is_none() => {}
            VoteSubmissionOutcome::Prepared => return Err(invalid()),
            _ if state.tx_hash.as_deref() == Some(attempt.canonical.tx_hash.as_str()) => {}
            _ => return Err(invalid()),
        }
    }
    Ok(())
}
