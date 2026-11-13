//! The public browser surface keeps SQLite and JavaScript on its owning thread.
use super::wallet::WebWallet;
use crate::voting::{
    config,
    persistence::Persistence,
    session::{VotingSessionInner, now_secs},
    types::{VotingApiError, VotingErrorCode},
};
use std::rc::Rc;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(typescript_custom_section)]
const VOTING_TYPES: &str = r#"
export type VotingErrorCode = "CONFIG_FETCH_FAILED" | "CONFIG_UNTRUSTED" | "ROUND_UNAUTHENTICATED" | "ROUND_EXPIRED" | "NETWORK_MISMATCH" | "WALLET_NOT_SYNCED" | "NOT_ELIGIBLE" | "PIR_SNAPSHOT_MISMATCH" | "PROOF_FAILED" | "PERSISTENCE_FAILED" | "SUBMISSION_REJECTED" | "SUBMISSION_UNKNOWN" | "OPERATION_IN_PROGRESS" | "RECOVERY_CONFLICT";
export interface VotingApiError extends Error { name: VotingErrorCode; }
export type VotingRoundPhase = "uninitialized" | "config_authenticated" | "eligible" | "round_prepared" | "delegation_pending" | "delegation_confirmed" | "vote_pending" | "vote_confirmed" | "shares_confirmed" | "not_eligible" | "round_rejected" | "expired";
export interface VotingRoundSummary { roundId: string; name: string; snapshotHeight: number; startsAt: string; endsAt: string; proposalCount: number; }
export interface VotingRejectedRound { roundId: string; code: VotingErrorCode; message: string; }
export interface VotingProposal { proposalId: number; title: string; options: string[]; }
export interface VotingDiscovery { accepted: VotingRoundSummary[]; rejected: VotingRejectedRound[]; configFingerprint: string; }
export type VotingEligibilityReason = "INSUFFICIENT_SNAPSHOT_VALUE" | "INSUFFICIENT_VOTING_POWER";
export interface VotingEligibility { roundId: string; eligible: boolean; snapshotVotingValueZats: string; minimumRequiredZats: string; reasonCode: VotingEligibilityReason | null; selectedValueZats: string; votingPower: string; selectedNoteCount: number; bundleCount: number; trimmedValueZats: string; }
export interface PreparedVotingRound { roundId: string; bundleCount: number; selectedNoteCount: number; votingPower: string; state: VotingRoundPhase; }
export type BallotDecision = { kind: "choice"; proposalId: number; option: number } | { kind: "skip"; proposalId: number };
export interface VotingActionResult { roundId: string; phase: VotingRoundPhase; completedBundles: number; totalBundles: number; nextAction: string; }
export interface VotingRoundStatus extends VotingActionResult { confirmedVotes: number; totalVotes: number; confirmedHelpers: number; requiredHelpers: number; }
export type VotingCheckpoint = (bytes: Uint8Array, revision: bigint) => Promise<void>;
"#;

#[cfg(feature = "voting-test-fixtures")]
#[wasm_bindgen(js_name = votingTestOwnedProof)]
pub async fn voting_test_owned_proof() -> bool {
    #[cfg(feature = "wasm-parallel")]
    let executor = crate::voting::proof_executor::RayonProofExecutor;
    #[cfg(not(feature = "wasm-parallel"))]
    let executor = zcash_voting::proof_executor::SequentialProofExecutor;
    zcash_voting::browser_proof_fixture::prove_owned_fixture(executor).await
}

#[wasm_bindgen]
pub struct WebVotingSession {
    pub(crate) inner: Rc<VotingSessionInner>,
}

fn value(value: &impl serde::Serialize) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(|_| VotingApiError::new(VotingErrorCode::RecoveryConflict).into())
}

#[wasm_bindgen]
impl WebVotingSession {
    #[wasm_bindgen(constructor)]
    pub fn new(
        wallet: &WebWallet,
        account_id: u32,
        voting_db_bytes: Option<Box<[u8]>>,
        #[wasm_bindgen(unchecked_param_type = "VotingCheckpoint")] persist_checkpoint: js_sys::Function,
    ) -> Result<WebVotingSession, JsValue> {
        Ok(Self {
            inner: Rc::new(VotingSessionInner::open(
                wallet.shared_inner(),
                account_id.into(),
                voting_db_bytes.as_deref(),
                Persistence::new(persist_checkpoint),
            )?),
        })
    }

    #[wasm_bindgen(getter, js_name = storageKey)]
    pub fn storage_key(&self) -> String {
        self.inner.storage_key()
    }

    #[wasm_bindgen(js_name = exportState)]
    pub fn export_state(&self) -> Result<Box<[u8]>, JsValue> {
        self.inner.export_state().map(Vec::into_boxed_slice).map_err(Into::into)
    }

    #[wasm_bindgen(js_name = discoverRounds)]
    #[wasm_bindgen(unchecked_return_type = "VotingDiscovery")]
    pub async fn discover_rounds(&self) -> Result<JsValue, JsValue> {
        value(
            &self
                .inner
                .discover_with(config::discover_rounds(&self.inner.transport, self.inner.network))
                .await?,
        )
    }

    #[wasm_bindgen(js_name = checkEligibility)]
    #[wasm_bindgen(unchecked_return_type = "VotingEligibility")]
    pub async fn check_eligibility(&self, round_id: String) -> Result<JsValue, JsValue> {
        value(&self.inner.check_eligibility_at(&round_id, now_secs).await?)
    }

    #[wasm_bindgen(js_name = roundStatus)]
    #[wasm_bindgen(unchecked_return_type = "VotingRoundStatus")]
    pub async fn round_status(&self, round_id: String) -> Result<JsValue, JsValue> {
        value(&self.inner.round_status_at(&round_id, now_secs()?)?)
    }

    #[wasm_bindgen(js_name = prepareRound)]
    #[wasm_bindgen(unchecked_return_type = "PreparedVotingRound")]
    pub async fn prepare_round(&self, round_id: String) -> Result<JsValue, JsValue> {
        value(&self.inner.prepare_round(&round_id).await?)
    }

    #[wasm_bindgen(js_name = submitDelegation)]
    #[wasm_bindgen(unchecked_return_type = "VotingActionResult")]
    pub async fn submit_delegation(
        &self,
        round_id: String,
        usk: super::keys::UnifiedSpendingKey,
        seed_fingerprint: super::keys::SeedFingerprint,
    ) -> Result<JsValue, JsValue> {
        let (usk, network, index, key_fingerprint) = usk.into_voting_parts();
        let fingerprint: zip32::fingerprint::SeedFingerprint = seed_fingerprint.into();
        if crate::voting::network::VotingNetwork::for_wallet(network) != self.inner.network {
            return Err(VotingApiError::new(VotingErrorCode::RecoveryConflict).into());
        }
        let account = self.inner.validate_delegation_key(&usk, fingerprint)?;
        if u32::from(index) != account.account_index || key_fingerprint != Some(fingerprint) {
            return Err(VotingApiError::new(VotingErrorCode::RecoveryConflict).into());
        }
        value(&self.inner.submit_delegation(&round_id, usk, fingerprint).await?)
    }

    #[wasm_bindgen(js_name = submitBallot)]
    #[wasm_bindgen(unchecked_return_type = "VotingActionResult")]
    pub async fn submit_ballot(
        &self,
        round_id: String,
        #[wasm_bindgen(unchecked_param_type = "BallotDecision[]")] decisions: JsValue,
    ) -> Result<JsValue, JsValue> {
        let decisions: Vec<crate::voting::types::BallotDecision> =
            serde_wasm_bindgen::from_value(decisions).map_err(|_| VotingApiError::new(VotingErrorCode::RecoveryConflict))?;
        value(&self.inner.submit_ballot(&round_id, Some(decisions)).await?)
    }

    #[wasm_bindgen(js_name = resumeRound)]
    #[wasm_bindgen(unchecked_return_type = "VotingActionResult")]
    pub async fn resume_round(&self, round_id: String) -> Result<JsValue, JsValue> {
        value(&self.inner.submit_ballot(&round_id, None).await?)
    }

    #[wasm_bindgen(js_name = roundProposals, unchecked_return_type = "VotingProposal[]")]
    pub async fn round_proposals(&self, round_id: String) -> Result<JsValue, JsValue> {
        value(
            &self
                .inner
                .round_proposals_with(&round_id, config::discover_rounds(&self.inner.transport, self.inner.network), now_secs)
                .await?,
        )
    }

    /// The host obtains explicit user confirmation naming this round before calling.
    #[wasm_bindgen(js_name = clearRound)]
    pub async fn clear_round(&self, round_id: String) -> Result<(), JsValue> {
        self.inner
            .clear_round_with(&round_id, || self.inner.persistence.checkpoint(&self.inner.db))
            .await
            .map_err(Into::into)
    }
}
