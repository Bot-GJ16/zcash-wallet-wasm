# Migrating to zcash_voting v5

This guide covers **v3.x → v5.0.x** and **v4.0.x → v5.0.x**, using
`v5.0.1` as the destination. Read it alongside the
[v5 release notes](../CHANGELOG.md#v501).

Do not target v5.0.0 for a new integration. It rejects an authenticated
vote-chain configuration containing more than eight endpoints before making a
network request. V5.0.1 accepts the complete configuration, up to 100
endpoints, while retaining the separate limit of eight submission attempts.

The main change is ownership of the voting workflow. The wallet supplies user
intent, signing, authenticated configuration, transport, and app lifecycle
signals. The SDK now drives proofs, chain submission and recovery, initial
helper delivery, and background confirmation. Replacing a few renamed methods
while retaining the old host polling loop is not a complete migration.

## Choose your starting point

| Starting release | Changes already present | What to adapt for v5 |
| --- | --- | --- |
| v3.0.x | The original host-driven delegation, vote submission, confirmation, and helper flow; proposal IDs 1–15. | Apply the earlier integration changes below and the full v5 workflow migration, including backend selection, Rust 1.91, and the 50-proposal circuit change. |
| v3.1.x | Default Zakura/explicit LRZ, Rust 1.91, persisted bundle policy, PIR cache, SDK helper plans and confirmation, atomic vote construction, and in-place launched-database upgrades. Proposal IDs remain 1–15. | Adopt the v5 drivers, chain lifecycle, confirmed-vote helper API, bindings, and 50-proposal circuit stack. Do not rebuild functionality already supplied by v3.1. |
| v4.0.0-rc.0 | The v3.0 API plus the 50-proposal circuit change and SQLite immediate-transaction fix. | Apply the earlier integration changes and full v5 workflow migration. |
| v4.0.0-rc.1 | The v4 rc.0 changes, updated LRZ dependencies, explicit `lrz` feature, and Rust 1.91. | Retain LRZ explicitly if that is your wallet backend; apply the earlier integration changes and full v5 workflow migration. |

The v4 maintenance branch was cut from v3.0, not v3.1. V5 incorporates its
50-proposal and SQLite fixes, but v4's larger version number does not mean it
contains v3.1's wallet integration APIs. At this guide's baseline, the v4 line
has only `v4.0.0-rc.0` and `v4.0.0-rc.1` releases.

### Additional changes for v3.0.x and v4.0.x

- Use the round's persisted `BundlePolicy` and policy-aware note-selection
  APIs. The default trims low-value trailing bundles, bounded by the smaller
  of 1% of selected note value and 1,000 ZEC. Use `BundlePolicy::default().with_max_privacy_bundles(None)`
  to opt out for new rounds; read `VotingDb::effective_bundle_policy` for
  existing rounds. Use `bundle_notes_for_index_for_round` rather than the
  removed `bundle_notes_for_index`. Display the flat
  `privacy_trim_dropped_bundles`, `privacy_trim_dropped_notes`, and
  `privacy_trim_dropped_value_zatoshi` fields from `BundleLayout`; those totals
  no longer live on `SignedDelegationBundle`. Replace
  `VotingNoteSelectionResultView::from_selected` with
  `from_selected_for_round`, and handle the `Result` returned by
  `BundlePolicy::with_privacy_drop_bps`.
- Keep the app-owned voting hotkey secret in secure storage. If reproducible
  bundle reconstruction is required, use `recoverable_bundle_policy_v1()` and
  restore the same secret and note inputs. This is not permission to delete
  an existing sidecar: a saved delegation may depend on its original randomness,
  signing context, and delivery history. Public-target custody delegation
  still needs its persisted recovery material.
- Own the lightwalletd channel in the host. Replace URL-taking helpers that
  opened their own connection with the `*_on` channel APIs, such as
  `lwd::anchor_tree_state_with_retry_on`. Pass the resulting anchor tree state
  to the delegation pipeline. Use `setup_bundles` to persist bundle selection;
  an eligibility check alone does not create it.
- Delegate helper payload construction, placement, entropy, journaling, and
  confirmation to the SDK. Supply the complete authenticated proposal roster
  and current helper fleet. Invalid helper URLs now fail validation. Confirmation
  requires two distinct helpers when at least two are configured, or the sole
  helper for a one-helper fleet.
- Static config v2 supports ordered dynamic-config mirrors. Resolve those
  through the config APIs instead of assuming one URL; v1 remains supported.
  Preserve authenticated round parameters and negotiated PIR geometry.
  Round-independent `precompute_pir_proofs` is available for optional cache
  warmup; it does not replace bundle setup.

## Build and chain prerequisites

Use Rust **1.91 or newer**. Choose exactly one backend consistently across the
wallet and voting dependencies. The v5 default is Zakura:

```toml
[dependencies]
zcash_voting = "5.0"
```

For an upstream librustzcash wallet, select LRZ explicitly:

```toml
[dependencies]
zcash_voting = { version = "5.0", default-features = false, features = ["lrz"] }
```

These are alternative configurations. Cargo features are additive: enabling
both `zakura` and `lrz`, or disabling defaults without choosing either, fails
to compile. Do not restore the old `upstream` feature name from early v3.1
prereleases. PIR and tree sync are always available; they are not optional
network feature flags. Use `zcash_voting::backend` re-exports where appropriate
so notes, keys, and PCZT types come from the selected crypto family.

V5.0.x pins `voting-crypto-deps 0.2.3`, `voting-circuits 0.12.1`,
`imt-tree 0.5.3`, `pir-types 0.6.3`, `pir-client 0.7.3`,
`vote-commitment-tree 0.6.1`, `vote-commitment-tree-client 0.8.1`, and
`zakura-wallet-lib 0.1.0-rc5`. Align any direct dependencies that exchange
Rust types with the SDK; update the application lockfile as part of the upgrade.
The [workspace manifest](../Cargo.toml) and
[crate manifest](../zcash_voting/Cargo.toml) are the source of truth.

Before enabling v5 in a wallet, verify the target chain supports:

- Proposal IDs **1–50** and the matching circuit/verifying keys; each vote
  still contains 16 encrypted shares. V3's 15-proposal circuit stack is not a
  compatible substitute.
- `delegate-and-cast-vote-batch` for fresh local delegation plus all chosen
  proposals in a bundle, even when only one proposal was chosen.
- `cast-vote-batch` for multiple due proposals on an existing delegation, and
  the existing singleton `cast-vote` and delegation routes for their workflows.

The combined route has no endpoint fallback. Do not treat an HTTP 404/405 as
proof that a mutation was never dispatched, or unlock a ballot and construct a
replacement transaction on that basis. The lifecycle preserves the ambiguity.
Config accepts both `vote_protocol: v0` and `v1`; that compatibility check alone
does not prove the chain serves the required routes. Atomic batches also reveal
that their member proposals were submitted together, while retaining the
individual proofs' privacy for choices and voting material.

## Replace the host workflow

### API replacements

| Old integration or API | V5 integration |
| --- | --- |
| Host loop selecting `session::resume_plan` steps, proving, posting, and polling | Bind a `RoundExecutor` and call `RoundDriver::run`. Read `RoundRunReport` and its `quiescence`; use plan predicates for UI state. |
| `confirmation::confirm_*`, host event parsing, `delegate::record_submission` / `record_van_position`, `vote::record_submission` / `record_batch_submission` / `record_vc_position`, or equivalent `VotingDb` writers | The driver's `ChainSubmissionClient` owns these transitions. The `confirmation` module is private. |
| `vote::submission`, `CommittedVote::submission`, `delegate::submission` | The chain lifecycle constructs requests from persisted material. `PreparedDelegationBundle::submission` and `signed_bundle` remain for capability export. |
| `VotingDb::build_and_prove_delegation` | `DelegationPipeline`, `delegate::ensure_proof`, or `PreparedDelegationBundle::ensure_proof`; concurrent callers share durable proof production. |
| Host delegation stage orchestration | Bind a `DelegationPipeline` once and supply it through `DelegationStepInputs`. Software signing uses `delegation_pipeline::DelegationSigner::Software` with a `SpendAuthSigner`; Keystone uses `DelegationSigner::Keystone`. |
| `CommittedVote::submit_prepared_shares` (v3.1), or host share JSON/POST loops (v3.0/v4) | Let the round driver deliver shares. For manual delivery, recover the vote, obtain `ConfirmedVote` with `confirmed()`, then call `submit_prepared_shares`. |
| Host timer around `track_pending_shares`; public `next_tracking_delay_for_round` / readiness-delay helpers | `ShareTrackingDriver::run` owns cadence, retries, and the vote-end boundary. Per-share readiness remains observable through tracking flags. |
| `share::pending_rounds` | `share::pending_rounds_for_accounts(&db, &wallet_ids)`, which returns wallet identity with each pending round. |
| `recovery::clear` / `VotingDb::clear_recovery_state` | No equivalent selective erasure. Normal session reset preserves durable submission evidence; explicit destructive deletion is a separate user decision. |

The development-only `RoundExecutor::advance_next`, `advance_step`,
`VoteRecoveryExecutor::advance`, and `ChainSubmissionClient::advance_until_terminal`
are also absent from v5.0.0. If an integration followed interim main builds,
replace these with `RoundDriver::run`; they are not alternative v5 entry points.
Likewise, an interim `delegate::DelegationSigner` is not the pipeline signer
above: `AdvanceDelegation` now carries `spend_auth_signature`.

For a specialized integration using the chain client directly, plain local
`advance_delegation`, `advance_vote`, and `advance_vote_batch` calls are
status-only. Use their `*_with_recovery` variants with
`ChainRecoveryMode::ExactTree` when exact-tree recovery is needed. Imported
delegation advancement is always poll-only. `RoundDriver` already selects the
recovery path for resumed work; do not add a second retry loop around it.

### Setup, ballot, and signing

1. Open the wallet sidecar with a nonempty wallet identity. The
   `VotingDb::open_wallet_sidecar` result is an `Arc<VotingDb>` shared by path;
   `scoped(wallet_id)` returns `Result<VotingDb, VotingError>`. Keep the executor,
   delegation pipeline, and host inputs on the same wallet and sidecar.
2. Create a `DelegationPipeline` with the wallet opener, authenticated round
   and lightwalletd inputs, account, voting hotkey, and bundle policy. Call
   `setup_bundles` to persist the round's selected bundles. Eligibility-only
   calls do not do this. Imported capabilities use their existing bundle setup.
3. Construct a `RoundExecutor`, then call `with_binding` with the canonical
   round ID, network, complete nonempty proposal roster and option counts, and
   the stored hotkey secret when votes may be cast. Bind the tree transport
   explicitly with `with_tree_transport` when it must use the host's route.
4. Persist each voter's decision, including explicit skips. For example, this
   helper records an already validated UI ballot with its authenticated option
   counts:

```rust
use zcash_voting::{round::VotingDb, session::Decision, Network, VotingError};

fn save_ballot(
    db: &VotingDb,
    round_id: &str,
    network: Network,
    decisions: &[(u32, Decision, u32)], // proposal ID, decision, option count
) -> Result<(), VotingError> {
    db.set_ballot_intents(round_id, network, decisions)
}
```

5. Supply a `RoundHostSource` with current time, authenticated ceremony/vote-end
   timing, the complete helper fleet, vote-tree endpoints, chain policy, proof
   concurrency, and delegation inputs. Its `host_context()` is read once per
   dispatch; refresh time and service configuration there rather than freezing
   them for a run that may take minutes.
6. Software wallets implement `SpendAuthSigner` and keep root wallet seed
   material outside the SDK. For Keystone, collect and persist signatures for
   every bundle named by `NeedsDelegationSignatures`, then run again with
   `KeystoneSignatureSource::Stored`. Keep one signer mode for the round.
   Requests can be prepared after background proof warmup or restart because
   the finalized signing PCZT is persisted. Imported delegations do not require
   the funds controller's signing key.

For fresh local work, the driver can prepare delegation proofs while the ballot
is open, then sign and submit delegation and choices in one combined envelope
once the ballot is terminal. Existing standalone and imported delegations keep
their recovery path. The fresh combined path needs no initial vote-tree sync.
See the [delegation wallet example](../wallet-example/src/example_delegation.rs),
[signing transaction guide](delegation-signing-transaction.md), and
[capability handoff guide](exporting-to-external-software.md).

### Run and interpret the report

After the executor is bound and the host source is configured, the execution
boundary is:

```rust
use zcash_voting::{
    ChainSubmissionControl, ChainTransport, NoopRoundDriveReporter,
    RoundDriver, RoundExecutor, RoundHostSource, RoundRunReport,
};

async fn drive_round<T: ChainTransport>(
    executor: &RoundExecutor<T>,
    host: &dyn RoundHostSource,
    control: &ChainSubmissionControl,
) -> RoundRunReport {
    RoundDriver::new(executor)
        .run(host, control, &NoopRoundDriveReporter)
        .await
}
```

`run` returns a report, not a `Result`. Always inspect `failures` and durable
`chain_outcomes` / `share_deliveries`, as well as `quiescence`: one bundle can
fail after another has succeeded. Signed bundles in `delegations` are not proof
that their transactions were submitted or confirmed. The final plan describes
the persisted state after the run.

| Stop reason | Host action |
| --- | --- |
| `NeedsBundleSetup` | Persist bundle setup, then run again. |
| `NeedsBallot` | Collect missing decisions or resolve clearable stale intents; never silently turn missing choices into skips. |
| `NeedsDelegationSignatures` | Collect the listed bundles' signatures, then run again. |
| `BackgroundShareWorkOnly` | Continue helper tracking; foreground completion does not mean every share is confirmed. |
| `NoWorkLeft` | No planned work remains for this run. Still inspect recorded failures and outcomes. |
| `Cancelled` | Honor the app/account transition; retain the reported durable progress. |
| `ChainRecoveryStalled` | Recovery remains durable; surface the diagnostic and schedule a later run when appropriate. |
| `ChainTerminal` / `PersistedChainTerminal` | Surface the outcome and persisted diagnostics. Standalone terminal submissions have no automatic retry. A definitely rejected combined batch may have been retired, allowing a fresh cast on a later run; obey the persisted rejection limit. |
| `Failures` / `PassBudgetExhausted` | Surface failures or exhausted work budget; use the final plan and typed failure information to decide the next action. |

After two consecutive combined-batch rejections against the same delegation
generation, v5 holds the bundle for host intervention. A relevant ballot edit
or setup rebuild clears the streak. If the cause was fixed externally, use
`VotingDb::retry_blocked_combined_cast` for an explicit retry; do not clear it
automatically in a retry loop.

`RoundQuiescence` and report structs are non-exhaustive: downstream matches need
an unknown-case path and must not treat an unfamiliar outcome as success.

Default execution overlaps five independent bundles. `FailureIsolation::StopRound`
is serial. Completion events may arrive out of dispatch order. Use
`RoundDrivePolicy::progress_baseline = ProgressBaseline::SelectedChoices` if
UI progress counts all selected votes across restarts; the default `Run` counts
work relative to this run. These are submission-progress totals, not counts of
confirmed helper shares.

On account/session switch, cancel the old `ChainSubmissionControl` or advance
its operation epoch. Build the replacement executor for its own wallet scope;
changing the host database handle's wallet ID does not retarget an executor.

### Continue helper tracking

The default planner asks the foreground driver to confirm only the designated
immediate share. A successful chain confirmation and helper acceptance are
separate from helper confirmation quorum. Use `RoundPlan::has_unconfirmed_shares`
and `share::pending_rounds_for_accounts` to restore background work, including
after restart. Run the tracker in a host background task:

```rust
use zcash_voting::{
    round::VotingDb, ChainSubmissionControl, HelperClient,
    NoopShareTrackingReporter, ShareTrackingDriver, ShareTrackingHostSource,
    ShareTrackingRunReport,
};

async fn track_round(
    db: &VotingDb,
    helper: &HelperClient,
    round_id: &str,
    host: &dyn ShareTrackingHostSource,
    control: &ChainSubmissionControl,
) -> ShareTrackingRunReport {
    ShareTrackingDriver::new(db, helper, round_id)
        .run(host, control, &NoopShareTrackingReporter)
        .await
}
```

Supply fresh timing and the complete current helper fleet through
`ShareTrackingHostSource`. Let the driver wait between passes and stop at vote
end; there is no default pass-count cutoff. Handle its stop reason, including
`AlreadyDriving`, cancellation, failures, and vote-end expiry. A live round
admits one tracking run. Poll its future to completion or drop it when done;
leaving a cancelled future retained but unpolled can prevent its replacement
from taking over.

For manual initial delivery, preserve the complete generation-bound plan via
`CommittedVote::prepare_share_delivery`, recover a fresh committed handle after
chain confirmation, and convert it to `ConfirmedVote` before submitting. Supply
the complete current fleet even if the plan was created under an earlier fleet.
Do not replan only missing shares or blindly replay an outcome-unknown POST.
See the [vote wallet example](../wallet-example/src/example_vote.rs) and
[helper submission contract](helper_submission_invariants.md).

## Bindings, transports, and optional diagnostics

- Regenerate Rust/FFI adapters for typed `NextStepView.kind`,
  `RoundPlanView.primary_action`, recovery kinds, and workflow phase fields.
  Unchanged variants retain their serde labels, but submit/poll distinctions
  become `advance_delegation`, `advance_vote`, and `advance_vote_batch`, with
  additional kinds for imported and combined work. Prefer derived plan flags
  over a host string allowlist. Use `NextStep::kind_view()` for the wire kind.
- Widen delegation recovery VAN positions to `u64`. Do not truncate positions
  or infer completion from a nonempty transaction hash: exact-tree confirmation
  can produce a confirmed vote without a hash. Read phase/confirmation APIs.
- Use `VotingError::kind()` and `retryable()` plus structured fields instead of
  parsing display text. Handle `DbBusy`, `PirUnavailable`,
  `InsufficientEligibility`, `NoSpendableNotes`, and `SetupAlreadyPersisted`.
  `VotingErrorView` includes setup-field and bundle attribution where applicable;
  unknown error categories decode as `Other`. `bundle_note_slots` is note
  capacity, not the number of real notes a voter must supply.
- `HyperTransport<R: RouteHttp = DirectRoute>` retains direct constructors.
  For Tor/proxy use `HyperTransport::with_route` and bind routed transports for
  every required service, including PIR and tree sync. A `RouteHttp` executor
  must honor dispatch-hook classification. `RouteRequest::connect_timeout` is
  optional; declare `enforces_connect_timeout` only when actually enforced.
  Fully configured connectors passed to `with_connector` do not gain automatic
  connection deadlines. See [routing contracts](chain_submission_invariants.md).
- Functions formerly taking `&PirClientBlocking` accept `&dyn PirProofSource`;
  existing clients can coerce. `PirFleet` adds ordered failover, with permanent
  layout/config errors kept distinct from retryable network failures.
- Configure `ProvingPolicy` through `configure_proving_runtime` before the first
  proof or cache warmup if the available-parallelism defaults exceed the host's
  memory budget. Worker count and active heavy-job limits are independent;
  each worker has a 64 MiB stack. The policy is fixed for the process.
- Optional `*_with_report` variants add per-call diagnostics without requiring
  their adoption for every workflow. See [observability](observability.md) for
  report handling, bounded collection, and failure diagnostics.

## Existing databases and upgrade boundaries

V3.0 and v4 sidecars use schema 13; v3.1.0 uses schema 17. V5.0.0 upgrades
launched schemas 13 and later incrementally to **schema 24**, preserving
round, delegation, vote, share, and recovery material. Schemas below 13 are
pre-launch and are reset on open. A database newer than 24 is rejected by
v5.0.0. Do not interpret a successful schema migration as a guarantee that any
in-flight workflow can be resumed across the API transition.

The `17 → 18` step creates `chain_submissions` without adopting prior
transaction hashes or confirmation evidence into lifecycle rows. Earlier
launched schemas pass through this step too. Completed legacy rounds remain
displayable, but **upgrading with an in-flight legacy submission is unsupported**.
Finish and confirm legacy submissions using the existing integration before
switching it to v5. Do not depend on v5 resubmission/exact-tree recovery as a
promised migration path for those submissions. See the
[legacy lifecycle boundary](chain_submission_invariants.md#version-18-to-version-19).

Keep the sidecar and securely stored voting hotkey through the upgrade. Normal
session reset preserves proved delegation setup and submission evidence.
`VotingDb::delete_round` refuses broadcast delegation state;
`delete_round_discarding_recovery` explicitly abandons it. Neither deletion nor
manual SQL edits are migration repairs. Older SDKs cannot be assumed to open a
v5-upgraded database, so do not plan a binary-only rollback over that sidecar.

Recognized preview/schema drift is repaired, including missing lifecycle
objects. Repair can discard unrecognized submission-tracking rows while
retaining domain recovery material; it does not reconstruct an arbitrary
preview's lifecycle guarantees. Unknown combined-preview layouts fail without
rewriting stored state. If a legacy bundle lacks its original signing PCZT,
Keystone request creation reports `DelegationPcztUnavailable`; do not
regenerate an already-broadcast setup automatically. Existing software proof
reuse and authoritative submission recovery do not require that PCZT.

Before shipping an upgraded host, exercise a fresh software vote, Keystone
signing across restart, imported capability polling without a signer, SDK-owned
submission recovery after restart, background tracking through vote end, and
an account switch during work. Separately test opening a completed legacy
sidecar and the host's policy for excluding unsupported in-flight upgrades.
These checks validate the application's integration; opening a database alone
does not cover the workflow migration.
