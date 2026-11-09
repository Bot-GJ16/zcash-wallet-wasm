# Valar Voting Upstream

- Repository: https://github.com/valargroup/zcash_voting
- Tag: `v5.2.0`
- Commit: `340c34c47c1230fa2cca37ab2f38fd801db32d0a`
- Crate: `zcash_voting` `5.2.0`
- Imported: 2026-10-31
- Wallet integration backend: `lrz`, with `browser`; never `zakura`.

This directory contains the complete workspace from that tag, merged with the
browser and wallet patches and copied without upstream `.git` metadata.
It is ordinary source, not a submodule. Upstream licenses, tests, examples,
documentation, and release tooling are retained.

## Current local compatibility

- The `lrz,browser` build retains the local LRZ graph and the caller-local
  browser transport, SQLite ownership, proof execution, and helper recovery.
- Voting schema v25 merges upstream v18-v24 with the earlier browser v18-v22
  journals. Legacy submission evidence is captured during migration so old
  accepted transactions resume by status lookup without a duplicate POST.
- NU7 Testnet and Mainnet are accepted for Ironwood V3 voting notes at their
  activation heights; TX1 effects v1 remains signed under NU6.3.
- The root wallet supplies the browser session driver, durable checkpoints,
  external signing, and compatibility wrappers for its existing public API.

## Historical import notes

The sections below document the earlier 3.1.0-rc.15 browser fork. Version and
schema numbers there describe that prior import, not the current upstream tag.
References below to testnet-only PIR and a snapshot-derived TX1 branch ID are
historical; the current behavior is described under Current local compatibility.

## Local Compatibility Patches

The browser fork also carries the proposal-capacity portion of upstream
`b5f30c13aff1bc9f57b260f3c6174a799c78add6` (the v4.0.x 1–50 proposal
upgrade). It uses the stable compatible dependency set from upstream v5.0.2:
`voting-circuits` 0.12.1, `voting-crypto-deps` 0.2.3, `imt-tree` 0.5.3,
`pir-types` 0.6.3, and `zakura-wallet-lib` 0.1.0-rc5. It also uses the matching
51-bit proposal-authority mask and accepts vote protocol v1.
These changes are inseparable because the authority mask is part of the VAN
commitment and vote proof circuit.

The root and this workspace patch public LRZ crates to `../librustzcash` so
PCZT, wallet backend, keys, primitives, protocol, and transparent types come
from the same local source. WASM imports those crates directly; native builds
retain the upstream `zakura-wallet-lib` facade with its `lrz` feature.

The browser patch categories are:

- Dependency gating: native Hyper, Rustls, Tonic channels, wallet SQLite,
  and multi-thread Tokio are target-gated. The browser graph uses the pinned
  dependency adapters documented in [browser-deps/README.md](browser-deps/README.md).
- Input-based wallet boundary: native wallet DB convenience entry points are
  gated. Protocol types, note bundling, signing, and witness validation remain
  compiled. The browser input adapter gathers owned wallet notes and witnesses,
  validates snapshot identity, and prepares the existing protocol inputs.
- SQLite serialization: `serialize` is enabled for both SQLite variants.
  Browser connections own byte loading and serialization on the caller thread;
  sensitive voting SQLite bytes are owner-bound and are not exposed through
  public DTOs or separate host storage.
- Fetch transport: native implementations remain target-gated while owned
  transport traits and response parsers remain compiled. The browser adapter
  owns Fetch, abort, timer, reader, and JavaScript promise handles in its
  caller-local task; only owned Rust request and response data cross its Send
  future.
- Async tree sync: the native Hyper convenience method is gated while the
  browser async tree path fetches and validates snapshots before opening the
  wallet, releases SQLite before await, and retains the shared tree,
  validation, and witness core.
- Proof executor: native large-stack threads are retained on native targets;
  WASM proves owned inputs sequentially or on an initialized Rayon pool without
  moving SQLite, JavaScript values, or promises across a worker boundary.
- Helper local futures: native Tokio preflight, submission, and polling entry
  points remain available to native tests. Browser `LocalHelperClient` uses
  caller-local timers, transport, and checkpoint hooks while sharing policy,
  wire parsing, durable storage, recovery, planning, and `session::resume_plan`.

Target gates intentionally preserve native APIs when `browser` is enabled on
a native test host. This permits contract tests alongside upstream regressions.
The `browser` feature rejects the Zakura backend at compile time.

## Updating

The session facade additionally exposes `VotingDb::round_session_json`, a
wallet-scoped read of caller-owned round context. Missing rounds return an
error, while a present round without context returns `None`. Schema and helper
lifecycle semantics are unchanged.
`VotingDb::round_params_with_network` similarly exposes a wallet-scoped read
of the complete stored protocol parameters and network for recovery identity
comparison, with safe errors for missing or unreadable records.

The browser voting database upgrades in place from launched schema v13 through
current schema v22: v18 binds bytes to one wallet owner and network, v19 adds a
wallet/round-scoped voting hotkey, v20 adds the canonical delegation-attempt
journal, v21 adds immutable delegation confirmation evidence, and v22 adds the
canonical vote-attempt journal. Pre-launch databases reset; launched databases
retain recoverable state and reject unknown newer versions. Hotkeys and
canonical recovery material remain only in sensitive owner-bound voting SQLite
bytes; mnemonic, root seed, USK, and private wallet keys are never persisted.

Async PIR cache preparation releases SQLite ownership before fetching or
validating proofs and reuses the existing cache verification path.
The snapshot transport binds the actual PIR handshake to the authenticated
testnet network, Ironwood dataset, layout, IMT root and height. The PIR adapter
uses browser clocks and validates the public encoded response length before
upstream decoding; query encoding and proof verification remain unchanged.
Owned proof inputs may run sequentially or on the host's initialized Rayon pool;
native large-stack proof behavior remains target-gated and unchanged.

Delegation's schema v20 owner/round/bundle-scoped canonical journal and schema
v21 confirmation fields preserve immutable original submission identity and
validated VAN position. Vote schema v22 journals canonical batch bytes,
precomputed transaction identity, ordered membership, outcome, and confirmation
evidence. Recovery polls by the canonical precomputed hash after a possible
dispatch and does not re-prove, re-sign, or blindly re-POST delegation or vote
requests. Canonical signed payloads and proof recovery material live only in
the sensitive voting SQLite export. An owned proof job separates synchronous
database reads and writes from executor work. The explicit delegation planner
covers prepared bundles without creating ballot choices or changing the
ordinary ballot/helper resume planner.

Initial delegation confirmation and restored original/current positions are
bounded by the vote commitment tree's protocol depth even before any vote.
Unsigned PCZT/proof continuation validates the original TX1 effects with the
selected backend's V6 transaction digest, the snapshot-derived branch ID, and
the account's randomized verification key before root-wallet signing. It never
rebuilds an existing PCZT or replaces write-once effects; a completed proof is
reused. Native compatibility event parsing remains unchanged.

The pinned voting library has no vote-chain HTTP client. The local
`delegation_submission` adapter uses the exact REST routes, request/response
contract, protobuf field mapping, 0x02 prefix, and uppercase SHA256 rule from
[`vote-sdk` 990fb1c3](https://github.com/valargroup/vote-sdk/tree/990fb1c3fbdbda9f4f459a5259551580c157c5dd)
(`api/handler.go`, `api/codec.go`, `proto/svote/v1/tx.proto`). These source files
are unchanged through `02c648134d2738fe74c93d2f379c91e572c143fd`.
Vizor `3acdff6c0e65b2aa90ebc3f433168e56686bc358`, using library 3.1.0-rc.15,
independently uses the same delegation and transaction lookup routes.
Valar's existing `DelegationSubmissionWire` serializer remains authoritative
for JSON. The golden fixture is independently encoded by `protoc`, using the
minimal pinned schema and the existing synthetic TX1 vector.

The status response has no transaction hash. Confirmation is bound to the exact
authenticated `/shielded-vote/v1/tx/{precomputed hash}` lookup, the canonical
durable bundle, and the validated round event and VAN position, not a claimed
response-body hash assertion. Possible dispatch is never retried by POST. A
cancelled dispatch-intent checkpoint can conservatively require polling even
when the original POST was never reached; no client can close that crash window
without a stronger server-side idempotency contract.

Browser helper submission uses the local runtime rather than native channels:
the immutable helper plan is checkpointed before delivery work, the shared
policy retains its duplicate-safe reconciliation rules, and Fetch capacity,
timeouts, cancellation, bounded response reads, and post-checkpoint outcome
classification are enforced on the caller thread. Native `HelperClient` keeps
its Send/Sync and paused-time behavior; native contract tests exercise the
local path without compiling browser JavaScript ownership into native helpers.

Check out the proposed upstream commit separately, review protocol/schema and
dependency changes, and merge the documented compatibility patches explicitly.
Update this revision and both Cargo lockfiles only after native LRZ tests,
root voting WASM compilation, and dependency-source checks pass. Do not copy
upstream `.git` metadata or replace the local LRZ graph with registry duplicates.
