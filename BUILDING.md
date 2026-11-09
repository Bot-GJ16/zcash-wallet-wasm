# Rebuilding the wallet WASM

The wallet uses the `wasm-parallel,voting` release package built by
`make build-voting-wasm`. `Dockerfile.wasm` builds the same Rust feature set and
exports `pkg/` with its SHA-256 manifest. It does not build the browser extension.

## Requirements

- Docker with Buildx and enough disk and memory for an optimized Rust/WASM build.
  On Apple Silicon, Docker must be able to run Linux amd64 containers.
- A clean checkout of the source commit to reproduce. Use its full commit SHA;
  a tag is not required. Do not use a moving branch name as the build identity.
- Network access on the first build for the pinned tool downloads and locked
  Cargo dependencies. The tool archives are checked against SHA-256 values in
  the Dockerfile.

The container uses Linux amd64, pinned Rust and Node image digests,
`nightly-2026-10-20`, `wasm-pack 0.15.0`, `wasm-bindgen 0.2.122`, and
`wasm-opt 117`. Clang 19 comes from the 2025-12-08 Debian snapshot. Cargo
must accept the checked-in `Cargo.lock` without changes.

## Build

Set `EXPECTED_SHA` to the published full source commit SHA before running this
block in a clean checkout. The checks stop if the checkout differs from that
commit or contains tracked or untracked changes.

```bash
set -euo pipefail
: "${EXPECTED_SHA:?Set EXPECTED_SHA to the published full commit SHA}"
test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"
test -z "$(git status --porcelain)"
test ! -e wasm-dist
mkdir -p wasm-dist
docker buildx build --platform linux/amd64 -f Dockerfile.wasm \
  --target wasm-package --output type=local,dest=./wasm-dist \
  --no-cache --progress plain . 2>&1 | tee wasm-dist/build.log
test -s wasm-dist/SHA256SUMS
docker run --rm --platform linux/amd64 \
  -v "$PWD/wasm-dist:/dist:ro" --entrypoint sh \
  docker.io/library/node:24.18.0-bookworm-slim@sha256:d45d78e7929b46875bbd4e29bea672d5bc48186c6c3588306521c815e78352d6 \
  -c 'cd /dist && sha256sum -c SHA256SUMS'
```

The output is in `wasm-dist/pkg/`, which is ignored by Git; the full build log
is `wasm-dist/build.log`. The container creates and verifies
`wasm-dist/SHA256SUMS` using its own Linux tools, and the last command verifies
the exported files again. The host does not need `sha256sum` or GNU `sort`.
Save the complete source SHA, Dockerfile revision,
Docker image digests, and all output hashes together when reporting a build.
To check byte reproducibility, run the same block from a second independent
clean checkout of the same SHA, then compare the two `SHA256SUMS` files with
`cmp`. Pinned inputs and one successful build alone do not establish byte
reproducibility; a build on macOS must also match the published manifest before
its output is used.

The frontend must take the entire `pkg/` directory from one verified build,
including the matching JS, WASM, type definitions, metadata, and worker helper.
Do not mix files from different builds or rebuild with host-installed Rust tools.
If any hash differs from the release manifest, stop the frontend release and
keep the build log for investigation. Source commit identity alone does not
prove that a deployed extension contains the corresponding binary.
Before distributing the package, collect the third-party notices applicable to
that exact WASM/JavaScript output, including linked Rust dependencies and the
generated worker helper. The root npm dependencies are development tools, not
the browser extension's dependency inventory; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

The `pkg/` output uses shared WebAssembly memory. The browser host must support
`SharedArrayBuffer` and cross-origin isolation, including compatible COOP/COEP
headers for the page, workers, and loaded resources. The separate
`build-voting-proof` target includes test fixtures and is not a release build.
The container checks the shared-memory import contract, required wallet/voting
exports, and the absence of voting test-only exports before copying any output.

The release package can be exercised in Chrome with the repository's isolated
test server and synthetic wallet fixtures:

```sh
npm ci
npx playwright install chromium
cargo test --locked --package zcash-wallet-wasm --features voting \
  --target x86_64-unknown-linux-gnu write_browser_session_fixtures -- --ignored
SESSION_WASM_DIR="$PWD/wasm-dist/pkg" \
SESSION_TEST_PAGE=release-smoke.html \
node tests/browser-session/run.mjs
```

Install the Chromium version required by the checked-in Playwright dependency
before running the browser smoke test. Set `CHROME` to a compatible Chromium
executable when using a system browser.
