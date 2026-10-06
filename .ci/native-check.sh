#!/usr/bin/env bash
set -euo pipefail
: "${CI:?CI only}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-2}"
export CARGO_HTTP_USER_AGENT=keyhole-ci
rustc --version
cargo --version
sha256sum Cargo.lock
python3 .github/check-first-party.py --archive
cargo fmt --all --check
node --test .github/test-auto-merge.mjs
: "${CARGO_TARGET_DIR:?}"
: "${CI_COMMIT_SHA:?}"
receipt="$CARGO_TARGET_DIR/ci-receipts/$CI_COMMIT_SHA"
mkdir -p "$receipt"
cargo metadata --locked --format-version 1 > "$receipt/dependency-metadata.json"
cargo clippy --locked --all-targets -- -D warnings
export CKYH_LINEAGE_FIXTURE_DIR="$receipt/lineage"
cargo test --locked --no-fail-fast
test -s "$CKYH_LINEAGE_FIXTURE_DIR/es256.json"
test -s "$CKYH_LINEAGE_FIXTURE_DIR/rs256.json"
sha256sum "$CKYH_LINEAGE_FIXTURE_DIR/es256.json" "$CKYH_LINEAGE_FIXTURE_DIR/rs256.json"
