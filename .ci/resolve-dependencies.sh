#!/usr/bin/env bash
# Resolve the changed integration graph; this is not a validation verdict.
set -euo pipefail
exec 2>&1
: "${ARTIFACT_ROOT:?Missing retained artifact destination}"
: "${CI_COMMIT_SHA:?Missing verified source revision}"
[[ "$ARTIFACT_ROOT" = /* && "$CI_COMMIT_SHA" =~ ^[0-9a-f]{40}$ ]] || exit 2
cp Cargo.lock dependency-lock-before.lock
cargo update
cargo metadata --locked --format-version 1 > dependency-metadata.json
python3 - <<'PYDIFF'
from pathlib import Path
from difflib import unified_diff
before = Path("dependency-lock-before.lock").read_text().splitlines(keepends=True)
after = Path("Cargo.lock").read_text().splitlines(keepends=True)
Path("dependency-lock.diff").write_text("".join(unified_diff(
    before, after, fromfile="committed/Cargo.lock", tofile="resolved/Cargo.lock")))
PYDIFF
resolved="$ARTIFACT_ROOT/$CI_COMMIT_SHA/resolve-dependencies"
mkdir -p "$resolved"
cp Cargo.lock dependency-metadata.json dependency-lock.diff "$resolved/"
sha256sum Cargo.lock dependency-metadata.json dependency-lock.diff
echo 'Resolved inputs only; review exact upstream revisions, commit the lock and run verify.'
