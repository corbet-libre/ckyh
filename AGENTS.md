# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Passkey authentication factor for cvld, a thin wrapper around established WebAuthn libraries.
- Registers and verifies passkeys and hands `cvld` an opaque authentication result.
- The passkey ecosystem is the device. A live, UV-authenticated member session may register another UV-verified passkey for the same membership, without manual approval. No recovery beyond passkeys.
- No own WebAuthn cryptography.
- This crate is LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add implementation code available only under the full GPL or AGPL.
- Tests use fixtures only; no live authenticators.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets` (no warnings),
  `cargo test` — all green before every commit. No local
  builds; use GHA, Crow as fallback.
