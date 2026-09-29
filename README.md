# cpky

**Passkey authentication factor for cvld.**

`cpky` implements the server half of WebAuthn for `cvld`, using `webauthn-rs`.
It registers and verifies passkeys, requires user verification, detects signature
counter regression, and revokes credentials. It does not run in the browser.

Storage sits behind `CredentialStore`; tests use an indexed, transactional
in-memory implementation. A production libSQL adapter through `crlt` is deferred.
The implemented API and integration obligations are in [docs/CONTRACT.md](docs/CONTRACT.md).

## API

- `Passkeys::new(store, community, rp_id, origins)` configures an isolated scope.
- `start_registration(member)` / `finish_registration(state, response, month)`
  register a caller-authorized, community-local UUID user handle.
- `start_authentication(member)` / `finish_authentication(state, response)`
  return an opaque `Authentication` with community and member accessors.
- `list(member)` and `revoke(member, credential_id)` manage current credentials.
- `with_authenticator_names(catalogue)` optionally maps AAGUIDs to model/provider
  names. Unknown types remain absent. Names never establish trust.

Send only the challenge response to the browser. Keep its corresponding pending
state in the server session: it is consumed once, bound to its facade instance,
and expires after five minutes. Authentication is account-first; discoverable
usernameless login is not implemented.

Only current verification material, ownership, revocation state, authenticator
type and creation month are stored. No device names, login dates, last-use times,
request logs, attestation chains or raw AAGUIDs are retained. Upstream tracing is
suppressed during verification even when the embedding application has a subscriber.

## Dependency survey

Checked the crates.io registry and upstream repositories on 2026-09-30:

| Candidate | Licence | Decision |
| --- | --- | --- |
| [webauthn-rs 0.5.5](https://crates.io/crates/webauthn-rs/0.5.5) | MPL-2.0 | Selected: maintained Rust server implementation with a UV-required passkey API and signature verification. Latest stable registry release; prereleases excluded. |
| [passkey-rs](https://github.com/1Password/passkey-rs) | MIT / Apache-2.0 | Maintained client and authenticator libraries; does not provide this server facade. |
| [SimpleWebAuthn](https://github.com/MasterKale/SimpleWebAuthn) | MIT | Maintained server implementation, but TypeScript would add another runtime to this Rust library. |

Upstream remains a dependency; no WebAuthn cryptography is copied or implemented
here. GitHub Actions uses current stable Rust for formatting, Clippy and tests.
This is a server library; no device or wasm32 build is required. Dependabot
proposes dependency updates for review and CI validation.

Additional dependencies:

| Dependency | Purpose |
| --- | --- |
| `webauthn-rs-core` 0.5.5 | Reuse upstream credential types and the authenticator-data parser for cosmetic AAGUID lookup. No alternate verifier. |
| `serde`, `serde_cbor_2` | Typed storage serialization and reading the attestation envelope after WebAuthn verification. |
| `tracing` | A scoped empty dispatcher prevents upstream credential/request traces. |
| `webauthn-authenticator-rs` 0.5.5 (tests) | Software authenticator fixtures that generate real keys, attestations and signed assertions. MPL-2.0. |
| `openssl` (tests) | Sign unusual assertion fixtures (zero counters, backup flags) using the software authenticator's test keys. |
| `serde_json`, `tracing-subscriber` (tests) | Persistence/privacy assertions and capture of attempted tracing events. |

The `danger-credential-internals` feature is used only to read verified credentials
and reconstruct their minimal stored form. It does not weaken user verification.
State serialization and user-presence-only features remain disabled. `webauthn-rs`
uses OpenSSL natively, so consumers need its platform build/runtime prerequisites.
The AAGUID parser is an upstream internal API; dependency updates must pass the
round-trip tests. Applications supply a curated name catalogue, for example names
from [passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids).
cpky performs no catalogue downloads or other network requests.

## Verification

[GitHub Actions](https://github.com/corbet-foss/cpky/actions/workflows/ci.yml) runs
`cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings` and
`cargo test --locked` on current stable Rust. Builds run in CI, not on workstations.
The dependency lock is retained as a CI artifact and committed after resolution.

Tests cover real registration/authentication and persistence round trips; required
UV; cloned, equal, zero and overlapping counters; simultaneous updates; revocation
during login; community/member isolation; RP/origin/challenge/signature failures;
single-use state and expiry; metadata minimization; redacted errors/debug output;
tracing suppression; and transactional failure rollback. All authenticators are
software fixtures. No hardware, live identity or network service is used in tests.

## Boundaries

What it does:

- Registers and verifies passkeys and hands `cvld` an opaque authentication result.

What it never does:

- A synced passkey alone never enrols a new device; device addition needs approval from an already active device (no recovery).
- No own WebAuthn cryptography.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).
