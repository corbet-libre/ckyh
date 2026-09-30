# cpky

**Passkey authentication factor for cvld.**

`cpky` implements the server half of WebAuthn for `cvld`, using `webauthn-rs`.
It registers and verifies passkeys, requires user verification, detects signature
counter regression, and revokes credentials. It does not run in the browser.

Storage sits behind `CredentialStore`. `LibsqlStore` implements it through `crlt`
using a fixed community handle and indexed, transactional libSQL queries. Tests
also retain the indexed in-memory implementation.
The implemented API and integration obligations are in [docs/CONTRACT.md](docs/CONTRACT.md).

## API

- `Passkeys::new(store, community, rp_id, origins)` configures an isolated scope.
- `start_registration(member)` / `finish_registration(state, response, month)`
  register a caller-authorized, community-local UUID user handle.
- `start_authentication(member)` / `finish_authentication(state, response)`
  return an opaque `Authentication` with community, member and exact credential-ID accessors.
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
| `crlt` (GitHub main revision `6b94dac`) | Community-scoped libSQL handles, immediate transactions, pooling, deadlines, migrations and mandatory index-plan checks. Pinned to the reviewed, CI-green revision. |
| `tokio` | Bridge the existing synchronous storage trait to crlt using a caller-owned multithreaded runtime. |
| `tracing` | A scoped empty dispatcher prevents upstream credential/request traces. |
| `webauthn-authenticator-rs` 0.5.5 (tests) | Software authenticator fixtures that generate real keys, attestations and signed assertions. MPL-2.0. |
| `openssl` (tests) | Sign unusual assertion fixtures (zero counters, backup flags) using the software authenticator's test keys. |
| `serde_json`, `tracing-subscriber` (tests) | Persistence/privacy assertions and capture of attempted tracing events. |
| `tempfile` (tests) | Disposable local libSQL databases and reopen tests. |

Storage candidates checked on crates.io and GitHub on 2026-09-30:

| Candidate | Decision |
| --- | --- |
| [crlt](https://github.com/corbet-foss/crlt/tree/6b94dacd7fa04aa8847c62c6471a1fc5c0f6c9dc) (LGPL-3.0-only WITH linking exception) | Selected: its main branch now exposes all required operations; keeps database policy in the shared facade. |
| [official libsql 0.9.30](https://crates.io/crates/libsql/0.9.30) (MIT) | Used transitively through crlt; a direct adapter would duplicate scoping, pooling and migration policy. No direct libsql dependency. |

The `danger-credential-internals` feature is used only to read verified credentials
and reconstruct their minimal stored form. It does not weaken user verification.
State serialization and user-presence-only features remain disabled. `webauthn-rs`
uses OpenSSL natively, so consumers need its platform build/runtime prerequisites.
The AAGUID parser is an upstream internal API; dependency updates must pass the
round-trip tests. Applications supply a curated name catalogue, for example names
from [passkey-authenticator-aaguids](https://github.com/passkeydeveloper/passkey-authenticator-aaguids).
cpky performs no catalogue downloads. Storage connects only to the database
configured by the service through crlt.

## libSQL storage

The service opens one `crlt::Db` per community and supplies its complete migration
history, adding `LIBSQL_SCHEMA` at the next migration version. The global wallet
uses a separate database. Migrations also run when reopening a database so crlt
can validate its history and recognize the tables.

```rust,no_run
use cpky::{LIBSQL_SCHEMA, LibsqlStore, Passkeys, Url};
use crlt::{Config, Db, Migration};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
let db = runtime.block_on(Db::open(Config::new("file:///data/community.db", "")))?;
runtime.block_on(db.migrate(&[Migration::new(1, "cpky_passkeys", LIBSQL_SCHEMA)]))?;
let store = LibsqlStore::new(&db, "community", runtime.handle().clone())?;
let passkeys = Passkeys::new(
    store, "community", "members.example.com",
    &[Url::parse("https://members.example.com")?],
)?;
# let _ = passkeys;
# Ok(())
# }
```

Keep the runtime alive. This adapter preserves the synchronous `CredentialStore`
API: call from synchronous threads, or use `tokio::task::spawn_blocking` from async
code. Calling directly inside an async task panics in Tokio's blocking bridge.
Current-thread runtime handles are rejected. Closures run on the calling thread
exactly once; their results are returned only after commit. Transactions are
never automatically retried. Database errors are reduced to static `cpky::Error`
categories with no SQL, row contents or upstream source.

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
software fixtures. Local libSQL tests additionally cover reopening, migrations,
community/member/database isolation, uniqueness and tombstones, corrupt rows,
closure rollback and panic, real deferred-constraint commit failure, timeouts,
concurrent writers through independent pools, and exact query plans.

The optional Turso test returns without connecting unless both `TURSO_URL` and
`TURSO_TOKEN` are nonempty. Run it only against a disposable test database on an
approved runner: it applies the cpky schema and writes fixture credentials.
Credentials are never stored in the repository or configured in public CI.

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

For public login endpoints use `start_authentication_for(member, credential_id)`.
It echoes the wallet's credential ID in uniform browser options without revealing
whether the account or key exists. The older account-list API is privileged.
