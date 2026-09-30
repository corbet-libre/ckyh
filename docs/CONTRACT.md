# cpky contract

cpky is the LGPL server-side passkey authentication factor below cvld. It is not
an admission gate, device registry, account recovery system, session issuer or
authorization policy engine. The same library can serve a community or the global
wallet, with distinct RP configurations, scopes and databases.

## Public API

| Operation | Input | Result |
| --- | --- | --- |
| `Passkeys::new` | Store, community namespace, RP ID, exact allowed HTTPS origins | Configured facade |
| `with_authenticator_names` | Trusted map from AAGUID UUID to model/provider name | Facade with cosmetic catalogue |
| `start_registration` | Community-local member UUID | Browser creation options and private `PendingRegistration` |
| `finish_registration` | Consumed pending state, browser registration response, server-supplied `CreationMonth` | Persisted `StoredPasskey` |
| `start_authentication` | Member UUID | Browser request options and private `PendingAuthentication` |
| `finish_authentication` | Consumed pending state, browser assertion | `Authentication` after a successful storage commit |
| `list` | Member UUID | Current records, including revoked tombstones |
| `revoke` | Member UUID, credential ID | Idempotent revocation, or a static error |

`CreationMonth::new(year, month)` accepts years 1–9999 and months 1–12. Its
deserializer enforces the same range and rejects extra fields. The server supplies
the current month at registration completion. There is no clock or date field for
authentication. `Uuid`, `Url`, credential IDs and browser protocol types are
re-exported from the upstream library; cpky does not define a second wire protocol.

The member UUID is an opaque, community-local WebAuthn user handle, assigned by
the embedding membership service. If its pseudonym has another representation,
that service owns the stable mapping. Do not reuse a global identifier across
communities. The UUID is also the browser account label; human names and handles
are not accepted or stored by cpky.

`Authentication` has private fields, no public constructor, no deserializer and no
credential secrets. Its accessors identify the community, member and exact passkey
credential ID. A cloned receipt retains that same binding.
It is an in-process result, not a signed proof or a bearer token. cvld must still
check admission, gates, device approval and other policy.

## Verification and ceremony lifetime

All cryptographic operations, challenge generation, origin/RP validation,
attestation parsing and signature verification use webauthn-rs 0.5.5 and its core.
Both ceremonies require user verification. UV-less responses are rejected even
if a client changes the browser options. User presence and backup flags are also
checked by upstream. A supplied assertion user handle must match the bound member.

RP ID and origins are supplied per community. Every origin must be HTTPS and
within the RP ID. Credentials in URLs, non-root paths, queries and fragments are
rejected. Origin matching does not implicitly permit subdomains or alternate
ports. Each additional origin is explicitly validated before being allowed. RP IDs
are durable credential bindings: changing an existing scope's RP makes its old
records unavailable. Assign separate RP IDs to separate communities and the wallet;
cpky cannot enforce deployment-wide domain assignments or public-suffix policy.

Registration requests ask for no identifying attestation. Hardware and synced
passkeys are allowed; no attestation trust or hardware-only eligibility is inferred.
Authentication is account-first, using an allow-list. Discoverable login is deferred.

Pending states are held only in server memory, bound to the exact facade instance,
and expire after five minutes using monotonic time. They have no `Clone`, serde or
`Debug` implementation, and completion consumes them on success or failure. The
embedding service must atomically remove state from its session before completion,
bind that session to the initiating client, discard expired entries and impose
limits on pending requests. A restart drops pending ceremonies; start a new one.
Browser timeout hints are not the server's expiry mechanism.

## Counters, concurrency and revocation

After signature verification, authentication runs a storage transaction against
the current credential row. It rechecks scope, owner, RP, revocation, counter and
backup eligibility before updating security state and returning success.

Upstream 0.5.5 permits a change from backup-ineligible to backup-eligible, but
rejects an assertion that simultaneously becomes eligible and already backed up.
cpky preserves that check. Existing credentials making that combined transition
need an upstream compatibility fix; credentials registered as backup-eligible
are unaffected.

If either the stored or received signature counter is nonzero, the received value
must be strictly greater. Equal or lower values, including a return to zero, fail
with `CounterRegression`. Two zero counters are allowed: some synced passkeys do
not support counters, so clone detection is unavailable for those credentials.
Counter regression is a risk signal, not proof of cloning; reordered legitimate
assertions can also trigger it. The row is left unchanged, and no event history or
automatic revocation is written.

The atomic current-row check handles two ceremonies started from the same stale
counter snapshot. A later count cannot be overwritten by an earlier assertion;
two concurrent assertions with the same nonzero count cannot both succeed.

Revocation is a boolean on the existing row, with no timestamp. It serializes
against authentication and is rechecked at completion, including for ceremonies
started before removal. Once a revocation commits, a subsequently committed login
cannot succeed. The receipt carries that exact credential ID; cmbr rechecks the corresponding
current record before every authenticated operation. Revoking that passkey
invalidates its sessions even when another passkey remains active.

Revoked credential IDs remain reserved within the community. Re-registration
cannot clear revocation or assign the same credential ID to another member.
All IDs for the member, including tombstones, are excluded in registration options;
storage uniqueness also covers other members and concurrent registrations.

## Storage boundary

`CredentialStore` is the only persistence interface. It exposes scoped `list`,
atomic unique `insert`, and serializable `update` with a synchronous closure.
This generic trait deliberately requires no database or async runtime. The current
in-memory implementation lives only in tests and uses primary and member indexes.

`LibsqlStore::new(&db, community, runtime_handle)` implements that same trait via
the crlt git dependency. It retains a fixed `crlt::Community` capability and refuses
operations naming a different community with `NotFound`. Only construction uses
the caller's `Db`; the adapter cannot switch communities or run migrations.
The service routes one database per community; the global wallet has its own DB.
Isolation also holds if the service accidentally gives two communities one DB.

`LIBSQL_SCHEMA` is trusted DDL for the caller's complete crlt migration history.
The service assigns its migration version alongside other libraries' migrations;
the adapter never installs an independent migration ledger. The initial table is
`cpky_passkeys`, with `community_id TEXT`, `credential_id BLOB`, `member TEXT`
(canonical UUID) and `record BLOB` (CBOR of `StoredPasskey`), all non-null. Its
primary key is `(community_id, member, credential_id)` and its unique credential
index is `cpky_passkeys_credential (community_id, credential_id)`. Clustering the
table by member makes listing an exact member range; credential lookups use the
unique index. This avoids duplicating the record payload in a covering secondary
index. crlt injects the community key into
every insert and query. Decoding verifies that payload ownership and credential ID
match the indexed columns. Malformed or inconsistent storage returns `Storage`.
No new passkey metadata is stored. The schema and record format are not encrypted
by cpky; deployment access control and storage protection belong to the service.

Every application read and update uses the appropriate composite index; literal
inserts need no scan. Tests check the exact statements with `EXPLAIN QUERY PLAN`,
and crlt enforces indexed plans at execution. Member lists have no silent
pagination: exceeding crlt's configured row limit fails with `Storage`.

The service supplies and keeps alive a multithreaded Tokio runtime. The adapter
blocks ordinary synchronous threads or `spawn_blocking` workers with
`Handle::block_on`. Direct calls inside an async task panic; current-thread
runtime handles are rejected with `Configuration`. This preserves existing trait
signatures, including non-`Send`, borrowed closures/results. The adapter does not
create a runtime per request or impose new bounds on existing store implementers.

`update` must read the current row, invoke its closure exactly once, and commit
before returning the result. It must serialize against updates and revocations
of the same key. Any closure or commit failure rolls back and returns an error;
never release the successful closure result before commit. An adapter must not
blindly retry a transaction containing an already-consumed closure. `insert`
must never upsert or revive a tombstone. Store errors expose no query or row data.

The libSQL adapter uses crlt's immediate transactions for both inserts and updates.
Insertion checks the unique credential key while holding the write transaction, so duplicate
IDs return `DuplicateCredential` without replacing another owner's row. Updates
read current state, run the closure on the caller's thread, reject key/owner
changes, write and commit. Closure errors and database failures roll back; panic
unwinding drops crlt's transaction and discards its connection. Database errors
map to `Storage` without an upstream source. Remote timeouts may leave a commit's
outcome unknown: no successful authentication is returned, and the service must
reconcile state before any retry. No closure is replayed automatically.

`StoredPasskey` serialization is solely for trusted storage. Never deserialize
these records from a client. Current fields are:

| Fields | Purpose |
| --- | --- |
| `community`, `member`, `rp_id` | Ownership and isolation |
| `credential_id`, `public_key` | WebAuthn verification material |
| `counter`, `backup_eligible`, `backup_state` | Current required authenticator security state |
| `revoked` | Current revocation state |
| `authenticator_type` | Optional catalogue-derived model/provider name |
| `created: { year, month }` | Creation month only |

There are no login dates, last-used fields, device names, history rows, request
records or exact creation times. Raw attestations, certificates, firmware metadata,
AAGUIDs, extension outputs and transport hints are discarded. The stored public
key belongs to the credential; no authenticator private key enters the server.

The AAGUID is parsed with upstream code after successful verification, including
when attestation format is `none`. A supplied trusted catalogue can resolve it to
a name; a missing, unknown or zero AAGUID leaves the name absent. AAGUIDs and names
are untrusted display hints, never evidence that a credential has hardware backing.
cpky does not download a catalogue or accept member-defined names.

## Privacy and integration duties

cpky emits no logs. Because upstream has detailed tracing instrumentation, all
upstream configuration, verification and parsing calls execute with a scoped empty
tracing dispatcher. The application's subscriber resumes unchanged afterward.
The same suppression covers the adapter's database futures on the calling thread.
Errors contain static categories and have no upstream error source. Credential
records and authentication results have redacted `Debug` implementations.

Browser wire types remain upstream types and can expose their contents when an
application formats them. The service and storage adapter must also avoid request
logging, response/body logging, SQL tracing and persistent ceremony state. An
in-process host still sees transient WebAuthn data; cpky cannot prevent the host,
proxy, crash reporter or database infrastructure from recording it.

The caller authorizes registration, listing and revocation; protects against CSRF,
enforces request-size and rate limits, and authenticates server-side sessions.
A synced passkey alone never authorizes adding a device. Approval by an already
active device is enforced by the surrounding cvld device protocol. No cpky API
enrols devices or provides account recovery.

## Validation and deferred work

GitHub Actions on current stable Rust runs fmt, warning-free Clippy on all targets,
and tests. This crate is server-only and does not target `wasm32-unknown-unknown`.
Software authenticator fixtures exercise actual registration and cryptographically
signed authentication; malformed, UV-less, replayed, revoked and counter-regressing
responses exercise the same production verifier. Tests also cover storage
transactions, concurrent assertions, metadata and logging boundaries.

Local libSQL tests exercise the adapter with real file-backed databases, reopen
and migration idempotence, isolation, duplicate/revoked credentials, corrupt rows,
rollback and panic, deferred-constraint commit failure, deadline expiry, concurrent
counter updates through independent pools, and all query plans. The optional Turso
round trip skips unless both `TURSO_URL` and `TURSO_TOKEN` are nonempty; it requires
a disposable database and is not supplied credentials by public CI.

Deferred: discoverable login, browser integration, a packaged/updatable
authenticator-name catalogue, and cvld device/session authorization. These are not
claimed as implemented here.

## Private account lookup

Member-facing login uses `start_authentication_for(member, credential_id)`.
The wallet retains the credential ID returned during registration. Known, absent,
keyless and revoked accounts all return the same options: a fresh upstream
challenge, required user verification and exactly the caller-supplied credential
ID. Empty or oversized IDs are rejected independently of account existence.
No list of stored IDs is returned. A missing/revoked key leaves the private
verification state empty, so it cannot authenticate. The UI allow-list is never
used as authorization. Non-discoverable credentials continue to work.

`start_authentication(member)` remains a trusted management integration API and
must not be exposed to unauthenticated account probes. cmbr uses only the private
lookup API. Pending ceremonies still require service-owned capacity limits.
