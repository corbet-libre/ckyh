# Coverage

CI resolves one fresh Cargo.lock and uses that snapshot for stable checks,
advisory policy and nightly LLVM branch instrumentation. Both line and branch
counts must be complete; any reachable gap fails the gate. Only the exact
defensive paths documented below are proposed for exclusion. Test harness files
(`tests/` and `tests.rs`) are omitted from
the measured source; their actual round trips still execute.

A configured gate is not a coverage result. The raw report is retained on failure.

The coverage job exports raw JSON and LCOV from the same actual test execution.
The gate requires every emitted production DA line and BRDA branch to have a
nonzero counter, at 100% for both metrics. It cross-checks file inventories,
summaries and emitted branch locations against the companion JSON. Missing,
duplicate, empty or malformed evidence cannot pass. Raw JSON totals remain
as diagnostic evidence for generic instantiations; source coverage does not
claim every generic instantiation is covered. Both artifacts are retained on
failure. The proposed exceptions require independent security review; this
document does not claim approval or successful execution of a new CI head.

## Proposed defensive-path exceptions

The source gate checks each exact line or branch arm against all three reports,
the expected source text, and complete hashes of the invariant-owning source,
tests and resolved lockfile. An exception fails if it moves, changes, disappears,
executes, or its supporting code or dependency snapshot changes. A line exception
cannot hide a branch. Every other emitted production counter must be positive.
No whole function or file is excluded, and every defense remains in production.

### Repeated origin validation

`Passkeys::new` first validates every origin through `WebauthnBuilder::new`.
The later builder call uses the identical immutable RP and first origin; its
error mapper cannot execute after the first call succeeded. Invalid, empty,
unrelated, insecure and userinfo origins are still exercised at the real boundary.
The [upstream builder](https://docs.rs/webauthn-rs/0.5.5/src/webauthn_rs/lib.rs.html#284-313)
performs deterministic origin/RP validation.

### Already validated authorizer RP

`start_additional_registration` receives its owned authorizer from `self.list`,
which checks every record through `check_record`, including its exact RP.
No callback or storage read occurs before the repeated comparison. The true arm
and its refusal line are unreachable. The corrupted-RP registration test exercises
the earlier rejection, including refusal before another ceremony starts.

### User verification after upstream verification

Keyhole's registration, identified authentication and discoverable authentication
all request Required UV. The maintained
[passkey APIs](https://docs.rs/webauthn-rs/0.5.5/src/webauthn_rs/lib.rs.html)
retain that requirement in opaque pending state; upstream
[ceremony verification](https://docs.rs/webauthn-rs-core/0.5.5/src/webauthn_rs_core/core.rs.html#543-549)
rejects unset UV before returning success. The authentication check also considers
the registration policy. The two repeated post-verification false-UV arms and
their refusal lines cannot execute through Keyhole's public ceremonies. Real
signed assertions and registrations without UV still fail without mutation.

### Repeated attestation envelope decoding

Upstream registration verifies the same immutable attestation bytes first,
including decoding its required borrowed `authData` byte string. Keyhole's second
borrowed envelope decoder only selects that already-validated field for cosmetic
AAGUID lookup. Its decode-error mapper cannot execute after upstream success.
Malformed and chunked-CBOR tests prove refusal without persistence; the latter
also asserts the actual upstream `ParseCBORFailure`, rather than inventing a
successful verification result. None-attestation and zero/known/unknown AAGUID
round trips remain covered.
The reviewed upstream type and conversion are
[`AttestationObjectInner` and `AttestationObject::try_from`](https://docs.rs/crate/webauthn-rs-core/0.5.5/source/src/internals.rs#407-454).
The registry archive was checked against the committed lockfile checksum; changing
that dependency snapshot invalidates these proposed exceptions.

Storage error and row-count checks have no exceptions: real incompatible schemas,
ignored inserts, duplicate imported rows, corruption, transaction expiry and
commit failures exercise those obligations.
