//! Server-side passkeys for cvld, backed by webauthn-rs.
//!
//! Keep ceremony states in a server-side session and consume them once. A verified
//! authentication identifies a member; it grants neither admission nor permission
//! to enrol a device. See `docs/CONTRACT.md` for storage and integration obligations.
#![forbid(unsafe_code)]

mod libsql_store;
mod model;
mod store;

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use webauthn_rs::prelude::{
    Credential, PasskeyAuthentication, PasskeyRegistration, Webauthn, WebauthnBuilder,
    WebauthnError,
};
use webauthn_rs_core::internals::AuthenticatorData;
use webauthn_rs_core::proto::Registration;

pub use libsql_store::{LIBSQL_SCHEMA, LibsqlStore};
pub use model::{Authentication, CreationMonth, Error, StoredPasskey};
pub use store::CredentialStore;
pub use webauthn_rs::prelude::{
    CreationChallengeResponse, CredentialID, PublicKeyCredential, RegisterPublicKeyCredential,
    RequestChallengeResponse, Url, Uuid,
};

const CEREMONY_LIFETIME: Duration = Duration::from_secs(300);

/// A community-scoped server facade. The store may be shared across communities.
///
/// The caller authorizes registration, listing and revocation. In particular,
/// adding a device requires approval from an existing active device outside cpky.
pub struct Passkeys<S> {
    store: S,
    community: String,
    rp_id: String,
    webauthn: Webauthn,
    instance: Arc<()>,
    names: BTreeMap<Uuid, String>,
}

/// Single-use, expiring registration state. Never send this to a client.
///
/// Deliberately neither cloneable nor serializable nor printable.
///
/// ```compile_fail
/// fn copy(state: cpky::PendingRegistration) { let _ = state.clone(); }
/// ```
pub struct PendingRegistration {
    instance: Arc<()>,
    started: Instant,
    member: Uuid,
    state: PasskeyRegistration,
}

/// Single-use, expiring authentication state. Never send this to a client.
///
/// Deliberately neither cloneable nor serializable nor printable.
///
/// ```compile_fail
/// fn copy(state: cpky::PendingAuthentication) { let _ = state.clone(); }
/// ```
///
/// ```compile_fail
/// fn expose(state: cpky::PendingAuthentication) {
///     let _ = serde_json::to_string(&state);
/// }
/// ```
pub struct PendingAuthentication {
    instance: Arc<()>,
    started: Instant,
    member: Uuid,
    state: PasskeyAuthentication,
}

impl<S: CredentialStore> Passkeys<S> {
    /// Configure a community's RP ID and exact HTTPS origins.
    ///
    /// Every origin must be under the RP ID. Paths, userinfo, query strings,
    /// fragments and insecure schemes are refused. Subdomains and ports are
    /// accepted only when explicitly listed. Use a separate RP for each community
    /// (and the global wallet); do not broaden an RP to a shared parent domain.
    pub fn new(
        store: S,
        community: impl Into<String>,
        rp_id: &str,
        origins: &[Url],
    ) -> Result<Self, Error> {
        let community = community.into();
        if community.is_empty() || rp_id.is_empty() || origins.is_empty() {
            return Err(Error::Configuration);
        }
        let webauthn = quiet(|| {
            for origin in origins {
                if origin.scheme() != "https"
                    || !origin.username().is_empty()
                    || origin.password().is_some()
                    || origin.path() != "/"
                    || origin.query().is_some()
                    || origin.fragment().is_some()
                {
                    return Err(Error::Configuration);
                }
                WebauthnBuilder::new(rp_id, origin).map_err(|_| Error::Configuration)?;
            }
            let mut builder = WebauthnBuilder::new(rp_id, &origins[0])
                .map_err(|_| Error::Configuration)?
                .timeout(CEREMONY_LIFETIME);
            for origin in &origins[1..] {
                builder = builder.append_allowed_origin(origin);
            }
            builder.build().map_err(|_| Error::Configuration)
        })?;
        Ok(Self {
            store,
            community,
            rp_id: rp_id.into(),
            webauthn,
            instance: Arc::new(()),
            names: BTreeMap::new(),
        })
    }

    /// Supply a trusted, local AAGUID-to-model-name catalogue.
    ///
    /// Names are display hints, never attestation or eligibility evidence. Unknown
    /// and zero AAGUIDs produce no name; raw AAGUIDs are never persisted. Do not
    /// populate this catalogue from member-supplied device names.
    pub fn with_authenticator_names(mut self, names: BTreeMap<Uuid, String>) -> Self {
        self.names = names;
        self
    }

    /// Start registration for a caller-authorized, community-local user handle.
    ///
    /// `member` is an opaque UUID assigned by the caller, not a global identifier
    /// or a device ID. It is also used as the browser's non-personal account label.
    pub fn start_registration(
        &self,
        member: Uuid,
    ) -> Result<(CreationChallengeResponse, PendingRegistration), Error> {
        let records = self.list(member)?;
        let excluded = records.iter().map(|r| r.credential_id.clone()).collect();
        let label = member.to_string();
        let (challenge, state) = quiet(|| {
            self.webauthn
                .start_passkey_registration(member, &label, &label, Some(excluded))
                .map_err(verification_error)
        })?;
        Ok((
            challenge,
            PendingRegistration {
                instance: Arc::clone(&self.instance),
                started: Instant::now(),
                member,
                state,
            },
        ))
    }

    /// Verify and atomically insert a credential, including uniqueness checks.
    ///
    /// The server supplies the current creation month at completion, never a
    /// browser timestamp. Success does not authorize a new device or admit a member.
    pub fn finish_registration(
        &self,
        pending: PendingRegistration,
        response: &RegisterPublicKeyCredential,
        created: CreationMonth,
    ) -> Result<StoredPasskey, Error> {
        self.check_pending(&pending.instance, pending.started)?;
        let (credential, aaguid) = quiet(|| {
            let passkey = self
                .webauthn
                .finish_passkey_registration(response, &pending.state)
                .map_err(verification_error)?;
            let credential: Credential = passkey.into();
            if !credential.user_verified {
                return Err(Error::UserVerificationRequired);
            }
            // Upstream validates the ceremony first. Reuse its authenticator-data
            // parser only to obtain the cosmetic AAGUID (including fmt="none").
            let envelope: AttestationEnvelope<'_> =
                serde_cbor_2::from_slice(response.response.attestation_object.as_ref())
                    .map_err(|_| Error::VerificationFailed)?;
            let data = AuthenticatorData::<Registration>::try_from(envelope.auth_data)
                .map_err(verification_error)?;
            let aaguid = data.acd.map(|acd| Uuid::from_bytes(acd.aaguid));
            Ok((credential, aaguid))
        })?;
        let authenticator_type = aaguid
            .filter(|id| !id.is_nil())
            .and_then(|id| self.names.get(&id).cloned());
        let record = StoredPasskey::new(
            self.community.clone(),
            pending.member,
            self.rp_id.clone(),
            credential,
            authenticator_type,
            created,
        );
        self.store.insert(record.clone())?;
        Ok(record)
    }

    /// Start account-first authentication with the member's active credentials.
    pub fn start_authentication(
        &self,
        member: Uuid,
    ) -> Result<(RequestChallengeResponse, PendingAuthentication), Error> {
        let passkeys: Vec<_> = self
            .list(member)?
            .into_iter()
            .filter(|r| !r.revoked)
            .map(|r| r.as_passkey())
            .collect();
        if passkeys.is_empty() {
            return Err(Error::NoActivePasskeys);
        }
        let (challenge, state) = quiet(|| {
            self.webauthn
                .start_passkey_authentication(&passkeys)
                .map_err(verification_error)
        })?;
        Ok((
            challenge,
            PendingAuthentication {
                instance: Arc::clone(&self.instance),
                started: Instant::now(),
                member,
                state,
            },
        ))
    }

    /// Start login with the credential ID already held by the wallet.
    ///
    /// Known, unknown and revoked credentials receive identical browser options
    /// apart from upstream randomness. No credential list is disclosed. The
    /// server state contains the matching active key or no keys, so a fabricated
    /// request can never complete. This preserves non-discoverable passkeys.
    pub fn start_authentication_for(
        &self,
        member: Uuid,
        credential_id: &CredentialID,
    ) -> Result<(RequestChallengeResponse, PendingAuthentication), Error> {
        if credential_id.is_empty() || credential_id.len() > 1024 {
            return Err(Error::VerificationFailed);
        }
        let passkeys: Vec<_> = self
            .list(member)?
            .into_iter()
            .filter(|r| !r.revoked && &r.credential_id == credential_id)
            .map(|r| r.as_passkey())
            .collect();
        let (mut challenge, state) = quiet(|| {
            self.webauthn
                .start_passkey_authentication(&passkeys)
                .map_err(verification_error)
        })?;
        // The client allow-list is a UI hint; only the private server state can
        // authorize an assertion. Echo exactly the caller's ID in every case.
        challenge.public_key.allow_credentials = vec![webauthn_rs_core::proto::AllowCredentials {
            type_: "public-key".into(),
            id: credential_id.clone().into(),
            transports: None,
        }];
        Ok((
            challenge,
            PendingAuthentication {
                instance: Arc::clone(&self.instance),
                started: Instant::now(),
                member,
                state,
            },
        ))
    }

    /// Verify an assertion and commit its counter before returning a result.
    ///
    /// Rechecks revocation and counters against the current row in one atomic
    /// update, so overlapping ceremonies cannot overwrite newer security state.
    pub fn finish_authentication(
        &self,
        pending: PendingAuthentication,
        response: &PublicKeyCredential,
    ) -> Result<Authentication, Error> {
        self.check_pending(&pending.instance, pending.started)?;
        if response
            .response
            .user_handle
            .as_ref()
            .is_some_and(|handle| handle.as_ref() != pending.member.as_bytes())
        {
            return Err(Error::VerificationFailed);
        }
        let verified = quiet(|| {
            self.webauthn
                .finish_passkey_authentication(response, &pending.state)
                .map_err(verification_error)
        })?;
        if !verified.user_verified() {
            return Err(Error::UserVerificationRequired);
        }
        self.store
            .update(&self.community, verified.cred_id(), |record| {
                self.check_record(record, pending.member)?;
                if record.revoked {
                    return Err(Error::Revoked);
                }
                if (record.counter != 0 || verified.counter() != 0)
                    && verified.counter() <= record.counter
                {
                    return Err(Error::CounterRegression);
                }
                if record.backup_eligible && !verified.backup_eligible() {
                    return Err(Error::VerificationFailed);
                }
                record.counter = verified.counter();
                record.backup_eligible = verified.backup_eligible();
                record.backup_state = verified.backup_state();
                Ok(Authentication::new(
                    self.community.clone(),
                    pending.member,
                    verified.cred_id().clone(),
                ))
            })
    }

    /// List current passkey records, including revocation tombstones.
    ///
    /// The caller must authorize this management operation. No last-use field exists.
    pub fn list(&self, member: Uuid) -> Result<Vec<StoredPasskey>, Error> {
        let records = self.store.list(&self.community, member)?;
        for record in &records {
            self.check_record(record, member)?;
        }
        Ok(records)
    }

    /// Revoke a passkey immediately and idempotently, including pending logins.
    ///
    /// The caller must authorize removal. Revoked IDs remain reserved, preventing
    /// re-registration from silently restoring a revoked credential.
    pub fn revoke(&self, member: Uuid, credential_id: &CredentialID) -> Result<(), Error> {
        self.store.update(&self.community, credential_id, |record| {
            self.check_record(record, member)?;
            record.revoked = true;
            Ok(())
        })
    }

    fn check_record(&self, record: &StoredPasskey, member: Uuid) -> Result<(), Error> {
        if record.community != self.community
            || record.member != member
            || record.rp_id != self.rp_id
        {
            return Err(Error::NotFound);
        }
        Ok(())
    }

    fn check_pending(&self, instance: &Arc<()>, started: Instant) -> Result<(), Error> {
        if !Arc::ptr_eq(&self.instance, instance) {
            return Err(Error::WrongCeremony);
        }
        if started.elapsed() >= CEREMONY_LIFETIME {
            return Err(Error::Expired);
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct AttestationEnvelope<'a> {
    #[serde(rename = "authData", borrow)]
    auth_data: &'a [u8],
}

fn verification_error(error: WebauthnError) -> Error {
    match error {
        WebauthnError::UserNotVerified => Error::UserVerificationRequired,
        WebauthnError::CredentialPossibleCompromise => Error::CounterRegression,
        _ => Error::VerificationFailed,
    }
}

fn quiet<T>(operation: impl FnOnce() -> T) -> T {
    // Upstream tracing can include credential data. These operations are synchronous,
    // so a scoped empty dispatcher covers the whole verification without changing
    // the embedding application's global subscriber.
    tracing::dispatcher::with_default(
        &tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
        operation,
    )
}

#[cfg(test)]
mod tests;
