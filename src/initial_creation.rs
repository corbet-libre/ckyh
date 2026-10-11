//! Immutable opaque provenance of the original first registered passkey.
use super::*;

/// An authenticated read of one original credential's opaque local commitments.
/// This is neither a signing capability nor proof of a root, device or payment.
/// It cannot be deserialized or used to authorize a new initial registration.
pub struct InitialCreationState {
    seed: [u8; 32],
    publication: Option<[u8; 32]>,
}
impl InitialCreationState {
    /// Exact opaque creation commitment retained by this original credential.
    pub fn seed(&self) -> [u8; 32] {
        self.seed
    }
    /// Exact immutable publication winner, if one has been committed.
    pub fn publication(&self) -> Option<[u8; 32]> {
        self.publication
    }
}

impl<S: CredentialStore> Passkeys<S> {
    /// Caller-authorized first registration. The optional nonzero commitment
    /// is bound to the ORIGINAL pending ceremony; no completion input replaces
    /// it. Both None and Some require atomic first-only store insertion.
    pub fn start_initial_registration(
        &self,
        member: Uuid,
        seed: Option<[u8; 32]>,
    ) -> Result<(CreationChallengeResponse, PendingRegistration), Error> {
        if member.is_nil() || seed == Some([0; 32]) {
            return Err(Error::Configuration);
        }
        self.registration(member, true, seed)
    }

    /// Read only the exact live credential that originally authenticated. An
    /// additional key cannot read another key's initial metadata; legacy keys
    /// lacking a retained commitment cannot acquire provenance retrospectively.
    pub fn initial_creation(
        &self,
        authentication: &Authentication,
    ) -> Result<InitialCreationState, Error> {
        self.initial_state(authentication, None)
    }

    /// Atomically claim the one immutable publication for this ORIGINAL key.
    /// Equal retries succeed; a different seed/publication refuses. The caller
    /// supplies opaque domain commitments, never raw roots or provider payloads.
    pub fn bind_initial_publication(
        &self,
        authentication: &Authentication,
        expected_seed: [u8; 32],
        publication: [u8; 32],
    ) -> Result<InitialCreationState, Error> {
        if expected_seed == [0; 32] || publication == [0; 32] {
            return Err(Error::Configuration);
        }
        self.initial_state(authentication, Some((expected_seed, publication)))
    }

    fn initial_state(
        &self,
        authentication: &Authentication,
        bind: Option<([u8; 32], [u8; 32])>,
    ) -> Result<InitialCreationState, Error> {
        if authentication.community() != self.community {
            return Err(Error::NotFound);
        }
        self.store
            .update(&self.community, authentication.credential_id(), |record| {
                self.check_record(record, authentication.member())?;
                if record.is_revoked() {
                    return Err(Error::Revoked);
                }
                let initial = record.initial_creation.as_mut().ok_or(Error::NotFound)?;
                if initial.seed == [0; 32] || initial.publication == Some([0; 32]) {
                    return Err(Error::Storage);
                }
                if let Some((expected, publication)) = bind {
                    if initial.seed != expected
                        || initial
                            .publication
                            .is_some_and(|current| current != publication)
                    {
                        return Err(Error::Conflict);
                    }
                    initial.publication = Some(publication);
                }
                Ok(InitialCreationState {
                    seed: initial.seed,
                    publication: initial.publication,
                })
            })
    }
}
