use crate::{Authentication, CredentialID, Error, StoredPasskey, Uuid};

/// Transactional storage boundary, implemented by [`crate::LibsqlStore`] via crlt.
///
/// All operations are scoped by community. Implementations must preserve the
/// atomicity documented here, return only static errors, and never log requests,
/// row contents or update times. The synchronous interface permits database
/// transactions without coupling the facade to an async runtime.
pub trait CredentialStore {
    /// Return this member's records, including revoked IDs, via an indexed lookup.
    fn list(&self, community: &str, member: Uuid) -> Result<Vec<StoredPasskey>, Error>;

    /// Atomically insert unless `(community, credential_id)` already exists for
    /// any member. On collision return `Error::DuplicateCredential`; never replace
    /// an existing row, including a revocation tombstone.
    fn insert(&self, record: StoredPasskey) -> Result<(), Error>;

    /// Insert the first credential only while this community/member has NO
    /// credential rows, including tombstones. Serialize that indexed emptiness
    /// check, credential uniqueness and insertion in ONE transaction across
    /// pools/processes. This may carry an initial opaque creation commitment.
    /// Unsupported stores refuse; falling back to ordinary insertion is unsafe.
    fn insert_initial(&self, _record: StoredPasskey) -> Result<(), Error> {
        Err(Error::Configuration)
    }

    /// Insert an additional key only while the exact authorizing key is active.
    /// Check ownership, community and RP against the new record, and revocation,
    /// in the same serializable transaction as uniqueness checking and insertion.
    /// Serialize against authorizer revocation, including other pools/processes.
    fn insert_authorized(
        &self,
        record: StoredPasskey,
        authorizer: &Authentication,
    ) -> Result<(), Error>;

    /// Read the current row and run `change` exactly once in a serializable atomic
    /// transaction. Serialize against every update/revocation of that credential.
    ///
    /// Commit changes before returning `Ok`; on closure or commit failure roll
    /// back and return `Err`. Never return the closure's success if commit fails.
    /// Return `Error::NotFound` for a missing key. The closure may not change the
    /// key or owner. Use an index on `(community, credential_id)`.
    fn update<T>(
        &self,
        community: &str,
        credential_id: &CredentialID,
        change: impl FnOnce(&mut StoredPasskey) -> Result<T, Error>,
    ) -> Result<T, Error>;
}
