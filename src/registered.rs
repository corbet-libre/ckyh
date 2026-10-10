//! Original live row projection for the owning Membership issuance lease.
use super::*;

impl<S: CredentialStore> Passkeys<S> {
    /// Read a live registered public key for the owning Membership/Policy service.
    /// The caller must hold its member-bound issuance lease and authenticate the
    /// member mapping. This public descriptor proves neither login nor admission;
    /// only Policy's signed binding can authorize an offline verifier to trust it.
    pub fn registered_public_credential(
        &self,
        member: Uuid,
        credential_id: &CredentialID,
    ) -> Result<crate::lineage::PublicCredential, Error> {
        self.store.update(&self.community, credential_id, |record| {
            self.check_record(record, member)?;
            if record.revoked {
                return Err(Error::Revoked);
            }
            record.public_credential(self.origins.clone())
        })
    }

    /// Project an actual live registration for certificate signing. The caller
    /// is Membership: it supplies its enrolled pseudonym and retains its member
    /// mutation lease until the original persistent signer commits. Client
    /// descriptors and UUID strings must never substitute for that pseudonym.
    pub fn registration_certificate(
        &self,
        member: Uuid,
        credential_id: &CredentialID,
        pseudonym: &str,
    ) -> Result<crate::certificate::RegistrationCertificate, Error> {
        let key = self.registered_public_credential(member, credential_id)?;
        crate::certificate::RegistrationCertificate::new(key, pseudonym)
            .map_err(|_| Error::VerificationFailed)
    }
}
