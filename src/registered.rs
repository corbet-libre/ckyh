//! Original live row projection for the owning Membership issuance lease.
use super::*;

impl<S: CredentialStore> Passkeys<S> {
    /// Observe the exact retained relying-party configuration of a wallet owner.
    /// These public strings grant no authentication; the trusted host compares
    /// them with its explicit wallet publication configuration at construction.
    pub fn wallet_configuration(&self) -> Result<(&str, &[String]), Error> {
        if self.community != "wallet" {
            return Err(Error::Configuration);
        }
        Ok((&self.rp_id, &self.origins))
    }

    /// Project only the authenticated current key in the isolated wallet scope.
    /// The wallet-local UUID comes from the original opaque authentication;
    /// callers cannot substitute a community pseudonym or another account.
    /// The wallet owner must retain its session/revocation lock through signing
    /// and recheck eligibility, the live key and time before returning bytes.
    pub fn wallet_registration_certificate(
        &self,
        authentication: &Authentication,
    ) -> Result<crate::certificate::RegistrationCertificate, Error> {
        if self.community != "wallet" || authentication.community() != "wallet" {
            return Err(Error::NotFound);
        }
        let key = self.public_credential(authentication)?;
        crate::certificate::RegistrationCertificate::new(key, &authentication.member().to_string())
            .map_err(|_| Error::VerificationFailed)
    }

    /// Export the exact currently active credential for Policy's signed binding.
    /// Call while holding the original Membership lease. The descriptor is only
    /// verification material, not a membership or revocation-freshness proof.
    pub fn public_credential(
        &self,
        authentication: &Authentication,
    ) -> Result<crate::lineage::PublicCredential, Error> {
        if authentication.community() != self.community {
            return Err(Error::NotFound);
        }
        self.registered_public_credential(authentication.member(), authentication.credential_id())
    }

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
