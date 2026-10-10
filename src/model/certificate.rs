//! Original registered-key export for certificate issuance.
use super::*;

impl StoredPasskey {
    pub(crate) fn public_credential(
        &self,
        origins: Vec<String>,
    ) -> Result<crate::lineage::PublicCredential, Error> {
        let spki = crate::quiet(|| {
            self.public_key
                .get_openssl_pkey()
                .map_err(|_| Error::VerificationFailed)?
                .public_key_to_der()
                .map_err(|_| Error::VerificationFailed)
        })?;
        Ok(crate::lineage::PublicCredential {
            community: self.community.clone(),
            member: *self.member.as_bytes(),
            credential_id: self.credential_id.as_ref().to_vec(),
            rp_id: self.rp_id.clone(),
            origins,
            algorithm: self.public_key.type_,
            spki,
            backup_eligible: self.backup_eligible,
        })
    }
}
