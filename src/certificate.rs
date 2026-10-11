//! Keyhole certificates use the existing csgn signer and published public ring.
//! Community certificates contain only the enrolled pseudonym. The isolated
//! wallet certificate contains its wallet-local UUID and never reaches a
//! community. Neither certificate confers membership or current lineage.
use crate::lineage::{Assertion, PublicCredential, VerifiedAssertion};
use serde::{Deserialize, Serialize};

const PURPOSE: &str = "ckyh.passkey-certificate.v1";
const MAX_CERTIFICATE_BYTES: usize = 65536;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Body {
    purpose: String,
    community: String,
    member: String,
    issued: u64,
    credential_id: Vec<u8>,
    rp_id: String,
    origins: Vec<String>,
    algorithm: webauthn_rs_proto::COSEAlgorithm,
    spki: Vec<u8>,
    backup_eligible: bool,
}
impl Body {
    fn valid(&self) -> bool {
        self.purpose == PURPOSE
            && !self.community.is_empty()
            && self.community.len() <= 256
            && !self.member.is_empty()
            && self.member.len() <= 256
            && !self.member.contains('\0')
            && !self.credential_id.is_empty()
            && self.credential_id.len() <= 1024
            && !self.rp_id.is_empty()
            && self.rp_id.len() <= 253
            && !self.origins.is_empty()
            && self.origins.len() <= 32
            && self
                .origins
                .iter()
                .all(|o| !o.is_empty() && o.len() <= 2048)
            && !self.spki.is_empty()
            && self.spki.len() <= 8192
            && matches!(
                self.algorithm,
                webauthn_rs_proto::COSEAlgorithm::ES256 | webauthn_rs_proto::COSEAlgorithm::RS256
            )
    }
    fn descriptor(&self) -> PublicCredential {
        PublicCredential {
            community: self.community.clone(),
            // Never exported or compared in certificate verification.
            member: [0; 16],
            credential_id: self.credential_id.clone(),
            rp_id: self.rp_id.clone(),
            origins: self.origins.clone(),
            algorithm: self.algorithm,
            spki: self.spki.clone(),
            backup_eligible: self.backup_eligible,
        }
    }
}

/// Fixed refusal category, with no credential, pseudonym or upstream diagnostic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidCertificate;
impl std::fmt::Display for InvalidCertificate {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid passkey certificate")
    }
}
impl std::error::Error for InvalidCertificate {}

/// Original live registration projected by Keyhole for its trusted Membership
/// owner. Not cloneable, serializable or constructible from a supplied descriptor.
/// Membership must retain its registration/revocation lock through signing.
pub struct RegistrationCertificate {
    body: Body,
}
impl RegistrationCertificate {
    #[cfg(feature = "server")]
    pub(crate) fn new(key: PublicCredential, pseudonym: &str) -> Result<Self, InvalidCertificate> {
        let body = Body {
            purpose: PURPOSE.into(),
            community: key.community,
            member: pseudonym.into(),
            issued: 0,
            credential_id: key.credential_id,
            rp_id: key.rp_id,
            origins: key.origins,
            algorithm: key.algorithm,
            spki: key.spki,
            backup_eligible: key.backup_eligible,
        };
        if !body.valid() {
            return Err(InvalidCertificate);
        }
        Ok(Self { body })
    }
    /// Original community namespace; never a client-selected signer scope.
    pub fn community(&self) -> &str {
        &self.body.community
    }
    /// Enrolled community pseudonym, or the isolated authenticated wallet UUID.
    pub fn member(&self) -> &str {
        &self.body.member
    }
    /// Original credential ID for the current revocation check.
    pub fn credential_id(&self) -> &[u8] {
        &self.body.credential_id
    }

    /// Sign through the existing durable owner; no second secret or key ring.
    /// The issuer's standard maximum validity bounds certificate expiry. This
    /// lifetime is independent of Policy epochs; renewal rereads a live key.
    #[cfg(feature = "certificate-signing")]
    pub async fn sign<S: csgn::Store>(
        &self,
        signer: &mut csgn::PersistentSigner<S>,
        now: u64,
    ) -> Result<Vec<u8>, InvalidCertificate> {
        let ring = signer.key_ring().map_err(|_| InvalidCertificate)?;
        if ring.issuer() != self.community() {
            return Err(InvalidCertificate);
        }
        let until = now
            .checked_add(ring.max_validity())
            .ok_or(InvalidCertificate)?;
        let mut body = serde_json::to_value(&self.body).map_err(|_| InvalidCertificate)?;
        body["issued"] = now.into();
        let payload = serde_json::to_vec(&body).map_err(|_| InvalidCertificate)?;
        signer
            .sign(csgn::Kind::Credential, &payload, now, until)
            .await
            .map_err(|_| InvalidCertificate)
    }
}

/// Signature-authenticated certificate only. The caller must check the CURRENT
/// community revocation feed before every assertion use, including after awaits.
pub struct VerifiedCertificate<'a> {
    body: Body,
    bytes: &'a [u8],
    until: u64,
}
impl VerifiedCertificate<'_> {
    /// Genuine community pseudonym, never a server UUID.
    pub fn member(&self) -> &str {
        &self.body.member
    }
    /// Exact credential ID carried in the current revocation publication.
    pub fn credential_id(&self) -> &[u8] {
        &self.body.credential_id
    }
    /// Original signed certificate for local evidence retention.
    pub fn signed_bytes(&self) -> &[u8] {
        self.bytes
    }
    /// Exclusive lifetime fixed by the original signer.
    pub fn valid_until(&self) -> u64 {
        self.until
    }
    /// Earliest valid certificate time, covered by its COSE signature.
    pub fn issued_at(&self) -> u64 {
        self.body.issued
    }
    /// Standard WebAuthn request over the exact canonical owner challenge.
    pub fn request(
        &self,
        challenge: [u8; 32],
        now: u64,
    ) -> Result<webauthn_rs_proto::RequestChallengeResponse, InvalidCertificate> {
        self.check_time(now)?;
        Ok(self.body.descriptor().request(challenge))
    }
    /// Use the original Keyhole assertion verifier. Unsigned userHandle routing
    /// data never becomes an identity assertion or a published UUID mapping.
    pub fn assertion(
        &self,
        assertion: &Assertion,
        challenge: [u8; 32],
        now: u64,
    ) -> Result<VerifiedAssertion, InvalidCertificate> {
        self.check_time(now)?;
        crate::lineage::verify_bound(&self.body.descriptor(), assertion, challenge, false)
            .map_err(|_| InvalidCertificate)
    }
    fn check_time(&self, now: u64) -> Result<(), InvalidCertificate> {
        if now < self.body.issued || now >= self.until {
            Err(InvalidCertificate)
        } else {
            Ok(())
        }
    }
}

/// Verify original COSE under a previously authenticated Beacon ring. Supplying
/// an arbitrary ring here confers no current authority; Charter owns that trust.
pub fn verify<'a>(
    ring: &csgn::KeyRing,
    bytes: &'a [u8],
    member: &str,
    now: u64,
) -> Result<VerifiedCertificate<'a>, InvalidCertificate> {
    if bytes.len() > MAX_CERTIFICATE_BYTES {
        return Err(InvalidCertificate);
    }
    let envelope = ring
        .verify(bytes, csgn::Kind::Credential, now)
        .map_err(|_| InvalidCertificate)?;
    let body: Body = serde_json::from_slice(envelope.payload()).map_err(|_| InvalidCertificate)?;
    if !body.valid()
        || body.community != ring.issuer()
        || body.member != member
        || body.issued != envelope.issued_at()
    {
        return Err(InvalidCertificate);
    }
    Ok(VerifiedCertificate {
        body,
        bytes,
        until: envelope.valid_until(),
    })
}
