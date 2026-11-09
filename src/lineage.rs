//! Stateless verification of an exact owner-provided lineage challenge.
//!
//! Policy must authenticate the descriptor's member/community binding and current
//! credential revocations first. A successful signature is not membership, a
//! current-lineage decision or permission to commit a change. Keys owns the exact
//! challenge, replay/epoch rules and deterministic conflict resolution.

use p256::{
    ecdsa::signature::Verifier,
    pkcs8::{
        AlgorithmIdentifierRef, DecodePublicKey, ObjectIdentifier, SubjectPublicKeyInfoRef,
        der::{Decode, asn1::AnyRef},
    },
};

/// `rsaEncryption` with NULL parameters (RFC 8017 A.1): the SPKI algorithm of an RS256
/// key. The same value as pkcs1's `ALGORITHM_ID`, kept here so ckyh does not pin a pkcs1
/// release beside the rsa pre-releases other crates of the workspace resolve.
const RSA_ENCRYPTION: AlgorithmIdentifierRef<'static> = AlgorithmIdentifierRef {
    oid: ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1"),
    parameters: Some(AnyRef::NULL),
};
use passkey_types::{
    crypto::sha256,
    ctap2::{AuthenticatorData, Flags},
};
use serde::{Deserialize, Serialize};
use webauthn_rs_proto::{COSEAlgorithm, CollectedClientData};

/// Public verification material exported from the original live Keyhole row.
/// Deserialization alone authenticates nothing; carry this inside Policy's
/// signed member binding, never accept a self-asserted descriptor as authority.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicCredential {
    pub(crate) community: String,
    pub(crate) member: [u8; 16],
    pub(crate) credential_id: Vec<u8>,
    pub(crate) rp_id: String,
    pub(crate) origins: Vec<String>,
    pub(crate) algorithm: COSEAlgorithm,
    pub(crate) spki: Vec<u8>,
    pub(crate) backup_eligible: bool,
}

impl std::fmt::Debug for PublicCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PublicCredential([redacted])")
    }
}

impl PublicCredential {
    /// Original community-local server namespace.
    pub fn community(&self) -> &str {
        &self.community
    }
    /// Original community-local account handle, never a global identity.
    pub fn member(&self) -> &[u8; 16] {
        &self.member
    }
    /// Original passkey credential ID used by the public revocation projection.
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }
    /// Original relying-party scope.
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
    /// Exact configured origins; no parent-domain broadening.
    pub fn origins(&self) -> &[String] {
        &self.origins
    }
    /// Standard SubjectPublicKeyInfo DER, exported by the original WebAuthn key.
    pub fn spki(&self) -> &[u8] {
        &self.spki
    }
    /// Original registered COSE algorithm. Current Keyhole offers ES256/RS256.
    pub fn algorithm(&self) -> COSEAlgorithm {
        self.algorithm
    }

    /// Original WebAuthn options for the exact challenge supplied by Keys.
    /// The trusted composition authenticates this descriptor before handing
    /// these options to device Passkeys. There is no PRF material here.
    pub fn request(&self, challenge: [u8; 32]) -> webauthn_rs_proto::RequestChallengeResponse {
        use webauthn_rs_proto::{
            AllowCredentials, PublicKeyCredentialRequestOptions, RequestChallengeResponse,
            UserVerificationPolicy,
        };
        RequestChallengeResponse {
            public_key: PublicKeyCredentialRequestOptions {
                challenge: challenge.to_vec().into(),
                timeout: None,
                rp_id: self.rp_id.clone(),
                allow_credentials: vec![AllowCredentials {
                    type_: "public-key".into(),
                    id: self.credential_id.clone().into(),
                    transports: None,
                }],
                user_verification: UserVerificationPolicy::Required,
                hints: None,
                extensions: None,
            },
            mediation: None,
        }
    }
}

/// Only the public signed assertion fields, separated by device Passkeys.
/// No extension output or PRF input belongs in this witness.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    /// Raw credential ID returned by the authenticator.
    pub credential_id: Vec<u8>,
    /// Exact signed client-data bytes, never reserialized JSON.
    pub client_data_json: Vec<u8>,
    /// Exact signed authenticator-data bytes.
    pub authenticator_data: Vec<u8>,
    /// Original authenticator signature (DER ECDSA or raw RSA).
    pub signature: Vec<u8>,
    /// Optional original community-local user handle.
    pub user_handle: Option<Vec<u8>>,
}

impl std::fmt::Debug for Assertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Assertion([redacted])")
    }
}

/// A refused descriptor/assertion, with no member or supplied bytes in errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidAssertion;
impl std::fmt::Display for InvalidAssertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("invalid passkey lineage assertion")
    }
}
impl std::error::Error for InvalidAssertion {}

/// Successful signature verification only. Policy/Charter and Keys retain
/// current-membership, revocation and lineage-commit authority.
pub struct VerifiedAssertion {
    _private: (),
}

/// Verify an exact lineage digest with maintained WebAuthn parsers and crypto.
/// There is no wall-clock call or online counter update: this verifies retained
/// offline evidence, not a new login. The caller enforces its original signed
/// authority's freshness and checks credential revocations at the point of use.
pub fn verify(
    descriptor: &PublicCredential,
    assertion: &Assertion,
    challenge: [u8; 32],
) -> Result<VerifiedAssertion, InvalidAssertion> {
    verify_bound(descriptor, assertion, challenge, true)
}

// Certificates carry the pseudonym, not the server's private user-handle mapping.
// The WebAuthn userHandle is unsigned routing data. Only the old server-bound
// descriptor path compares it; certificate verification authenticates the exact
// credential, signature and signed challenge instead.
pub(crate) fn verify_bound(
    descriptor: &PublicCredential,
    assertion: &Assertion,
    challenge: [u8; 32],
    check_user_handle: bool,
) -> Result<VerifiedAssertion, InvalidAssertion> {
    if descriptor.credential_id.is_empty()
        || descriptor.credential_id.len() > 1024
        || descriptor.spki.len() > 8192
        || descriptor.rp_id.is_empty()
        || descriptor.origins.is_empty()
        || descriptor.origins.len() > 32
        || assertion.credential_id != descriptor.credential_id
        || assertion.client_data_json.len() > 16384
        || assertion.authenticator_data.len() > 16384
        || assertion.signature.len() > 1024
        || assertion.user_handle.as_ref().is_some_and(|h| h.len() > 64)
        || (check_user_handle
            && assertion
                .user_handle
                .as_ref()
                .is_some_and(|h| h.as_slice() != descriptor.member))
    {
        return Err(InvalidAssertion);
    }
    // The upstream typed deserializer also refuses duplicate known JSON fields.
    let client: CollectedClientData =
        serde_json::from_slice(&assertion.client_data_json).map_err(|_| InvalidAssertion)?;
    if client.type_ != "webauthn.get" || client.challenge.as_slice() != challenge {
        return Err(InvalidAssertion);
    }
    ceremony_origin(&client, &assertion.client_data_json, &descriptor.origins)?;
    let auth = AuthenticatorData::from_slice(&assertion.authenticator_data)
        .map_err(|_| InvalidAssertion)?;
    if auth.rp_id_hash() != sha256(descriptor.rp_id.as_bytes())
        || !auth.flags.contains(Flags::UP | Flags::UV)
        || auth.flags.contains(Flags::AT)
        || auth.flags.contains(Flags::BE) != descriptor.backup_eligible
        || (auth.flags.contains(Flags::BS) && !auth.flags.contains(Flags::BE))
    {
        return Err(InvalidAssertion);
    }
    // Upstream parses the flags and structures but permits trailing bytes. The
    // assertion has a fixed 37-byte prefix and, only with ED, one bounded CBOR
    // extension map. Reuse the maintained CBOR parser and require full input.
    if auth.flags.contains(Flags::ED) {
        let mut input = std::io::Cursor::new(&assertion.authenticator_data[37..]);
        let extensions: ciborium::Value =
            ciborium::from_reader(&mut input).map_err(|_| InvalidAssertion)?;
        let ciborium::Value::Map(entries) = extensions else {
            return Err(InvalidAssertion);
        };
        if entries.len() > 32
            || input.position() != (assertion.authenticator_data.len() - 37) as u64
        {
            return Err(InvalidAssertion);
        }
        let mut names = std::collections::BTreeSet::new();
        for (key, _) in entries {
            let ciborium::Value::Text(name) = key else {
                return Err(InvalidAssertion);
            };
            if name.is_empty() || name.len() > 64 || !names.insert(name) {
                return Err(InvalidAssertion);
            }
        }
    } else if assertion.authenticator_data.len() != 37 {
        return Err(InvalidAssertion);
    }
    let mut signed = assertion.authenticator_data.clone();
    signed.extend_from_slice(&sha256(&assertion.client_data_json));
    match descriptor.algorithm {
        COSEAlgorithm::ES256 => {
            let key = p256::ecdsa::VerifyingKey::from_public_key_der(&descriptor.spki)
                .map_err(|_| InvalidAssertion)?;
            let signature = p256::ecdsa::Signature::from_der(&assertion.signature)
                .map_err(|_| InvalidAssertion)?;
            key.verify(&signed, &signature)
                .map_err(|_| InvalidAssertion)?;
        }
        COSEAlgorithm::RS256 => {
            let key = SubjectPublicKeyInfoRef::from_der(&descriptor.spki)
                .map_err(|_| InvalidAssertion)?;
            if key.algorithm != RSA_ENCRYPTION {
                return Err(InvalidAssertion);
            }
            let public_key = key.subject_public_key.as_bytes().ok_or(InvalidAssertion)?;
            ring::signature::UnparsedPublicKey::new(
                &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                public_key,
            )
            .verify(&signed, &assertion.signature)
            .map_err(|_| InvalidAssertion)?;
        }
        _ => return Err(InvalidAssertion),
    }
    Ok(VerifiedAssertion { _private: () })
}

/// All browsers use an ordinary top-level vault popup for ceremonies. The
/// signed client-data bytes are never rewritten for the upstream verifier.
pub(crate) fn ceremony_origin(
    client: &CollectedClientData,
    raw: &[u8],
    origins: &[String],
) -> Result<(), InvalidAssertion> {
    if raw.len() > 16384
        || !origins
            .iter()
            .any(|origin| origin == client.origin.as_str())
        || client.cross_origin == Some(true)
        || client.unknown_keys.contains_key("topOrigin")
    {
        return Err(InvalidAssertion);
    }
    Ok(())
}
