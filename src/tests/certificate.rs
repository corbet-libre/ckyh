//! A genuine issuer signature must not bypass the certificate's scoped format.
use super::*;
use crate::certificate::{InvalidCertificate, verify};
use serde_json::json;

const NOW: u64 = 1_800_000_000;
const MEMBER_NAME: &str = "community-pseudonym";

#[test]
fn signed_invalid_certificate_claims_are_refused_after_authentic_envelope_verification() {
    let (server, _, record) = setup();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let projected = server
        .registration_certificate(MEMBER, record.credential_id(), MEMBER_NAME)
        .unwrap();
    let mut signer = runtime
        .block_on(csgn::PersistentSigner::create(
            csgn::MemoryStore::default(),
            "one",
            csgn::SecretKey::from_seed(&mut [48; 32]),
            NOW,
            1000,
        ))
        .unwrap();
    let original = runtime.block_on(projected.sign(&mut signer, NOW)).unwrap();
    let ring = signer.key_ring().unwrap();
    let envelope = ring.verify(&original, csgn::Kind::Credential, NOW).unwrap();
    let body: serde_json::Value = serde_json::from_slice(envelope.payload()).unwrap();
    assert_eq!(
        verify(ring, &original, MEMBER_NAME, NOW).unwrap().member(),
        MEMBER_NAME
    );

    // Each payload is genuinely signed by the configured issuer. Refusal must
    // come from certificate semantics, not an unrelated signature failure.
    for (field, value) in [
        ("purpose", json!("unrelated-purpose")),
        ("community", json!("")),
        ("community", json!("x".repeat(257))),
        ("community", json!("another-community")),
        ("member", json!("")),
        ("member", json!("x".repeat(257))),
        ("member", json!("hidden\0suffix")),
        ("member", json!("another-member")),
        ("credential_id", json!([])),
        ("credential_id", json!(vec![0_u8; 1025])),
        ("rp_id", json!("")),
        ("rp_id", json!("x".repeat(254))),
        ("origins", json!([])),
        ("origins", json!(vec![ORIGIN; 33])),
        ("origins", json!([""])),
        ("origins", json!(["x".repeat(2049)])),
        ("spki", json!([])),
        ("spki", json!(vec![0_u8; 8193])),
        (
            "algorithm",
            json!(webauthn_rs_proto::COSEAlgorithm::INSECURE_RS1),
        ),
        ("issued", json!(NOW - 1)),
        ("issued", json!(NOW + 1)),
        ("unknown_claim", json!(true)),
    ] {
        let mut altered = body.clone();
        altered[field] = value;
        let payload = serde_json::to_vec(&altered).unwrap();
        let signed = runtime
            .block_on(signer.sign(csgn::Kind::Credential, &payload, NOW, NOW + 1000))
            .unwrap();
        let ring = signer.key_ring().unwrap();
        assert_eq!(
            ring.verify(&signed, csgn::Kind::Credential, NOW)
                .unwrap()
                .payload(),
            payload,
            "the {field} negative must reach the certificate boundary"
        );
        assert!(
            matches!(
                verify(ring, &signed, MEMBER_NAME, NOW),
                Err(InvalidCertificate)
            ),
            "accepted invalid {field}"
        );
    }
}

#[test]
fn original_registration_projection_and_signer_scope_refuse_invalid_issuance() {
    let (server, _, record) = setup();
    for member in [String::new(), "x".repeat(257), "hidden\0suffix".into()] {
        assert!(
            server
                .registration_certificate(MEMBER, record.credential_id(), &member)
                .is_err()
        );
    }
    let projected = server
        .registration_certificate(MEMBER, record.credential_id(), MEMBER_NAME)
        .unwrap();
    assert_eq!(projected.community(), "one");
    assert_eq!(projected.member(), MEMBER_NAME);
    assert_eq!(projected.credential_id(), record.credential_id().as_ref());
    let runtime = tokio::runtime::Runtime::new().unwrap();
    for issuer in ["foreign", "one"] {
        let mut signer = runtime
            .block_on(csgn::PersistentSigner::create(
                csgn::MemoryStore::default(),
                issuer,
                csgn::SecretKey::from_seed(&mut [49; 32]),
                NOW,
                1000,
            ))
            .unwrap();
        let requested_at = if issuer == "one" { u64::MAX } else { NOW };
        let error = runtime
            .block_on(projected.sign(&mut signer, requested_at))
            .unwrap_err();
        assert_eq!(error, InvalidCertificate);
        assert_eq!(error.to_string(), "invalid passkey certificate");
        assert_eq!(format!("{error:?}"), "InvalidCertificate");
        assert!(std::error::Error::source(&error).is_none());
    }
}

#[test]
fn oversized_certificate_is_refused_without_accepting_any_envelope_or_member() {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let signer = runtime
        .block_on(csgn::PersistentSigner::create(
            csgn::MemoryStore::default(),
            "one",
            csgn::SecretKey::from_seed(&mut [50; 32]),
            NOW,
            1000,
        ))
        .unwrap();
    assert!(matches!(
        verify(
            signer.key_ring().unwrap(),
            &vec![0; 65537],
            MEMBER_NAME,
            NOW
        ),
        Err(InvalidCertificate)
    ));
}

#[test]
fn malformed_stored_curve_point_cannot_be_exported_or_certified() {
    use webauthn_rs_core::proto::{COSEKey, COSEKeyType};
    let (server, _, original) = setup();
    let mut encoded = serde_json::to_value(&original).unwrap();
    let mut public_key: COSEKey = serde_json::from_value(encoded["public_key"].clone()).unwrap();
    let COSEKeyType::EC_EC2(point) = &mut public_key.key else {
        panic!("genuine ES256 registration fixture")
    };
    // The trusted-store fault has a valid COSE shape but is not a P-256 point.
    point.x = vec![0; 32].into();
    point.y = vec![0; 32].into();
    assert!(public_key.get_openssl_pkey().is_err());
    encoded["public_key"] = serde_json::to_value(public_key).unwrap();
    let corrupt: StoredPasskey = serde_json::from_value(encoded).unwrap();
    let exact = serde_json::to_vec(&corrupt).unwrap();
    server
        .store
        .update("one", original.credential_id(), |row| {
            *row = corrupt;
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        server.registered_public_credential(MEMBER, original.credential_id()),
        Err(Error::VerificationFailed)
    ));
    assert!(matches!(
        server.registration_certificate(MEMBER, original.credential_id(), MEMBER_NAME),
        Err(Error::VerificationFailed)
    ));
    assert_eq!(
        serde_json::to_vec(&server.list(MEMBER).unwrap().remove(0)).unwrap(),
        exact
    );
    server
        .store
        .update("one", original.credential_id(), |row| {
            *row = original.clone();
            Ok(())
        })
        .unwrap();
    assert!(
        server
            .registration_certificate(MEMBER, original.credential_id(), MEMBER_NAME)
            .is_ok()
    );
}
