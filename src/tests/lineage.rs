//! Real original registration/login followed by portable offline verification.
use super::*;
use crate::lineage::{Assertion, PublicCredential, verify};
use serde_json::json;

fn witness(response: &PublicKeyCredential) -> Assertion {
    Assertion {
        credential_id: response.raw_id.as_ref().to_vec(),
        client_data_json: response.response.client_data_json.as_ref().to_vec(),
        authenticator_data: response.response.authenticator_data.as_ref().to_vec(),
        signature: response.response.signature.as_ref().to_vec(),
        user_handle: response
            .response
            .user_handle
            .as_ref()
            .map(|h| h.as_ref().to_vec()),
    }
}

#[test]
fn certificate_uses_registered_key_pseudonym_and_original_offline_assertion_verifier() {
    let (server, mut token, record) = setup();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let now = 1_800_000_000;
    let pseudonym = "community-pseudonym";
    let request = server
        .registration_certificate(MEMBER, record.credential_id(), pseudonym)
        .unwrap();
    let mut signer = runtime
        .block_on(csgn::PersistentSigner::create(
            csgn::MemoryStore::default(),
            "one",
            csgn::SecretKey::from_seed(&mut [45; 32]),
            now,
            1000,
        ))
        .unwrap();
    let bytes = runtime.block_on(request.sign(&mut signer, now)).unwrap();
    let ring = signer.key_ring().unwrap();
    let certificate = crate::certificate::verify(ring, &bytes, pseudonym, now).unwrap();
    let payload = ring.verify(&bytes, csgn::Kind::Credential, now).unwrap();
    let body: serde_json::Value = serde_json::from_slice(payload.payload()).unwrap();
    assert_eq!(body["member"], pseudonym);
    assert!(body.get("user").is_none());
    assert!(body.get("user_handle").is_none());
    assert!(body.get("credential").is_none());
    assert!(!String::from_utf8_lossy(payload.payload()).contains(&MEMBER.to_string()));
    assert_eq!(certificate.credential_id(), record.credential_id().as_ref());
    assert_eq!(certificate.signed_bytes(), bytes);
    assert_eq!(certificate.issued_at(), now);
    assert_eq!(certificate.valid_until(), now + 1000);
    let challenge = [79; 32];
    let response = assertion(
        &mut token,
        certificate.request(challenge, now).unwrap(),
        ORIGIN,
    );
    let signed = witness(&response);
    certificate.assertion(&signed, challenge, now).unwrap();
    assert!(certificate.assertion(&signed, [80; 32], now).is_err());
    assert!(certificate.request(challenge, now - 1).is_err());
    assert!(
        certificate
            .assertion(&signed, challenge, now + 1000)
            .is_err()
    );
    assert!(crate::certificate::verify(ring, &bytes, &MEMBER.to_string(), now).is_err());
    assert!(crate::certificate::verify(ring, &bytes, pseudonym, now + 1000).is_err());
    let mut altered = signed.clone();
    altered.credential_id.push(1);
    assert!(certificate.assertion(&altered, challenge, now).is_err());
    // The optional user handle is not covered by the WebAuthn signature; the
    // certificate path never treats it as a second member identity. The ordinary
    // descriptor verifier still enforces the original exact server handle.
    altered = signed.clone();
    altered.user_handle = Some(OTHER.as_bytes().to_vec());
    certificate.assertion(&altered, challenge, now).unwrap();
    let descriptor = server
        .registered_public_credential(MEMBER, record.credential_id())
        .unwrap();
    assert!(verify(&descriptor, &altered, challenge).is_err());
    altered.user_handle = Some(vec![0; 65]);
    assert!(certificate.assertion(&altered, challenge, now).is_err());
    if let Some(directory) = std::env::var_os("CKYH_LINEAGE_FIXTURE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join("certificate.json"),
            serde_json::to_vec(&json!({
                "ring":ring.to_cbor(),"certificate":bytes,"member":pseudonym,
                "assertion":signed,"challenge":challenge,"now":now
            }))
            .unwrap(),
        )
        .unwrap();
    }
    // Genuine renewed signature from the same committed key, with no second
    // registration and no fabricated descriptor; lost delivery changes no key.
    let renewal = server
        .registration_certificate(MEMBER, record.credential_id(), pseudonym)
        .unwrap();
    let renewed = runtime
        .block_on(renewal.sign(&mut signer, now + 1))
        .unwrap();
    let renewed =
        crate::certificate::verify(signer.key_ring().unwrap(), &renewed, pseudonym, now + 1)
            .unwrap();
    assert_eq!(renewed.credential_id(), record.credential_id().as_ref());
    renewed.assertion(&signed, challenge, now + 1).unwrap();
    assert!(
        server
            .registration_certificate(OTHER, record.credential_id(), pseudonym)
            .is_err()
    );
    server.revoke(MEMBER, record.credential_id()).unwrap();
    assert!(
        server
            .registration_certificate(MEMBER, record.credential_id(), pseudonym)
            .is_err()
    );
    // Old signature validity is not revocation authority; current Charter is
    // responsible for refusing this still-cryptographically-valid certificate.
    renewed.assertion(&signed, challenge, now + 1).unwrap();
}

fn capture(name: &str, descriptor: &PublicCredential, response: &Assertion, challenge: [u8; 32]) {
    // Optional CI export contains public material only. Actual browser tests
    // consume these same original-server vectors, not separately made answers.
    if let Some(directory) = std::env::var_os("CKYH_LINEAGE_FIXTURE_DIR") {
        let directory = std::path::PathBuf::from(directory);
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(
            directory.join(format!("{name}.json")),
            serde_json::to_vec(
                &json!({"descriptor":descriptor,"assertion":response,"challenge":challenge}),
            )
            .unwrap(),
        )
        .unwrap();
    }
}

#[test]
fn es256_original_keyhole_and_offline_verifier_accept_the_same_real_assertion() {
    let (server, mut token, record) = setup();
    let authentication = login(&server, &mut token);
    let descriptor = server.public_credential(&authentication).unwrap();
    let service_descriptor = server
        .registered_public_credential(MEMBER, record.credential_id())
        .unwrap();
    assert_eq!(
        serde_json::to_vec(&descriptor).unwrap(),
        serde_json::to_vec(&service_descriptor).unwrap()
    );
    assert!(matches!(
        server.registered_public_credential(Uuid::new_v4(), record.credential_id()),
        Err(Error::NotFound)
    ));
    assert_eq!(descriptor.community(), "one");
    assert_eq!(descriptor.member(), MEMBER.as_bytes());
    assert_eq!(descriptor.rp_id(), RP);
    assert_eq!(descriptor.credential_id(), record.credential_id().as_ref());
    assert_eq!(
        descriptor.algorithm(),
        webauthn_rs_proto::COSEAlgorithm::ES256
    );
    assert_eq!(descriptor.origins(), &[format!("{ORIGIN}/")]);
    assert!(!descriptor.spki().is_empty());
    assert_eq!(format!("{descriptor:?}"), "PublicCredential([redacted])");
    let (request, pending) = server.start_authentication(MEMBER).unwrap();
    let challenge: [u8; 32] = request.public_key.challenge.as_slice().try_into().unwrap();
    let response = assertion(&mut token, request, ORIGIN);
    verify(&descriptor, &witness(&response), challenge).unwrap();
    server.finish_authentication(pending, &response).unwrap();

    let challenge = [93; 32];
    let request = descriptor.request(challenge);
    assert_eq!(request.public_key.challenge.as_slice(), challenge);
    assert_eq!(
        request.public_key.user_verification,
        UserVerificationPolicy::Required
    );
    assert!(request.public_key.extensions.is_none());
    let response = assertion(&mut token, request, ORIGIN);
    verify(&descriptor, &witness(&response), challenge).unwrap();
    capture("es256", &descriptor, &witness(&response), challenge);
    server.revoke(MEMBER, record.credential_id()).unwrap();
    assert!(matches!(
        server.public_credential(&authentication),
        Err(Error::Revoked)
    ));
    assert!(matches!(
        server.registered_public_credential(MEMBER, record.credential_id()),
        Err(Error::Revoked)
    ));
    // Cryptographic validity alone deliberately supplies no current authority.
    assert!(verify(&descriptor, &witness(&response), challenge).is_ok());
    let foreign = service(MemoryStore::default(), "foreign");
    assert!(matches!(
        foreign.public_credential(&authentication),
        Err(Error::NotFound)
    ));
}

#[test]
fn signed_wrong_context_flags_and_client_json_are_refused() {
    let (server, mut token, _) = setup();
    let authentication = login(&server, &mut token);
    let descriptor = server.public_credential(&authentication).unwrap();
    let challenge = [4; 32];
    let response = assertion(&mut token, descriptor.request(challenge), ORIGIN);
    for (field, value) in [
        ("type", json!("webauthn.create")),
        ("challenge", json!("AA")),
        ("origin", json!("https://foreign.example.com")),
        ("origin", json!(format!("{ORIGIN}/path"))),
        ("crossOrigin", json!(true)),
        ("topOrigin", json!(ORIGIN)),
    ] {
        let mut changed = response.clone();
        let mut client: serde_json::Value =
            serde_json::from_slice(changed.response.client_data_json.as_ref()).unwrap();
        client[field] = value;
        changed.response.client_data_json = serde_json::to_vec(&client).unwrap().into();
        resign(&token, &mut changed);
        assert!(verify(&descriptor, &witness(&changed), challenge).is_err());
    }
    let mut duplicate = response.clone();
    let mut raw = String::from_utf8(duplicate.response.client_data_json.as_ref().to_vec()).unwrap();
    raw.insert_str(1, "\"type\":\"webauthn.get\",");
    duplicate.response.client_data_json = raw.into_bytes().into();
    resign(&token, &mut duplicate);
    assert!(verify(&descriptor, &witness(&duplicate), challenge).is_err());
    for flags in [0, 1, 4, 5 | 8, 5 | 16, 5 | 64] {
        let mut changed = response.clone();
        let mut data = changed.response.authenticator_data.as_ref().to_vec();
        data[32] = flags;
        changed.response.authenticator_data = data.into();
        resign(&token, &mut changed);
        assert!(verify(&descriptor, &witness(&changed), challenge).is_err());
    }
    let valid = witness(&response);
    assert_eq!(format!("{valid:?}"), "Assertion([redacted])");
    assert!(verify(&descriptor, &valid, [5; 32]).is_err());
    let mut wrong = descriptor.clone();
    wrong.rp_id = "foreign.example.com".into();
    assert!(verify(&wrong, &valid, challenge).is_err());
    wrong = descriptor.clone();
    wrong.algorithm = webauthn_rs_proto::COSEAlgorithm::RS256;
    assert!(verify(&wrong, &valid, challenge).is_err());
    wrong.algorithm = webauthn_rs_proto::COSEAlgorithm::INSECURE_RS1;
    assert!(verify(&wrong, &valid, challenge).is_err());
    let mut altered = valid.clone();
    altered.signature[0] ^= 1;
    assert!(verify(&descriptor, &altered, challenge).is_err());
    altered = valid.clone();
    altered.credential_id.push(1);
    assert!(verify(&descriptor, &altered, challenge).is_err());
    altered = valid.clone();
    altered.user_handle = Some(OTHER.as_bytes().to_vec());
    assert!(verify(&descriptor, &altered, challenge).is_err());
    altered = valid.clone();
    altered.client_data_json = vec![0xff];
    assert!(verify(&descriptor, &altered, challenge).is_err());
    altered = valid;
    altered.authenticator_data.truncate(36);
    assert!(verify(&descriptor, &altered, challenge).is_err());
    assert_eq!(
        crate::lineage::InvalidAssertion.to_string(),
        "invalid passkey lineage assertion"
    );
}

#[test]
fn bounded_lineage_inputs_and_well_formed_invalid_signatures_are_refused() {
    let (server, mut token, _) = setup();
    let authentication = login(&server, &mut token);
    let descriptor = server.public_credential(&authentication).unwrap();
    let challenge = [49; 32];
    let response = assertion(&mut token, descriptor.request(challenge), ORIGIN);
    let valid = witness(&response);
    verify(&descriptor, &valid, challenge).unwrap();
    for field in 0..6 {
        let mut changed = descriptor.clone();
        match field {
            0 => changed.credential_id.clear(),
            1 => changed.credential_id = vec![1; 1025],
            2 => changed.spki = vec![1; 8193],
            3 => changed.rp_id.clear(),
            4 => changed.origins.clear(),
            5 => changed.origins = vec![format!("{ORIGIN}/"); 33],
            _ => unreachable!(),
        }
        assert!(
            verify(&changed, &valid, challenge).is_err(),
            "descriptor {field}"
        );
    }
    for field in 0..3 {
        let mut changed = valid.clone();
        match field {
            0 => changed.client_data_json = vec![b' '; 16385],
            1 => changed.authenticator_data = vec![0; 16385],
            2 => changed.signature = vec![0; 1025],
            _ => unreachable!(),
        }
        assert!(
            verify(&descriptor, &changed, challenge).is_err(),
            "assertion {field}"
        );
    }
    // Preserve valid DER and all ceremony bindings, but alter the signed counter.
    let mut tampered = valid.clone();
    tampered.authenticator_data[36] ^= 1;
    assert!(verify(&descriptor, &tampered, challenge).is_err());
    verify(&descriptor, &valid, challenge).unwrap();
}

#[test]
fn parseable_attested_data_in_an_assertion_is_not_an_authentication() {
    let server = service(MemoryStore::default(), "one");
    let mut token = token();
    let (request, pending) = server.start_registration(MEMBER).unwrap();
    let registration = registration(&mut token, request, ORIGIN);
    let object: BTreeMap<String, Value> =
        serde_cbor_2::from_slice(registration.response.attestation_object.as_ref()).unwrap();
    let Value::Bytes(attested) = &object["authData"] else {
        panic!("genuine registration authenticator data")
    };
    server
        .finish_registration(pending, &registration, month())
        .unwrap();
    let authentication = login(&server, &mut token);
    let descriptor = server.public_credential(&authentication).unwrap();
    let challenge = [50; 32];
    let mut response = assertion(&mut token, descriptor.request(challenge), ORIGIN);
    let mut data = response.response.authenticator_data.as_ref().to_vec();
    assert_eq!(data.len(), 37);
    data[32] |= 0x40;
    data.extend_from_slice(&attested[37..]);
    let parsed = passkey_types::ctap2::AuthenticatorData::from_slice(&data).unwrap();
    assert!(parsed.attested_credential_data.is_some());
    response.response.authenticator_data = data.into();
    resign(&token, &mut response);
    assert!(verify(&descriptor, &witness(&response), challenge).is_err());
}

#[test]
fn signed_vault_frame_is_refused_even_with_its_exact_configured_parent() {
    let vault = "https://vault.members.example.com";
    let server = Passkeys::new(
        MemoryStore::default(),
        "one",
        RP,
        &[Url::parse(ORIGIN).unwrap(), Url::parse(vault).unwrap()],
    )
    .unwrap();
    let mut token = token();
    let record = enrol(&server, &mut token, MEMBER);
    let descriptor = server
        .registered_public_credential(MEMBER, record.credential_id())
        .unwrap();
    let challenge = [61; 32];
    let mut response = assertion(&mut token, descriptor.request(challenge), vault);
    let mut client: serde_json::Value =
        serde_json::from_slice(response.response.client_data_json.as_ref()).unwrap();
    client["crossOrigin"] = json!(true);
    client["topOrigin"] = json!(ORIGIN);
    response.response.client_data_json = serde_json::to_vec(&client).unwrap().into();
    resign(&token, &mut response);
    assert!(verify(&descriptor, &witness(&response), challenge).is_err());

    for (field, value) in [
        ("topOrigin", json!("https://foreign.example.com")),
        ("topOrigin", json!(format!("{ORIGIN}/"))),
        ("topOrigin", json!(format!("{ORIGIN}:4443"))),
        ("topOrigin", json!(format!("{ORIGIN}/path"))),
        ("topOrigin", json!(vault)),
        ("topOrigin", json!(null)),
        ("topOrigin", json!([ORIGIN])),
        ("crossOrigin", json!(false)),
        ("origin", json!(ORIGIN)),
        ("origin", json!("https://vault.foreign.example.com")),
    ] {
        let mut changed_client = client.clone();
        changed_client[field] = value;
        let mut changed = response.clone();
        changed.response.client_data_json = serde_json::to_vec(&changed_client).unwrap().into();
        resign(&token, &mut changed);
        assert!(verify(&descriptor, &witness(&changed), challenge).is_err());
    }
    let mut missing = client.clone();
    missing.as_object_mut().unwrap().remove("topOrigin");
    let mut changed = response.clone();
    changed.response.client_data_json = serde_json::to_vec(&missing).unwrap().into();
    resign(&token, &mut changed);
    assert!(verify(&descriptor, &witness(&changed), challenge).is_err());
    let mut duplicate = String::from_utf8(response.response.client_data_json.to_vec()).unwrap();
    duplicate.insert_str(1, &format!("\"top\\u004frigin\":\"{ORIGIN}\","));
    changed.response.client_data_json = duplicate.into_bytes().into();
    resign(&token, &mut changed);
    assert!(verify(&descriptor, &witness(&changed), challenge).is_err());
    let mut no_parent = descriptor.clone();
    no_parent
        .origins
        .retain(|origin| origin != &format!("{ORIGIN}/"));
    assert!(verify(&no_parent, &witness(&response), challenge).is_err());

    // The same ordinary top-level popup route applies in every browser. A
    // matching parent does not authorize an embedded ceremony.
    let (request, pending) = server.start_authentication(MEMBER).unwrap();
    let before = serde_json::to_value(server.list(MEMBER).unwrap()).unwrap();
    let mut online = assertion(&mut token, request, vault);
    let mut data: serde_json::Value =
        serde_json::from_slice(online.response.client_data_json.as_ref()).unwrap();
    data["crossOrigin"] = json!(true);
    data["topOrigin"] = json!(ORIGIN);
    online.response.client_data_json = serde_json::to_vec(&data).unwrap().into();
    resign(&token, &mut online);
    assert_eq!(
        server.finish_authentication(pending, &online).unwrap_err(),
        Error::VerificationFailed
    );
    assert_eq!(
        serde_json::to_value(server.list(MEMBER).unwrap()).unwrap(),
        before
    );
}

#[test]
fn online_top_level_boundary_preserves_counters_and_allows_the_configured_popup() {
    let vault = "https://vault.members.example.com";
    let server = Passkeys::new(
        MemoryStore::default(),
        "one",
        RP,
        &[Url::parse(ORIGIN).unwrap(), Url::parse(vault).unwrap()],
    )
    .unwrap();
    let mut token = token();
    let record = enrol(&server, &mut token, MEMBER);
    let descriptor = server
        .registered_public_credential(MEMBER, record.credential_id())
        .unwrap();
    for discoverable in [false, true] {
        for (cross_origin, parent) in [
            (true, None),
            (true, Some(json!(ORIGIN))),
            (false, Some(json!(null))),
        ] {
            let (mut request, pending) = server.start_discoverable_authentication().unwrap();
            // This non-resident fixture selects its real registered key locally;
            // the original server discovery state still has no selected member.
            request.public_key.allow_credentials =
                descriptor.request([0; 32]).public_key.allow_credentials;
            let (request, account) = if discoverable {
                (request, None)
            } else {
                let (request, pending) = server.start_authentication(MEMBER).unwrap();
                (request, Some(pending))
            };
            let mut response = assertion(&mut token, request, vault);
            response.response.user_handle = Some(MEMBER.as_bytes().to_vec().into());
            let mut data: serde_json::Value =
                serde_json::from_slice(response.response.client_data_json.as_ref()).unwrap();
            data["crossOrigin"] = json!(cross_origin);
            if let Some(parent) = parent {
                data["topOrigin"] = parent;
            }
            response.response.client_data_json = serde_json::to_vec(&data).unwrap().into();
            resign(&token, &mut response);
            let before = serde_json::to_value(server.list(MEMBER).unwrap()).unwrap();
            let result = if let Some(account) = account {
                server.finish_authentication(account, &response)
            } else {
                server.finish_discoverable_authentication(pending, &response)
            };
            assert_eq!(result.unwrap_err(), Error::VerificationFailed);
            assert_eq!(
                serde_json::to_value(server.list(MEMBER).unwrap()).unwrap(),
                before
            );
        }
        let (mut request, pending) = server.start_discoverable_authentication().unwrap();
        request.public_key.allow_credentials =
            descriptor.request([0; 32]).public_key.allow_credentials;
        let (request, account) = if discoverable {
            (request, None)
        } else {
            let (request, pending) = server.start_authentication(MEMBER).unwrap();
            (request, Some(pending))
        };
        let mut response = assertion(&mut token, request, vault);
        response.response.user_handle = Some(MEMBER.as_bytes().to_vec().into());
        let authentication = if let Some(account) = account {
            server.finish_authentication(account, &response)
        } else {
            server.finish_discoverable_authentication(pending, &response)
        }
        .unwrap();
        assert_eq!(authentication.member(), MEMBER);
        assert_eq!(authentication.credential_id(), record.credential_id());
    }
}

fn rsa_signature(key: &PKey<openssl::pkey::Private>, response: &mut PublicKeyCredential) {
    let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    signer
        .update(response.response.authenticator_data.as_ref())
        .unwrap();
    signer
        .update(&sha256(response.response.client_data_json.as_ref()))
        .unwrap();
    response.response.signature = signer.sign_to_vec().unwrap().into();
}

#[test]
fn signed_extensions_are_exactly_one_bounded_map_and_backup_state_may_change() {
    use ciborium::Value as Cbor;
    let (server, mut token, _) = setup();
    let authentication = login(&server, &mut token);
    let descriptor = server.public_credential(&authentication).unwrap();
    let challenge = [8; 32];
    let response = assertion(&mut token, descriptor.request(challenge), ORIGIN);
    let mut trailer = response.clone();
    let mut bytes = trailer.response.authenticator_data.as_ref().to_vec();
    bytes.push(0);
    trailer.response.authenticator_data = bytes.into();
    resign(&token, &mut trailer);
    assert!(verify(&descriptor, &witness(&trailer), challenge).is_err());
    let pair = || (Cbor::Text("example".into()), Cbor::Bool(true));
    for (map, accepted) in [
        (Cbor::Map(vec![]), true),
        (Cbor::Map(vec![pair()]), true),
        (Cbor::Bool(true), false),
        (Cbor::Map(vec![pair(), pair()]), false),
        (
            Cbor::Map(vec![(Cbor::Integer(1.into()), Cbor::Bool(true))]),
            false,
        ),
        (
            Cbor::Map(vec![(Cbor::Text(String::new()), Cbor::Bool(true))]),
            false,
        ),
        (
            Cbor::Map(vec![(Cbor::Text("x".repeat(65)), Cbor::Bool(true))]),
            false,
        ),
        (
            Cbor::Map(
                (0..33)
                    .map(|n| (Cbor::Text(n.to_string()), Cbor::Bool(true)))
                    .collect(),
            ),
            false,
        ),
    ] {
        let mut changed = response.clone();
        let mut bytes = changed.response.authenticator_data.as_ref().to_vec();
        bytes[32] |= 128;
        ciborium::into_writer(&map, &mut bytes).unwrap();
        changed.response.authenticator_data = bytes.clone().into();
        resign(&token, &mut changed);
        assert_eq!(
            verify(&descriptor, &witness(&changed), challenge).is_ok(),
            accepted
        );
        if accepted {
            bytes.push(0);
            changed.response.authenticator_data = bytes.into();
            resign(&token, &mut changed);
            assert!(verify(&descriptor, &witness(&changed), challenge).is_err());
        }
    }
    let mut backed_up = descriptor.clone();
    backed_up.backup_eligible = true;
    for backup_state in [false, true] {
        let mut changed = response.clone();
        let mut bytes = changed.response.authenticator_data.as_ref().to_vec();
        bytes[32] |= 8;
        if backup_state {
            bytes[32] |= 16;
        }
        changed.response.authenticator_data = bytes.into();
        resign(&token, &mut changed);
        assert!(verify(&backed_up, &witness(&changed), challenge).is_ok());
    }
}

#[test]
fn rs256_original_registration_login_and_portable_spki_verification_interoperate() {
    let server = service(MemoryStore::default(), "one");
    let mut token = token();
    let key = openssl::rsa::Rsa::generate(2048).unwrap();
    let cose = coset::CoseKeyBuilder::new()
        .key_type(coset::iana::KeyType::RSA)
        .algorithm(coset::iana::Algorithm::RS256)
        .param(-1, coset::cbor::Value::Bytes(key.n().to_vec()))
        .param(-2, coset::cbor::Value::Bytes(key.e().to_vec()))
        .build();
    let key = PKey::from_rsa(key).unwrap();
    let (request, pending) = server.start_registration(MEMBER).unwrap();
    let mut response = registration(&mut token, request, ORIGIN);
    // A fixture authenticator uses the real maintained CTAP/COSE encoder and
    // OpenSSL RSA signer. The production server verifies the entire ceremony.
    let mut object: BTreeMap<String, Value> =
        serde_cbor_2::from_slice(response.response.attestation_object.as_ref()).unwrap();
    let Value::Bytes(auth) = &object["authData"] else {
        panic!("authenticator bytes")
    };
    let mut auth = passkey_types::ctap2::AuthenticatorData::from_slice(auth.as_slice()).unwrap();
    auth.attested_credential_data.as_mut().unwrap().key = cose;
    object.insert("authData".into(), Value::Bytes(auth.to_vec()));
    object.insert("fmt".into(), Value::Text("none".into()));
    object.insert("attStmt".into(), Value::Map(BTreeMap::new()));
    response.response.attestation_object = serde_cbor_2::to_vec(&object).unwrap().into();
    server
        .finish_registration(pending, &response, month())
        .unwrap();

    let (request, pending) = server.start_authentication(MEMBER).unwrap();
    let mut response = assertion(&mut token, request, ORIGIN);
    rsa_signature(&key, &mut response);
    let authentication = server.finish_authentication(pending, &response).unwrap();
    let descriptor = server.public_credential(&authentication).unwrap();
    assert_eq!(
        descriptor.algorithm(),
        webauthn_rs_proto::COSEAlgorithm::RS256
    );
    let challenge = [77; 32];
    let mut response = assertion(&mut token, descriptor.request(challenge), ORIGIN);
    rsa_signature(&key, &mut response);
    let valid = witness(&response);
    verify(&descriptor, &valid, challenge).unwrap();
    capture("rs256", &descriptor, &valid, challenge);
    // The certificate path must retain this genuinely registered RSA key too,
    // including the same original assertion verifier and signed public scope.
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let now = 1_800_000_000;
    let projected = server
        .registration_certificate(MEMBER, authentication.credential_id(), "rsa-member")
        .unwrap();
    let mut signer = runtime
        .block_on(csgn::PersistentSigner::create(
            csgn::MemoryStore::default(),
            "one",
            csgn::SecretKey::from_seed(&mut [51; 32]),
            now,
            1000,
        ))
        .unwrap();
    let bytes = runtime.block_on(projected.sign(&mut signer, now)).unwrap();
    let certificate =
        crate::certificate::verify(signer.key_ring().unwrap(), &bytes, "rsa-member", now).unwrap();
    assert_eq!(certificate.member(), "rsa-member");
    assert_eq!(
        certificate.credential_id(),
        authentication.credential_id().as_ref()
    );
    certificate.assertion(&valid, challenge, now).unwrap();
    let mut malformed = descriptor.clone();
    malformed.spki = vec![0];
    assert!(verify(&malformed, &valid, challenge).is_err());
    let mut tampered = valid.clone();
    tampered.authenticator_data[36] ^= 1;
    assert!(verify(&descriptor, &tampered, challenge).is_err());
    let mut wrong = descriptor;
    wrong.algorithm = webauthn_rs_proto::COSEAlgorithm::ES256;
    assert!(verify(&wrong, &valid, challenge).is_err());
}
