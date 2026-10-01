use super::*;
use passkey::{
    authenticator::{Authenticator, UserCheck, UserValidationMethod, extensions::HmacSecretConfig},
    client::{Client, DefaultClientData},
    types::{
        Passkey,
        ctap2::{Aaguid, Ctap2Error},
    },
};
use serde_json::{Value as Json, json};

struct User(bool);

#[async_trait::async_trait]
impl UserValidationMethod for User {
    type PasskeyItem = Passkey;

    async fn check_user<'a>(
        &self,
        _credential: Option<&'a Passkey>,
        _presence: bool,
        _verification: bool,
    ) -> Result<UserCheck, Ctap2Error> {
        Ok(UserCheck {
            presence: true,
            verification: self.0,
        })
    }

    fn is_presence_enabled(&self) -> bool {
        true
    }
    fn is_verification_enabled(&self) -> Option<bool> {
        Some(true)
    }
}

/// An actual CTAP2/WebAuthn software authenticator, with only its user gesture
/// supplied by the fixture. Key generation, PRF and signatures are upstream code.
#[derive(Clone, Default)]
struct Software {
    credential: Option<Passkey>,
}

impl Software {
    fn ceremony(&mut self, options: Json, create: bool, uv: bool, origin: &str) -> Json {
        let mut authenticator =
            Authenticator::new(Aaguid::new_empty(), self.credential.take(), User(uv))
                .hmac_secret(HmacSecretConfig::new_with_uv_only().enable_on_make_credential());
        authenticator.set_make_credentials_with_signature_counter(true);
        let mut client = Client::new(authenticator);
        let origin = Url::parse(origin).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let response = runtime.block_on(async {
            if create {
                serde_json::to_value(
                    client
                        .register(
                            &origin,
                            serde_json::from_value(options).unwrap(),
                            DefaultClientData,
                        )
                        .await
                        .unwrap(),
                )
                .unwrap()
            } else {
                serde_json::to_value(
                    client
                        .authenticate(
                            &origin,
                            serde_json::from_value(options).unwrap(),
                            DefaultClientData,
                        )
                        .await
                        .unwrap(),
                )
                .unwrap()
            }
        });
        self.credential = client.authenticator().store().clone();
        response
    }

    fn register<S: CredentialStore>(
        &mut self,
        server: &Passkeys<S>,
        member: Uuid,
    ) -> StoredPasskey {
        let (options, pending) = server.start_registration(member).unwrap();
        assert_eq!(options.public_key.user.id.as_ref(), member.as_bytes());
        let original = serde_json::to_value(options).unwrap();
        let mut response = self.ceremony(with_prf(original), true, true, ORIGIN);
        assert_eq!(response["clientExtensionResults"]["prf"]["enabled"], true);
        assert!(serde_json::from_value::<RegisterPublicKeyCredential>(response.clone()).is_err());
        strip_prf(&mut response);
        server
            .finish_registration(pending, &serde_json::from_value(response).unwrap(), month())
            .unwrap()
    }

    fn discover<S: CredentialStore>(
        &mut self,
        server: &Passkeys<S>,
    ) -> (PendingDiscoverableAuthentication, Json) {
        let (options, pending) = server.start_discoverable_authentication().unwrap();
        let options = serde_json::to_value(options).unwrap();
        assert_eq!(options["publicKey"]["allowCredentials"], json!([]));
        assert_eq!(options["publicKey"]["userVerification"], "required");
        assert!(options.get("mediation").is_none_or(Json::is_null));
        (
            pending,
            self.ceremony(with_prf(options), false, true, ORIGIN),
        )
    }
}

fn with_prf(mut options: Json) -> Json {
    let original = options.clone();
    // This is a test input, not the production Keyhole salt.
    options["publicKey"]["extensions"]["prf"] = json!({"eval": {"first": "dGVzdC1vbmx5"}});
    let mut preserved = options.clone();
    preserved["publicKey"]["extensions"]
        .as_object_mut()
        .unwrap()
        .remove("prf");
    assert_eq!(preserved, original);
    options
}

fn strip_prf(response: &mut Json) -> Json {
    response["clientExtensionResults"]
        .as_object_mut()
        .unwrap()
        .remove("prf")
        .unwrap()
}

fn clean_assertion(mut response: Json) -> PublicKeyCredential {
    strip_prf(&mut response);
    serde_json::from_value(response).unwrap()
}

#[test]
fn synced_resident_passkey_restores_without_a_client_identifier_and_keeps_prf_local() {
    let server = service(MemoryStore::default(), "one");
    let mut device = Software::default();
    let record = device.register(&server, MEMBER);
    let (options, _) = server.start_registration(MEMBER).unwrap();
    let options = serde_json::to_value(options).unwrap();
    assert_eq!(
        options["publicKey"]["authenticatorSelection"]["residentKey"],
        "required"
    );
    assert_eq!(
        options["publicKey"]["authenticatorSelection"]["requireResidentKey"],
        true
    );
    assert_eq!(
        options["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert_eq!(
        options["publicKey"]["excludeCredentials"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let (pending, mut response) = device.discover(&server);
    assert!(serde_json::from_value::<PublicKeyCredential>(response.clone()).is_err());
    let first_prf = strip_prf(&mut response);
    assert_eq!(first_prf["results"]["first"].as_array().unwrap().len(), 32);
    let auth = server
        .finish_discoverable_authentication(pending, &serde_json::from_value(response).unwrap())
        .unwrap();
    assert_eq!(auth.member(), MEMBER);
    assert_eq!(auth.credential_id(), record.credential_id());

    // The new client has no member or credential ID: only the provider's synced
    // authenticator storage. Discovery returns both the assertion and same PRF.
    let mut phone = device.clone();
    let (pending, mut response) = phone.discover(&server);
    assert_eq!(strip_prf(&mut response), first_prf);
    let auth = server
        .finish_discoverable_authentication(pending, &serde_json::from_value(response).unwrap())
        .unwrap();
    assert_eq!(auth.member(), MEMBER);
    assert_eq!(auth.credential_id(), record.credential_id());
    let row = serde_json::to_value(&server.list(MEMBER).unwrap()[0]).unwrap();
    assert_eq!(
        row.as_object().unwrap().len(),
        serde_json::to_value(record)
            .unwrap()
            .as_object()
            .unwrap()
            .len()
    );
    for field in [
        "prf",
        "extensions",
        "last_used",
        "login_date",
        "device_name",
    ] {
        assert!(row.get(field).is_none());
    }
}

#[test]
fn prf_is_refused_under_every_wire_alias_in_both_response_types() {
    let server = service(MemoryStore::default(), "one");
    let mut device = Software::default();
    let (options, _) = server.start_registration(MEMBER).unwrap();
    let mut registration = device.ceremony(
        with_prf(serde_json::to_value(options).unwrap()),
        true,
        true,
        ORIGIN,
    );
    strip_prf(&mut registration);
    // Reuse this authenticator's registration in a separately bound ceremony.
    let mut other = Software::default();
    other.register(&server, OTHER);
    let (_, assertion) = other.discover(&server);
    let mut assertion = assertion;
    strip_prf(&mut assertion);
    for alias in ["extensions", "clientExtensionResults"] {
        for prf in [
            Json::Null,
            json!(false),
            json!({}),
            json!({"enabled": true}),
            json!({"results":{"first":"DO-NOT-ECHO"}}),
        ] {
            for (is_registration, original) in [(true, &registration), (false, &assertion)] {
                let mut payload = original.clone();
                payload
                    .as_object_mut()
                    .unwrap()
                    .remove("clientExtensionResults");
                payload[alias] = json!({"prf": prf});
                let error = if is_registration {
                    serde_json::from_value::<RegisterPublicKeyCredential>(payload).unwrap_err()
                } else {
                    serde_json::from_value::<PublicKeyCredential>(payload).unwrap_err()
                };
                assert_eq!(error.to_string(), "client secret extension refused");
                // Duplicate extension names must not hide an earlier PRF value.
                let duplicate = format!("{{\"{alias}\":{{\"prf\":null}},\"{alias}\":{{}}}}");
                assert!(serde_json::from_str::<PublicKeyCredential>(&duplicate).is_err());
                assert!(serde_json::from_str::<RegisterPublicKeyCredential>(&duplicate).is_err());
            }
        }
    }
    assert_eq!(server.list(OTHER).unwrap()[0].counter(), 0);
}

#[test]
fn discovery_requires_exact_handle_credential_scope_rp_origin_challenge_and_uv() {
    let server = service(MemoryStore::default(), "one");
    let mut device = Software::default();
    device.register(&server, MEMBER);
    for handle in [
        Json::Null,
        json!(""),
        json!("AQ"),
        json!("AAAAAAAAAAAAAAAAAAAAAg"),
    ] {
        let (pending, mut response) = device.discover(&server);
        response["response"]["userHandle"] = handle;
        assert!(
            server
                .finish_discoverable_authentication(pending, &clean_assertion(response))
                .is_err()
        );
    }
    let (pending, mut response) = device.discover(&server);
    response["rawId"] = json!("dW5rbm93bg");
    assert!(
        server
            .finish_discoverable_authentication(pending, &clean_assertion(response))
            .is_err()
    );
    let other = service(server.store.clone(), "two");
    let (pending, response) = device.discover(&other);
    assert!(
        other
            .finish_discoverable_authentication(pending, &clean_assertion(response))
            .is_err()
    );
    let (_, response) = device.discover(&server);
    let (_, pending) = server.start_discoverable_authentication().unwrap();
    assert!(
        server
            .finish_discoverable_authentication(pending, &clean_assertion(response))
            .is_err()
    );
    for (origin, rp, uv) in [
        ("https://evil.members.example.com", RP, true),
        (ORIGIN, "example.com", true),
        (ORIGIN, RP, false),
    ] {
        let (options, pending) = server.start_discoverable_authentication().unwrap();
        let mut options = serde_json::to_value(options).unwrap();
        options["publicKey"]["rpId"] = json!(rp);
        if !uv {
            options["publicKey"]["userVerification"] = json!("discouraged");
        }
        let response = device.ceremony(options, false, uv, origin);
        let response = serde_json::from_value(response).unwrap();
        assert!(
            server
                .finish_discoverable_authentication(pending, &response)
                .is_err()
        );
    }
    assert_eq!(server.list(MEMBER).unwrap()[0].counter(), 0);
}

#[test]
fn discovery_rechecks_counter_revocation_expiry_instance_and_commit() {
    let server = service(MemoryStore::default(), "one");
    let mut device = Software::default();
    let record = device.register(&server, MEMBER);
    let mut clone = device.clone();
    let (p1, r1) = device.discover(&server);
    let (p2, r2) = clone.discover(&server);
    server
        .finish_discoverable_authentication(p1, &clean_assertion(r1))
        .unwrap();
    assert_eq!(
        server
            .finish_discoverable_authentication(p2, &clean_assertion(r2))
            .unwrap_err(),
        Error::CounterRegression
    );
    let (mut pending, response) = device.discover(&server);
    pending.started = Instant::now() - CEREMONY_LIFETIME;
    assert_eq!(
        server
            .finish_discoverable_authentication(pending, &clean_assertion(response))
            .unwrap_err(),
        Error::Expired
    );
    let (pending, response) = device.discover(&server);
    assert_eq!(
        service(server.store.clone(), "one")
            .finish_discoverable_authentication(pending, &clean_assertion(response))
            .unwrap_err(),
        Error::WrongCeremony
    );
    let (pending, response) = device.discover(&server);
    server.store.0.lock().unwrap().fail_writes = true;
    assert_eq!(
        server
            .finish_discoverable_authentication(pending, &clean_assertion(response))
            .unwrap_err(),
        Error::Storage
    );
    server.store.0.lock().unwrap().fail_writes = false;
    assert_eq!(server.list(MEMBER).unwrap()[0].counter(), 1);
    let (pending, response) = device.discover(&server);
    server.revoke(MEMBER, record.credential_id()).unwrap();
    assert!(
        server
            .finish_discoverable_authentication(pending, &clean_assertion(response))
            .is_err()
    );
    let (pending, response) = device.discover(&server);
    assert!(
        server
            .finish_discoverable_authentication(pending, &clean_assertion(response))
            .is_err()
    );
}

#[test]
fn discovery_allows_zero_counters_and_sign_in_without_a_prf_result() {
    let server = service(MemoryStore::default(), "one");
    let mut device = Software::default();
    device.register(&server, MEMBER);
    device.credential.as_mut().unwrap().counter = None;
    for _ in 0..2 {
        let (options, pending) = server.start_discoverable_authentication().unwrap();
        let response = device.ceremony(serde_json::to_value(options).unwrap(), false, true, ORIGIN);
        assert!(response["clientExtensionResults"].get("prf").is_none());
        server
            .finish_discoverable_authentication(pending, &serde_json::from_value(response).unwrap())
            .unwrap();
    }
    assert_eq!(server.list(MEMBER).unwrap()[0].counter(), 0);
    device.credential.as_mut().unwrap().counter = Some(0);
    let (pending, response) = device.discover(&server);
    server
        .finish_discoverable_authentication(pending, &clean_assertion(response))
        .unwrap();
    device.credential.as_mut().unwrap().counter = None;
    let (pending, response) = device.discover(&server);
    assert_eq!(
        server
            .finish_discoverable_authentication(pending, &clean_assertion(response))
            .unwrap_err(),
        Error::CounterRegression
    );
}

#[test]
fn legacy_secret_outputs_are_rejected_even_from_typed_authenticators() {
    let (server, mut token, _) = setup();
    let (options, pending) = server.start_authentication(MEMBER).unwrap();
    let mut response = assertion(&mut token, options, ORIGIN);
    response.extensions.hmac_get_secret = Some(webauthn_rs_core::proto::HmacGetSecretOutput {
        output1: vec![42; 32].into(),
        output2: None,
    });
    assert_eq!(
        server
            .finish_authentication(pending, &response)
            .unwrap_err(),
        Error::ClientSecretExtension
    );
    let (_, pending) = server.start_discoverable_authentication().unwrap();
    assert_eq!(
        server
            .finish_discoverable_authentication(pending, &response)
            .unwrap_err(),
        Error::ClientSecretExtension
    );
}

#[test]
fn upstream_cross_origin_registration_is_refused_even_at_an_allowed_vault_origin() {
    let vault = "https://vault.members.example.com";
    let server = Passkeys::new(
        MemoryStore::default(),
        "one",
        RP,
        &[Url::parse(ORIGIN).unwrap(), Url::parse(vault).unwrap()],
    )
    .unwrap();
    let (options, pending) = server.start_registration(MEMBER).unwrap();
    let mut client = Client::new(Authenticator::new(
        Aaguid::new_empty(),
        None::<Passkey>,
        User(true),
    ));
    let response = tokio::runtime::Runtime::new()
        .unwrap()
        .block_on(client.register(
            &Url::parse(vault).unwrap(),
            serde_json::from_value(serde_json::to_value(options).unwrap()).unwrap(),
            DefaultClientData,
        ))
        .unwrap();
    let mut response: RegisterPublicKeyCredential =
        serde_json::from_value(serde_json::to_value(response).unwrap()).unwrap();
    // Model the browser's cross-origin client data without duplicate JSON keys.
    // The verifier must reject this before considering the attestation.
    let mut client_data: Json =
        serde_json::from_slice(response.response.client_data_json.as_ref()).unwrap();
    client_data["crossOrigin"] = json!(true);
    response.response.client_data_json = serde_json::to_vec(&client_data).unwrap().into();
    assert!(matches!(
        quiet(|| server
            .webauthn
            .finish_passkey_registration(&response, &pending.state)),
        Err(WebauthnError::CredentialCrossOrigin)
    ));
    assert_eq!(
        server
            .finish_registration(pending, &response, month())
            .unwrap_err(),
        Error::VerificationFailed
    );
    assert!(server.list(MEMBER).unwrap().is_empty());
}
