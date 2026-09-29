use super::*;
use std::collections::{BTreeSet, HashMap};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};

use openssl::{ec::EcKey, hash::MessageDigest, pkey::PKey, sha::sha256, sign::Signer};
use serde_cbor_2::Value;
use tracing_subscriber::prelude::*;
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};
use webauthn_rs_core::proto::UserVerificationPolicy;

const ORIGIN: &str = "https://members.example.com";
const RP: &str = "members.example.com";
const MEMBER: Uuid = Uuid::from_u128(1);
const OTHER: Uuid = Uuid::from_u128(2);

type Key = (String, Vec<u8>);

#[derive(Default)]
struct Rows {
    by_id: BTreeMap<Key, StoredPasskey>,
    by_member: BTreeMap<(String, Uuid), BTreeSet<Vec<u8>>>,
    fail_reads: bool,
    fail_writes: bool,
}

/// Real in-memory transactions with indexes, rollback and commit-failure injection.
#[derive(Clone, Default)]
struct MemoryStore(Arc<Mutex<Rows>>);

impl CredentialStore for MemoryStore {
    fn list(&self, community: &str, member: Uuid) -> Result<Vec<StoredPasskey>, Error> {
        let rows = self.0.lock().map_err(|_| Error::Storage)?;
        if rows.fail_reads {
            return Err(Error::Storage);
        }
        Ok(rows
            .by_member
            .get(&(community.into(), member))
            .into_iter()
            .flatten()
            .map(|id| rows.by_id[&(community.into(), id.clone())].clone())
            .collect())
    }

    fn insert(&self, record: StoredPasskey) -> Result<(), Error> {
        let mut rows = self.0.lock().map_err(|_| Error::Storage)?;
        let id = record.credential_id.as_ref().to_vec();
        let key = (record.community.clone(), id.clone());
        if rows.by_id.contains_key(&key) {
            return Err(Error::DuplicateCredential);
        }
        if rows.fail_writes {
            return Err(Error::Storage);
        }
        rows.by_member
            .entry((record.community.clone(), record.member))
            .or_default()
            .insert(id);
        rows.by_id.insert(key, record);
        Ok(())
    }

    fn update<T>(
        &self,
        community: &str,
        credential_id: &CredentialID,
        change: impl FnOnce(&mut StoredPasskey) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let mut rows = self.0.lock().map_err(|_| Error::Storage)?;
        let key = (community.into(), credential_id.as_ref().to_vec());
        let mut record = rows.by_id.get(&key).ok_or(Error::NotFound)?.clone();
        let result = change(&mut record)?;
        if rows.fail_writes {
            return Err(Error::Storage);
        }
        rows.by_id.insert(key, record);
        Ok(result)
    }
}

fn service(store: MemoryStore, community: &str) -> Passkeys<MemoryStore> {
    Passkeys::new(store, community, RP, &[Url::parse(ORIGIN).unwrap()]).unwrap()
}

fn month() -> CreationMonth {
    CreationMonth::new(2026, 9).unwrap()
}

fn token() -> SoftToken {
    SoftToken::new(true).unwrap().0
}

fn registration(
    token: &mut SoftToken,
    challenge: CreationChallengeResponse,
    origin: &str,
) -> RegisterPublicKeyCredential {
    token
        .perform_register(Url::parse(origin).unwrap(), challenge.public_key, 300_000)
        .unwrap()
}

fn assertion(
    token: &mut SoftToken,
    challenge: RequestChallengeResponse,
    origin: &str,
) -> PublicKeyCredential {
    token
        .perform_auth(Url::parse(origin).unwrap(), challenge.public_key, 300_000)
        .unwrap()
}

fn enrol(server: &Passkeys<MemoryStore>, token: &mut SoftToken, member: Uuid) -> StoredPasskey {
    let (challenge, pending) = server.start_registration(member).unwrap();
    let response = registration(token, challenge, ORIGIN);
    server
        .finish_registration(pending, &response, month())
        .unwrap()
}

fn login(server: &Passkeys<MemoryStore>, token: &mut SoftToken) -> Authentication {
    let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
    let response = assertion(token, challenge, ORIGIN);
    server.finish_authentication(pending, &response).unwrap()
}

fn setup() -> (Passkeys<MemoryStore>, SoftToken, StoredPasskey) {
    let server = service(MemoryStore::default(), "one");
    let mut token = token();
    let record = enrol(&server, &mut token, MEMBER);
    (server, token, record)
}

/// Sign unusual wire fixtures with OpenSSL and the software authenticator's test
/// key. No production signer or protocol verification is replaced by this helper.
fn resign(token: &SoftToken, response: &mut PublicKeyCredential) {
    let Value::Map(fields) = serde_cbor_2::value::to_value(token).unwrap() else {
        panic!("software token must be a map");
    };
    let keys: HashMap<Vec<u8>, Vec<u8>> =
        serde_cbor_2::value::from_value(fields[&Value::Text("tokens".into())].clone()).unwrap();
    let key = EcKey::private_key_from_der(&keys[response.raw_id.as_ref()]).unwrap();
    let key = PKey::from_ec_key(key).unwrap();
    let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
    signer
        .update(response.response.authenticator_data.as_ref())
        .unwrap();
    signer
        .update(&sha256(response.response.client_data_json.as_ref()))
        .unwrap();
    response.response.signature = signer.sign_to_vec().unwrap().into();
}

fn signed_counter(token: &SoftToken, response: &mut PublicKeyCredential, counter: u32) {
    let mut bytes = response.response.authenticator_data.as_ref().to_vec();
    bytes[33..37].copy_from_slice(&counter.to_be_bytes());
    response.response.authenticator_data = bytes.into();
    resign(token, response);
}

#[test]
fn registration_authentication_and_persistence_round_trip() {
    let (server, mut token, record) = setup();
    assert_eq!(record.member(), MEMBER);
    assert_eq!(record.community(), "one");
    assert_eq!(record.created(), month());
    assert_eq!(record.counter(), 0);
    let result = login(&server, &mut token);
    assert_eq!(result.member(), MEMBER);
    assert_eq!(result.community(), "one");
    login(&server, &mut token);
    let record = server.list(MEMBER).unwrap().remove(0);
    assert_eq!(record.counter(), 2);
    let restored: StoredPasskey =
        serde_json::from_str(&serde_json::to_string(&record).unwrap()).unwrap();
    let store = MemoryStore::default();
    store.insert(restored).unwrap();
    let reopened = service(store, "one");
    login(&reopened, &mut token);
    assert_eq!(reopened.list(MEMBER).unwrap()[0].counter(), 3);
}

#[test]
fn both_ceremonies_require_user_verification_in_options() {
    let (server, _, _) = setup();
    let (request, _) = server.start_registration(MEMBER).unwrap();
    assert_eq!(
        serde_json::to_value(request).unwrap()["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    let (request, _) = server.start_authentication(MEMBER).unwrap();
    assert_eq!(
        serde_json::to_value(request).unwrap()["publicKey"]["userVerification"],
        "required"
    );
}

#[test]
fn registration_without_uv_is_refused() {
    let server = service(MemoryStore::default(), "one");
    let (mut challenge, pending) = server.start_registration(MEMBER).unwrap();
    challenge
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .user_verification = UserVerificationPolicy::Discouraged_DO_NOT_USE;
    let response = registration(&mut token(), challenge, ORIGIN);
    assert_eq!(
        server
            .finish_registration(pending, &response, month())
            .unwrap_err(),
        Error::UserVerificationRequired
    );
    assert!(server.list(MEMBER).unwrap().is_empty());
}

#[test]
fn validly_signed_assertion_without_uv_is_refused() {
    let (server, mut token, _) = setup();
    let (mut challenge, pending) = server.start_authentication(MEMBER).unwrap();
    challenge.public_key.user_verification = UserVerificationPolicy::Discouraged_DO_NOT_USE;
    let response = assertion(&mut token, challenge, ORIGIN);
    assert_eq!(
        server
            .finish_authentication(pending, &response)
            .unwrap_err(),
        Error::UserVerificationRequired
    );
    assert_eq!(server.list(MEMBER).unwrap()[0].counter(), 0);
}

#[test]
fn cloned_authenticator_counter_is_flagged() {
    let (server, mut token, _) = setup();
    let mut cloned = SoftToken::from_cbor(&token.to_cbor().unwrap()).unwrap();
    login(&server, &mut token);
    login(&server, &mut token);
    let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
    let response = assertion(&mut cloned, challenge, ORIGIN);
    assert_eq!(
        server
            .finish_authentication(pending, &response)
            .unwrap_err(),
        Error::CounterRegression
    );
    assert_eq!(server.list(MEMBER).unwrap()[0].counter(), 2);
}

#[test]
fn zero_counters_are_allowed_until_a_counter_is_established() {
    let (server, mut token, _) = setup();
    for _ in 0..2 {
        let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
        let mut response = assertion(&mut token, challenge, ORIGIN);
        signed_counter(&token, &mut response, 0);
        server.finish_authentication(pending, &response).unwrap();
    }
    assert_eq!(server.list(MEMBER).unwrap()[0].counter(), 0);
    login(&server, &mut token);
    for counter in [0, 3] {
        let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
        let mut response = assertion(&mut token, challenge, ORIGIN);
        signed_counter(&token, &mut response, counter);
        assert_eq!(
            server
                .finish_authentication(pending, &response)
                .unwrap_err(),
            Error::CounterRegression
        );
    }
    assert_eq!(server.list(MEMBER).unwrap()[0].counter(), 3);
}

#[test]
fn overlapping_ceremonies_cannot_overwrite_newer_counters() {
    let (server, mut token, _) = setup();
    let (first, pending_first) = server.start_authentication(MEMBER).unwrap();
    let (second, pending_second) = server.start_authentication(MEMBER).unwrap();
    let first = assertion(&mut token, first, ORIGIN);
    let second = assertion(&mut token, second, ORIGIN);
    server
        .finish_authentication(pending_second, &second)
        .unwrap();
    assert_eq!(
        server
            .finish_authentication(pending_first, &first)
            .unwrap_err(),
        Error::CounterRegression
    );
    assert_eq!(server.list(MEMBER).unwrap()[0].counter(), 2);
}

#[test]
fn concurrent_equal_counters_have_exactly_one_winner() {
    let (server, mut token, _) = setup();
    let mut cloned = SoftToken::from_cbor(&token.to_cbor().unwrap()).unwrap();
    let (a, pa) = server.start_authentication(MEMBER).unwrap();
    let (b, pb) = server.start_authentication(MEMBER).unwrap();
    let a = assertion(&mut token, a, ORIGIN);
    let b = assertion(&mut cloned, b, ORIGIN);
    let barrier = std::sync::Barrier::new(2);
    std::thread::scope(|scope| {
        let first = scope.spawn(|| {
            barrier.wait();
            server.finish_authentication(pa, &a)
        });
        let second = scope.spawn(|| {
            barrier.wait();
            server.finish_authentication(pb, &b)
        });
        let results = [first.join().unwrap(), second.join().unwrap()];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(Error::CounterRegression)))
                .count(),
            1
        );
    });
}

#[test]
fn revocation_refuses_pending_and_future_authentication() {
    let (server, mut token, record) = setup();
    let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
    let response = assertion(&mut token, challenge, ORIGIN);
    server.revoke(MEMBER, record.credential_id()).unwrap();
    server.revoke(MEMBER, record.credential_id()).unwrap();
    assert_eq!(
        server
            .finish_authentication(pending, &response)
            .unwrap_err(),
        Error::Revoked
    );
    assert!(matches!(
        server.start_authentication(MEMBER),
        Err(Error::NoActivePasskeys)
    ));
    assert!(server.list(MEMBER).unwrap()[0].is_revoked());
    assert_eq!(
        server.store.insert(record).unwrap_err(),
        Error::DuplicateCredential
    );
}

#[test]
fn revocation_is_scoped_to_owner_and_community() {
    let (server, mut token, record) = setup();
    let other = service(server.store.clone(), "two");
    assert_eq!(
        server.revoke(OTHER, record.credential_id()).unwrap_err(),
        Error::NotFound
    );
    assert_eq!(
        other.revoke(MEMBER, record.credential_id()).unwrap_err(),
        Error::NotFound
    );
    assert!(other.list(MEMBER).unwrap().is_empty());
    assert!(matches!(
        other.start_authentication(MEMBER),
        Err(Error::NoActivePasskeys)
    ));
    login(&server, &mut token);
}

#[test]
fn multiple_credentials_exclude_revoked_ids_and_keep_other_keys_working() {
    let (server, mut first, record) = setup();
    let mut second = token();
    enrol(&server, &mut second, MEMBER);
    server.revoke(MEMBER, record.credential_id()).unwrap();
    login(&server, &mut second);
    let (registration, _) = server.start_registration(MEMBER).unwrap();
    assert_eq!(
        registration.public_key.exclude_credentials.unwrap().len(),
        2
    );
    let (authentication, _) = server.start_authentication(MEMBER).unwrap();
    assert_eq!(authentication.public_key.allow_credentials.len(), 1);
    assert!(
        first
            .perform_auth(
                Url::parse(ORIGIN).unwrap(),
                authentication.public_key,
                300_000
            )
            .is_err()
    );
}

#[test]
fn duplicate_registration_cannot_reassign_a_credential() {
    let (server, _, record) = setup();
    let mut duplicate = record.clone();
    duplicate.member = OTHER;
    assert_eq!(
        server.store.insert(duplicate).unwrap_err(),
        Error::DuplicateCredential
    );
    assert_eq!(server.list(MEMBER).unwrap().len(), 1);
    assert!(server.list(OTHER).unwrap().is_empty());
    let mut another_community = record;
    another_community.community = "two".into();
    server.store.insert(another_community).unwrap();
    assert_eq!(
        service(server.store.clone(), "two")
            .list(MEMBER)
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn registration_replay_and_challenge_substitution_are_refused() {
    let server = service(MemoryStore::default(), "one");
    let mut token = token();
    let (challenge, pending) = server.start_registration(MEMBER).unwrap();
    let response = registration(&mut token, challenge, ORIGIN);
    server
        .finish_registration(pending, &response, month())
        .unwrap();
    let (_, pending) = server.start_registration(OTHER).unwrap();
    assert_eq!(
        server
            .finish_registration(pending, &response, month())
            .unwrap_err(),
        Error::VerificationFailed
    );
    assert!(server.list(OTHER).unwrap().is_empty());
}

#[test]
fn authentication_replay_is_refused_with_a_fresh_challenge() {
    let (server, mut token, _) = setup();
    let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
    let response = assertion(&mut token, challenge, ORIGIN);
    server.finish_authentication(pending, &response).unwrap();
    let (_, pending) = server.start_authentication(MEMBER).unwrap();
    assert_eq!(
        server
            .finish_authentication(pending, &response)
            .unwrap_err(),
        Error::VerificationFailed
    );
}

#[test]
fn both_ceremonies_expire_on_the_server() {
    let (server, mut token, _) = setup();
    let (challenge, mut pending) = server.start_registration(OTHER).unwrap();
    pending.started = Instant::now() - CEREMONY_LIFETIME;
    let response = registration(&mut token, challenge, ORIGIN);
    assert_eq!(
        server
            .finish_registration(pending, &response, month())
            .unwrap_err(),
        Error::Expired
    );
    let (challenge, mut pending) = server.start_authentication(MEMBER).unwrap();
    pending.started = Instant::now() - CEREMONY_LIFETIME;
    let response = assertion(&mut token, challenge, ORIGIN);
    assert_eq!(
        server
            .finish_authentication(pending, &response)
            .unwrap_err(),
        Error::Expired
    );
}

#[test]
fn ceremony_states_are_bound_to_the_facade_instance() {
    let (server, mut token, _) = setup();
    let other = service(server.store.clone(), "two");
    let (challenge, pending) = server.start_registration(OTHER).unwrap();
    let response = registration(&mut token, challenge, ORIGIN);
    assert_eq!(
        other
            .finish_registration(pending, &response, month())
            .unwrap_err(),
        Error::WrongCeremony
    );
    let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
    let response = assertion(&mut token, challenge, ORIGIN);
    assert_eq!(
        other.finish_authentication(pending, &response).unwrap_err(),
        Error::WrongCeremony
    );
}

#[test]
fn origins_are_exact_in_both_ceremonies() {
    let (server, mut token, _) = setup();
    for origin in [
        "https://evil.example.com",
        "https://sub.members.example.com",
        "https://members.example.com:8443",
        "http://members.example.com",
    ] {
        let (challenge, pending) = server.start_registration(OTHER).unwrap();
        let response = registration(&mut token, challenge, origin);
        assert_eq!(
            server
                .finish_registration(pending, &response, month())
                .unwrap_err(),
            Error::VerificationFailed
        );
        let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
        let response = assertion(&mut token, challenge, origin);
        assert_eq!(
            server
                .finish_authentication(pending, &response)
                .unwrap_err(),
            Error::VerificationFailed
        );
    }
}

#[test]
fn explicitly_configured_additional_origin_is_accepted() {
    let alternate = "https://app.members.example.com:8443";
    let server = Passkeys::new(
        MemoryStore::default(),
        "one",
        RP,
        &[Url::parse(ORIGIN).unwrap(), Url::parse(alternate).unwrap()],
    )
    .unwrap();
    let mut token = token();
    let (challenge, pending) = server.start_registration(MEMBER).unwrap();
    let response = registration(&mut token, challenge, alternate);
    server
        .finish_registration(pending, &response, month())
        .unwrap();
    let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
    let response = assertion(&mut token, challenge, alternate);
    server.finish_authentication(pending, &response).unwrap();
}

#[test]
fn configuration_rejects_insecure_malformed_and_unrelated_origins() {
    for origin in [
        "http://members.example.com",
        "https://evil.com",
        "https://members.example.com/path",
        "https://user@members.example.com",
        "https://members.example.com/?query",
        "https://members.example.com/#fragment",
        "https://notmembers.example.com",
    ] {
        assert!(matches!(
            Passkeys::new(
                MemoryStore::default(),
                "one",
                RP,
                &[Url::parse(origin).unwrap()]
            ),
            Err(Error::Configuration)
        ));
    }
    assert!(matches!(
        Passkeys::new(MemoryStore::default(), "one", RP, &[]),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        Passkeys::new(
            MemoryStore::default(),
            "",
            RP,
            &[Url::parse(ORIGIN).unwrap()]
        ),
        Err(Error::Configuration)
    ));
    assert!(matches!(
        Passkeys::new(
            MemoryStore::default(),
            "one",
            RP,
            &[
                Url::parse(ORIGIN).unwrap(),
                Url::parse("https://evil.com").unwrap()
            ]
        ),
        Err(Error::Configuration)
    ));
}

#[test]
fn wrong_rp_hash_is_refused_in_both_ceremonies() {
    let (server, mut token, _) = setup();
    let (mut challenge, pending) = server.start_registration(OTHER).unwrap();
    challenge.public_key.rp.id = "evil.example.com".into();
    let response = registration(&mut token, challenge, ORIGIN);
    assert_eq!(
        server
            .finish_registration(pending, &response, month())
            .unwrap_err(),
        Error::VerificationFailed
    );
    let (mut challenge, pending) = server.start_authentication(MEMBER).unwrap();
    challenge.public_key.rp_id = "evil.example.com".into();
    let response = assertion(&mut token, challenge, ORIGIN);
    assert_eq!(
        server
            .finish_authentication(pending, &response)
            .unwrap_err(),
        Error::VerificationFailed
    );
}

#[test]
fn tampered_signature_and_authenticator_data_are_refused() {
    let (server, mut token, _) = setup();
    for field in ["signature", "authenticator_data", "client_data"] {
        let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
        let mut response = assertion(&mut token, challenge, ORIGIN);
        match field {
            "signature" => response.response.signature = vec![0; 64].into(),
            "authenticator_data" => response.response.authenticator_data = vec![0; 12].into(),
            _ => response.response.client_data_json = b"not json".to_vec().into(),
        }
        assert_eq!(
            server
                .finish_authentication(pending, &response)
                .unwrap_err(),
            Error::VerificationFailed
        );
    }
    assert_eq!(server.list(MEMBER).unwrap()[0].counter(), 0);
}

#[test]
fn wrong_user_handle_and_unregistered_credentials_are_refused() {
    let (server, mut token, _) = setup();
    for wrong_handle in [true, false] {
        let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
        let mut response = assertion(&mut token, challenge, ORIGIN);
        if wrong_handle {
            response.response.user_handle = Some(OTHER.as_bytes().to_vec().into());
        } else {
            response.raw_id = vec![7; 32].into();
        }
        assert_eq!(
            server
                .finish_authentication(pending, &response)
                .unwrap_err(),
            Error::VerificationFailed
        );
    }
    let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
    let mut response = assertion(&mut token, challenge, ORIGIN);
    response.response.user_handle = Some(MEMBER.as_bytes().to_vec().into());
    server.finish_authentication(pending, &response).unwrap();
}

#[test]
fn malformed_attestation_is_refused_without_writing() {
    let server = service(MemoryStore::default(), "one");
    let (challenge, pending) = server.start_registration(MEMBER).unwrap();
    let mut response = registration(&mut token(), challenge, ORIGIN);
    response.response.attestation_object = vec![0xff].into();
    assert_eq!(
        server
            .finish_registration(pending, &response, month())
            .unwrap_err(),
        Error::VerificationFailed
    );
    assert!(server.list(MEMBER).unwrap().is_empty());
}

#[test]
fn known_aaguid_maps_to_name_and_raw_metadata_is_discarded() {
    let names = BTreeMap::from([(
        webauthn_authenticator_rs::softtoken::AAGUID,
        "Software test authenticator".to_string(),
    )]);
    let server = service(MemoryStore::default(), "one").with_authenticator_names(names);
    let record = enrol(&server, &mut token(), MEMBER);
    assert_eq!(
        record.authenticator_type(),
        Some("Software test authenticator")
    );
    let value = serde_json::to_value(record).unwrap();
    let mut fields: Vec<_> = value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    fields.sort_unstable();
    assert_eq!(
        fields,
        [
            "authenticator_type",
            "backup_eligible",
            "backup_state",
            "community",
            "counter",
            "created",
            "credential_id",
            "member",
            "public_key",
            "revoked",
            "rp_id"
        ]
    );
    assert_eq!(
        value["created"],
        serde_json::json!({"year": 2026, "month": 9})
    );
    assert!(
        !value
            .to_string()
            .contains(&webauthn_authenticator_rs::softtoken::AAGUID.to_string())
    );
}

#[test]
fn unknown_authenticator_has_no_invented_name() {
    let (_, _, record) = setup();
    assert_eq!(record.authenticator_type(), None);
}

#[test]
fn aaguid_lookup_also_handles_none_attestation_and_zero_aaguids() {
    for zero in [false, true] {
        let names = BTreeMap::from([
            (
                webauthn_authenticator_rs::softtoken::AAGUID,
                "Software test authenticator".to_string(),
            ),
            (Uuid::nil(), "Must not be used".to_string()),
        ]);
        let server = service(MemoryStore::default(), "one").with_authenticator_names(names);
        let (challenge, pending) = server.start_registration(MEMBER).unwrap();
        let mut response = registration(&mut token(), challenge, ORIGIN);
        let Value::Map(mut envelope) =
            serde_cbor_2::from_slice(response.response.attestation_object.as_ref()).unwrap()
        else {
            panic!("attestation must be a map");
        };
        envelope.insert(Value::Text("fmt".into()), Value::Text("none".into()));
        envelope.insert(Value::Text("attStmt".into()), Value::Map(BTreeMap::new()));
        if zero {
            let Value::Bytes(data) = envelope.get_mut(&Value::Text("authData".into())).unwrap()
            else {
                panic!("authenticator data must be bytes");
            };
            data[37..53].fill(0);
        }
        response.response.attestation_object =
            serde_cbor_2::to_vec(&Value::Map(envelope)).unwrap().into();
        let record = server
            .finish_registration(pending, &response, month())
            .unwrap();
        assert_eq!(
            record.authenticator_type(),
            if zero {
                None
            } else {
                Some("Software test authenticator")
            }
        );
    }
}

#[test]
fn duplicate_id_is_rejected_at_ceremony_completion_for_another_member() {
    let server = service(MemoryStore::default(), "one");
    let (first, first_pending) = server.start_registration(MEMBER).unwrap();
    let (second, second_pending) = server.start_registration(OTHER).unwrap();
    let mut token = token();
    let first = registration(&mut token, first, ORIGIN);
    let mut second = registration(&mut token, second, ORIGIN);
    server
        .finish_registration(first_pending, &first, month())
        .unwrap();
    // An attacker can copy a public credential into a fmt=none registration,
    // paired with fresh client data. The atomic uniqueness check must reject it.
    let Value::Map(mut envelope) =
        serde_cbor_2::from_slice(first.response.attestation_object.as_ref()).unwrap()
    else {
        panic!("attestation must be a map");
    };
    envelope.insert(Value::Text("fmt".into()), Value::Text("none".into()));
    envelope.insert(Value::Text("attStmt".into()), Value::Map(BTreeMap::new()));
    second.response.attestation_object =
        serde_cbor_2::to_vec(&Value::Map(envelope)).unwrap().into();
    second.raw_id = first.raw_id;
    second.id = first.id;
    assert_eq!(
        server
            .finish_registration(second_pending, &second, month())
            .unwrap_err(),
        Error::DuplicateCredential
    );
    assert!(server.list(OTHER).unwrap().is_empty());
}

#[test]
fn validly_signed_missing_presence_is_rejected() {
    let (server, mut token, _) = setup();
    let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
    let mut response = assertion(&mut token, challenge, ORIGIN);
    let mut data = response.response.authenticator_data.as_ref().to_vec();
    data[32] &= !1;
    response.response.authenticator_data = data.into();
    resign(&token, &mut response);
    assert_eq!(
        server
            .finish_authentication(pending, &response)
            .unwrap_err(),
        Error::VerificationFailed
    );
}

#[test]
fn backup_state_updates_survive_storage_round_trip() {
    let (server, mut token, _) = setup();
    // Upstream 0.5.5 rejects a simultaneous transition from ineligible to already
    // backed up. Preserve that rejection; eligibility must change first.
    let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
    let mut response = assertion(&mut token, challenge, ORIGIN);
    let mut data = response.response.authenticator_data.as_ref().to_vec();
    data[32] = 0x1d;
    response.response.authenticator_data = data.into();
    resign(&token, &mut response);
    assert_eq!(
        server
            .finish_authentication(pending, &response)
            .unwrap_err(),
        Error::VerificationFailed
    );
    for flags in [0x0d, 0x1d, 0x0d] {
        let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
        let mut response = assertion(&mut token, challenge, ORIGIN);
        let mut data = response.response.authenticator_data.as_ref().to_vec();
        data[32] = flags;
        response.response.authenticator_data = data.into();
        resign(&token, &mut response);
        server.finish_authentication(pending, &response).unwrap();
        let value = serde_json::to_value(&server.list(MEMBER).unwrap()[0]).unwrap();
        assert_eq!(value["backup_eligible"], true);
        assert_eq!(value["backup_state"], flags & 0x10 != 0);
    }
    let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
    let response = assertion(&mut token, challenge, ORIGIN);
    assert_eq!(
        server
            .finish_authentication(pending, &response)
            .unwrap_err(),
        Error::VerificationFailed
    );
}

#[test]
fn invalid_calendar_months_cannot_enter_storage() {
    for (year, month) in [(0, 1), (10000, 1), (2026, 0), (2026, 13)] {
        assert_eq!(
            CreationMonth::new(year, month).unwrap_err(),
            Error::InvalidMonth
        );
        assert!(
            serde_json::from_value::<CreationMonth>(
                serde_json::json!({"year": year, "month": month})
            )
            .is_err()
        );
    }
    for (year, month) in [(1, 1), (9999, 12)] {
        let date = CreationMonth::new(year, month).unwrap();
        assert_eq!((date.year(), date.month()), (year, month));
    }
    assert!(
        serde_json::from_value::<CreationMonth>(
            serde_json::json!({"year": 2026, "month": 9, "day": 30})
        )
        .is_err()
    );
}

#[test]
fn storage_failure_cannot_return_authentication_or_change_counter() {
    let (server, mut token, _) = setup();
    let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
    let response = assertion(&mut token, challenge, ORIGIN);
    server.store.0.lock().unwrap().fail_writes = true;
    assert_eq!(
        server
            .finish_authentication(pending, &response)
            .unwrap_err(),
        Error::Storage
    );
    assert_eq!(server.list(MEMBER).unwrap()[0].counter(), 0);
    server.store.0.lock().unwrap().fail_writes = false;
    login(&server, &mut token);
}

#[test]
fn storage_failure_does_not_register_or_revoke() {
    let (server, mut token, record) = setup();
    let (challenge, pending) = server.start_registration(OTHER).unwrap();
    let response = registration(&mut token, challenge, ORIGIN);
    server.store.0.lock().unwrap().fail_writes = true;
    assert_eq!(
        server
            .finish_registration(pending, &response, month())
            .unwrap_err(),
        Error::Storage
    );
    assert!(server.list(OTHER).unwrap().is_empty());
    assert_eq!(
        server.revoke(MEMBER, record.credential_id()).unwrap_err(),
        Error::Storage
    );
    assert!(!server.list(MEMBER).unwrap()[0].is_revoked());
    server.store.0.lock().unwrap().fail_reads = true;
    assert!(matches!(
        server.start_registration(MEMBER),
        Err(Error::Storage)
    ));
    assert!(matches!(
        server.start_authentication(MEMBER),
        Err(Error::Storage)
    ));
}

#[derive(Clone)]
struct EventCount(Arc<AtomicUsize>);

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for EventCount {
    fn on_event(&self, _: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

#[test]
fn server_operations_do_not_emit_upstream_request_traces() {
    let count = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(EventCount(Arc::clone(&count)));
    let mut token = token();
    tracing::subscriber::with_default(subscriber, || {
        let server = service(MemoryStore::default(), "one");
        let (challenge, pending) = server.start_registration(MEMBER).unwrap();
        let response = quiet(|| registration(&mut token, challenge, ORIGIN));
        let record = server
            .finish_registration(pending, &response, month())
            .unwrap();
        let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
        let response = quiet(|| assertion(&mut token, challenge, ORIGIN));
        let result = server.finish_authentication(pending, &response).unwrap();
        assert_eq!(format!("{record:?}"), "StoredPasskey([redacted])");
        assert_eq!(format!("{result:?}"), "Authentication([redacted])");
        let (_, pending) = server.start_authentication(MEMBER).unwrap();
        let error = server
            .finish_authentication(pending, &response)
            .unwrap_err();
        assert_eq!(error.to_string(), "passkey verification failed");
        assert!(std::error::Error::source(&error).is_none());
        server.revoke(MEMBER, record.credential_id()).unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 0);
        tracing::info!("subscriber still works outside cpky");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    });
}
