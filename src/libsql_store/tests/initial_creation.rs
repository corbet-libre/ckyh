//! Actual UV, independent SQLite pools and immutable first-key ownership.
use super::*;

fn creation_response(
    token: &mut SoftToken,
    mut challenge: crate::CreationChallengeResponse,
) -> crate::RegisterPublicKeyCredential {
    // This existing legacy fixture signs real UV registrations but has no
    // resident storage; original server counter/credential verification remains.
    challenge
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    token
        .perform_register(Url::parse(ORIGIN).unwrap(), challenge.public_key, 300_000)
        .unwrap()
        .into()
}
fn authenticate(server: &Passkeys<LibsqlStore>, token: &mut SoftToken) -> Authentication {
    let (pending, response) = assertion(server, token);
    server.finish_authentication(pending, &response).unwrap()
}

#[test]
fn committed_creation_and_publication_survive_lost_replies_and_reopen() {
    let fixture = Fixture::new();
    let first = service(fixture.store(COMMUNITY));
    let mut device = SoftToken::new(true).unwrap().0;
    let (challenge, pending) = first
        .start_initial_registration(MEMBER, Some([1; 32]))
        .unwrap();
    let response = creation_response(&mut device, challenge);
    // Discard the genuine committed response, as if the first HTTP reply was lost.
    first
        .finish_registration(pending, &response, CreationMonth::new(2026, 9).unwrap())
        .unwrap();
    let reopened = fixture.reopen();
    let second =
        service(LibsqlStore::new(&reopened, COMMUNITY, fixture.runtime.handle().clone()).unwrap());
    let auth = authenticate(&second, &mut device);
    let creation = second.initial_creation(&auth).unwrap();
    assert_eq!(creation.seed(), [1; 32]);
    assert_eq!(creation.publication(), None);
    second
        .bind_initial_publication(&auth, [1; 32], [2; 32])
        .unwrap();
    // Lose the successful bind reply too; authoritative read recovers its winner.
    let reopened_again = fixture.reopen();
    let third = service(
        LibsqlStore::new(&reopened_again, COMMUNITY, fixture.runtime.handle().clone()).unwrap(),
    );
    let fresh = authenticate(&third, &mut device);
    assert_eq!(
        third.initial_creation(&fresh).unwrap().publication(),
        Some([2; 32])
    );
    assert_eq!(
        third
            .bind_initial_publication(&fresh, [1; 32], [2; 32])
            .unwrap()
            .publication(),
        Some([2; 32])
    );
    for (seed, publication) in [([3; 32], [2; 32]), ([1; 32], [3; 32])] {
        assert!(matches!(
            third.bind_initial_publication(&fresh, seed, publication),
            Err(Error::Conflict)
        ));
    }
    for (seed, publication) in [([0; 32], [2; 32]), ([1; 32], [0; 32])] {
        assert!(matches!(
            third.bind_initial_publication(&fresh, seed, publication),
            Err(Error::Configuration)
        ));
    }
    assert_eq!(
        third.initial_creation(&fresh).unwrap().publication(),
        Some([2; 32])
    );
    third.revoke(MEMBER, fresh.credential_id()).unwrap();
    assert!(matches!(
        third.initial_creation(&fresh),
        Err(Error::Revoked)
    ));
    assert!(matches!(
        third.bind_initial_publication(&fresh, [1; 32], [2; 32]),
        Err(Error::Revoked)
    ));
    let retained = serde_json::to_value(third.list(MEMBER).unwrap().remove(0)).unwrap();
    assert_eq!(
        retained["initial_creation"]["publication"],
        serde_json::to_value([2u8; 32]).unwrap()
    );
    assert!(matches!(
        third.start_initial_registration(MEMBER, Some([4; 32])),
        Err(Error::Conflict)
    ));
}

#[test]
fn additional_or_legacy_keys_cannot_acquire_initial_creation() {
    let fixture = Fixture::new();
    let server = service(fixture.store(COMMUNITY));
    let mut original = SoftToken::new(true).unwrap().0;
    let (challenge, pending) = server
        .start_initial_registration(MEMBER, Some([1; 32]))
        .unwrap();
    server
        .finish_registration(
            pending,
            &creation_response(&mut original, challenge),
            CreationMonth::new(2026, 9).unwrap(),
        )
        .unwrap();
    let auth = authenticate(&server, &mut original);
    let mut additional = SoftToken::new(true).unwrap().0;
    let (challenge, pending) = server.start_additional_registration(&auth).unwrap();
    let added = server
        .finish_registration(
            pending,
            &creation_response(&mut additional, challenge),
            CreationMonth::new(2026, 9).unwrap(),
        )
        .unwrap();
    let other_auth = authenticate(&server, &mut additional);
    assert_eq!(other_auth.credential_id(), added.credential_id());
    assert!(matches!(
        server.initial_creation(&other_auth),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        server.bind_initial_publication(&other_auth, [1; 32], [2; 32]),
        Err(Error::NotFound)
    ));
    assert_eq!(server.initial_creation(&auth).unwrap().publication(), None);
    let mut legacy = SoftToken::new(true).unwrap().0;
    let (challenge, pending) = server.start_initial_registration(OTHER, None).unwrap();
    let stored = server
        .finish_registration(
            pending,
            &creation_response(&mut legacy, challenge),
            CreationMonth::new(2026, 9).unwrap(),
        )
        .unwrap();
    let encoded = serde_json::to_value(&stored).unwrap();
    assert!(encoded.get("initial_creation").is_none());
    let decoded: StoredPasskey = serde_json::from_value(encoded).unwrap();
    assert!(decoded.initial_creation.is_none());
    let (challenge, pending) = server.start_authentication(OTHER).unwrap();
    let response: crate::PublicKeyCredential = legacy
        .perform_auth(Url::parse(ORIGIN).unwrap(), challenge.public_key, 300_000)
        .unwrap()
        .into();
    let legacy_auth = server.finish_authentication(pending, &response).unwrap();
    assert!(matches!(
        server.bind_initial_publication(&legacy_auth, [1; 32], [2; 32]),
        Err(Error::NotFound)
    ));
}

#[test]
fn independent_pools_seeded_and_ordinary_first_registration_have_one_winner() {
    let fixture = Fixture::new();
    let first = service(fixture.store(COMMUNITY));
    let db = fixture.reopen();
    let second =
        service(LibsqlStore::new(&db, COMMUNITY, fixture.runtime.handle().clone()).unwrap());
    let mut a = SoftToken::new(true).unwrap().0;
    let mut b = SoftToken::new(true).unwrap().0;
    let (ca, pa) = first
        .start_initial_registration(MEMBER, Some([1; 32]))
        .unwrap();
    let (cb, pb) = second.start_initial_registration(MEMBER, None).unwrap();
    let ra = creation_response(&mut a, ca);
    let rb = creation_response(&mut b, cb);
    assert_ne!(ra.raw_id, rb.raw_id);
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            barrier.wait();
            first.finish_registration(pa, &ra, CreationMonth::new(2026, 9).unwrap())
        });
        let right = scope.spawn(|| {
            barrier.wait();
            second.finish_registration(pb, &rb, CreationMonth::new(2026, 9).unwrap())
        });
        let results = [left.join().unwrap(), right.join().unwrap()];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(Error::Conflict)))
                .count(),
            1
        );
    });
    assert_eq!(first.list(MEMBER).unwrap().len(), 1);
}

#[test]
fn independent_pools_cloned_authenticated_publication_intents_have_one_winner() {
    let fixture = Fixture::new();
    let first = service(fixture.store(COMMUNITY));
    let db = fixture.reopen();
    let second =
        service(LibsqlStore::new(&db, COMMUNITY, fixture.runtime.handle().clone()).unwrap());
    let mut a = SoftToken::new(true).unwrap().0;
    let (challenge, pending) = first
        .start_initial_registration(MEMBER, Some([1; 32]))
        .unwrap();
    first
        .finish_registration(
            pending,
            &creation_response(&mut a, challenge),
            CreationMonth::new(2026, 9).unwrap(),
        )
        .unwrap();
    let auth = authenticate(&first, &mut a);
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        let left = scope.spawn(|| {
            barrier.wait();
            first.bind_initial_publication(&auth, [1; 32], [2; 32])
        });
        let right = scope.spawn(|| {
            barrier.wait();
            second.bind_initial_publication(&auth, [1; 32], [3; 32])
        });
        let results = [left.join().unwrap(), right.join().unwrap()];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(Error::Conflict)))
                .count(),
            1
        );
    });
    let winner = first.initial_creation(&auth).unwrap().publication();
    assert!([Some([2; 32]), Some([3; 32])].contains(&winner));
}

#[test]
fn invalid_initial_commitments_and_foreign_owners_cannot_change_real_storage() {
    let fixture = Fixture::new();
    let store = fixture.store(COMMUNITY);
    let server = service(store.clone());
    for (member, seed) in [(Uuid::nil(), None), (MEMBER, Some([0; 32]))] {
        assert!(matches!(
            server.start_initial_registration(member, seed),
            Err(Error::Configuration)
        ));
    }
    assert!(server.list(MEMBER).unwrap().is_empty());
    let mut device = SoftToken::new(true).unwrap().0;
    let (challenge, pending) = server
        .start_initial_registration(MEMBER, Some([1; 32]))
        .unwrap();
    server
        .finish_registration(
            pending,
            &creation_response(&mut device, challenge),
            CreationMonth::new(2026, 9).unwrap(),
        )
        .unwrap();
    let auth = authenticate(&server, &mut device);
    let original = server.list(MEMBER).unwrap().remove(0);
    assert_eq!(store.insert(original.clone()), Err(Error::Configuration));
    assert_eq!(
        store.insert_authorized(original.clone(), &auth),
        Err(Error::Configuration)
    );
    let foreign = Passkeys::new(
        fixture.store("foreign"),
        "foreign",
        "members.example.com",
        &[Url::parse(ORIGIN).unwrap()],
    )
    .unwrap();
    assert!(matches!(
        foreign.initial_creation(&auth),
        Err(Error::NotFound)
    ));
    assert!(matches!(
        foreign.bind_initial_publication(&auth, [1; 32], [2; 32]),
        Err(Error::NotFound)
    ));
    assert!(foreign.list(MEMBER).unwrap().is_empty());
    for corrupt_publication in [false, true] {
        let mut corrupt = original.clone();
        let initial = corrupt.initial_creation.as_mut().unwrap();
        if corrupt_publication {
            initial.publication = Some([0; 32]);
        } else {
            initial.seed = [0; 32];
        }
        let bytes = serde_cbor_2::to_vec(&corrupt).unwrap();
        fixture
            .runtime
            .block_on(store.scope.execute(
                UPDATE,
                params![bytes.clone(), auth.credential_id().as_ref()],
            ))
            .unwrap();
        assert!(matches!(
            server.initial_creation(&auth),
            Err(Error::Storage)
        ));
        assert!(matches!(
            server.bind_initial_publication(&auth, [1; 32], [2; 32]),
            Err(Error::Storage)
        ));
        assert_eq!(
            serde_cbor_2::to_vec(&store.list(COMMUNITY, MEMBER).unwrap().remove(0)).unwrap(),
            bytes
        );
    }
}

#[test]
fn first_only_insert_refuses_a_real_incompatible_index_query() {
    let source = Fixture::new();
    let original = record(source.store(COMMUNITY));
    let directory = tempfile::tempdir().unwrap();
    let runtime = runtime();
    let url = Url::from_file_path(directory.path().join("broken.db")).unwrap();
    let db = runtime
        .block_on(Db::open(Config::new(url.as_str(), "")))
        .unwrap();
    // Real SQLite table lacks the record column required by the original LIST.
    runtime.block_on(db.migrate(&[Migration::new(1, "broken_passkeys", "CREATE TABLE cpky_passkeys (community_id TEXT NOT NULL, member TEXT NOT NULL, credential_id BLOB NOT NULL, PRIMARY KEY (community_id, member, credential_id));")])).unwrap();
    let store = LibsqlStore::new(&db, COMMUNITY, runtime.handle().clone()).unwrap();
    assert_eq!(store.insert_initial(original), Err(Error::Storage));
    assert!(
        runtime
            .block_on(
                store
                    .scope
                    .query("SELECT member FROM cpky_passkeys", params![])
            )
            .unwrap()
            .is_empty()
    );
}
