use super::*;
use crate::{CreationMonth, Passkeys, Url};
use crlt::{Config, Migration};
use std::{cell::Cell, sync::Barrier, time::Duration};
use tempfile::TempDir;
use tokio::runtime::{Builder, Runtime};
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

const COMMUNITY: &str = "one";
const MEMBER: Uuid = Uuid::from_u128(1);
const OTHER: Uuid = Uuid::from_u128(2);
const ORIGIN: &str = "https://members.example.com";

struct Fixture {
    runtime: Runtime,
    db: Db,
    directory: TempDir,
}

fn runtime() -> Runtime {
    Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap()
}

fn migrate(runtime: &Runtime, db: &Db) {
    runtime
        .block_on(db.migrate(&[Migration::new(1, "cpky_passkeys", LIBSQL_SCHEMA)]))
        .unwrap();
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let runtime = runtime();
        let url = Url::from_file_path(directory.path().join("community.db")).unwrap();
        let mut config = Config::new(url.as_str(), "");
        config.max_connections = 4;
        let db = runtime.block_on(Db::open(config)).unwrap();
        migrate(&runtime, &db);
        Self {
            runtime,
            db,
            directory,
        }
    }

    fn reopen(&self) -> Db {
        let url = Url::from_file_path(self.directory.path().join("community.db")).unwrap();
        let db = self
            .runtime
            .block_on(Db::open(Config::new(url.as_str(), "")))
            .unwrap();
        migrate(&self.runtime, &db);
        db
    }

    fn store(&self, community: &str) -> LibsqlStore {
        LibsqlStore::new(&self.db, community, self.runtime.handle().clone()).unwrap()
    }
}

fn service(store: LibsqlStore) -> Passkeys<LibsqlStore> {
    Passkeys::new(
        store,
        COMMUNITY,
        "members.example.com",
        &[Url::parse(ORIGIN).unwrap()],
    )
    .unwrap()
}

fn register(server: &Passkeys<LibsqlStore>, token: &mut SoftToken) -> StoredPasskey {
    let (mut challenge, pending) = server.start_registration(MEMBER).unwrap();
    challenge
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let response: crate::RegisterPublicKeyCredential = token
        .perform_register(Url::parse(ORIGIN).unwrap(), challenge.public_key, 300_000)
        .unwrap()
        .into();
    server
        .finish_registration(pending, &response, CreationMonth::new(2026, 9).unwrap())
        .unwrap()
}

fn assertion(
    server: &Passkeys<LibsqlStore>,
    token: &mut SoftToken,
) -> (crate::PendingAuthentication, crate::PublicKeyCredential) {
    let (challenge, pending) = server.start_authentication(MEMBER).unwrap();
    let response = token
        .perform_auth(Url::parse(ORIGIN).unwrap(), challenge.public_key, 300_000)
        .unwrap();
    (pending, response.into())
}

fn record(store: LibsqlStore) -> StoredPasskey {
    register(&service(store), &mut SoftToken::new(true).unwrap().0)
}

#[test]
fn passkey_round_trip_survives_close_and_reopen() {
    let fixture = Fixture::new();
    let store = fixture.store(COMMUNITY);
    let server = service(store.clone());
    let mut token = SoftToken::new(true).unwrap().0;
    let original = register(&server, &mut token);
    let (pending, response) = assertion(&server, &mut token);
    assert_eq!(
        server
            .finish_authentication(pending, &response)
            .unwrap()
            .member(),
        MEMBER
    );
    let id = original.credential_id().clone();
    drop(server);
    drop(store);
    let Fixture {
        runtime,
        db,
        directory,
    } = fixture;
    drop(db);
    let url = Url::from_file_path(directory.path().join("community.db")).unwrap();
    let db = runtime
        .block_on(Db::open(Config::new(url.as_str(), "")))
        .unwrap();
    migrate(&runtime, &db);
    let server = service(LibsqlStore::new(&db, COMMUNITY, runtime.handle().clone()).unwrap());
    let restored = server.list(MEMBER).unwrap().remove(0);
    assert_eq!(restored.counter(), 1);
    assert_eq!(restored.credential_id(), &id);
    assert_eq!(restored.created(), original.created());
    let (pending, response) = assertion(&server, &mut token);
    server.finish_authentication(pending, &response).unwrap();
    assert_eq!(server.list(MEMBER).unwrap()[0].counter(), 2);
    let (pending, response) = assertion(&server, &mut token);
    server.revoke(MEMBER, &id).unwrap();
    server.revoke(MEMBER, &id).unwrap();
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
    assert_eq!(
        server.store.insert(original).unwrap_err(),
        Error::DuplicateCredential
    );
    assert!(server.list(MEMBER).unwrap()[0].is_revoked());
    assert_eq!(server.list(MEMBER).unwrap()[0].counter(), 2);
}

#[test]
fn scope_member_and_database_boundaries_are_preserved() {
    let fixture = Fixture::new();
    let one = fixture.store(COMMUNITY);
    let original = record(one.clone());
    let two = fixture.store("two");
    let mut another = original.clone();
    another.community = "two".into();
    another.member = OTHER;
    two.insert(another).unwrap();
    assert!(one.list(COMMUNITY, OTHER).unwrap().is_empty());
    assert!(two.list("two", MEMBER).unwrap().is_empty());
    assert_eq!(two.list("two", OTHER).unwrap().len(), 1);
    assert_eq!(one.list("two", OTHER).unwrap_err(), Error::NotFound);
    assert_eq!(two.insert(original.clone()).unwrap_err(), Error::NotFound);
    assert_eq!(
        one.update("two", original.credential_id(), |_| -> Result<(), Error> {
            panic!("wrong scope")
        })
        .unwrap_err(),
        Error::NotFound
    );
    service(one.clone())
        .revoke(MEMBER, original.credential_id())
        .unwrap();
    assert!(!two.list("two", OTHER).unwrap()[0].is_revoked());
    let isolated = Fixture::new();
    let separate = isolated.store(COMMUNITY);
    assert!(separate.list(COMMUNITY, MEMBER).unwrap().is_empty());
    separate.insert(original).unwrap();
    assert!(!separate.list(COMMUNITY, MEMBER).unwrap()[0].is_revoked());
}

#[test]
fn duplicate_ownership_and_revocation_tombstones_are_never_replaced() {
    let fixture = Fixture::new();
    let store = fixture.store(COMMUNITY);
    let original = record(store.clone());
    let mut duplicate = original.clone();
    duplicate.member = OTHER;
    for revoked in [false, true] {
        store
            .update(COMMUNITY, original.credential_id(), |row| {
                row.revoked = revoked;
                Ok(())
            })
            .unwrap();
        assert_eq!(
            store.insert(duplicate.clone()).unwrap_err(),
            Error::DuplicateCredential
        );
        let rows = store.list(COMMUNITY, MEMBER).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].is_revoked(), revoked);
        assert!(store.list(COMMUNITY, OTHER).unwrap().is_empty());
    }
}

#[test]
fn closures_run_once_and_can_borrow_non_send_state() {
    let fixture = Fixture::new();
    let store = fixture.store(COMMUNITY);
    let original = record(store.clone());
    let calls = Cell::new(0);
    let answer = String::from("committed");
    let returned = store
        .update(COMMUNITY, original.credential_id(), |row| {
            calls.set(calls.get() + 1);
            row.counter = 9;
            Ok(&answer)
        })
        .unwrap();
    assert_eq!(returned, "committed");
    assert_eq!(calls.get(), 1);
    assert_eq!(store.list(COMMUNITY, MEMBER).unwrap()[0].counter(), 9);
    assert_eq!(
        store
            .update(COMMUNITY, original.credential_id(), |row| {
                calls.set(calls.get() + 1);
                row.counter = 10;
                Err::<(), _>(Error::CounterRegression)
            })
            .unwrap_err(),
        Error::CounterRegression
    );
    assert_eq!(calls.get(), 2);
    assert_eq!(store.list(COMMUNITY, MEMBER).unwrap()[0].counter(), 9);
    assert_eq!(
        store
            .update(COMMUNITY, &vec![255].into(), |_| -> Result<(), Error> {
                panic!("missing row")
            })
            .unwrap_err(),
        Error::NotFound
    );
}

#[test]
fn ownership_mutations_and_panics_roll_back() {
    let fixture = Fixture::new();
    let store = fixture.store(COMMUNITY);
    let original = record(store.clone());
    for field in 0..3 {
        assert_eq!(
            store
                .update(COMMUNITY, original.credential_id(), |row| {
                    match field {
                        0 => row.community = "two".into(),
                        1 => row.member = OTHER,
                        _ => row.credential_id = vec![255].into(),
                    }
                    row.counter = 9;
                    Ok(())
                })
                .unwrap_err(),
            Error::Storage
        );
    }
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = store.update(
                COMMUNITY,
                original.credential_id(),
                |row| -> Result<(), Error> {
                    row.counter = 9;
                    panic!("fixture closure panic");
                },
            );
        }))
        .is_err()
    );
    assert_eq!(store.list(COMMUNITY, MEMBER).unwrap()[0].counter(), 0);
    store
        .update(COMMUNITY, original.credential_id(), |row| {
            row.counter = 1;
            Ok(())
        })
        .unwrap();
}

#[test]
fn independent_pools_serialize_equal_counter_authentication() {
    let fixture = Fixture::new();
    let first = service(fixture.store(COMMUNITY));
    let mut token = SoftToken::new(true).unwrap().0;
    register(&first, &mut token);
    let mut cloned = SoftToken::from_cbor(&token.to_cbor().unwrap()).unwrap();
    let db = fixture.reopen();
    let second =
        service(LibsqlStore::new(&db, COMMUNITY, fixture.runtime.handle().clone()).unwrap());
    let (pa, a) = assertion(&first, &mut token);
    let (pb, b) = assertion(&second, &mut cloned);
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        let a = scope.spawn(|| {
            barrier.wait();
            first.finish_authentication(pa, &a)
        });
        let b = scope.spawn(|| {
            barrier.wait();
            second.finish_authentication(pb, &b)
        });
        let results = [a.join().unwrap(), b.join().unwrap()];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(Error::CounterRegression)))
                .count(),
            1
        );
    });
    assert_eq!(first.list(MEMBER).unwrap()[0].counter(), 1);
}

#[test]
fn concurrent_duplicate_inserts_have_one_winner() {
    let fixture = Fixture::new();
    let source = Fixture::new();
    let original = record(source.store(COMMUNITY));
    let store = fixture.store(COMMUNITY);
    let barrier = Barrier::new(2);
    std::thread::scope(|scope| {
        let insert = || {
            barrier.wait();
            store.insert(original.clone())
        };
        let a = scope.spawn(insert);
        let b = scope.spawn(insert);
        let results = [a.join().unwrap(), b.join().unwrap()];
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(Error::DuplicateCredential)))
                .count(),
            1
        );
    });
}

#[test]
fn exact_queries_use_composite_indexes() {
    let fixture = Fixture::new();
    let store = fixture.store(COMMUNITY);
    let original = record(store.clone());
    let bytes = serde_cbor_2::to_vec(&original).unwrap();
    fixture.runtime.block_on(async {
        for (sql, parameters, expected) in [
            (
                LIST,
                vec![Value::Text(MEMBER.to_string())],
                Some("PRIMARY KEY (community_id=? AND member=?)"),
            ),
            (
                GET,
                vec![Value::Blob(original.credential_id.as_ref().to_vec())],
                Some("cpky_passkeys_credential (community_id=? AND credential_id=?)"),
            ),
            (
                EXISTS,
                vec![Value::Blob(original.credential_id.as_ref().to_vec())],
                Some("cpky_passkeys_credential (community_id=? AND credential_id=?)"),
            ),
            (
                INSERT,
                vec![
                    Value::Blob(vec![0]),
                    Value::Text(MEMBER.to_string()),
                    Value::Blob(bytes.clone()),
                ],
                None,
            ),
            (
                UPDATE,
                vec![
                    Value::Blob(bytes),
                    Value::Blob(original.credential_id.as_ref().to_vec()),
                ],
                Some("cpky_passkeys_credential (community_id=? AND credential_id=?)"),
            ),
        ] {
            let plan = store.scope.explain(sql, parameters).await.unwrap();
            plan.assert_indexed().unwrap();
            if let Some(index) = expected {
                assert!(
                    plan.details().iter().any(|d| d.contains(index)),
                    "{sql}: {plan:?}"
                );
            }
        }
    });
}

#[test]
fn corrupt_payloads_and_mismatched_index_fields_fail_closed() {
    let fixture = Fixture::new();
    let store = fixture.store(COMMUNITY);
    let original = record(store.clone());
    for field in 0..4 {
        let mut corrupt = original.clone();
        match field {
            0 => corrupt.community = "two".into(),
            1 => corrupt.member = OTHER,
            2 => corrupt.credential_id = vec![255].into(),
            _ => {}
        }
        let bytes = if field == 3 {
            vec![255]
        } else {
            serde_cbor_2::to_vec(&corrupt).unwrap()
        };
        fixture
            .runtime
            .block_on(
                store
                    .scope
                    .execute(UPDATE, params![bytes, original.credential_id.as_ref()]),
            )
            .unwrap();
        assert_eq!(store.list(COMMUNITY, MEMBER).unwrap_err(), Error::Storage);
        assert_eq!(
            store
                .update(
                    COMMUNITY,
                    original.credential_id(),
                    |_| -> Result<(), Error> { panic!("corrupt row") }
                )
                .unwrap_err(),
            Error::Storage
        );
    }
}

#[test]
fn commit_failure_never_returns_the_successful_closure_result() {
    let fixture = Fixture::new();
    fixture
        .runtime
        .block_on(fixture.db.migrate(&[
            Migration::new(1, "cpky_passkeys", LIBSQL_SCHEMA),
            Migration::new(
                2,
                "commit_failure_fixture",
                "
            CREATE TABLE parents (community_id TEXT NOT NULL, id TEXT NOT NULL,
                PRIMARY KEY (community_id, id)) WITHOUT ROWID;
            CREATE TABLE children (community_id TEXT NOT NULL, id TEXT NOT NULL,
                parent TEXT NOT NULL, PRIMARY KEY (community_id, id),
                FOREIGN KEY (community_id, parent) REFERENCES parents (community_id, id)
                DEFERRABLE INITIALLY DEFERRED) WITHOUT ROWID;
        ",
            ),
        ]))
        .unwrap();
    let store = fixture.store(COMMUNITY);
    store
        .run(async {
            let mut tx = store.scope.tx().await.unwrap();
            tx.execute(
                "INSERT INTO children (id, parent) VALUES (?1, ?2)",
                ["child", "missing"],
            )
            .await
            .unwrap();
            assert_eq!(
                complete(tx, Ok("must not escape")).await.unwrap_err(),
                Error::Storage
            );
            assert!(
                store
                    .scope
                    .query("SELECT id FROM children WHERE id = ?1", ["child"])
                    .await
                    .unwrap()
                    .is_empty()
            );
            Ok(())
        })
        .unwrap();
}

#[test]
fn expired_transaction_does_not_commit_or_retry_a_closure() {
    let fixture = Fixture::new();
    let url = Url::from_file_path(fixture.directory.path().join("community.db")).unwrap();
    let mut config = Config::new(url.as_str(), "");
    config.timeout = Duration::from_secs(1);
    config.busy_timeout = Duration::ZERO;
    let db = fixture.runtime.block_on(Db::open(config)).unwrap();
    migrate(&fixture.runtime, &db);
    let store = LibsqlStore::new(&db, COMMUNITY, fixture.runtime.handle().clone()).unwrap();
    let original = record(store.clone());
    let calls = Cell::new(0);
    assert_eq!(
        store
            .update(COMMUNITY, original.credential_id(), |row| {
                calls.set(calls.get() + 1);
                row.counter = 9;
                std::thread::sleep(Duration::from_millis(1100));
                Ok("must not escape")
            })
            .unwrap_err(),
        Error::Storage
    );
    assert_eq!(calls.get(), 1);
    assert_eq!(store.list(COMMUNITY, MEMBER).unwrap()[0].counter(), 0);
}

#[test]
fn migrations_are_idempotent_and_missing_schema_errors_are_redacted() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture
            .runtime
            .block_on(
                fixture
                    .db
                    .migrate(&[Migration::new(1, "cpky_passkeys", LIBSQL_SCHEMA)])
            )
            .unwrap(),
        0
    );
    let url = Url::from_file_path(fixture.directory.path().join("empty.db")).unwrap();
    let db = fixture
        .runtime
        .block_on(Db::open(Config::new(url.as_str(), "")))
        .unwrap();
    let store = LibsqlStore::new(&db, COMMUNITY, fixture.runtime.handle().clone()).unwrap();
    let error = store.list(COMMUNITY, MEMBER).unwrap_err();
    assert_eq!(error, Error::Storage);
    assert!(std::error::Error::source(&error).is_none());
    assert_eq!(format!("{store:?}"), "LibsqlStore([redacted])");
    assert_eq!(error.to_string(), "passkey storage failed");
    assert!(matches!(
        LibsqlStore::new(&db, "", fixture.runtime.handle().clone()),
        Err(Error::Configuration)
    ));
    let current = Builder::new_current_thread().enable_all().build().unwrap();
    assert!(matches!(
        LibsqlStore::new(&db, COMMUNITY, current.handle().clone()),
        Err(Error::Configuration)
    ));
}

#[test]
fn async_callers_use_spawn_blocking() {
    let fixture = Fixture::new();
    let store = fixture.store(COMMUNITY);
    fixture.runtime.block_on(async move {
        tokio::task::spawn_blocking(move || {
            record(store.clone());
            assert_eq!(store.list(COMMUNITY, MEMBER).unwrap().len(), 1);
        })
        .await
        .unwrap();
    });
}

#[test]
fn row_limits_fail_instead_of_returning_partial_member_lists() {
    let fixture = Fixture::new();
    let store = fixture.store(COMMUNITY);
    record(store.clone());
    record(store);
    let url = Url::from_file_path(fixture.directory.path().join("community.db")).unwrap();
    let mut config = Config::new(url.as_str(), "");
    config.max_rows = 1;
    let db = fixture.runtime.block_on(Db::open(config)).unwrap();
    migrate(&fixture.runtime, &db);
    let store = LibsqlStore::new(&db, COMMUNITY, fixture.runtime.handle().clone()).unwrap();
    assert_eq!(store.list(COMMUNITY, MEMBER).unwrap_err(), Error::Storage);
}

#[test]
fn adapter_operations_suppress_dependency_tracing() {
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tracing_subscriber::prelude::*;

    struct Count(Arc<AtomicUsize>);
    impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Count {
        fn on_event(&self, _: &tracing::Event<'_>, _: tracing_subscriber::layer::Context<'_, S>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    let fixture = Fixture::new();
    let source = Fixture::new();
    let original = record(source.store(COMMUNITY));
    let store = fixture.store(COMMUNITY);
    let count = Arc::new(AtomicUsize::new(0));
    let subscriber = tracing_subscriber::registry().with(Count(count.clone()));
    tracing::subscriber::with_default(subscriber, || {
        store.insert(original.clone()).unwrap();
        assert_eq!(store.list(COMMUNITY, MEMBER).unwrap().len(), 1);
        store
            .update(COMMUNITY, original.credential_id(), |row| {
                row.revoked = true;
                Ok(())
            })
            .unwrap();
        assert_eq!(
            store.insert(original).unwrap_err(),
            Error::DuplicateCredential
        );
        assert_eq!(count.load(Ordering::SeqCst), 0);
        tracing::info!("subscriber remains active outside the adapter");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    });
}

#[test]
fn turso_round_trip_when_configured() {
    let (Ok(url), Ok(token)) = (std::env::var("TURSO_URL"), std::env::var("TURSO_TOKEN")) else {
        return;
    };
    if url.is_empty() || token.is_empty() {
        return;
    }
    let runtime = runtime();
    let db = runtime.block_on(Db::open(Config::new(url, token))).unwrap();
    migrate(&runtime, &db);
    let store = LibsqlStore::new(&db, COMMUNITY, runtime.handle().clone()).unwrap();
    let server = service(store.clone());
    let mut token = SoftToken::new(true).unwrap().0;
    let original = register(&server, &mut token);
    let (pending, response) = assertion(&server, &mut token);
    server.finish_authentication(pending, &response).unwrap();
    server.revoke(MEMBER, original.credential_id()).unwrap();
    runtime
        .block_on(store.scope.execute(
            "DELETE FROM cpky_passkeys WHERE credential_id = ?1",
            params![original.credential_id.as_ref()],
        ))
        .unwrap();
}

#[test]
fn additional_key_survives_removal_and_reopen_with_atomic_authorizer_check() {
    let fixture = Fixture::new();
    let server = service(fixture.store(COMMUNITY));
    let mut first = SoftToken::new(true).unwrap().0;
    let original = register(&server, &mut first);
    let (pending, response) = assertion(&server, &mut first);
    let auth = server.finish_authentication(pending, &response).unwrap();
    let mut second = SoftToken::new(true).unwrap().0;
    let (mut options, pending) = server.start_additional_registration(&auth).unwrap();
    options
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let response: crate::RegisterPublicKeyCredential = second
        .perform_register(Url::parse(ORIGIN).unwrap(), options.public_key, 300_000)
        .unwrap()
        .into();
    let added = server
        .finish_registration(pending, &response, CreationMonth::new(2026, 10).unwrap())
        .unwrap();
    let (mut options, pending) = server.start_additional_registration(&auth).unwrap();
    options
        .public_key
        .authenticator_selection
        .as_mut()
        .unwrap()
        .require_resident_key = false;
    let response: crate::RegisterPublicKeyCredential = SoftToken::new(true)
        .unwrap()
        .0
        .perform_register(Url::parse(ORIGIN).unwrap(), options.public_key, 300_000)
        .unwrap()
        .into();
    let reopened = fixture.reopen();
    let other_pool =
        service(LibsqlStore::new(&reopened, COMMUNITY, fixture.runtime.handle().clone()).unwrap());
    other_pool.revoke(MEMBER, original.credential_id()).unwrap();
    assert!(matches!(
        server.finish_registration(pending, &response, CreationMonth::new(2026, 10).unwrap()),
        Err(Error::Revoked)
    ));
    assert_eq!(other_pool.list(MEMBER).unwrap().len(), 2);
    let (pending, response) = assertion(&other_pool, &mut second);
    let authentication = other_pool
        .finish_authentication(pending, &response)
        .unwrap();
    assert_eq!(authentication.member(), MEMBER);
    assert_eq!(authentication.credential_id(), added.credential_id());
}
