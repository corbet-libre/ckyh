use std::{fmt, future::Future};

use crlt::{Community, Db, Row, Transaction, Value, params};
use tokio::runtime::{Handle, RuntimeFlavor};

use crate::{Authentication, CredentialID, CredentialStore, Error, StoredPasskey, Uuid, quiet};

/// Initial ckyh schema for the service's complete crlt migration history.
///
/// Assign a version with `crlt::Migration::new(version, "cpky_passkeys", LIBSQL_SCHEMA)`.
/// Run migrations before constructing the store, including after reopening a DB.
/// Deploy one database per community; the global wallet uses its own database.
pub const LIBSQL_SCHEMA: &str = "
CREATE TABLE cpky_passkeys (
    community_id TEXT NOT NULL,
    credential_id BLOB NOT NULL,
    member TEXT NOT NULL,
    record BLOB NOT NULL,
    PRIMARY KEY (community_id, member, credential_id)
) WITHOUT ROWID;
CREATE UNIQUE INDEX cpky_passkeys_credential ON cpky_passkeys (community_id, credential_id);
";

const LIST: &str = "SELECT community_id, credential_id, member, record
    FROM cpky_passkeys WHERE member = ?1";
const GET: &str = "SELECT community_id, credential_id, member, record
    FROM cpky_passkeys WHERE credential_id = ?1";
const EXISTS: &str = "SELECT credential_id FROM cpky_passkeys WHERE credential_id = ?1";
const INSERT: &str =
    "INSERT INTO cpky_passkeys (credential_id, member, record) VALUES (?1, ?2, ?3)";
const UPDATE: &str = "UPDATE cpky_passkeys SET record = ?1 WHERE credential_id = ?2";

/// Synchronous credential storage over a fixed crlt community capability.
///
/// The service supplies and keeps alive a multithreaded Tokio runtime. Operations
/// block the calling thread: use ordinary synchronous threads or `spawn_blocking`
/// from async code, never call directly inside an async task (`Handle::block_on`
/// would panic). The update closure stays on the caller's thread and needs no
/// `Send` or `'static` bounds. No transaction or closure is automatically retried.
#[derive(Clone)]
pub struct LibsqlStore {
    scope: Community,
    community: String,
    runtime: Handle,
}

impl LibsqlStore {
    fn insert_checked(
        &self,
        record: StoredPasskey,
        authorizer: Option<&Authentication>,
    ) -> Result<(), Error> {
        self.check_scope(&record.community)?;
        let bytes = serde_cbor_2::to_vec(&record).map_err(|_| Error::Storage)?;
        self.run(async {
            let mut tx = self.scope.tx().await.map_err(|_| Error::Storage)?;
            let result = async {
                if let Some(auth) = authorizer {
                    if auth.community() != record.community || auth.member() != record.member {
                        return Err(Error::NotFound);
                    }
                    let rows = tx
                        .query(GET, params![auth.credential_id().as_ref()])
                        .await
                        .map_err(|_| Error::Storage)?;
                    let current = self.decode(rows.first().ok_or(Error::NotFound)?)?;
                    if current.member != record.member || current.rp_id != record.rp_id {
                        return Err(Error::NotFound);
                    }
                    if current.revoked {
                        return Err(Error::Revoked);
                    }
                }
                // BEGIN IMMEDIATE serializes this check with all writers, including
                // stores using independent pools or processes for the same file.
                if !tx
                    .query(EXISTS, params![record.credential_id.as_ref()])
                    .await
                    .map_err(|_| Error::Storage)?
                    .is_empty()
                {
                    return Err(Error::DuplicateCredential);
                }
                let count = tx
                    .execute(
                        INSERT,
                        params![
                            record.credential_id.as_ref(),
                            record.member.to_string(),
                            bytes
                        ],
                    )
                    .await
                    .map_err(|_| Error::Storage)?;
                if count != 1 {
                    return Err(Error::Storage);
                }
                Ok(())
            }
            .await;
            complete(tx, result).await
        })
    }

    /// Bind the store to one community in an already migrated database.
    ///
    /// Only the derived community capability is retained, not migration authority.
    /// The caller owns database routing, runtime lifetime and authorization to
    /// choose a community. Current-thread runtimes are refused because their I/O
    /// and timer drivers cannot be driven by `Handle::block_on` alone.
    pub fn new(db: &Db, community: impl Into<String>, runtime: Handle) -> Result<Self, Error> {
        if runtime.runtime_flavor() != RuntimeFlavor::MultiThread {
            return Err(Error::Configuration);
        }
        let community = community.into();
        let scope = db
            .community(community.clone())
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            scope,
            community,
            runtime,
        })
    }

    fn check_scope(&self, community: &str) -> Result<(), Error> {
        if community == self.community {
            Ok(())
        } else {
            Err(Error::NotFound)
        }
    }

    fn run<T>(&self, future: impl Future<Output = Result<T, Error>>) -> Result<T, Error> {
        quiet(|| self.runtime.block_on(future))
    }

    fn decode(&self, row: &Row) -> Result<StoredPasskey, Error> {
        let Value::Blob(bytes) = row.get_value(3).map_err(|_| Error::Storage)? else {
            return Err(Error::Storage);
        };
        let record: StoredPasskey = serde_cbor_2::from_slice(bytes).map_err(|_| Error::Storage)?;
        let Value::Blob(id) = row.get_value(1).map_err(|_| Error::Storage)? else {
            return Err(Error::Storage);
        };
        if record.community != self.community
            || row.get_str(0).map_err(|_| Error::Storage)? != self.community
            || record.credential_id.as_ref() != id.as_slice()
            || row.get_str(2).map_err(|_| Error::Storage)? != record.member.to_string()
        {
            return Err(Error::Storage);
        }
        Ok(record)
    }
}

impl CredentialStore for LibsqlStore {
    fn list(&self, community: &str, member: Uuid) -> Result<Vec<StoredPasskey>, Error> {
        self.check_scope(community)?;
        self.run(async {
            self.scope
                .query(LIST, [member.to_string()])
                .await
                .map_err(|_| Error::Storage)?
                .iter()
                .map(|row| self.decode(row))
                .collect()
        })
    }

    fn insert(&self, record: StoredPasskey) -> Result<(), Error> {
        self.insert_checked(record, None)
    }

    fn insert_authorized(
        &self,
        record: StoredPasskey,
        authorizer: &Authentication,
    ) -> Result<(), Error> {
        self.insert_checked(record, Some(authorizer))
    }

    fn update<T>(
        &self,
        community: &str,
        credential_id: &CredentialID,
        change: impl FnOnce(&mut StoredPasskey) -> Result<T, Error>,
    ) -> Result<T, Error> {
        self.check_scope(community)?;
        self.run(async {
            let mut tx = self.scope.tx().await.map_err(|_| Error::Storage)?;
            let result = async {
                let rows = tx
                    .query(GET, params![credential_id.as_ref()])
                    .await
                    .map_err(|_| Error::Storage)?;
                let mut record = self.decode(rows.first().ok_or(Error::NotFound)?)?;
                let member = record.member;
                let result = change(&mut record)?;
                if record.community != community
                    || record.credential_id != *credential_id
                    || record.member != member
                {
                    return Err(Error::Storage);
                }
                let bytes = serde_cbor_2::to_vec(&record).map_err(|_| Error::Storage)?;
                let count = tx
                    .execute(UPDATE, params![bytes, credential_id.as_ref()])
                    .await
                    .map_err(|_| Error::Storage)?;
                if count != 1 {
                    return Err(Error::Storage);
                }
                Ok(result)
            }
            .await;
            complete(tx, result).await
        })
    }
}

async fn complete<T>(tx: Transaction, result: Result<T, Error>) -> Result<T, Error> {
    match result {
        Ok(value) => {
            tx.commit().await.map_err(|_| Error::Storage)?;
            Ok(value)
        }
        Err(error) => {
            tx.rollback().await.map_err(|_| Error::Storage)?;
            Err(error)
        }
    }
}

impl fmt::Debug for LibsqlStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("LibsqlStore([redacted])")
    }
}

#[cfg(test)]
#[path = "libsql_store/tests.rs"]
mod tests;
