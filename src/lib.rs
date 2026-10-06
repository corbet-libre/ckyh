//! Server-side passkeys for cvld, backed by webauthn-rs.
//!
//! Keep ceremony states in a server-side session and consume them once. A verified
//! authentication identifies a member; it grants neither admission nor permission
//! to enrol a device. See `docs/CONTRACT.md` for storage and integration obligations.
#![forbid(unsafe_code)]

/// Registration certificates carried with offline passkey assertions.
pub mod certificate;
/// Portable verification of passkey-signed lineage challenges.
pub mod lineage;

#[cfg(feature = "server")]
mod server;
#[cfg(feature = "server")]
fn quiet<T>(operation: impl FnOnce() -> T) -> T {
    // Upstream tracing can include credential data. These operations are synchronous,
    // so a scoped empty dispatcher covers the whole verification without changing
    // the embedding application's global subscriber.
    tracing::dispatcher::with_default(
        &tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default()),
        operation,
    )
}

#[cfg(feature = "server")]
pub use server::*;
