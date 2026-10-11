use std::fmt;

mod certificate;

use serde::{Deserialize, Serialize};
use webauthn_rs::prelude::{AttestationFormat, COSEKey, Credential, CredentialID, Passkey, Uuid};
use webauthn_rs_core::proto::UserVerificationPolicy;

/// Errors contain static categories only, never client data or upstream diagnostics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Invalid RP, origin or community configuration.
    Configuration,
    /// Year must be 1..=9999 and month 1..=12.
    InvalidMonth,
    /// An assertion or registration failed WebAuthn verification.
    VerificationFailed,
    /// A client sent PRF or legacy hmac-secret extension outputs.
    ClientSecretExtension,
    /// The authenticator did not verify its user.
    UserVerificationRequired,
    /// A nonzero counter failed to advance, or regressed to zero.
    CounterRegression,
    /// This credential is revoked.
    Revoked,
    /// The member has no active passkeys in this scope.
    NoActivePasskeys,
    /// No record exists for the requested scope, owner and credential.
    NotFound,
    /// A credential ID already exists in this community, including tombstones.
    DuplicateCredential,
    /// Initial ownership or an immutable publication already has a different winner.
    Conflict,
    /// Ceremony state belongs to another facade instance.
    WrongCeremony,
    /// The five-minute server-side ceremony deadline elapsed.
    Expired,
    /// Storage failed; no successful authentication may be returned.
    Storage,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Configuration => "invalid passkey configuration",
            Self::InvalidMonth => "invalid creation month",
            Self::VerificationFailed => "passkey verification failed",
            Self::ClientSecretExtension => "client secret extension refused",
            Self::UserVerificationRequired => "user verification required",
            Self::CounterRegression => "passkey counter regression detected",
            Self::Revoked => "passkey revoked",
            Self::NoActivePasskeys => "no active passkeys",
            Self::NotFound => "passkey not found",
            Self::DuplicateCredential => "passkey already registered",
            Self::Conflict => "initial passkey creation conflict",
            Self::WrongCeremony => "ceremony belongs to another instance",
            Self::Expired => "passkey ceremony expired",
            Self::Storage => "passkey storage failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for Error {}

/// Coarse creation date with no day, time or timezone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "MonthFields", into = "MonthFields")]
pub struct CreationMonth {
    year: u16,
    month: u8,
}

impl CreationMonth {
    /// Construct a validated calendar month (years 1..=9999).
    pub fn new(year: u16, month: u8) -> Result<Self, Error> {
        if !(1..=9999).contains(&year) || !(1..=12).contains(&month) {
            return Err(Error::InvalidMonth);
        }
        Ok(Self { year, month })
    }

    /// Calendar year.
    pub fn year(self) -> u16 {
        self.year
    }

    /// Calendar month, 1..=12.
    pub fn month(self) -> u8 {
        self.month
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct MonthFields {
    year: u16,
    month: u8,
}

impl TryFrom<MonthFields> for CreationMonth {
    type Error = Error;

    fn try_from(value: MonthFields) -> Result<Self, Self::Error> {
        Self::new(value.year, value.month)
    }
}

impl From<CreationMonth> for MonthFields {
    fn from(value: CreationMonth) -> Self {
        Self {
            year: value.year,
            month: value.month,
        }
    }
}

/// Trusted-store record: verification material, ownership and minimal metadata.
///
/// Serialization is for the storage adapter, never a browser API. It omits raw
/// attestations, certificates, AAGUIDs, transport hints, extensions and timestamps.
/// Deserialize only from the trusted store, never from member input.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPasskey {
    pub(crate) community: String,
    pub(crate) member: Uuid,
    pub(crate) rp_id: String,
    pub(crate) credential_id: CredentialID,
    public_key: COSEKey,
    pub(crate) counter: u32,
    pub(crate) backup_eligible: bool,
    pub(crate) backup_state: bool,
    authenticator_type: Option<String>,
    created: CreationMonth,
    pub(crate) revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) initial_creation: Option<InitialCreationRecord>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InitialCreationRecord {
    pub(crate) seed: [u8; 32],
    pub(crate) publication: Option<[u8; 32]>,
}

impl StoredPasskey {
    pub(crate) fn new(
        community: String,
        member: Uuid,
        rp_id: String,
        credential: Credential,
        authenticator_type: Option<String>,
        created: CreationMonth,
    ) -> Self {
        Self {
            community,
            member,
            rp_id,
            credential_id: credential.cred_id,
            public_key: credential.cred,
            counter: credential.counter,
            backup_eligible: credential.backup_eligible,
            backup_state: credential.backup_state,
            authenticator_type,
            created,
            revoked: false,
            initial_creation: None,
        }
    }

    /// Community namespace; part of every storage key.
    pub fn community(&self) -> &str {
        &self.community
    }

    /// Opaque, community-local member handle supplied at registration.
    pub fn member(&self) -> Uuid {
        self.member
    }

    /// Credential ID, unique within the community even after revocation.
    pub fn credential_id(&self) -> &CredentialID {
        &self.credential_id
    }

    /// Model/provider name from the supplied catalogue, if known. Not a device name.
    pub fn authenticator_type(&self) -> Option<&str> {
        self.authenticator_type.as_deref()
    }

    /// Coarse month of registration.
    pub fn created(&self) -> CreationMonth {
        self.created
    }

    /// Current WebAuthn signature counter. Zero may mean unsupported.
    pub fn counter(&self) -> u32 {
        self.counter
    }

    /// Current revocation state; no revocation timestamp is recorded.
    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub(crate) fn as_passkey(&self) -> Passkey {
        Credential {
            cred_id: self.credential_id.clone(),
            cred: self.public_key.clone(),
            counter: self.counter,
            transports: None,
            user_verified: true,
            backup_eligible: self.backup_eligible,
            backup_state: self.backup_state,
            registration_policy: UserVerificationPolicy::Required,
            extensions: Default::default(),
            attestation: Default::default(),
            attestation_format: AttestationFormat::None,
        }
        .into()
    }
}

impl fmt::Debug for StoredPasskey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StoredPasskey([redacted])")
    }
}

/// An opaque in-process authentication result. It is not an admission or device grant.
///
/// No public constructor or deserializer exists. Only successful verification and
/// a committed storage update can produce this result through the facade.
#[derive(Clone)]
pub struct Authentication {
    community: String,
    member: Uuid,
    credential: CredentialID,
}

impl Authentication {
    pub(crate) fn new(community: String, member: Uuid, credential: CredentialID) -> Self {
        Self {
            community,
            member,
            credential,
        }
    }

    /// Exact passkey that authenticated this session. Recheck its current
    /// revocation state before every authorized operation.
    pub fn credential_id(&self) -> &CredentialID {
        &self.credential
    }

    /// Community in which authentication succeeded.
    pub fn community(&self) -> &str {
        &self.community
    }

    /// Authenticated community-local member.
    pub fn member(&self) -> Uuid {
        self.member
    }
}

impl fmt::Debug for Authentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Authentication([redacted])")
    }
}
