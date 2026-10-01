//! Guard the wire boundary before upstream can discard unknown extensions.

use std::{
    fmt,
    marker::PhantomData,
    ops::{Deref, DerefMut},
};

use serde::{
    Deserialize, Deserializer, Serialize,
    de::{self, DeserializeOwned, MapAccess, Visitor},
};
use serde_json::{Map, Value};

use crate::Error;

struct CredentialVisitor<T>(PhantomData<T>);

impl<'de, T: DeserializeOwned> Visitor<'de> for CredentialVisitor<T> {
    type Value = T;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a passkey response without client secrets")
    }

    fn visit_map<M: MapAccess<'de>>(self, mut input: M) -> Result<T, M::Error> {
        let mut fields = Map::new();
        while let Some(mut key) = input.next_key::<String>()? {
            if key == "clientExtensionResults" {
                key = "extensions".into();
            }
            if fields.contains_key(&key) {
                return Err(de::Error::custom("duplicate passkey response field"));
            }
            let value = if key == "extensions" {
                input.next_value::<SecretFreeExtensions>()?.0
            } else {
                input.next_value()?
            };
            fields.insert(key, value);
        }
        serde_json::from_value(Value::Object(fields))
            .map_err(|_| de::Error::custom("invalid passkey response"))
    }
}

struct SecretFreeExtensions(Value);

impl<'de> Deserialize<'de> for SecretFreeExtensions {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct ExtensionsVisitor;
        impl<'de> Visitor<'de> for ExtensionsVisitor {
            type Value = SecretFreeExtensions;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("client extensions without secrets")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut input: M) -> Result<Self::Value, M::Error> {
                let mut fields = Map::new();
                while let Some(key) = input.next_key::<String>()? {
                    // Refuse even null/false/empty values, before reading them.
                    // Include the legacy hmac-secret output names: these are
                    // equally unsuitable for a server authentication response.
                    if matches!(key.as_str(), "prf") {
                        return Err(de::Error::custom(Error::ClientSecretExtension));
                    }
                    if fields.contains_key(&key) {
                        return Err(de::Error::custom("duplicate client extension"));
                    }
                    let value: Value = input.next_value()?;
                    if matches!(key.as_str(), "hmacGetSecret" | "hmac_get_secret")
                        && !value.is_null()
                    {
                        return Err(de::Error::custom(Error::ClientSecretExtension));
                    }
                    fields.insert(key, value);
                }
                Ok(SecretFreeExtensions(Value::Object(fields)))
            }
        }
        deserializer.deserialize_map(ExtensionsVisitor)
    }
}

macro_rules! response {
    ($name:ident, $upstream:ty, $doc:literal) => {
        #[doc = $doc]
        ///
        /// Deserialize untrusted responses directly into this type. Parsing into
        /// an upstream type first loses unknown extensions and bypasses this guard.
        /// Upstream conversions are for trusted in-process authenticators only.
        #[derive(Clone, Serialize)]
        #[serde(transparent)]
        pub struct $name(pub(crate) $upstream);

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                deserializer
                    .deserialize_map(CredentialVisitor(PhantomData))
                    .map(Self)
            }
        }

        impl From<$upstream> for $name {
            fn from(value: $upstream) -> Self {
                Self(value)
            }
        }

        impl Deref for $name {
            type Target = $upstream;
            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }

        impl DerefMut for $name {
            fn deref_mut(&mut self) -> &mut Self::Target {
                &mut self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "([redacted])"))
            }
        }
    };
}

response!(
    RegisterPublicKeyCredential,
    webauthn_rs::prelude::RegisterPublicKeyCredential,
    "Registration response with a secret-rejecting JSON boundary."
);
response!(
    PublicKeyCredential,
    webauthn_rs::prelude::PublicKeyCredential,
    "Assertion response with a secret-rejecting JSON boundary."
);

impl PublicKeyCredential {
    pub(crate) fn check_extensions(&self) -> Result<(), Error> {
        if self.extensions.hmac_get_secret.is_some() {
            return Err(Error::ClientSecretExtension);
        }
        Ok(())
    }
}
