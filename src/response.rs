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

#[cfg(feature = "server")]
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
                        return Err(de::Error::custom("client secret extension refused"));
                    }
                    if fields.contains_key(&key) {
                        return Err(de::Error::custom("duplicate client extension"));
                    }
                    let value: Value = input.next_value()?;
                    if matches!(key.as_str(), "hmacGetSecret" | "hmac_get_secret")
                        && !value.is_null()
                    {
                        return Err(de::Error::custom("client secret extension refused"));
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
    webauthn_rs_proto::RegisterPublicKeyCredential,
    "Registration response with a secret-rejecting JSON boundary."
);
response!(
    PublicKeyCredential,
    webauthn_rs_proto::PublicKeyCredential,
    "Assertion response with a secret-rejecting JSON boundary."
);

#[cfg(feature = "server")]
impl PublicKeyCredential {
    pub(crate) fn check_extensions(&self) -> Result<(), Error> {
        if self.extensions.hmac_get_secret.is_some() {
            return Err(Error::ClientSecretExtension);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn portable_response_guard_retains_ambiguity_and_secret_refusals() {
        for (raw, expected) in [
            (
                r#"{"id":"one","id":"two"}"#,
                "duplicate passkey response field",
            ),
            (
                r#"{"extensions":{},"clientExtensionResults":{}}"#,
                "duplicate passkey response field",
            ),
            (
                r#"{"extensions":{"unknown":true,"unknown":false}}"#,
                "duplicate client extension",
            ),
            (
                r#"{"extensions":{"prf":false}}"#,
                "client secret extension refused",
            ),
            (
                r#"{"extensions":{"prf":null}}"#,
                "client secret extension refused",
            ),
            (
                r#"{"extensions":{"hmacGetSecret":{"output1":"DO-NOT-ECHO"}}}"#,
                "client secret extension refused",
            ),
            (
                r#"{"clientExtensionResults":{"hmac_get_secret":false}}"#,
                "client secret extension refused",
            ),
        ] {
            let registration =
                serde_json::from_str::<RegisterPublicKeyCredential>(raw).unwrap_err();
            let assertion = serde_json::from_str::<PublicKeyCredential>(raw).unwrap_err();
            for error in [registration, assertion] {
                assert!(error.to_string().contains(expected));
                assert!(!error.to_string().contains("DO-NOT-ECHO"));
            }
        }
        for raw in ["[]", r#"{"extensions":[]}"#] {
            assert!(serde_json::from_str::<RegisterPublicKeyCredential>(raw).is_err());
            assert!(serde_json::from_str::<PublicKeyCredential>(raw).is_err());
        }
    }

    #[test]
    fn portable_response_preserves_original_signed_fields_without_verifying_them() {
        // Parsing exposes the original bytes; only the original assertion verifier
        // can establish authority. These deliberately short bytes are not a proof.
        let raw = r#"{"id":"AQID","rawId":"AQID","type":"public-key","response":{"clientDataJSON":"BAUG","authenticatorData":"BwgJ","signature":"CgsM","userHandle":"DQ4P"},"clientExtensionResults":{}}"#;
        let response: PublicKeyCredential = serde_json::from_str(raw).unwrap();
        assert_eq!(response.raw_id.as_ref(), &[1, 2, 3]);
        assert_eq!(response.response.client_data_json.as_ref(), &[4, 5, 6]);
        assert_eq!(response.response.authenticator_data.as_ref(), &[7, 8, 9]);
        assert_eq!(response.response.signature.as_ref(), &[10, 11, 12]);
        assert_eq!(
            response.response.user_handle.as_ref().unwrap().as_ref(),
            &[13, 14, 15]
        );
        assert_eq!(format!("{response:?}"), "PublicKeyCredential([redacted])");
        let upstream: &webauthn_rs_proto::PublicKeyCredential = &response;
        let reparsed: PublicKeyCredential =
            serde_json::from_value(serde_json::to_value(upstream).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&response).unwrap(),
            serde_json::to_value(reparsed).unwrap()
        );
    }
}
