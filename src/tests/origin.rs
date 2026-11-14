use super::*;

#[test]
fn device_key_authentication_reports_its_origin_and_key() {
    let key = [9u8; 32];
    let auth = Authentication::from_device_key("community".into(), MEMBER, key);
    assert_eq!(auth.origin(), Origin::DeviceKey);
    assert_eq!(auth.device_key(), Some(key));
    let passkey = Authentication::new(
        "community".into(),
        MEMBER,
        CredentialID::from(vec![1u8; 16]),
    );
    assert_eq!(passkey.origin(), Origin::Passkey);
    assert_eq!(passkey.device_key(), None);
}
