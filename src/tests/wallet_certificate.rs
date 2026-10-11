//! Original wallet registration/authentication and the same certificate format.
use super::*;

const WALLET_RP: &str = "wallet.example.com";
const WALLET_ORIGIN: &str = "https://wallet.example.com";

fn wallet(store: MemoryStore) -> Passkeys<MemoryStore> {
    Passkeys::new(
        store,
        "wallet",
        WALLET_RP,
        &[Url::parse(WALLET_ORIGIN).unwrap()],
    )
    .unwrap()
}

#[test]
fn wallet_certificate_uses_only_the_actual_current_wallet_key_and_local_member() {
    let store = MemoryStore::default();
    let wallet = wallet(store.clone());
    assert_eq!(
        wallet.wallet_configuration().unwrap(),
        (WALLET_RP, &[format!("{WALLET_ORIGIN}/")][..])
    );
    let mut token = token();
    let (challenge, pending) = wallet.start_registration(MEMBER).unwrap();
    let response = registration(&mut token, challenge, WALLET_ORIGIN);
    let record = wallet
        .finish_registration(pending, &response, month())
        .unwrap();
    let (challenge, pending) = wallet.start_authentication(MEMBER).unwrap();
    let response = assertion(&mut token, challenge, WALLET_ORIGIN);
    let authentication = wallet.finish_authentication(pending, &response).unwrap();
    let projected = wallet
        .wallet_registration_certificate(&authentication)
        .unwrap();
    assert_eq!(projected.community(), "wallet");
    assert_eq!(projected.member(), MEMBER.to_string());
    assert_eq!(projected.credential_id(), record.credential_id().as_ref());

    let community = service(store, "community");
    assert!(community.wallet_configuration().is_err());
    assert!(
        community
            .wallet_registration_certificate(&authentication)
            .is_err()
    );
    let (community, mut community_token, _) = setup();
    let community_authentication = login(&community, &mut community_token);
    assert!(
        wallet
            .wallet_registration_certificate(&community_authentication)
            .is_err()
    );
    assert!(
        community
            .wallet_registration_certificate(&community_authentication)
            .is_err()
    );

    let runtime = tokio::runtime::Runtime::new().unwrap();
    let now = 1_800_000_000;
    let mut signer = runtime
        .block_on(csgn::PersistentSigner::create(
            csgn::MemoryStore::default(),
            "wallet",
            csgn::SecretKey::from_seed(&mut [46; 32]),
            now,
            1000,
        ))
        .unwrap();
    let bytes = runtime.block_on(projected.sign(&mut signer, now)).unwrap();
    let certificate =
        crate::certificate::verify(signer.key_ring().unwrap(), &bytes, &MEMBER.to_string(), now)
            .unwrap();
    assert_eq!(certificate.credential_id(), record.credential_id().as_ref());
    assert!(
        crate::certificate::verify(
            signer.key_ring().unwrap(),
            &bytes,
            "community-pseudonym",
            now
        )
        .is_err()
    );
    assert!(
        crate::certificate::verify(
            signer.key_ring().unwrap(),
            &bytes,
            &MEMBER.to_string(),
            now + 1000
        )
        .is_err()
    );
    wallet.revoke(MEMBER, record.credential_id()).unwrap();
    assert!(matches!(
        wallet.wallet_registration_certificate(&authentication),
        Err(Error::Revoked)
    ));
}
