//! Execute the exact original-server vectors in a real browser.
#![cfg(all(target_arch = "wasm32", not(feature = "server")))]
use ckyh::lineage::{Assertion, PublicCredential, verify};
use serde::Deserialize;
use wasm_bindgen_test::*;
wasm_bindgen_test_configure!(run_in_browser);

#[derive(Deserialize)]
struct Fixture {
    descriptor: PublicCredential,
    assertion: Assertion,
    challenge: [u8; 32],
}

#[wasm_bindgen_test]
fn native_keyhole_es256_and_rs256_assertions_verify_in_the_browser() {
    for text in [
        include_str!(concat!(env!("CKYH_LINEAGE_FIXTURE_DIR"), "/es256.json")),
        include_str!(concat!(env!("CKYH_LINEAGE_FIXTURE_DIR"), "/rs256.json")),
    ] {
        let mut fixture: Fixture = serde_json::from_str(text).unwrap();
        verify(&fixture.descriptor, &fixture.assertion, fixture.challenge).unwrap();
        fixture.challenge[0] ^= 1;
        assert!(verify(&fixture.descriptor, &fixture.assertion, fixture.challenge).is_err());
        fixture.challenge[0] ^= 1;
        fixture.assertion.signature[0] ^= 1;
        assert!(verify(&fixture.descriptor, &fixture.assertion, fixture.challenge).is_err());
    }
}
