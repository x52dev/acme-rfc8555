use acme::{create_p256_key, PrivateKey};

#[test]
fn private_key_pem_round_trip() {
    let pem = create_p256_key().to_pkcs8_pem().unwrap();
    let key = PrivateKey::from_pkcs8_pem(&pem).unwrap();

    assert_eq!(key.to_pkcs8_pem().unwrap(), pem);
}

#[test]
fn private_key_rejects_invalid_pem() {
    assert!(PrivateKey::from_pkcs8_pem("not a private key").is_err());
}
