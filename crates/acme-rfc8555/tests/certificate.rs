use acme::{create_p256_key, Certificate};
use zeroize::Zeroizing;

fn certificate_pem() -> String {
    rcgen::generate_simple_self_signed(vec!["example.com".to_owned()])
        .unwrap()
        .cert
        .pem()
}

#[test]
fn certificate_parse_rejects_invalid_certificate() {
    let key = create_p256_key().to_pkcs8_pem().unwrap();

    assert!(Certificate::parse(key, "not a certificate".to_owned()).is_err());
}

#[test]
fn certificate_parse_rejects_invalid_private_key() {
    let key = Zeroizing::new("not a private key".to_owned());

    assert!(Certificate::parse(key, certificate_pem()).is_err());
}

#[test]
fn certificate_parse_preserves_pem_and_exports_key_der() {
    let key = create_p256_key().to_pkcs8_pem().unwrap();
    let certificate_pem = certificate_pem();

    let certificate = Certificate::parse(key.clone(), certificate_pem.clone()).unwrap();

    assert_eq!(certificate.private_key(), key.as_str());
    assert_eq!(certificate.certificate(), certificate_pem);
    assert!(!certificate.private_key_der().unwrap().is_empty());
}

#[test]
fn certificate_valid_days_left_reads_the_certificate() {
    let key = create_p256_key().to_pkcs8_pem().unwrap();
    let certificate = Certificate::parse(key, certificate_pem()).unwrap();

    assert!(certificate.valid_days_left().unwrap() > 0);
}
