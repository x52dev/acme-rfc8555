use acme::Certificate;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroizing;

fn issue_certificate(valid_for: Duration) -> (KeyPair, rcgen::Certificate) {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["example.com".to_owned()]).unwrap();

    let now = OffsetDateTime::now_utc();
    params.not_before = now - Duration::days(60);
    params.not_after = now + valid_for;

    let certificate = params.self_signed(&key).unwrap();

    (key, certificate)
}

#[test]
fn parse_accepts_a_valid_p256_key_and_certificate() {
    let (key, certificate) = issue_certificate(Duration::days(30));

    let parsed =
        Certificate::parse(Zeroizing::new(key.serialize_pem()), certificate.pem()).unwrap();

    assert_eq!(
        parsed.certificate_chain().unwrap(),
        vec![certificate.der().to_vec()]
    );
}

#[test]
fn parse_rejects_a_malformed_certificate() {
    let (key, _) = issue_certificate(Duration::days(30));

    assert!(Certificate::parse(
        Zeroizing::new(key.serialize_pem()),
        "bad certificate".into()
    )
    .is_err());
}

#[test]
fn parse_rejects_an_empty_certificate_chain() {
    let (key, _) = issue_certificate(Duration::days(30));

    assert!(Certificate::parse(Zeroizing::new(key.serialize_pem()), String::new()).is_err());
}

#[test]
fn parse_rejects_a_malformed_certificate_after_a_valid_one() {
    let (key, certificate) = issue_certificate(Duration::days(30));
    let chain = format!(
        "{}-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n",
        certificate.pem()
    );

    assert!(Certificate::parse(Zeroizing::new(key.serialize_pem()), chain).is_err());
}

#[test]
fn parse_rejects_a_malformed_private_key() {
    let (_, certificate) = issue_certificate(Duration::days(30));

    assert!(
        Certificate::parse(Zeroizing::new("bad private key".into()), certificate.pem()).is_err()
    );
}

#[test]
fn certificate_chain_returns_each_certificate_in_pem_order() {
    let (key, end_entity) = issue_certificate(Duration::days(30));
    let (_, issuer) = issue_certificate(Duration::days(50));
    let chain = format!("{}{}", end_entity.pem(), issuer.pem());

    let parsed = Certificate::parse(Zeroizing::new(key.serialize_pem()), chain).unwrap();

    assert_eq!(
        parsed.certificate_chain().unwrap(),
        vec![end_entity.der().to_vec(), issuer.der().to_vec()]
    );
}

#[test]
fn private_key_der_matches_the_original_pkcs8_key() {
    let (key, certificate) = issue_certificate(Duration::days(30));
    let parsed =
        Certificate::parse(Zeroizing::new(key.serialize_pem()), certificate.pem()).unwrap();

    assert_eq!(parsed.private_key_der().unwrap(), key.serialize_der());
}

#[test]
fn valid_days_left_uses_the_certificate_expiry() {
    let (key, certificate) = issue_certificate(Duration::days(30));
    let parsed =
        Certificate::parse(Zeroizing::new(key.serialize_pem()), certificate.pem()).unwrap();

    assert_eq!(parsed.valid_days_left().unwrap(), 29);
}

#[test]
fn valid_days_left_is_negative_after_expiry() {
    let (key, certificate) = issue_certificate(Duration::days(-3));
    let parsed =
        Certificate::parse(Zeroizing::new(key.serialize_pem()), certificate.pem()).unwrap();

    assert!(parsed.valid_days_left().unwrap() < 0);
}
