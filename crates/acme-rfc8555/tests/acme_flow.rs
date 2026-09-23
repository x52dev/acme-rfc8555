use std::time::Duration;

use acme::{create_p256_key, Certificate, Directory, DirectoryUrl, RevocationReason};
use acme_test_server::{start_server, AcmeServerConfig};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

#[tokio::test]
async fn certificate_is_issued_after_http_authorization() {
    let server = start_server(AcmeServerConfig::default());
    let directory = Directory::fetch(DirectoryUrl::Other(&server.directory_url))
        .await
        .unwrap();
    let account = directory.register_account(None).await.unwrap();
    let mut order = account.new_order("example.com", &[]).await.unwrap();

    assert!(!order.is_validated());
    assert!(order.confirm_validations().is_none());

    let authorizations = order.authorizations().await.unwrap();
    assert_eq!(authorizations.len(), 1);
    assert!(authorizations[0].need_challenge());

    let challenge = authorizations[0].http_challenge().unwrap();
    assert!(challenge.need_validate());
    challenge.validate(Duration::from_millis(1)).await.unwrap();

    order.refresh().await.unwrap();
    assert!(order.is_validated());

    let certificate_key = create_p256_key();
    let issued = order
        .confirm_validations()
        .unwrap()
        .finalize(certificate_key, Duration::from_millis(1))
        .await
        .unwrap()
        .download_cert()
        .await
        .unwrap();

    assert_eq!(issued.certificate_chain().unwrap().len(), 1);
    Certificate::parse(
        Zeroizing::new(issued.private_key().to_owned()),
        issued.certificate().to_owned(),
    )
    .unwrap();
    assert_eq!(server.finalization_polls(), 2);
}

#[tokio::test]
async fn failed_http_authorization_returns_the_provider_reason() {
    let server = start_server(AcmeServerConfig {
        reject_challenge: true,
        ..Default::default()
    });
    let directory = Directory::fetch(DirectoryUrl::Other(&server.directory_url))
        .await
        .unwrap();
    let account = directory.register_account(None).await.unwrap();
    let order = account.new_order("example.com", &[]).await.unwrap();
    let authorizations = order.authorizations().await.unwrap();
    let challenge = authorizations[0].http_challenge().unwrap();

    let error = challenge
        .validate(Duration::from_millis(1))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("challenge proof was not found"));
    assert!(order.confirm_validations().is_none());
}

#[tokio::test]
async fn bad_nonce_error_retries_the_order_request() {
    let server = start_server(AcmeServerConfig {
        reject_first_order_nonce: true,
        ..Default::default()
    });
    let directory = Directory::fetch(DirectoryUrl::Other(&server.directory_url))
        .await
        .unwrap();
    let account = directory.register_account(None).await.unwrap();

    let order = account.new_order("example.com", &[]).await.unwrap();

    assert!(!order.is_validated());
    assert_eq!(server.order_requests(), 2);
}

#[tokio::test]
async fn account_can_be_loaded_from_its_saved_key() {
    let server = start_server(AcmeServerConfig::default());
    let directory = Directory::fetch(DirectoryUrl::Other(&server.directory_url))
        .await
        .unwrap();
    let registered = directory.register_account(None).await.unwrap();
    let saved_key = registered.acme_private_key_pem().unwrap();

    let loaded = directory.load_existing_account(&saved_key).await.unwrap();

    assert_eq!(loaded.acme_private_key_pem().unwrap(), saved_key);
    assert_eq!(server.account_requests(), 2);
}

#[tokio::test]
async fn loading_an_unknown_account_returns_the_provider_error() {
    let server = start_server(AcmeServerConfig {
        reject_unknown_account: true,
        ..Default::default()
    });
    let directory = Directory::fetch(DirectoryUrl::Other(&server.directory_url))
        .await
        .unwrap();
    let key = create_p256_key().to_pkcs8_pem().unwrap();

    let error = directory.load_existing_account(&key).await.unwrap_err();

    assert!(error.to_string().contains("accountDoesNotExist"));
}

#[tokio::test]
async fn account_can_revoke_a_certificate() {
    let server = start_server(AcmeServerConfig::default());
    let directory = Directory::fetch(DirectoryUrl::Other(&server.directory_url))
        .await
        .unwrap();
    let account = directory.register_account(None).await.unwrap();
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let certificate_pem = CertificateParams::new(vec!["example.com".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap()
        .pem();
    let certificate =
        Certificate::parse(Zeroizing::new(key.serialize_pem()), certificate_pem).unwrap();

    account
        .revoke_certificate(&certificate, RevocationReason::KeyCompromise)
        .await
        .unwrap();

    assert_eq!(server.revocation_requests(), 1);
}

#[tokio::test]
async fn challenge_proofs_use_the_same_key_authorization() {
    let server = start_server(AcmeServerConfig::default());
    let directory = Directory::fetch(DirectoryUrl::Other(&server.directory_url))
        .await
        .unwrap();
    let account = directory.register_account(None).await.unwrap();
    let order = account.new_order("example.com", &[]).await.unwrap();
    let authorizations = order.authorizations().await.unwrap();
    let authorization = &authorizations[0];

    let http = authorization.http_challenge().unwrap();
    let dns = authorization.dns_challenge().unwrap();
    let tls_alpn = authorization.tls_alpn_challenge().unwrap();
    let key_authorization = http.http_proof().unwrap();

    assert!(key_authorization.starts_with("test-token."));
    assert_eq!(
        dns.dns_proof().unwrap(),
        URL_SAFE_NO_PAD.encode(Sha256::digest(key_authorization.as_bytes()))
    );
    assert_eq!(
        tls_alpn.tls_alpn_proof().unwrap(),
        <[u8; 32]>::from(Sha256::digest(key_authorization.as_bytes()))
    );
}

#[tokio::test]
async fn new_order_deduplicates_names_and_preserves_the_requested_order() {
    let server = start_server(AcmeServerConfig {
        reverse_order_identifiers: true,
        ..Default::default()
    });
    let directory = Directory::fetch(DirectoryUrl::Other(&server.directory_url))
        .await
        .unwrap();
    let account = directory.register_account(None).await.unwrap();

    let order = account
        .new_order("example.com", &["www.example.com", "example.com"])
        .await
        .unwrap();

    assert_eq!(
        order.api_order().domains(),
        ["example.com", "www.example.com"]
    );
}

#[tokio::test]
async fn finalization_reports_an_invalid_order() {
    let server = start_server(AcmeServerConfig {
        reject_finalization: true,
        ..Default::default()
    });
    let directory = Directory::fetch(DirectoryUrl::Other(&server.directory_url))
        .await
        .unwrap();
    let account = directory.register_account(None).await.unwrap();
    let mut order = account.new_order("example.com", &[]).await.unwrap();
    let authorizations = order.authorizations().await.unwrap();
    authorizations[0]
        .http_challenge()
        .unwrap()
        .validate(Duration::from_millis(1))
        .await
        .unwrap();
    order.refresh().await.unwrap();

    let error = order
        .confirm_validations()
        .unwrap()
        .finalize(create_p256_key(), Duration::from_millis(1))
        .await
        .err()
        .unwrap();

    assert!(error.to_string().contains("Invalid"));
    assert_eq!(server.finalization_polls(), 2);
}

#[tokio::test]
async fn certificate_download_reports_a_missing_url() {
    let server = start_server(AcmeServerConfig {
        omit_certificate_url: true,
        ..Default::default()
    });
    let directory = Directory::fetch(DirectoryUrl::Other(&server.directory_url))
        .await
        .unwrap();
    let account = directory.register_account(None).await.unwrap();
    let mut order = account.new_order("example.com", &[]).await.unwrap();
    let authorizations = order.authorizations().await.unwrap();
    authorizations[0]
        .http_challenge()
        .unwrap()
        .validate(Duration::from_millis(1))
        .await
        .unwrap();
    order.refresh().await.unwrap();
    let finalized = order
        .confirm_validations()
        .unwrap()
        .finalize(create_p256_key(), Duration::from_millis(1))
        .await
        .unwrap();

    let error = finalized.download_cert().await.unwrap_err();

    assert!(error.to_string().contains("certificate url"));
}
