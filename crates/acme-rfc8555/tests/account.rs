use acme::{Directory, DirectoryUrl};

#[tokio::test]
async fn load_account_preserves_the_account_key() {
    let server = acme_test_server::with_directory_server();
    let directory = Directory::fetch(DirectoryUrl::Other(&server.dir_url))
        .await
        .unwrap();
    let registered = directory.register_account(None).await.unwrap();
    let pem = registered.acme_private_key_pem().unwrap();

    let loaded = directory.load_account(&pem, None).await.unwrap();

    assert_eq!(loaded.acme_private_key_pem().unwrap(), pem);
    assert!(loaded.api_account().is_status_valid());
}

#[tokio::test]
async fn load_existing_account_preserves_the_account_key() {
    let server = acme_test_server::with_directory_server();
    let directory = Directory::fetch(DirectoryUrl::Other(&server.dir_url))
        .await
        .unwrap();
    let registered = directory.register_account(None).await.unwrap();
    let pem = registered.acme_private_key_pem().unwrap();

    let loaded = directory.load_existing_account(&pem).await.unwrap();

    assert_eq!(loaded.acme_private_key_pem().unwrap(), pem);
    assert!(loaded.api_account().is_status_valid());
}

#[tokio::test]
async fn load_existing_account_rejects_invalid_pem() {
    let server = acme_test_server::with_directory_server();
    let directory = Directory::fetch(DirectoryUrl::Other(&server.dir_url))
        .await
        .unwrap();

    assert!(directory
        .load_existing_account("not a private key")
        .await
        .is_err());
}

#[tokio::test]
async fn new_order_deduplicates_domain_names() {
    let server = acme_test_server::with_directory_server();
    let directory = Directory::fetch(DirectoryUrl::Other(&server.dir_url))
        .await
        .unwrap();
    let account = directory.register_account(None).await.unwrap();

    let order = account
        .new_order("acme-test.example.com", &["acme-test.example.com"])
        .await
        .unwrap();

    assert_eq!(order.api_order().domains(), ["acme-test.example.com"]);
}
