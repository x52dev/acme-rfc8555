use std::{
    sync::{Arc, OnceLock},
    thread,
    time::Duration,
};

use acme_lite::{create_p256_key, Directory, DirectoryUrl};
use rustls::server::Acceptor;
use tokio::fs;

const CHALLENGE_DIR: &str = "./acme-challenges";
const DOMAIN_NAME: &str = "example.org";
const CONTACT_EMAIL: &str = "contact@example.org";

static ACME_IDENT: OnceLock<[u8; 32]> = OnceLock::new();

fn acme_tls_server() {
    // Start a TLS server accepting connections as they arrive.
    let listener = std::net::TcpListener::bind(("0.0.0.0", 443)).unwrap();

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        // Read TLS packets until we are ready to accept a connection.
        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };

        let _hello = accepted.client_hello();

        // Generate a server config for the accepted connection, optionally customizing the
        // configuration based on the client hello.
        let config = acme_tls_server_config();
        let mut conn = accepted.into_connection(config).unwrap();

        // Proceed with handling the connection until the ACME client closes the connection.
        _ = conn.complete_io(&mut stream);
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("ensuring challenge dir exists");
    fs::create_dir_all(CHALLENGE_DIR)
        .await
        .expect("should be able to create challenge directory");

    log::info!("starting temporary TLS challenge server");

    let _srv_handle = thread::spawn(acme_tls_server);

    log::info!("fetching LetsEncrypt directory");
    // Create a directory entrypoint.
    // Note: Change to `DirectoryUrl::LetsEncrypt` in production.
    let dir = Directory::from_url(DirectoryUrl::LetsEncryptStaging).await?;

    // Your contact addresses, note the `mailto:`
    let contact = vec![format!("mailto:{CONTACT_EMAIL}")];

    log::info!("generating signing key and registering with ACME provider");
    // You should write it to disk any use `load_account` afterwards.
    let acc = dir.register_account(Some(contact.clone())).await?;

    log::info!("loading account from signing key");
    let signing_key_pem = acc.acme_signing_key_pem()?;
    let acc = dir.load_account(&signing_key_pem, Some(contact)).await?;

    log::info!("ordering a new TLS certificate for our domain");
    let mut order = acc.new_order(DOMAIN_NAME, &[]).await?;

    // If the ownership of the domain(s) have already been authorized in a previous order, you might
    // be able to skip validation. The ACME API provider decides.
    log::info!("waiting for certificate signing request to be validated");
    let ord_csr = loop {
        // Are we done?
        if let Some(ord_csr) = order.confirm_validations() {
            log::info!("certificate signing request validated");
            break ord_csr;
        }

        // Get the possible authorizations (for a single domain this will only be one element).
        let auths = order.authorizations().await?;
        let auth = &auths[0];

        // For TLS, the challenge is a text file that needs to be placed in your web server's root:
        let tls_challenge = auth.tls_alpn_challenge().unwrap();

        // The ACME identifier is a 32-byte hash of the proof.
        let acme_ident = tls_challenge.tls_alpn_proof()?;

        ACME_IDENT.get_or_init(|| acme_ident);

        // After the ID is accessible during a TLS handshake, the `validate`
        // call tells the ACME API to start checking the existence of the proof.
        //
        // The order will change status later to either confirm ownership of the
        // domain, or fail due to a failed TLS handshake. To see the change,
        // we poll the API after 5 seconds.
        tls_challenge.validate(Duration::from_secs(5)).await?;

        // Update the state against the ACME API.
        order.refresh().await?;
    };

    // Ownership is proven. Create a private key for
    // the certificate. These are provided for convenience, you
    // can provide your own keypair instead if you want.
    let signing_key = create_p256_key();

    // Submit the CSR. This causes the ACME provider to enter a
    // state of "processing" that must be polled until the
    // certificate is either issued or rejected. Again we poll
    // for the status change.
    let ord_cert = ord_csr
        .finalize_signing_key(signing_key, Duration::from_secs(5))
        .await?;

    // Finally download the certificate.
    let cert = ord_cert.download_cert().await?;

    // NOTE: Here you would spawn your server and use the private key plus
    // certificate to configure TLS on it. For this example, we just print the
    // certificate and exit.

    println!("{}", cert.certificate());

    // Delete acme-challenge dir
    fs::remove_dir_all(CHALLENGE_DIR).await?;

    Ok(())
}

/// Generate a self-signed server configuration for the ACME negotiator.
fn acme_tls_server_config() -> Arc<rustls::ServerConfig> {
    let mut cert_params = rcgen::CertificateParams::new(vec![DOMAIN_NAME.to_owned()]);
    cert_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    cert_params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(
        ACME_IDENT.get().expect("ACME ID should be set by now"),
    )];

    let cert = rcgen::Certificate::from_params(cert_params).unwrap();
    let cert_der = cert.serialize_der().unwrap();
    let key_der = cert.serialize_private_key_der();

    let mut server_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::Certificate(cert_der.clone())],
            rustls::PrivateKey(key_der.clone()),
        )
        .unwrap();

    // defined in https://datatracker.ietf.org/doc/html/rfc8737#section-4
    const ACME_ALPN: &[u8] = b"acme-tls/1";

    server_config.alpn_protocols = vec![ACME_ALPN.to_vec()];
    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    Arc::new(server_config)
}
