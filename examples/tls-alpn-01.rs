use std::{
    sync::{Arc, OnceLock},
    thread,
    time::Duration,
};

use acme_lite::{create_p256_key, Directory, DirectoryUrl};
use rustls::server::{Acceptor, ClientHello};
use tokio::fs;

const CHALLENGE_DIR: &str = "./acme-challenges";
const DOMAIN_NAME: &str = "example.org";
const CONTACT_EMAIL: &str = "contact@example.org";

static TOKEN: OnceLock<[u8; 32]> = OnceLock::new();

fn acme_tls_server() {
    // Start a TLS server accepting connections as they arrive.
    let listener = std::net::TcpListener::bind(("0.0.0.0", 443)).unwrap();

    for stream in listener.incoming() {
        let mut stream = stream.unwrap();
        let mut acceptor = Acceptor::default();

        // Read TLS packets until we've consumed a full client hello and are ready to accept a
        // connection.
        let accepted = loop {
            acceptor.read_tls(&mut stream).unwrap();
            if let Some(accepted) = acceptor.accept().unwrap() {
                break accepted;
            }
        };

        // Generate a server config for the accepted connection, optionally customizing the
        // configuration based on the client hello.
        let config = acme_tls_server_config(accepted.client_hello());
        let mut conn = accepted.into_connection(config).unwrap();

        // Proceed with handling the ServerConnection
        // Important: We do no error handling here, but you should!
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
    let mut new_order = acc.new_order(DOMAIN_NAME, &[]).await?;

    // If the ownership of the domain(s) have already been authorized in a previous order, you might
    // be able to skip validation. The ACME API provider decides.
    log::info!("waiting for certificate signing request to be validated");
    let ord_csr = loop {
        // Are we done?
        if let Some(ord_csr) = new_order.confirm_validations() {
            log::info!("certificate signing request validated");
            break ord_csr;
        }

        // Get the possible authorizations (for a single domain this will only be one element).
        let auths = new_order.authorizations().await?;
        let auth = &auths[0];

        // For HTTP, the challenge is a text file that needs to be placed in your web server's root:
        //
        // /.well-known/acme-challenge/<token>
        //
        // The important thing is that it's accessible over the
        // web for the domain(s) you are trying to get a
        // certificate for:
        //
        // http://example.org/.well-known/acme-challenge/<token>
        let tls_challenge = auth.tls_alpn_challenge().unwrap();

        // The token is the filename.
        let (token, hash) = tls_challenge.tls_alpn_proof()?;

        TOKEN.get_or_init(|| hash);
        log::info!("{hash:?} : {token}");

        // After the file is accessible from the web, the calls
        // this to tell the ACME API to start checking the
        // existence of the proof.
        //
        // The order at ACME will change status to either
        // confirm ownership of the domain, or fail due to the
        // not finding the proof. To see the change, we poll
        // the API with 5 seconds wait between.
        tls_challenge.validate(Duration::from_secs(5)).await?;

        // Update the state against the ACME API.
        new_order.refresh().await?;
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

/// Generate a server configuration for the client using the test PKI.
///
/// Importantly this creates a new client certificate verifier per-connection so that the server
/// can read in the latest CRL content from disk.
///
/// Since the presented client certificate is not available in the `ClientHello` the server
/// must know ahead of time which CRLs it cares about.
fn acme_tls_server_config(_hello: ClientHello) -> Arc<rustls::ServerConfig> {
    // Create a server end entity cert issued by the CA.
    let mut server_ee_params = rcgen::CertificateParams::new(vec![DOMAIN_NAME.to_owned()]);
    server_ee_params.is_ca = rcgen::IsCa::NoCa;
    server_ee_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    server_ee_params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    server_ee_params.custom_extensions = vec![rcgen::CustomExtension::new_acme_identifier(
        TOKEN.get().unwrap(),
    )];

    let server_cert = rcgen::Certificate::from_params(server_ee_params).unwrap();
    let server_cert_der = server_cert.serialize_der().unwrap();
    let server_key_der = server_cert.serialize_private_key_der();

    // Build a server config using the fresh verifier. If necessary, this could be customized
    // based on the ClientHello (e.g. selecting a different certificate, or customizing
    // supported algorithms/protocol versions).
    let mut server_config = rustls::ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(
            vec![rustls::Certificate(server_cert_der.clone())],
            rustls::PrivateKey(server_key_der.clone()),
        )
        .unwrap();

    // defined in https://datatracker.ietf.org/doc/html/rfc8737#section-4
    const ACME_ALPN: &[u8] = b"acme-tls/1";

    server_config.alpn_protocols = vec![ACME_ALPN.to_vec()];
    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    Arc::new(server_config)
}
