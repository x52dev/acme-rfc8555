use std::{collections::HashMap, sync::Arc, thread, time::Duration};

use acme::{create_p256_key, Directory, DirectoryUrl};
use eyre::{eyre, WrapErr as _};
use parking_lot::Mutex;
use rustls::{
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
    server::Acceptor,
    sign::{CertifiedKey, SingleCertAndKey},
};
use tokio::fs;

const CERTIFICATE_DIR: &str = "./acme-certificates";

const DOMAINS: &[&str] = &["example.org"];
const CONTACT_EMAIL: Option<&str> = None;

/// Thread-safe map of ServerName to ACME identity for TLS challenge type (32-byte hash).
type AcmeIdentityMap = Arc<Mutex<HashMap<String, [u8; 32]>>>;

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| eyre!("could not install rustls crypto provider"))?;

    log::info!("ensuring certificate dir exists");
    fs::create_dir_all(CERTIFICATE_DIR)
        .await
        .expect("should be able to create certificate directory");

    log::info!("starting temporary TLS challenge server");

    let identity_map = AcmeIdentityMap::default();

    let _srv_handle = thread::spawn({
        let identity_map = Arc::clone(&identity_map);
        move || {
            if let Err(err) = acme_tls_server(identity_map) {
                let err =
                    error_reporter::Report::new(<_ as AsRef<dyn std::error::Error>>::as_ref(&err));
                log::error!("{err}");
            }
        }
    });

    log::info!("fetching LetsEncrypt directory");
    // Create a directory entrypoint.
    // Note: Change to `DirectoryUrl::LetsEncrypt` in production.
    let dir = Directory::fetch(DirectoryUrl::LetsEncryptStaging).await?;

    // Your contact addresses, note the `mailto:`
    let contact = CONTACT_EMAIL.map(|email| vec![format!("mailto:{email}")]);

    log::info!("generating private key and registering with ACME provider");
    // Usually, you'll write the private key to disk any use `load_account` in the future.
    let acc = dir.register_account(contact.clone()).await?;

    log::info!("ordering a new TLS certificate for our domain");
    let mut order = acc.new_order(DOMAINS[0], DOMAINS).await?;

    // If the ownership of the domain(s) have already been authorized in a previous order, you might
    // be able to skip validation. The ACME API provider decides.
    log::info!("waiting for certificate signing request to be validated");
    let csr = loop {
        // Are we done?
        if let Some(csr) = order.confirm_validations() {
            log::info!("certificate signing request validated");
            break csr;
        }

        // Get the possible authorizations.
        let auths = order.authorizations().await?;

        for auth in auths {
            // For TLS, the challenge is a text file that needs to be placed in your web server's root:
            let tls_challenge = auth.tls_alpn_challenge().unwrap();

            // The ACME identifier is a 32-byte hash of the proof.
            let acme_ident = tls_challenge.tls_alpn_proof()?;

            log::info!("storing authorization proof for {}", auth.domain_name());
            identity_map
                .lock()
                .insert(auth.domain_name().to_owned(), acme_ident);

            // After the ID is accessible during a TLS handshake, the `validate`
            // call tells the ACME API to start checking the existence of the
            // proof.
            //
            // The order will change status later to either confirm ownership of
            // the domain, or fail due to a failed TLS handshake. To see the
            // change, we poll the API every 5 seconds.
            tls_challenge.validate(Duration::from_secs(5)).await?;
        }

        // Update the state against the ACME API.
        order.refresh().await?;
    };

    // Ownership is proven. Create a private key for the certificate.
    // Alternatively you can load a private key from elsewhere.
    let private_key = create_p256_key();

    log::info!("submitting CSR for: {:?}", &csr.api_order().domains());

    // Submit the CSR. This causes the ACME provider to enter a state of
    // "processing" that must be polled until the certificate is either issued
    // or rejected. Again we poll for the status change.
    let ord_cert = csr.finalize(private_key, Duration::from_secs(5)).await?;

    log::info!("downloading certificate");
    let cert = ord_cert.download_cert().await?;

    // NOTE: Here you would spawn your real server and use the private key plus
    // certificate to configure TLS on it. For this example, we just print the
    // certificate and exit.

    let cert_path = format!("{CERTIFICATE_DIR}/{}.pem", DOMAINS[0]);
    log::info!("persisting certificate to {cert_path}");
    fs::write(cert_path, cert.certificate()).await?;

    let key_path = format!("{CERTIFICATE_DIR}/{}.key", DOMAINS[0]);
    log::info!("persisting private key to {key_path}");
    fs::write(key_path, cert.private_key()).await?;

    println!();
    println!("{}", cert.certificate());
    println!("cert valid for {} days", cert.valid_days_left()?);

    Ok(())
}

/// Starts a (synchronous) TCP/TLS listener on port 443 that responds to connections from an ACME
/// provider with self-signed certificates containing proof of domain ownership for items in `ids`.
fn acme_tls_server(ids: AcmeIdentityMap) -> eyre::Result<()> {
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

        let hello = accepted.client_hello();

        let Some(server_name) = hello.server_name() else {
            // ACME servers have to indicate a server name.
            // If it's not present then drop the connection.
            continue;
        };

        log::info!("received TLS connection for {server_name}");

        let Some(&acme_identity) = ids.lock().get(server_name) else {
            // If the server name indicated doesn't have an associated identity,
            // then the connection is not for us; drop it.
            continue;
        };

        log::info!("constructing TLS ALPN response");

        // Generate a server config for the accepted connection based on the
        // server name indicated.
        let config = acme_tls_server_config(server_name, acme_identity)
            .wrap_err("Failed to construct server config")?;
        let mut conn = accepted
            .into_connection(config)
            .map_err(|(err, _)| err)
            .wrap_err("Failed to accept connection")?;

        // Proceed with handling the connection until the ACME client closes
        // the connection.
        conn.complete_io(&mut stream)
            .wrap_err("Failed to complete I/O")?;
    }

    Ok(())
}

/// Generate a self-signed server configuration for the ACME negotiator.
fn acme_tls_server_config(
    server_name: &str,
    acme_identity: [u8; 32],
) -> eyre::Result<Arc<rustls::ServerConfig>> {
    let mut cert_params = rcgen::CertificateParams::new(vec![server_name.to_owned()])
        .wrap_err("Failed to construct cert params")?;
    cert_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
    cert_params.custom_extensions =
        vec![rcgen::CustomExtension::new_acme_identifier(&acme_identity)];

    let key_pair = rcgen::KeyPair::generate().wrap_err("Failed to generate keypair")?;
    let key_der = key_pair.serialize_der();

    let cert = cert_params
        .self_signed(&key_pair)
        .wrap_err("Failed to generate cert")?;

    // save rcgen cert for inspection
    std::fs::write("acme-certificates/tls-alpn-cert.pem", cert.pem())?;

    let server_config = rustls::ServerConfig::builder().with_no_client_auth();

    // construct certified key manually since rustls webpki doesn't understand
    // the critical ACME identifier extension required for the certificate
    let private_key = server_config
        .crypto_provider()
        .key_provider
        .load_private_key(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der)))
        .wrap_err("Failed to load private key")?;

    let certified_key = CertifiedKey::new(vec![cert.der().clone()], private_key);
    verify_keys_match(&certified_key).wrap_err("Keys do not match")?;

    let mut server_config =
        server_config.with_cert_resolver(Arc::new(SingleCertAndKey::from(certified_key)));

    // defined in https://datatracker.ietf.org/doc/html/rfc8737#section-4
    const ACME_ALPN: &[u8] = b"acme-tls/1";

    server_config.alpn_protocols = vec![ACME_ALPN.to_vec()];
    server_config.key_log = Arc::new(rustls::KeyLogFile::new());

    Ok(Arc::new(server_config))
}

/// This step isn't strictly necessary but re-implements the type of validation done by
/// `CertifiedKey::from_der`, a function which we can't call because it validates critical
/// extensions.
fn verify_keys_match(certified_key: &CertifiedKey) -> eyre::Result<()> {
    let matched = certified_key.keys_match();

    let cert_err = match matched {
        // don't treat unknown consistency as an error
        Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => {
            return Ok(())
        }
        Err(rustls::Error::InvalidCertificate(err)) => err,
        Err(err) => return Err(err.into()),
    };

    if let rustls::CertificateError::Other(other_err) = &cert_err {
        if let Some(webpki::Error::UnsupportedCriticalExtension) =
            // unfortunate dependency on exact webpki version
            other_err.0.downcast_ref::<webpki::Error>()
        {
            // unsupported critical extension is expected for this cert
            return Ok(());
        }
    }

    // any other reason should be propagated
    Err(rustls::Error::InvalidCertificate(cert_err).into())
}
