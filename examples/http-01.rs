use std::time::Duration;

use acme::{create_p256_key, Directory, DirectoryUrl};
use actix_files::Files;
use actix_web::{middleware::Logger, App, HttpServer};
use tokio::fs;

const CHALLENGE_DIR: &str = "./acme-challenges";
const CERTIFICATE_DIR: &str = "./acme-certificates";

const DOMAINS: &[&str] = &["glados.x52.dev", "oc.x52.dev"];
const CONTACT_EMAIL: Option<&str> = None;

#[actix_web::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("ensuring challenge dir exists");
    fs::create_dir_all(CHALLENGE_DIR)
        .await
        .expect("should be able to create challenge directory");

    log::info!("ensuring certificate dir exists");
    fs::create_dir_all(CERTIFICATE_DIR)
        .await
        .expect("should be able to create certificate directory");

    log::info!("starting temporary HTTP challenge server");
    let srv = HttpServer::new(|| {
        App::new()
            .wrap(Logger::default().log_target("acme_http_server"))
            .service(Files::new("/.well-known/acme-challenge", CHALLENGE_DIR).show_files_listing())
    })
    .bind(("0.0.0.0", 80))?
    .workers(1)
    .disable_signals()
    .shutdown_timeout(0)
    .run();

    let srv_handle = srv.handle();
    let srv_task = actix_web::rt::spawn(srv);

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
    log::info!("waiting for order to be validated");
    let csr = loop {
        // Are we done?
        if let Some(csr) = order.confirm_validations() {
            log::info!("order validated");
            break csr;
        }

        // Get the possible authorizations.
        // For a single domain this will only be one element.
        let auths = order.authorizations().await?;

        for auth in auths {
            // For HTTP, the challenge is a text file that needs to be placed in
            // your web server's root:
            //
            // /.well-known/acme-challenge/<token>
            //
            // The important thing is that it's accessible over the
            // web for the domain(s) you are trying to get a
            // certificate for:
            //
            // http://example.org/.well-known/acme-challenge/<token>
            let http_challenge = auth.http_challenge().unwrap();

            // The token is the filename.
            let token = http_challenge.http_token();
            let path = format!("{CHALLENGE_DIR}/{token}");

            // The proof is the contents of the file.
            let proof = http_challenge.http_proof()?;

            log::info!("persisting authorization proof to {path}");
            fs::write(path, proof).await?;

            // After the file is accessible from the web, the `validate` call
            // tells the ACME API to start checking the existence of the proof.
            //
            // The order at ACME will change status to either confirm ownership
            // of the domain, or fail due to the not finding the proof. To see
            // the change, we poll API every 5 seconds.
            http_challenge.validate(Duration::from_secs(5)).await?;
        }

        // Update the state against the ACME API.
        order.refresh().await?;
    };

    // Ownership is proven. Create a private key for
    // the certificate. These are provided for convenience, you
    // can provide your own keypair instead if you want.
    let private_key = create_p256_key();

    log::info!("submitting CSR for: {:?}", &csr.api_order().domains());

    // Submit the CSR. This causes the ACME provider to enter a state of
    // "processing" that must be polled until the certificate is either issued
    // or rejected. Again we poll for the status change.
    let ord_cert = csr.finalize(private_key, Duration::from_secs(5)).await?;

    log::info!("downloading certificate");
    let cert = ord_cert.download_cert().await?;

    // NOTE: Here you would spawn your HTTP server and use the private key plus
    // certificate to configure TLS on it. For this example, we just persist the
    // certificate, print it, and exit.

    let cert_path = format!("{CERTIFICATE_DIR}/{}.pem", DOMAINS.first().unwrap());
    log::info!("persisting certificate to {cert_path}");
    fs::write(cert_path, cert.certificate()).await?;

    let key_path = format!("{CERTIFICATE_DIR}/{}.key", DOMAINS.first().unwrap());
    log::info!("persisting private key to {key_path}");
    fs::write(key_path, cert.private_key()).await?;

    println!();
    println!("{}", cert.certificate());

    // Stop temporary ACME server.
    srv_handle.stop(true).await;
    srv_task.await??;

    Ok(())
}
