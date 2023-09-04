use std::time::Duration;

use acme_lite::{create_p256_key, Directory, DirectoryUrl};
use actix_files::Files;
use actix_web::{middleware::Logger, App, HttpServer};
use tokio::fs;

const CHALLENGE_DIR: &str = "./acme-challenges";
const DOMAIN_NAME: &str = "example.org";
const CONTACT_EMAIL: &str = "contact@example.org";

#[actix_web::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("ensuring challenge dir exists");
    fs::create_dir_all(CHALLENGE_DIR)
        .await
        .expect("should be able to create challenge directory");

    log::info!("starting temporary HTTP challenge server");
    let srv = HttpServer::new(|| {
        App::new()
            .wrap(Logger::default().log_target("acme_http_server"))
            .service(Files::new("/.well-known/acme-challenge", CHALLENGE_DIR).show_files_listing())
    })
    .bind(("0.0.0.0", 80))?
    .shutdown_timeout(0)
    .disable_signals()
    .run();

    let srv_handle = srv.handle();
    let srv_task = actix_web::rt::spawn(srv);

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
        let http_challenge = auth.http_challenge().unwrap();

        // The token is the filename.
        let token = http_challenge.http_token();
        let path = format!("{CHALLENGE_DIR}/{token}");

        // The proof is the contents of the file.
        let proof = http_challenge.http_proof()?;

        // Place the file and contents in the correct place.
        fs::write(path, proof).await?;

        // After the file is accessible from the web, the calls
        // this to tell the ACME API to start checking the
        // existence of the proof.
        //
        // The order at ACME will change status to either
        // confirm ownership of the domain, or fail due to the
        // not finding the proof. To see the change, we poll
        // the API with 5000 milliseconds wait between.
        http_challenge.validate(Duration::from_millis(5000)).await?;

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
        .finalize_signing_key(signing_key, Duration::from_millis(5000))
        .await?;

    // Finally download the certificate.
    let cert = ord_cert.download_cert().await?;

    // NOTE: Here you would spawn your HTTP server and use the private key plus
    // certificate to configure TLS on it. For this example, we just print the
    // certificate and exit.

    println!("{}", cert.certificate());

    // Stop temporary server for ACME challenge
    srv_handle.stop(true).await;
    srv_task.await??;

    // Delete acme-challenge dir
    fs::remove_dir_all(CHALLENGE_DIR).await?;

    Ok(())
}
