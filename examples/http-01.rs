use std::fs;
use std::time::Duration;

use acme_lite::create_p256_key;
use acme_lite::{Directory, DirectoryUrl};
use actix_files::Files;
use actix_web::{App, HttpServer};

const PRIMARY_NAME: &str = "example.org";

#[tokio::main(flavor = "current_thread")]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;

    // Use `DirectoryUrl::LetsEncrypt` for production uses.
    let url = DirectoryUrl::LetsEncryptStaging;

    // Create temporary Actix Web server for ACME challenge.
    let srv = HttpServer::new(|| {
        App::new().service(
            Files::new("/.well-known/acme-challenge", "acme-challenge").show_files_listing(),
        )
    })
    .bind(("0.0.0.0", 80))?
    .shutdown_timeout(0)
    .run();

    let srv_handle = srv.handle();
    let srv_task = actix_web::rt::spawn(srv);

    // Create a directory entrypoint.
    let dir = Directory::from_url(url).await?;

    // Your contact addresses, note the `mailto:`
    let contact = vec!["mailto:foo@bar.com".to_owned()];

    // Generate a private key and register an account with your ACME provider.
    // You should write it to disk any use `load_account` afterwards.
    let acc = dir.register_account(Some(contact.clone())).await?;

    // Example of how to load an account from string:
    let signing_key_pem = acc.acme_signing_key_pem()?;
    let acc = dir.load_account(&signing_key_pem, Some(contact)).await?;

    // Order a new TLS certificate for a domain.
    let mut ord_new = acc.new_order(PRIMARY_NAME, &[]).await?;

    // If the ownership of the domain(s) have already been
    // authorized in a previous order, you might be able to
    // skip validation. The ACME API provider decides.
    let ord_csr = loop {
        // are we done?
        if let Some(ord_csr) = ord_new.confirm_validations() {
            break ord_csr;
        }

        // Get the possible authorizations (for a single domain
        // this will only be one element).
        let auths = ord_new.authorizations().await?;

        // For HTTP, the challenge is a text file that needs to
        // be placed in your web server's root:
        //
        // /<root>/.well-known/acme-challenge/<token>
        //
        // The important thing is that it's accessible over the
        // web for the domain(s) you are trying to get a
        // certificate for:
        //
        // http://example.org/.well-known/acme-challenge/<token>
        let http_challenge = auths[0].http_challenge().unwrap();

        // The token is the filename.
        let token = http_challenge.http_token();
        let path = format!(".well-known/acme-challenge/{token}");

        // The proof is the contents of the file.
        let proof = http_challenge.http_proof()?;

        // Place the file and contents in the correct place.
        fs::write(path, proof)?;

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
        ord_new.refresh().await?;
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
    println!("{cert:?}");

    // Stop temporary server for ACME challenge
    srv_handle.stop(true).await;
    srv_task.await??;

    // Delete acme-challenge dir
    fs::remove_dir_all("./acme-challenge")?;

    Ok(())
}
