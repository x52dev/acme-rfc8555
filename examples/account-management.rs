use std::io;

use acme_lite::{Directory, DirectoryUrl};
use tokio::fs;

const ACCOUNTS_DIR: &str = "./acme-accounts";

const CONTACT_EMAIL: Option<&str> = None;

#[actix_web::main]
async fn main() -> eyre::Result<()> {
    color_eyre::install()?;
    env_logger::init_from_env(env_logger::Env::new().default_filter_or("info"));

    log::info!("ensuring accounts dir exists");
    fs::create_dir_all(ACCOUNTS_DIR)
        .await
        .expect("should be able to create accounts directory");

    log::info!("fetching LetsEncrypt directory");
    let dir = Directory::fetch(DirectoryUrl::LetsEncryptStaging).await?;

    let key_path = format!("{ACCOUNTS_DIR}/account.pem");

    log::info!("loading private key from disk");
    let acc = match fs::read_to_string(&key_path).await {
        Ok(private_key_pem) => {
            log::info!("loading account from private key");
            dir.load_existing_account(&private_key_pem).await?
        }

        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let contact = CONTACT_EMAIL.map(|email| vec![format!("mailto:{email}")]);

            log::info!("generating private key and registering with ACME provider");
            let acc = dir.register_account(contact).await?;
            let private_key_pem = acc.acme_private_key_pem()?;

            log::info!("persisting account to {key_path}");
            fs::write(key_path, private_key_pem).await?;

            acc
        }

        Err(err) => return Err(err.into()),
    };

    dbg!(&acc);

    Ok(())
}
