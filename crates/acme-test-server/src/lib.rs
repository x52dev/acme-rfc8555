//! Local ACME server for integration tests.

use std::sync::{Arc, Mutex};

use actix_web::{
    http::StatusCode,
    web::{self, Data},
    App, HttpRequest, HttpResponse,
};
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256};
use serde_json::json;

#[derive(Default)]
struct AcmeState {
    challenge_started: bool,
    reject_challenge: bool,
    reject_first_order_nonce: bool,
    reject_unknown_account: bool,
    reverse_order_identifiers: bool,
    reject_finalization: bool,
    omit_certificate_url: bool,
    account_requests: usize,
    order_requests: usize,
    revocation_requests: usize,
    authorization_polls: usize,
    order_ready: bool,
    finalized: bool,
    finalization_polls: usize,
}

#[derive(Default)]
pub struct AcmeServerConfig {
    pub reject_challenge: bool,
    pub reject_first_order_nonce: bool,
    pub reject_unknown_account: bool,
    pub reverse_order_identifiers: bool,
    pub reject_finalization: bool,
    pub omit_certificate_url: bool,
}

pub struct AcmeServer {
    pub directory_url: String,
    state: Arc<Mutex<AcmeState>>,
    _server: actix_test::TestServer,
}

struct ServerData {
    certificate_pem: String,
    state: Arc<Mutex<AcmeState>>,
}

impl AcmeServer {
    pub fn account_requests(&self) -> usize {
        self.state.lock().unwrap().account_requests
    }

    pub fn order_requests(&self) -> usize {
        self.state.lock().unwrap().order_requests
    }

    pub fn revocation_requests(&self) -> usize {
        self.state.lock().unwrap().revocation_requests
    }

    pub fn finalization_polls(&self) -> usize {
        self.state.lock().unwrap().finalization_polls
    }
}

fn base_url(req: &HttpRequest) -> String {
    let connection = req.connection_info();
    format!("{}://{}", connection.scheme(), connection.host())
}

fn json_response(value: serde_json::Value) -> HttpResponse {
    HttpResponse::Ok().json(value)
}

async fn directory(req: HttpRequest) -> HttpResponse {
    let base_url = base_url(&req);

    json_response(json!({
        "newNonce": format!("{base_url}/nonce"),
        "newAccount": format!("{base_url}/account"),
        "newOrder": format!("{base_url}/new-order"),
        "revokeCert": format!("{base_url}/revoke"),
        "keyChange": format!("{base_url}/key-change"),
    }))
}

async fn nonce() -> HttpResponse {
    HttpResponse::NoContent()
        .insert_header(("Replay-Nonce", "dGVzdC1ub25jZQ"))
        .finish()
}

async fn account(req: HttpRequest, data: Data<ServerData>) -> HttpResponse {
    let mut state = data.state.lock().unwrap();
    state.account_requests += 1;

    if state.reject_unknown_account {
        HttpResponse::BadRequest()
            .insert_header(("Content-Type", "application/problem+json"))
            .body(json!({"type": "urn:ietf:params:acme:error:accountDoesNotExist"}).to_string())
    } else {
        let status = if state.account_requests == 1 {
            StatusCode::CREATED
        } else {
            StatusCode::OK
        };

        HttpResponse::build(status)
            .insert_header(("Location", format!("{}/account/1", base_url(&req))))
            .body(r#"{"status":"valid"}"#)
    }
}

async fn new_order(req: HttpRequest, data: Data<ServerData>) -> HttpResponse {
    let mut state = data.state.lock().unwrap();
    state.order_requests += 1;

    if state.reject_first_order_nonce && state.order_requests == 1 {
        HttpResponse::BadRequest()
            .insert_header(("Content-Type", "application/problem+json"))
            .insert_header(("Replay-Nonce", "cmV0cnktbm9uY2U"))
            .body(json!({"type": "urn:ietf:params:acme:error:badNonce"}).to_string())
    } else {
        let identifiers = if state.reverse_order_identifiers {
            vec![
                json!({"type": "dns", "value": "www.example.com"}),
                json!({"type": "dns", "value": "example.com"}),
            ]
        } else {
            vec![json!({"type": "dns", "value": "example.com"})]
        };

        let base_url = base_url(&req);

        HttpResponse::Created()
            .insert_header(("Location", format!("{base_url}/order/1")))
            .body(
                json!({
                    "status": "pending",
                    "identifiers": identifiers,
                    "authorizations": [format!("{base_url}/authorization/1")],
                    "finalize": format!("{base_url}/finalize/1"),
                })
                .to_string(),
            )
    }
}

async fn authorization(req: HttpRequest, data: Data<ServerData>) -> HttpResponse {
    let mut state = data.state.lock().unwrap();
    let base_url = base_url(&req);

    let status = if !state.challenge_started {
        "pending"
    } else {
        state.authorization_polls += 1;

        if state.authorization_polls == 1 {
            "pending"
        } else if state.reject_challenge {
            "invalid"
        } else {
            state.order_ready = true;
            "valid"
        }
    };

    let error = (status == "invalid").then(|| {
        json!({
            "type": "urn:ietf:params:acme:error:unauthorized",
            "detail": "challenge proof was not found",
        })
    });

    json_response(json!({
        "identifier": {"type": "dns", "value": "example.com"},
        "status": status,
        "challenges": [
            {
                "type": "http-01",
                "status": status,
                "url": format!("{base_url}/challenge/1"),
                "token": "test-token",
                "error": error,
            },
            {
                "type": "dns-01",
                "status": status,
                "url": format!("{base_url}/challenge/2"),
                "token": "test-token",
            },
            {
                "type": "tls-alpn-01",
                "status": status,
                "url": format!("{base_url}/challenge/3"),
                "token": "test-token",
            },
        ],
    }))
}

async fn challenge(req: HttpRequest, data: Data<ServerData>) -> HttpResponse {
    data.state.lock().unwrap().challenge_started = true;

    json_response(json!({
        "type": "http-01",
        "status": "pending",
        "url": format!("{}/challenge/1", base_url(&req)),
        "token": "test-token",
    }))
}

async fn order(req: HttpRequest, data: Data<ServerData>) -> HttpResponse {
    let mut state = data.state.lock().unwrap();
    let base_url = base_url(&req);

    let status = if state.finalized {
        state.finalization_polls += 1;

        if state.finalization_polls == 1 {
            "processing"
        } else if state.reject_finalization {
            "invalid"
        } else {
            "valid"
        }
    } else if state.order_ready {
        "ready"
    } else {
        "pending"
    };

    json_response(json!({
        "status": status,
        "identifiers": [{"type": "dns", "value": "example.com"}],
        "authorizations": [format!("{base_url}/authorization/1")],
        "finalize": format!("{base_url}/finalize/1"),
        "certificate": (status == "valid" && !state.omit_certificate_url)
            .then(|| format!("{base_url}/certificate/1")),
    }))
}

async fn finalize(data: Data<ServerData>) -> HttpResponse {
    data.state.lock().unwrap().finalized = true;

    HttpResponse::Ok().finish()
}

async fn certificate(data: Data<ServerData>) -> HttpResponse {
    HttpResponse::Ok().body(data.certificate_pem.clone())
}

async fn revoke(data: Data<ServerData>) -> HttpResponse {
    data.state.lock().unwrap().revocation_requests += 1;

    HttpResponse::Ok().finish()
}

pub fn start_server(config: AcmeServerConfig) -> AcmeServer {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let certificate_pem = CertificateParams::new(vec!["example.com".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap()
        .pem();

    let state = Arc::new(Mutex::new(AcmeState {
        reject_challenge: config.reject_challenge,
        reject_first_order_nonce: config.reject_first_order_nonce,
        reject_unknown_account: config.reject_unknown_account,
        reverse_order_identifiers: config.reverse_order_identifiers,
        reject_finalization: config.reject_finalization,
        omit_certificate_url: config.omit_certificate_url,
        ..Default::default()
    }));

    let data = Data::new(ServerData {
        certificate_pem,
        state: Arc::clone(&state),
    });

    let server = actix_test::start(move || {
        App::new()
            .app_data(data.clone())
            .route("/directory", web::get().to(directory))
            .route("/nonce", web::head().to(nonce))
            .route("/account", web::post().to(account))
            .route("/new-order", web::post().to(new_order))
            .route("/authorization/1", web::post().to(authorization))
            .route("/challenge/1", web::post().to(challenge))
            .route("/order/1", web::post().to(order))
            .route("/finalize/1", web::post().to(finalize))
            .route("/certificate/1", web::post().to(certificate))
            .route("/revoke", web::post().to(revoke))
    });

    AcmeServer {
        directory_url: server.url("/directory"),
        state,
        _server: server,
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_make_directory() {
        let server = super::start_server(Default::default());
        let res = reqwest::get(&server.directory_url).await.unwrap();
        assert!(res.status().is_success());
    }
}
