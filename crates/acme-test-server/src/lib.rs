//! A local ACME directory server for tests.

#![allow(clippy::trivial_regex)]

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    OnceLock,
};

use actix_web::{web, App, HttpRequest, HttpResponse};
use regex::Regex;

static RE_URL: OnceLock<Regex> = OnceLock::new();

fn re_url() -> &'static Regex {
    RE_URL.get_or_init(|| regex::Regex::new("<URL>").unwrap())
}

/// A running test server that serves a fixed ACME directory.
pub struct TestServer {
    /// The URL of the ACME directory endpoint.
    pub dir_url: String,
    _server: actix_test::TestServer,
}

impl TestServer {
    /// Returns the URL for a path on this test server.
    pub fn url(&self, path: &str) -> String {
        self._server.url(path)
    }
}

fn base_url(req: &HttpRequest) -> String {
    let connection = req.connection_info();
    format!("{}://{}", connection.scheme(), connection.host())
}

async fn get_directory(req: HttpRequest) -> HttpResponse {
    const BODY: &str = r#"{
    "keyChange": "<URL>/acme/key-change",
    "newAccount": "<URL>/acme/new-acct",
    "newNonce": "<URL>/acme/new-nonce",
    "newOrder": "<URL>/acme/new-order",
    "revokeCert": "<URL>/acme/revoke-cert",
    "meta": {
        "caaIdentities": [
        "testdir.org"
        ]
    }
    }"#;

    let url = base_url(&req);
    let body = RE_URL
        .get_or_init(|| Regex::new("<URL>").unwrap())
        .replace_all(BODY, url.as_str())
        .into_owned();

    HttpResponse::Ok().body(body)
}

async fn head_new_nonce() -> HttpResponse {
    HttpResponse::NoContent()
        .insert_header((
            "Replay-Nonce",
            "8_uBBV3N2DBRJczhoiB46ugJKUkUHxGzVe6xIMpjHFM",
        ))
        .finish()
}

async fn post_new_acct(req: HttpRequest) -> HttpResponse {
    const BODY: &str = r#"{
    "id": 7728515,
    "key": {
        "use": "sig",
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "x": "ttpobTRK2bw7ttGBESRO7Nb23mbIRfnRZwunL1W6wRI",
        "y": "h2Z00J37_2qRKH0-flrHEsH0xbit915Tyvd2v_CAOSk"
    },
    "contact": [
        "mailto:foo@bar.com"
    ],
    "initialIp": "90.171.37.12",
    "createdAt": "2018-12-31T17:15:40.399104457Z",
    "status": "valid"
    }"#;

    let url = base_url(&req);
    let location = re_url()
        .replace_all("<URL>/acme/acct/7728515", url.as_str())
        .into_owned();

    HttpResponse::Created()
        .insert_header(("Location", location))
        .body(BODY)
}

async fn post_new_order(req: HttpRequest) -> HttpResponse {
    const BODY: &str = r#"{
    "status": "pending",
    "expires": "2019-01-09T08:26:43.570360537Z",
    "identifiers": [
        {
        "type": "dns",
        "value": "acme-test.example.com"
        }
    ],
    "authorizations": [
        "<URL>/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs"
    ],
    "finalize": "<URL>/acme/finalize/7738992/18234324"
    }"#;

    let url = base_url(&req);
    let location = re_url()
        .replace_all("<URL>/acme/order/YTqpYUthlVfwBncUufE8", url.as_str())
        .into_owned();

    HttpResponse::Created()
        .insert_header(("Location", location))
        .body(re_url().replace_all(BODY, url.as_str()).into_owned())
}

async fn post_get_order(req: HttpRequest) -> HttpResponse {
    const BODY: &str = r#"{
    "status": "<STATUS>",
    "expires": "2019-01-09T08:26:43.570360537Z",
    "identifiers": [
        {
        "type": "dns",
        "value": "acme-test.example.com"
        }
    ],
    "authorizations": [
        "<URL>/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs"
    ],
    "finalize": "<URL>/acme/finalize/7738992/18234324",
    "certificate": "<URL>/acme/cert/fae41c070f967713109028"
    }"#;

    let url = base_url(&req);
    let body = re_url().replace_all(BODY, url.as_str()).into_owned();

    HttpResponse::Ok().body(body)
}

async fn post_authz(req: HttpRequest) -> HttpResponse {
    const BODY: &str = r#"{
        "identifier": {
            "type": "dns",
            "value": "acmetest.algesten.se"
        },
        "status": "pending",
        "expires": "2019-01-09T08:26:43Z",
        "challenges": [
        {
            "type": "http-01",
            "status": "pending",
            "url": "<URL>/acme/challenge/YTqpYUthlVfwBncUufE8IRWLMSRqcSs/216789597",
            "token": "MUi-gqeOJdRkSb_YR2eaMxQBqf6al8dgt_dOttSWb0w"
        },
        {
            "type": "tls-alpn-01",
            "status": "pending",
            "url": "<URL>/acme/challenge/YTqpYUthlVfwBncUufE8IRWLMSRqcSs/216789598",
            "token": "WCdRWkCy4THTD_j5IH4ISAzr59lFIg5wzYmKxuOJ1lU"
        },
        {
            "type": "dns-01",
            "status": "pending",
            "url": "<URL>/acme/challenge/YTqpYUthlVfwBncUufE8IRWLMSRqcSs/216789599",
            "token": "RRo2ZcXAEqxKvMH8RGcATjSK1KknLEUmauwfQ5i3gG8"
        }
        ]
    }"#;

    let url = base_url(&req);
    HttpResponse::Created().body(re_url().replace_all(BODY, url.as_str()).into_owned())
}

async fn post_finalize() -> HttpResponse {
    HttpResponse::Ok().finish()
}

async fn post_certificate() -> HttpResponse {
    HttpResponse::Ok().body("CERT HERE")
}

async fn get_problem() -> HttpResponse {
    HttpResponse::BadRequest()
        .insert_header(("content-type", "application/problem+json"))
        .body(r#"{"type":"badNonce","detail":"nonce expired"}"#)
}

async fn get_malformed_problem() -> HttpResponse {
    HttpResponse::BadRequest()
        .insert_header(("content-type", "application/problem+json"))
        .body("not json")
}

async fn get_plain_error() -> HttpResponse {
    HttpResponse::BadRequest()
        .insert_header(("content-type", "text/plain"))
        .body("upstream failure")
}

async fn post_validation_challenge() -> HttpResponse {
    HttpResponse::Ok().body(
        r#"{"type":"http-01","status":"processing","url":"https://example.com/challenge","token":"token"}"#,
    )
}

fn validation_authorization(status: &str, challenges: &str) -> HttpResponse {
    HttpResponse::Ok().body(format!(
        r#"{{"identifier":{{"type":"dns","value":"acme-test.example.com"}},"status":"{status}","challenges":{challenges}}}"#
    ))
}

async fn post_validation_pending_then_valid(polls: web::Data<AtomicUsize>) -> HttpResponse {
    let status = if polls.fetch_add(1, Ordering::Relaxed) == 0 {
        "pending"
    } else {
        "valid"
    };

    validation_authorization(status, "[]")
}

async fn post_validation_invalid_error() -> HttpResponse {
    validation_authorization(
        "invalid",
        r#"[{"type":"dns-01","status":"invalid","url":"https://example.com/challenge","token":"token","error":{"type":"urn:ietf:params:acme:error:dns","detail":"DNS lookup failed"}}]"#,
    )
}

async fn post_validation_invalid_no_error() -> HttpResponse {
    validation_authorization("invalid", "[]")
}

/// Starts a server that returns fixed ACME directory and resource responses.
pub fn with_directory_server() -> TestServer {
    let validation_polls = web::Data::new(AtomicUsize::new(0));
    let server = actix_test::start(move || {
        App::new()
            .app_data(validation_polls.clone())
            .route(
                "/error/{kind}",
                web::get().to(|kind: web::Path<String>| async move {
                    let mut response = HttpResponse::BadRequest();

                    match kind.as_str() {
                        "parameterized" => {
                            response.insert_header((
                                "Content-Type",
                                "Application/Problem+Json; charset=utf-8",
                            ));
                        }
                        "malformed" => {
                            response.insert_header(("Content-Type", "invalid"));
                        }
                        "non-ascii" => {
                            response.insert_header((
                                "Content-Type",
                                actix_web::http::header::HeaderValue::from_bytes(b"\xff").unwrap(),
                            ));
                        }
                        _ => {}
                    }

                    response.body(web::Bytes::from_static(
                        br#"{"type":"badNonce","detail":"nonce expired"}"#,
                    ))
                }),
            )
            .route("/directory", web::get().to(get_directory))
            .route("/acme/new-nonce", web::head().to(head_new_nonce))
            .route("/acme/new-acct", web::post().to(post_new_acct))
            .route("/acme/new-order", web::post().to(post_new_order))
            .route(
                "/acme/order/YTqpYUthlVfwBncUufE8",
                web::post().to(post_get_order),
            )
            .route(
                "/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs",
                web::post().to(post_authz),
            )
            .route(
                "/acme/finalize/7738992/18234324",
                web::post().to(post_finalize),
            )
            .route(
                "/acme/cert/fae41c070f967713109028",
                web::post().to(post_certificate),
            )
            .route("/test/problem", web::get().to(get_problem))
            .route(
                "/test/malformed-problem",
                web::get().to(get_malformed_problem),
            )
            .route("/test/plain-error", web::get().to(get_plain_error))
            .route(
                "/test/validation/challenge",
                web::post().to(post_validation_challenge),
            )
            .route(
                "/test/validation/pending-then-valid",
                web::post().to(post_validation_pending_then_valid),
            )
            .route(
                "/test/validation/invalid-error",
                web::post().to(post_validation_invalid_error),
            )
            .route(
                "/test/validation/invalid-no-error",
                web::post().to(post_validation_invalid_no_error),
            )
    });

    TestServer {
        dir_url: server.url("/directory"),
        _server: server,
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn test_make_directory() {
        let server = super::with_directory_server();
        let res = reqwest::get(&server.dir_url).await.unwrap();
        assert!(res.status().is_success());
    }
}
