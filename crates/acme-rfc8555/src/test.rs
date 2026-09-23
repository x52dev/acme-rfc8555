#![allow(clippy::trivial_regex)]

use std::{convert::Infallible, future::ready, net::TcpListener, sync::OnceLock};

use actix_http::{HttpService, Method, Request, Response, StatusCode};
use actix_server::{Server, ServerHandle};
use actix_web::body::MessageBody;
use regex::Regex;

static RE_URL: OnceLock<Regex> = OnceLock::new();

fn re_url() -> &'static Regex {
    RE_URL.get_or_init(|| regex::Regex::new("<URL>").unwrap())
}

pub struct TestServer {
    pub dir_url: String,
    handle: ServerHandle,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        drop(self.handle.stop(false));
    }
}

fn get_directory(url: &str) -> Response<impl MessageBody> {
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

    Response::with_body(
        StatusCode::OK,
        RE_URL
            .get_or_init(|| Regex::new("<URL>").unwrap())
            .replace_all(BODY, url),
    )
}

fn head_new_nonce() -> Response<impl MessageBody> {
    Response::build(StatusCode::NO_CONTENT)
        .insert_header((
            "Replay-Nonce",
            "8_uBBV3N2DBRJczhoiB46ugJKUkUHxGzVe6xIMpjHFM",
        ))
        .finish()
}

fn post_new_acct(url: &str) -> Response<impl MessageBody> {
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

    let location = re_url()
        .replace_all("<URL>/acme/acct/7728515", url)
        .into_owned();

    Response::build(StatusCode::CREATED)
        .insert_header(("Location", location))
        .body(BODY)
}

fn post_new_order(url: &str) -> Response<impl MessageBody> {
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

    let location = re_url()
        .replace_all("<URL>/acme/order/YTqpYUthlVfwBncUufE8", url)
        .into_owned();

    Response::build(StatusCode::CREATED)
        .insert_header(("Location", location))
        .body(re_url().replace_all(BODY, url))
}

fn post_get_order(url: &str) -> Response<impl MessageBody> {
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

    let body = re_url().replace_all(BODY, url).into_owned();

    Response::build(StatusCode::OK).body(body)
}

fn post_authz(url: &str) -> Response<impl MessageBody> {
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

    Response::build(StatusCode::CREATED).body(re_url().replace_all(BODY, url))
}

fn post_finalize(_url: &str) -> Response<impl MessageBody> {
    Response::ok()
}

fn post_certificate(_url: &str) -> Response<impl MessageBody> {
    Response::build(StatusCode::OK).body("CERT HERE")
}

fn route_request(req: Request, url: &str) -> Response<impl MessageBody> {
    match (req.method(), req.path()) {
        (&Method::GET, "/directory") => get_directory(url).map_into_boxed_body(),
        (&Method::HEAD, "/acme/new-nonce") => head_new_nonce().map_into_boxed_body(),
        (&Method::POST, "/acme/new-acct") => post_new_acct(url).map_into_boxed_body(),
        (&Method::POST, "/acme/new-order") => post_new_order(url).map_into_boxed_body(),

        (&Method::POST, "/acme/order/YTqpYUthlVfwBncUufE8") => {
            post_get_order(url).map_into_boxed_body()
        }

        (&Method::POST, "/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs") => {
            post_authz(url).map_into_boxed_body()
        }

        (&Method::POST, "/acme/finalize/7738992/18234324") => {
            post_finalize(url).map_into_boxed_body()
        }

        (&Method::POST, "/acme/cert/fae41c070f967713109028") => {
            post_certificate(url).map_into_boxed_body()
        }

        (_, _) => Response::build(StatusCode::NOT_FOUND)
            .finish()
            .map_into_boxed_body(),
    }
}

pub fn with_directory_server() -> TestServer {
    let lst = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = lst.local_addr().unwrap().port();

    let url = format!("http://127.0.0.1:{port}");
    let dir_url = format!("{url}/directory");

    let server = Server::build()
        .listen("acme", lst, move || {
            let url = url.clone();

            HttpService::build()
                .finish(move |req| ready(Ok::<_, Infallible>(route_request(req, &url))))
                .tcp()
        })
        .unwrap()
        .workers(1)
        .run();

    let handle = server.handle();

    tokio::spawn(server);

    TestServer { dir_url, handle }
}

#[tokio::test]
pub async fn test_make_directory() {
    let server = with_directory_server();
    let res = reqwest::get(&server.dir_url).await.unwrap();
    assert!(res.status().is_success());
}
