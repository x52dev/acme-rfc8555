#![allow(clippy::trivial_regex)]

use std::{convert::Infallible, net::TcpListener};

use hyper::{
    service::{make_service_fn, service_fn},
    Body, Method, Request, Response, Server,
};
use once_cell::sync::Lazy;

static RE_URL: Lazy<regex::Regex> = Lazy::new(|| regex::Regex::new("<URL>").unwrap());

pub struct TestServer {
    pub dir_url: String,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.shutdown.take().unwrap().send(()).ok();
    }
}

fn get_directory(url: &str) -> Response<Body> {
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
    Response::new(Body::from(RE_URL.replace_all(BODY, url)))
}

fn head_new_nonce() -> Response<Body> {
    Response::builder()
        .status(204)
        .header(
            "Replay-Nonce",
            "8_uBBV3N2DBRJczhoiB46ugJKUkUHxGzVe6xIMpjHFM",
        )
        .body(Body::empty())
        .unwrap()
}

fn post_new_acct(url: &str) -> Response<Body> {
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
    let location: String = RE_URL.replace_all("<URL>/acme/acct/7728515", url).into();
    Response::builder()
        .status(201)
        .header("Location", location)
        .body(Body::from(BODY))
        .unwrap()
}

fn post_new_order(url: &str) -> Response<Body> {
    const BODY: &str = r#"{
    "status": "pending",
    "expires": "2019-01-09T08:26:43.570360537Z",
    "identifiers": [
        {
        "type": "dns",
        "value": "acmetest.example.com"
        }
    ],
    "authorizations": [
        "<URL>/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs"
    ],
    "finalize": "<URL>/acme/finalize/7738992/18234324"
    }"#;
    let location: String = RE_URL
        .replace_all("<URL>/acme/order/YTqpYUthlVfwBncUufE8", url)
        .into();
    Response::builder()
        .status(201)
        .header("Location", location)
        .body(Body::from(RE_URL.replace_all(BODY, url)))
        .unwrap()
}

fn post_get_order(url: &str) -> Response<Body> {
    const BODY: &str = r#"{
    "status": "<STATUS>",
    "expires": "2019-01-09T08:26:43.570360537Z",
    "identifiers": [
        {
        "type": "dns",
        "value": "acmetest.example.com"
        }
    ],
    "authorizations": [
        "<URL>/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs"
    ],
    "finalize": "<URL>/acme/finalize/7738992/18234324",
    "certificate": "<URL>/acme/cert/fae41c070f967713109028"
    }"#;
    let b = RE_URL.replace_all(BODY, url).to_string();
    Response::builder().status(200).body(Body::from(b)).unwrap()
}

fn post_authz(url: &str) -> Response<Body> {
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
    Response::builder()
        .status(201)
        .body(Body::from(RE_URL.replace_all(BODY, url)))
        .unwrap()
}

fn post_finalize(_url: &str) -> Response<Body> {
    Response::builder().status(200).body(Body::empty()).unwrap()
}

fn post_certificate(_url: &str) -> Response<Body> {
    Response::builder()
        .status(200)
        .body("CERT HERE".into())
        .unwrap()
}

fn route_request(req: Request<Body>, url: &str) -> Response<Body> {
    match (req.method(), req.uri().path()) {
        (&Method::GET, "/directory") => get_directory(url),
        (&Method::HEAD, "/acme/new-nonce") => head_new_nonce(),
        (&Method::POST, "/acme/new-acct") => post_new_acct(url),
        (&Method::POST, "/acme/new-order") => post_new_order(url),
        (&Method::POST, "/acme/order/YTqpYUthlVfwBncUufE8") => post_get_order(url),
        (&Method::POST, "/acme/authz/YTqpYUthlVfwBncUufE8IRWLMSRqcSs") => post_authz(url),
        (&Method::POST, "/acme/finalize/7738992/18234324") => post_finalize(url),
        (&Method::POST, "/acme/cert/fae41c070f967713109028") => post_certificate(url),
        (_, _) => Response::builder().status(404).body(Body::empty()).unwrap(),
    }
}

pub fn with_directory_server() -> TestServer {
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = tcp.local_addr().unwrap().port();

    let url = format!("http://127.0.0.1:{}", port);
    let dir_url = format!("{url}/directory");

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    let make_service = make_service_fn(move |_| {
        let url = url.clone();
        async move {
            let url = url.clone();
            hyper::Result::Ok(service_fn(move |req| {
                let url = url.clone();
                async move { Ok::<_, Infallible>(route_request(req, &url)) }
            }))
        }
    });

    let server = Server::from_tcp(tcp)
        .unwrap()
        .serve(make_service)
        .with_graceful_shutdown(async {
            rx.await.ok();
        });

    tokio::spawn(server);

    TestServer {
        dir_url,
        shutdown: Some(tx),
    }
}

#[tokio::test]
pub async fn test_make_directory() {
    let server = with_directory_server();
    let res = reqwest::get(&server.dir_url).await.unwrap();
    assert!(res.status().is_success());
}
