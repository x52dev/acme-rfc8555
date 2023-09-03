use std::time::Duration;

use crate::api::ApiProblem;

pub(crate) type ReqResult<T> = std::result::Result<T, ApiProblem>;

pub(crate) async fn req_get(url: &str) -> reqwest::Response {
    let client = http_client();
    let req = client.get(url);
    log::trace!("{req:?}");
    req.send().await.unwrap()
}

pub(crate) async fn req_head(url: &str) -> reqwest::Response {
    let client = http_client();
    let req = client.head(url).header("cache-control", "no-store");
    log::trace!("{req:?}");
    req.send().await.unwrap()
}

fn http_client() -> reqwest::Client {
    reqwest::ClientBuilder::new()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

pub(crate) async fn req_post(url: &str, body: &str) -> reqwest::Response {
    let client = http_client();
    let req = client
        .post(url)
        .header("content-type", "application/jose+json");
    log::trace!("{req:?} {body}");
    req.body(body.to_owned()).send().await.unwrap()
}

pub(crate) async fn req_handle_error(res: reqwest::Response) -> ReqResult<reqwest::Response> {
    // ok responses pass through
    if res.status().is_success() {
        return Ok(res);
    }

    let problem = if res.headers().get("content-type").unwrap() == "application/problem+json" {
        // if we were sent a problem+json, deserialize it
        let body = res.text().await.unwrap();

        log::trace!("error response body: {body}");

        serde_json::from_str(&body).unwrap_or_else(|err| ApiProblem {
            _type: "problemJsonFail".to_owned(),
            detail: Some(format!(
                "Failed to deserialize application/problem+json ({err}) body: {body}"
            )),
            subproblems: None,
        })
    } else {
        // some other problem
        let status = format!("{} {}", res.status(), res.status().as_str());
        let body = res.text().await.unwrap();
        let detail = format!("{status} body: {body}");
        ApiProblem {
            _type: "httpReqError".to_owned(),
            detail: Some(detail),
            subproblems: None,
        }
    };

    Err(problem)
}

pub(crate) fn req_expect_header(res: &reqwest::Response, name: &str) -> ReqResult<String> {
    res.headers()
        .get(name)
        .map(|v| v.to_str().unwrap().to_owned())
        .ok_or_else(|| ApiProblem {
            _type: format!("Missing header: {name}"),
            detail: None,
            subproblems: None,
        })
}
