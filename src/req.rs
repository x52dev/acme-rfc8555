use std::time::Duration;

use crate::api::ApiProblem;

pub(crate) type ReqResult<T> = std::result::Result<T, ApiProblem>;

pub(crate) async fn req_get(url: &str) -> reqwest::Response {
    let client = ureq_agent();
    let req = client.get(url);
    log::trace!("{req:?}");
    req.send().await.unwrap()
}

pub(crate) async fn req_head(url: &str) -> reqwest::Response {
    let client = ureq_agent();
    let req = client.head(url);
    log::trace!("{req:?}");
    req.send().await.unwrap()
}

fn ureq_agent() -> reqwest::Client {
    reqwest::ClientBuilder::new()
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(30))
        .build()
        .unwrap()
}

pub(crate) async fn req_post(url: &str, body: &str) -> reqwest::Response {
    let client = ureq_agent();
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
        let body = req_safe_read_body(res).await;
        serde_json::from_str(&body).unwrap_or_else(|err| ApiProblem {
            _type: "problemJsonFail".into(),
            detail: Some(format!(
                "Failed to deserialize application/problem+json ({err}) body: {body}"
            )),
            subproblems: None,
        })
    } else {
        // some other problem
        let status = format!("{} {}", res.status(), res.status().as_str());
        let body = req_safe_read_body(res).await;
        let detail = format!("{} body: {}", status, body);
        ApiProblem {
            _type: "httpReqError".into(),
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
            _type: format!("Missing header: {}", name),
            detail: None,
            subproblems: None,
        })
}

pub(crate) async fn req_safe_read_body(res: reqwest::Response) -> String {
    res.text().await.unwrap()

    // let mut res_body = String::new();
    // let mut read = res.text().await.unwrap();
    // // letsencrypt sometimes closes the TLS abruptly causing io error
    // // even though we did capture the body.
    // read.read_to_string(&mut res_body).ok();
    // res_body
}
