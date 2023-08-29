use std::time::Duration;

use crate::{api::ApiProblem, error::*};

pub(crate) type ReqResult<T> = std::result::Result<T, ApiProblem>;

pub(crate) fn req_get(url: &str) -> ureq::Response {
    let client = ureq_agent();
    let req = client.get(url);
    trace!("{req:?}");
    req.call().unwrap()
}

pub(crate) fn req_head(url: &str) -> ureq::Response {
    let client = ureq_agent();
    let req = client.head(url);
    trace!("{req:?}");
    req.call().unwrap()
}

fn ureq_agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(30))
        .timeout_read(Duration::from_secs(30))
        .timeout_write(Duration::from_secs(30))
        .build()
}

pub(crate) fn req_post(url: &str, body: &str) -> ureq::Response {
    let client = ureq_agent();
    let req = client
        .post(url)
        .set("content-type", "application/jose+json");
    trace!("{req:?} {body}");
    req.send_string(body).unwrap()
}

pub(crate) fn req_handle_error(res: ureq::Response) -> ReqResult<ureq::Response> {
    // ok responses pass through
    if (200..=299).contains(&res.status()) {
        return Ok(res);
    }

    let problem = if res.content_type() == "application/problem+json" {
        // if we were sent a problem+json, deserialize it
        let body = req_safe_read_body(res);
        serde_json::from_str(&body).unwrap_or_else(|err| ApiProblem {
            _type: "problemJsonFail".into(),
            detail: Some(format!(
                "Failed to deserialize application/problem+json ({err}) body: {body}"
            )),
            subproblems: None,
        })
    } else {
        // some other problem
        let status = format!("{} {}", res.status(), res.status_text());
        let body = req_safe_read_body(res);
        let detail = format!("{} body: {}", status, body);
        ApiProblem {
            _type: "httpReqError".into(),
            detail: Some(detail),
            subproblems: None,
        }
    };

    Err(problem)
}

pub(crate) fn req_expect_header(res: &ureq::Response, name: &str) -> ReqResult<String> {
    res.header(name)
        .map(|v| v.to_string())
        .ok_or_else(|| ApiProblem {
            _type: format!("Missing header: {}", name),
            detail: None,
            subproblems: None,
        })
}

pub(crate) fn req_safe_read_body(res: ureq::Response) -> String {
    use std::io::Read;
    let mut res_body = String::new();
    let mut read = res.into_reader();
    // letsencrypt sometimes closes the TLS abruptly causing io error
    // even though we did capture the body.
    read.read_to_string(&mut res_body).ok();
    res_body
}
