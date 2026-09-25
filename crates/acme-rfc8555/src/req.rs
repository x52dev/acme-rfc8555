use std::time::Duration;

use crate::api::Problem;

pub(crate) type ReqResult<T> = std::result::Result<T, Problem>;

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

    let is_problem = res
        .headers()
        .get("content-type")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<mime::Mime>().ok())
        .is_some_and(|media_type| media_type.essence_str() == "application/problem+json");

    let problem = if is_problem {
        // if we were sent a problem+json, deserialize it
        let body = res.text().await.unwrap();

        log::trace!("error response body: {body}");

        serde_json::from_str(&body).unwrap_or_else(|err| Problem {
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
        Problem {
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
        .ok_or_else(|| Problem {
            _type: format!("Missing header: {name}"),
            detail: None,
            subproblems: None,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parses_json_problem_response() {
        let server = acme_test_server::with_directory_server();
        let response = req_get(&server.url("/test/problem")).await;

        let problem = req_handle_error(response).await.unwrap_err();

        assert_eq!(
            problem,
            Problem {
                _type: "badNonce".to_owned(),
                detail: Some("nonce expired".to_owned()),
                subproblems: None,
            }
        );
    }

    #[tokio::test]
    async fn malformed_json_problem_keeps_the_response_body() {
        let server = acme_test_server::with_directory_server();
        let response = req_get(&server.url("/test/malformed-problem")).await;

        let problem = req_handle_error(response).await.unwrap_err();

        assert_eq!(problem._type, "problemJsonFail");
        assert!(problem.detail.unwrap().contains("body: not json"));
    }

    #[tokio::test]
    async fn plain_http_error_keeps_status_and_body() {
        let server = acme_test_server::with_directory_server();
        let response = req_get(&server.url("/test/plain-error")).await;

        let problem = req_handle_error(response).await.unwrap_err();

        assert_eq!(problem._type, "httpReqError");
        let detail = problem.detail.unwrap();
        assert!(detail.contains("400"));
        assert!(detail.contains("upstream failure"));
    }

    #[tokio::test]
    async fn missing_response_header_returns_problem() {
        let server = acme_test_server::with_directory_server();
        let response = req_get(&server.dir_url).await;

        let problem = req_expect_header(&response, "location").unwrap_err();

        assert_eq!(problem._type, "Missing header: location");
    }

    #[tokio::test]
    async fn missing_content_type_returns_http_error() {
        let server = acme_test_server::with_directory_server();
        let response = req_get(&server.url("/error/missing")).await;

        assert!(!response.headers().contains_key("content-type"));

        let problem = req_handle_error(response).await.unwrap_err();

        assert_eq!(problem._type, "httpReqError");

        let detail = problem.detail.unwrap();
        assert!(detail.contains("400"), "{detail}");
        assert!(detail.contains("nonce expired"), "{detail}");
    }

    #[tokio::test]
    async fn malformed_content_type_returns_http_error() {
        let server = acme_test_server::with_directory_server();
        let response = req_get(&server.url("/error/malformed")).await;

        let problem = req_handle_error(response).await.unwrap_err();

        assert_eq!(problem._type, "httpReqError");

        let detail = problem.detail.unwrap();
        assert!(detail.contains("400"), "{detail}");
        assert!(detail.contains("nonce expired"), "{detail}");
    }

    #[tokio::test]
    async fn non_ascii_content_type_returns_http_error() {
        let server = acme_test_server::with_directory_server();
        let response = req_get(&server.url("/error/non-ascii")).await;

        let problem = req_handle_error(response).await.unwrap_err();

        assert_eq!(problem._type, "httpReqError");

        let detail = problem.detail.unwrap();
        assert!(detail.contains("400"), "{detail}");
        assert!(detail.contains("nonce expired"), "{detail}");
    }

    #[tokio::test]
    async fn parameterized_content_type_parses_json_problem() {
        let server = acme_test_server::with_directory_server();
        let response = req_get(&server.url("/error/parameterized")).await;

        let problem = req_handle_error(response).await.unwrap_err();

        assert_eq!(problem._type, "badNonce");
        assert_eq!(problem.detail.as_deref(), Some("nonce expired"));
    }
}
