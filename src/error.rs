use anyhow::{anyhow, Error};

use crate::api::ApiProblem;

impl From<ApiProblem> for Error {
    fn from(err: ApiProblem) -> Error {
        anyhow!("{err}")
    }
}
