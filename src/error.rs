pub use anyhow::{anyhow, bail, Context, Error, Result};

use crate::api::ApiProblem;

impl From<ApiProblem> for Error {
    fn from(x: ApiProblem) -> Error {
        anyhow!("{}", x)
    }
}
