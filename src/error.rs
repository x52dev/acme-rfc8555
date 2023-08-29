pub use anyhow::{anyhow, bail, Context, Error, Result};
pub use log::{debug, trace};

use crate::api::ApiProblem;

impl From<ApiProblem> for Error {
    fn from(x: ApiProblem) -> Error {
        anyhow!("{}", x)
    }
}
