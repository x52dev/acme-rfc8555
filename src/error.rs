use crate::api::ApiProblem;

impl From<ApiProblem> for eyre::Error {
    fn from(err: ApiProblem) -> eyre::Error {
        eyre::eyre!("{err}")
    }
}
