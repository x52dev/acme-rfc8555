use crate::api::Problem;

impl From<Problem> for eyre::Error {
    fn from(err: Problem) -> eyre::Error {
        eyre::eyre!("{err}")
    }
}
