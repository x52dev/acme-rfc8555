use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Identifier {
    #[serde(rename = "type")]
    pub _type: String,
    pub value: String,
}

impl Identifier {
    pub(crate) fn dns(value: &str) -> Self {
        Self {
            _type: "dns".to_owned(),
            value: value.to_owned(),
        }
    }

    pub fn is_type_dns(&self) -> bool {
        self._type == "dns"
    }
}
