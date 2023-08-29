use base64::prelude::*;
use serde::de;

use crate::{error::*, req::req_safe_read_body};

pub(crate) fn base64url<T: ?Sized + AsRef<[u8]>>(input: &T) -> String {
    BASE64_URL_SAFE_NO_PAD.encode(input)
}

pub(crate) fn read_json<T: de::DeserializeOwned>(res: ureq::Response) -> Result<T> {
    let res_body = req_safe_read_body(res);
    debug!("{}", res_body);
    Ok(serde_json::from_str(&res_body)?)
}
