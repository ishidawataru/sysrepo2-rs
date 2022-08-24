//
// Copyright (c) The sysrepo2-rs Core Contributors
//
// See LICENSE for license details.
//

use sysrepo2_sys as ffi;
use yang2::Error as YError;

use crate::utils::*;

pub type Result<T> = std::result::Result<T, Error>;

/// Enum listing possible errors from yang2-rs.
#[derive(Debug, Eq, PartialEq)]
pub struct Error {
    pub errcode: ffi::sr_error_t::Type,
    pub msg: Option<String>,
    pub error_format: Option<String>,
}

impl Error {
    pub fn new(errcode: ffi::sr_error_t::Type) -> Error {
        let msg = char_ptr_to_opt_string(unsafe { ffi::sr_strerror(errcode as i32) });
        let error_format = None;
        Self {
            errcode,
            msg,
            error_format,
        }
    }
}

impl From<YError> for Error {
    fn from(v: YError) -> Self {
        Error {
            errcode: ffi::sr_error_t::SR_ERR_LY,
            msg: v.msg,
            error_format: None,
        }
    }
}

impl std::fmt::Display for Error {
    // Print only the base error message by default.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(msg) = &self.msg {
            write!(f, "{}", msg)
        } else {
            write!(f, "Unknown error: {}", self.errcode)
        }
    }
}

impl std::error::Error for Error {}
