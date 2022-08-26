//
// Copyright (c) The sysrepo2-rs Core Contributors
//
// See LICENSE for license details.
//

use num_derive::FromPrimitive;
use sysrepo2_sys as ffi;
use yang2::Error as YError;

use crate::utils::*;

pub type Result<T> = std::result::Result<T, Error>;

#[allow(clippy::upper_case_acronyms)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq, FromPrimitive)]
pub enum ErrorCode {
    // intentionally drop this
    // Ok = ffi::sr_error_t::SR_ERR_OK,
    InvalArg = ffi::sr_error_t::SR_ERR_INVAL_ARG,
    Ly = ffi::sr_error_t::SR_ERR_LY,
    Sys = ffi::sr_error_t::SR_ERR_SYS,
    NoMemory = ffi::sr_error_t::SR_ERR_NO_MEMORY,
    NotFound = ffi::sr_error_t::SR_ERR_NOT_FOUND,
    Exists = ffi::sr_error_t::SR_ERR_EXISTS,
    Internal = ffi::sr_error_t::SR_ERR_INTERNAL,
    Unsupported = ffi::sr_error_t::SR_ERR_UNSUPPORTED,
    ValidationFailed = ffi::sr_error_t::SR_ERR_VALIDATION_FAILED,
    OperationFailed = ffi::sr_error_t::SR_ERR_OPERATION_FAILED,
    Unauthorized = ffi::sr_error_t::SR_ERR_UNAUTHORIZED,
    Locked = ffi::sr_error_t::SR_ERR_LOCKED,
    TimeOut = ffi::sr_error_t::SR_ERR_TIME_OUT,
    CallbackFailed = ffi::sr_error_t::SR_ERR_CALLBACK_FAILED,
    CallbackShelve = ffi::sr_error_t::SR_ERR_CALLBACK_SHELVE,
}

impl Into<i32> for ErrorCode {
    fn into(self) -> i32 {
        self as i32
    }
}

/// Enum listing possible errors from yang2-rs.
#[derive(Debug, Eq, PartialEq)]
pub struct Error {
    pub errcode: ErrorCode,
    pub msg: Option<String>,
    pub error_format: Option<String>,
}

impl Error {
    pub fn new(errcode: ErrorCode) -> Error {
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
            errcode: ErrorCode::Ly,
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
            write!(f, "Unknown error: {:?}", self.errcode)
        }
    }
}

impl std::error::Error for Error {}
