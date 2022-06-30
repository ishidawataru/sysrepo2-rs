use num_derive::FromPrimitive;
//
// Copyright (c) The yang2-rs Core Contributors
//
// See LICENSE for license details.

use num_traits::FromPrimitive;
use std::ffi::CString;

use crate::utils::*;

use sysrepo2_sys as ffi;

#[allow(clippy::upper_case_acronyms)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum LogLevel {
    NONE = ffi::sr_log_level_t::SR_LL_NONE,
    ERR = ffi::sr_log_level_t::SR_LL_ERR,
    WRN = ffi::sr_log_level_t::SR_LL_WRN,
    INF = ffi::sr_log_level_t::SR_LL_INF,
    DBG = ffi::sr_log_level_t::SR_LL_DBG,
}

pub fn log_stderr(level: LogLevel) {
    unsafe {
        ffi::sr_log_stderr(level as u32);
    }
}

pub fn log_get_stderr() -> LogLevel {
    unsafe { LogLevel::from_u32(ffi::sr_log_get_stderr()).unwrap() }
}

static mut SYSLOG_APPNAME: Option<Box<CString>> = None;

pub fn log_syslog(app_name: &str, level: LogLevel) {
    let app = Box::new(CString::new(app_name.as_bytes()).unwrap());
    unsafe {
        SYSLOG_APPNAME = Some(app);
        ffi::sr_log_syslog(SYSLOG_APPNAME.as_ref().unwrap().as_ptr(), level as u32)
    }
}

pub fn log_get_syslog() -> LogLevel {
    unsafe { LogLevel::from_u32(ffi::sr_log_get_syslog()).unwrap() }
}

type LogCallback = Box<dyn Fn(LogLevel, &str) + Send + Sync>;

static mut LOG_CALLBACK: Option<LogCallback> = None;

extern "C" fn callback_wrapper(
    level: ffi::sr_log_level_t::Type,
    message: *const ::std::os::raw::c_char,
) {
    unsafe {
        if let Some(cb) = &LOG_CALLBACK {
            cb(LogLevel::from_u32(level).unwrap(), char_ptr_to_str(message));
        }
    }
}

pub fn log_set_cb(cb: LogCallback) {
    unsafe {
        LOG_CALLBACK = Some(cb);
        ffi::sr_log_set_cb(Some(callback_wrapper))
    }
}

#[cfg(test)]
mod tests {
    use crate::connection::Connection;
    use crate::log::*;
    use crate::types::*;
    use std::sync::{Arc, Mutex};

    #[test]
    fn test_log_stderr() {
        log_stderr(LogLevel::INF);
        assert_eq!(log_get_stderr(), LogLevel::INF);
    }

    #[test]
    fn test_log_syslog() {
        log_syslog("sysrepo", LogLevel::INF);
        assert_eq!(log_get_syslog(), LogLevel::INF);
    }

    #[test]
    fn test_log_set_cb() {
        let logs = Arc::new(Mutex::new(Vec::new()));
        let llogs = logs.clone();
        log_set_cb(Box::new(move |l: LogLevel, m: &str| {
            llogs.lock().unwrap().push((l, m.to_string()))
        }));
        let _conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");

        assert_eq!(logs.lock().unwrap().len(), 1);
    }
}
