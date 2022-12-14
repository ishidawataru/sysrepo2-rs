//
// Copyright (c) The sysrepo2-rs Core Contributors
//
// See LICENSE for license details.
//

use num_traits::FromPrimitive;
use std::ffi::CString;
use std::fmt;

use crate::session::SessionContextHolder;
use crate::value::Value;

use crate::error::{Error, ErrorCode, Result};
use crate::types::*;

use sysrepo2_sys as ffi;

#[derive(Debug)]
pub struct Change {
    pub operation: ChangeOperation,
    pub old: Option<Value>,
    pub new: Option<Value>,
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct Changes<'a, H: SessionContextHolder> {
    sess: &'a H,
    iter: *mut ffi::sr_change_iter_t,
}

impl<H: SessionContextHolder> Changes<'_, H> {
    pub fn new<'a>(sess: &'a H, xpath: &str) -> Result<Changes<'a, H>> {
        let mut iter = std::ptr::null_mut();
        let iter_p = &mut iter;
        let c_xpath = CString::new(xpath).unwrap();

        ErrorCode::from_i32(unsafe {
            ffi::sr_get_changes_iter(sess.raw(), c_xpath.as_ptr(), iter_p)
        })
        .map_or_else(|| Ok(Changes { sess, iter }), |ret| Err(Error::new(ret)))
    }
}

impl<H: SessionContextHolder> Drop for Changes<'_, H> {
    fn drop(&mut self) {
        unsafe { ffi::sr_free_change_iter(self.iter) };
    }
}

impl<H: SessionContextHolder> Iterator for Changes<'_, H> {
    type Item = Change;

    fn next(&mut self) -> Option<Change> {
        let mut op: u32 = 0;
        let op_p = &mut op;

        let mut old = std::ptr::null_mut();
        let old_p = &mut old;

        let mut new = std::ptr::null_mut();
        let new_p = &mut new;

        let ret = unsafe {
            ffi::sr_get_change_next(self.sess.raw(), self.iter, op_p, old_p, new_p) as u32
        };
        if ret != ffi::sr_error_t::SR_ERR_OK {
            return None;
        }
        Some(Change {
            operation: ChangeOperation::from_u32(op).unwrap(),
            old: if old.is_null() {
                None
            } else {
                Some(Value::new(old))
            },
            new: if new.is_null() {
                None
            } else {
                Some(Value::new(new))
            },
        })
    }
}
