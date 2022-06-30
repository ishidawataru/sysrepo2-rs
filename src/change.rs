//
// Copyright (c) The sysrepo2-rs Core Contributors
//
// See LICENSE for license details.
//

use num_traits::FromPrimitive;
use std::ffi::CString;
use std::fmt;

use crate::session::Session;
use crate::value::Value;

use crate::error::{Error, Result};
use crate::types::*;

use sysrepo2_sys as ffi;

#[derive(Debug)]
pub struct Change {
    _operation: ChangeOperation,
    _old: Option<Value>,
    _new: Option<Value>,
}

impl fmt::Display for Change {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub struct Changes<'a> {
    sess: &'a Session<'a>,
    iter: *mut ffi::sr_change_iter_t,
}

impl<'a> Changes<'a> {
    pub fn new(sess: &'a Session, xpath: &str) -> Result<Changes<'a>> {
        let mut iter = std::ptr::null_mut();
        let iter_p = &mut iter;
        let c_xpath = CString::new(xpath).unwrap();

        let ret =
            unsafe { ffi::sr_get_changes_iter(sess.inner.0, c_xpath.as_ptr(), iter_p) as u32 };
        if ret != ffi::sr_error_t::SR_ERR_OK {
            return Err(Error::new(ret));
        }
        Ok(Changes { sess, iter })
    }
}

impl<'a> Drop for Changes<'a> {
    fn drop(&mut self) {
        unsafe { ffi::sr_free_change_iter(self.iter) };
    }
}

impl Iterator for Changes<'_> {
    type Item = Change;

    fn next(&mut self) -> Option<Change> {
        let mut op: u32 = 0;
        let op_p = &mut op;

        let mut old = std::ptr::null_mut();
        let old_p = &mut old;

        let mut new = std::ptr::null_mut();
        let new_p = &mut new;

        let ret = unsafe {
            ffi::sr_get_change_next(self.sess.inner.0, self.iter, op_p, old_p, new_p) as u32
        };
        if ret != ffi::sr_error_t::SR_ERR_OK {
            return None;
        }
        Some(Change {
            _operation: ChangeOperation::from_u32(op).unwrap(),
            _old: if old.is_null() {
                None
            } else {
                Some(Value::new(old))
            },
            _new: if new.is_null() {
                None
            } else {
                Some(Value::new(new))
            },
        })
    }
}
