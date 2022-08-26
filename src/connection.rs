//
// Copyright (c) The sysrepo2-rs Core Contributors
//
// See LICENSE for license details.
//

use crate::error::{Error, ErrorCode, Result};
use num_traits::FromPrimitive;
use std::ffi::CString;
use std::ops::Deref;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::session::{Session, SessionInner};
use crate::types::*;

use libyang2_sys::ly_ctx;
use yang2::context::Context as YContext;

use sysrepo2_sys as ffi;

pub struct Connection {
    pub(crate) raw: *mut ffi::sr_conn_ctx_t,
}

pub enum ConnectionOrSession<'a> {
    Connection(&'a Connection),
    Session(&'a Session<'a>),
}

pub struct Context<'a> {
    ctx: ConnectionOrSession<'a>,
    pub(crate) raw: Option<YContext>,
}

impl<'a> Context<'a> {
    fn from_connection(conn: &'a Connection) -> Context<'a> {
        unsafe {
            let ctx = ffi::sr_acquire_context(conn.raw);
            let raw = YContext::from_raw(ctx as *mut ly_ctx);
            Context {
                raw: Some(raw),
                ctx: ConnectionOrSession::Connection(conn),
            }
        }
    }

    pub(crate) fn from_session(sess: &'a Session<'a>) -> Context<'a> {
        unsafe {
            let ctx = ffi::sr_session_acquire_context(sess.inner.0);
            let raw = YContext::from_raw(ctx as *mut ly_ctx);
            Context {
                raw: Some(raw),
                ctx: ConnectionOrSession::Session(sess),
            }
        }
    }
}

impl<'a> Deref for Context<'a> {
    type Target = YContext;

    fn deref(&self) -> &Self::Target {
        &self.raw.as_ref().unwrap()
    }
}

impl<'a> Drop for Context<'a> {
    fn drop(&mut self) {
        // we must free self.raw by using sr_release_context() or sr_session_release_context().
        // take the ownership of self.raw here and use std::mem::forget() so that
        // YContext::drop() doesn't get executed for the ctx.
        std::mem::forget(std::mem::replace(&mut self.raw, None));

        match self.ctx {
            ConnectionOrSession::Connection(conn) => unsafe { ffi::sr_release_context(conn.raw) },
            ConnectionOrSession::Session(sess) => unsafe {
                ffi::sr_session_release_context(sess.inner.0)
            },
        };
    }
}

impl Connection {
    pub fn new(options: ConnectionOptions) -> Result<Connection> {
        let mut conn = std::ptr::null_mut();
        let conn_ptr = &mut conn;

        ErrorCode::from_i32(unsafe { ffi::sr_connect(options.bits(), conn_ptr) })
            .map_or_else(|| Ok(Connection { raw: conn }), |ret| Err(Error::new(ret)))
    }

    pub fn create_session(&mut self, t: DatastoreType) -> Result<Session> {
        let mut sess = std::ptr::null_mut();
        let sess_ptr = &mut sess;

        ErrorCode::from_i32(unsafe { ffi::sr_session_start(self.raw, t as u32, sess_ptr) })
            .map_or_else(
                || {
                    Ok(Session {
                        _sub_callbacks: Vec::new(),
                        _sub_handles: Vec::new(),
                        _sub_ctxs: Vec::new(),
                        inner: SessionInner(sess),
                        _marker: std::marker::PhantomData,
                    })
                },
                |ret| Err(Error::new(ret)),
            )
    }

    pub fn get_context(&self) -> Context {
        Context::from_connection(self)
    }

    pub fn get_content_id(&self) -> u32 {
        unsafe { ffi::sr_get_content_id(self.raw) }
    }

    pub fn install_module<P: AsRef<Path>>(
        &mut self,
        schema_path: P,
        search_dirs: &[P],
        features: &[&str],
    ) -> Result<()> {
        let schema_path = CString::new(schema_path.as_ref().as_os_str().as_bytes()).unwrap();
        let search_dirs = search_dirs
            .iter()
            .map(|s| s.as_ref().to_str().unwrap())
            .collect::<Vec<_>>()
            .join(":");
        let search_dirs = CString::new(search_dirs).unwrap();

        let mut ptrs = Vec::new();
        let mut strs = Vec::new();

        for f in features {
            let c_str = CString::new(f.as_bytes()).unwrap();
            ptrs.push(c_str.as_ptr());
            strs.push(c_str);
        }

        ptrs.push(std::ptr::null());

        ErrorCode::from_i32(unsafe {
            ffi::sr_install_module(
                self.raw,
                schema_path.as_ptr(),
                search_dirs.as_ptr(),
                ptrs.as_ptr() as *mut *const ::std::os::raw::c_char,
            )
        })
        .map_or_else(|| Ok(()), |ret| Err(Error::new(ret)))
    }

    pub fn remove_module(&mut self, module_name: &str, force: bool) -> Result<()> {
        ErrorCode::from_i32(unsafe {
            let m = CString::new(module_name.as_bytes()).unwrap();
            ffi::sr_remove_module(self.raw, m.as_ptr(), if force { 1 } else { 0 })
        })
        .map_or_else(|| Ok(()), |ret| Err(Error::new(ret)))
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        unsafe { ffi::sr_disconnect(self.raw) };
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use crate::connection::*;

    #[test]
    fn create_connection() {
        let _conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let _conn =
            Connection::new(ConnectionOptions::CACHE_RUNNING).expect("Failed to create connection");
    }

    #[test]
    fn test_session() {
        let mut conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let mut sess = conn
            .create_session(DatastoreType::RUNNING)
            .expect("Failed to create session");
        assert_eq!(sess.get_ds(), DatastoreType::RUNNING);
        sess.switch_ds(DatastoreType::OPERATIONAL)
            .expect("Failed to swtich datastore");
        assert_eq!(sess.get_ds(), DatastoreType::OPERATIONAL);
    }

    pub(crate) fn ensure_test_module(conn: &mut Connection) -> Result<()> {
        let exists = {
            let ctx = conn.get_context();
            let m = ctx.get_module("test", None);
            m != None
        };

        if !exists {
            conn.install_module("./assets/yang/test.yang", &["./assets/yang"], &[])
                .unwrap();
        }

        let ctx = conn.get_context();
        let m = ctx.get_module("test", None).unwrap();
        assert_eq!(m.name(), "test");

        Ok(())
    }

    #[test]
    fn test_install_and_remove_module() {
        let mut conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        ensure_test_module(&mut conn).expect("Failed to ensure module");

        conn.remove_module("test", false)
            .expect("Failed to remove module");

        {
            let ctx = conn.get_context();
            let m = ctx.get_module("test", None);
            assert_eq!(m, None);
        }

        ensure_test_module(&mut conn).expect("Failed to install module");
    }
}
