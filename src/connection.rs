//
// Copyright (c) The sysrepo2-rs Core Contributors
//
// See LICENSE for license details.
//

use crate::error::{Error, ErrorCode, Result};
use crate::session::{ImplicitSession, Session, SessionContextHolder};
use crate::types::*;
use num_traits::FromPrimitive;
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use libyang2_sys::ly_ctx;
use yang2::context::ContextAllocator;

use sysrepo2_sys as ffi;

enum ConnectionOrSession {
    Connection(Arc<Mutex<Connection>>),
    Session(Arc<Mutex<Session>>),
    ImplicitSession(ImplicitSession),
}

pub struct SysrepoContextAllocator {
    ctx: ConnectionOrSession,
    raw: *mut ly_ctx,
}

impl SysrepoContextAllocator {
    pub fn from_connection(conn: Arc<Mutex<Connection>>) -> Self {
        unsafe {
            let ctx = ffi::sr_acquire_context(conn.lock().unwrap().raw());
            let raw = ctx as *mut ly_ctx;
            Self {
                raw: raw,
                ctx: ConnectionOrSession::Connection(conn),
            }
        }
    }

    pub fn from_session(sess: Arc<Mutex<Session>>) -> Self {
        unsafe {
            let ctx = ffi::sr_session_acquire_context(sess.lock().unwrap().raw());
            let raw = ctx as *mut ly_ctx;
            Self {
                raw: raw,
                ctx: ConnectionOrSession::Session(sess),
            }
        }
    }

    pub(crate) fn from_implicit_session(sess: ImplicitSession) -> Self {
        unsafe {
            let ctx = ffi::sr_session_acquire_context(sess.raw());
            let raw = ctx as *mut ly_ctx;
            Self {
                raw: raw,
                ctx: ConnectionOrSession::ImplicitSession(sess),
            }
        }
    }
}

impl Drop for SysrepoContextAllocator {
    fn drop(&mut self) {
        match &self.ctx {
            ConnectionOrSession::Connection(conn) => unsafe {
                ffi::sr_release_context(conn.lock().unwrap().raw())
            },
            ConnectionOrSession::Session(sess) => unsafe {
                ffi::sr_session_release_context(sess.lock().unwrap().raw())
            },
            ConnectionOrSession::ImplicitSession(sess) => unsafe {
                ffi::sr_session_release_context(sess.raw())
            },
        };
    }
}

impl ContextAllocator for SysrepoContextAllocator {
    fn raw(&self) -> *mut ly_ctx {
        self.raw
    }
}

#[derive(Debug)]
pub struct Connection {
    raw: *mut ffi::sr_conn_ctx_t,
}

unsafe impl Send for Connection {}

impl Connection {
    pub fn new(options: ConnectionOptions) -> Result<Connection> {
        let mut conn = std::ptr::null_mut();
        let conn_ptr = &mut conn;

        ErrorCode::from_i32(unsafe { ffi::sr_connect(options.bits(), conn_ptr) })
            .map_or_else(|| Ok(Connection { raw: conn }), |ret| Err(Error::new(ret)))
    }

    pub(crate) fn raw(&self) -> *mut ffi::sr_conn_ctx_t {
        self.raw
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
    use crate::session::Session;
    use std::sync::{Arc, Mutex};
    use yang2::context::Context;

    #[test]
    fn create_connection() {
        let _conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let _conn =
            Connection::new(ConnectionOptions::CACHE_RUNNING).expect("Failed to create connection");
    }

    #[test]
    fn test_session() {
        let conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let conn = Arc::new(Mutex::new(conn));
        let mut sess =
            Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");
        assert_eq!(sess.get_ds(), DatastoreType::RUNNING);
        sess.switch_ds(DatastoreType::OPERATIONAL)
            .expect("Failed to swtich datastore");
        assert_eq!(sess.get_ds(), DatastoreType::OPERATIONAL);
    }

    #[test]
    fn test_multiple_sessions() {
        let conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let conn = Arc::new(Mutex::new(conn));
        let _s1 = Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");
        let _s2 = Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");
    }

    pub(crate) fn ensure_test_module(conn: &Arc<Mutex<Connection>>) -> Result<()> {
        let exists = {
            let a = SysrepoContextAllocator::from_connection(conn.clone());
            let ctx = Context::from_allocator(Box::new(a)).unwrap();
            ctx.get_module("test", None) != None
        };

        if !exists {
            conn.lock()
                .unwrap()
                .install_module("./assets/yang/test.yang", &["./assets/yang"], &[])
                .unwrap();
        }

        let a = SysrepoContextAllocator::from_connection(conn.clone());
        let ctx = Context::from_allocator(Box::new(a)).unwrap();
        let m = ctx.get_module("test", None).unwrap();
        assert_eq!(m.name(), "test");

        Ok(())
    }

    #[test]
    fn test_multiple_contexts() {
        let conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let conn = Arc::new(Mutex::new(conn));

        let a1 = SysrepoContextAllocator::from_connection(Arc::clone(&conn));
        let ctx1 = Context::from_allocator(Box::new(a1)).unwrap();
        ctx1.get_module("test", None);

        let a2 = SysrepoContextAllocator::from_connection(Arc::clone(&conn));
        let ctx2 = Context::from_allocator(Box::new(a2)).unwrap();
        ctx2.get_module("test", None);
    }

    #[test]
    fn test_session_context() {
        let conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let conn = Arc::new(Mutex::new(conn));
        let sess = Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");
        let sess = Arc::new(Mutex::new(sess));
        let a = SysrepoContextAllocator::from_session(sess);
        Context::from_allocator(Box::new(a)).unwrap();
    }

    #[test]
    fn test_install_and_remove_module() {
        let conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let conn = Arc::new(Mutex::new(conn));

        ensure_test_module(&conn).expect("Failed to ensure module");

        {
            conn.lock()
                .unwrap()
                .remove_module("test", false)
                .expect("Failed to remove module");
        }

        {
            let a = SysrepoContextAllocator::from_connection(Arc::clone(&conn));
            let ctx = Context::from_allocator(Box::new(a)).unwrap();
            let m = ctx.get_module("test", None);
            assert_eq!(m, None);
        }

        ensure_test_module(&conn).expect("Failed to install module");
    }
}
