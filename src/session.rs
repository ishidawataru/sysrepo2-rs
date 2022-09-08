//
// Copyright (c) The sysrepo2-rs Core Contributors
//
// See LICENSE for license details.
//

use std::ffi::CString;
use std::future::Future;
use std::os::unix::io::RawFd;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use crate::change::{Change, Changes};
use crate::connection::{Connection, SysrepoContextAllocator};
use crate::error::{Error, ErrorCode, Result};
use crate::types::*;
use crate::utils::*;
use crate::value::Value;

use num_traits::FromPrimitive;

use tokio::io::unix::AsyncFd;
use tokio::runtime::Handle;
use tokio::task;

use sysrepo2_sys as ffi;

use yang2::context::Context;
use yang2::data::{Data, DataTree};

use libyang2_sys;

pub type ModuleChangeCallbackSync = Box<dyn FnMut(EventType, u32, Vec<Change>) -> Result<()>>;

pub type ModuleChangeCallbackAsync =
    Box<dyn FnMut(EventType, u32, Vec<Change>) -> Pin<Box<dyn Future<Output = Result<()>>>>>;

pub enum ModuleChangeCallback {
    Sync(ModuleChangeCallbackSync),
    Async(ModuleChangeCallbackAsync),
}

pub type OperGetItemsCallbackSync = Box<dyn FnMut(&str, Arc<Context>) -> Result<DataTree>>;

pub type OperGetItemsCallbackAsync =
    Box<dyn FnMut(&str, Arc<Context>) -> Pin<Box<dyn Future<Output = Result<DataTree>>>>>;

pub enum OperGetItemsCallback {
    Sync(OperGetItemsCallbackSync),
    Async(OperGetItemsCallbackAsync),
}

pub enum SubscriptionCallback {
    ModuleChangeCallback(Box<ModuleChangeCallback>),
    OperGetItemsCallback(Box<OperGetItemsCallback>),
}

pub struct Subscription(*mut ffi::sr_subscription_ctx_t);

unsafe impl Send for Subscription {}

impl Drop for Subscription {
    fn drop(&mut self) {
        unsafe {
            ffi::sr_unsubscribe(self.0);
        }
    }
}

unsafe extern "C" fn module_change_callback(
    session: *mut ffi::sr_session_ctx_t,
    _sub_id: u32,
    module_name: *const ::std::os::raw::c_char,
    _xpath: *const ::std::os::raw::c_char,
    event: ffi::sr_event_t::Type,
    request_id: u32,
    private_data: *mut ::std::os::raw::c_void,
) -> ::std::os::raw::c_int {
    let callback = &mut *(private_data as *mut ModuleChangeCallback);

    let module = char_ptr_to_str(module_name);
    let path = format!("/{}:*//.", module);

    // Note from sysrepo-python subscription.py
    //
    // ATTENTION: the implicit session passed as argument will be
    // freed when this function returns. The callback must NOT
    // keep a reference on it as it will be invalid. Changes must be
    // gathered now.
    //
    let sess = ImplicitSession(session);
    let changes = sess.get_changes(&path).unwrap();
    let changes: Vec<Change> = changes.collect();

    let evtype = EventType::from_u32(event as u32).unwrap();

    let ret = match callback {
        ModuleChangeCallback::Async(ref mut callback) => task::block_in_place(|| {
            let current = Handle::current();
            current.block_on(async { callback(evtype, request_id, changes).await })
        }),
        ModuleChangeCallback::Sync(ref mut callback) => callback(evtype, request_id, changes),
    };

    match ret {
        Ok(_) => 0,
        Err(e) => e.errcode.try_into().unwrap(),
    }
}

unsafe extern "C" fn oper_get_items_callback(
    session: *mut ffi::sr_session_ctx_t,
    _sub_id: u32,
    _module_name: *const ::std::os::raw::c_char,
    _path: *const ::std::os::raw::c_char,
    request_xpath: *const ::std::os::raw::c_char,
    _request_id: u32,
    parent: *mut *mut ffi::lyd_node,
    private_data: *mut ::std::os::raw::c_void,
) -> ::std::os::raw::c_int {
    let callback = &mut *(private_data as *mut OperGetItemsCallback);

    let req_xpath = char_ptr_to_str(request_xpath);

    let a = SysrepoContextAllocator::from_implicit_session(ImplicitSession(session));
    let ctx = Arc::new(Context::from_allocator(Box::new(a)).unwrap());

    let src = match callback {
        OperGetItemsCallback::Sync(callback) => callback(req_xpath, ctx),
        OperGetItemsCallback::Async(callback) => task::block_in_place(|| {
            let current = Handle::current();
            current.block_on(callback(req_xpath, ctx))
        }),
    };

    if let Err(e) = src {
        return e.errcode.try_into().unwrap();
    }

    let src = src.unwrap();
    let a = SysrepoContextAllocator::from_implicit_session(ImplicitSession(session));
    let ctx = Arc::new(Context::from_allocator(Box::new(a)).unwrap());
    let mut dst = DataTree::new(&ctx);
    dst.replace(*parent as *mut libyang2_sys::lyd_node);
    if let Err(_) = dst.merge(&src) {
        return ErrorCode::Ly.into();
    }

    *parent = dst.replace(std::ptr::null_mut()) as *mut ffi::lyd_node;

    0 // Ok
}

pub struct ImplicitSession(*mut ffi::sr_session_ctx_t);

pub trait SessionContextHolder {
    fn raw(&self) -> *mut ffi::sr_session_ctx_t;
}

impl SessionContextHolder for ImplicitSession {
    fn raw(&self) -> *mut ffi::sr_session_ctx_t {
        self.0
    }
}

impl ImplicitSession {
    pub fn get_changes(&self, xpath: &str) -> Result<Changes<Self>> {
        Changes::new(self, xpath)
    }
}

pub(crate) struct SessionInner(pub *mut ffi::sr_session_ctx_t);

impl Drop for SessionInner {
    fn drop(&mut self) {
        unsafe { ffi::sr_session_stop(self.0) };
    }
}

pub struct Session {
    pub(crate) _sub_ctxs: Vec<Subscription>,
    pub(crate) _sub_callbacks: Vec<SubscriptionCallback>,
    pub(crate) _sub_handles: Vec<task::JoinHandle<()>>,
    pub(crate) inner: SessionInner,
    pub(crate) _conn: Option<Arc<Mutex<Connection>>>,
}

unsafe impl Send for Session {}

impl SessionContextHolder for Session {
    fn raw(&self) -> *mut ffi::sr_session_ctx_t {
        self.inner.0
    }
}

impl Session {
    pub fn new(conn: &Arc<Mutex<Connection>>, t: DatastoreType) -> Result<Session> {
        let mut sess = std::ptr::null_mut();
        let sess_ptr = &mut sess;

        ErrorCode::from_i32(unsafe {
            ffi::sr_session_start(conn.lock().unwrap().raw(), t as u32, sess_ptr)
        })
        .map_or_else(
            || {
                Ok(Session {
                    _sub_callbacks: Vec::new(),
                    _sub_handles: Vec::new(),
                    _sub_ctxs: Vec::new(),
                    inner: SessionInner(sess),
                    _conn: Some(Arc::clone(conn)),
                })
            },
            |ret| Err(Error::new(ret)),
        )
    }

    pub fn switch_ds(&mut self, t: DatastoreType) -> Result<()> {
        ErrorCode::from_i32(unsafe { ffi::sr_session_switch_ds(self.inner.0, t as u32) })
            .map_or_else(|| Ok(()), |ret| Err(Error::new(ret)))
    }

    pub fn get_ds(&self) -> DatastoreType {
        let dstype = unsafe { ffi::sr_session_get_ds(self.inner.0) };
        match dstype {
            ffi::sr_datastore_t::SR_DS_STARTUP => DatastoreType::STARTUP,
            ffi::sr_datastore_t::SR_DS_RUNNING => DatastoreType::RUNNING,
            ffi::sr_datastore_t::SR_DS_CANDIDATE => DatastoreType::CANDIDATE,
            ffi::sr_datastore_t::SR_DS_OPERATIONAL => DatastoreType::OPERATIONAL,
            _ => panic!("unknown datastore type"),
        }
    }

    pub fn set_orig_name(&mut self, orig_name: &str) -> Result<()> {
        ErrorCode::from_i32(unsafe {
            ffi::sr_session_set_orig_name(
                self.inner.0,
                orig_name.as_ptr() as *const ::std::os::raw::c_char,
            )
        })
        .map_or_else(|| Ok(()), |ret| Err(Error::new(ret)))
    }

    pub fn get_orig_name(&self) -> Option<&str> {
        unsafe { char_ptr_to_opt_str(ffi::sr_session_get_orig_name(self.inner.0)) }
    }

    pub fn get_item(&self, path: &str, timeout_ms: u32) -> Result<Value> {
        let mut value = std::ptr::null_mut();
        let value_ptr = &mut value;

        let c_string = CString::new(path).unwrap();

        ErrorCode::from_i32(unsafe {
            ffi::sr_get_item(self.inner.0, c_string.as_ptr(), timeout_ms, value_ptr)
        })
        .map_or_else(
            || {
                Ok(Value {
                    raw: value,
                    _owned: None,
                })
            },
            |ret| Err(Error::new(ret)),
        )
    }

    pub fn get_changes(&self, xpath: &str) -> Result<Changes<Self>> {
        Changes::new(self, xpath)
    }

    /// Prepare to set (create) the value of a leaf, leaf-list, list, or presence container.
    /// These changes are applied only after calling Session::apply_changes().
    /// Data are represented as Value structures.
    pub fn set_item(&mut self, path: &str, value: &Value, options: EditOptions) -> Result<()> {
        let c_path = CString::new(path).unwrap();
        ErrorCode::from_i32(unsafe {
            ffi::sr_set_item(self.inner.0, c_path.as_ptr(), value.raw, options.bits())
        })
        .map_or_else(|| Ok(()), |ret| Err(Error::new(ret)))
    }

    /// Prepare to set (create) the value of a leaf, leaf-list, list, or presence container.
    /// These changes are applied only after calling Session::apply_changes().
    /// Data are represented as pairs of a path and string value.
    pub fn set_item_str(
        &mut self,
        path: &str,
        value: &str,
        origin: Option<&str>,
        options: EditOptions,
    ) -> Result<()> {
        let c_path = CString::new(path).unwrap();
        let c_value = CString::new(value).unwrap();
        let c_origin = if let Some(o) = origin {
            Some(CString::new(o).unwrap())
        } else {
            None
        };

        ErrorCode::from_i32(unsafe {
            ffi::sr_set_item_str(
                self.inner.0,
                c_path.as_ptr(),
                c_value.as_ptr(),
                if c_origin.is_none() {
                    std::ptr::null()
                } else {
                    c_origin.unwrap().as_ptr()
                },
                options.bits(),
            )
        })
        .map_or_else(|| Ok(()), |ret| Err(Error::new(ret)))
    }

    /// Prepare to delete the nodes matching the specified xpath. These changes are applied only
    /// after calling Session::apply_changes(). The accepted values are the same as for Session::set_item_str().
    pub fn delete_item(&mut self, path: &str, options: EditOptions) -> Result<()> {
        let c_path = CString::new(path).unwrap();
        ErrorCode::from_i32(unsafe {
            ffi::sr_delete_item(self.inner.0, c_path.as_ptr(), options.bits())
        })
        .map_or_else(|| Ok(()), |ret| Err(Error::new(ret)))
    }

    /// Perform the validation a datastore and any changes made in the current session, but do not
    /// apply nor discard them.
    pub fn validate(&self, module_name: &str, timeout_ms: u32) -> Result<()> {
        let c_path = CString::new(module_name).unwrap();
        ErrorCode::from_i32(unsafe { ffi::sr_validate(self.inner.0, c_path.as_ptr(), timeout_ms) })
            .map_or_else(|| Ok(()), |ret| Err(Error::new(ret)))
    }

    /// Apply changes made in the current session.
    /// In case the changes could not be applied successfully for any reason,
    /// they remain intact in the session.
    pub fn apply_changes(&mut self, timeout_ms: u32) -> Result<()> {
        ErrorCode::from_i32(unsafe { ffi::sr_apply_changes(self.inner.0, timeout_ms) })
            .map_or_else(|| Ok(()), |ret| Err(Error::new(ret)))
    }

    /// Learn whether there are any prepared non-applied changes in the session.
    pub fn has_changes(&self) -> bool {
        let ret = unsafe { ffi::sr_has_changes(self.inner.0) as u32 };
        ret != 0
    }

    /// Discard prepared changes made in the current session.
    pub fn discard_changes(&mut self) -> Result<()> {
        ErrorCode::from_i32(unsafe { ffi::sr_discard_changes(self.inner.0) })
            .map_or_else(|| Ok(()), |ret| Err(Error::new(ret)))
    }

    /// Replace a datastore with the contents of a data tree. If the module is specified, limit
    /// the operation only to the specified module. If it is not specified, the operation is performed on all modules.
    pub fn replace_config(
        &self,
        module_name: &str,
        src_config: &DataTree,
        timeout_ms: u32,
    ) -> Result<()> {
        let c_path = CString::new(module_name).unwrap();
        ErrorCode::from_i32(unsafe {
            let c_config = src_config.raw() as *mut ffi::lyd_node;
            ffi::sr_replace_config(self.inner.0, c_path.as_ptr(), c_config, timeout_ms)
        })
        .map_or_else(|| Ok(()), |ret| Err(Error::new(ret)))
    }

    pub fn subscribe_module_change(
        &mut self,
        mod_name: &str,
        xpath: Option<&str>,
        callback: ModuleChangeCallbackSync,
        priority: u32,
        options: SubscriptionOptions,
    ) -> Result<()> {
        let sub = self._subscribe_module_change(
            mod_name,
            xpath,
            ModuleChangeCallback::Sync(callback),
            priority,
            options,
        )?;
        self._sub_ctxs.push(sub);
        Ok(())
    }

    pub fn subscribe_module_change_async(
        &mut self,
        mod_name: &str,
        xpath: Option<&str>,
        callback: ModuleChangeCallbackAsync,
        priority: u32,
        options: SubscriptionOptions,
    ) -> Result<()> {
        let sub = self._subscribe_module_change(
            mod_name,
            xpath,
            ModuleChangeCallback::Async(callback),
            priority,
            options | SubscriptionOptions::NO_THREAD,
        )?;
        self.handle_event(sub)
    }

    fn _subscribe_module_change(
        &mut self,
        mod_name: &str,
        xpath: Option<&str>,
        callback: ModuleChangeCallback,
        priority: u32,
        options: SubscriptionOptions,
    ) -> Result<Subscription> {
        let c_mod_name = CString::new(mod_name).unwrap();
        let c_xpath = if let Some(x) = xpath {
            Some(CString::new(x).unwrap())
        } else {
            None
        };
        let mut csub = std::ptr::null_mut();
        let csub_p = &mut csub;

        let cb = Box::new(callback);
        let cb = Box::into_raw(cb);

        ErrorCode::from_i32(unsafe {
            ffi::sr_module_change_subscribe(
                self.inner.0,
                c_mod_name.as_ref().as_ptr(),
                if c_xpath.is_none() {
                    std::ptr::null()
                } else {
                    c_xpath.as_ref().unwrap().as_ptr()
                },
                Some(module_change_callback),
                cb as *mut std::os::raw::c_void,
                priority,
                options.bits(),
                csub_p,
            )
        })
        .map_or_else(|| Ok(()), |ret| Err(Error::new(ret)))?;

        self._sub_callbacks
            .push(SubscriptionCallback::ModuleChangeCallback(unsafe {
                Box::from_raw(cb)
            }));

        Ok(Subscription(csub))
    }

    pub fn subscribe_oper_data_request(
        &mut self,
        mod_name: &str,
        xpath: Option<&str>,
        callback: OperGetItemsCallbackSync,
        options: SubscriptionOptions,
    ) -> Result<()> {
        let sub = self._subscribe_oper_data_request(
            mod_name,
            xpath,
            OperGetItemsCallback::Sync(callback),
            options,
        )?;
        self._sub_ctxs.push(sub);
        Ok(())
    }

    pub fn subscribe_oper_data_request_async(
        &mut self,
        mod_name: &str,
        xpath: Option<&str>,
        callback: OperGetItemsCallbackAsync,
        options: SubscriptionOptions,
    ) -> Result<()> {
        let sub = self._subscribe_oper_data_request(
            mod_name,
            xpath,
            OperGetItemsCallback::Async(callback),
            options | SubscriptionOptions::NO_THREAD,
        )?;
        self.handle_event(sub)
    }

    pub fn _subscribe_oper_data_request(
        &mut self,
        mod_name: &str,
        xpath: Option<&str>,
        callback: OperGetItemsCallback,
        options: SubscriptionOptions,
    ) -> Result<Subscription> {
        let c_mod_name = CString::new(mod_name).unwrap();
        let c_xpath = if let Some(x) = xpath {
            Some(CString::new(x).unwrap())
        } else {
            None
        };
        let mut csub = std::ptr::null_mut();
        let csub_p = &mut csub;

        let cb = Box::new(callback);
        let cb = Box::into_raw(cb);

        ErrorCode::from_i32(unsafe {
            ffi::sr_oper_get_subscribe(
                self.inner.0,
                c_mod_name.as_ref().as_ptr(),
                if c_xpath.is_none() {
                    std::ptr::null()
                } else {
                    c_xpath.as_ref().unwrap().as_ptr()
                },
                Some(oper_get_items_callback),
                cb as *mut std::os::raw::c_void,
                options.bits(),
                csub_p,
            )
        })
        .map_or_else(|| Ok(()), |ret| Err(Error::new(ret)))?;

        self._sub_callbacks
            .push(SubscriptionCallback::OperGetItemsCallback(unsafe {
                Box::from_raw(cb)
            }));

        Ok(Subscription(csub))
    }

    fn handle_event(&mut self, sub: Subscription) -> Result<()> {
        let handle = tokio::spawn(async move {
            let sub = sub;

            let fd = {
                let mut fd: RawFd = 0;
                let ret = unsafe { ffi::sr_get_event_pipe(sub.0, &mut fd) as u32 };

                if ret != ffi::sr_error_t::SR_ERR_OK {
                    panic!("failed to get event pipe");
                }
                fd
            };

            let a = AsyncFd::new(fd).expect("Failed to create AsyncFd");

            loop {
                a.readable().await.unwrap().clear_ready();
                {
                    let ret = unsafe {
                        // TODO this might take time
                        // consider making this async or spawn this block
                        // by task::spawn_blocking()
                        ffi::sr_subscription_process_events(
                            sub.0,
                            std::ptr::null_mut(),
                            std::ptr::null_mut(),
                        ) as u32
                    };
                    if ret != ffi::sr_error_t::SR_ERR_OK {
                        panic!("process event failed");
                    }
                }
            }
        });
        self._sub_handles.push(handle);
        Ok(())
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self._sub_handles.len() == 0 {
            return;
        }

        // cancel all subscription event handlers and await for them
        // this ensures Subscription destructors are called
        task::block_in_place(|| {
            let current = Handle::current();
            current.block_on(async {
                for h in &mut self._sub_handles {
                    h.abort();
                    match h.await {
                        Ok(_) => panic!("subscription event handler should not return Ok()"),
                        Err(e) => {
                            if !e.is_cancelled() {
                                panic!("failed to close subscription event handler: {:?}", e)
                            }
                        }
                    }
                }
            });
        });
    }
}

#[cfg(test)]
mod tests {
    use crate::connection::tests::ensure_test_module;
    use crate::connection::Connection;
    use crate::session::Session;
    use crate::types::*;
    use crate::value::Value;
    use std::sync::{Arc, Mutex};
    use yang2::data::{Data, DataFormat, DataPrinterFlags, DataTree};

    #[test]
    fn test_orig_name() {
        let conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let conn = Arc::new(Mutex::new(conn));
        let mut sess =
            Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");
        sess.set_orig_name("hello")
            .expect("Failed to set original name");
    }

    #[test]
    fn test_set_item() {
        let conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let conn = Arc::new(Mutex::new(conn));
        let mut sess =
            Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");
        sess.set_item_str("/test:test-uint32", "10", None, EditOptions::DEFAULT)
            .expect("Failed to set value");
        sess.apply_changes(0).expect("Failed to apply changes");

        let value = sess
            .get_item("/test:test-uint32", 0)
            .expect("Failed to get value");
        assert_eq!(value.value_type(), ValueType::Uint32);
        let v: u32 = value.try_into().expect("Failed to convert value to u32");
        assert_eq!(v, 10);
    }

    #[test]
    fn test_subscribe_module_change() {
        let conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let conn = Arc::new(Mutex::new(conn));
        ensure_test_module(&conn).expect("Failed to ensure module");

        {
            let mut sess =
                Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");
            sess.delete_item("/test:test-uint32", EditOptions::DEFAULT)
                .expect("Failed to delete");
            sess.apply_changes(0).unwrap()
        }

        let changes = Arc::new(Mutex::new(Vec::new()));
        {
            let mut sess =
                Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");

            let lchanges = changes.clone();
            sess.subscribe_module_change(
                "test",
                None,
                Box::new(move |e, r, c| {
                    for v in c {
                        lchanges.lock().unwrap().push((e, r, v));
                    }
                    Ok(())
                }),
                0,
                SubscriptionOptions::DEFAULT,
            )
            .expect("Failed to subcribe");

            for i in vec![10u32, 20u32, 30u32] {
                let v = Value::from(i);
                sess.set_item("/test:test-uint32", &v, EditOptions::DEFAULT)
                    .expect("Failed to set value");
                sess.apply_changes(0).unwrap();

                let v = sess
                    .get_item("/test:test-uint32", 0)
                    .expect("Failed to get value");
                let v: u32 = v.try_into().expect("Failed to convert value to u32");
                assert_eq!(v, i);
            }
        }

        let changes = Arc::try_unwrap(changes).unwrap().into_inner().unwrap();
        for c in &changes {
            println!("{c:?}");
        }
        assert_eq!(changes.len(), 6);
    }

    #[test]
    fn test_subscribe_oper_data_request_sync() {
        let conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let conn = Arc::new(Mutex::new(conn));
        ensure_test_module(&conn).expect("Failed to ensure module");

        {
            let mut sess =
                Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");
            sess.delete_item("/test:test-uint32", EditOptions::DEFAULT)
                .expect("Failed to delete");
            sess.apply_changes(0).unwrap()
        }

        for i in vec![10u32, 20u32, 30u32] {
            let value = Arc::new(Mutex::new(i));

            let v = {
                let mut sess =
                    Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");

                let v = Arc::clone(&value);
                sess.subscribe_oper_data_request(
                    "test",
                    Some("/test:test-uint32"),
                    Box::new(move |xpath, ctx| {
                        println!("xpath: {}", xpath);
                        let v = v.lock().unwrap().to_string();
                        let mut data = DataTree::new(&ctx);
                        data.new_path("/test:test-uint32", Some(&v), false)
                            .expect("Failed to create a new path");
                        data.print_file(
                            std::io::stdout(),
                            DataFormat::JSON,
                            DataPrinterFlags::WD_ALL | DataPrinterFlags::WITH_SIBLINGS,
                        )
                        .expect("Failed to print data tree");
                        Ok(data)
                    }),
                    SubscriptionOptions::DEFAULT,
                )
                .expect("Failed to subcribe");

                sess.switch_ds(DatastoreType::OPERATIONAL)
                    .expect("Failed to switch datastore");

                sess.get_item("/test:test-uint32", 0)
                    .expect("Failed to get value")
            };
            let v: u32 = v.try_into().expect("Failed to convert value to u32");
            assert_eq!(v, Arc::try_unwrap(value).unwrap().into_inner().unwrap());
        }
    }
}

#[cfg(test)]
mod async_tests {
    use crate::connection::tests::ensure_test_module;
    use crate::connection::Connection;
    use crate::session::Session;
    use crate::types::*;
    use crate::value::Value;
    use std::sync::{Arc, Mutex};
    use yang2::data::{Data, DataFormat, DataPrinterFlags, DataTree};

    use tokio::task;

    #[tokio::test(flavor = "multi_thread")]
    async fn test_subscribe_module_change_async() {
        let conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let conn = Arc::new(Mutex::new(conn));
        ensure_test_module(&conn).expect("Failed to ensure module");

        let changes = Arc::new(Mutex::new(Vec::new()));
        {
            let mut sess =
                Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");

            let changes = changes.clone();
            sess.subscribe_module_change_async(
                "test",
                None,
                Box::new(move |e, r, c| {
                    let changes = changes.clone(); // clone again
                    Box::pin(async move {
                        for v in c {
                            changes.lock().unwrap().push((e, r, v));
                        }
                        Ok(())
                    })
                }),
                0,
                SubscriptionOptions::DEFAULT,
            )
            .expect("Failed to subscribe");

            task::spawn_blocking(|| {
                let conn = Connection::new(ConnectionOptions::DEFAULT)
                    .expect("Failed to create connection");
                let conn = Arc::new(Mutex::new(conn));

                let mut sess =
                    Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");

                for i in vec![10u32, 20u32, 30u32] {
                    let v = Value::from(i);
                    sess.set_item("/test:test-uint32", &v, EditOptions::DEFAULT)
                        .expect("Failed to set value");
                    sess.apply_changes(0).unwrap();

                    let v = sess
                        .get_item("/test:test-uint32", 0)
                        .expect("Failed to get value");
                    let v: u32 = v.try_into().expect("Failed to convert value to u32");
                    assert_eq!(v, i);
                }
            })
            .await
            .expect("Failed to test");
        }

        let changes = Arc::try_unwrap(changes).unwrap().into_inner().unwrap();
        for c in &changes {
            println!("{c:?}");
        }
        assert_eq!(changes.len(), 6);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_subscribe_oper_data_request_async() {
        let conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let conn = Arc::new(Mutex::new(conn));

        ensure_test_module(&conn).expect("Failed to ensure module");

        {
            let mut sess =
                Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");
            sess.delete_item("/test:test-uint32", EditOptions::DEFAULT)
                .expect("Failed to delete");
            sess.apply_changes(0).unwrap()
        }

        for i in vec![10u32, 20u32, 30u32] {
            let value = Arc::new(Mutex::new(i));

            let v = {
                let mut sess =
                    Session::new(&conn, DatastoreType::RUNNING).expect("Failed to create session");

                let v = Arc::clone(&value);

                sess.subscribe_oper_data_request_async(
                    "test",
                    Some("/test:test-uint32"),
                    Box::new(move |xpath, ctx| {
                        println!("xpath: {}", xpath);
                        let v = Arc::clone(&v);
                        Box::pin(async move {
                            let v = v.lock().unwrap().to_string();
                            let mut data = DataTree::new(&ctx);
                            data.new_path("/test:test-uint32", Some(&v), false)
                                .expect("Failed to create a new path");
                            data.print_file(
                                std::io::stdout(),
                                DataFormat::JSON,
                                DataPrinterFlags::WD_ALL | DataPrinterFlags::WITH_SIBLINGS,
                            )
                            .expect("Failed to print data tree");
                            Ok(data)
                        })
                    }),
                    SubscriptionOptions::DEFAULT,
                )
                .expect("Failed to subcribe");

                sess.switch_ds(DatastoreType::OPERATIONAL)
                    .expect("Failed to switch datastore");
                sess.get_item("/test:test-uint32", 0)
                    .expect("Failed to get value")
            };
            let v: u32 = v.try_into().expect("Failed to convert value to u32");
            assert_eq!(v, Arc::try_unwrap(value).unwrap().into_inner().unwrap());
        }
    }
}
