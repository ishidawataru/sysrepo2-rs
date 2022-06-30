//
// Copyright (c) The sysrepo2-rs Core Contributors
//
// See LICENSE for license details.
//

use std::ffi::CString;
use std::sync::Arc;

use crate::change::Changes;
use crate::connection::{Connection, Context};
use crate::error::{Error, Result};
use crate::types::*;
use crate::utils::*;
use crate::value::Value;

use num_traits::FromPrimitive;

use sysrepo2_sys as ffi;

use yang2::data::{Data, DataTree};
use yang2::utils::Binding;

use libyang2_sys;

pub type ModuleChangeCallback = Box<dyn FnMut(EventType, u32, Changes) -> Result<()> + Send + Sync>;

pub type OperGetItemsCallback = Box<dyn FnMut(&str, &mut DataTree) -> Result<()> + Send + Sync>;

pub struct SubscriptionInner {
    pub(crate) module_change_callback: Option<ModuleChangeCallback>,
    pub(crate) oper_get_items_callback: Option<OperGetItemsCallback>,
}

pub struct Subscription<'a> {
    pub(crate) raw: *mut ffi::sr_subscription_ctx_t,
    pub(crate) _inner: Box<SubscriptionInner>,
    pub(crate) _marker: std::marker::PhantomData<&'a Session<'a>>,
}

impl<'a> Drop for Subscription<'a> {
    fn drop(&mut self) {
        unsafe {
            ffi::sr_unsubscribe(self.raw);
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
    let inner = &mut *(private_data as *mut SubscriptionInner);

    let sess = Session {
        _marker: std::marker::PhantomData,
        _subs: Vec::new(),
        inner: SessionInner(session),
    };

    let module = char_ptr_to_str(module_name);

    let path = format!("/{}:*//.", module);

    let ret = (inner.module_change_callback.as_mut().unwrap())(
        EventType::from_u32(event as u32).unwrap(),
        request_id,
        sess.get_changes(&path).unwrap(),
    );

    std::mem::forget(sess); // implicit session will be freed by sysrepo
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
    let inner = &mut *(private_data as *mut SubscriptionInner);

    let sess = Session {
        _marker: std::marker::PhantomData,
        _subs: Vec::new(),
        inner: SessionInner(session),
    };
    // implicit session will be freed by sysrepo
    let mut sess = std::mem::ManuallyDrop::new(sess);

    let mut ctx = sess.get_context();
    // take the yang2 raw context inside from the sysrepo2 context `ctx`
    // and create an Arc<yang2::Context> so that we can create yang2::DataTree
    let y2ctx = Arc::new(std::mem::replace(&mut ctx.raw, None).unwrap());

    let ret = {
        let mut data = DataTree::from_raw(&y2ctx, *parent as *mut libyang2_sys::lyd_node);
        let req_xpath = char_ptr_to_str(request_xpath);
        let ret = (inner.oper_get_items_callback.as_mut().unwrap())(req_xpath, &mut data);
        // we need to call DataTree::drop() to drop a reference to `y2ctx`.
        // Otherwise the Arc::try_unwrap() will fail.
        // However, we can't drop `parent` since this is owned by sysrepo
        // call DataTree::replace(std::ptr::null_mut()) to replace the internal node to null so that
        // we can safely call DataTree::drop()
        *parent = data.replace(std::ptr::null_mut()) as *mut ffi::lyd_node;
        ret
    };

    // bring back the yang2 raw context to sysrepo2 context so that
    // we can drop this context properly by sysrepo2::Context::drop()
    let tmp = Arc::try_unwrap(y2ctx).unwrap();
    assert_eq!(std::mem::replace(&mut ctx.raw, Some(tmp)), None);

    match ret {
        Ok(_) => 0,
        Err(e) => e.errcode.try_into().unwrap(),
    }
}

pub(crate) struct SessionInner(pub *mut ffi::sr_session_ctx_t);

impl Drop for SessionInner {
    fn drop(&mut self) {
        unsafe { ffi::sr_session_stop(self.0) };
    }
}

pub struct Session<'a> {
    pub(crate) _marker: std::marker::PhantomData<&'a Connection>,
    pub(crate) _subs: Vec<Subscription<'a>>,
    pub(crate) inner: SessionInner,
}

impl<'a> Session<'a> {
    pub fn switch_ds(&self, t: DatastoreType) -> Result<()> {
        let ret = unsafe { ffi::sr_session_switch_ds(self.inner.0, t as u32) as u32 };
        if ret != ffi::sr_error_t::SR_ERR_OK {
            return Err(Error {
                errcode: ret,
                msg: None,
                error_format: None,
            });
        }
        Ok(())
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

    pub fn get_context(&'a mut self) -> Context {
        Context::from_session(self)
    }

    pub fn set_orig_name(&self, orig_name: &str) -> Result<()> {
        let ret = unsafe {
            ffi::sr_session_set_orig_name(
                self.inner.0,
                orig_name.as_ptr() as *const ::std::os::raw::c_char,
            ) as u32
        };
        if ret != ffi::sr_error_t::SR_ERR_OK {
            return Err(Error::new(ret));
        }
        Ok(())
    }

    pub fn get_orig_name(&self) -> Option<&str> {
        unsafe { char_ptr_to_opt_str(ffi::sr_session_get_orig_name(self.inner.0)) }
    }

    pub fn get_item(&self, path: &str, timeout_ms: u32) -> Result<Value> {
        let mut value = std::ptr::null_mut();
        let value_ptr = &mut value;

        let c_string = CString::new(path).unwrap();

        let ret = unsafe {
            ffi::sr_get_item(self.inner.0, c_string.as_ptr(), timeout_ms, value_ptr) as u32
        };
        if ret != ffi::sr_error_t::SR_ERR_OK {
            return Err(Error::new(ret));
        }
        Ok(Value {
            raw: value,
            _owned: None,
        })
    }

    pub fn get_changes(&self, xpath: &str) -> Result<Changes> {
        Changes::new(self, xpath)
    }

    /// Prepare to set (create) the value of a leaf, leaf-list, list, or presence container.
    /// These changes are applied only after calling Session::apply_changes().
    /// Data are represented as Value structures.
    pub fn set_item(&self, path: &str, value: &Value, options: EditOptions) -> Result<()> {
        let c_path = CString::new(path).unwrap();
        let ret = unsafe {
            ffi::sr_set_item(self.inner.0, c_path.as_ptr(), value.raw, options.bits()) as u32
        };

        if ret != ffi::sr_error_t::SR_ERR_OK {
            return Err(Error::new(ret));
        }
        Ok(())
    }

    /// Prepare to set (create) the value of a leaf, leaf-list, list, or presence container.
    /// These changes are applied only after calling Session::apply_changes().
    /// Data are represented as pairs of a path and string value.
    pub fn set_item_str(
        &self,
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

        let ret = unsafe {
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
            ) as u32
        };

        if ret != ffi::sr_error_t::SR_ERR_OK {
            return Err(Error::new(ret));
        }
        Ok(())
    }

    /// Prepare to delete the nodes matching the specified xpath. These changes are applied only
    /// after calling Session::apply_changes(). The accepted values are the same as for Session::set_item_str().
    pub fn delete_item(&self, path: &str, options: EditOptions) -> Result<()> {
        let c_path = CString::new(path).unwrap();
        let ret =
            unsafe { ffi::sr_delete_item(self.inner.0, c_path.as_ptr(), options.bits()) as u32 };

        if ret != ffi::sr_error_t::SR_ERR_OK {
            return Err(Error::new(ret));
        }
        Ok(())
    }

    /// Perform the validation a datastore and any changes made in the current session, but do not
    /// apply nor discard them.
    pub fn validate(&self, module_name: &str, timeout_ms: u32) -> Result<()> {
        let c_path = CString::new(module_name).unwrap();
        let ret = unsafe { ffi::sr_validate(self.inner.0, c_path.as_ptr(), timeout_ms) as u32 };

        if ret != ffi::sr_error_t::SR_ERR_OK {
            return Err(Error::new(ret));
        }
        Ok(())
    }

    /// Apply changes made in the current session.
    /// In case the changes could not be applied successfully for any reason,
    /// they remain intact in the session.
    pub fn apply_changes(&self, timeout_ms: u32) -> Result<()> {
        let ret = unsafe { ffi::sr_apply_changes(self.inner.0, timeout_ms) as u32 };
        if ret != ffi::sr_error_t::SR_ERR_OK {
            return Err(Error::new(ret));
        }
        Ok(())
    }

    /// Learn whether there are any prepared non-applied changes in the session.
    pub fn has_changes(&self) -> bool {
        let ret = unsafe { ffi::sr_has_changes(self.inner.0) as u32 };
        ret != 0
    }

    /// Discard prepared changes made in the current session.
    pub fn discard_changes(&self) -> Result<()> {
        let ret = unsafe { ffi::sr_discard_changes(self.inner.0) as u32 };

        if ret != ffi::sr_error_t::SR_ERR_OK {
            return Err(Error::new(ret));
        }
        Ok(())
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
        let ret = unsafe {
            let c_config = src_config.raw() as *mut ffi::lyd_node;
            ffi::sr_replace_config(self.inner.0, c_path.as_ptr(), c_config, timeout_ms) as u32
        };

        if ret != ffi::sr_error_t::SR_ERR_OK {
            return Err(Error::new(ret));
        }
        Ok(())
    }

    pub fn subscribe_module_change(
        &mut self,
        mod_name: &str,
        xpath: Option<&str>,
        callback: ModuleChangeCallback,
        priority: u32,
        options: SubscriptionOptions,
    ) -> Result<()> {
        let c_mod_name = CString::new(mod_name).unwrap();
        let c_xpath = if let Some(x) = xpath {
            Some(CString::new(x).unwrap())
        } else {
            None
        };
        let mut csub = std::ptr::null_mut();
        let csub_p = &mut csub;

        let inner = Box::new(SubscriptionInner {
            module_change_callback: Some(callback),
            oper_get_items_callback: None,
        });
        let inner_p = Box::into_raw(inner);

        unsafe {
            let ret = ffi::sr_module_change_subscribe(
                self.inner.0,
                c_mod_name.as_ref().as_ptr(),
                if c_xpath.is_none() {
                    std::ptr::null()
                } else {
                    c_xpath.as_ref().unwrap().as_ptr()
                },
                Some(module_change_callback),
                inner_p as *mut std::os::raw::c_void,
                priority,
                options.bits(),
                csub_p,
            ) as u32;

            let inner = Box::from_raw(inner_p);

            if ret != ffi::sr_error_t::SR_ERR_OK {
                Err(Error::new(ret))
            } else {
                self._subs.push(Subscription {
                    raw: csub,
                    _inner: inner,
                    _marker: std::marker::PhantomData,
                });
                Ok(())
            }
        }
    }

    pub fn subscribe_oper_data_request(
        &mut self,
        mod_name: &str,
        xpath: Option<&str>,
        callback: OperGetItemsCallback,
        options: SubscriptionOptions,
    ) -> Result<()> {
        let c_mod_name = CString::new(mod_name).unwrap();
        let c_xpath = if let Some(x) = xpath {
            Some(CString::new(x).unwrap())
        } else {
            None
        };
        let mut csub = std::ptr::null_mut();
        let csub_p = &mut csub;

        let inner = Box::new(SubscriptionInner {
            module_change_callback: None,
            oper_get_items_callback: Some(callback),
        });
        let inner_p = Box::into_raw(inner);

        unsafe {
            let ret = ffi::sr_oper_get_subscribe(
                self.inner.0,
                c_mod_name.as_ref().as_ptr(),
                if c_xpath.is_none() {
                    std::ptr::null()
                } else {
                    c_xpath.as_ref().unwrap().as_ptr()
                },
                Some(oper_get_items_callback),
                inner_p as *mut std::os::raw::c_void,
                options.bits(),
                csub_p,
            ) as u32;

            let inner = Box::from_raw(inner_p);

            if ret != ffi::sr_error_t::SR_ERR_OK {
                Err(Error::new(ret))
            } else {
                self._subs.push(Subscription {
                    raw: csub,
                    _inner: inner,
                    _marker: std::marker::PhantomData,
                });
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::connection::tests::ensure_test_module;
    use crate::connection::Connection;
    use crate::types::*;
    use crate::value::Value;
    use std::sync::{Arc, Mutex};
    use yang2::data::{Data, DataFormat, DataPrinterFlags};

    #[test]
    fn test_orig_name() {
        let conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let sess = conn
            .create_session(DatastoreType::RUNNING)
            .expect("Failed to create session");
        sess.set_orig_name("hello")
            .expect("Failed to set original name");
    }

    #[test]
    fn test_set_item() {
        let conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        let sess = conn
            .create_session(DatastoreType::RUNNING)
            .expect("Failed to create session");
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
        let mut conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        ensure_test_module(&mut conn).expect("Failed to ensure module");

        {
            let sess = conn
                .create_session(DatastoreType::RUNNING)
                .expect("Failed to create session");
            sess.delete_item("/test:test-uint32", EditOptions::DEFAULT)
                .expect("Failed to delete");
            sess.apply_changes(0).unwrap()
        }

        let changes = Arc::new(Mutex::new(Vec::new()));
        {
            let mut sess = conn
                .create_session(DatastoreType::RUNNING)
                .expect("Failed to create session");

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
    fn test_subscribe_oper_data_request() {
        let mut conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        ensure_test_module(&mut conn).expect("Failed to ensure module");

        {
            let sess = conn
                .create_session(DatastoreType::RUNNING)
                .expect("Failed to create session");
            sess.delete_item("/test:test-uint32", EditOptions::DEFAULT)
                .expect("Failed to delete");
            sess.apply_changes(0).unwrap()
        }

        for i in vec![10u32, 20u32, 30u32] {
            let value = Arc::new(Mutex::new(i));

            let v = {
                let mut sess = conn
                    .create_session(DatastoreType::RUNNING)
                    .expect("Failed to create session");

                {
                    let v = value.clone();
                    sess.subscribe_oper_data_request(
                        "test",
                        Some("/test:test-uint32"),
                        Box::new(move |xpath, data| {
                            println!("xpath: {}", xpath);
                            let v = (*v).lock().unwrap().to_string();
                            data.new_path("/test:test-uint32", Some(&v), false)
                                .expect("Failed to create a new path");
                            data.print_file(
                                std::io::stdout(),
                                DataFormat::JSON,
                                DataPrinterFlags::WD_ALL | DataPrinterFlags::WITH_SIBLINGS,
                            )
                            .expect("Failed to print data tree");
                            Ok(())
                        }),
                        SubscriptionOptions::DEFAULT,
                    )
                    .expect("Failed to subcribe");
                }

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
