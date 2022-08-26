//
// Copyright (c) The yang2-rs Core Contributors
//
// See LICENSE for license details.

use std::convert::TryInto;
use std::fmt;

use crate::types::*;
use crate::utils::*;

use num_traits::FromPrimitive;

use sysrepo2_sys as ffi;

pub struct Value {
    pub(crate) raw: *mut ffi::sr_val_t,
    pub(crate) _owned: Option<Box<ffi::sr_val_t>>,
}

impl fmt::Debug for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} = {}", self.xpath(), self)?;
        Ok(())
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.value_type() {
            ValueType::Container | ValueType::ContainerPresent => write!(f, "(container)"),
            ValueType::List => write!(f, "(list instance)"),
            ValueType::Str => write!(
                f,
                "{}",
                char_ptr_to_str(unsafe { (*self.raw).data.string_val })
            ),
            ValueType::Enum => write!(
                f,
                "{}",
                char_ptr_to_str(unsafe { (*self.raw).data.enum_val })
            ),
            ValueType::Int8 => write!(f, "{}", unsafe { (*self.raw).data.int8_val }),
            ValueType::Int16 => write!(f, "{}", unsafe { (*self.raw).data.int16_val }),
            ValueType::Int32 => write!(f, "{}", unsafe { (*self.raw).data.int32_val }),
            ValueType::Int64 => write!(f, "{}", unsafe { (*self.raw).data.int64_val }),
            ValueType::Uint8 => write!(f, "{}", unsafe { (*self.raw).data.uint8_val }),
            ValueType::Uint16 => write!(f, "{}", unsafe { (*self.raw).data.uint16_val }),
            ValueType::Uint32 => write!(f, "{}", unsafe { (*self.raw).data.uint32_val }),
            ValueType::Uint64 => write!(f, "{}", unsafe { (*self.raw).data.uint64_val }),
            _ => write!(f, "unsupported value type: {:?}", self.value_type()),
        }?;
        Ok(())
    }
}

impl Value {
    pub fn new(raw: *mut ffi::sr_val_t) -> Value {
        Value { raw, _owned: None }
    }

    pub fn xpath(&self) -> &str {
        char_ptr_to_str(unsafe { (*self.raw).xpath })
    }

    pub fn value_type(&self) -> ValueType {
        unsafe { ValueType::from_u32((*self.raw).type_).unwrap() }
    }

    pub fn origin(&self) -> &str {
        char_ptr_to_str(unsafe { (*self.raw).origin })
    }

    pub fn dflt(&self) -> isize {
        unsafe { (*self.raw).dflt as isize }
    }
}

unsafe impl Send for Value {}

impl From<i8> for Value {
    fn from(v: i8) -> Self {
        let mut v = Box::new(ffi::sr_val_t {
            type_: ffi::sr_val_type_t::SR_INT8_T,
            data: ffi::sr_val_data_u { int8_val: v },
            ..Default::default()
        });
        let ptr: *mut ffi::sr_val_t = &mut *v;
        Value {
            raw: ptr,
            _owned: Some(v),
        }
    }
}

impl TryInto<i8> for Value {
    type Error = ();

    fn try_into(self) -> Result<i8, Self::Error> {
        if self.value_type() == ValueType::Int8 {
            unsafe { Ok((*self.raw).data.int8_val) }
        } else {
            Err(())
        }
    }
}

impl From<u32> for Value {
    fn from(v: u32) -> Self {
        let mut v = Box::new(ffi::sr_val_t {
            type_: ffi::sr_val_type_t::SR_UINT32_T,
            data: ffi::sr_val_data_u { uint32_val: v },
            ..Default::default()
        });
        let ptr: *mut ffi::sr_val_t = &mut *v;
        Value {
            raw: ptr,
            _owned: Some(v),
        }
    }
}

impl TryInto<u32> for Value {
    type Error = ();

    fn try_into(self) -> Result<u32, Self::Error> {
        if self.value_type() == ValueType::Uint32 {
            unsafe { Ok((*self.raw).data.uint32_val) }
        } else {
            Err(())
        }
    }
}

impl Drop for Value {
    fn drop(&mut self) {
        if self._owned.is_none() {
            unsafe { ffi::sr_free_val(self.raw) };
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::connection::tests::ensure_test_module;
    use crate::connection::*;
    use crate::log::*;
    use crate::value::*;

    #[test]
    fn test_value() {
        let mut conn =
            Connection::new(ConnectionOptions::DEFAULT).expect("Failed to create connection");
        log_stderr(LogLevel::DBG);
        ensure_test_module(&mut conn).expect("Failed to ensure module");
        let mut sess = conn
            .create_session(DatastoreType::RUNNING)
            .expect("Failed to create session");

        for i in vec![10u32, 20u32, 30u32] {
            let v = i.into();
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
}
