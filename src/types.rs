//
// Copyright (c) The yang2-rs Core Contributors
//
// See LICENSE for license details.

use bitflags::bitflags;
use num_derive::FromPrimitive;

use sysrepo2_sys as ffi;

#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum ValueType {
    Unknown = ffi::sr_val_type_t::SR_UNKNOWN_T,
    List = ffi::sr_val_type_t::SR_LIST_T,
    Container = ffi::sr_val_type_t::SR_CONTAINER_T,
    ContainerPresent = ffi::sr_val_type_t::SR_CONTAINER_PRESENCE_T,
    LeafEmpty = ffi::sr_val_type_t::SR_LEAF_EMPTY_T,
    Notification = ffi::sr_val_type_t::SR_NOTIFICATION_T,
    Binary = ffi::sr_val_type_t::SR_BINARY_T,
    Bits = ffi::sr_val_type_t::SR_BITS_T,
    Bool = ffi::sr_val_type_t::SR_BOOL_T,
    Decimal64 = ffi::sr_val_type_t::SR_DECIMAL64_T,
    Enum = ffi::sr_val_type_t::SR_ENUM_T,
    IdentityRef = ffi::sr_val_type_t::SR_IDENTITYREF_T,
    InstanceId = ffi::sr_val_type_t::SR_INSTANCEID_T,
    Int8 = ffi::sr_val_type_t::SR_INT8_T,
    Int16 = ffi::sr_val_type_t::SR_INT16_T,
    Int32 = ffi::sr_val_type_t::SR_INT32_T,
    Int64 = ffi::sr_val_type_t::SR_INT64_T,
    Str = ffi::sr_val_type_t::SR_STRING_T,
    Uint8 = ffi::sr_val_type_t::SR_UINT8_T,
    Uint16 = ffi::sr_val_type_t::SR_UINT16_T,
    Uint32 = ffi::sr_val_type_t::SR_UINT32_T,
    Uint64 = ffi::sr_val_type_t::SR_UINT64_T,
    AnyXML = ffi::sr_val_type_t::SR_ANYXML_T,
    AnyData = ffi::sr_val_type_t::SR_ANYDATA_T,
}

bitflags! {
    pub struct EditOptions: u32 {
        const DEFAULT = ffi::sr_edit_flag_t::SR_EDIT_DEFAULT as u32;
        const NON_RECURSIVE = ffi::sr_edit_flag_t::SR_EDIT_NON_RECURSIVE as u32;
        const STRICT = ffi::sr_edit_flag_t::SR_EDIT_STRICT as u32;
        const ISOLATE = ffi::sr_edit_flag_t::SR_EDIT_ISOLATE as u32;
    }
}

bitflags! {
    pub struct ConnectionOptions: u32 {
        const DEFAULT = ffi::sr_conn_flag_t::SR_CONN_DEFAULT as u32;
        const CACHE_RUNNING = ffi::sr_conn_flag_t::SR_CONN_CACHE_RUNNING as u32;
    }
}

#[allow(clippy::upper_case_acronyms)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum DatastoreType {
    STARTUP = ffi::sr_datastore_t::SR_DS_STARTUP,
    RUNNING = ffi::sr_datastore_t::SR_DS_RUNNING,
    CANDIDATE = ffi::sr_datastore_t::SR_DS_CANDIDATE,
    OPERATIONAL = ffi::sr_datastore_t::SR_DS_OPERATIONAL,
}

bitflags! {
    pub struct SubscriptionOptions: u32 {
        const DEFAULT = ffi::sr_subscr_flag_t::SR_SUBSCR_DEFAULT as u32;
        const NO_THREAD = ffi::sr_subscr_flag_t::SR_SUBSCR_NO_THREAD as u32;
        const PASSIVE = ffi::sr_subscr_flag_t::SR_SUBSCR_PASSIVE as u32;
        const DONE_ONLY = ffi::sr_subscr_flag_t::SR_SUBSCR_DONE_ONLY as u32;
        const ENABLED = ffi::sr_subscr_flag_t::SR_SUBSCR_ENABLED as u32;
        const UPDATE = ffi::sr_subscr_flag_t::SR_SUBSCR_UPDATE as u32;
        const OPER_MERGE = ffi::sr_subscr_flag_t::SR_SUBSCR_OPER_MERGE as u32;
        const THREAD_SUSPEND = ffi::sr_subscr_flag_t::SR_SUBSCR_THREAD_SUSPEND as u32;
    }
}

#[allow(clippy::upper_case_acronyms)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum EventType {
    UPDATE = ffi::sr_event_t::SR_EV_UPDATE,
    CHANGE = ffi::sr_event_t::SR_EV_CHANGE,
    DONE = ffi::sr_event_t::SR_EV_DONE,
    ABORT = ffi::sr_event_t::SR_EV_ABORT,
    ENABLED = ffi::sr_event_t::SR_EV_ENABLED,
    RPC = ffi::sr_event_t::SR_EV_RPC,
}

#[allow(clippy::upper_case_acronyms)]
#[repr(u32)]
#[derive(Clone, Copy, Debug, PartialEq, FromPrimitive)]
pub enum ChangeOperation {
    CREATED = ffi::sr_change_oper_t::SR_OP_CREATED,
    MODIFIED = ffi::sr_change_oper_t::SR_OP_MODIFIED,
    DELETED = ffi::sr_change_oper_t::SR_OP_DELETED,
    MOVED = ffi::sr_change_oper_t::SR_OP_MOVED,
}
