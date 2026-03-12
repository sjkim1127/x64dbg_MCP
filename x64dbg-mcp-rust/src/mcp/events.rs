use serde_json::{json, Value};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use std::sync::Mutex;
use once_cell::sync::Lazy;
use std::sync::atomic::{AtomicI32, Ordering};
use std::ffi::c_void;

pub static PLUGIN_HANDLE: AtomicI32 = AtomicI32::new(0);

#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum CBTYPE {
    CB_SYSTEMBREAKPOINT = 6,
    CB_EXCEPTION = 10,
    CB_BREAKPOINT = 11,
    CB_PAUSEDEBUG = 12,
    CB_STEPPED = 14,
}

extern "C" {
    pub fn _plugin_registercallback(
        pluginHandle: i32,
        cbType: CBTYPE,
        cbPlugin: extern "C" fn(CBTYPE, *mut c_void),
    );
}

pub static EVENT_RX: Lazy<Mutex<Option<UnboundedReceiver<Value>>>> = Lazy::new(|| Mutex::new(None));

pub fn init_event_channel() -> UnboundedSender<Value> {
    let (tx, rx) = unbounded_channel();
    if let Ok(mut lock) = EVENT_RX.lock() {
        *lock = Some(rx);
    }
    tx
}

pub static EVENT_TX: Lazy<UnboundedSender<Value>> = Lazy::new(init_event_channel);

pub extern "C" fn cb_system_breakpoint(_cb_type: CBTYPE, _info: *mut c_void) {
    let _ = EVENT_TX.send(json!({ "event": "CB_SYSTEMBREAKPOINT", "message": "System Breakpoint hit" }));
}

pub extern "C" fn cb_exception(_cb_type: CBTYPE, _info: *mut c_void) {
    let _ = EVENT_TX.send(json!({ "event": "CB_EXCEPTION", "message": "Exception raised" }));
}

pub extern "C" fn cb_breakpoint(_cb_type: CBTYPE, _info: *mut c_void) {
    let _ = EVENT_TX.send(json!({ "event": "CB_BREAKPOINT", "message": "Breakpoint hit" }));
}

pub extern "C" fn cb_pausedebug(_cb_type: CBTYPE, _info: *mut c_void) {
    // Only send Pause notifications to not overwhelm the UI during fast stepping,
    // actually, AI might want this.
    let _ = EVENT_TX.send(json!({ "event": "CB_PAUSEDEBUG", "message": "Debugger paused" }));
}

pub extern "C" fn cb_stepped(_cb_type: CBTYPE, _info: *mut c_void) {
    let _ = EVENT_TX.send(json!({ "event": "CB_STEPPED", "message": "Instruction stepped" }));
}

pub fn register_callbacks(handle: i32) {
    PLUGIN_HANDLE.store(handle, Ordering::SeqCst);
    unsafe {
        _plugin_registercallback(handle, CBTYPE::CB_SYSTEMBREAKPOINT, cb_system_breakpoint);
        _plugin_registercallback(handle, CBTYPE::CB_EXCEPTION, cb_exception);
        _plugin_registercallback(handle, CBTYPE::CB_BREAKPOINT, cb_breakpoint);
        _plugin_registercallback(handle, CBTYPE::CB_PAUSEDEBUG, cb_pausedebug);
        _plugin_registercallback(handle, CBTYPE::CB_STEPPED, cb_stepped);
    }
}
