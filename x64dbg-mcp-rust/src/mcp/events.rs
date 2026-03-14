use crate::x64dbg::{_plugin_registercallback, CBTYPE};
use once_cell::sync::Lazy;
use serde_json::{json, Value};
use std::ffi::c_void;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::Mutex;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_util::sync::CancellationToken;

pub static PLUGIN_HANDLE: AtomicI32 = AtomicI32::new(0);
pub static SHUTDOWN_TOKEN: Lazy<CancellationToken> = Lazy::new(CancellationToken::new);

pub static EVENT_RX: Lazy<Mutex<Option<Receiver<Value>>>> = Lazy::new(|| Mutex::new(None));

pub fn init_event_channel() -> Sender<Value> {
    let (tx, rx) = channel(1024); // Bounded channel to prevent OOM
    if let Ok(mut lock) = EVENT_RX.lock() {
        *lock = Some(rx);
    }
    tx
}

pub static EVENT_TX: Lazy<Sender<Value>> = Lazy::new(init_event_channel);

fn send_event(event: Value) {
    // try_send to avoid blocking GUI thread
    let _ = EVENT_TX.try_send(event);
}

pub extern "C" fn cb_system_breakpoint(_cb_type: i32, _info: *mut c_void) {
    send_event(json!({ "event": "CB_SYSTEMBREAKPOINT", "message": "System Breakpoint hit" }));
}

pub extern "C" fn cb_exception(_cb_type: i32, _info: *mut c_void) {
    send_event(json!({ "event": "CB_EXCEPTION", "message": "Exception raised" }));
}

pub extern "C" fn cb_breakpoint(_cb_type: i32, _info: *mut c_void) {
    send_event(json!({ "event": "CB_BREAKPOINT", "message": "Breakpoint hit" }));
}

pub extern "C" fn cb_pausedebug(_cb_type: i32, _info: *mut c_void) {
    send_event(json!({ "event": "CB_PAUSEDEBUG", "message": "Debugger paused" }));
}

pub extern "C" fn cb_stepped(_cb_type: i32, _info: *mut c_void) {
    send_event(json!({ "event": "CB_STEPPED", "message": "Instruction stepped" }));
}

pub fn register_callbacks(handle: i32) {
    PLUGIN_HANDLE.store(handle, Ordering::SeqCst);
    unsafe {
        _plugin_registercallback(handle, CBTYPE::CB_SYSTEMBREAKPOINT as i32, Some(cb_system_breakpoint));
        _plugin_registercallback(handle, CBTYPE::CB_EXCEPTION as i32, Some(cb_exception));
        _plugin_registercallback(handle, CBTYPE::CB_BREAKPOINT as i32, Some(cb_breakpoint));
        _plugin_registercallback(handle, CBTYPE::CB_PAUSEDEBUG as i32, Some(cb_pausedebug));
        _plugin_registercallback(handle, CBTYPE::CB_STEPPED as i32, Some(cb_stepped));
    }
}
