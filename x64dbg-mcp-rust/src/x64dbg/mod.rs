#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

// Include the generated bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

pub mod api;

use std::os::raw::c_void;

#[cfg(test)]
#[no_mangle]
pub extern "C" fn GuiExecuteOnGuiThreadEx(_cb: extern "C" fn(*mut c_void), _userdata: *mut c_void) {
    // In tests, we don't have a GUI thread.
    // The test runner will manually call the drain function or we use run_mock_task_loop.
}
