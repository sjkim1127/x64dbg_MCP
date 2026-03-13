pub mod mcp;
pub mod x64dbg;

use std::ffi::CString;
use std::os::raw::c_void;
use std::thread;

use mcp::server::start_mcp_server;
use x64dbg::api::log_print;
use x64dbg::{PLUG_INITSTRUCT, PLUG_SDKVERSION};

#[no_mangle]
pub extern "C" fn pluginit(init_struct: *mut PLUG_INITSTRUCT) -> bool {
    unsafe {
        (*init_struct).pluginVersion = 1;
        (*init_struct).sdkVersion = PLUG_SDKVERSION as i32;
        let name = CString::new("McpServerRust").unwrap();
        let name_bytes = name.as_bytes_with_nul();
        let len = name_bytes.len().min((*init_struct).pluginName.len() - 1);

        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            (*init_struct).pluginName.as_mut_ptr() as *mut u8,
            len,
        );
        (*init_struct).pluginName[len] = 0;
    }

    // Initialize tracing with x64dbg layer
    use tracing_subscriber::prelude::*;
    let _ = tracing_subscriber::registry()
        .with(mcp::logger::X64DbgLogLayer)
        .try_init();

    log_print("MCP Server (Rust) initialized!\n");
    tracing::info!("Plugin initialized and tracing system started.");

    mcp::events::register_callbacks(unsafe { (*init_struct).pluginHandle });

    // Initialize the event channel
    let _ = mcp::events::EVENT_TX.send(serde_json::json!({
        "event": "PLUGIN_START",
        "message": "x64dbg MCP plugin started"
    }));

    // Start MCP server in a background thread
    thread::spawn(|| {
        start_mcp_server();
    });

    true
}

#[no_mangle]
pub extern "C" fn plugsetup(_setup_struct: *mut c_void) -> bool {
    true
}

#[no_mangle]
pub extern "C" fn plugstop() -> bool {
    log_print("MCP Server (Rust) stopping...\n");
    mcp::events::SHUTDOWN_TOKEN.cancel();
    true
}
