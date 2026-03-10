#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::os::raw::c_void;
use std::thread;
use std::ffi::{CString, CStr};
use std::future::Future;
use std::sync::Arc;
use rmcp::{
    model::*,
    service::RequestContext,
    RoleServer, ServerHandler,
    ErrorData,
    transport::{
        StreamableHttpServerConfig, StreamableHttpService,
        streamable_http_server::session::local::LocalSessionManager,
    },
};
use serde::{Deserialize};
use serde_json::{json, Value};
use std::collections::HashSet;

// Include the generated bindings
include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

const MEM_IMAGE: u32 = 0x1000000;

// Safe wrapper around x64dbg log
fn log_print(msg: &str) {
    let msg_c = CString::new(msg).unwrap();
    unsafe {
        _plugin_logputs(msg_c.as_ptr());
    }
}

#[derive(Clone)]
struct X64DbgMcpServer;

#[derive(Debug, Deserialize)]
struct ExecuteCommandArgs {
    command: String,
}

#[derive(Debug, Deserialize)]
struct ReadMemoryArgs {
    address: String, // hex string
    size: usize,
}

#[derive(Debug, Deserialize)]
struct SetRegisterArgs {
    register: String,
    value: String, // hex string
}

#[derive(Debug, Deserialize)]
struct SetBreakpointArgs {
    address: String,
}

#[derive(Debug, Deserialize)]
struct SetCommentLabelArgs {
    address: String,
    text: String,
}

fn to_json_object(v: Value) -> JsonObject {
    if let Value::Object(m) = v {
        m
    } else {
        panic!("Value is not an object")
    }
}

fn parse_hex(s: &str) -> Result<duint, ErrorData> {
    duint::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|_| ErrorData::invalid_params(format!("Invalid hex format: {}", s), None))
}

impl ServerHandler for X64DbgMcpServer {
    fn initialize(
        &self,
        _request: InitializeRequestParams,
        _cx: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<InitializeResult, ErrorData>> + Send + '_ {
        async move {
            Ok(InitializeResult::new(
                ServerCapabilities::builder()
                    .enable_tools()
                    .build(),
            )
            .with_server_info(Implementation::new("x64dbg-rust-mcp", "0.1.0")))
        }
    }

    fn ping(
        &self,
        _cx: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<(), ErrorData>> + Send + '_ {
        async move { Ok(()) }
    }

    fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _cx: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListToolsResult, ErrorData>> + Send + '_ {
        async move {
            Ok(ListToolsResult {
                tools: vec![
                    Tool::new(
                        "ExecuteCommand",
                        "Executes a command in x64dbg",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "command": { "type": "string", "description": "The command to execute" }
                            },
                            "required": ["command"]
                        })))
                    ),
                    Tool::new(
                        "ReadMemory",
                        "Reads memory from the debuggee",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "address": { "type": "string", "description": "Hex address (e.g. 0x140001000)" },
                                "size": { "type": "integer", "description": "Number of bytes to read" }
                            },
                            "required": ["address", "size"]
                        })))
                    ),
                    Tool::new(
                        "GetRegisters",
                        "Gets the current values of general-purpose registers",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {}
                        })))
                    ),
                    Tool::new(
                        "SetRegister",
                        "Sets a register value",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "register": { "type": "string", "description": "Register name (rax, rip, etc.)" },
                                "value": { "type": "string", "description": "Hex value" }
                            },
                            "required": ["register", "value"]
                        })))
                    ),
                    Tool::new(
                        "GetBreakpoints",
                        "Lists all active software breakpoints",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {}
                        })))
                    ),
                    Tool::new(
                        "SetBreakpoint",
                        "Sets a software breakpoint at an address",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "address": { "type": "string", "description": "Hex address" }
                            },
                            "required": ["address"]
                        })))
                    ),
                    Tool::new(
                        "GetThreads",
                        "Lists all threads in the process",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {}
                        })))
                    ),
                    Tool::new(
                        "GetModules",
                        "Lists all loaded modules in the process",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {}
                        })))
                    ),
                    Tool::new(
                        "GetCallStack",
                        "Gets the current call stack for the active thread",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {}
                        })))
                    ),
                    Tool::new(
                        "SetComment",
                        "Sets a comment at a specific address",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "address": { "type": "string", "description": "Hex address" },
                                "text": { "type": "string", "description": "Comment text" }
                            },
                            "required": ["address", "text"]
                        })))
                    ),
                    Tool::new(
                        "SetLabel",
                        "Sets a label at a specific address",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "address": { "type": "string", "description": "Hex address" },
                                "text": { "type": "string", "description": "Label text" }
                            },
                            "required": ["address", "text"]
                        })))
                    )
                ],
                next_cursor: None,
                meta: None,
            })
        }
    }

    fn call_tool(
        &self,
        request: CallToolRequestParams,
        _cx: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<CallToolResult, ErrorData>> + Send + '_ {
        async move {
            match &*request.name {
                "ExecuteCommand" => {
                    let args: ExecuteCommandArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let cmd_c = CString::new(args.command).unwrap();
                    let success = unsafe { DbgCmdExecDirect(cmd_c.as_ptr()) };
                    
                    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
                }
                "ReadMemory" => {
                    let args: ReadMemoryArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let addr = parse_hex(&args.address)?;
                    let mut buffer = vec![0u8; args.size];
                    
                    let success = unsafe {
                        DbgMemRead(addr, buffer.as_mut_ptr() as *mut c_void, args.size as duint)
                    };
                    
                    if success {
                        Ok(CallToolResult::success(vec![Content::text(format!(
                            "Address: 0x{:X}\nHex: {}",
                            addr,
                            buffer.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(" ")
                        ))]))
                    } else {
                        Ok(CallToolResult::error(vec![Content::text("Failed to read memory")]))
                    }
                }
                "GetRegisters" => {
                    let mut reg_dump = unsafe { std::mem::zeroed::<REGDUMP_AVX512>() };
                    let success = unsafe { DbgGetRegDumpEx(&mut reg_dump, std::mem::size_of::<REGDUMP_AVX512>()) };
                    
                    if success {
                        let regs = &reg_dump.regcontext;
                        let mut reg_map = serde_json::Map::new();
                        
                        reg_map.insert("rax".into(), json!(format!("0x{:X}", regs.cax)));
                        reg_map.insert("rbx".into(), json!(format!("0x{:X}", regs.cbx)));
                        reg_map.insert("rcx".into(), json!(format!("0x{:X}", regs.ccx)));
                        reg_map.insert("rdx".into(), json!(format!("0x{:X}", regs.cdx)));
                        reg_map.insert("rsi".into(), json!(format!("0x{:X}", regs.csi)));
                        reg_map.insert("rdi".into(), json!(format!("0x{:X}", regs.cdi)));
                        reg_map.insert("rbp".into(), json!(format!("0x{:X}", regs.cbp)));
                        reg_map.insert("rsp".into(), json!(format!("0x{:X}", regs.csp)));
                        reg_map.insert("rip".into(), json!(format!("0x{:X}", regs.cip)));
                        reg_map.insert("eflags".into(), json!(format!("0x{:X}", regs.eflags)));

                        #[cfg(target_pointer_width = "64")]
                        {
                            reg_map.insert("r8".into(), json!(format!("0x{:X}", regs.r8)));
                            reg_map.insert("r9".into(), json!(format!("0x{:X}", regs.r9)));
                            reg_map.insert("r10".into(), json!(format!("0x{:X}", regs.r10)));
                            reg_map.insert("r11".into(), json!(format!("0x{:X}", regs.r11)));
                            reg_map.insert("r12".into(), json!(format!("0x{:X}", regs.r12)));
                            reg_map.insert("r13".into(), json!(format!("0x{:X}", regs.r13)));
                            reg_map.insert("r14".into(), json!(format!("0x{:X}", regs.r14)));
                            reg_map.insert("r15".into(), json!(format!("0x{:X}", regs.r15)));
                        }

                        Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&Value::Object(reg_map)).unwrap())]))
                    } else {
                        Ok(CallToolResult::error(vec![Content::text("Failed to get registers (Is the debugger stopped?)")]))
                    }
                }
                "SetRegister" => {
                    let args: SetRegisterArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let cmd = format!("{}={}", args.register, args.value);
                    let cmd_c = CString::new(cmd).unwrap();
                    let success = unsafe { DbgCmdExecDirect(cmd_c.as_ptr()) };
                    
                    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
                }
                "GetBreakpoints" => {
                    let mut bp_map = unsafe { std::mem::zeroed::<BPMAP>() };
                    let count = unsafe { DbgGetBpList(BPXTYPE_bp_normal, &mut bp_map) };
                    
                    let mut bplist = Vec::new();
                    if count > 0 && !bp_map.bp.is_null() {
                        for i in 0..count {
                            let bp = unsafe { *bp_map.bp.add(i as usize) };
                            bplist.push(json!({
                                "address": format!("0x{:X}", bp.addr),
                                "enabled": bp.enabled,
                                "name": unsafe { CStr::from_ptr(bp.name.as_ptr()).to_string_lossy() },
                                "hit_count": bp.hitCount
                            }));
                        }
                        unsafe { BridgeFree(bp_map.bp as *mut c_void) };
                    }
                    
                    Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&bplist).unwrap())]))
                }
                "SetBreakpoint" => {
                    let args: SetBreakpointArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let cmd = format!("bp {}", args.address);
                    let cmd_c = CString::new(cmd).unwrap();
                    let success = unsafe { DbgCmdExecDirect(cmd_c.as_ptr()) };
                    
                    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
                }
                "GetThreads" => {
                    let mut thread_list = unsafe { std::mem::zeroed::<THREADLIST>() };
                    unsafe { DbgGetThreadList(&mut thread_list) };
                    
                    let mut tlist = Vec::new();
                    if thread_list.count > 0 && !thread_list.list.is_null() {
                        for i in 0..thread_list.count {
                            let t = unsafe { *thread_list.list.add(i as usize) };
                            tlist.push(json!({
                                "id": t.BasicInfo.ThreadId,
                                "address": format!("0x{:X}", t.BasicInfo.ThreadStartAddress),
                                "name": unsafe { CStr::from_ptr(t.BasicInfo.threadName.as_ptr()).to_string_lossy() }
                            }));
                        }
                        unsafe { BridgeFree(thread_list.list as *mut c_void) };
                    }
                    
                    Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&tlist).unwrap())]))
                }
                "GetModules" => {
                    let mut mem_map = unsafe { std::mem::zeroed::<MEMMAP>() };
                    let success = unsafe { DbgMemMap(&mut mem_map) };
                    
                    let mut mlist = Vec::new();
                    let mut seen_bases = HashSet::new();
                    
                    if success && mem_map.count > 0 && !mem_map.page.is_null() {
                        for i in 0..mem_map.count {
                            let page = unsafe { *mem_map.page.add(i as usize) };
                            let base = page.mbi.AllocationBase as usize;
                            if page.mbi.Type == MEM_IMAGE && !seen_bases.contains(&base) {
                                let name = unsafe { CStr::from_ptr(page.info.as_ptr()).to_string_lossy() };
                                if !name.is_empty() {
                                    mlist.push(json!({
                                        "base": format!("0x{:X}", base),
                                        "name": name
                                    }));
                                    seen_bases.insert(base);
                                }
                            }
                        }
                        unsafe { BridgeFree(mem_map.page as *mut c_void) };
                    }
                    
                    Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&mlist).unwrap())]))
                }
                "GetCallStack" => {
                    let mut call_stack = unsafe { std::mem::zeroed::<DBGCALLSTACK>() };
                    unsafe { (*DbgFunctions()).GetCallStack.unwrap()(&mut call_stack) };
                    
                    let mut cs_list = Vec::new();
                    if call_stack.total > 0 && !call_stack.entries.is_null() {
                        for i in 0..call_stack.total {
                            let entry = unsafe { *call_stack.entries.add(i as usize) };
                            cs_list.push(json!({
                                "address": format!("0x{:X}", entry.addr),
                                "from": format!("0x{:X}", entry.from),
                                "to": format!("0x{:X}", entry.to),
                                "comment": unsafe { CStr::from_ptr(entry.comment.as_ptr()).to_string_lossy() }
                            }));
                        }
                    }
                    
                    Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&cs_list).unwrap())]))
                }
                "SetComment" => {
                    let args: SetCommentLabelArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let addr = parse_hex(&args.address)?;
                    let text_c = CString::new(args.text).unwrap();
                    let success = unsafe { DbgSetCommentAt(addr, text_c.as_ptr()) };
                    
                    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
                }
                "SetLabel" => {
                    let args: SetCommentLabelArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let addr = parse_hex(&args.address)?;
                    let text_c = CString::new(args.text).unwrap();
                    let success = unsafe { DbgSetLabelAt(addr, text_c.as_ptr()) };
                    
                    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
                }
                _ => Err(ErrorData::method_not_found::<CallToolRequestMethod>()),
            }
        }
    }
}

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
            len
        );
        (*init_struct).pluginName[len] = 0;
    }

    log_print("MCP Server (Rust) initialized!\n");

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
    true
}

#[tokio::main]
async fn start_mcp_server() {
    log_print("Starting MCP server listener on http://127.0.0.1:50301/mcp/sse ...\n");
    
    let server = X64DbgMcpServer;
    let config = StreamableHttpServerConfig {
        stateful_mode: true,
        ..Default::default()
    };
    
    let service = StreamableHttpService::new(
        move || Ok(server.clone()),
        LocalSessionManager::default().into(),
        config,
    );

    let router = axum::Router::new().nest_service("/mcp", service);
    let bind_addr = "127.0.0.1:50301";
    
    match tokio::net::TcpListener::bind(bind_addr).await {
        Ok(listener) => {
            if let Err(e) = axum::serve(listener, router).await {
                log_print(&format!("MCP Server Error: {}\n", e));
            }
        }
        Err(e) => {
            log_print(&format!("Failed to bind to {}: {}\n", bind_addr, e));
        }
    }
}
