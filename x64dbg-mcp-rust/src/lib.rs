#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::os::raw::c_void;
use std::thread;
use std::ffi::{CString, CStr};
use std::future::Future;
use std::sync::{Arc, Mutex, OnceLock};
use crossbeam_channel::{unbounded, Sender, Receiver};
use tokio::sync::oneshot;
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

static SHUTDOWN_TX: OnceLock<Mutex<Option<oneshot::Sender<()>>>> = OnceLock::new();
type Task = Box<dyn FnOnce() + Send + 'static>;
static TASK_TX: OnceLock<Sender<Task>> = OnceLock::new();
static TASK_RX: OnceLock<Receiver<Task>> = OnceLock::new();

unsafe extern "C" fn process_tasks_callback() {
    if let Some(rx) = TASK_RX.get() {
        while let Ok(task) = rx.try_recv() {
            task();
        }
    }
}

pub async fn run_on_gui_thread<T, F>(f: F) -> T
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = oneshot::channel();
    let task = Box::new(move || {
        let result = f();
        let _ = tx.send(result);
    });

    if let Some(queue) = TASK_TX.get() {
        let _ = queue.send(task);
        unsafe {
            GuiExecuteOnGuiThread(Some(process_tasks_callback));
        }
    }
    rx.await.unwrap_or_else(|_| panic!("Failed to receive result from GUI thread"))
}

// Safe wrapper around x64dbg log
fn log_print(msg: &str) {
    if let Ok(msg_c) = CString::new(msg) {
        unsafe {
            _plugin_logputs(msg_c.as_ptr());
        }
    }
}

#[derive(Clone)]
struct X64DbgMcpServer;

#[derive(Debug, Deserialize)]
struct ExecuteCommandArgs {
    command: String,
}

#[derive(Debug, Deserialize)]
struct ExecuteScriptArgs {
    commands: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReadMemoryArgs {
    address: String, // hex string
    size: usize,
}

#[derive(Debug, Deserialize)]
struct WriteMemoryArgs {
    address: String, // hex string
    data: String,    // hex bytes e.g. "9090"
}

#[derive(Debug, Deserialize)]
struct EvaluateExpressionArgs {
    expression: String,
}

#[derive(Debug, Deserialize)]
struct DisassembleArgs {
    address: String, // hex string
    count: Option<usize>,
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
        serde_json::Map::new()
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
                    .resources(ResourceCapabilities {
                        subscribe: Some(false),
                        list_changed: Some(false),
                    })
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

    fn list_resources(
        &self,
        _request: Option<PaginatedRequestParams>,
        _cx: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ListResourcesResult, ErrorData>> + Send + '_ {
        async move {
            Ok(ListResourcesResult {
                resources: vec![
                    Resource::new(
                        "debug://modules",
                        "Loaded Modules",
                    ).with_description("List of all currently loaded modules in the process")
                     .with_mime_type("application/json"),
                    Resource::new(
                        "debug://threads",
                        "Thread List",
                    ).with_description("List of all active threads in the process")
                     .with_mime_type("application/json"),
                    Resource::new(
                        "debug://registers",
                        "Current Registers",
                    ).with_description("Current state of general-purpose CPU registers")
                     .with_mime_type("application/json"),
                ],
                next_cursor: None,
                meta: None,
            })
        }
    }

    fn read_resource(
        &self,
        request: ReadResourceRequestParams,
        _cx: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<ReadResourceResult, ErrorData>> + Send + '_ {
        async move {
            let uri = request.uri.as_str();
            
            let content = match uri {
                "debug://modules" => {
                    let mlist = run_on_gui_thread(|| {
                        let mut mem_map = unsafe { std::mem::zeroed::<MEMMAP>() };
                        let success = unsafe { DbgMemMap(&mut mem_map) };
                        
                        let mut mlist = Vec::new();
                        let mut seen_bases = HashSet::new();
                        
                        if success && mem_map.count > 0 && !mem_map.page.is_null() {
                            for i in 0..mem_map.count {
                                let page = unsafe { *mem_map.page.add(i as usize) };
                                let base = page.mbi.AllocationBase as usize;
                                if page.mbi.Type == MEM_IMAGE && !seen_bases.contains(&base) {
                                    let name = unsafe { CStr::from_ptr(page.info.as_ptr()).to_string_lossy().into_owned() };
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
                        mlist
                    }).await;
                    serde_json::to_string_pretty(&mlist).unwrap_or_else(|_| "[]".to_string())
                },
                "debug://threads" => {
                    let tlist = run_on_gui_thread(|| {
                        let mut thread_list = unsafe { std::mem::zeroed::<THREADLIST>() };
                        unsafe { DbgGetThreadList(&mut thread_list) };
                        
                        let mut tlist = Vec::new();
                        if thread_list.count > 0 && !thread_list.list.is_null() {
                            for i in 0..thread_list.count {
                                let t = unsafe { *thread_list.list.add(i as usize) };
                                tlist.push(json!({
                                    "id": t.BasicInfo.ThreadId,
                                    "address": format!("0x{:X}", t.BasicInfo.ThreadStartAddress),
                                    "name": unsafe { CStr::from_ptr(t.BasicInfo.threadName.as_ptr()).to_string_lossy().into_owned() }
                                }));
                            }
                            unsafe { BridgeFree(thread_list.list as *mut c_void) };
                        }
                        tlist
                    }).await;
                    serde_json::to_string_pretty(&tlist).unwrap_or_else(|_| "[]".to_string())
                },
                "debug://registers" => {
                    let reg_json = run_on_gui_thread(|| {
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
                            serde_json::to_string_pretty(&reg_map).unwrap_or_else(|_| "{}".to_string())
                        } else {
                            "{\"error\": \"Debugger not running or paused\"}".to_string()
                        }
                    }).await;
                    reg_json
                },
                _ => return Err(ErrorData::invalid_params(format!("Resource not found: {}", uri), None)),
            };

            Ok(ReadResourceResult {
                contents: vec![ResourceContents::text(content, uri).with_mime_type("application/json")],
                meta: None,
            })
        }
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
                        "ExecuteScript",
                        "Executes a list of x64dbg commands sequentially (useful for batch operations)",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "commands": { 
                                    "type": "array", 
                                    "items": { "type": "string" },
                                    "description": "List of x64dbg commands to execute in order" 
                                }
                            },
                            "required": ["commands"]
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
                        "WriteMemory",
                        "Writes memory to the debuggee",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "address": { "type": "string", "description": "Hex address (e.g. 0x140001000)" },
                                "data": { "type": "string", "description": "Hex string of bytes to write (e.g. 9090 for NOP NOP)" }
                            },
                            "required": ["address", "data"]
                        })))
                    ),
                    Tool::new(
                        "EvaluateExpression",
                        "Evaluates a mathematical expression or resolves an address (e.g. [esp+8], rax+0x10)",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "expression": { "type": "string", "description": "The expression to evaluate" }
                            },
                            "required": ["expression"]
                        })))
                    ),
                    Tool::new(
                        "Disassemble",
                        "Gets disassembly of instructions starting at a specific address",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "address": { "type": "string", "description": "Hex address to start disassembling from" },
                                "count": { "type": "integer", "description": "Number of instructions to disassemble (default: 1)" }
                            },
                            "required": ["address"]
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
                    
                    let cmd_c = CString::new(args.command)
                        .map_err(|_| ErrorData::invalid_params("Invalid command format", None))?;
                        
                    let success = run_on_gui_thread(move || {
                        unsafe { DbgCmdExecDirect(cmd_c.as_ptr()) }
                    }).await;
                    
                    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
                }
                "ExecuteScript" => {
                    let args: ExecuteScriptArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let mut results = Vec::new();
                    let mut all_success = true;

                    for cmd_str in args.commands {
                        let cmd_c = CString::new(cmd_str.clone())
                            .map_err(|_| ErrorData::invalid_params("Invalid command format", None))?;
                            
                        let success = run_on_gui_thread(move || {
                            unsafe { DbgCmdExecDirect(cmd_c.as_ptr()) }
                        }).await;
                        
                        results.push(format!("Command '{}' -> Success: {}", cmd_str, success));
                        
                        if !success {
                            all_success = false;
                            break; // Stop execution on first failure
                        }
                    }
                    
                    let result_text = results.join("\n");
                    if all_success {
                        Ok(CallToolResult::success(vec![Content::text(result_text)]))
                    } else {
                        Ok(CallToolResult::error(vec![Content::text(format!("Script failed:\n{}", result_text))]))
                    }
                }
                "ReadMemory" => {
                    let args: ReadMemoryArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let addr = parse_hex(&args.address)?;
                    let size = args.size;
                    
                    let (success, buffer) = run_on_gui_thread(move || {
                        let mut buffer = vec![0u8; size];
                        let success = unsafe {
                            DbgMemRead(addr, buffer.as_mut_ptr() as *mut c_void, size as duint)
                        };
                        (success, buffer)
                    }).await;
                    
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
                "WriteMemory" => {
                    let args: WriteMemoryArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let addr = parse_hex(&args.address)?;
                    
                    // Parse hex string to bytes
                    let hex_data = args.data.trim().replace(" ", "");
                    if hex_data.len() % 2 != 0 {
                        return Err(ErrorData::invalid_params("Hex data length must be even", None));
                    }
                    
                    let mut buffer = Vec::new();
                    for i in (0..hex_data.len()).step_by(2) {
                        let byte_str = &hex_data[i..i+2];
                        let byte = u8::from_str_radix(byte_str, 16)
                            .map_err(|_| ErrorData::invalid_params("Invalid hex byte", None))?;
                        buffer.push(byte);
                    }
                    
                    let size = buffer.len() as duint;
                    
                    let success = run_on_gui_thread(move || {
                        unsafe {
                            DbgMemWrite(addr, buffer.as_ptr() as *const c_void, size)
                        }
                    }).await;
                    
                    if success {
                        Ok(CallToolResult::success(vec![Content::text(format!("Successfully wrote {} bytes to 0x{:X}", size, addr))]))
                    } else {
                        Ok(CallToolResult::error(vec![Content::text("Failed to write memory")]))
                    }
                }
                "EvaluateExpression" => {
                    let args: EvaluateExpressionArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let expr_c = CString::new(args.expression)
                        .map_err(|_| ErrorData::invalid_params("Invalid expression format", None))?;
                        
                    let result = run_on_gui_thread(move || {
                        unsafe { DbgValFromString(expr_c.as_ptr()) }
                    }).await;
                    
                    Ok(CallToolResult::success(vec![Content::text(format!("0x{:X}", result))]))
                }
                "Disassemble" => {
                    let args: DisassembleArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let start_addr = parse_hex(&args.address)?;
                    let count = args.count.unwrap_or(1);
                    
                    let disasm_list = run_on_gui_thread(move || {
                        let mut current_addr = start_addr;
                        let mut results = Vec::new();
                        
                        for _ in 0..count {
                            let mut instr = unsafe { std::mem::zeroed::<DISASM_INSTR>() };
                            unsafe { DbgDisasmAt(current_addr, &mut instr) };
                            
                            if instr.instr_size > 0 {
                                results.push(json!({
                                    "address": format!("0x{:X}", current_addr),
                                    "instruction": unsafe { CStr::from_ptr(instr.instruction.as_ptr()).to_string_lossy().into_owned() },
                                    "size": instr.instr_size
                                }));
                                current_addr += instr.instr_size as usize;
                            } else {
                                break;
                            }
                        }
                        results
                    }).await;
                    
                    let json_str = serde_json::to_string_pretty(&disasm_list)
                        .map_err(|e| ErrorData::internal_error(e.to_string()))?;
                    Ok(CallToolResult::success(vec![Content::text(json_str)]))
                }
                "GetRegisters" => {
                    let result = run_on_gui_thread(|| {
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
                            Some(reg_map)
                        } else {
                            None
                        }
                    }).await;
                    
                    if let Some(reg_map) = result {
                        let json_str = serde_json::to_string_pretty(&Value::Object(reg_map))
                            .map_err(|e| ErrorData::internal_error(e.to_string()))?;
                        Ok(CallToolResult::success(vec![Content::text(json_str)]))
                    } else {
                        Ok(CallToolResult::error(vec![Content::text("Failed to get registers (Is the debugger stopped?)")]))
                    }
                }
                "SetRegister" => {
                    let args: SetRegisterArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let cmd = format!("{}={}", args.register, args.value);
                    let cmd_c = CString::new(cmd)
                        .map_err(|_| ErrorData::invalid_params("Invalid register or value format", None))?;
                        
                    let success = run_on_gui_thread(move || {
                        unsafe { DbgCmdExecDirect(cmd_c.as_ptr()) }
                    }).await;
                    
                    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
                }
                "GetBreakpoints" => {
                    let bplist = run_on_gui_thread(|| {
                        let mut bp_map = unsafe { std::mem::zeroed::<BPMAP>() };
                        let count = unsafe { DbgGetBpList(BPXTYPE_bp_normal, &mut bp_map) };
                        
                        let mut bplist = Vec::new();
                        if count > 0 && !bp_map.bp.is_null() {
                            for i in 0..count {
                                let bp = unsafe { *bp_map.bp.add(i as usize) };
                                bplist.push(json!({
                                    "address": format!("0x{:X}", bp.addr),
                                    "enabled": bp.enabled,
                                    "name": unsafe { CStr::from_ptr(bp.name.as_ptr()).to_string_lossy().into_owned() },
                                    "hit_count": bp.hitCount
                                }));
                            }
                            unsafe { BridgeFree(bp_map.bp as *mut c_void) };
                        }
                        bplist
                    }).await;
                    
                    let json_str = serde_json::to_string_pretty(&bplist)
                        .map_err(|e| ErrorData::internal_error(e.to_string()))?;
                    Ok(CallToolResult::success(vec![Content::text(json_str)]))
                }
                "SetBreakpoint" => {
                    let args: SetBreakpointArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let cmd = format!("bp {}", args.address);
                    let cmd_c = CString::new(cmd)
                        .map_err(|_| ErrorData::invalid_params("Invalid address format", None))?;
                        
                    let success = run_on_gui_thread(move || {
                        unsafe { DbgCmdExecDirect(cmd_c.as_ptr()) }
                    }).await;
                    
                    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
                }
                "GetThreads" => {
                    let tlist = run_on_gui_thread(|| {
                        let mut thread_list = unsafe { std::mem::zeroed::<THREADLIST>() };
                        unsafe { DbgGetThreadList(&mut thread_list) };
                        
                        let mut tlist = Vec::new();
                        if thread_list.count > 0 && !thread_list.list.is_null() {
                            for i in 0..thread_list.count {
                                let t = unsafe { *thread_list.list.add(i as usize) };
                                tlist.push(json!({
                                    "id": t.BasicInfo.ThreadId,
                                    "address": format!("0x{:X}", t.BasicInfo.ThreadStartAddress),
                                    "name": unsafe { CStr::from_ptr(t.BasicInfo.threadName.as_ptr()).to_string_lossy().into_owned() }
                                }));
                            }
                            unsafe { BridgeFree(thread_list.list as *mut c_void) };
                        }
                        tlist
                    }).await;
                    
                    let json_str = serde_json::to_string_pretty(&tlist)
                        .map_err(|e| ErrorData::internal_error(e.to_string()))?;
                    Ok(CallToolResult::success(vec![Content::text(json_str)]))
                }
                "GetModules" => {
                    let mlist = run_on_gui_thread(|| {
                        let mut mem_map = unsafe { std::mem::zeroed::<MEMMAP>() };
                        let success = unsafe { DbgMemMap(&mut mem_map) };
                        
                        let mut mlist = Vec::new();
                        let mut seen_bases = HashSet::new();
                        
                        if success && mem_map.count > 0 && !mem_map.page.is_null() {
                            for i in 0..mem_map.count {
                                let page = unsafe { *mem_map.page.add(i as usize) };
                                let base = page.mbi.AllocationBase as usize;
                                if page.mbi.Type == MEM_IMAGE && !seen_bases.contains(&base) {
                                    let name = unsafe { CStr::from_ptr(page.info.as_ptr()).to_string_lossy().into_owned() };
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
                        mlist
                    }).await;
                    
                    let json_str = serde_json::to_string_pretty(&mlist)
                        .map_err(|e| ErrorData::internal_error(e.to_string()))?;
                    Ok(CallToolResult::success(vec![Content::text(json_str)]))
                }
                "GetCallStack" => {
                    let cs_list = run_on_gui_thread(|| {
                        let mut call_stack = unsafe { std::mem::zeroed::<DBGCALLSTACK>() };
                        let mut cs_list = Vec::new();
                        unsafe {
                            if let Some(func) = (*DbgFunctions()).GetCallStack {
                                func(&mut call_stack);
                                if call_stack.total > 0 && !call_stack.entries.is_null() {
                                    for i in 0..call_stack.total {
                                        let entry = *call_stack.entries.add(i as usize);
                                        cs_list.push(json!({
                                            "address": format!("0x{:X}", entry.addr),
                                            "from": format!("0x{:X}", entry.from),
                                            "to": format!("0x{:X}", entry.to),
                                            "comment": CStr::from_ptr(entry.comment.as_ptr()).to_string_lossy().into_owned()
                                        }));
                                    }
                                    BridgeFree(call_stack.entries as *mut c_void);
                                }
                            }
                        }
                        cs_list
                    }).await;
                    
                    let json_str = serde_json::to_string_pretty(&cs_list)
                        .map_err(|e| ErrorData::internal_error(e.to_string()))?;
                    Ok(CallToolResult::success(vec![Content::text(json_str)]))
                }
                "SetComment" => {
                    let args: SetCommentLabelArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let addr = parse_hex(&args.address)?;
                    let text_c = CString::new(args.text)
                        .map_err(|_| ErrorData::invalid_params("Invalid comment text format", None))?;
                        
                    let success = run_on_gui_thread(move || {
                        unsafe { DbgSetCommentAt(addr, text_c.as_ptr()) }
                    }).await;
                    
                    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
                }
                "SetLabel" => {
                    let args: SetCommentLabelArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
                        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
                    
                    let addr = parse_hex(&args.address)?;
                    let text_c = CString::new(args.text)
                        .map_err(|_| ErrorData::invalid_params("Invalid label text format", None))?;
                        
                    let success = run_on_gui_thread(move || {
                        unsafe { DbgSetLabelAt(addr, text_c.as_ptr()) }
                    }).await;
                    
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
        let name = CString::new("McpServerRust").unwrap_or_default();
        let name_bytes = name.as_bytes_with_nul();
        let len = name_bytes.len().min((*init_struct).pluginName.len() - 1);
        
        std::ptr::copy_nonoverlapping(
            name_bytes.as_ptr(),
            (*init_struct).pluginName.as_mut_ptr() as *mut u8,
            len
        );
        (*init_struct).pluginName[len] = 0;
    }

    // Initialize Channels
    let _ = TASK_TX.set({
        let (tx, rx) = unbounded();
        let _ = TASK_RX.set(rx);
        tx
    });
    let _ = SHUTDOWN_TX.set(Mutex::new(None));

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
    if let Some(mutex) = SHUTDOWN_TX.get() {
        if let Ok(mut lock) = mutex.lock() {
            if let Some(tx) = lock.take() {
                let _ = tx.send(());
            }
        }
    }
    true
}

#[tokio::main]
async fn start_mcp_server() {
    let port = std::env::var("X64DBG_MCP_PORT").unwrap_or_else(|_| "50301".to_string());
    let bind_addr = format!("127.0.0.1:{}", port);
    log_print(&format!("Starting MCP server listener on http://{}/mcp/sse ...\n", bind_addr));
    
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
    
    match tokio::net::TcpListener::bind(&bind_addr).await {
        Ok(listener) => {
            let (tx, rx) = oneshot::channel();
            if let Some(mutex) = SHUTDOWN_TX.get() {
                if let Ok(mut lock) = mutex.lock() {
                    *lock = Some(tx);
                }
            }

            if let Err(e) = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = rx.await;
                    log_print("MCP Server shutting down gracefully...\n");
                })
                .await 
            {
                log_print(&format!("MCP Server Error: {}\n", e));
            }
        }
        Err(e) => {
            log_print(&format!("Failed to bind to {}: {}\n", bind_addr, e));
        }
    }
}
