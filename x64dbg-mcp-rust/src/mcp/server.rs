use super::tools::*;
use crate::x64dbg::api::log_print;
use once_cell::sync::Lazy;
use rmcp::{
    model::*,
    service::{Peer, RequestContext},
    transport::{
        streamable_http_server::session::local::LocalSessionManager, StreamableHttpServerConfig,
        StreamableHttpService,
    },
    ErrorData, Resource, RoleServer, Server, ServerHandler, Tool,
};
use serde_json::{json, Value};
use std::future::Future;
use std::sync::{Arc, Mutex};

pub static GLOBAL_PEERS: Lazy<Mutex<Vec<Peer<RoleServer>>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub async fn broadcast_event(level: LoggingLevel, data: Value) {
    let peers = if let Ok(mut peers) = GLOBAL_PEERS.lock() {
        peers.retain(|p: &Peer<RoleServer>| !p.is_transport_closed());
        peers.clone()
    } else {
        return;
    };

    for peer in peers {
        let params = LoggingMessageNotificationParam::new(level, data.clone())
            .with_logger("x64dbg".to_string());
        let notif_inner = LoggingMessageNotification::new(params);
        let notif = ServerNotification::LoggingMessageNotification(notif_inner);

        let peer2 = peer.clone();
        let notif2 = notif.clone();
        tokio::spawn(async move {
            let _ = peer2.notify(notif2).await;
        });
    }
}

fn to_json_object(v: Value) -> JsonObject {
    if let Value::Object(m) = v {
        m
    } else {
        panic!("Value is not an object")
    }
}

#[derive(Clone)]
pub struct X64DbgMcpServer;

impl ServerHandler for X64DbgMcpServer {
    fn initialize(
        &self,
        _request: InitializeRequestParams,
        cx: RequestContext<RoleServer>,
    ) -> impl Future<Output = Result<InitializeResult, ErrorData>> + Send + '_ {
        let peer = cx.peer.clone();
        async move {
            if let Ok(mut peers) = GLOBAL_PEERS.lock() {
                peers.push(peer);
            }
            Ok(
                InitializeResult::new(ServerCapabilities::builder().enable_tools().build())
                    .with_server_info(Implementation::new("x64dbg-rust-mcp", "0.1.0")),
            )
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
                    ),
                    Tool::new(
                        "DebugRun",
                        "Resume execution of the debugged process",
                        Arc::new(to_json_object(json!({ "type": "object", "properties": {} })))
                    ),
                    Tool::new(
                        "DebugPause",
                        "Pause execution of the debugged process",
                        Arc::new(to_json_object(json!({ "type": "object", "properties": {} })))
                    ),
                    Tool::new(
                        "DebugStop",
                        "Stop debugging",
                        Arc::new(to_json_object(json!({ "type": "object", "properties": {} })))
                    ),
                    Tool::new(
                        "DebugStepIn",
                        "Step into the next instruction",
                        Arc::new(to_json_object(json!({ "type": "object", "properties": {} })))
                    ),
                    Tool::new(
                        "DebugStepOver",
                        "Step over the next instruction",
                        Arc::new(to_json_object(json!({ "type": "object", "properties": {} })))
                    ),
                    Tool::new(
                        "DebugStepOut",
                        "Step out of the current function",
                        Arc::new(to_json_object(json!({ "type": "object", "properties": {} })))
                    ),
                    Tool::new(
                        "AssembleMem",
                        "Assemble instruction directly into memory",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "address": { "type": "string", "description": "Hex address" },
                                "instruction": { "type": "string", "description": "Assembly string" }
                            },
                            "required": ["address", "instruction"]
                        })))
                    ),
                    Tool::new(
                        "PatternFindMem",
                        "Find pattern in memory",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "start": { "type": "string", "description": "Hex start address" },
                                "size": { "type": "string", "description": "Hex size to search" },
                                "pattern": { "type": "string", "description": "Byte pattern e.g. 48 8b 05 ? ? ?" }
                            },
                            "required": ["start", "size", "pattern"]
                        })))
                    ),
                    Tool::new(
                        "MemoryIsValidPtr",
                        "Check if memory address is readable",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "address": { "type": "string", "description": "Hex address" }
                            },
                            "required": ["address"]
                        })))
                    ),
                    Tool::new(
                        "MiscParseExpression",
                        "Evaluates a complex expression (e.g. '[eax]+4') via '? expr' and returns the evaluated integer.",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "expression": { "type": "string", "description": "Expression to evaluate (e.g., 'rax+8')" }
                            },
                            "required": ["expression"]
                        }))),
                    ),
                    Tool::new(
                        "YaraScanMem",
                        "Scans a chunk of memory using a given YARA rule. Automatically applies pure rust Boreal engine.",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "start": { "type": "string", "description": "Start address in hex (e.g., '0x401000')" },
                                "size": { "type": "string", "description": "Size to read and scan in hex (e.g., '0x1000')" },
                                "rule": { "type": "string", "description": "YARA rules string" }
                            },
                            "required": ["start", "size", "rule"]
                        }))),
                    ),
                    Tool::new(
                        "AnalyzeFunction",
                        "Analyze function at address to retrieve Control Flow Graph (CFG) nodes and instructions.",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "address": { "type": "string", "description": "Hex address of the function entry point" }
                            },
                            "required": ["address"]
                        }))),
                    ),
                    Tool::new(
                        "StructDumpMem",
                        "Dumps a C-like structure from memory into a parsed JSON representation.",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "address": { "type": "string", "description": "Start address in hex" },
                                "fields": {
                                    "type": "array",
                                    "description": "List of struct fields containing name and type. Supported types: u8, u16, u32, u64, i8, i16, i32, i64, f32, f64, char[N], u8[N], ptr",
                                    "items": {
                                        "type": "object",
                                        "properties": {
                                            "name": { "type": "string" },
                                            "type": { "type": "string", "description": "e.g., 'u32', 'char[16]', 'ptr'" }
                                        },
                                        "required": ["name", "type"]
                                    }
                                }
                            },
                            "required": ["address", "fields"]
                        }))),
                    ),
                    Tool::new(
                        "GetSymbols",
                        "Extract all function, import, and export symbols from a loaded module. Not fully implemented via native struct yet, but acts as a placeholder.",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "module": { "type": "string", "description": "Module name or '*' for all modules" }
                            },
                        })))
                    ),
                    Tool::new(
                        "GetStrings",
                        "Extract string references from a loaded module.",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "module": { "type": "string", "description": "Module name or '*' for all modules" }
                            },
                        })))
                    ),
                    Tool::new(
                        "ExecuteScript",
                        "Execute a Rhai script in the x64dbg GUI thread for quick internal automated actions.",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "script": { "type": "string", "description": "Rhai script code" }
                            },
                            "required": ["script"]
                        })))
                    ),
                    Tool::new(
                        "GetXrefs",
                        "Get all cross-references (calls, jumps, data access) to a specific address.",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "address": { "type": "string", "description": "Hex address" }
                            },
                            "required": ["address"]
                        })))
                    ),
                    Tool::new(
                        "GetMemoryMapFull",
                        "Get the full memory map of the process, including non-module regions and their protection states.",
                        Arc::new(to_json_object(json!({ "type": "object", "properties": {} })))
                    ),
                    Tool::new(
                        "DisassembleRange",
                        "Disassemble a range of instructions starting from an address.",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "address": { "type": "string", "description": "Starting hex address" },
                                "size": { "type": "integer", "description": "Number of instructions to disassemble" }
                            },
                            "required": ["address", "size"]
                        })))
                    ),
                    Tool::new(
                        "SetBookmark",
                        "Set or remove a bookmark at a specific address.",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "address": { "type": "string", "description": "Hex address" },
                                "is_bookmark": { "type": "boolean", "description": "Set true to add, false to remove" }
                            },
                            "required": ["address", "is_bookmark"]
                        })))
                    ),
                    Tool::new(
                        "GetPebTeb",
                        "Retrieve the PEB and TEB addresses of the current process and thread.",
                        Arc::new(to_json_object(json!({ "type": "object", "properties": {} })))
                    ),
                    Tool::new(
                        "GetTcpConnections",
                        "List all active TCP connections (remote/local IP and Port) of the debugged process.",
                        Arc::new(to_json_object(json!({ "type": "object", "properties": {} })))
                    ),
                    Tool::new(
                        "GetHandles",
                        "List all system handles (files, keys, etc.) owned by the debugged process.",
                        Arc::new(to_json_object(json!({ "type": "object", "properties": {} })))
                    ),
                    Tool::new(
                        "GetPatches",
                        "List all byte patches currently applied to the debugged process (original vs patched).",
                        Arc::new(to_json_object(json!({ "type": "object", "properties": {} })))
                    ),
                    Tool::new(
                        "GetHeaps",
                        "List all memory heaps allocated by the debugged process.",
                        Arc::new(to_json_object(json!({ "type": "object", "properties": {} })))
                    ),
                    Tool::new(
                        "GetWindows",
                        "List all GUI windows created by the debugged process, including handles and titles.",
                        Arc::new(to_json_object(json!({ "type": "object", "properties": {} })))
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
                "ExecuteCommand" => handle_execute_command(request).await,
                "ReadMemory" => handle_read_memory(request).await,
                "GetRegisters" => handle_get_registers(request).await,
                "SetRegister" => handle_set_register(request).await,
                "GetBreakpoints" => handle_get_breakpoints(request).await,
                "SetBreakpoint" => handle_set_breakpoint(request).await,
                "GetThreads" => handle_get_threads(request).await,
                "GetModules" => handle_get_modules(request).await,
                "GetCallStack" => handle_get_call_stack(request).await,
                "SetComment" => handle_set_comment(request).await,
                "SetLabel" => handle_set_label(request).await,
                "DebugRun" => handle_debug_run(request).await,
                "DebugPause" => handle_debug_pause(request).await,
                "DebugStop" => handle_debug_stop(request).await,
                "DebugStepIn" => handle_debug_step_in(request).await,
                "DebugStepOver" => handle_debug_step_over(request).await,
                "DebugStepOut" => handle_debug_step_out(request).await,
                "AssembleMem" => handle_assemble_mem(request).await,
                "PatternFindMem" => handle_pattern_find_mem(request).await,
                "MemoryIsValidPtr" => handle_memory_is_valid_ptr(request).await,
                "MiscParseExpression" => handle_misc_parse_expression(request).await,
                "YaraScanMem" => handle_yara_scan_mem(request).await,
                "AnalyzeFunction" => handle_analyze_function(request).await,
                "StructDumpMem" => handle_struct_dump_mem(request).await,
                "GetSymbols" => handle_get_symbols(request).await,
                "GetStrings" => handle_get_strings(request).await,
                "ExecuteScript" => handle_execute_script(request).await,
                "GetXrefs" => handle_get_xrefs(request).await,
                "GetMemoryMapFull" => handle_get_memory_map_full(request).await,
                "DisassembleRange" => handle_disassemble_range(request).await,
                "SetBookmark" => handle_bookmark(request).await,
                "GetPebTeb" => handle_get_peb_teb(request).await,
                "GetTcpConnections" => handle_get_tcp_connections(request).await,
                "GetHandles" => handle_get_handles(request).await,
                "GetPatches" => handle_get_patches(request).await,
                "GetHeaps" => handle_get_heaps(request).await,
                "GetWindows" => handle_get_windows(request).await,
                _ => Err(ErrorData::invalid_params(
                    format!("Unknown tool: {}", request.name),
                    None,
                )),
            }
        }
    }
}

#[tokio::main]
pub async fn start_mcp_server() {
    let port = std::env::var("X64DBG_MCP_PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(50301);
    let bind_addr = format!("127.0.0.1:{}", port);
    log_print(&format!(
        "Starting MCP server listener on http://{} ...\n",
        bind_addr
    ));

    let shutdown_token = super::events::SHUTDOWN_TOKEN.clone();

    // Start background event loop for sending notifications to all peers
    if let Ok(mut lock) = super::events::EVENT_RX.lock() {
        if let Some(mut rx) = lock.take() {
            let loop_shutdown = shutdown_token.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        event = rx.recv() => {
                            if let Some(event) = event {
                                broadcast_event(LoggingLevel::Info, event).await;
                            } else {
                                break;
                            }
                        }
                        _ = loop_shutdown.cancelled() => {
                            break;
                        }
                    }
                }
            });
        }
    }

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
    let listen_addr = bind_addr.clone();

    let server_shutdown = shutdown_token.clone();
    match tokio::net::TcpListener::bind(&listen_addr).await {
        Ok(listener) => {
            let server = axum::serve(listener, router).with_graceful_shutdown(async move {
                server_shutdown.cancelled().await;
            });
            if let Err(e) = server.await {
                log_print(&format!("MCP Server Error: {}\n", e));
            }
        }
        Err(e) => {
            log_print(&format!("Failed to bind to {}: {}\n", bind_addr, e));
        }
    }
    log_print("MCP Server background thread exiting.\n");
}
