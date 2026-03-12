use super::tools::*;
use crate::x64dbg::api::log_print;
use rmcp::{
    model::*,
    service::{Peer, RequestContext},
    RoleServer, ServerHandler,
    ErrorData,
    transport::{
        StreamableHttpServerConfig, StreamableHttpService,
        streamable_http_server::session::local::LocalSessionManager,
    },
};
use std::future::Future;
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use serde_json::{json, Value};

pub static GLOBAL_PEERS: Lazy<Mutex<Vec<Peer<RoleServer>>>> = Lazy::new(|| Mutex::new(Vec::new()));

pub async fn broadcast_event(level: LoggingLevel, data: Value) {
    let peers = if let Ok(mut peers) = GLOBAL_PEERS.lock() {
        peers.retain(|p| !p.is_transport_closed());
        peers.clone()
    } else {
        return;
    };
    
    for peer in peers {
        let notif = ServerNotification::LoggingMessageNotification(
            LoggingMessageNotification {
                params: LoggingMessageNotificationParam {
                    level,
                    data: data.clone(),
                    logger: Some("x64dbg".to_string()),
                },
                method: LoggingMessageNotificationMethod,
                extensions: Default::default(),
            }
        );
        let _ = peer.send_notification(notif).await;
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
                        "Parse x64dbg expression (e.g. [eax+4])",
                        Arc::new(to_json_object(json!({
                            "type": "object",
                            "properties": {
                                "expression": { "type": "string", "description": "Expression string" }
                            },
                            "required": ["expression"]
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
                _ => Err(ErrorData::method_not_found::<CallToolRequestMethod>()),
            }
        }
    }
}

#[tokio::main]
pub async fn start_mcp_server() {
    log_print("Starting MCP server listener on http://127.0.0.1:50301/mcp/sse ...\n");
    
    // Start background event loop for sending notifications to all peers
    if let Ok(mut lock) = super::events::EVENT_RX.lock() {
        if let Some(mut rx) = lock.take() {
            tokio::spawn(async move {
                while let Some(event) = rx.recv().await {
                    broadcast_event(LoggingLevel::Info, event).await;
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
