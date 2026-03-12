use super::tools::*;
use crate::x64dbg::api::log_print;
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
use std::future::Future;
use std::sync::Arc;
use serde_json::{json, Value};

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
                "ExecuteCommand" => handle_execute_command(request),
                "ReadMemory" => handle_read_memory(request),
                "GetRegisters" => handle_get_registers(request),
                "SetRegister" => handle_set_register(request),
                "GetBreakpoints" => handle_get_breakpoints(request),
                "SetBreakpoint" => handle_set_breakpoint(request),
                "GetThreads" => handle_get_threads(request),
                "GetModules" => handle_get_modules(request),
                "GetCallStack" => handle_get_call_stack(request),
                "SetComment" => handle_set_comment(request),
                "SetLabel" => handle_set_label(request),
                _ => Err(ErrorData::method_not_found::<CallToolRequestMethod>()),
            }
        }
    }
}

#[tokio::main]
pub async fn start_mcp_server() {
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
