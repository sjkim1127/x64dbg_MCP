use crate::mcp::types::*;
use crate::x64dbg::api::*;
use rmcp::{model::*, ErrorData};
use serde_json::{json, Value};

use crate::mcp::concurrency::{DbgRequest, DbgResponse, McpTask, TASK_TX, drain_task_queue_callback};
use tokio::sync::oneshot;

pub fn parse_hex(s: &str) -> Result<crate::x64dbg::duint, ErrorData> {
    crate::x64dbg::duint::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|_| ErrorData::invalid_params(format!("Invalid hex format: {}", s), None))
}

async fn dispatch_dbg_request(request: DbgRequest) -> Result<DbgResponse, ErrorData> {
    let (resp_tx, resp_rx) = oneshot::channel();
    let task = McpTask {
        request,
        responder: resp_tx,
    };
    
    if TASK_TX.send(task).is_err() {
        return Err(ErrorData::internal_error("Failed to send task to x64dbg MCP queue"));
    }
    
    // Wake up x64dbg main thread to process the queue
    unsafe {
        crate::x64dbg::GuiExecuteOnGuiThreadEx(drain_task_queue_callback, std::ptr::null_mut());
    }
    
    resp_rx.await.map_err(|_| ErrorData::internal_error("Failed to receive response from x64dbg"))
}

pub async fn handle_execute_command(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: ExecuteCommandArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    
    match dispatch_dbg_request(DbgRequest::ExecuteCommand(args.command)).await? {
        DbgResponse::CommandSuccess(success) => {
            Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
        },
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_read_memory(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: ReadMemoryArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    
    let addr = parse_hex(&args.address)? as usize;
    match dispatch_dbg_request(DbgRequest::ReadMemory { address: addr, size: args.size }).await? {
        DbgResponse::MemoryData(Some(buffer)) => {
            Ok(CallToolResult::success(vec![Content::text(format!(
                "Address: 0x{:X}\nHex: {}",
                addr,
                buffer.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(" ")
            ))]))
        },
        DbgResponse::MemoryData(None) => Ok(CallToolResult::error(vec![Content::text("Failed to read memory")])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_get_registers(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetRegisters).await? {
        DbgResponse::Registers(Some(json_str)) => Ok(CallToolResult::success(vec![Content::text(json_str)])),
        DbgResponse::Registers(None) => Ok(CallToolResult::error(vec![Content::text("Failed to get registers (Is the debugger stopped?)")])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_set_register(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: SetRegisterArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    
    match dispatch_dbg_request(DbgRequest::SetRegister { register: args.register, value: args.value }).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_get_breakpoints(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetBreakpoints).await? {
        DbgResponse::Breakpoints(json) => Ok(CallToolResult::success(vec![Content::text(json)])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_set_breakpoint(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: SetBreakpointArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    
    match dispatch_dbg_request(DbgRequest::SetBreakpoint(args.address)).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_get_threads(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetThreads).await? {
        DbgResponse::Threads(json) => Ok(CallToolResult::success(vec![Content::text(json)])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_get_modules(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetModules).await? {
        DbgResponse::Modules(json) => Ok(CallToolResult::success(vec![Content::text(json)])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_get_call_stack(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetCallStack).await? {
        DbgResponse::CallStack(json) => Ok(CallToolResult::success(vec![Content::text(json)])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_set_comment(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: SetCommentLabelArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    
    let addr = parse_hex(&args.address)? as usize;
    match dispatch_dbg_request(DbgRequest::SetComment { address: addr, text: args.text }).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_set_label(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: SetCommentLabelArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    
    let addr = parse_hex(&args.address)? as usize;
    match dispatch_dbg_request(DbgRequest::SetLabel { address: addr, text: args.text }).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_debug_run(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::ExecuteCommand("run".to_string())).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_debug_pause(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::ExecuteCommand("pause".to_string())).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_debug_stop(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::ExecuteCommand("StopDebug".to_string())).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_debug_step_in(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::ExecuteCommand("sti".to_string())).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_debug_step_over(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::ExecuteCommand("sto".to_string())).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_debug_step_out(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::ExecuteCommand("rtr".to_string())).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_assemble_mem(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: AssembleMemArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    let cmd = format!("asm {}, \"{}\"", args.address, args.instruction);
    match dispatch_dbg_request(DbgRequest::ExecuteCommand(cmd)).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_pattern_find_mem(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: PatternFindMemArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    let cmd = format!("find {}, \"{}\"", args.start, args.pattern);
    match dispatch_dbg_request(DbgRequest::ExecuteCommand(cmd)).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(format!("Issued find command: {}", success))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_memory_is_valid_ptr(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: MemoryAddressArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    let addr = parse_hex(&args.address)? as usize;
    
    match dispatch_dbg_request(DbgRequest::MemoryIsValidPtr(addr)).await? {
        DbgResponse::Boolean(is_valid) => Ok(CallToolResult::success(vec![Content::text(format!("{}", is_valid))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}

pub async fn handle_misc_parse_expression(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: MiscParseExpressionArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    let cmd = format!("? {}", args.expression);
    match dispatch_dbg_request(DbgRequest::ExecuteCommand(cmd)).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(format!("Issued expression evaluation: {}", success))])),
        _ => Err(ErrorData::internal_error("Unexpected response value"))
    }
}
