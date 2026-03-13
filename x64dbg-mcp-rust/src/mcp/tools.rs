use crate::mcp::types::*;
use crate::x64dbg::api::*;
use rmcp::{model::*, ErrorData};
use serde_json::{json, Value};

use crate::mcp::concurrency::{
    drain_task_queue_callback, DbgRequest, DbgResponse, McpTask, TASK_TX,
};
use tokio::sync::oneshot;

pub fn parse_hex(s: &str) -> Result<usize, ErrorData> {
    usize::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|_| ErrorData::invalid_params(format!("Invalid hex format: {}", s), None))
}

async fn dispatch_dbg_request(request: DbgRequest) -> Result<DbgResponse, ErrorData> {
    let (resp_tx, resp_rx) = oneshot::channel();
    let task = McpTask {
        request,
        responder: resp_tx,
    };

    if TASK_TX.send(task).is_err() {
        return Err(ErrorData::internal_error(
            "Failed to send task to x64dbg MCP queue",
            None,
        ));
    }

    // Wake up x64dbg main thread to process the queue
    unsafe {
        crate::x64dbg::GuiExecuteOnGuiThreadEx(drain_task_queue_callback, std::ptr::null_mut());
    }

    resp_rx
        .await
        .map_err(|_| ErrorData::internal_error("Failed to receive response from x64dbg", None))
}

pub async fn handle_execute_command(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: ExecuteCommandArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

    match dispatch_dbg_request(DbgRequest::ExecuteCommand(args.command)).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Success: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_read_memory(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: ReadMemoryArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

    let addr = parse_hex(&args.address)?;
    match dispatch_dbg_request(DbgRequest::ReadMemory {
        address: addr,
        size: args.size,
    })
    .await?
    {
        DbgResponse::MemoryData(Some(buffer)) => {
            Ok(CallToolResult::success(vec![Content::text(format!(
                "Address: 0x{:X}\nHex: {}",
                addr,
                buffer
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<String>>()
                    .join(" ")
            ))]))
        }
        DbgResponse::MemoryData(None) => Ok(CallToolResult::error(vec![Content::text(
            "Failed to read memory",
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_registers(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetRegisters).await? {
        DbgResponse::Registers(Some(val)) => {
            let json_str = serde_json::to_string_pretty(&val).unwrap_or_default();
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        DbgResponse::Registers(None) => Ok(CallToolResult::error(vec![Content::text(
            "Failed to get registers (Is the debugger stopped?)",
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_set_register(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: SetRegisterArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

    match dispatch_dbg_request(DbgRequest::SetRegister {
        register: args.register,
        value: args.value,
    })
    .await?
    {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Success: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_breakpoints(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetBreakpoints).await? {
        DbgResponse::Breakpoints(v) => {
            let json_str = serde_json::to_string_pretty(&v).unwrap_or_else(|_| "[]".to_string());
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_set_breakpoint(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: SetBreakpointArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

    match dispatch_dbg_request(DbgRequest::SetBreakpoint(args.address)).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Success: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_threads(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetThreads).await? {
        DbgResponse::Threads(v) => {
            let json_str = serde_json::to_string_pretty(&v).unwrap_or_else(|_| "[]".to_string());
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_modules(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetModules).await? {
        DbgResponse::Modules(v) => {
            let json_str = serde_json::to_string_pretty(&v).unwrap_or_else(|_| "[]".to_string());
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_call_stack(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetCallStack).await? {
        DbgResponse::CallStack(v) => {
            let json_str = serde_json::to_string_pretty(&v).unwrap_or_else(|_| "[]".to_string());
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_set_comment(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: SetCommentLabelArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

    let addr = parse_hex(&args.address)?;
    match dispatch_dbg_request(DbgRequest::SetComment {
        address: addr,
        text: args.text,
    })
    .await?
    {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Success: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_set_label(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: SetCommentLabelArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

    let addr = parse_hex(&args.address)?;
    match dispatch_dbg_request(DbgRequest::SetLabel {
        address: addr,
        text: args.text,
    })
    .await?
    {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Success: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_debug_run(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::ExecuteCommand("run".to_string())).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Success: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_debug_pause(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::ExecuteCommand("pause".to_string())).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Success: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_debug_stop(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::ExecuteCommand("StopDebug".to_string())).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Success: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_debug_step_in(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::ExecuteCommand("sti".to_string())).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Success: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_debug_step_over(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::ExecuteCommand("sto".to_string())).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Success: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_debug_step_out(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::ExecuteCommand("rtr".to_string())).await? {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Success: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_assemble_mem(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: AssembleMemArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    match dispatch_dbg_request(DbgRequest::AssembleMem {
        address: args.address,
        instruction: args.instruction,
    })
    .await?
    {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Success: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_pattern_find_mem(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: PatternFindMemArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    match dispatch_dbg_request(DbgRequest::PatternFindMem {
        start: args.start,
        pattern: args.pattern,
    })
    .await?
    {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Issued find command: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_memory_is_valid_ptr(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: MemoryAddressArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    let addr = parse_hex(&args.address)?;

    match dispatch_dbg_request(DbgRequest::MemoryIsValidPtr(addr)).await? {
        DbgResponse::Boolean(is_valid) => Ok(CallToolResult::success(vec![Content::text(
            format!("{}", is_valid),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_misc_parse_expression(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: MiscParseExpressionArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    match dispatch_dbg_request(DbgRequest::MiscParseExpression {
        expression: args.expression,
    })
    .await?
    {
        DbgResponse::CommandSuccess(success) => Ok(CallToolResult::success(vec![Content::text(
            format!("Issued expression evaluation: {}", success),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_yara_scan_mem(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: YaraScanMemArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

    let start_addr = parse_hex(&args.start)?;
    let size = parse_hex(&args.size)?;

    let dbg_req = DbgRequest::ReadMemory {
        address: start_addr,
        size,
    };
    let response = dispatch_dbg_request(dbg_req).await?;

    if let DbgResponse::MemoryData(Some(data)) = response {
        // CPU 집약적인 YARA 스캔을 블로킹 풀로 오프로드
        let rule = args.rule.clone();
        let scan_res = tokio::task::spawn_blocking(move || {
            let mut compiler = boreal::Compiler::new();
            match compiler.add_rules_str(&rule) {
                Ok(_) => {
                    let scanner = compiler.finalize();
                    match scanner.scan_mem(&data) {
                        Ok(scan_result) => {
                            let mut matches = Vec::new();
                            for r in scan_result.rules {
                                for string_match in r.matches {
                                    for m in string_match.matches {
                                        matches.push(format!(
                                            "Rule '{}' matched at offset 0x{:X} within chunk",
                                            r.name, m.offset
                                        ));
                                    }
                                }
                            }
                            if matches.is_empty() {
                                "No YARA rule matches found.".to_string()
                            } else {
                                matches.join("\n")
                            }
                        }
                        Err(err) => format!("YARA scan error: {:?}", err),
                    }
                }
                Err(e) => format!("Rule compilation failed: {:?}", e),
            }
        })
        .await
        .map_err(|e| ErrorData::internal_error(e.to_string(), None))?;

        Ok(CallToolResult::success(vec![Content::text(scan_res)]))
    } else {
        Err(ErrorData::internal_error(
            "Failed to read memory for YARA scan",
            None,
        ))
    }
}

pub async fn handle_analyze_function(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: AnalyzeFunctionArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

    let addr = parse_hex(&args.address)?;

    match dispatch_dbg_request(DbgRequest::AnalyzeFunction(addr)).await? {
        DbgResponse::FunctionAnalysis(Some(result)) => {
            let json_res = serde_json::to_string_pretty(&result).unwrap();
            Ok(CallToolResult::success(vec![Content::text(json_res)]))
        }
        DbgResponse::FunctionAnalysis(None) => Ok(CallToolResult::success(vec![Content::text(
            "Failed to analyze function at the given address.",
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_struct_dump_mem(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: StructDumpMemArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    let addr = parse_hex(&args.address)?;

    // 계산 시 Alignment를 고려한 전체 크기 파악
    let mut total_size = 0;
    for field in &args.fields {
        let align = alignof_type(&field.field_type);
        let padding = (align - (total_size % align)) % align;
        total_size += padding + sizeof_type(&field.field_type);
    }

    let dbg_req = DbgRequest::ReadMemory {
        address: addr,
        size: total_size,
    };
    let response = dispatch_dbg_request(dbg_req).await?;

    if let DbgResponse::MemoryData(Some(data)) = response {
        let mut result_json = serde_json::Map::new();
        let mut curr_offset = 0;

        for field in &args.fields {
            let align = alignof_type(&field.field_type);
            let padding = (align - (curr_offset % align)) % align;
            curr_offset += padding;

            let field_size = sizeof_type(&field.field_type);
            if curr_offset + field_size > data.len() {
                break;
            }

            let slice = &data[curr_offset..curr_offset + field_size];
            let parsed_val = parse_value(slice, &field.field_type);
            result_json.insert(field.name.clone(), parsed_val);

            curr_offset += field_size;
        }

        let json_str =
            serde_json::to_string_pretty(&serde_json::Value::Object(result_json)).unwrap();
        Ok(CallToolResult::success(vec![Content::text(json_str)]))
    } else {
        Ok(CallToolResult::success(vec![Content::text(
            "Failed to read memory for struct logic",
        )]))
    }
}

fn sizeof_type(t: &str) -> usize {
    if t.starts_with("char[") || t.starts_with("u8[") {
        if let Some(val_str) = t.split('[').nth(1).and_then(|s| s.strip_suffix(']')) {
            return val_str.parse().unwrap_or(1);
        }
    }
    match t {
        "u8" | "i8" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" | "f32" => 4,
        "u64" | "i64" | "f64" | "ptr" | "pointer" => 8,
        _ => 4,
    }
}

fn alignof_type(t: &str) -> usize {
    if t.starts_with("char[") || t.starts_with("u8[") {
        return 1;
    }
    match t {
        "u8" | "i8" => 1,
        "u16" | "i16" => 2,
        "u32" | "i32" | "f32" => 4,
        "u64" | "i64" | "f64" | "ptr" | "pointer" => 8,
        _ => 4,
    }
}

fn parse_value(data: &[u8], t: &str) -> serde_json::Value {
    if t.starts_with("char[") {
        let s = String::from_utf8_lossy(data);
        return serde_json::Value::String(s.trim_end_matches('\0').to_string());
    } else if t.starts_with("u8[") {
        let hex: String = data.iter().map(|b| format!("{:02X}", b)).collect();
        return serde_json::Value::String(hex);
    }

    match t {
        "u8" => serde_json::json!(format!("0x{:02X}", data[0])),
        "i8" => serde_json::json!(data[0] as i8),
        "u16" => {
            let mut b = [0u8; 2];
            b.copy_from_slice(&data[0..2]);
            serde_json::json!(format!("0x{:04X}", u16::from_le_bytes(b)))
        }
        "i16" => {
            let mut b = [0u8; 2];
            b.copy_from_slice(&data[0..2]);
            serde_json::json!(i16::from_le_bytes(b))
        }
        "u32" => {
            let mut b = [0u8; 4];
            b.copy_from_slice(&data[0..4]);
            serde_json::json!(format!("0x{:08X}", u32::from_le_bytes(b)))
        }
        "i32" => {
            let mut b = [0u8; 4];
            b.copy_from_slice(&data[0..4]);
            serde_json::json!(i32::from_le_bytes(b))
        }
        "u64" | "ptr" | "pointer" => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[0..8]);
            serde_json::json!(format!("0x{:016X}", u64::from_le_bytes(b)))
        }
        "i64" => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&data[0..8]);
            serde_json::json!(i64::from_le_bytes(b))
        }
        _ => serde_json::Value::Null,
    }
}

pub async fn handle_get_symbols(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: SymbolStringArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

    match dispatch_dbg_request(DbgRequest::GetSymbols(args.module)).await? {
        DbgResponse::Symbols(v) => {
            let json_str = serde_json::to_string(&v).unwrap_or_else(|_| "[]".to_string());
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_strings(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: SymbolStringArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

    match dispatch_dbg_request(DbgRequest::GetStrings(args.module)).await? {
        DbgResponse::Strings(v) => {
            let json_str = serde_json::to_string(&v).unwrap_or_else(|_| "[]".to_string());
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_execute_script(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: ExecuteScriptArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;

    match dispatch_dbg_request(DbgRequest::ExecuteScript(args.script)).await? {
        DbgResponse::ScriptResult(Ok(res)) => Ok(CallToolResult::success(vec![Content::text(
            format!("Script returned: {}", res),
        )])),
        DbgResponse::ScriptResult(Err(e)) => Ok(CallToolResult::error(vec![Content::text(
            format!("Script failed: {}", e),
        )])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_xrefs(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: MemoryAddressArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    let addr = parse_hex(&args.address)?;

    match dispatch_dbg_request(DbgRequest::GetXrefs(addr)).await? {
        DbgResponse::GenericList(v) => {
            let json_str = serde_json::to_string_pretty(&v).unwrap_or_default();
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_memory_map_full(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetMemoryMapFull).await? {
        DbgResponse::GenericList(v) => {
            let json_str = serde_json::to_string_pretty(&v).unwrap_or_default();
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_disassemble_range(
    request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    let args: ReadMemoryArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    let addr = parse_hex(&args.address)?;

    match dispatch_dbg_request(DbgRequest::DisassembleRange {
        address: addr,
        count: args.size,
    })
    .await?
    {
        DbgResponse::GenericList(v) => {
            let json_str = serde_json::to_string_pretty(&v).unwrap_or_else(|_| "[]".to_string());
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_bookmark(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: BookmarkArgs =
        serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
            .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    let addr = parse_hex(&args.address)?;

    match dispatch_dbg_request(DbgRequest::Bookmark {
        address: addr,
        is_set: args.is_bookmark,
    })
    .await?
    {
        DbgResponse::Boolean(success) => Ok(CallToolResult::success(vec![Content::text(format!(
            "Bookmark toggled: {}",
            success
        ))])),
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_peb_teb(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetPebTeb).await? {
        DbgResponse::GenericValue(v) => {
            let json_str = serde_json::to_string_pretty(&v).unwrap_or_default();
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_tcp_connections(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetTcpConnections).await? {
        DbgResponse::GenericList(v) => {
            let json_str = serde_json::to_string_pretty(&v).unwrap_or_default();
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_handles(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetHandles).await? {
        DbgResponse::GenericList(v) => {
            let json_str = serde_json::to_string_pretty(&v).unwrap_or_default();
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_patches(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetPatches).await? {
        DbgResponse::GenericList(v) => {
            let json_str = serde_json::to_string_pretty(&v).unwrap_or_default();
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_heaps(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetHeaps).await? {
        DbgResponse::GenericList(v) => {
            let json_str = serde_json::to_string_pretty(&v).unwrap_or_default();
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}

pub async fn handle_get_windows(
    _request: CallToolRequestParams,
) -> Result<CallToolResult, ErrorData> {
    match dispatch_dbg_request(DbgRequest::GetWindows).await? {
        DbgResponse::GenericList(v) => {
            let json_str = serde_json::to_string_pretty(&v).unwrap_or_default();
            Ok(CallToolResult::success(vec![Content::text(json_str)]))
        }
        _ => Err(ErrorData::internal_error("Unexpected response value", None)),
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_hex() {
        assert_eq!(parse_hex("0x123").unwrap(), 0x123);
        assert_eq!(parse_hex("ABC").unwrap(), 0xABC);
        assert!(parse_hex("invalid").is_err());
    }

    #[test]
    fn test_sizeof_type() {
        assert_eq!(sizeof_type("u8"), 1);
        assert_eq!(sizeof_type("u32"), 4);
        assert_eq!(sizeof_type("u64"), 8);
        assert_eq!(sizeof_type("char[16]"), 16);
        assert_eq!(sizeof_type("ptr"), 8);
    }

    #[test]
    fn test_alignof_type() {
        assert_eq!(alignof_type("u8"), 1);
        assert_eq!(alignof_type("u16"), 2);
        assert_eq!(alignof_type("u32"), 4);
        assert_eq!(alignof_type("u64"), 8);
        assert_eq!(alignof_type("char[16]"), 1);
    }

    #[test]
    fn test_parse_value() {
        let data = vec![0x39, 0x05, 0x00, 0x00];
        let val = parse_value(&data, "u32");
        assert_eq!(val, serde_json::json!("0x00000539"));

        let data = vec![b'H', b'e', b'l', b'l', b'o', 0x00];
        let val = parse_value(&data, "char[6]");
        assert_eq!(val, serde_json::json!("Hello"));
    }
}
