use crate::mcp::types::*;
use crate::x64dbg::api::*;
use rmcp::{model::*, ErrorData};
use serde_json::{json, Value};

pub fn parse_hex(s: &str) -> Result<crate::x64dbg::duint, ErrorData> {
    crate::x64dbg::duint::from_str_radix(s.trim_start_matches("0x"), 16)
        .map_err(|_| ErrorData::invalid_params(format!("Invalid hex format: {}", s), None))
}

pub fn handle_execute_command(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: ExecuteCommandArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    
    let success = execute_command_api(&args.command);
    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
}

pub fn handle_read_memory(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: ReadMemoryArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    
    let addr = parse_hex(&args.address)?;
    if let Some(buffer) = read_memory_api(addr, args.size) {
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Address: 0x{:X}\nHex: {}",
            addr,
            buffer.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(" ")
        ))]))
    } else {
        Ok(CallToolResult::error(vec![Content::text("Failed to read memory")]))
    }
}

pub fn handle_get_registers(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    if let Some(reg_dump) = get_registers_api() {
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

pub fn handle_set_register(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: SetRegisterArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    
    let cmd = format!("{}={}", args.register, args.value);
    let success = execute_command_api(&cmd);
    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
}

pub fn handle_get_breakpoints(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let bplist = get_breakpoints_api();
    Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&bplist).unwrap())]))
}

pub fn handle_set_breakpoint(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: SetBreakpointArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    
    let cmd = format!("bp {}", args.address);
    let success = execute_command_api(&cmd);
    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
}

pub fn handle_get_threads(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let tlist = get_threads_api();
    Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&tlist).unwrap())]))
}

pub fn handle_get_modules(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let mlist = get_modules_api();
    Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&mlist).unwrap())]))
}

pub fn handle_get_call_stack(_request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let cs_list = get_call_stack_api();
    Ok(CallToolResult::success(vec![Content::text(serde_json::to_string_pretty(&cs_list).unwrap())]))
}

pub fn handle_set_comment(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: SetCommentLabelArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    
    let addr = parse_hex(&args.address)?;
    let success = set_comment_at_api(addr, &args.text);
    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
}

pub fn handle_set_label(request: CallToolRequestParams) -> Result<CallToolResult, ErrorData> {
    let args: SetCommentLabelArgs = serde_json::from_value(Value::Object(request.arguments.unwrap_or_default()))
        .map_err(|e| ErrorData::invalid_params(e.to_string(), None))?;
    
    let addr = parse_hex(&args.address)?;
    let success = set_label_at_api(addr, &args.text);
    Ok(CallToolResult::success(vec![Content::text(format!("Success: {}", success))]))
}
