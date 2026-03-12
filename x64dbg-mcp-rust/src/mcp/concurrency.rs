use crossbeam_channel::{unbounded, Receiver, Sender};
use once_cell::sync::Lazy;
use std::os::raw::c_void;
use tokio::sync::oneshot;

use crate::x64dbg::api::*;
use crate::mcp::types::*;

pub enum DbgRequest {
    ExecuteCommand(String),
    ReadMemory { address: usize, size: usize },
    GetRegisters,
    SetRegister { register: String, value: String },
    GetBreakpoints,
    SetBreakpoint(String), // address hex
    GetThreads,
    GetModules,
    GetCallStack,
    SetComment { address: usize, text: String },
    SetLabel { address: usize, text: String },
    MemoryIsValidPtr(usize),
}

pub enum DbgResponse {
    CommandSuccess(bool),
    MemoryData(Option<Vec<u8>>),
    Registers(Option<String>),
    Breakpoints(String),
    Threads(String),
    Modules(String),
    CallStack(String),
    Boolean(bool),
}

pub struct McpTask {
    pub request: DbgRequest,
    pub responder: oneshot::Sender<DbgResponse>,
}

pub static TASK_TX: Lazy<Sender<McpTask>> = Lazy::new(|| {
    let (tx, rx) = unbounded();
    unsafe {
        GLOBAL_RX = Some(rx);
    }
    tx
});

static mut GLOBAL_RX: Option<Receiver<McpTask>> = None;

// Callback executed by x64dbg GUI Thread
pub extern "C" fn drain_task_queue_callback(_userdata: *mut c_void) {
    let rx = unsafe { GLOBAL_RX.as_ref().unwrap() };

    while let Ok(task) = rx.try_recv() {
        let response = match task.request {
            DbgRequest::ExecuteCommand(cmd) => {
                let result = execute_command_api(&cmd);
                DbgResponse::CommandSuccess(result)
            }
            DbgRequest::ReadMemory { address, size } => {
                let data = read_memory_api(address, size);
                DbgResponse::MemoryData(data)
            }
            DbgRequest::GetRegisters => {
                let reg_str = if let Some(reg_dump) = get_registers_api() {
                    let regs = &reg_dump.regcontext;
                    let mut reg_map = serde_json::Map::new();

                    reg_map.insert("rax".into(), serde_json::json!(format!("0x{:X}", regs.cax)));
                    reg_map.insert("rbx".into(), serde_json::json!(format!("0x{:X}", regs.cbx)));
                    reg_map.insert("rcx".into(), serde_json::json!(format!("0x{:X}", regs.ccx)));
                    reg_map.insert("rdx".into(), serde_json::json!(format!("0x{:X}", regs.cdx)));
                    reg_map.insert("rsi".into(), serde_json::json!(format!("0x{:X}", regs.csi)));
                    reg_map.insert("rdi".into(), serde_json::json!(format!("0x{:X}", regs.cdi)));
                    reg_map.insert("rbp".into(), serde_json::json!(format!("0x{:X}", regs.cbp)));
                    reg_map.insert("rsp".into(), serde_json::json!(format!("0x{:X}", regs.csp)));
                    reg_map.insert("rip".into(), serde_json::json!(format!("0x{:X}", regs.cip)));
                    reg_map.insert("eflags".into(), serde_json::json!(format!("0x{:X}", regs.eflags)));

                    #[cfg(target_pointer_width = "64")]
                    {
                        reg_map.insert("r8".into(), serde_json::json!(format!("0x{:X}", regs.r8)));
                        reg_map.insert("r9".into(), serde_json::json!(format!("0x{:X}", regs.r9)));
                        reg_map.insert("r10".into(), serde_json::json!(format!("0x{:X}", regs.r10)));
                        reg_map.insert("r11".into(), serde_json::json!(format!("0x{:X}", regs.r11)));
                        reg_map.insert("r12".into(), serde_json::json!(format!("0x{:X}", regs.r12)));
                        reg_map.insert("r13".into(), serde_json::json!(format!("0x{:X}", regs.r13)));
                        reg_map.insert("r14".into(), serde_json::json!(format!("0x{:X}", regs.r14)));
                        reg_map.insert("r15".into(), serde_json::json!(format!("0x{:X}", regs.r15)));
                    }
                    Some(serde_json::to_string_pretty(&serde_json::Value::Object(reg_map)).unwrap())
                } else {
                    None
                };
                DbgResponse::Registers(reg_str)
            }
            DbgRequest::SetRegister { register, value } => {
                let cmd = format!("{}={}", register, value);
                let result = execute_command_api(&cmd);
                DbgResponse::CommandSuccess(result)
            }
            DbgRequest::GetBreakpoints => {
                let bplist = get_breakpoints_api();
                DbgResponse::Breakpoints(serde_json::to_string_pretty(&bplist).unwrap())
            }
            DbgRequest::SetBreakpoint(addr) => {
                let cmd = format!("bp {}", addr);
                let result = execute_command_api(&cmd);
                DbgResponse::CommandSuccess(result)
            }
            DbgRequest::GetThreads => {
                let tlist = get_threads_api();
                DbgResponse::Threads(serde_json::to_string_pretty(&tlist).unwrap())
            }
            DbgRequest::GetModules => {
                let mlist = get_modules_api();
                DbgResponse::Modules(serde_json::to_string_pretty(&mlist).unwrap())
            }
            DbgRequest::GetCallStack => {
                let cslist = get_call_stack_api();
                DbgResponse::CallStack(serde_json::to_string_pretty(&cslist).unwrap())
            }
            DbgRequest::SetComment { address, text } => {
                let result = set_comment_at_api(address, &text);
                DbgResponse::CommandSuccess(result)
            }
            DbgRequest::SetLabel { address, text } => {
                let result = set_label_at_api(address, &text);
                DbgResponse::CommandSuccess(result)
            }
            DbgRequest::MemoryIsValidPtr(address) => {
                let is_valid = read_memory_api(address, 1).is_some();
                DbgResponse::Boolean(is_valid)
            }
        };

        let _ = task.responder.send(response);
    }
}
