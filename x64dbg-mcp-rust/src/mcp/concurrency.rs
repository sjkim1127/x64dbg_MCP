use crossbeam_channel::{unbounded, Receiver, Sender};
use once_cell::sync::Lazy;
use std::os::raw::c_void;
use tokio::sync::oneshot;
use rhai::{Engine, Dynamic, Array, Map};
use std::sync::OnceLock;

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
    AnalyzeFunction(usize),
    GetSymbols(String), // module name
    GetStrings(String), // module name
    ExecuteScript(String), // Rhai script content
    GetXrefs(usize),
    GetMemoryMapFull,
    DisassembleRange { address: usize, count: usize },
    Bookmark { address: usize, is_set: bool },
    GetPebTeb,
    GetTcpConnections,
    GetHandles,
    GetPatches,
    GetHeaps,
    GetWindows,
}

pub enum DbgResponse {
    CommandSuccess(bool),
    MemoryData(Option<Vec<u8>>),
    Registers(Option<serde_json::Value>),
    Breakpoints(Vec<serde_json::Value>),
    Threads(Vec<serde_json::Value>),
    Modules(Vec<serde_json::Value>),
    CallStack(Vec<serde_json::Value>),
    Boolean(bool),
    FunctionAnalysis(Option<AnalyzeFunctionResult>),
    ScriptResult(Result<String, String>),
    Symbols(Vec<serde_json::Value>),
    Strings(Vec<serde_json::Value>),
    GenericList(Vec<serde_json::Value>),
    GenericValue(serde_json::Value),
}

pub struct McpTask {
    pub request: DbgRequest,
    pub responder: oneshot::Sender<DbgResponse>,
}

pub static TASK_TX: Lazy<Sender<McpTask>> = Lazy::new(|| {
    let (tx, rx) = unbounded();
    GLOBAL_RX.set(rx).expect("GLOBAL_RX already initialized");
    tx
});

static GLOBAL_RX: OnceLock<Receiver<McpTask>> = OnceLock::new();

// Callback executed by x64dbg GUI Thread
pub extern "C" fn drain_task_queue_callback(_userdata: *mut c_void) {
    let rx = if let Some(rx) = GLOBAL_RX.get() {
        rx
    } else {
        return;
    };

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
                let reg_val = if let Some(reg_dump) = get_registers_api() {
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
                    Some(serde_json::Value::Object(reg_map))
                } else {
                    None
                };
                DbgResponse::Registers(reg_val)
            }
            DbgRequest::SetRegister { register, value } => {
                let cmd = format!("{}={}", register, value);
                let result = execute_command_api(&cmd);
                DbgResponse::CommandSuccess(result)
            }
            DbgRequest::GetBreakpoints => {
                DbgResponse::Breakpoints(get_breakpoints_api())
            }
            DbgRequest::SetBreakpoint(addr) => {
                let cmd = format!("bp {}", addr);
                let result = execute_command_api(&cmd);
                DbgResponse::CommandSuccess(result)
            }
            DbgRequest::GetThreads => {
                DbgResponse::Threads(get_threads_api())
            }
            DbgRequest::GetModules => {
                DbgResponse::Modules(get_modules_api())
            }
            DbgRequest::GetCallStack => {
                DbgResponse::CallStack(get_call_stack_api())
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
            DbgRequest::AnalyzeFunction(entry) => {
                let mut f_start: duint = 0;
                let mut f_end: duint = 0;
                let boundary_success = unsafe { DbgFunctionGet(entry as duint, &mut f_start, &mut f_end) };

                let mut graph = unsafe { std::mem::zeroed::<BridgeCFGraphList>() };
                let success = unsafe { DbgAnalyzeFunction(entry as duint, &mut graph) };
                
                if success {
                    let mut nodes = Vec::new();
                    let node_ptr = graph.nodes.data as *const BridgeCFNodeList;
                    let node_count = graph.nodes.count as usize;
                    
                    let mut xrefs = Vec::new();
                    for i in 0..node_count {
                        let node = unsafe { &*node_ptr.add(i) };
                        
                        let mut instructions = Vec::new();
                        let instr_ptr = node.instrs.data as *const BridgeCFInstruction;
                        let instr_count = node.instrs.count as usize;
                        for j in 0..instr_count {
                            let instr = unsafe { &*instr_ptr.add(j) };
                            
                            // Try to get string reference at this instruction
                            use std::ffi::CStr;
                            let mut string_buf = vec![0i8; 512];
                            if unsafe { DbgGetStringAt(instr.addr, string_buf.as_mut_ptr()) } {
                                let string_val = unsafe { CStr::from_ptr(string_buf.as_ptr()).to_string_lossy().into_owned() };
                                if !string_val.is_empty() {
                                    xrefs.push(XRefInfo {
                                        address: format!("0x{:X}", instr.addr),
                                        from: format!("0x{:X}", instr.addr),
                                        type_name: format!("STRING: {}", string_val),
                                    });
                                }
                            }

                            instructions.push(CFGInstruction {
                                address: format!("0x{:X}", instr.addr),
                                bytes: instr.data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<String>>().join(""),
                            });
                        }
                        
                        let mut exits = Vec::new();
                        let exit_ptr = node.exits.data as *const duint;
                        let exit_count = node.exits.count as usize;
                        for k in 0..exit_count {
                            let exit_addr = unsafe { *exit_ptr.add(k) };
                            exits.push(format!("0x{:X}", exit_addr));
                        }
                        
                        nodes.push(CFGNode {
                            start: format!("0x{:X}", node.start),
                            end: format!("0x{:X}", node.end),
                            brtrue: format!("0x{:X}", node.brtrue),
                            brfalse: format!("0x{:X}", node.brfalse),
                            instruction_count: node.icount,
                            is_terminal: node.terminal,
                            is_split: node.split,
                            has_indirect_call: node.indirectcall,
                            instructions,
                            exits,
                        });
                    }
                    
                    // Cleanup
                    for i in 0..node_count {
                        let node = unsafe { &*node_ptr.add(i) };
                        unsafe {
                            if !node.exits.data.is_null() { BridgeFree(node.exits.data); }
                            if !node.instrs.data.is_null() { BridgeFree(node.instrs.data); }
                        }
                    }
                    unsafe {
                        if !graph.nodes.data.is_null() { BridgeFree(graph.nodes.data); }
                    }

                    DbgResponse::FunctionAnalysis(Some(AnalyzeFunctionResult {
                        start: format!("0x{:X}", if boundary_success { f_start } else { entry as duint }),
                        end: format!("0x{:X}", if boundary_success { f_end } else { 0 }),
                        entry_point: format!("0x{:X}", graph.entryPoint),
                        nodes,
                        xrefs,
                    }))
                } else {
                    DbgResponse::FunctionAnalysis(None)
                }
            }
            DbgRequest::GetSymbols(module) => {
                DbgResponse::Symbols(get_symbols_api(&module))
            }
            DbgRequest::GetStrings(module) => {
                DbgResponse::Strings(get_strings_api(&module))
            }
            DbgRequest::ExecuteScript(script) => {
                // Use the globally cached engine
                match RHAI_ENGINE.eval::<Dynamic>(&script) {
                    Ok(result) => {
                        let result_str = format!("{:?}", result);
                        DbgResponse::ScriptResult(Ok(result_str))
                    },
                    Err(e) => DbgResponse::ScriptResult(Err(e.to_string())),
                }
            }
            DbgRequest::GetXrefs(addr) => {
                DbgResponse::GenericList(get_xrefs_api(addr as duint))
            }
            DbgRequest::GetMemoryMapFull => {
                DbgResponse::GenericList(get_memory_map_full_api())
            }
            DbgRequest::DisassembleRange { address, count } => {
                DbgResponse::GenericList(disassemble_range_api(address as duint, count))
            }
            DbgRequest::Bookmark { address, is_set } => {
                DbgResponse::Boolean(bookmark_api(address as duint, is_set))
            }
            DbgRequest::GetPebTeb => {
                DbgResponse::GenericValue(get_peb_teb_api())
            }
            DbgRequest::GetTcpConnections => {
                DbgResponse::GenericList(get_tcp_connections_api())
            }
            DbgRequest::GetHandles => {
                DbgResponse::GenericList(get_handles_api())
            }
            DbgRequest::GetPatches => {
                DbgResponse::GenericList(get_patches_api())
            }
            DbgRequest::GetHeaps => {
                DbgResponse::GenericList(get_heaps_api())
            }
            DbgRequest::GetWindows => {
                DbgResponse::GenericList(get_windows_api())
            }
        };

        let _ = task.responder.send(response);
    }
}

// Global Rhai engine pre-initialized with all functions
static RHAI_ENGINE: Lazy<Engine> = Lazy::new(|| {
    let mut engine = Engine::new();
    
    // Safety: Limit the number of operations to prevent GUI freezing
    engine.set_max_operations(100_000);
    engine.register_fn("execute_command", |cmd: &str| -> bool {
        execute_command_api(cmd)
    });
    engine.register_fn("log_print", |msg: &str| {
        log_print(msg);
    });
    engine.register_fn("read_memory", |addr: i64, size: i64| -> Array {
        if let Some(data) = read_memory_api(addr as duint, size as usize) {
            data.into_iter().map(|b| (b as i64).into()).collect()
        } else {
            Array::new()
        }
    });
    engine.register_fn("get_registers", || -> Map {
        if let Some(reg_dump) = get_registers_api() {
            let mut map = Map::new();
            let regs = &reg_dump.regcontext;
            map.insert("rax".into(), (regs.cax as i64).into());
            map.insert("rbx".into(), (regs.cbx as i64).into());
            map.insert("rcx".into(), (regs.ccx as i64).into());
            map.insert("rdx".into(), (regs.cdx as i64).into());
            map.insert("rsi".into(), (regs.csi as i64).into());
            map.insert("rdi".into(), (regs.cdi as i64).into());
            map.insert("rbp".into(), (regs.cbp as i64).into());
            map.insert("rsp".into(), (regs.csp as i64).into());
            map.insert("rip".into(), (regs.cip as i64).into());
            map
        } else {
            Map::new()
        }
    });

    engine.register_fn("get_breakpoints", || -> Array {
        let v = serde_json::to_value(get_breakpoints_api()).unwrap_or(serde_json::Value::Array(vec![]));
        if let Dynamic::Array(a) = json_to_rhai(v) { a } else { Array::new() }
    });
    engine.register_fn("get_modules", || -> Array {
        let v = serde_json::to_value(get_modules_api()).unwrap_or(serde_json::Value::Array(vec![]));
        if let Dynamic::Array(a) = json_to_rhai(v) { a } else { Array::new() }
    });
    engine.register_fn("get_threads", || -> Array {
        let v = serde_json::to_value(get_threads_api()).unwrap_or(serde_json::Value::Array(vec![]));
        if let Dynamic::Array(a) = json_to_rhai(v) { a } else { Array::new() }
    });
    engine.register_fn("get_call_stack", || -> Array {
        let v = serde_json::to_value(get_call_stack_api()).unwrap_or(serde_json::Value::Array(vec![]));
        if let Dynamic::Array(a) = json_to_rhai(v) { a } else { Array::new() }
    });
    engine.register_fn("get_symbols", |module: &str| -> Array {
        let v = serde_json::to_value(get_symbols_api(module)).unwrap_or(serde_json::Value::Array(vec![]));
        if let Dynamic::Array(a) = json_to_rhai(v) { a } else { Array::new() }
    });
    engine.register_fn("get_strings", |module: &str| -> Array {
        let v = serde_json::to_value(get_strings_api(module)).unwrap_or(serde_json::Value::Array(vec![]));
        if let Dynamic::Array(a) = json_to_rhai(v) { a } else { Array::new() }
    });

    engine
});

// Helper to convert serde_json to Rhai Dynamic
fn json_to_rhai(v: serde_json::Value) -> Dynamic {
    match v {
        serde_json::Value::Null => Dynamic::UNIT,
        serde_json::Value::Bool(b) => b.into(),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() { i.into() }
            else if let Some(f) = n.as_f64() { f.into() }
            else { Dynamic::UNIT }
        },
        serde_json::Value::String(s) => s.into(),
        serde_json::Value::Array(a) => {
            let arr: Array = a.into_iter().map(json_to_rhai).collect();
            arr.into()
        },
        serde_json::Value::Object(o) => {
            let mut map = Map::new();
            for (k, v) in o {
                map.insert(k.into(), json_to_rhai(v));
            }
            map.into()
        }
    }
}
