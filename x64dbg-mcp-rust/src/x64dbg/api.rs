use super::*;
use std::ffi::{CStr, CString};
use std::os::raw::c_void;
use std::collections::HashSet;

pub const MEM_IMAGE_VAL: u32 = 0x1000000;

pub fn log_print(msg: &str) {
    if let Ok(msg_c) = CString::new(msg) {
        unsafe {
            _plugin_logputs(msg_c.as_ptr());
        }
    }
}

pub fn execute_command_api(cmd: &str) -> bool {
    if let Ok(cmd_c) = CString::new(cmd) {
        unsafe { DbgCmdExecDirect(cmd_c.as_ptr()) }
    } else {
        false
    }
}

pub fn read_memory_api(addr: duint, size: usize) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; size];
    let success = unsafe {
        DbgMemRead(addr, buffer.as_mut_ptr() as *mut c_void, size as duint)
    };
    if success {
        Some(buffer)
    } else {
        None
    }
}

pub fn get_registers_api() -> Option<REGDUMP_AVX512> {
    let mut reg_dump = unsafe { std::mem::zeroed::<REGDUMP_AVX512>() };
    let success = unsafe { DbgGetRegDumpEx(&mut reg_dump, std::mem::size_of::<REGDUMP_AVX512>()) };
    if success {
        Some(reg_dump)
    } else {
        None
    }
}

// RAII 래퍼: 스코프 종료 시 자동으로 BridgeFree 호출
struct BridgeMemoryGuard(*mut c_void);
impl Drop for BridgeMemoryGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { BridgeFree(self.0) };
        }
    }
}

// Helper to access DbgFunctions safely
fn dbg_functions() -> &'static DBGFUNCTIONS {
    unsafe { &*DbgFunctions() }
}

pub fn get_breakpoints_api() -> Vec<serde_json::Value> { // Changed to serde_json::Value to match original return type
    let mut bplist = unsafe { std::mem::zeroed::<BPMAP>() };
    let count = unsafe { DbgGetBplist(BPXTYPE::bp_none, &mut bplist) }; // Changed to DbgGetBplist and BPXTYPE::bp_none as per instruction
    let mut breakpoints = Vec::new();

    if count > 0 && !bplist.list.is_null() {
        let _guard = BridgeMemoryGuard(bplist.list as *mut c_void);
        let entries = unsafe { std::slice::from_raw_parts(bplist.list, count as usize) };
        for entry in entries {
            breakpoints.push(serde_json::json!({ // Changed to serde_json::json! to match original return type
                "address": format!("0x{:X}", entry.addr),
                "enabled": entry.enabled,
                "type_name": format!("{:?}", entry.type_), // Added type_name as per instruction
            }));
        }
    }
    breakpoints
}

pub fn get_threads_api() -> Vec<serde_json::Value> { // Changed to serde_json::Value to match original return type
    let mut tlist = unsafe { std::mem::zeroed::<THREADLIST>() };
    unsafe { DbgGetThreadList(&mut tlist) };
    let mut threads = Vec::new();

    if tlist.count > 0 && !tlist.list.is_null() {
        let _guard = BridgeMemoryGuard(tlist.list as *mut c_void);
        let entries = unsafe { std::slice::from_raw_parts(tlist.list, tlist.count as usize) };
        for entry in entries {
            threads.push(serde_json::json!({ // Changed to serde_json::json! to match original return type
                "handle": format!("0x{:X}", entry.Handle as usize),
                "id": entry.ThreadId,
                "cip": format!("0x{:X}", entry.ThreadCip),
                "wait_reason": entry.WaitReason,
            }));
        }
    }
    threads
}

pub fn get_modules_api() -> Vec<serde_json::Value> { // Changed to serde_json::Value to match original return type
    let mut mmap = unsafe { std::mem::zeroed::<MEMMAP>() };
    if unsafe { DbgMemMap(&mut mmap) } {
        let mut modules = Vec::new();
        if mmap.count > 0 && !mmap.page.is_null() {
            let _guard = BridgeMemoryGuard(mmap.page as *mut c_void);
            let pages = unsafe { std::slice::from_raw_parts(mmap.page, mmap.count as usize) };
            for page in pages {
                let info = unsafe { CStr::from_ptr(page.info.as_ptr()).to_string_lossy().into_owned() };
                if !info.is_empty() {
                    modules.push(serde_json::json!({ // Changed to serde_json::json! to match original return type
                        "base": format!("0x{:X}", page.mbi.BaseAddress as usize),
                        "size": format!("0x{:X}", page.mbi.RegionSize as usize),
                        "name": info,
                    }));
                }
            }
        }
        modules
    } else {
        Vec::new()
    }
}

pub fn get_call_stack_api() -> Vec<serde_json::Value> { // Changed to serde_json::Value to match original return type
    let mut cs = unsafe { std::mem::zeroed::<DBGCALLSTACK>() };
    unsafe { dbg_functions().GetCallStack.unwrap()(&mut cs) };
    let mut entries = Vec::new();

    if cs.total > 0 && !cs.entries.is_null() {
        let _guard = BridgeMemoryGuard(cs.entries as *mut c_void);
        let stack_entries = unsafe { std::slice::from_raw_parts(cs.entries, cs.total as usize) };
        for entry in stack_entries {
            entries.push(serde_json::json!({ // Changed to serde_json::json! to match original return type
                "address": format!("0x{:X}", entry.addr),
                "from": format!("0x{:X}", entry.from),
                "to": format!("0x{:X}", entry.to),
                "comment": unsafe { CStr::from_ptr(entry.comment.as_ptr()).to_string_lossy().into_owned() },
            }));
        }
    }
    entries
}

pub fn set_comment_at_api(addr: duint, text: &str) -> bool {
    if let Ok(text_c) = CString::new(text) {
        unsafe { DbgSetCommentAt(addr, text_c.as_ptr()) }
    } else {
        false
    }
}

pub fn set_label_at_api(addr: duint, text: &str) -> bool {
    if let Ok(text_c) = CString::new(text) {
        unsafe { DbgSetLabelAt(addr, text_c.as_ptr()) }
    } else {
        false
    }
}

pub fn get_symbols_api(module_name: &str) -> Vec<serde_json::Value> {
    let base = if module_name == "*" {
        0
    } else {
        let mod_c = CString::new(module_name).unwrap();
        unsafe { DbgModBaseFromName(mod_c.as_ptr()) }
    };

    if base == 0 && module_name != "*" {
        return Vec::new();
    }

    let mut symbols = Vec::new();

    extern "C" fn cb_symbol_enum(symbol: *const SYMBOLPTR, user: *mut c_void) -> bool {
        let symbols = unsafe { &mut *(user as *mut Vec<serde_json::Value>) };
        let mut info = unsafe { std::mem::zeroed::<SYMBOLINFO>() };
        unsafe { DbgGetSymbolInfo(symbol, &mut info) };

        let decorated = if info.decoratedSymbol.is_null() {
            String::new()
        } else {
            unsafe { CStr::from_ptr(info.decoratedSymbol).to_string_lossy().into_owned() }
        };

        symbols.push(serde_json::json!({
            "address": format!("0x{:X}", info.addr),
            "name": decorated,
            "type": info.type_,
            "ordinal": info.ordinal
        }));

        if info.freeDecorated {
            unsafe { BridgeFree(info.decoratedSymbol as *mut c_void) };
        }
        if info.freeUndecorated {
            unsafe { BridgeFree(info.undecoratedSymbol as *mut c_void) };
        }

        true
    }

    unsafe {
        DbgSymbolEnum(base, Some(cb_symbol_enum), &mut symbols as *mut _ as *mut c_void);
    }

    symbols
}

pub fn get_strings_api(module_name: &str) -> Vec<serde_json::Value> {
    let base = if module_name == "*" {
        let regs = get_registers_api();
        if let Some(r) = regs {
            unsafe { dbg_functions().ModBaseFromAddr.unwrap()(r.regcontext.cip) }
        } else {
            0
        }
    } else {
        let mod_c = CString::new(module_name).unwrap();
        unsafe { DbgModBaseFromName(mod_c.as_ptr()) }
    };

    if base == 0 {
        return Vec::new();
    }

    // Get module size
    let size = unsafe { dbg_functions().ModSizeFromAddr.unwrap()(base) };
    if size == 0 { return Vec::new(); }

    let mut strings = Vec::new();
    let chunk_size = 0x10000; // 64KB chunks
    
    // Performance optimization: Read module in chunks and scan in Rust
    for current_addr in (base..base + size).step_by(chunk_size as usize) { // Cast chunk_size to usize
        let read_len = std::cmp::min(chunk_size, (base + size) - current_addr) as usize; // Cast to usize
        if let Some(buffer) = read_memory_api(current_addr, read_len) {
            let mut start = 0;
            while start < buffer.len() {
                // Look for start of a string (printable characters)
                if buffer[start] >= 0x20 && buffer[start] <= 0x7E {
                    let mut end = start + 1;
                    while end < buffer.len() && buffer[end] >= 0x20 && buffer[end] <= 0x7E {
                        end += 1;
                    }
                    
                    // Found a printable sequence, check length
                    if end - start >= 4 {
                        if let Ok(content) = std::str::from_utf8(&buffer[start..end]) {
                            strings.push(serde_json::json!({
                                "address": format!("0x{:X}", current_addr + start as duint), // Cast start to duint
                                "content": content.to_string()
                            }));
                        }
                    }
                    start = end;
                } else {
                    start += 1;
                }
                
                if strings.len() >= 1000 { break; }
            }
        }
        if strings.len() >= 1000 { break; }
    }

    strings
}
