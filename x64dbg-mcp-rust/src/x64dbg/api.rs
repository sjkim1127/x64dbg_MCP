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

pub fn get_breakpoints_api() -> Vec<serde_json::Value> {
    let mut bp_map = unsafe { std::mem::zeroed::<BPMAP>() };
    let count = unsafe { DbgGetBpList(BPXTYPE_bp_normal, &mut bp_map) };
    
    let mut bplist = Vec::new();
    if count > 0 && !bp_map.bp.is_null() {
        for i in 0..count {
            let bp = unsafe { *bp_map.bp.add(i as usize) };
            bplist.push(serde_json::json!({
                "address": format!("0x{:X}", bp.addr),
                "enabled": bp.enabled,
                "name": if bp.name.as_ptr().is_null() { String::new() } else { unsafe { CStr::from_ptr(bp.name.as_ptr()).to_string_lossy().into_owned() } },
                "hit_count": bp.hitCount
            }));
        }
        unsafe { BridgeFree(bp_map.bp as *mut c_void) };
    }
    bplist
}

pub fn get_threads_api() -> Vec<serde_json::Value> {
    let mut thread_list = unsafe { std::mem::zeroed::<THREADLIST>() };
    unsafe { DbgGetThreadList(&mut thread_list) };
    
    let mut tlist = Vec::new();
    if thread_list.count > 0 && !thread_list.list.is_null() {
        for i in 0..thread_list.count {
            let t = unsafe { *thread_list.list.add(i as usize) };
            tlist.push(serde_json::json!({
                "id": t.BasicInfo.ThreadId,
                "address": format!("0x{:X}", t.BasicInfo.ThreadStartAddress),
                "name": if t.BasicInfo.threadName.as_ptr().is_null() { String::new() } else { unsafe { CStr::from_ptr(t.BasicInfo.threadName.as_ptr()).to_string_lossy().into_owned() } }
            }));
        }
        unsafe { BridgeFree(thread_list.list as *mut c_void) };
    }
    tlist
}

pub fn get_modules_api() -> Vec<serde_json::Value> {
    let mut mem_map = unsafe { std::mem::zeroed::<MEMMAP>() };
    let success = unsafe { DbgMemMap(&mut mem_map) };
    
    let mut mlist = Vec::new();
    let mut seen_bases = HashSet::new();
    
    if success && mem_map.count > 0 && !mem_map.page.is_null() {
        for i in 0..mem_map.count {
            let page = unsafe { *mem_map.page.add(i as usize) };
            let base = page.mbi.AllocationBase as usize;
            if page.mbi.Type == MEM_IMAGE_VAL && !seen_bases.contains(&base) {
                let name = if page.info.as_ptr().is_null() { String::new() } else { unsafe { CStr::from_ptr(page.info.as_ptr()).to_string_lossy().into_owned() } };
                if !name.is_empty() {
                    mlist.push(serde_json::json!({
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
}

pub fn get_call_stack_api() -> Vec<serde_json::Value> {
    let mut call_stack = unsafe { std::mem::zeroed::<DBGCALLSTACK>() };
    unsafe { (*DbgFunctions()).GetCallStack.unwrap()(&mut call_stack) };
    
    let mut cs_list = Vec::new();
    if call_stack.total > 0 && !call_stack.entries.is_null() {
        for i in 0..call_stack.total {
            let entry = unsafe { *call_stack.entries.add(i as usize) };
            cs_list.push(serde_json::json!({
                "address": format!("0x{:X}", entry.addr),
                "from": format!("0x{:X}", entry.from),
                "to": format!("0x{:X}", entry.to),
                "comment": if entry.comment.as_ptr().is_null() { String::new() } else { unsafe { CStr::from_ptr(entry.comment.as_ptr()).to_string_lossy().into_owned() } }
            }));
        }
        unsafe { BridgeFree(call_stack.entries as *mut c_void) };
    }
    cs_list
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
        // For simplicity, let's just use current CIP module if '*' is specified but not handled globally
        let regs = get_registers_api();
        if let Some(r) = regs {
            unsafe { (*DbgFunctions()).ModBaseFromAddr.unwrap()(r.regcontext.cip) }
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
    let mut size: duint = 0;
    unsafe { size = (*DbgFunctions()).ModSizeFromAddr.unwrap()(base); }
    if size == 0 { return Vec::new(); }

    let mut strings = Vec::new();
    let chunk_size = 0x1000;
    
    // We iterate through the module memory and look for string references
    // This is a simplified version of what 'strref' does.
    // In x64dbg, DbgGetStringAt is often used to check if an address points to a string.
    
    for addr in (base..base + size).step_by(8) { // Step by pointer size for speed
        let mut string_buf = vec![0i8; 512];
        if unsafe { DbgGetStringAt(addr, string_buf.as_mut_ptr()) } {
            let string_val = unsafe { CStr::from_ptr(string_buf.as_ptr()).to_string_lossy().into_owned() };
            if !string_val.trim().is_empty() {
                strings.push(serde_json::json!({
                    "address": format!("0x{:X}", addr),
                    "content": string_val
                }));
            }
        }
        // Limit to 1000 strings to prevent overwhelming the AI
        if strings.len() >= 1000 { break; }
    }

    strings
}
