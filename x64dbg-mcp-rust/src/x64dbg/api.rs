use super::*;
use std::ffi::{CStr, CString};
use std::os::raw::c_void;
use std::collections::HashSet;

pub const MEM_IMAGE_VAL: u32 = 0x1000000;

pub fn log_print(msg: &str) {
    let msg_c = CString::new(msg).unwrap();
    unsafe {
        _plugin_logputs(msg_c.as_ptr());
    }
}

pub fn execute_command_api(cmd: &str) -> bool {
    let cmd_c = CString::new(cmd).unwrap();
    unsafe { DbgCmdExecDirect(cmd_c.as_ptr()) }
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
                "name": unsafe { CStr::from_ptr(bp.name.as_ptr()).to_string_lossy() },
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
                "name": unsafe { CStr::from_ptr(t.BasicInfo.threadName.as_ptr()).to_string_lossy() }
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
                let name = unsafe { CStr::from_ptr(page.info.as_ptr()).to_string_lossy() };
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
                "comment": unsafe { CStr::from_ptr(entry.comment.as_ptr()).to_string_lossy() }
            }));
        }
    }
    cs_list
}

pub fn set_comment_at_api(addr: duint, text: &str) -> bool {
    let text_c = CString::new(text).unwrap();
    unsafe { DbgSetCommentAt(addr, text_c.as_ptr()) }
}

pub fn set_label_at_api(addr: duint, text: &str) -> bool {
    let text_c = CString::new(text).unwrap();
    unsafe { DbgSetLabelAt(addr, text_c.as_ptr()) }
}
