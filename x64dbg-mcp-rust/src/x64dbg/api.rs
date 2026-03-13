use super::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_void};

#[repr(C)]
pub struct ListInfo {
    pub count: i32,
    pub size: usize,
    pub data: *mut c_void,
}

#[repr(C)]
pub struct TCPCONNECTIONINFO {
    pub RemoteAddress: [c_char; 50],
    pub RemotePort: u16,
    pub LocalAddress: [c_char; 50],
    pub LocalPort: u16,
    pub StateText: [c_char; 50],
    pub State: u32,
}

#[repr(C)]
pub struct HANDLEINFO {
    pub Handle: duint,
    pub TypeNumber: u8,
    pub GrantedAccess: u32,
}

#[repr(C)]
pub struct DBGPATCHINFO {
    pub mod_name: [c_char; 256],
    pub addr: duint,
    pub oldbyte: u8,
    pub newbyte: u8,
}

#[repr(C)]
pub struct HEAPINFO {
    pub addr: duint,
    pub size: duint,
    pub flags: duint,
}

#[repr(C)]
pub struct RECT {
    pub left: i32,
    pub top: i32,
    pub right: i32,
    pub bottom: i32,
}

#[repr(C)]
pub struct WINDOW_INFO {
    pub handle: duint,
    pub parent: duint,
    pub threadId: u32,
    pub style: u32,
    pub styleEx: u32,
    pub wndProc: duint,
    pub enabled: bool,
    pub position: RECT,
    pub windowTitle: [c_char; 512],
    pub windowClass: [c_char; 512],
}

pub type CBSTRING = Option<extern "C" fn(str: *const c_char, userdata: *mut c_void)>;

pub const MEM_IMAGE_VAL: u32 = 0x1000000;

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub enum XREFTYPE {
    XREF_NONE,
    XREF_DATA,
    XREF_JMP,
    XREF_CALL,
}

#[repr(C)]
pub struct XREF_RECORD {
    pub addr: duint,
    pub type_: XREFTYPE,
}

#[repr(C)]
pub struct XREF_INFO {
    pub refcount: duint,
    pub references: *mut XREF_RECORD,
}

#[repr(C)]
pub struct DBGFUNCTIONS {
    pub GetCallStack: Option<extern "C" fn(callstack: *mut DBGCALLSTACK)>,
    pub GetSEHChain: Option<extern "C" fn(sehchain: *mut c_void)>,
    pub _padding1: [Option<extern "C" fn()>; 3], // Skip symbol download etc.
    pub GetProcessList: Option<extern "C" fn(entries: *mut *mut c_void, count: *mut i32)>,
    pub _padding2: [Option<extern "C" fn()>; 10],
    pub EnumHandles: Option<extern "C" fn(handles: *mut ListInfo) -> bool>,
    pub GetHandleName: Option<
        extern "C" fn(
            handle: duint,
            name: *mut c_char,
            nameSize: usize,
            typeName: *mut c_char,
            typeNameSize: usize,
        ) -> bool,
    >,
    pub EnumTcpConnections: Option<extern "C" fn(connections: *mut ListInfo) -> bool>,
    pub _padding3: [Option<extern "C" fn()>; 7],
    pub EnumWindows: Option<extern "C" fn(windows: *mut ListInfo) -> bool>,
    pub EnumHeaps: Option<extern "C" fn(heaps: *mut ListInfo) -> bool>,
}

#[repr(C)]
pub struct DBGCALLSTACK {
    pub total: i32,
    pub entries: *mut DBGCALLSTACKENTRY,
}

#[repr(C)]
pub struct DISASM_ARG {
    pub type_: i32,
    pub segment: i32,
    pub mnemonic: [i8; 64],
    pub constant: duint,
    pub value: duint,
    pub memvalue: duint,
}

#[repr(C)]
pub struct DISASM_INSTR {
    pub instruction: [i8; 64],
    pub type_: i32,
    pub argcount: i32,
    pub instr_size: i32,
    pub arg: [DISASM_ARG; 3],
}

extern "C" {
    pub fn DbgXrefGet(addr: duint, info: *mut XREF_INFO) -> bool;
    pub fn DbgDisasmAt(addr: duint, instr: *mut DISASM_INSTR);
    pub fn DbgGetBookmarkAt(addr: duint) -> bool;
    pub fn DbgSetBookmarkAt(addr: duint, is_bookmark: bool) -> bool;
    pub fn DbgGetPebAddress(process_id: u32) -> duint;
    pub fn DbgGetTebAddress(thread_id: u32) -> duint;
    pub fn DbgGetProcessId() -> u32;
    pub fn DbgGetThreadId() -> u32;
    pub fn DbgSymbolEnum(
        base: duint,
        cb: Option<extern "C" fn(*const c_void, *mut c_void) -> bool>,
        user: *mut c_void,
    ) -> bool;
    pub fn BridgeFree(ptr: *mut c_void);
    pub fn DbgGetSymbolInfo(symbol: *const c_void, info: *mut SYMBOLINFO);
    pub fn DbgModBaseFromName(name: *const c_char) -> duint;
    pub fn DbgGetBplist(type_: BPXTYPE, list: *mut BPMAP) -> i32;
    pub fn DbgGetThreadList(list: *mut THREADLIST);
    pub fn DbgMemMap(mmap: *mut MEMMAP) -> bool;
    pub fn DbgSetCommentAt(addr: duint, text: *const c_char) -> bool;
    pub fn DbgSetLabelAt(addr: duint, text: *const c_char) -> bool;
    pub fn DbgGetStringAt(addr: duint, text: *mut c_char) -> bool;
    pub fn DbgFunctionGet(addr: duint, start: *mut duint, end: *mut duint) -> bool;
    pub fn DbgAnalyzeFunction(entry: duint, graph: *mut BridgeCFGraphList) -> bool;
}

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
    let success = unsafe { DbgMemRead(addr, buffer.as_mut_ptr() as *mut c_void, size as duint) };
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

pub fn get_breakpoints_api() -> Vec<serde_json::Value> {
    // Changed to serde_json::Value to match original return type
    let mut bplist = unsafe { std::mem::zeroed::<BPMAP>() };
    let count = unsafe { DbgGetBplist(BPXTYPE::bp_none, &mut bplist) }; // Changed to DbgGetBplist and BPXTYPE::bp_none as per instruction
    let mut breakpoints = Vec::new();

    if count > 0 && !bplist.list.is_null() {
        let _guard = BridgeMemoryGuard(bplist.list as *mut c_void);
        let entries = unsafe { std::slice::from_raw_parts(bplist.list, count as usize) };
        for entry in entries {
            breakpoints.push(
                serde_json::json!({ // Changed to serde_json::json! to match original return type
                    "address": format!("0x{:X}", entry.addr),
                    "enabled": entry.enabled,
                    "type_name": format!("{:?}", entry.type_), // Added type_name as per instruction
                }),
            );
        }
    }
    breakpoints
}

pub fn get_threads_api() -> Vec<serde_json::Value> {
    // Changed to serde_json::Value to match original return type
    let mut tlist = unsafe { std::mem::zeroed::<THREADLIST>() };
    unsafe { DbgGetThreadList(&mut tlist) };
    let mut threads = Vec::new();

    if tlist.count > 0 && !tlist.list.is_null() {
        let _guard = BridgeMemoryGuard(tlist.list as *mut c_void);
        let entries = unsafe { std::slice::from_raw_parts(tlist.list, tlist.count as usize) };
        for entry in entries {
            threads.push(
                serde_json::json!({ // Changed to serde_json::json! to match original return type
                    "handle": format!("0x{:X}", entry.Handle as usize),
                    "id": entry.ThreadId,
                    "cip": format!("0x{:X}", entry.ThreadCip),
                    "wait_reason": entry.WaitReason,
                }),
            );
        }
    }
    threads
}

pub fn get_modules_api() -> Vec<serde_json::Value> {
    // Changed to serde_json::Value to match original return type
    let mut mmap = unsafe { std::mem::zeroed::<MEMMAP>() };
    if unsafe { DbgMemMap(&mut mmap) } {
        let mut modules = Vec::new();
        if mmap.count > 0 && !mmap.page.is_null() {
            let _guard = BridgeMemoryGuard(mmap.page as *mut c_void);
            let pages = unsafe { std::slice::from_raw_parts(mmap.page, mmap.count as usize) };
            for page in pages {
                let info = unsafe {
                    CStr::from_ptr(page.info.as_ptr())
                        .to_string_lossy()
                        .into_owned()
                };
                if !info.is_empty() {
                    modules.push(
                        serde_json::json!({ // Changed to serde_json::json! to match original return type
                            "base": format!("0x{:X}", page.mbi.BaseAddress as usize),
                            "size": format!("0x{:X}", page.mbi.RegionSize as usize),
                            "name": info,
                        }),
                    );
                }
            }
        }
        modules
    } else {
        Vec::new()
    }
}

pub fn get_call_stack_api() -> Vec<serde_json::Value> {
    // Changed to serde_json::Value to match original return type
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
            unsafe {
                CStr::from_ptr(info.decoratedSymbol)
                    .to_string_lossy()
                    .into_owned()
            }
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
        DbgSymbolEnum(
            base,
            Some(cb_symbol_enum),
            &mut symbols as *mut _ as *mut c_void,
        );
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
    if size == 0 {
        return Vec::new();
    }

    let mut strings = Vec::new();
    let chunk_size = 0x10000; // 64KB chunks

    // Performance optimization: Read module in chunks and scan in Rust
    for current_addr in (base..base + size).step_by(chunk_size as usize) {
        // Cast chunk_size to usize
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

                if strings.len() >= 1000 {
                    break;
                }
            }
        }
        if strings.len() >= 1000 {
            break;
        }
    }

    strings
}

pub fn get_xrefs_api(addr: duint) -> Vec<serde_json::Value> {
    let mut info = unsafe { std::mem::zeroed::<XREF_INFO>() };
    if unsafe { DbgXrefGet(addr, &mut info) } {
        let mut xrefs = Vec::new();
        if info.refcount > 0 && !info.references.is_null() {
            let _guard = BridgeMemoryGuard(info.references as *mut c_void);
            let records =
                unsafe { std::slice::from_raw_parts(info.references, info.refcount as usize) };
            for record in records {
                xrefs.push(serde_json::json!({
                    "address": format!("0x{:X}", record.addr),
                    "type": format!("{:?}", record.type_),
                }));
            }
        }
        xrefs
    } else {
        Vec::new()
    }
}

pub fn get_memory_map_full_api() -> Vec<serde_json::Value> {
    let mut mmap = unsafe { std::mem::zeroed::<MEMMAP>() };
    if unsafe { DbgMemMap(&mut mmap) } {
        let mut regions = Vec::new();
        if mmap.count > 0 && !mmap.page.is_null() {
            let _guard = BridgeMemoryGuard(mmap.page as *mut c_void);
            let pages = unsafe { std::slice::from_raw_parts(mmap.page, mmap.count as usize) };
            for page in pages {
                let info = unsafe {
                    CStr::from_ptr(page.info.as_ptr())
                        .to_string_lossy()
                        .into_owned()
                };
                regions.push(serde_json::json!({
                    "base": format!("0x{:X}", page.mbi.BaseAddress as usize),
                    "size": format!("0x{:X}", page.mbi.RegionSize as usize),
                    "protection": format!("0x{:X}", page.mbi.Protect),
                    "type": format!("0x{:X}", page.mbi.Type),
                    "state": format!("0x{:X}", page.mbi.State),
                    "info": info,
                }));
            }
        }
        regions
    } else {
        Vec::new()
    }
}

pub fn disassemble_range_api(addr: duint, count: usize) -> Vec<serde_json::Value> {
    let mut instructions = Vec::new();
    let mut current_addr = addr;

    for _ in 0..count {
        let mut instr = unsafe { std::mem::zeroed::<DISASM_INSTR>() };
        unsafe { DbgDisasmAt(current_addr, &mut instr) };

        let text = unsafe {
            CStr::from_ptr(instr.instruction.as_ptr())
                .to_string_lossy()
                .into_owned()
        };
        if text.is_empty() {
            break;
        }

        instructions.push(serde_json::json!({
            "address": format!("0x{:X}", current_addr),
            "text": text,
            "size": instr.instr_size,
        }));
        current_addr += instr.instr_size as duint;
    }
    instructions
}

pub fn bookmark_api(addr: duint, is_set: bool) -> bool {
    unsafe { DbgSetBookmarkAt(addr, is_set) }
}

pub fn get_bookmarks_api() -> Vec<duint> {
    // x64dbg doesn't have a direct "list all bookmarks" FFI that returns a list in bridgemain.
    // Usually, you either iterate memory or use a command.
    // However, we can use the 'BookmarkList' command via execute_command_api and parse it,
    // OR we can leave it for now and focus on get/set.
    // Let's implement it by iterating sections or common regions, but that's slow.
    // For now, we'll just expose get_bookmark.
    Vec::new()
}

pub fn get_peb_teb_api() -> serde_json::Value {
    let pid = unsafe { DbgGetProcessId() };
    let tid = unsafe { DbgGetThreadId() };
    let peb = unsafe { DbgGetPebAddress(pid) };
    let teb = unsafe { DbgGetTebAddress(tid) };

    serde_json::json!({
        "pid": pid,
        "tid": tid,
        "peb": format!("0x{:X}", peb),
        "teb": format!("0x{:X}", teb),
    })
}

pub fn get_tcp_connections_api() -> Vec<serde_json::Value> {
    let mut connections = ListInfo {
        count: 0,
        size: 0,
        data: std::ptr::null_mut(),
    };
    if unsafe { dbg_functions().EnumTcpConnections.unwrap()(&mut connections) } {
        let mut result = Vec::new();
        if connections.count > 0 && !connections.data.is_null() {
            let _guard = BridgeMemoryGuard(connections.data);
            let ptr = connections.data as *const TCPCONNECTIONINFO;
            let entries = unsafe { std::slice::from_raw_parts(ptr, connections.count as usize) };
            for entry in entries {
                result.push(serde_json::json!({
                    "remote": format!("{}:{}",
                        unsafe { CStr::from_ptr(entry.RemoteAddress.as_ptr()).to_string_lossy() },
                        entry.RemotePort),
                    "local": format!("{}:{}",
                        unsafe { CStr::from_ptr(entry.LocalAddress.as_ptr()).to_string_lossy() },
                        entry.LocalPort),
                    "state": unsafe { CStr::from_ptr(entry.StateText.as_ptr()).to_string_lossy() },
                }));
            }
        }
        result
    } else {
        Vec::new()
    }
}

pub fn get_handles_api() -> Vec<serde_json::Value> {
    let mut handles = ListInfo {
        count: 0,
        size: 0,
        data: std::ptr::null_mut(),
    };
    if unsafe { dbg_functions().EnumHandles.unwrap()(&mut handles) } {
        let mut result = Vec::new();
        if handles.count > 0 && !handles.data.is_null() {
            let _guard = BridgeMemoryGuard(handles.data);
            let ptr = handles.data as *const HANDLEINFO;
            let entries = unsafe { std::slice::from_raw_parts(ptr, handles.count as usize) };
            for entry in entries {
                let mut name_buf = [0i8; 512];
                let mut type_buf = [0i8; 512];
                let mut name = String::new();
                let mut type_name = String::new();

                if unsafe {
                    dbg_functions().GetHandleName.unwrap()(
                        entry.Handle,
                        name_buf.as_mut_ptr(),
                        512,
                        type_buf.as_mut_ptr(),
                        512,
                    )
                } {
                    name = unsafe {
                        CStr::from_ptr(name_buf.as_ptr())
                            .to_string_lossy()
                            .into_owned()
                    };
                    type_name = unsafe {
                        CStr::from_ptr(type_buf.as_ptr())
                            .to_string_lossy()
                            .into_owned()
                    };
                }

                result.push(serde_json::json!({
                    "handle": format!("0x{:X}", entry.Handle),
                    "type": type_name,
                    "name": name,
                    "access": format!("0x{:X}", entry.GrantedAccess),
                }));
            }
        }
        result
    } else {
        Vec::new()
    }
}

pub fn get_heaps_api() -> Vec<serde_json::Value> {
    let mut heaps = ListInfo {
        count: 0,
        size: 0,
        data: std::ptr::null_mut(),
    };
    if unsafe { dbg_functions().EnumHeaps.unwrap()(&mut heaps) } {
        let mut result = Vec::new();
        if heaps.count > 0 && !heaps.data.is_null() {
            let _guard = BridgeMemoryGuard(heaps.data);
            let ptr = heaps.data as *const HEAPINFO;
            let entries = unsafe { std::slice::from_raw_parts(ptr, heaps.count as usize) };
            for entry in entries {
                result.push(serde_json::json!({
                    "address": format!("0x{:X}", entry.addr),
                    "size": format!("0x{:X}", entry.size),
                    "flags": format!("0x{:X}", entry.flags),
                }));
            }
        }
        result
    } else {
        Vec::new()
    }
}

pub fn get_windows_api() -> Vec<serde_json::Value> {
    let mut windows = ListInfo {
        count: 0,
        size: 0,
        data: std::ptr::null_mut(),
    };
    if unsafe { dbg_functions().EnumWindows.unwrap()(&mut windows) } {
        let mut result = Vec::new();
        if windows.count > 0 && !windows.data.is_null() {
            let _guard = BridgeMemoryGuard(windows.data);
            let ptr = windows.data as *const WINDOW_INFO;
            let entries = unsafe { std::slice::from_raw_parts(ptr, windows.count as usize) };
            for entry in entries {
                result.push(serde_json::json!({
                    "handle": format!("0x{:X}", entry.handle),
                    "title": unsafe { CStr::from_ptr(entry.windowTitle.as_ptr()).to_string_lossy() },
                    "class": unsafe { CStr::from_ptr(entry.windowClass.as_ptr()).to_string_lossy() },
                    "thread_id": entry.threadId,
                    "style": format!("0x{:X}", entry.style),
                }));
            }
        }
        result
    } else {
        Vec::new()
    }
}

pub fn get_patches_api() -> Vec<serde_json::Value> {
    let mut count: usize = 0;
    // First call to get required buffer size
    unsafe { (dbg_functions().PatchEnum.as_ref().unwrap())(std::ptr::null_mut(), &mut count) };

    if count > 0 {
        let mut patches = vec![
            unsafe { std::mem::zeroed::<DBGPATCHINFO>() };
            count / std::mem::size_of::<DBGPATCHINFO>()
        ];
        if unsafe {
            (dbg_functions().PatchEnum.as_ref().unwrap())(patches.as_mut_ptr(), &mut count)
        } {
            return patches
                .into_iter()
                .map(|p| {
                    serde_json::json!({
                        "module": unsafe { CStr::from_ptr(p.mod_name.as_ptr()).to_string_lossy() },
                        "address": format!("0x{:X}", p.addr),
                        "old": format!("{:02X}", p.oldbyte),
                        "new": format!("{:02X}", p.newbyte),
                    })
                })
                .collect();
        }
    }
    Vec::new()
}
