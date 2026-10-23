//! Exception-dispatch hook.
//!
//! Port of the exception handling in `dllmain.cpp`. The hook is installed into
//! `KiUserExceptionDispatcher`, either through its function pointer (current
//! Windows) or by patching its entry stub (Wine). It redirects known crash sites
//! past the faulting instruction, writes crash logs, and suspends the process on
//! fatal faults.
//!
//! The mechanism depends on undocumented ntdll internals. It is the riskiest
//! part of the port and has not been run against the game.

use std::collections::HashMap;
use std::ffi::{CStr, c_void};
use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::Debug::{CONTEXT, EXCEPTION_RECORD, RtlPcToFileHeader};
use windows::Win32::System::LibraryLoader::{GetModuleFileNameA, GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Memory::{
    PAGE_EXECUTE_READWRITE, PAGE_PROTECTION_FLAGS, VirtualProtect,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, OpenProcess, OpenThread, PROCESS_ALL_ACCESS,
    THREAD_ALL_ACCESS,
};
use windows::Win32::UI::WindowsAndMessaging::{MB_OK, MessageBoxA};
use windows::core::{PCSTR, s};

use crate::build;
use crate::offsets::{self, address};
use crate::protection;

const CRASH_LOG_NAME: &str = "crashes.log";
const LOG_FAILED_EXIT_CODE: i32 = -444;

const STATUS_ILLEGAL_INSTRUCTION: i32 = 0xC000_001D_u32.cast_signed();
const EXCEPTION_ACCESS_VIOLATION: i32 = 0xC000_0005_u32.cast_signed();
const EXCEPTION_NONCONTINUABLE: u32 = 0x1;

const UNKNOWN_MODULE: &str = "<Unknown Module>";
const CLIENTFIELD_DOESNT_EXIST: &CStr = c"Clientfield does not exist";

/// Stand-in localized string handed to crashing UI code. It is always empty.
static EMPTY_LOCALIZED_TEXT: [u8; 4] = [0; 4];

/// Set while the hook is being removed, so the next fault resumes cleanly.
pub static IS_UNHOOKING: AtomicBool = AtomicBool::new(false);
/// Thread id currently writing the crash log, or 0 when nobody is.
static LCK_DUMPING: AtomicU32 = AtomicU32::new(0);
/// Pointer slot the hook was written into, or 0.
static FN_PTR_HOOK: AtomicUsize = AtomicUsize::new(0);
/// Original stub bytes saved before the Wine-style patch.
static WINE_OLD_DATA: Mutex<Option<[u8; WINE_HOOK_SIZE]>> = Mutex::new(None);
static SAVED_EXCEPTIONS: Mutex<Option<HashMap<i64, CONTEXT>>> = Mutex::new(None);

const WINE_HOOK_SIZE: usize = 0x1B;
const WINE_KI_DISPATCH_OFFSET: usize = 0xB;
const WINE_STUB_PATTERN: i32 = 0x248C_8B48;
const KI_DISPATCH_PTR_PATTERN: i32 = 0x058B_48FC;

type ZwContinueFn = unsafe extern "system" fn(*mut CONTEXT, u8) -> i32;
type NtSuspendProcessFn = unsafe extern "system" fn(HANDLE) -> i32;

fn lock_saved() -> MutexGuard<'static, Option<HashMap<i64, CONTEXT>>> {
    SAVED_EXCEPTIONS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Resolves an export from `module`, or 0 if it is missing.
///
/// # Safety
///
/// `module` must be a valid module handle or null; `name` must be NUL-terminated.
unsafe fn proc_address(module: &str, name: PCSTR) -> usize {
    let name_c = std::ffi::CString::new(module).unwrap_or_default();
    // SAFETY: `name_c` is a valid NUL-terminated module name.
    let handle = unsafe { GetModuleHandleA(PCSTR(name_c.as_ptr().cast())) }.unwrap_or_default();
    // SAFETY: `handle` is a module handle from `GetModuleHandleA`; `name` is NUL-terminated.
    unsafe { GetProcAddress(handle, name) }.map_or(0, |function| function as *const () as usize)
}

/// Address of `ntdll!ZwContinue`, or 0 if it is missing.
pub fn zw_continue_address() -> usize {
    // SAFETY: resolves an export of ntdll, which is always loaded in a Windows process.
    unsafe { proc_address("ntdll.dll", s!("ZwContinue")) }
}

/// Calls `ZwContinue`, which resumes execution at `context` and does not return on success.
///
/// # Safety
///
/// `context` must point to a `CONTEXT` captured for the current exception.
unsafe fn zw_continue(context: *mut CONTEXT) {
    // SAFETY: `ntdll!ZwContinue` has this signature; the address is resolved from ntdll.
    let address = unsafe { proc_address("ntdll.dll", s!("ZwContinue")) };
    if address == 0 {
        return;
    }
    // SAFETY: the resolved export is `ZwContinue`, matching `ZwContinueFn`.
    let function: ZwContinueFn = unsafe { std::mem::transmute(address) };
    // SAFETY: the caller guarantees `context` is the exception's context record.
    unsafe { function(context, 0) };
}

/// Redirects execution to `rip` and resumes.
///
/// # Safety
///
/// `context` must be the context of the exception currently being handled.
unsafe fn resume_at(context: *mut CONTEXT, rip: usize) {
    // SAFETY: the caller guarantees `context` is valid for the current exception.
    unsafe {
        (*context).Rip = rip as u64;
        zw_continue(context);
    }
}

/// Address of the empty localized string returned to crashing UI code.
fn localized_empty_text() -> u64 {
    EMPTY_LOCALIZED_TEXT.as_ptr().addr() as u64
}

fn open_crash_log() -> std::fs::File {
    match OpenOptions::new()
        .create(true)
        .append(true)
        .open(CRASH_LOG_NAME)
    {
        Ok(file) => file,
        Err(_) => std::process::exit(LOG_FAILED_EXIT_CODE),
    }
}

/// Stops every thread of the process by suspending the process itself.
fn suspend_process() {
    // SAFETY: opens the current process with full access, as the original does.
    let Ok(process) = (unsafe { OpenProcess(PROCESS_ALL_ACCESS, false, GetCurrentProcessId()) })
    else {
        return;
    };
    // SAFETY: `NtSuspendProcess` takes a process handle; the address comes from ntdll.
    let address = unsafe { proc_address("ntdll.dll", s!("NtSuspendProcess")) };
    if address != 0 {
        // SAFETY: the resolved export is `NtSuspendProcess`, matching the signature.
        let function: NtSuspendProcessFn = unsafe { std::mem::transmute(address) };
        // SAFETY: `process` is a valid handle opened above.
        unsafe { function(process) };
    }
    // SAFETY: `process` is a handle opened above and not used afterwards.
    let _ = unsafe { CloseHandle(process) };
}

/// Writes one exception line block for every saved context, then empties the map.
///
/// # Safety
///
/// Reads the saved stack of each context; the addresses are the faulting thread's own stack.
unsafe fn dump_saved_exceptions(log: &mut std::fs::File, code: i32) {
    let image_base = build::image_base() as u64;
    let mut saved = lock_saved();
    let Some(map) = saved.as_mut() else {
        return;
    };

    while let Some(&key) = map.keys().next() {
        let Some(context) = map.remove(&key) else {
            break;
        };

        let mut module_base: *mut c_void = std::ptr::null_mut();
        // SAFETY: `key` is a code address captured from an exception record.
        unsafe { RtlPcToFileHeader(key as *const c_void, &raw mut module_base) };
        let faulting_module = module_base as u64;
        let module_name = if faulting_module != 0 {
            let mut buffer = [0u8; 260];
            // SAFETY: the buffer is 260 bytes, matching MAX_PATH.
            let length = unsafe { GetModuleFileNameA(Some(HMODULE(module_base)), &mut buffer) };
            String::from_utf8_lossy(&buffer[..length as usize]).into_owned()
        } else {
            UNKNOWN_MODULE.to_owned()
        };

        let key_u = key.cast_unsigned();
        let mut text = String::new();
        let _ = writeln!(text, "Game: {image_base:016x}");
        let _ = writeln!(text, "Module: {module_name}");
        let _ = writeln!(
            text,
            "[{faulting_module:016x}]Exception at ({:016x}) (RIP:{:016x}) (Rsp: {:016x})",
            key_u.wrapping_sub(faulting_module),
            context.Rip,
            context.Rsp
        );
        let _ = writeln!(
            text,
            "[{key_u:016x}]Rcx: ({:016x}) Rdx: ({:016x}) R8: ({:016x}) R9: ({:016x})",
            context.Rcx, context.Rdx, context.R8, context.R9
        );
        let _ = writeln!(
            text,
            "[{key_u:016x}]Rax: ({:016x}) Rbx: ({:016x}) Rsi: ({:016x}) Rdi: ({:016x})",
            context.Rax, context.Rbx, context.Rsi, context.Rdi
        );
        let _ = writeln!(
            text,
            "[{key_u:016x}]R10: ({:016x}) R11: ({:016x}) R12: ({:016x}) R13: ({:016x})",
            context.R10, context.R11, context.R12, context.R13
        );
        let _ = writeln!(
            text,
            "[{key_u:016x}]Rbp: ({:016x}) R14: ({:016x}) R15: ({:016x}) Dr7: ({:016x})",
            context.Rbp, context.R14, context.R15, context.Dr7
        );
        let _ = writeln!(
            text,
            "[{key_u:016x}]Dr0: ({:016x}) Dr1: ({:016x}) Dr2: ({:016x}) Dr3: ({:016x})",
            context.Dr0, context.Dr1, context.Dr2, context.Dr3
        );

        let span = if code == STATUS_ILLEGAL_INSTRUCTION {
            0x1200
        } else {
            0x400
        };
        for offset in (0..span).step_by(0x10) {
            let stack = context.Rsp + u64::try_from(offset).unwrap_or_default();
            // SAFETY: the faulting thread's stack is mapped for at least this range.
            let (low, high) = unsafe {
                (
                    (stack as *const u64).read_unaligned(),
                    ((stack + 8) as *const u64).read_unaligned(),
                )
            };
            let _ = writeln!(text, "[{stack:016x}] {low:016x} {high:016x}\n");
        }

        let _ = log.write_all(text.as_bytes());
    }
}

/// Writes a crash log entry and handles the fault, following the original dispatch order.
///
/// # Safety
///
/// Called by the process's exception dispatcher with a valid record and context.
unsafe extern "system" fn exception_hook(record: *mut EXCEPTION_RECORD, context: *mut CONTEXT) {
    if record.is_null() || context.is_null() {
        return;
    }

    if IS_UNHOOKING.load(Ordering::Acquire) {
        // SAFETY: `context` is the valid context of the current exception.
        unsafe {
            (*context).Dr7 = 0;
            (*context).Rip = address(offsets::ROP_RETN) as u64;
        }
        IS_UNHOOKING.store(false, Ordering::Release);
        // SAFETY: as above.
        unsafe { zw_continue(context) };
        return;
    }

    // SAFETY: `record` and `context` are valid for the duration of the call.
    unsafe { protection::except_hook(record, context) };

    // SAFETY: `context` is valid for the duration of the call.
    if unsafe { (*context).Rcx } == 0xFFEE_DDCC_4433_2211 {
        return;
    }

    // SAFETY: `record` is valid; only its address field is read.
    let at = unsafe { (*record).ExceptionAddress } as usize;
    // SAFETY: as above.
    if unsafe { redirect_known_crash(at, context) } {
        return;
    }

    // SAFETY: `record` and `context` are valid for the duration of the call.
    unsafe { handle_general_exception(record, context) };
}

/// Handles the known crash sites. Returns `Some(())` when the fault was handled.
///
/// # Safety
///
/// `context` must be the context of the exception at `at`.
unsafe fn redirect_known_crash(at: usize, context: *mut CONTEXT) -> bool {
    let text = localized_empty_text();

    // SAFETY (all `resume_at` / field writes below): `context` is the current exception's context.
    unsafe {
        if at == address(0x22D2F0D) {
            (*context).Rax = 0;
            resume_at(context, address(0x22D389E));
        } else if at == address(0x464FEF) {
            (*context).Rax = 0;
            resume_at(context, address(0x4651A2));
        } else if at == address(0x15E4B7A) {
            resume_at(context, address(0x15E4BA3));
        } else if at == address(0x12EE4EC) {
            resume_at(context, address(0x12EE5E8));
        } else if at == address(0x22C965C) {
            resume_at(context, address(0x22C9686));
        } else if at == address(offsets::LUA_CRASH1) {
            resume_at(context, address(offsets::LUA_CRASH1_RIP));
        } else if at == address(offsets::LUA_CRASH2) {
            (*context).Rdx = text;
            zw_continue(context);
        } else if at == address(offsets::LUA_CRASH3) {
            (*context).Rsi = text;
            zw_continue(context);
        } else if at == address(0x22328F6) {
            (*context).Rcx = text;
            zw_continue(context);
        } else if at == address(0x1E9E657) {
            resume_at(context, address(0x1E9E7E3));
        } else if at == address(0x1A604C4) {
            resume_at(context, address(0x1A6054B));
        } else if at == address(0x133EC1) || at == address(0x133EEB) {
            resume_at(context, address(0x133F12));
        } else if at == address(0x133F31) {
            resume_at(context, address(0x133F42));
        } else if [0xC15B80, 0xC15C50, 0xC18CF5]
            .iter()
            .any(|&rva| at == address(rva))
        {
            (*context).Rcx = 1;
            (*context).Rdx = CLIENTFIELD_DOESNT_EXIST.as_ptr() as u64;
            (*context).R8 = 0;
            resume_at(context, address(offsets::OFF_SCRVM_RUNTIME_ERROR));
        } else if GSC_CLIENTFIELD_CRASHES
            .iter()
            .any(|&rva| at == address(rva))
        {
            (*context).Rcx = 0;
            (*context).Rdx = CLIENTFIELD_DOESNT_EXIST.as_ptr() as u64;
            (*context).R8 = 0;
            resume_at(context, address(offsets::OFF_SCRVM_RUNTIME_ERROR));
        } else if at == address(0x13591F3) {
            resume_at(context, address(0x13591FA));
        } else if at == address(0x11D2580) {
            (*context).Rax = 0;
            resume_at(context, address(0x11D2592));
        } else if at == address(0x22C4935) {
            (*context).Rax = 0;
            resume_at(context, address(0x22C49FE));
        } else if at == address(offsets::SCRVM_ERROR) {
            handle_script_error(context);
        } else {
            return false;
        }
    }
    true
}

/// GSC call sites that read a missing clientfield.
const GSC_CLIENTFIELD_CRASHES: [usize; 9] = [
    0x1A5F94B, 0x1A5FA5E, 0x1A5FB5E, 0x1A5FBFD, 0x1A5FE76, 0x1A5FF86, 0x1A6003D, 0x1A602C7,
    0x1A604C4,
];

/// Script VM fatal-flag table, one byte per VM, stride 35392.
const SCR_VM_FATAL_TABLE_RVA: usize = 0x5124869;
/// Script VM error-message table, one pointer per VM, stride 0x78.
const SCR_VM_ERROR_TABLE_RVA: usize = 0x51A3710;

/// Handles a `SCRVM_Error` call: writes a fatal script error or resumes the VM.
///
/// # Safety
///
/// `context` must be the context of the script VM error call.
unsafe fn handle_script_error(context: *mut CONTEXT) {
    // SAFETY: the caller guarantees `context`; the advances mirror the original.
    unsafe {
        (*context).Rip = (*context).Rip.wrapping_add(4);
        (*context).Rsp = (*context).Rsp.wrapping_sub(0x30);
    }

    // SAFETY: `context` is valid; its `Rcx` is the VM index in the original.
    let index = usize::from(unsafe { (*context).Rcx }.to_le_bytes()[0]);
    // SAFETY: the tables are indexed by the VM number, as in the original.
    let (fatal_flag, error_pointer) = unsafe {
        (
            *((address(SCR_VM_FATAL_TABLE_RVA) + 35392 * index) as *const u8),
            *((address(SCR_VM_ERROR_TABLE_RVA) + 0x78 * index) as *const usize),
        )
    };
    let mut is_fatal = fatal_flag != 0;

    let error_message = if error_pointer != 0 {
        // SAFETY: a non-null error pointer is a NUL-terminated string in the game's table.
        let message = unsafe { CStr::from_ptr(error_pointer as *const std::ffi::c_char) };
        if message.to_bytes().is_empty() {
            "unknown".to_owned()
        } else {
            message.to_string_lossy().into_owned()
        }
    } else {
        "unknown".to_owned()
    };
    if error_message.contains("Invalid opcode") {
        is_fatal = true;
    }

    if !is_fatal {
        // SAFETY: `context` is the VM error call's context, so resuming it is the original behaviour.
        unsafe { zw_continue(context) };
        return;
    }

    // SAFETY: the VM table holds one fault record per index, read only on the fatal path.
    let fs_value = unsafe { *((address(offsets::SCRVM_FS) as *const i64).add(index * 4)) };

    let mut log = open_crash_log();
    let client = if index != 0 { "Client" } else { "Server" };
    let _ = write!(log, "Script Exception Type: {client}");
    let _ = writeln!(log, "Script Fatal Exception at : {fs_value:016x}");
    let low_bits = fs_value.cast_unsigned() & 0xFFFF_FFFF;
    let _ = write!(log, "\t at: (null){low_bits:x}");
    let _ = writeln!(log, "Error Message: {error_message}");
    let _ = log.flush();
    drop(log);

    // SAFETY: a static NUL-terminated message box with no owner window.
    unsafe {
        MessageBoxA(
            None,
            s!(
                "Unfortunately, a fatal script error has occured in Black Ops III. The error has been recorded in steamapps/common/Black Ops III/crashes.log."
            ),
            s!("Fatal Script Error"),
            MB_OK,
        );
    }
    std::process::exit(0);
}

/// Logs an unrecognized access violation or non-continuable fault, then suspends the process.
///
/// # Safety
///
/// `record` and `context` must be valid for the current exception.
unsafe fn handle_general_exception(record: *mut EXCEPTION_RECORD, context: *mut CONTEXT) {
    // SAFETY: `record` is valid.
    let (code, flags, at) = unsafe {
        (
            (*record).ExceptionCode.0,
            (*record).ExceptionFlags,
            (*record).ExceptionAddress as i64,
        )
    };
    let mut b_fatal = false;
    if code == EXCEPTION_ACCESS_VIOLATION || flags & EXCEPTION_NONCONTINUABLE != 0 {
        // SAFETY: `context` is valid for the current exception.
        let context_value = unsafe { *context };
        // SAFETY: `GetCurrentThreadId` has no preconditions.
        let thread = unsafe { GetCurrentThreadId() };

        if LCK_DUMPING.load(Ordering::Acquire) != 0 {
            lock_saved()
                .get_or_insert_with(HashMap::new)
                .insert(at, context_value);
        } else {
            LCK_DUMPING.store(thread, Ordering::Release);
            let mut log = open_crash_log();
            let stamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |duration| duration.as_secs());
            let _ = write!(log, "Crash log {stamp:016x}\n\n");
            lock_saved()
                .get_or_insert_with(HashMap::new)
                .insert(at, context_value);
            // SAFETY: the log is open and the saved contexts are read from the map.
            unsafe { dump_saved_exceptions(&mut log, code) };
            let _ = log.flush();
            drop(log);
            LCK_DUMPING.store(0, Ordering::Release);
        }

        if code != STATUS_ILLEGAL_INSTRUCTION {
            b_fatal = true;
        }
    }

    if b_fatal {
        // SAFETY: `GetCurrentThreadId` has no preconditions.
        let thread = unsafe { GetCurrentThreadId() };
        let dumping = LCK_DUMPING.load(Ordering::Acquire);
        if dumping != 0 && dumping != thread {
            // SAFETY: opens the current thread with full access, as the original does.
            if let Ok(handle) = unsafe { OpenThread(THREAD_ALL_ACCESS, false, thread) } {
                // SAFETY: `kernel32!SuspendThread` takes a thread handle.
                let suspend = unsafe { proc_address("kernel32.dll", s!("SuspendThread")) };
                // SAFETY: `context` is valid; the handler resumes at SuspendThread with the handle.
                unsafe {
                    (*context).Rip = suspend as u64;
                    (*context).Rcx = handle.0 as u64;
                    zw_continue(context);
                }
            }
        } else {
            suspend_process();
        }
    }
}

/// Patches the stub on current Windows, which stores a pointer to the handler.
///
/// # Safety
///
/// `dispatcher` must be the address of `KiUserExceptionDispatcher` in ntdll.
unsafe fn install_pointer_hook(dispatcher: usize, handler: usize) {
    // SAFETY: the dispatcher's first word was checked by the caller to match the pattern.
    let distance = unsafe { ((dispatcher + 4) as *const u32).read_unaligned() } as usize;
    let slot = (dispatcher + 8) + distance;
    FN_PTR_HOOK.store(slot, Ordering::Release);

    let mut old = PAGE_PROTECTION_FLAGS(0);
    // SAFETY: the slot is an 8-byte pointer inside ntdll's data.
    unsafe {
        let _ = VirtualProtect(slot as *const _, 8, PAGE_EXECUTE_READWRITE, &raw mut old);
        (slot as *mut usize).write_unaligned(handler);
        let _ = VirtualProtect(slot as *const _, 8, old, &raw mut old);
    }
}

/// Machine code that calls the handler through the stub, with the original stub saved.
fn wine_stub(handler: usize) -> [u8; WINE_HOOK_SIZE] {
    let mut bytes = [
        0x48, 0xB8, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x48, 0x89, 0xE2, 0x48, 0x8D,
        0x8C, 0x24, 0xF0, 0x04, 0x00, 0x00, 0xFF, 0xD0, 0x90, 0x90, 0x90, 0x90,
    ];
    bytes[2..10].copy_from_slice(&(handler as u64).to_le_bytes());
    bytes
}

/// Overwrites the Wine-style dispatcher stub with a call to `handler`.
///
/// # Safety
///
/// `dispatcher` must be the address of `KiUserExceptionDispatcher` with the Wine stub.
unsafe fn install_wine_hook(dispatcher: usize, handler: usize) {
    let begin = dispatcher + WINE_KI_DISPATCH_OFFSET;
    let mut old_data = [0u8; WINE_HOOK_SIZE];
    // SAFETY: the stub is WINE_HOOK_SIZE bytes inside ntdll's code.
    unsafe {
        std::ptr::copy_nonoverlapping(begin as *const u8, old_data.as_mut_ptr(), WINE_HOOK_SIZE);
    };
    *WINE_OLD_DATA.lock().unwrap_or_else(PoisonError::into_inner) = Some(old_data);

    // SAFETY: `begin` is the stub described above; it is rewritten with the new bytes.
    unsafe { crate::arxan::write_bytes(begin, &wine_stub(handler)) };
}

/// Restores the Wine-style dispatcher stub.
///
/// # Safety
///
/// `dispatcher` must be the address of `KiUserExceptionDispatcher` with the patched stub.
unsafe fn uninstall_wine_hook(dispatcher: usize) {
    let saved = *WINE_OLD_DATA.lock().unwrap_or_else(PoisonError::into_inner);
    let Some(old_data) = saved else {
        return;
    };
    // SAFETY: restores the bytes saved by `install_wine_hook` at the same address.
    unsafe { crate::arxan::write_bytes(dispatcher + WINE_KI_DISPATCH_OFFSET, &old_data) };
}

/// Installs the exception hook into `KiUserExceptionDispatcher`.
///
/// # Safety
///
/// Must run inside the game process, after ntdll is loaded.
pub unsafe fn install() {
    // SAFETY: resolves ntdll's dispatcher export.
    let dispatcher = unsafe { proc_address("ntdll.dll", s!("KiUserExceptionDispatcher")) };
    if dispatcher == 0 {
        return;
    }

    // SAFETY: the dispatcher's code is readable; its first word selects the layout.
    let first_word = unsafe { (dispatcher as *const i32).read_unaligned() };
    if first_word == KI_DISPATCH_PTR_PATTERN {
        // SAFETY: the pattern matches the pointer layout handled by `install_pointer_hook`.
        unsafe { install_pointer_hook(dispatcher, exception_hook as *const () as usize) };
    } else if first_word == WINE_STUB_PATTERN {
        // SAFETY: the pattern matches the Wine stub handled by `install_wine_hook`.
        unsafe { install_wine_hook(dispatcher, exception_hook as *const () as usize) };
    }
}

/// Points the dispatcher at a no-op and restores any patched stub.
///
/// # Safety
///
/// Must run inside the game process; the hook must have been installed by [`install`].
pub unsafe fn uninstall() {
    // SAFETY: calls the game's INT3 stub, which forces an exception to set up debug registers.
    unsafe {
        let trigger: unsafe extern "system" fn() =
            std::mem::transmute(address(offsets::INT3_2_BO3));
        trigger();
    }

    // SAFETY: resolves ntdll's dispatcher export.
    let dispatcher = unsafe { proc_address("ntdll.dll", s!("KiUserExceptionDispatcher")) };
    if dispatcher == 0 {
        return;
    }
    // SAFETY: the dispatcher's code is readable; its first word selects the layout.
    let first_word = unsafe { (dispatcher as *const i32).read_unaligned() };
    if first_word == KI_DISPATCH_PTR_PATTERN {
        let slot = FN_PTR_HOOK.load(Ordering::Acquire);
        if slot != 0 {
            let mut old = PAGE_PROTECTION_FLAGS(0);
            // SAFETY: `slot` is the pointer slot written by `install_pointer_hook`.
            unsafe {
                let _ = VirtualProtect(slot as *const _, 8, PAGE_EXECUTE_READWRITE, &raw mut old);
                (slot as *mut usize).write_unaligned(nullsub as *const () as usize);
                let _ = VirtualProtect(slot as *const _, 8, old, &raw mut old);
            }
        }
    } else if first_word == WINE_STUB_PATTERN {
        // SAFETY: the stub was patched by `install_wine_hook`.
        unsafe { uninstall_wine_hook(dispatcher) };
    }
}

/// Replacement handler that does nothing, used once the hook is removed.
unsafe extern "system" fn nullsub() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wine_stub_embeds_handler_address() {
        let stub = wine_stub(0x1122_3344_5566_7788);
        assert_eq!(&stub[2..10], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(stub.len(), WINE_HOOK_SIZE);
        assert_eq!(&stub[0..2], &[0x48, 0xB8]);
    }

    #[test]
    fn gsc_clientfield_list_is_unique() {
        let mut sorted = GSC_CLIENTFIELD_CRASHES;
        sorted.sort_unstable();
        assert!(sorted.windows(2).all(|pair| pair[0] != pair[1]));
    }
}
