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

use std::ffi::{CStr, c_void};
use std::fs::OpenOptions;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
use windows::Win32::Storage::FileSystem::{
    CreateFileA, FILE_APPEND_DATA, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE,
    FlushFileBuffers, OPEN_ALWAYS, WriteFile,
};
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT, EXCEPTION_RECORD, OutputDebugStringA, ReadProcessMemory, RtlPcToFileHeader,
};
use windows::Win32::System::LibraryLoader::{GetModuleFileNameA, GetModuleHandleA, GetProcAddress};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, GetCurrentThreadId, SuspendThread, TerminateProcess,
};
use windows::Win32::UI::WindowsAndMessaging::{MB_OK, MessageBoxA};
use windows::core::{PCSTR, s};

use crate::build;
use crate::crash_queue::CrashQueue;
use crate::offsets::{self, address};
use crate::protection;

const CRASH_LOG_NAME: &str = "crashes.log";
/// [`CRASH_LOG_NAME`] for the allocation-free emergency path.
const CRASH_LOG_NAME_C: &CStr = c"crashes.log";
const LOG_FAILED_EXIT_CODE: i32 = -444;
/// Exit code when the process cannot be suspended, as in the fork.
const SUSPEND_FAILED_EXIT_CODE: u32 = (-444_i32).cast_unsigned();

const STATUS_ILLEGAL_INSTRUCTION: i32 = 0xC000_001D_u32.cast_signed();
const EXCEPTION_ACCESS_VIOLATION: i32 = 0xC000_0005_u32.cast_signed();
const EXCEPTION_NONCONTINUABLE: u32 = 0x1;

const UNKNOWN_MODULE: &str = "<Unknown Module>";
const CLIENTFIELD_DOESNT_EXIST: &CStr = c"Clientfield does not exist";

/// Thread id that owns the fatal crash session, or 0 before the first fatal fault.
/// Never reset once claimed: the session is sealed and the process suspended.
static LCK_DUMPING: AtomicU32 = AtomicU32::new(0);
/// Pointer slot the hook was written into, or 0.
static FN_PTR_HOOK: AtomicUsize = AtomicUsize::new(0);
/// The callback the pointer slot held before the hook was written.
static ORIGINAL_DISPATCH_CALLBACK: AtomicUsize = AtomicUsize::new(0);
/// Set just before the dispatcher is patched, so a write that fails partway is still restored.
static DISPATCHER_INSTALLED: AtomicBool = AtomicBool::new(false);
/// Set while the handler should process faults. Cleared when a retained dispatcher is
/// logically deactivated, so the native pointer layout forwards to the saved callback.
static HANDLER_ACTIVE: AtomicBool = AtomicBool::new(false);
/// Set once a patch that can raise an induced exception is live. After that the
/// dispatcher is kept for the life of the process: an in-flight thread can still hold
/// a marker or a detour address that a scan cannot rule out.
static PRODUCERS_EXPOSED: AtomicBool = AtomicBool::new(false);
// The Wine stub is never rewritten back: a thread can return into it from the
// handler, so the saved original bytes would not make removal safe. Unload keeps
// the stub and the handler for the life of the process on that layout.

/// Maximum number of fatal faults logged in full in one session (fork `MAX_SAVED_EXCEPTIONS`).
const MAX_SAVED_EXCEPTIONS: usize = 16;

/// One fatal fault waiting to be written by the session owner.
#[derive(Clone, Copy)]
struct SavedException {
    address: i64,
    context: CONTEXT,
    code: i32,
}

static SAVED_EXCEPTIONS: CrashQueue<SavedException, MAX_SAVED_EXCEPTIONS> = CrashQueue::new();

/// Bounded wait for a reserved slot to be published.
const PUBLISH_SPIN_LIMIT: u32 = 1_000_000;

const WINE_HOOK_SIZE: usize = 0x1B;
const WINE_KI_DISPATCH_OFFSET: usize = 0xB;
const WINE_STUB_PATTERN: i32 = 0x248C_8B48;
const KI_DISPATCH_PTR_PATTERN: i32 = 0x058B_48FC;

type ZwContinueFn = unsafe extern "system" fn(*mut CONTEXT, u8) -> i32;
type NtSuspendProcessFn = unsafe extern "system" fn(HANDLE) -> i32;

/// Resolves an export from `module`, or 0 if it is missing.
///
/// # Safety
///
/// `module` and `name` must be NUL-terminated. Does not allocate, so it is usable on the
/// fatal crash path.
unsafe fn proc_address(module: PCSTR, name: PCSTR) -> usize {
    // SAFETY: the caller guarantees `module` is a NUL-terminated module name.
    let handle = unsafe { GetModuleHandleA(module) }.unwrap_or_default();
    // SAFETY: `handle` is a module handle from `GetModuleHandleA`; `name` is NUL-terminated.
    unsafe { GetProcAddress(handle, name) }.map_or(0, |function| function as *const () as usize)
}

/// Address of `ntdll!ZwContinue`, or 0 if it is missing.
pub fn zw_continue_address() -> usize {
    // SAFETY: resolves an export of ntdll, which is always loaded in a Windows process.
    unsafe { proc_address(s!("ntdll.dll"), s!("ZwContinue")) }
}

/// Calls `ZwContinue`, which resumes execution at `context` and does not return on success.
///
/// # Safety
///
/// `context` must point to a `CONTEXT` captured for the current exception.
unsafe fn zw_continue(context: *mut CONTEXT) {
    // SAFETY: `ntdll!ZwContinue` has this signature; the address is resolved from ntdll.
    let address = unsafe { proc_address(s!("ntdll.dll"), s!("ZwContinue")) };
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

fn open_crash_log() -> std::fs::File {
    try_open_crash_log().unwrap_or_else(|| std::process::exit(LOG_FAILED_EXIT_CODE))
}

fn try_open_crash_log() -> Option<std::fs::File> {
    OpenOptions::new()
        .create(true)
        .append(true)
        .open(CRASH_LOG_NAME)
        .ok()
}

/// Stops every thread of the process by suspending the process itself. Port of the fork's
/// `SuspendProcess`: the pseudo-handle needs no access rights and cannot leak, and the
/// process is terminated if it cannot be suspended.
fn suspend_process() {
    // SAFETY: resolves an ntdll export by static NUL-terminated names.
    let address = unsafe { proc_address(s!("ntdll.dll"), s!("NtSuspendProcess")) };
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle and has no preconditions.
    let process = unsafe { GetCurrentProcess() };
    let suspended = address != 0 && {
        // SAFETY: the resolved export is `NtSuspendProcess`, matching the signature.
        let function: NtSuspendProcessFn = unsafe { std::mem::transmute(address) };
        // SAFETY: `process` is the current-process pseudo-handle.
        let status = unsafe { function(process) };
        status >= 0
    };
    if !suspended {
        // SAFETY: terminates the current process through its pseudo-handle.
        let _ = unsafe { TerminateProcess(process, SUSPEND_FAILED_EXIT_CODE) };
    }
}

/// Bytes read per stack line: two 64-bit words.
const STACK_LINE_BYTES: usize = 16;

/// Start of the stack line at `stack + offset`, or `None` if the line would run past the
/// end of the address space (fork `StackProbe.h`).
fn stack_line_address(stack: usize, offset: usize) -> Option<usize> {
    let start = stack.checked_add(offset)?;
    start.checked_add(STACK_LINE_BYTES)?;
    Some(start)
}

/// Port of the fork's `ReadStackLine`: reads two words at `stack + offset` without
/// faulting, or `None` if the range overflows or is not fully readable.
fn read_stack_line(stack: usize, offset: usize) -> Option<[u64; 2]> {
    let start = stack_line_address(stack, offset)?;
    let mut words = [0u64; 2];
    let mut copied = 0usize;
    // SAFETY: `ReadProcessMemory` validates the source range itself and fails instead of
    // faulting; the destination is a local 16-byte buffer.
    unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            start as *const c_void,
            words.as_mut_ptr().cast(),
            STACK_LINE_BYTES,
            Some(&raw mut copied),
        )
    }
    .ok()?;
    (copied == STACK_LINE_BYTES).then_some(words)
}

const EMERGENCY_TEMPLATE: &[u8] =
    b"T7 Patch emergency exception: address=0x0000000000000000 code=0x00000000\r\n";
const EMERGENCY_LINE_LEN: usize = EMERGENCY_TEMPLATE.len();
const EMERGENCY_ADDRESS_START: usize = b"T7 Patch emergency exception: address=0x".len();
const EMERGENCY_CODE_START: usize = EMERGENCY_ADDRESS_START + 16 + b" code=0x".len();
const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Writes `value` as lowercase hex into `out`, most significant digit first, one digit per byte.
fn write_hex(out: &mut [u8], value: u64) {
    let digits = out.len();
    for (index, byte) in out.iter_mut().enumerate() {
        let shift = 4 * (digits - 1 - index);
        let nibble = usize::try_from((value >> shift) & 0xF).unwrap_or_default();
        *byte = HEX_DIGITS[nibble];
    }
}

/// The emergency log line for a fault, built without allocating.
fn format_emergency_line(address: i64, code: u32) -> [u8; EMERGENCY_LINE_LEN] {
    let mut line = [0u8; EMERGENCY_LINE_LEN];
    line.copy_from_slice(EMERGENCY_TEMPLATE);
    write_hex(
        &mut line[EMERGENCY_ADDRESS_START..EMERGENCY_ADDRESS_START + 16],
        address.cast_unsigned(),
    );
    write_hex(
        &mut line[EMERGENCY_CODE_START..EMERGENCY_CODE_START + 8],
        u64::from(code),
    );
    line
}

/// Port of the fork's `EmergencyException`: logs one line for a fault that cannot be
/// written in full, without the heap, `std::fs` or any lock this crate owns.
fn emergency_exception(address: i64, code: u32) {
    let line = format_emergency_line(address, code);
    let mut text = [0u8; EMERGENCY_LINE_LEN + 1];
    text[..EMERGENCY_LINE_LEN].copy_from_slice(&line);
    // SAFETY: `text` is NUL-terminated by its final zero byte.
    unsafe { OutputDebugStringA(PCSTR(text.as_ptr())) };

    // SAFETY: the file name is a static NUL-terminated string; no security attributes or
    // template file are passed.
    let Ok(file) = (unsafe {
        CreateFileA(
            PCSTR(CRASH_LOG_NAME_C.as_ptr().cast()),
            FILE_APPEND_DATA.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }) else {
        return;
    };
    let mut written = 0u32;
    // SAFETY: `file` is the handle opened above; `line` is a local buffer.
    let _ = unsafe { WriteFile(file, Some(&line), Some(&raw mut written), None) };
    // SAFETY: as above.
    let _ = unsafe { FlushFileBuffers(file) };
    // SAFETY: `file` was opened above and is not used afterwards.
    let _ = unsafe { CloseHandle(file) };
}

/// Port of the fork's `DumpException`: writes one crash-log entry. The header and
/// registers are flushed before the stack is read, so they survive a failure there.
fn dump_exception(log: &mut std::fs::File, address: i64, context: &CONTEXT, code: i32) {
    let image_base = build::image_base() as u64;

    let mut module_base: *mut c_void = std::ptr::null_mut();
    // SAFETY: only looks up which loaded image contains `address`; it does not dereference it.
    unsafe { RtlPcToFileHeader(address as *const c_void, &raw mut module_base) };
    let faulting_module = module_base as u64;
    let mut module_name = UNKNOWN_MODULE.to_owned();
    if faulting_module != 0 {
        let mut buffer = [0u8; 260];
        // SAFETY: the buffer is 260 bytes, matching MAX_PATH.
        let length = unsafe { GetModuleFileNameA(Some(HMODULE(module_base)), &mut buffer) };
        if length != 0 {
            module_name = String::from_utf8_lossy(&buffer[..length as usize]).into_owned();
        }
    }

    let key = address.cast_unsigned();
    let _ = writeln!(log, "Game: {image_base:016x}");
    let _ = writeln!(log, "Module: {module_name}");
    let _ = writeln!(
        log,
        "[{faulting_module:016x}]Exception at ({:016x}) (RIP:{:016x}) (Rsp: {:016x})",
        key.wrapping_sub(faulting_module),
        context.Rip,
        context.Rsp
    );
    let _ = writeln!(
        log,
        "[{key:016x}]Rcx: ({:016x}) Rdx: ({:016x}) R8: ({:016x}) R9: ({:016x})",
        context.Rcx, context.Rdx, context.R8, context.R9
    );
    let _ = writeln!(
        log,
        "[{key:016x}]Rax: ({:016x}) Rbx: ({:016x}) Rsi: ({:016x}) Rdi: ({:016x})",
        context.Rax, context.Rbx, context.Rsi, context.Rdi
    );
    let _ = writeln!(
        log,
        "[{key:016x}]R10: ({:016x}) R11: ({:016x}) R12: ({:016x}) R13: ({:016x})",
        context.R10, context.R11, context.R12, context.R13
    );
    let _ = writeln!(
        log,
        "[{key:016x}]Rbp: ({:016x}) R14: ({:016x}) R15: ({:016x}) Dr7: ({:016x})",
        context.Rbp, context.R14, context.R15, context.Dr7
    );
    let _ = writeln!(
        log,
        "[{key:016x}]Dr0: ({:016x}) Dr1: ({:016x}) Dr2: ({:016x}) Dr3: ({:016x})",
        context.Dr0, context.Dr1, context.Dr2, context.Dr3
    );
    // Preserve the exception and registers even if reading the stack fails.
    let _ = log.flush();

    let span = if code == STATUS_ILLEGAL_INSTRUCTION {
        0x1200
    } else {
        0x400
    };
    let rsp = usize::try_from(context.Rsp).unwrap_or(usize::MAX);
    for offset in (0..span).step_by(0x10) {
        let Some([first_word, second_word]) = read_stack_line(rsp, offset) else {
            let _ = writeln!(
                log,
                "Stack unreadable at RSP+0x{offset:x}; stack dump stopped."
            );
            break;
        };
        let stack = rsp + offset;
        let _ = writeln!(log, "[{stack:016x}] {first_word:016x} {second_word:016x}\n");
    }
    let _ = log.flush();
}

/// Waits a bounded time for `slot` to be published by the thread that reserved it.
fn wait_published(slot: usize) -> Option<SavedException> {
    for _ in 0..PUBLISH_SPIN_LIMIT {
        if let Some(saved) = SAVED_EXCEPTIONS.published(slot) {
            return Some(saved);
        }
        std::hint::spin_loop();
    }
    SAVED_EXCEPTIONS.published(slot)
}

/// The session owner's work: drains every reserved fault into the crash log, then seals
/// the queue so later faults fall back to the emergency log. Falls back to the emergency
/// log for the owner's own fault if the crash log cannot be opened.
fn write_crash_session(address: i64, code: u32) {
    let Some(mut log) = try_open_crash_log() else {
        emergency_exception(address, code);
        return;
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs());
    let _ = write!(log, "Crash log {stamp:016x}\n\n");

    let mut consumed = 0;
    loop {
        while consumed < SAVED_EXCEPTIONS.count() {
            if let Some(saved) = wait_published(consumed) {
                dump_exception(&mut log, saved.address, &saved.context, saved.code);
            } else {
                let _ = writeln!(
                    log,
                    "Reserved exception {consumed} did not finish publishing; skipped."
                );
            }
            consumed += 1;
        }
        if SAVED_EXCEPTIONS.seal_if_drained(consumed) {
            break;
        }
    }
    let _ = writeln!(
        log,
        "Crash session closed (capacity {MAX_SAVED_EXCEPTIONS}); later faults use emergency logging."
    );
    let _ = log.flush();
}

/// Forwards a fault to the dispatcher callback the hook replaced.
///
/// # Safety
///
/// `record` and `context` must be valid for the duration of the call.
unsafe fn forward_to_original(record: *mut EXCEPTION_RECORD, context: *mut CONTEXT) {
    let original = ORIGINAL_DISPATCH_CALLBACK.load(Ordering::Acquire);
    if original == 0 {
        // Wine's stub layout has no callable original callback. The handler stays
        // installed and keeps handling faults there; the Wine path is test-only.
        return;
    }
    // SAFETY: the slot held this function pointer before the hook was written.
    let callback: unsafe extern "system" fn(*mut EXCEPTION_RECORD, *mut CONTEXT) =
        unsafe { std::mem::transmute(original) };
    // SAFETY: forwards the dispatcher's own arguments to its original callback.
    unsafe { callback(record, context) };
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
    if !HANDLER_ACTIVE.load(Ordering::Acquire)
        && ORIGINAL_DISPATCH_CALLBACK.load(Ordering::Acquire) != 0
    {
        // SAFETY: `record` and `context` are valid for the duration of the call.
        unsafe { forward_to_original(record, context) };
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
    let text = protection::ui_localize_default_text();

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
        // The character-index and LUA_CRASH1-3 fixups that the C++ repeats here are
        // left to `protection::except_hook`, which handles them first.
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

/// Logs an unrecognized access violation or non-continuable fault, then suspends the
/// process. Port of the fork's fatal path in `ExceptHook`.
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
    if code != EXCEPTION_ACCESS_VIOLATION && flags & EXCEPTION_NONCONTINUABLE == 0 {
        return;
    }
    let code_bits = code.cast_unsigned();

    // SAFETY: `GetCurrentThreadId` has no preconditions.
    let thread = unsafe { GetCurrentThreadId() };
    if LCK_DUMPING.load(Ordering::Acquire) == thread {
        // A fault inside the dumper itself: log without the crash log machinery.
        emergency_exception(at, code_bits);
        suspend_process();
        return;
    }

    // Reserve before looking for the owner, so the owner cannot seal the session between
    // this thread seeing it and reserving a slot.
    if let Some(slot) = SAVED_EXCEPTIONS.reserve() {
        // SAFETY: `context` is valid for the current exception.
        let context_value = unsafe { *context };
        SAVED_EXCEPTIONS.publish(
            slot,
            SavedException {
                address: at,
                context: context_value,
                code,
            },
        );
    } else {
        emergency_exception(at, code_bits);
    }

    if LCK_DUMPING
        .compare_exchange(0, thread, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        write_crash_session(at, code_bits);
        // Ownership is kept: nothing may append to a sealed session.
        suspend_process();
    } else {
        // Park only this thread; the owner must stay runnable to finish its log.
        // SAFETY: suspends the current thread through its pseudo-handle.
        unsafe { SuspendThread(GetCurrentThread()) };
    }
}

/// Patches the stub on current Windows, which stores a pointer to the handler. The slot's
/// previous value is saved for [`uninstall`].
///
/// # Safety
///
/// `dispatcher` must be the address of `KiUserExceptionDispatcher` in ntdll.
unsafe fn install_pointer_hook(dispatcher: usize, handler: usize) -> Result<(), String> {
    // SAFETY: the dispatcher's first word was checked by the caller to match the pattern.
    let displacement = unsafe { ((dispatcher + 4) as *const i32).read_unaligned() };
    let Some(slot) = rip_relative_target(dispatcher + 8, displacement) else {
        return Err("T7 Patch: exception dispatcher slot is out of range".to_owned());
    };
    FN_PTR_HOOK.store(slot, Ordering::Release);
    // SAFETY: `slot` is the 8-byte callback pointer the dispatcher loads RIP-relatively.
    let original = unsafe { (slot as *const usize).read_unaligned() };
    ORIGINAL_DISPATCH_CALLBACK.store(original, Ordering::Release);
    DISPATCHER_INSTALLED.store(true, Ordering::Release);

    // SAFETY: the slot is an 8-byte pointer inside ntdll's data; nothing is written if it
    // cannot be made writable.
    if !unsafe { crate::arxan::write_usize(slot, handler) } {
        return Err("T7 Patch: cannot write the exception dispatcher slot".to_owned());
    }
    Ok(())
}

/// The target of a RIP-relative operand: `next_instruction` plus the signed `disp32`
/// (fork `7f400a9`), or `None` if it leaves the address space.
fn rip_relative_target(next_instruction: usize, displacement: i32) -> Option<usize> {
    next_instruction.checked_add_signed(isize::try_from(displacement).ok()?)
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
unsafe fn install_wine_hook(dispatcher: usize, handler: usize) -> Result<(), String> {
    let begin = dispatcher + WINE_KI_DISPATCH_OFFSET;
    DISPATCHER_INSTALLED.store(true, Ordering::Release);

    // SAFETY: `begin` is the stub described above; it is rewritten with the new
    // bytes and `write_code` freezes every other thread first.
    match unsafe { crate::threads::write_code(begin, &wine_stub(handler)) } {
        Ok(report) if report.complete() => Ok(()),
        Ok(report) => {
            if !report.bytes_written {
                DISPATCHER_INSTALLED.store(false, Ordering::Release);
            }
            Err("T7 Patch: cannot write the Wine exception dispatcher stub".to_owned())
        }
        Err(error) => {
            if matches!(
                error,
                crate::threads::CodeWriteError::Busy | crate::threads::CodeWriteError::Freeze(_)
            ) {
                DISPATCHER_INSTALLED.store(false, Ordering::Release);
            }
            Err(format!(
                "T7 Patch: cannot write the Wine exception dispatcher stub: {error}"
            ))
        }
    }
}

/// Address of `ntdll!KiUserExceptionDispatcher` and the first word of its code, which
/// selects the layout.
fn dispatcher_layout() -> Result<(usize, i32), String> {
    // SAFETY: resolves ntdll's dispatcher export.
    let dispatcher = unsafe { proc_address(s!("ntdll.dll"), s!("KiUserExceptionDispatcher")) };
    if dispatcher == 0 {
        return Err("T7 Patch: missing exception dispatcher".to_owned());
    }
    // SAFETY: the dispatcher's code is readable; its first word selects the layout.
    let first_word = unsafe { (dispatcher as *const i32).read_unaligned() };
    Ok((dispatcher, first_word))
}

/// Port of the fork's `InstallHook`: installs the exception hook into
/// `KiUserExceptionDispatcher`. An unknown dispatcher layout is an error.
///
/// # Safety
///
/// Must run inside the game process, after ntdll is loaded.
pub unsafe fn install() -> Result<(), String> {
    if DISPATCHER_INSTALLED.load(Ordering::Acquire) {
        // A retained dispatcher is reused; its saved original callback must not be
        // overwritten with our own handler.
        HANDLER_ACTIVE.store(true, Ordering::Release);
        return Ok(());
    }
    let (dispatcher, first_word) = dispatcher_layout()?;
    let handler = exception_hook as *const () as usize;
    let result = if first_word == KI_DISPATCH_PTR_PATTERN {
        // SAFETY: the pattern matches the pointer layout handled by `install_pointer_hook`.
        unsafe { install_pointer_hook(dispatcher, handler) }
    } else if first_word == WINE_STUB_PATTERN {
        // SAFETY: the pattern matches the Wine stub handled by `install_wine_hook`.
        unsafe { install_wine_hook(dispatcher, handler) }
    } else {
        Err("T7 Patch: unsupported exception dispatcher".to_owned())
    };
    if result.is_ok() {
        HANDLER_ACTIVE.store(true, Ordering::Release);
    }
    result
}

/// Records that a patch which can raise an induced exception is live.
///
/// Once this is set, [`uninstall`] retains the dispatcher for the life of the
/// process: a thread may already hold the lobby marker or a detour address.
pub(crate) fn note_exception_producer() {
    PRODUCERS_EXPOSED.store(true, Ordering::Release);
}

/// Port of the fork's `UninstallHook`: restores the dispatcher's original callback when no
/// exception producer was ever exposed. Once the lobby marker or the IAT detour has been
/// written, or on the Wine stub layout, the hook is retained for the process lifetime.
/// Does nothing if the hook was never installed.
///
/// # Safety
///
/// Must run inside the game process.
pub unsafe fn uninstall(producers_remaining: bool) -> Result<(), String> {
    if !DISPATCHER_INSTALLED.load(Ordering::Acquire) {
        return Ok(());
    }
    let (_dispatcher, first_word) = dispatcher_layout()?;
    if first_word == WINE_STUB_PATTERN {
        // The stub is executable code and a handler invocation returns into it.
        // RIP-only freezing cannot prove that no thread will return there, so keep
        // the stub and the handler. Wine is the test layout; native Windows uses
        // the pointer layout below.
        HANDLER_ACTIVE.store(true, Ordering::Release);
        crate::dllmain::debug_print(
            "T7 Patch: Wine exception stub retained for the process lifetime.\n",
        );
        return Ok(());
    }
    if PRODUCERS_EXPOSED.load(Ordering::Acquire) {
        // Keep the trampolines and the dispatcher alive. If a producer could not be
        // restored, keep handling faults too: the induced marker and detour paths
        // are still reachable. Otherwise Unload is a logical deactivation.
        HANDLER_ACTIVE.store(producers_remaining, Ordering::Release);
        crate::dllmain::debug_print(if producers_remaining {
            "T7 Patch: exception dispatcher retained; a producer is still installed.\n"
        } else {
            "T7 Patch: exception dispatcher retained; Unload is logical deactivation.\n"
        });
        return Ok(());
    }
    if first_word == KI_DISPATCH_PTR_PATTERN {
        let slot = FN_PTR_HOOK.load(Ordering::Acquire);
        if slot != 0 {
            let original = ORIGINAL_DISPATCH_CALLBACK.load(Ordering::Acquire);
            // SAFETY: `slot` is the pointer slot written by `install_pointer_hook`, and
            // `original` is the value it held before.
            if !unsafe { crate::arxan::write_usize(slot, original) } {
                return Err("T7 Patch: cannot restore the exception dispatcher slot".to_owned());
            }
        }
    } else {
        return Err("T7 Patch: dispatcher changed before restoration".to_owned());
    }
    HANDLER_ACTIVE.store(false, Ordering::Release);
    PRODUCERS_EXPOSED.store(false, Ordering::Release);
    DISPATCHER_INSTALLED.store(false, Ordering::Release);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rip_relative_target_sign_extends() {
        assert_eq!(
            rip_relative_target(0x7FF8_0000_1008, 0x10),
            Some(0x7FF8_0000_1018)
        );
        assert_eq!(
            rip_relative_target(0x7FF8_0000_1008, -0x8),
            Some(0x7FF8_0000_1000)
        );
        assert_eq!(
            rip_relative_target(0x7FF8_0000_1008, i32::MIN),
            Some(0x7FF7_8000_1008)
        );
        assert_eq!(rip_relative_target(4, -8), None);
    }

    #[test]
    fn wine_stub_embeds_handler_address() {
        let stub = wine_stub(0x1122_3344_5566_7788);
        assert_eq!(&stub[2..10], &0x1122_3344_5566_7788u64.to_le_bytes());
        assert_eq!(stub.len(), WINE_HOOK_SIZE);
        assert_eq!(&stub[0..2], &[0x48, 0xB8]);
    }

    #[test]
    fn emergency_line_formats_hex_in_place() {
        let line = format_emergency_line(0x7FF6_1234_ABCD_0042, 0xC000_0005);
        assert_eq!(
            &line[..],
            b"T7 Patch emergency exception: address=0x7ff61234abcd0042 code=0xc0000005\r\n"
        );
        let line = format_emergency_line(-1, 0);
        assert_eq!(
            &line[..],
            b"T7 Patch emergency exception: address=0xffffffffffffffff code=0x00000000\r\n"
        );
        assert_eq!(&format_emergency_line(0, 0)[..], EMERGENCY_TEMPLATE);
    }

    #[test]
    fn stack_line_address_rejects_overflow() {
        assert_eq!(stack_line_address(0x1000, 0x20), Some(0x1020));
        assert_eq!(
            stack_line_address(usize::MAX - 16, 0),
            Some(usize::MAX - 16)
        );
        assert_eq!(stack_line_address(usize::MAX - 15, 0), None);
        assert_eq!(
            stack_line_address(usize::MAX - 20, 4),
            Some(usize::MAX - 16)
        );
        assert_eq!(stack_line_address(usize::MAX - 20, 5), None);
        assert_eq!(stack_line_address(usize::MAX, 1), None);
        assert_eq!(stack_line_address(1, usize::MAX), None);
        assert_eq!(stack_line_address(usize::MAX, 0), None);
    }

    #[test]
    fn read_stack_line_reads_live_memory_and_rejects_bad_addresses() {
        let words = [0x1122_3344_5566_7788_u64, 0x99AA_BBCC_DDEE_FF00];
        let base = words.as_ptr() as usize;
        assert_eq!(read_stack_line(base, 0), Some(words));
        assert_eq!(read_stack_line(0, 0), None);
        assert_eq!(read_stack_line(usize::MAX - 8, 0), None);
    }

    #[test]
    fn gsc_clientfield_list_is_unique() {
        let mut sorted = GSC_CLIENTFIELD_CRASHES;
        sorted.sort_unstable();
        assert!(sorted.windows(2).all(|pair| pair[0] != pair[1]));
    }
}
