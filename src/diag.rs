//! In-game diagnostics with no C++ counterpart. Nothing here is installed unless
//! `T7PATCH_ONLY` names it (see `dllmain::Components`).
//!
//! `trace` hooks the game function at February RVA `0x1EEA130`, which builds a
//! `LobbyMsg` from `(data = r8, size = r9d)` and reads it with
//! `LobbyMsgRW_PackageUInt`. Runs 2, 9 and 11 crashed there on a NULL `data`
//! with size 22 (`docs/in-game-findings.md`). Its callers are hidden behind
//! Arxan-encoded stack values, so the hook logs the return address and
//! arguments of the first few calls and of every call with NULL data. With
//! `trace` on, [`trace`] also logs decisions elsewhere, such as each verdict of
//! `protection::check_pending_info_requests`.

use std::fmt::Write;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use windows::Win32::System::Diagnostics::Debug::{OutputDebugStringA, ReadProcessMemory};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::core::PCSTR;

use crate::{build, dllmain::debug_print, ffi, offsets};

/// February RVA of the traced function.
pub const TRACED_LOBBY_READ: usize = 0x1EEA130;
/// Calls logged regardless of their arguments, to show the usual callers.
const FIRST_CALLS_LOGGED: u32 = 4;
/// NULL-data calls logged before the hook goes quiet.
const NULL_CALLS_LOGGED: u32 = 16;
/// Stack words logged from the entry RSP, the return address first.
const STACK_WORDS: usize = 12;

/// Trampoline to the original function. Read by the thunk as a plain pointer,
/// which `AtomicUsize` is laid out as.
static ORIG_TRACED: AtomicUsize = AtomicUsize::new(0);
static CALLS: AtomicU32 = AtomicU32::new(0);
/// Set once the trace hook exists, so other modules' [`trace`] lines are emitted.
static TRACING: AtomicBool = AtomicBool::new(false);
static NULL_CALLS: AtomicU32 = AtomicU32::new(0);

// The detour. It keeps the four argument registers, passes them and the entry
// RSP (which points at the return address) to `trace_call`, then tail-jumps to
// the trampoline with the argument registers and the stack as they were on entry.
// RAX, R10, R11, XMM0-5 and the flags are not preserved; they are volatile and
// the traced function's prologue reads none of them. Four pushes and 0x38 bytes
// keep RSP 16-byte aligned at the call (entry RSP is 8 mod 16), with shadow space
// and a fifth-argument slot. The `.seh_*` directives emit unwind data for that
// prologue, so a stack walk from inside `trace_call` gets through this frame.
std::arch::global_asm!(
    ".globl t7patch_trace_lobby_read",
    ".def t7patch_trace_lobby_read",
    ".scl 2",
    ".type 32",
    ".endef",
    "t7patch_trace_lobby_read:",
    ".seh_proc t7patch_trace_lobby_read",
    "push rcx",
    ".seh_pushreg rcx",
    "push rdx",
    ".seh_pushreg rdx",
    "push r8",
    ".seh_pushreg r8",
    "push r9",
    ".seh_pushreg r9",
    "sub rsp, 0x38",
    ".seh_stackalloc 0x38",
    ".seh_endprologue",
    "lea rax, [rsp + 0x58]",
    "mov qword ptr [rsp + 0x20], rax",
    "call {trace}",
    "add rsp, 0x38",
    "pop r9",
    "pop r8",
    "pop rdx",
    "pop rcx",
    "jmp qword ptr [rip + {orig}]",
    ".seh_endproc",
    trace = sym trace_call,
    orig = sym ORIG_TRACED,
);

unsafe extern "system" {
    fn t7patch_trace_lobby_read();
}

/// Copies `out.len()` words from `address` without faulting. Returns how many
/// were read.
fn read_words(address: usize, out: &mut [u64]) -> usize {
    let mut copied = 0usize;
    // SAFETY: `ReadProcessMemory` validates the source range and fails instead of
    // faulting; the destination is `out`, which is `size_of_val(out)` bytes.
    let read = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address as *const core::ffi::c_void,
            out.as_mut_ptr().cast(),
            size_of_val(out),
            Some(&raw mut copied),
        )
    };
    if read.is_ok() {
        copied / size_of::<u64>()
    } else {
        0
    }
}

/// A log line on the stack, so tracing does not allocate on the game thread.
/// Text past the capacity is dropped; the last byte is kept for the NUL.
struct Line {
    bytes: [u8; LINE_CAPACITY],
    len: usize,
}

const LINE_CAPACITY: usize = 512;

impl Line {
    const fn new() -> Self {
        Self {
            bytes: [0; LINE_CAPACITY],
            len: 0,
        }
    }

    #[cfg(test)]
    fn text(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    /// Sends the line to the debugger output.
    fn emit(&mut self) {
        self.bytes[self.len.min(LINE_CAPACITY - 1)] = 0;
        // SAFETY: the buffer is NUL-terminated at or before its last byte.
        unsafe { OutputDebugStringA(PCSTR(self.bytes.as_ptr())) };
    }
}

impl Write for Line {
    fn write_str(&mut self, text: &str) -> std::fmt::Result {
        let room = LINE_CAPACITY - 1 - self.len;
        let take = text.len().min(room);
        self.bytes[self.len..self.len + take].copy_from_slice(&text.as_bytes()[..take]);
        self.len += take;
        Ok(())
    }
}

/// Writes a code address relative to the game image when it lies inside it.
fn write_address(out: &mut Line, address: u64) {
    let base = build::image_base() as u64;
    let _ = match address.checked_sub(base) {
        Some(rva) if base != 0 && rva < 0x2000_0000 => write!(out, " game+{rva:X}"),
        _ => write!(out, " {address:016x}"),
    };
}

/// Called by the thunk on every call of the traced function.
extern "system" fn trace_call(rcx: u64, rdx: u64, r8: u64, r9: u64, entry_rsp: usize) {
    let call = CALLS.fetch_add(1, Ordering::Relaxed);
    let null_data = r8 == 0;
    let null_call = if null_data {
        NULL_CALLS.fetch_add(1, Ordering::Relaxed)
    } else {
        u32::MAX
    };
    if call >= FIRST_CALLS_LOGGED && !(null_data && null_call < NULL_CALLS_LOGGED) {
        return;
    }
    let mut stack = [0u64; STACK_WORDS];
    let words = read_words(entry_rsp, &mut stack);
    let mut line = Line::new();
    let _ = write!(
        line,
        "T7 Patch trace 0x1EEA130 call {call}{}: rcx={rcx:x} rdx={rdx:x} r8={r8:x} r9={r9:x} rsp={entry_rsp:x} stack (return address first):",
        if null_data { " NULL-DATA" } else { "" },
    );
    if words == 0 {
        let _ = line.write_str(" unreadable");
    }
    for &word in &stack[..words] {
        write_address(&mut line, word);
    }
    let _ = line.write_str("\n");
    line.emit();
}

/// Emits a trace line while `trace` is on; does nothing otherwise. Formats into a
/// stack buffer, so it does not allocate on the game thread.
pub fn trace(args: std::fmt::Arguments<'_>) {
    if !TRACING.load(Ordering::Acquire) {
        return;
    }
    let mut line = Line::new();
    let _ = line.write_fmt(args);
    line.emit();
}

/// Creates the trace hook. It is enabled with the other hooks.
pub fn create_trace_hook() -> Result<(), String> {
    // SAFETY: the thunk preserves the traced function's arguments and stack and
    // jumps to the trampoline stored below before the hook can be enabled.
    let trampoline = unsafe {
        ffi::create_hook(
            offsets::address(TRACED_LOBBY_READ),
            t7patch_trace_lobby_read as *const () as usize,
        )
    }
    .map_err(|error| format!("T7 Patch: trace hook creation failed: {error}"))?;
    ORIG_TRACED.store(trampoline, Ordering::Release);
    TRACING.store(true, Ordering::Release);
    debug_print("T7 Patch: trace hook on 0x1EEA130 created\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn read_words_reads_live_memory_and_rejects_bad_addresses() {
        let words = [1u64, 2, 3];
        let mut out = [0u64; 3];
        assert_eq!(read_words(words.as_ptr() as usize, &mut out), 3);
        assert_eq!(out, words);
        assert_eq!(read_words(0, &mut out), 0);
    }

    extern "system" fn traced_stand_in(a: u32, b: u64, c: u64, d: u32) -> u64 {
        u64::from(a) ^ b.rotate_left(8) ^ c.rotate_left(16) ^ u64::from(d).rotate_left(24)
    }

    #[test]
    fn thunk_passes_arguments_and_result_through_and_counts_calls() {
        type Traced = unsafe extern "system" fn(u32, u64, u64, u32) -> u64;
        ORIG_TRACED.store(traced_stand_in as *const () as usize, Ordering::Release);
        // SAFETY: the thunk has the stand-in's ABI; it forwards to `ORIG_TRACED`.
        let thunk: Traced = unsafe { std::mem::transmute(t7patch_trace_lobby_read as *const ()) };
        let before = CALLS.load(Ordering::Relaxed);
        let nulls = NULL_CALLS.load(Ordering::Relaxed);
        for (a, b, c, d) in [(7, 0x1111, 0x2222, 22), (1, 0xDEAD_BEEF, 0, 0x16)] {
            // SAFETY: as above.
            let result = unsafe { thunk(a, b, c, d) };
            assert_eq!(result, traced_stand_in(a, b, c, d));
        }
        assert_eq!(CALLS.load(Ordering::Relaxed), before + 2);
        assert_eq!(NULL_CALLS.load(Ordering::Relaxed), nulls + 1);
    }

    #[test]
    fn line_marks_addresses_outside_the_image_and_truncates() {
        let mut line = Line::new();
        write_address(&mut line, 0x1234);
        assert_eq!(line.text(), b" 0000000000001234");
        for _ in 0..100 {
            let _ = line.write_str("0123456789");
        }
        assert_eq!(line.text().len(), LINE_CAPACITY - 1);
        line.emit();
        assert_eq!(line.bytes[LINE_CAPACITY - 1], 0);
    }
}
