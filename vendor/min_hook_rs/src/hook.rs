//! Hook management for MinHook-rs
//!
//! This module provides the main API for creating, enabling, disabling, and managing function hooks.
//! It is a direct port of MinHook's hook.c.
//!
//! The core logic includes:
//! - Global hook manager with thread-safe access (using Mutex)
//! - Dynamic allocation and management of hook entries
//! - Thread freezing and context adjustment for safe patching
//! - API for creating, removing, enabling, disabling, and queuing hooks
//! - Utility for working with Windows modules and function addresses
//!
//! Vendored into T7Patch-rs and patched: the freeze fails closed and hook changes
//! apply as one transaction. See `VENDORED.md`.

use crate::buffer::{
    MEMORY_SLOT_SIZE, free_buffer, initialize_buffer, is_executable_address, uninitialize_buffer,
};
use crate::error::{HookError, Result};
use crate::instruction::*;
use crate::trampoline::create_trampoline;
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use windows_sys::Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SystemProcessInformation,
};
use windows_sys::Wdk::System::Threading::{NtQueryInformationThread, ThreadBasicInformation};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Hook module only supports x86_64 architecture");

/// Initial capacity for the hook entry buffer.
const INITIAL_HOOK_CAPACITY: usize = 32;
/// Upper bound on the threads one freeze may hold. A game process has far fewer.
const MAX_THREADS: usize = 512;
/// How many freeze attempts may be disturbed (a thread created during the freeze,
/// or one whose suspension could not be confirmed) before the freeze is abandoned.
const FREEZE_ATTEMPTS: usize = 16;
/// Smallest process-information buffer; grown before the freeze when too small.
const MIN_PROCESS_BUFFER: usize = 256 * 1024;
/// Special value indicating an invalid hook position.
const INVALID_HOOK_POS: usize = usize::MAX;
/// Thread access rights for suspending/resuming threads.
const THREAD_ACCESS: u32 = THREAD_SUSPEND_RESUME
    | THREAD_GET_CONTEXT
    | THREAD_QUERY_INFORMATION
    | THREAD_SET_CONTEXT
    | THREAD_SYNCHRONIZE;
/// How many times a failed `ResumeThread` is retried before the thread is declared stuck.
const RESUME_ATTEMPTS: usize = 3;
/// How many times a failed protection restore is retried.
const RESTORE_ATTEMPTS: usize = 3;
const PAGE_SIZE: usize = 0x1000;
/// Most pages one patch range (at most 7 bytes) can touch.
const MAX_PATCH_PAGES: usize = 2;

/// Set once a frozen thread could not be resumed. Its handle is leaked on purpose
/// and every later hook change is refused with [`HookError::ThreadResume`].
static THAW_FAILED: AtomicBool = AtomicBool::new(false);

/// True once a freeze left a live thread suspended. Terminal for the process.
pub fn thaw_failed() -> bool {
    THAW_FAILED.load(Ordering::Acquire)
}

/// Set once a patched page could not be returned to its original protection.
static PROTECTION_LOST: AtomicBool = AtomicBool::new(false);

/// True once a hook change left a page with a changed (writable) protection.
pub fn protection_lost() -> bool {
    PROTECTION_LOST.load(Ordering::Acquire)
}

/// Set once the instruction cache could not be flushed over a patch.
static FLUSH_FAILED: AtomicBool = AtomicBool::new(false);

/// True once an instruction cache flush over a patch failed.
pub fn flush_failed() -> bool {
    FLUSH_FAILED.load(Ordering::Acquire)
}

/// Represents a single hook entry.
#[derive(Debug, Clone)]
struct HookEntry {
    /// Address of the target function.
    target: *mut c_void,
    /// Address of the detour or relay function.
    detour: *mut c_void,
    /// Address of the trampoline function.
    trampoline: *mut c_void,
    /// Backup of the original prologue of the target function.
    backup: [u8; 8],
    /// Whether the hot patch area is used.
    patch_above: bool,
    /// Whether the hook is currently enabled.
    is_enabled: bool,
    /// Whether the hook is queued for enabling/disabling.
    queue_enable: bool,
    /// Number of instruction boundaries.
    n_ip: u32,
    /// Instruction boundaries of the target function.
    old_ips: [u8; 8],
    /// Instruction boundaries of the trampoline function.
    new_ips: [u8; 8],
}

/// Stores all hook entries and allocation info.
struct HookCollection {
    items: Vec<HookEntry>,
    capacity: usize,
    size: usize,
}

/// Global hook manager, responsible for all hook operations.
struct HookManager {
    /// Indicates if the library is initialized.
    heap: bool,
    /// Collection of all hook entries.
    hooks: HookCollection,
    /// Set once a trampoline slot was kept because a thread might still reach it.
    /// From then on the trampoline buffers are never released.
    retain_buffers: bool,
}

/// Global singleton for the hook manager, protected by a Mutex.
static HOOK_MANAGER: OnceLock<Mutex<HookManager>> = OnceLock::new();

impl HookEntry {
    /// Creates a new, empty hook entry.
    fn new() -> Self {
        Self {
            target: ptr::null_mut(),
            detour: ptr::null_mut(),
            trampoline: ptr::null_mut(),
            backup: [0; 8],
            patch_above: false,
            is_enabled: false,
            queue_enable: false,
            n_ip: 0,
            old_ips: [0; 8],
            new_ips: [0; 8],
        }
    }

    /// Returns the start and length of the bytes the hook overwrites.
    fn patch_range(&self) -> (*mut u8, usize) {
        if self.patch_above {
            (
                (self.target as *mut u8).wrapping_sub(size_of::<JmpRel>()),
                size_of::<JmpRel>() + size_of::<JmpRelShort>(),
            )
        } else {
            (self.target as *mut u8, size_of::<JmpRel>())
        }
    }

    /// Writes the jump (`enable`) or the original prologue (`!enable`).
    ///
    /// # Safety
    ///
    /// The patch range must be writable and no thread may be executing it.
    unsafe fn write_patch(&self, enable: bool) {
        let (patch_target, _) = self.patch_range();
        // SAFETY: the caller made the patch range writable and froze every other thread.
        unsafe {
            if enable {
                let jmp = JmpRel::new_jmp(
                    (self.detour as isize - (patch_target as isize + size_of::<JmpRel>() as isize))
                        as i32,
                );
                ptr::copy_nonoverlapping(
                    &jmp as *const JmpRel as *const u8,
                    patch_target,
                    size_of::<JmpRel>(),
                );
                if self.patch_above {
                    let short_jmp = JmpRelShort::new(
                        -(size_of::<JmpRelShort>() as i8 + size_of::<JmpRel>() as i8),
                    );
                    ptr::copy_nonoverlapping(
                        &short_jmp as *const JmpRelShort as *const u8,
                        self.target as *mut u8,
                        size_of::<JmpRelShort>(),
                    );
                }
            } else if self.patch_above {
                ptr::copy_nonoverlapping(
                    self.backup.as_ptr(),
                    patch_target,
                    size_of::<JmpRel>() + size_of::<JmpRelShort>(),
                );
            } else {
                ptr::copy_nonoverlapping(self.backup.as_ptr(), patch_target, size_of::<JmpRel>());
            }
        }
    }
}

/// Finds the original instruction pointer for a thread, used when disabling a hook.
fn find_old_ip(hook: &HookEntry, ip: usize) -> usize {
    if hook.patch_above && ip == (hook.target as usize - size_of::<JmpRel>()) {
        return hook.target as usize;
    }
    for i in 0..hook.n_ip as usize {
        if ip == (hook.trampoline as usize + hook.new_ips[i] as usize) {
            return hook.target as usize + hook.old_ips[i] as usize;
        }
    }
    if ip == hook.detour as usize {
        return hook.target as usize;
    }
    0
}

/// Finds the new instruction pointer for a thread, used when enabling a hook.
fn find_new_ip(hook: &HookEntry, ip: usize) -> usize {
    for i in 0..hook.n_ip as usize {
        if ip == (hook.target as usize + hook.old_ips[i] as usize) {
            return hook.trampoline as usize + hook.new_ips[i] as usize;
        }
    }
    0
}

/// Computes where a thread suspended at `ip` must resume once every `(pos, enable)`
/// change in `batch` is applied. Pure: reads the hook table only.
fn plan_ip(hooks: &[HookEntry], batch: &[(usize, bool)], ip: usize) -> usize {
    let mut ip = ip;
    for &(pos, enable) in batch {
        let hook = &hooks[pos];
        let moved = if enable {
            find_new_ip(hook, ip)
        } else {
            find_old_ip(hook, ip)
        };
        if moved != 0 {
            ip = moved;
        }
    }
    ip
}

/// A thread context buffer. `GetThreadContext` and `SetThreadContext` need 16-byte
/// alignment on x64, which the `windows-sys` `CONTEXT` type does not carry.
#[repr(C, align(16))]
#[derive(Clone, Copy)]
struct AlignedContext(CONTEXT);

impl AlignedContext {
    /// A buffer for the one context read per frozen thread: the control registers,
    /// which a move rewrites, and the integer registers, which the slot check reads.
    fn captured() -> Self {
        // SAFETY: `CONTEXT` is plain data; all-zero is a valid value.
        let mut context = Self(unsafe { std::mem::zeroed::<CONTEXT>() });
        context.0.ContextFlags = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;
        context
    }

    /// A copy of a captured context that resumes at `ip` and writes back only the
    /// control registers, as a move always did. The integer registers are left alone.
    fn moved_to(&self, ip: u64) -> Self {
        let mut context = *self;
        context.0.ContextFlags = CONTEXT_CONTROL_AMD64;
        context.0.Rip = ip;
        context
    }
}

/// Most bytes of one thread's stack the slot check reads. A larger span counts as
/// unknown, so the slot is kept rather than scanned in part.
const MAX_STACK_SCAN_BYTES: usize = 64 * 1024 * 1024;
/// Most stack bytes one transaction reads across every thread, so the time threads
/// stay frozen is bounded. Past it the remaining threads count as unknown.
const MAX_TOTAL_SCAN_BYTES: usize = 256 * 1024 * 1024;
/// Words the stack scan reads at a time, into a fixed buffer.
const STACK_CHUNK_WORDS: usize = 64;

/// The trampoline slots a transaction may free, sorted. Built before the freeze.
struct SlotSet {
    starts: Vec<usize>,
    /// A slot whose end overflows the address space: nothing can be proven about it.
    malformed: bool,
}

impl SlotSet {
    /// Allocates, so it runs before any thread is suspended.
    fn new(starts: impl Iterator<Item = usize>) -> Self {
        let mut starts: Vec<usize> = starts.collect();
        starts.sort_unstable();
        let malformed = starts
            .iter()
            .any(|&start| start.checked_add(MEMORY_SLOT_SIZE).is_none());
        Self { starts, malformed }
    }

    fn is_empty(&self) -> bool {
        self.starts.is_empty()
    }

    /// True when `address` lies in `[start, start + MEMORY_SLOT_SIZE)` of a slot.
    fn contains(&self, address: usize) -> bool {
        // The last slot starting at or below `address`.
        let after = self.starts.partition_point(|&start| start <= address);
        after > 0 && address - self.starts[after - 1] < MEMORY_SLOT_SIZE
    }

    fn contains_word(&self, word: u64) -> bool {
        usize::try_from(word).is_ok_and(|address| self.contains(address))
    }
}

/// How a frozen thread may still reach a slot. Anything but `Clear` keeps the slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reach {
    Clear,
    /// Its instruction pointer, once moved, lies in a slot.
    Rip,
    /// A general-purpose register holds an address in a slot.
    Register,
    /// A word on its live stack holds an address in a slot.
    Stack,
    /// Its stack could not be read in full, so nothing is known.
    Unknown,
}

/// The general-purpose registers of a captured context, RSP included.
fn registers(context: &CONTEXT) -> [u64; 16] {
    [
        context.Rax,
        context.Rbx,
        context.Rcx,
        context.Rdx,
        context.Rsi,
        context.Rdi,
        context.Rbp,
        context.Rsp,
        context.R8,
        context.R9,
        context.R10,
        context.R11,
        context.R12,
        context.R13,
        context.R14,
        context.R15,
    ]
}

/// Scans `[rsp, base)` for a word in `slots`, `STACK_CHUNK_WORDS` at a time, and
/// charges the bytes read to `budget`. `read` fills its buffer from an address and
/// fails instead of faulting. A zero or misaligned base, an RSP outside the stack,
/// a span past the limits, or a failed read is `Unknown`. Allocation-free; never
/// writes the stack.
fn scan_stack(
    rsp: usize,
    base: usize,
    slots: &SlotSet,
    budget: &mut usize,
    mut read: impl FnMut(usize, &mut [u64]) -> bool,
) -> Reach {
    if rsp == 0 || base == 0 || !base.is_multiple_of(8) || rsp > base {
        return Reach::Unknown;
    }
    let mut cursor = rsp & !7;
    let span = base - cursor;
    if span > MAX_STACK_SCAN_BYTES || span > *budget {
        return Reach::Unknown;
    }
    *budget -= span;
    let mut chunk = [0u64; STACK_CHUNK_WORDS];
    while cursor < base {
        let words = ((base - cursor) / 8).min(STACK_CHUNK_WORDS);
        if !read(cursor, &mut chunk[..words]) {
            return Reach::Unknown;
        }
        if chunk[..words].iter().any(|&word| slots.contains_word(word)) {
            return Reach::Stack;
        }
        cursor += words * 8;
    }
    Reach::Clear
}

/// Whether a frozen thread, resuming at `new_ip`, may still reach a slot: by RIP, by
/// a register, or by a word on its live stack (`base` is its `NT_TIB.StackBase`, or
/// `None` if that could not be read).
fn reach(
    context: &CONTEXT,
    new_ip: usize,
    base: Option<usize>,
    slots: &SlotSet,
    budget: &mut usize,
    read: impl FnMut(usize, &mut [u64]) -> bool,
) -> Reach {
    if slots.malformed {
        return Reach::Unknown;
    }
    if slots.contains(new_ip) {
        return Reach::Rip;
    }
    if registers(context)
        .iter()
        .any(|&value| slots.contains_word(value))
    {
        return Reach::Register;
    }
    let Some(base) = base else {
        return Reach::Unknown;
    };
    let rsp = usize::try_from(context.Rsp).unwrap_or(0);
    scan_stack(rsp, base, slots, budget, read)
}

/// A suspended thread whose instruction pointer must move.
struct ThreadMove {
    handle: HANDLE,
    context: AlignedContext,
    original_ip: u64,
}

/// Threads suspended by [`FrozenThreads::freeze`], with the context read from each
/// while confirming its suspension. Each handle stays open until its thread is
/// resumed by [`FrozenThreads::thaw`]. Drop thaws too, as a safety net for an early
/// return, but cannot report a failure, so error paths thaw explicitly through
/// [`FrozenThreads::abort`].
struct FrozenThreads {
    handles: Vec<HANDLE>,
    /// `contexts[i]` is the context of `handles[i]`, read once it was suspended.
    contexts: Vec<AlignedContext>,
    active: bool,
}

/// What [`FrozenThreads::open_suspend`] found.
enum Suspension {
    /// The thread is suspended and its handle held.
    Held,
    /// The thread has exited, or its id names no thread of this process.
    Gone,
    /// The thread could not be opened or suspended and is not confirmed to have
    /// exited. The attempt must be thawed and retried.
    Disturbed,
}

impl FrozenThreads {
    /// Suspends every other thread of the process, verified against threads created
    /// while the freeze runs. Fails closed: if a live thread cannot be opened,
    /// suspended or confirmed suspended in any of the bounded attempts, or new threads
    /// keep appearing, the threads already suspended are resumed and an error is
    /// returned. A thread whose handle is signaled has terminated and is skipped.
    fn freeze(list: &mut ThreadList) -> Result<Self> {
        // Allocate before suspending: a suspended thread may hold the heap lock.
        let mut frozen = Self {
            handles: Vec::with_capacity(MAX_THREADS),
            contexts: Vec::with_capacity(MAX_THREADS),
            active: false,
        };
        let mut seen = IdSet::new();
        let mut gone = IdSet::new();
        let mut fresh = IdSet::new();
        let mut disturbed = HookError::ThreadSuspend;
        for _attempt in 0..FREEZE_ATTEMPTS {
            seen.clear();
            gone.clear();
            frozen.active = true;
            match frozen.attempt(list, &mut seen, &mut gone, &mut fresh) {
                Ok(None) => return Ok(frozen),
                Ok(Some(error)) => {
                    disturbed = error;
                    if !frozen.thaw() {
                        return Err(HookError::ThreadResume);
                    }
                    // Let a starting or exiting thread settle before retrying. Never
                    // wait while threads are suspended: the thread may need one of them.
                    // SAFETY: Sleep takes a plain duration.
                    unsafe { Sleep(1) };
                }
                Err(error) => return Err(frozen.abort(error)),
            }
        }
        Err(disturbed)
    }

    // An enumeration is a snapshot, not a creation barrier: a thread not yet
    // suspended can create another. One attempt suspends every thread of a
    // snapshot, reads their contexts (which waits for `SuspendThread` to take
    // effect), and enumerates again. A thread in the second list but not the first
    // was created during the freeze. It is never suspended, and the attempt is
    // thawed and retried instead. Returns the disturbance, or `None` once frozen.
    //
    // Under Wine a thread whose creator was suspended between registering it and
    // starting it never reaches its suspension, so reading its context waits forever
    // with every other thread frozen. Such a thread has no TEB yet, so the context
    // is read only once the TEB is set; a thread without one also retries. On
    // Windows the TEB is set when the thread is created.
    //
    // A thread that cannot be opened or suspended and whose handle is not signaled
    // retries too: Windows refuses to suspend a thread that is terminating
    // (`STATUS_THREAD_IS_TERMINATING`) before its handle is signaled, and such a
    // thread may still run user-mode code (DLL detach).
    //
    // `gone` holds the ids whose thread had exited. One listed again on the second
    // enumeration is checked once more: if its id now names a live thread of this
    // process, a new thread was given the recycled id, which is a disturbance.
    fn attempt(
        &mut self,
        list: &mut ThreadList,
        seen: &mut IdSet,
        gone: &mut IdSet,
        fresh: &mut IdSet,
    ) -> Result<Option<HookError>> {
        fresh.clear();
        list.enumerate(fresh)?;
        #[cfg(test)]
        fault::hide_threads(fresh);
        for &id in fresh.as_slice() {
            match self.open_suspend(id)? {
                Suspension::Held => seen.insert(id)?,
                Suspension::Gone => gone.insert(id)?,
                Suspension::Disturbed => return Ok(Some(HookError::ThreadSuspend)),
            }
        }
        for &handle in &self.handles {
            // SAFETY: `handle` is an open thread this freeze suspended.
            match unsafe { sys::started(handle) } {
                Some(true) => {}
                Some(false) => return Ok(Some(HookError::ThreadSuspend)),
                None => return Ok(Some(HookError::ThreadContext)),
            }
            let mut context = AlignedContext::captured();
            // SAFETY: as above; the thread has started, so its suspension takes effect.
            if !unsafe { sys::get_context(handle, &mut context) } {
                return Ok(Some(HookError::ThreadContext));
            }
            // Never grows: both vectors hold MAX_THREADS and pair with `handles`.
            self.contexts.push(context);
        }
        fresh.clear();
        list.enumerate(fresh)?;
        #[cfg(test)]
        fault::hide_threads(fresh);
        for &id in fresh.as_slice() {
            let known = seen.contains(id) || (gone.contains(id) && still_gone(id)?);
            if !known {
                return Ok(Some(HookError::ThreadSuspend));
            }
        }
        Ok(None)
    }

    /// Opens and suspends `id`.
    fn open_suspend(&mut self, id: u32) -> Result<Suspension> {
        if self.handles.len() >= MAX_THREADS {
            // Never grow while threads are suspended.
            return Err(HookError::ThreadSuspend);
        }
        // SAFETY: plain Win32 calls on a handle this function opens and owns.
        unsafe {
            let handle = sys::open_thread(id);
            if handle.is_null() {
                // The id no longer names a thread: it exited after the enumeration.
                if GetLastError() == ERROR_INVALID_PARAMETER {
                    return Ok(Suspension::Gone);
                }
                return Ok(Suspension::Disturbed);
            }
            let owner = GetProcessIdOfThread(handle);
            if owner != GetCurrentProcessId() {
                CloseHandle(handle);
                // A reused id now names another process's thread; ours exited.
                // Zero means the query failed, which proves nothing.
                return Ok(if owner != 0 {
                    Suspension::Gone
                } else {
                    Suspension::Disturbed
                });
            }
            if !sys::suspend_thread(handle) {
                let state = liveness(handle);
                CloseHandle(handle);
                return match state {
                    Liveness::Exited => Ok(Suspension::Gone),
                    Liveness::Running => Ok(Suspension::Disturbed),
                    Liveness::Unknown => Err(HookError::ThreadSuspend),
                };
            }
            self.handles.push(handle);
        }
        Ok(Suspension::Held)
    }

    /// Thaws after `error` and returns the error to report: `error` itself, or
    /// [`HookError::ThreadResume`] when a thread stayed suspended.
    fn abort(&mut self, error: HookError) -> HookError {
        if self.thaw() {
            error
        } else {
            HookError::ThreadResume
        }
    }

    /// Resumes every suspended thread exactly once. A thread that stays suspended
    /// keeps its handle open, so its id cannot be reused under us, and sets
    /// [`THAW_FAILED`]. Returns `false` in that case. Allocation-free.
    fn thaw(&mut self) -> bool {
        if !self.active {
            return true;
        }
        self.active = false;
        let mut thawed = true;
        for &handle in &self.handles {
            if resume_one(handle) {
                // SAFETY: `handle` was opened by `freeze` and its thread is running or gone.
                unsafe { CloseHandle(handle) };
            } else {
                thawed = false;
                #[cfg(test)]
                fault::stuck(handle);
            }
        }
        self.handles.clear();
        self.contexts.clear();
        if !thawed {
            THAW_FAILED.store(true, Ordering::Release);
        }
        thawed
    }
}

impl Drop for FrozenThreads {
    fn drop(&mut self) {
        // Safety net for an early return or panic: never leave the process suspended.
        let _ = self.thaw();
    }
}

/// Resumes a thread `freeze` suspended, retrying a failure. A thread that has
/// terminated counts as resumed.
fn resume_one(handle: HANDLE) -> bool {
    for attempt in 0..RESUME_ATTEMPTS {
        if attempt > 0 {
            // SAFETY: Sleep takes a plain duration.
            unsafe { Sleep(1) };
        }
        // SAFETY: `handle` is open with THREAD_SUSPEND_RESUME and was suspended by `freeze`.
        if unsafe { sys::resume_thread(handle) } {
            return true;
        }
    }
    matches!(liveness(handle), Liveness::Exited)
}

/// True when `id` names no live thread of this process. An id that cannot be opened,
/// or whose owner cannot be read, counts as live, so the caller retries rather than
/// trusting it. A failed wait fails closed.
fn still_gone(id: u32) -> Result<bool> {
    // SAFETY: plain Win32 calls on a handle this function opens and closes.
    unsafe {
        let handle = sys::open_thread(id);
        if handle.is_null() {
            return Ok(GetLastError() == ERROR_INVALID_PARAMETER);
        }
        let owner = GetProcessIdOfThread(handle);
        let gone = if owner == 0 {
            Ok(false)
        } else if owner != GetCurrentProcessId() {
            Ok(true)
        } else {
            match liveness(handle) {
                Liveness::Exited => Ok(true),
                Liveness::Running => Ok(false),
                Liveness::Unknown => Err(HookError::ThreadSuspend),
            }
        };
        CloseHandle(handle);
        gone
    }
}

/// Whether a thread has terminated, from its handle's signaled state. The exit code
/// cannot tell: it stays `STILL_ACTIVE` while a thread terminates, and a thread may
/// exit with that very code.
enum Liveness {
    Exited,
    Running,
    /// The wait failed, so nothing is known.
    Unknown,
}

fn liveness(handle: HANDLE) -> Liveness {
    // SAFETY: `handle` is an open thread handle with SYNCHRONIZE; a zero timeout
    // never blocks.
    match unsafe { sys::wait(handle) } {
        WAIT_OBJECT_0 => Liveness::Exited,
        WAIT_TIMEOUT => Liveness::Running,
        _ => Liveness::Unknown,
    }
}

/// A fixed-capacity, duplicate-free set of thread ids. Never allocates.
struct IdSet {
    ids: [u32; MAX_THREADS],
    len: usize,
}

impl IdSet {
    const fn new() -> Self {
        Self {
            ids: [0; MAX_THREADS],
            len: 0,
        }
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    fn as_slice(&self) -> &[u32] {
        &self.ids[..self.len]
    }

    fn contains(&self, id: u32) -> bool {
        self.as_slice().contains(&id)
    }

    /// Adds `id` unless it is already present.
    fn insert(&mut self, id: u32) -> Result<()> {
        if self.contains(id) {
            return Ok(());
        }
        if self.len >= MAX_THREADS {
            return Err(HookError::ThreadSuspend);
        }
        self.ids[self.len] = id;
        self.len += 1;
        Ok(())
    }
}

/// Lists this process's threads through `NtQuerySystemInformation`, into a buffer
/// sized before the freeze, so enumerating again while threads are suspended does
/// not allocate on the Rust side. Toolhelp is not used: Wine's
/// `CreateToolhelp32Snapshot` allocates from the process heap, which a suspended
/// thread may hold locked. Wine's own enumeration still allocates on its Unix
/// side; see the Known limits in `VENDORED.md`.
struct ThreadList {
    process_id: u32,
    current_thread: u32,
    /// `SYSTEM_PROCESS_INFORMATION` buffer, 8-byte aligned.
    buffer: Vec<u64>,
}

impl ThreadList {
    /// Sizes the buffer with headroom. Allocates, so it runs before any freeze.
    fn new() -> Result<Self> {
        // SAFETY: both queries take no arguments and cannot fail.
        let (process_id, current_thread) = unsafe { (GetCurrentProcessId(), GetCurrentThreadId()) };
        let mut bytes = MIN_PROCESS_BUFFER;
        for _attempt in 0..8 {
            let mut buffer = vec![0u64; bytes / 8];
            let mut needed = 0u32;
            let status = query_processes(&mut buffer, &mut needed);
            if status >= 0 {
                // Leave room for threads created before the freeze queries again.
                let used = usize::try_from(needed).unwrap_or(bytes);
                if used.saturating_mul(2) > bytes {
                    buffer = vec![0u64; used.saturating_mul(2).div_ceil(8)];
                }
                return Ok(Self {
                    process_id,
                    current_thread,
                    buffer,
                });
            }
            if status != STATUS_INFO_LENGTH_MISMATCH {
                return Err(HookError::ThreadSuspend);
            }
            bytes = usize::try_from(needed)
                .unwrap_or(0)
                .max(bytes)
                .saturating_mul(2);
        }
        Err(HookError::ThreadSuspend)
    }

    /// Fills `ids` with every thread of this process except the caller.
    fn enumerate(&mut self, ids: &mut IdSet) -> Result<()> {
        let mut needed = 0u32;
        if query_processes(&mut self.buffer, &mut needed) < 0 {
            return Err(HookError::ThreadSuspend);
        }
        // SAFETY: the buffer is a live `Vec<u64>`, so its bytes are initialized.
        let bytes = unsafe {
            std::slice::from_raw_parts(self.buffer.as_ptr().cast::<u8>(), self.buffer.len() * 8)
        };
        parse_process_threads(bytes, self.process_id, self.current_thread, ids)
    }
}

fn query_processes(buffer: &mut [u64], needed: &mut u32) -> NTSTATUS {
    let length = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
    // SAFETY: `buffer` is writable for `length` bytes and `needed` is a valid out-pointer.
    unsafe {
        NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr().cast(),
            length,
            needed,
        )
    }
}

// x64 `SYSTEM_PROCESS_INFORMATION` and `SYSTEM_THREAD_INFORMATION` layout.
const PROCESS_NEXT_OFFSET: usize = 0x00;
const PROCESS_THREAD_COUNT: usize = 0x04;
const PROCESS_ID: usize = 0x50;
const PROCESS_ENTRY_SIZE: usize = 0x100;
const THREAD_ENTRY_SIZE: usize = 0x50;
const THREAD_CLIENT_ID_THREAD: usize = 0x30;

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

/// Collects the thread ids of `process_id`, except `skip`, from a
/// `SystemProcessInformation` buffer. Every read is bounds-checked.
fn parse_process_threads(bytes: &[u8], process_id: u32, skip: u32, ids: &mut IdSet) -> Result<()> {
    let invalid = HookError::ThreadSuspend;
    let mut offset = 0usize;
    loop {
        let next = read_u32(bytes, offset + PROCESS_NEXT_OFFSET).ok_or(invalid)?;
        let count = read_u32(bytes, offset + PROCESS_THREAD_COUNT).ok_or(invalid)?;
        let pid = read_u64(bytes, offset + PROCESS_ID).ok_or(invalid)?;
        if pid == u64::from(process_id) {
            let count = usize::try_from(count).map_err(|_| invalid)?;
            for index in 0..count {
                let entry = offset + PROCESS_ENTRY_SIZE + index * THREAD_ENTRY_SIZE;
                let tid = read_u64(bytes, entry + THREAD_CLIENT_ID_THREAD).ok_or(invalid)?;
                let tid = u32::try_from(tid).map_err(|_| invalid)?;
                if tid != skip {
                    ids.insert(tid)?;
                }
            }
            return Ok(());
        }
        if next == 0 {
            return Err(invalid);
        }
        offset = offset
            .checked_add(usize::try_from(next).map_err(|_| invalid)?)
            .ok_or(invalid)?;
    }
}

/// Makes every page of `[address, address + size)` writable, recording each
/// original protection in `journal` as it is replaced. Each page gets its own call,
/// so a range across two pages with different protections restores both. Returns
/// `false` on failure, leaving the pages already changed in `journal`.
fn make_writable(journal: &mut Vec<(usize, usize, u32)>, address: usize, size: usize) -> bool {
    let end = address + size;
    let mut page = address & !(PAGE_SIZE - 1);
    while page < end {
        let start = address.max(page);
        let stop = end.min(page + PAGE_SIZE);
        let mut old = 0u32;
        // SAFETY: the range lies in the hooked, mapped function.
        if !unsafe {
            sys::protect(
                start as *mut u8,
                stop - start,
                PAGE_EXECUTE_READWRITE,
                &mut old,
            )
        } {
            return false;
        }
        // Never grows: the journal holds MAX_PATCH_PAGES entries per batch entry.
        journal.push((start, stop - start, old));
        page += PAGE_SIZE;
    }
    true
}

/// Puts back every protection in `journal`, newest first, so a page that two patch
/// ranges share ends with its original protection. Each restore is retried; a page
/// that stays changed sets [`PROTECTION_LOST`]. The others are still restored.
fn restore_protection(journal: &mut Vec<(usize, usize, u32)>) {
    while let Some((start, size, old)) = journal.pop() {
        let restored = (0..RESTORE_ATTEMPTS).any(|_| {
            let mut ignored = 0u32;
            // SAFETY: restores a protection this transaction changed on a mapped range.
            unsafe { sys::restore_protect(start as *mut u8, size, old, &mut ignored) }
        });
        if !restored {
            PROTECTION_LOST.store(true, Ordering::Release);
        }
    }
}

/// Flushes the instruction cache over every patch range in `batch`. A failure sets
/// [`FLUSH_FAILED`]; the other ranges are still flushed.
fn flush(hooks: &[HookEntry], batch: &[(usize, bool)]) {
    for &(pos, _) in batch {
        let (address, size) = hooks[pos].patch_range();
        // SAFETY: flushes a mapped code range.
        if !unsafe { sys::flush(address, size) } {
            FLUSH_FAILED.store(true, Ordering::Release);
        }
    }
}

/// Syscalls the freeze depends on. Under `cfg(test)` each can be made to fail.
mod sys {
    use super::*;

    pub(super) unsafe fn open_thread(id: u32) -> HANDLE {
        #[cfg(test)]
        if let Some(error) = fault::open_thread(id) {
            // SAFETY: sets this thread's last-error value only.
            unsafe { SetLastError(error) };
            return ptr::null_mut();
        }
        // SAFETY: `OpenThread` has no memory preconditions.
        unsafe { OpenThread(THREAD_ACCESS, FALSE, id) }
    }

    pub(super) unsafe fn suspend_thread(handle: HANDLE) -> bool {
        #[cfg(test)]
        if fault::hit(fault::Call::SuspendThread) {
            return false;
        }
        // SAFETY: the caller passes an open thread handle.
        unsafe { SuspendThread(handle) != u32::MAX }
    }

    pub(super) unsafe fn resume_thread(handle: HANDLE) -> bool {
        #[cfg(test)]
        if fault::resume_fails(handle) {
            return false;
        }
        // SAFETY: the caller passes an open thread handle it suspended.
        unsafe { ResumeThread(handle) != u32::MAX }
    }

    pub(super) unsafe fn get_context(handle: HANDLE, context: &mut AlignedContext) -> bool {
        #[cfg(test)]
        if fault::hit(fault::Call::GetContext) {
            return false;
        }
        // SAFETY: the caller passes an open, suspended thread; the buffer is aligned.
        unsafe { GetThreadContext(handle, &mut context.0) != 0 }
    }

    /// Whether the thread has started, from its TEB, or `None` if the query failed.
    /// Never blocks.
    pub(super) unsafe fn started(handle: HANDLE) -> Option<bool> {
        #[cfg(test)]
        if fault::hit(fault::Call::Started) {
            return Some(false);
        }
        // SAFETY: forwarded from the caller.
        unsafe { teb(handle) }.map(|teb| teb != 0)
    }

    /// The thread's TEB address, zero until it has started, or `None` if the query
    /// failed. Never blocks.
    unsafe fn teb(handle: HANDLE) -> Option<usize> {
        // x64 THREAD_BASIC_INFORMATION is 0x30 bytes; TebBaseAddress is at +8.
        let mut information = [0u64; 6];
        let mut returned = 0u32;
        // SAFETY: the handle has THREAD_QUERY_INFORMATION and the buffer is 0x30 bytes.
        let status = unsafe {
            NtQueryInformationThread(
                handle,
                ThreadBasicInformation,
                information.as_mut_ptr().cast(),
                size_of_val(&information) as u32,
                &mut returned,
            )
        };
        if status < 0 {
            return None;
        }
        usize::try_from(information[1]).ok()
    }

    /// The top (highest address) of the suspended thread's stack, its
    /// `NT_TIB.StackBase`, or `None` if it cannot be read. Never blocks.
    pub(super) unsafe fn stack_base(handle: HANDLE) -> Option<usize> {
        #[cfg(test)]
        if fault::hit(fault::Call::StackBase) {
            return None;
        }
        // SAFETY: forwarded from the caller.
        let teb = unsafe { teb(handle) }?;
        if teb == 0 {
            return None;
        }
        // NT_TIB.StackBase is the second word of the TEB.
        let mut base = [0u64; 1];
        // SAFETY: the read is validated and fails instead of faulting.
        if !unsafe { read_words(teb.checked_add(8)?, &mut base) } {
            return None;
        }
        usize::try_from(base[0]).ok()
    }

    /// Reads `out.len()` words of a frozen thread's stack at `address`, failing
    /// instead of faulting. Allocation-free on the Rust side.
    pub(super) unsafe fn read_stack(address: usize, out: &mut [u64]) -> bool {
        #[cfg(test)]
        if fault::hit(fault::Call::ReadStack) {
            return false;
        }
        // SAFETY: forwarded from the caller.
        unsafe { read_words(address, out) }
    }

    /// Reads `out.len()` words at `address` of this process; a short read fails.
    unsafe fn read_words(address: usize, out: &mut [u64]) -> bool {
        let bytes = size_of_val(out);
        let mut copied = 0usize;
        // SAFETY: ReadProcessMemory validates the source range and fails instead of
        // faulting; `out` is writable for `bytes` bytes.
        let read = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                address as *const c_void,
                out.as_mut_ptr().cast(),
                bytes,
                &mut copied,
            )
        };
        read != 0 && copied == bytes
    }

    pub(super) unsafe fn wait(handle: HANDLE) -> u32 {
        #[cfg(test)]
        if fault::hit(fault::Call::Wait) {
            return WAIT_FAILED;
        }
        // SAFETY: the caller passes an open handle with SYNCHRONIZE.
        unsafe { WaitForSingleObject(handle, 0) }
    }

    pub(super) unsafe fn set_context(handle: HANDLE, context: &AlignedContext) -> bool {
        #[cfg(test)]
        if fault::hit(fault::Call::SetContext) {
            return false;
        }
        // SAFETY: the caller passes an open, suspended thread; the buffer is aligned.
        unsafe { SetThreadContext(handle, &context.0) != 0 }
    }

    pub(super) unsafe fn protect(address: *mut u8, size: usize, new: u32, old: &mut u32) -> bool {
        #[cfg(test)]
        if fault::hit(fault::Call::Protect) {
            return false;
        }
        // SAFETY: changes protection only; the caller passes a mapped range.
        unsafe { VirtualProtect(address as *mut c_void, size, new, old) != 0 }
    }

    pub(super) unsafe fn restore_protect(
        address: *mut u8,
        size: usize,
        new: u32,
        old: &mut u32,
    ) -> bool {
        #[cfg(test)]
        if fault::hit(fault::Call::Reprotect) {
            return false;
        }
        // SAFETY: changes protection only; the caller passes a mapped range.
        unsafe { VirtualProtect(address as *mut c_void, size, new, old) != 0 }
    }

    pub(super) unsafe fn flush(address: *mut u8, size: usize) -> bool {
        #[cfg(test)]
        if fault::hit(fault::Call::Flush) {
            return false;
        }
        // SAFETY: the current process pseudo-handle is always valid.
        unsafe { FlushInstructionCache(GetCurrentProcess(), address as *const c_void, size) != 0 }
    }

    /// Whether every suspended thread is given a (no-op) context write, so tests
    /// can reach the context-apply step without parking a thread in a hook.
    pub(super) fn force_moves() -> bool {
        #[cfg(test)]
        return fault::force_moves();
        #[cfg(not(test))]
        false
    }
}

/// Test-only failure injection for the freeze. State is per thread, so it only
/// affects hook calls made by the test that set it.
#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;
    use std::sync::atomic::Ordering;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_INVALID_PARAMETER, HANDLE,
    };
    use windows_sys::Win32::System::Threading::{GetThreadId, ResumeThread};

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum Call {
        OpenThread,
        SuspendThread,
        GetContext,
        SetContext,
        Protect,
        Reprotect,
        Flush,
        Started,
        Wait,
        StackBase,
        ReadStack,
    }

    const CALLS: usize = 11;
    /// Most freeze rounds a hide schedule covers.
    const MAX_ROUNDS: usize = 2 * super::FREEZE_ATTEMPTS;
    /// Most stuck handles one test can collect. Fixed, so recording one never allocates.
    const MAX_STUCK: usize = 8;

    thread_local! {
        /// Per call: a bitmask of which calls (by zero-based index) fail, and the next index.
        static PLAN: Cell<[(u64, u32); CALLS]> = const { Cell::new([(0, 0); CALLS]) };
        static FORCE_MOVES: Cell<bool> = const { Cell::new(false) };
        /// A thread id whose resumes fail, and how many more of them fail.
        static STICK: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
        /// A thread id whose opens report it gone, and how many more of them do.
        static GONE: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
        /// Handles the thaw left suspended, for the test to resume itself.
        static STUCK: Cell<[usize; MAX_STUCK]> = const { Cell::new([0; MAX_STUCK]) };
        /// Per freeze round, how many trailing ids the enumeration hides, so a thread
        /// seems to appear in a later round. And how many rounds have run.
        static HIDE: Cell<([u8; MAX_ROUNDS], usize)> = const { Cell::new(([0; MAX_ROUNDS], 0)) };
    }

    /// Hides `schedule[round]` trailing ids from each freeze round's enumeration.
    pub(crate) fn hide(schedule: &[u8]) {
        let mut rounds = [0; MAX_ROUNDS];
        rounds[..schedule.len()].copy_from_slice(schedule);
        HIDE.with(|hide| hide.set((rounds, 0)));
    }

    /// How many freeze rounds have run since the last [`hide`] or [`clear`].
    pub(crate) fn rounds() -> usize {
        HIDE.with(|hide| hide.get().1)
    }

    pub(super) fn hide_threads(ids: &mut super::IdSet) {
        HIDE.with(|hide| {
            let (schedule, round) = hide.get();
            let count = schedule.get(round).copied().unwrap_or(0);
            ids.len = ids.len.saturating_sub(usize::from(count));
            hide.set((schedule, round + 1));
        });
    }

    /// Fails the calls to `call` whose zero-based index is set in `mask`. Plans for
    /// different calls combine.
    pub(crate) fn fail(call: Call, mask: u64) {
        PLAN.with(|plan| {
            let mut plans = plan.get();
            plans[call as usize] = (mask, 0);
            plan.set(plans);
        });
    }

    pub(crate) fn set_force_moves(force: bool) {
        FORCE_MOVES.with(|value| value.set(force));
    }

    /// Fails the next `times` resumes of thread `id`.
    pub(crate) fn stick(id: u32, times: u32) {
        STICK.with(|stick| stick.set((id, times)));
    }

    /// Resumes and closes every handle the thaw left suspended, then clears the
    /// terminal latches. Returns how many threads it resumed.
    pub(crate) fn release_stuck() -> usize {
        let handles = STUCK.with(|stuck| stuck.replace([0; MAX_STUCK]));
        let mut released = 0;
        for handle in handles.into_iter().filter(|&handle| handle != 0) {
            // SAFETY: the thaw kept this handle open and its thread suspended.
            unsafe {
                ResumeThread(handle as HANDLE);
                CloseHandle(handle as HANDLE);
            }
            released += 1;
        }
        super::THAW_FAILED.store(false, Ordering::Release);
        released
    }

    /// Clears the protection and flush latches.
    pub(crate) fn reset_latches() {
        super::PROTECTION_LOST.store(false, Ordering::Release);
        super::FLUSH_FAILED.store(false, Ordering::Release);
    }

    pub(crate) fn clear() {
        PLAN.with(|plan| plan.set([(0, 0); CALLS]));
        FORCE_MOVES.with(|value| value.set(false));
        STICK.with(|stick| stick.set((0, 0)));
        GONE.with(|gone| gone.set((0, 0)));
        HIDE.with(|hide| hide.set(([0; MAX_ROUNDS], 0)));
    }

    pub(super) fn hit(call: Call) -> bool {
        PLAN.with(|plan| {
            let mut plans = plan.get();
            let (mask, index) = plans[call as usize];
            plans[call as usize].1 = index + 1;
            plan.set(plans);
            // Index 63 and beyond share bit 63, so a mask can fail every later call.
            mask & (1 << index.min(63)) != 0
        })
    }

    pub(super) fn resume_fails(handle: HANDLE) -> bool {
        STICK.with(|stick| {
            let (id, times) = stick.get();
            // SAFETY: `handle` is an open thread handle.
            if times == 0 || unsafe { GetThreadId(handle) } != id {
                return false;
            }
            stick.set((id, times - 1));
            true
        })
    }

    pub(super) fn stuck(handle: HANDLE) {
        STUCK.with(|stuck| {
            let mut handles = stuck.get();
            if let Some(slot) = handles.iter_mut().find(|slot| **slot == 0) {
                *slot = handle as usize;
            }
            stuck.set(handles);
        });
    }

    pub(super) fn open_thread(id: u32) -> Option<u32> {
        let gone = GONE.with(|gone| {
            let (gone_id, times) = gone.get();
            let hit = times > 0 && gone_id == id;
            if hit {
                gone.set((gone_id, times - 1));
            }
            hit
        });
        if gone {
            return Some(ERROR_INVALID_PARAMETER);
        }
        // Any other failure, as an access check that fails.
        hit(Call::OpenThread).then_some(ERROR_ACCESS_DENIED)
    }

    /// Makes the next `times` opens of thread `id` report that it no longer exists.
    pub(crate) fn gone(id: u32, times: u32) {
        GONE.with(|gone| gone.set((id, times)));
    }

    pub(super) fn force_moves() -> bool {
        FORCE_MOVES.with(Cell::get)
    }

    /// Most threads whose slot check one transaction records: every thread a
    /// freeze can hold, so no finding is dropped.
    const MAX_REACH: usize = super::MAX_THREADS;

    thread_local! {
        /// What the last transaction's slot check found, per thread id, in order.
        static REACH: Cell<([(u32, super::Reach); MAX_REACH], usize)> =
            const { Cell::new(([(0, super::Reach::Clear); MAX_REACH], 0)) };
    }

    pub(super) fn begin_reach() {
        REACH.with(|reach| reach.set(([(0, super::Reach::Clear); MAX_REACH], 0)));
    }

    /// Records a thread's slot check. Fixed storage, so it never allocates.
    pub(super) fn record_reach(handle: HANDLE, found: super::Reach) {
        // SAFETY: `handle` is an open thread handle.
        let id = unsafe { GetThreadId(handle) };
        REACH.with(|reach| {
            let (mut entries, len) = reach.get();
            if len < MAX_REACH {
                entries[len] = (id, found);
                reach.set((entries, len + 1));
            }
        });
    }

    /// What the last transaction's slot check found for thread `id`, if it was checked.
    pub(super) fn reach_of(id: u32) -> Option<super::Reach> {
        REACH.with(|reach| {
            let (entries, len) = reach.get();
            entries[..len]
                .iter()
                .find(|(entry, _)| *entry == id)
                .map(|&(_, found)| found)
        })
    }

    /// Every slot check of the last transaction.
    pub(super) fn reaches() -> Vec<super::Reach> {
        REACH.with(|reach| {
            let (entries, len) = reach.get();
            entries[..len].iter().map(|&(_, found)| found).collect()
        })
    }
}

impl HookManager {
    /// Creates a new, uninitialized hook manager.
    const fn new() -> Self {
        Self {
            heap: false,
            hooks: HookCollection {
                items: Vec::new(),
                capacity: 0,
                size: 0,
            },
            retain_buffers: false,
        }
    }

    /// Finds the index of a hook entry by target address.
    fn find_hook_entry(&self, target: *mut c_void) -> usize {
        for i in 0..self.hooks.size {
            if ptr::eq(target, self.hooks.items[i].target) {
                return i;
            }
        }
        INVALID_HOOK_POS
    }

    /// Adds a new hook entry, growing the buffer if needed.
    fn add_hook_entry(&mut self) -> Option<&mut HookEntry> {
        if self.hooks.items.is_empty() {
            self.hooks.capacity = INITIAL_HOOK_CAPACITY;
            self.hooks.items.reserve(self.hooks.capacity);
            if self.hooks.items.capacity() == 0 {
                return None;
            }
        } else if self.hooks.size >= self.hooks.capacity {
            self.hooks.capacity *= 2;
            self.hooks.items.reserve(self.hooks.capacity);
            if self.hooks.items.capacity() < self.hooks.capacity {
                return None;
            }
        }
        self.hooks.items.push(HookEntry::new());
        self.hooks.size += 1;
        Some(&mut self.hooks.items[self.hooks.size - 1])
    }

    /// Deletes a hook entry at the given index, shrinking the buffer if needed.
    fn delete_hook_entry(&mut self, pos: usize) {
        if pos < self.hooks.size - 1 {
            self.hooks.items[pos] = self.hooks.items[self.hooks.size - 1].clone();
        }
        self.hooks.size -= 1;
        self.hooks.items.truncate(self.hooks.size);
        if self.hooks.capacity / 2 >= INITIAL_HOOK_CAPACITY
            && self.hooks.capacity / 2 >= self.hooks.size
        {
            self.hooks.capacity /= 2;
            self.hooks.items.shrink_to(self.hooks.capacity);
        }
    }

    /// Applies `batch` (`(pos, enable)` pairs whose state changes) as one transaction,
    /// with every other thread frozen:
    ///
    /// 1. compute where each thread must resume from the context the freeze read
    ///    (no writes);
    /// 2. make every patch range writable, then write the bytes;
    /// 3. write the moved contexts.
    ///
    /// On failure nothing changes: the bytes and the contexts already written are
    /// restored. If a context cannot be restored, every hook in the batch is left
    /// disabled (a moved thread is then either in a kept trampoline or at original
    /// code), the trampoline buffers are retained for good, and an error is returned.
    ///
    /// If a thread cannot be resumed afterwards, the hook state is still recorded as
    /// it ended up, the buffers are retained, [`THAW_FAILED`] is set, and
    /// [`HookError::ThreadResume`] is returned in place of any other result. Every
    /// later call is then refused with it.
    ///
    /// Returns whether every thread was verified unable to reach the trampoline slots
    /// of the hooks in `watch` once the batch applied: no thread's RIP (after its
    /// move), general-purpose register, or word on its live stack (RSP up to its
    /// `NT_TIB.StackBase`) lies in one. A stack that cannot be read in full, or a
    /// missing stack base, counts as reaching them; that is not an error.
    fn transact(&mut self, batch: &[(usize, bool)], watch: &[usize]) -> Result<bool> {
        if thaw_failed() {
            return Err(HookError::ThreadResume);
        }
        if batch.is_empty() && watch.is_empty() {
            return Ok(true);
        }
        // Allocate before freezing: a suspended thread may hold the heap lock.
        let mut list = ThreadList::new()?;
        let mut moves: Vec<ThreadMove> = Vec::with_capacity(MAX_THREADS);
        let mut journal: Vec<(usize, usize, u32)> =
            Vec::with_capacity(batch.len() * MAX_PATCH_PAGES);
        let slots = SlotSet::new(
            watch
                .iter()
                .map(|&pos| self.hooks.items[pos].trampoline as usize),
        );
        #[cfg(test)]
        fault::begin_reach();
        let mut frozen = FrozenThreads::freeze(&mut list)?;
        let hooks = &self.hooks.items;

        // Step 1: plan the moves from the contexts the freeze read. A second read
        // would be a second chance to block. A watched slot stays allocated while
        // any thread may still reach it, or nothing is known about one.
        let mut clear = true;
        let mut budget = MAX_TOTAL_SCAN_BYTES;
        for (&handle, captured) in frozen.handles.iter().zip(&frozen.contexts) {
            let ip = captured.0.Rip;
            let new_ip = plan_ip(hooks, batch, ip as usize);
            // Tests check every thread, so each holder's own finding is recorded.
            if !slots.is_empty() && (clear || cfg!(test)) {
                // SAFETY: `handle` is an open thread this freeze suspended.
                let base = unsafe { sys::stack_base(handle) };
                let found = reach(
                    &captured.0,
                    new_ip,
                    base,
                    &slots,
                    &mut budget,
                    // SAFETY: the read is validated and never faults.
                    |address, out| unsafe { sys::read_stack(address, out) },
                );
                #[cfg(test)]
                fault::record_reach(handle, found);
                clear &= found == Reach::Clear;
            }
            if new_ip as u64 != ip || sys::force_moves() {
                moves.push(ThreadMove {
                    handle,
                    context: captured.moved_to(new_ip as u64),
                    original_ip: ip,
                });
            }
        }

        // Step 2: unprotect every page first, so the byte writes cannot fail.
        for &(pos, _) in batch {
            let (address, size) = hooks[pos].patch_range();
            if !make_writable(&mut journal, address as usize, size) {
                restore_protection(&mut journal);
                return Err(frozen.abort(HookError::MemoryProtect));
            }
        }
        for &(pos, enable) in batch {
            // SAFETY: the range is writable and every other thread is frozen.
            unsafe { hooks[pos].write_patch(enable) };
        }

        // Step 3: move the threads.
        let mut result = Ok(());
        let mut end_disabled = false;
        for i in 0..moves.len() {
            // SAFETY: the handle is open and its thread suspended; the buffer is aligned.
            if unsafe { sys::set_context(moves[i].handle, &moves[i].context) } {
                continue;
            }
            result = Err(HookError::ThreadContext);
            let mut restored = true;
            for done in &mut moves[..i] {
                done.context.0.Rip = done.original_ip;
                // SAFETY: as above.
                restored &= unsafe { sys::set_context(done.handle, &done.context) };
            }
            for &(pos, enable) in batch {
                // A thread left moved by a failed restore sits in a trampoline (enable)
                // or at original code (disable); the disabled state suits both.
                if restored || enable {
                    // SAFETY: the range is still writable and the threads frozen.
                    unsafe { hooks[pos].write_patch(!enable) };
                }
            }
            end_disabled = !restored;
            break;
        }

        restore_protection(&mut journal);
        flush(hooks, batch);
        let thawed = frozen.thaw();

        // Record what the image now holds before reporting any error.
        if end_disabled {
            for &(pos, _) in batch {
                self.hooks.items[pos].is_enabled = false;
                self.hooks.items[pos].queue_enable = false;
            }
        } else if result.is_ok() {
            for &(pos, enable) in batch {
                self.hooks.items[pos].is_enabled = enable;
                self.hooks.items[pos].queue_enable = enable;
            }
        }
        if end_disabled || !thawed {
            // A moved or still-suspended thread may resume inside a trampoline.
            self.retain_buffers = true;
        }
        if !thawed {
            return Err(HookError::ThreadResume);
        }
        result?;
        Ok(clear)
    }

    /// Builds the batch of hooks whose state differs from `want(hook)`.
    fn batch_where(&self, want: impl Fn(&HookEntry) -> bool) -> Vec<(usize, bool)> {
        self.hooks.items[..self.hooks.size]
            .iter()
            .enumerate()
            .filter_map(|(pos, hook)| {
                let enable = want(hook);
                (hook.is_enabled != enable).then_some((pos, enable))
            })
            .collect()
    }

    /// Enables or disables all hooks.
    fn enable_all_hooks_ll(&mut self, enable: bool) -> Result<()> {
        let batch = self.batch_where(|_| enable);
        self.transact(&batch, &[]).map(|_| ())
    }

    /// Public API: enables or disables a specific hook or all hooks.
    fn enable_hook(&mut self, target: *mut c_void, enable: bool) -> Result<()> {
        if !self.heap {
            return Err(HookError::NotInitialized);
        }
        if target == ALL_HOOKS {
            self.enable_all_hooks_ll(enable)
        } else {
            let pos = self.find_hook_entry(target);
            if pos != INVALID_HOOK_POS {
                if self.hooks.items[pos].is_enabled != enable {
                    self.transact(&[(pos, enable)], &[]).map(|_| ())
                } else {
                    Err(if enable {
                        HookError::Enabled
                    } else {
                        HookError::Disabled
                    })
                }
            } else {
                Err(HookError::NotCreated)
            }
        }
    }

    /// Queues a hook for enabling or disabling.
    fn queue_hook(&mut self, target: *mut c_void, queue_enable: bool) -> Result<()> {
        if !self.heap {
            return Err(HookError::NotInitialized);
        }
        if target == ALL_HOOKS {
            for i in 0..self.hooks.size {
                self.hooks.items[i].queue_enable = queue_enable;
            }
        } else {
            let pos = self.find_hook_entry(target);
            if pos != INVALID_HOOK_POS {
                self.hooks.items[pos].queue_enable = queue_enable;
            } else {
                return Err(HookError::NotCreated);
            }
        }
        Ok(())
    }

    /// Applies all queued hook enable/disable operations.
    fn apply_queued(&mut self) -> Result<()> {
        if !self.heap {
            return Err(HookError::NotInitialized);
        }
        let batch = self.batch_where(|hook| hook.queue_enable);
        self.transact(&batch, &[]).map(|_| ())
    }

    /// Initializes the hook manager and internal buffer.
    fn initialize(&mut self) -> Result<()> {
        if self.heap {
            return Err(HookError::AlreadyInitialized);
        }
        initialize_buffer();
        self.heap = true;
        Ok(())
    }

    /// Uninitializes the hook manager and releases all resources. The trampoline
    /// buffers are released only if every thread was verified to be outside them.
    fn uninitialize(&mut self) -> Result<()> {
        if !self.heap {
            return Err(HookError::NotInitialized);
        }
        let batch = self.batch_where(|_| false);
        let watch: Vec<usize> = (0..self.hooks.size).collect();
        let clear = self.transact(&batch, &watch)?;
        if clear && !self.retain_buffers {
            uninitialize_buffer();
        } else {
            self.retain_buffers = true;
        }
        self.hooks.items.clear();
        self.hooks.capacity = 0;
        self.hooks.size = 0;
        self.heap = false;
        Ok(())
    }

    /// Creates a new hook for the specified target and detour.
    fn create_hook(&mut self, target: *mut c_void, detour: *mut c_void) -> Result<*mut c_void> {
        if !self.heap {
            return Err(HookError::NotInitialized);
        }
        if !is_executable_address(target as usize) || !is_executable_address(detour as usize) {
            return Err(HookError::NotExecutable);
        }
        let pos = self.find_hook_entry(target);
        if pos != INVALID_HOOK_POS {
            return Err(HookError::AlreadyCreated);
        }
        let mut trampoline = Trampoline::new(target, detour, ptr::null_mut());
        create_trampoline(&mut trampoline)?;
        let hook_entry = self.add_hook_entry().ok_or(HookError::MemoryAlloc)?;
        hook_entry.target = target;
        hook_entry.detour = trampoline.relay;
        hook_entry.trampoline = trampoline.trampoline;
        hook_entry.patch_above = trampoline.patch_above;
        hook_entry.is_enabled = false;
        hook_entry.queue_enable = false;
        hook_entry.n_ip = trampoline.n_ip;
        hook_entry.old_ips = trampoline.old_ips;
        hook_entry.new_ips = trampoline.new_ips;
        unsafe {
            if trampoline.patch_above {
                ptr::copy_nonoverlapping(
                    (target as *const u8).sub(size_of::<JmpRel>()),
                    hook_entry.backup.as_mut_ptr(),
                    size_of::<JmpRel>() + size_of::<JmpRelShort>(),
                );
            } else {
                ptr::copy_nonoverlapping(
                    target as *const u8,
                    hook_entry.backup.as_mut_ptr(),
                    size_of::<JmpRel>(),
                );
            }
        }
        Ok(hook_entry.trampoline)
    }

    /// Removes a hook for the specified target. Its trampoline is released only if
    /// every thread was verified to be outside it.
    fn remove_hook(&mut self, target: *mut c_void) -> Result<()> {
        if !self.heap {
            return Err(HookError::NotInitialized);
        }
        let pos = self.find_hook_entry(target);
        if pos == INVALID_HOOK_POS {
            return Err(HookError::NotCreated);
        }
        let batch: &[(usize, bool)] = if self.hooks.items[pos].is_enabled {
            &[(pos, false)]
        } else {
            &[]
        };
        let clear = self.transact(batch, &[pos])?;
        if clear && !self.retain_buffers {
            free_buffer(self.hooks.items[pos].trampoline);
        } else {
            self.retain_buffers = true;
        }
        self.delete_hook_entry(pos);
        Ok(())
    }
}

unsafe impl Send for HookManager {}
unsafe impl Sync for HookManager {}

/// Special value for targeting all hooks.
pub const ALL_HOOKS: *mut c_void = ptr::null_mut();

/// Returns a reference to the global hook manager.
fn get_manager() -> &'static Mutex<HookManager> {
    HOOK_MANAGER.get_or_init(|| Mutex::new(HookManager::new()))
}

/// Initializes the MinHook library.
pub fn initialize() -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .initialize()
}

/// Uninitializes the MinHook library and releases all resources.
pub fn uninitialize() -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .uninitialize()
}

/// Creates a hook for the specified target and detour.
pub fn create_hook(target: *mut c_void, detour: *mut c_void) -> Result<*mut c_void> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .create_hook(target, detour)
}

/// Removes a hook for the specified target.
pub fn remove_hook(target: *mut c_void) -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .remove_hook(target)
}

/// Enables a hook for the specified target.
pub fn enable_hook(target: *mut c_void) -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .enable_hook(target, true)
}

/// Disables a hook for the specified target.
pub fn disable_hook(target: *mut c_void) -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .enable_hook(target, false)
}

/// Queues a hook to be enabled for the specified target.
pub fn queue_enable_hook(target: *mut c_void) -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .queue_hook(target, true)
}

/// Queues a hook to be disabled for the specified target.
pub fn queue_disable_hook(target: *mut c_void) -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .queue_hook(target, false)
}

/// Applies all queued hook enable/disable operations.
pub fn apply_queued() -> Result<()> {
    get_manager()
        .lock()
        .map_err(|_| HookError::Unknown)?
        .apply_queued()
}

/// Creates a hook for a function in a specific module by name, returning the trampoline and target.
pub fn create_hook_api_ex(
    module_name: &str,
    proc_name: &str,
    detour: *mut c_void,
) -> Result<(*mut c_void, *mut c_void)> {
    let module_wide = string_to_wide(module_name);
    let proc_c_str = string_to_c_string(proc_name);
    let hmodule = unsafe { GetModuleHandleW(module_wide.as_ptr()) };
    if hmodule.is_null() {
        return Err(HookError::ModuleNotFound);
    }
    let target = unsafe { GetProcAddress(hmodule, proc_c_str.as_ptr()) };
    if target.is_none() {
        return Err(HookError::FunctionNotFound);
    }
    let target_ptr = target.unwrap() as *mut c_void;
    let trampoline = create_hook(target_ptr, detour)?;
    Ok((trampoline, target_ptr))
}

/// Creates a hook for a function in a specific module by name.
pub fn create_hook_api(
    module_name: &str,
    proc_name: &str,
    detour: *mut c_void,
) -> Result<(*mut c_void, *mut c_void)> {
    create_hook_api_ex(module_name, proc_name, detour)
}

/// Converts a HookError to a static string.
pub fn status_to_string(error: HookError) -> &'static str {
    error.as_str()
}

/// Converts a Rust string to a wide (UTF-16) null-terminated string for Windows APIs.
fn string_to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Converts a Rust string to a C-style null-terminated string for Windows APIs.
fn string_to_c_string(s: &str) -> Vec<u8> {
    s.bytes().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::fault::{self, Call};
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, MutexGuard};
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};

    /// Hook tests share the global manager, so they run one at a time.
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    type MixFn = extern "system" fn(u64) -> u64;

    // Long enough for the 5-byte jump the hook writes over its prologue.
    #[inline(never)]
    extern "system" fn mix_a(seed: u64) -> u64 {
        let mut value = seed;
        for round in 0..std::hint::black_box(8u64) {
            value = value.wrapping_mul(31).wrapping_add(round);
        }
        value
    }

    #[inline(never)]
    extern "system" fn mix_b(seed: u64) -> u64 {
        let mut value = seed;
        for round in 0..std::hint::black_box(6u64) {
            value = value.wrapping_mul(37).wrapping_add(round);
        }
        value
    }

    extern "system" fn detour(seed: u64) -> u64 {
        seed ^ 0xA5A5
    }

    fn target(f: MixFn) -> *mut c_void {
        f as *mut c_void
    }

    fn bytes(f: MixFn) -> [u8; 8] {
        // SAFETY: the function's first 8 bytes are mapped code.
        unsafe { ptr::read_volatile(f as *const [u8; 8]) }
    }

    fn hooked(f: MixFn) -> bool {
        std::hint::black_box(f)(7) == 7 ^ 0xA5A5
    }

    /// A fault mask hitting every call after the first, so one thread is suspended
    /// (and must be resumed) and every retry fails too. Unlike a mask aimed at the
    /// last thread, it does not depend on how many threads exist when the freeze
    /// runs: test threads come and go.
    fn after_first_call() -> u64 {
        u64::MAX << 1
    }

    /// Whether the manager records the hook on `f` as enabled.
    fn recorded_enabled(f: MixFn) -> bool {
        let manager = get_manager().lock().unwrap();
        let pos = manager.find_hook_entry(target(f));
        manager.hooks.items[pos].is_enabled
    }

    fn retain_buffers() -> bool {
        get_manager().lock().unwrap().retain_buffers
    }

    /// Serializes the test, starts two spinning threads for the freeze to suspend,
    /// and creates (disabled) hooks on `mix_a` and `mix_b`.
    struct Fixture {
        stop: Arc<AtomicBool>,
        count: Arc<AtomicU64>,
        threads: Vec<JoinHandle<()>>,
        /// The spinners' thread ids, for [`fault::stick`].
        spinners: Vec<u32>,
        _guard: MutexGuard<'static, ()>,
    }

    impl Fixture {
        fn new() -> Self {
            let guard = TEST_LOCK
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            fault::clear();
            let _ = initialize();
            for f in [mix_a as MixFn, mix_b] {
                let _ = remove_hook(target(f));
                create_hook(target(f), detour as MixFn as *mut c_void).expect("create_hook");
            }
            let stop = Arc::new(AtomicBool::new(false));
            let count = Arc::new(AtomicU64::new(0));
            let (ids, spinner_ids) = std::sync::mpsc::channel();
            let threads = (0..2)
                .map(|_| {
                    let (stop, count, ids) = (stop.clone(), count.clone(), ids.clone());
                    std::thread::spawn(move || {
                        // SAFETY: reads the calling thread's id.
                        let _ = ids.send(unsafe { GetCurrentThreadId() });
                        while !stop.load(Ordering::Relaxed) {
                            count.fetch_add(1, Ordering::Relaxed);
                            std::hint::spin_loop();
                        }
                    })
                })
                .collect();
            // Make sure the spinners exist before the test freezes anything.
            let spinners = (0..2)
                .map(|_| spinner_ids.recv().expect("spinner id"))
                .collect();
            let fixture = Self {
                stop,
                count,
                threads,
                spinners,
                _guard: guard,
            };
            fixture.assert_threads_run();
            fixture
        }

        /// Asserts the spinners are running, so a failed freeze resumed them.
        fn assert_threads_run(&self) {
            let start = self.count.load(Ordering::Relaxed);
            let deadline = Instant::now() + Duration::from_secs(5);
            while self.count.load(Ordering::Relaxed) == start {
                assert!(Instant::now() < deadline, "a frozen thread was not resumed");
                std::thread::yield_now();
            }
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            fault::clear();
            // A stranded spinner would hang the join below.
            fault::release_stuck();
            fault::reset_latches();
            get_manager().lock().unwrap().retain_buffers = false;
            self.stop.store(true, Ordering::Relaxed);
            for thread in self.threads.drain(..) {
                let _ = thread.join();
            }
            for f in [mix_a as MixFn, mix_b] {
                let _ = remove_hook(target(f));
            }
        }
    }

    fn entry(target: usize, trampoline: usize, detour: usize) -> HookEntry {
        let mut hook = HookEntry::new();
        hook.target = target as *mut c_void;
        hook.trampoline = trampoline as *mut c_void;
        hook.detour = detour as *mut c_void;
        hook.n_ip = 2;
        hook.old_ips[..2].copy_from_slice(&[0, 3]);
        hook.new_ips[..2].copy_from_slice(&[0, 9]);
        hook
    }

    #[test]
    fn plan_ip_moves_threads_between_target_and_trampoline() {
        let mut hooks = vec![entry(0x1000, 0x2000, 0x2030), entry(0x5000, 0x6000, 0x6030)];
        let enable_both = [(0, true), (1, true)];
        assert_eq!(plan_ip(&hooks, &enable_both, 0x1003), 0x2009);
        assert_eq!(plan_ip(&hooks, &enable_both, 0x5000), 0x6000);
        assert_eq!(plan_ip(&hooks, &enable_both, 0x1001), 0x1001);
        assert_eq!(plan_ip(&hooks, &[(1, true)], 0x1003), 0x1003);

        let disable = [(0, false)];
        assert_eq!(plan_ip(&hooks, &disable, 0x2009), 0x1003);
        assert_eq!(plan_ip(&hooks, &disable, 0x2030), 0x1000);
        assert_eq!(plan_ip(&hooks, &disable, 0x2010), 0x2010);
        hooks[0].patch_above = true;
        assert_eq!(plan_ip(&hooks, &disable, 0x1000 - 5), 0x1000);
    }

    #[test]
    fn open_failure_resumes_threads_and_patches_nothing() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        fault::fail(Call::OpenThread, after_first_call());
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadSuspend));
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(bytes(mix_a), before);
        assert!(!hooked(mix_a));
        enable_hook(target(mix_a)).expect("retry");
        assert!(hooked(mix_a));
    }

    #[test]
    fn suspend_failure_resumes_threads_and_patches_nothing() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        fault::fail(Call::SuspendThread, after_first_call());
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadSuspend));
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(bytes(mix_a), before);
        enable_hook(target(mix_a)).expect("retry");
    }

    #[test]
    fn exited_thread_is_skipped() {
        let fixture = Fixture::new();
        // A spinner, which stays alive, so the check is sure to list it again.
        fault::gone(fixture.spinners[0], 1);
        enable_hook(target(mix_a)).expect("an exited thread does not block the freeze");
        // The thread reported gone is still listed and in fact alive, as a thread
        // given a recycled id would be, so the first attempt is retried.
        assert_eq!(fault::rounds(), 4);
        assert!(hooked(mix_a));
    }

    #[test]
    fn context_read_failure_patches_nothing() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        fault::fail(Call::GetContext, u64::MAX << 1);
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadContext));
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(bytes(mix_a), before);
        enable_hook(target(mix_a)).expect("retry");
    }

    #[test]
    fn context_write_failure_restores_bytes_and_contexts() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        fault::set_force_moves(true);
        fault::fail(Call::SetContext, 0b10);
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadContext));
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(bytes(mix_a), before);
        assert!(!retain_buffers());
        enable_hook(target(mix_a)).expect("the hook stayed disabled");
        assert!(hooked(mix_a));
    }

    #[test]
    fn failed_context_restore_leaves_hooks_disabled_and_keeps_buffers() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        fault::set_force_moves(true);
        // The second write fails, then so does restoring the first.
        fault::fail(Call::SetContext, 0b110);
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadContext));
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(bytes(mix_a), before);
        assert!(retain_buffers());
        get_manager().lock().unwrap().retain_buffers = false;
        enable_hook(target(mix_a)).expect("the hook was left disabled");
    }

    #[test]
    fn protect_failure_in_a_batch_patches_nothing() {
        let fixture = Fixture::new();
        let (before_a, before_b) = (bytes(mix_a), bytes(mix_b));
        fault::fail(Call::Protect, 0b10);
        assert_eq!(enable_hook(ALL_HOOKS), Err(HookError::MemoryProtect));
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!((bytes(mix_a), bytes(mix_b)), (before_a, before_b));
        enable_hook(ALL_HOOKS).expect("retry");
        assert!(hooked(mix_a) && hooked(mix_b));
    }

    #[test]
    fn failed_disable_of_all_hooks_keeps_them_enabled() {
        let fixture = Fixture::new();
        enable_hook(ALL_HOOKS).expect("enable");
        fault::fail(Call::OpenThread, after_first_call());
        assert_eq!(disable_hook(ALL_HOOKS), Err(HookError::ThreadSuspend));
        fault::clear();
        fixture.assert_threads_run();
        assert!(hooked(mix_a) && hooked(mix_b));
        disable_hook(target(mix_a)).expect("still enabled");
        assert!(!hooked(mix_a));
    }

    #[test]
    fn failed_apply_queued_changes_nothing() {
        let fixture = Fixture::new();
        queue_enable_hook(ALL_HOOKS).expect("queue");
        fault::set_force_moves(true);
        fault::fail(Call::SetContext, 0b10);
        assert_eq!(apply_queued(), Err(HookError::ThreadContext));
        fault::clear();
        fixture.assert_threads_run();
        assert!(!hooked(mix_a) && !hooked(mix_b));
        apply_queued().expect("retry");
        assert!(hooked(mix_a) && hooked(mix_b));
    }

    #[test]
    fn failed_remove_keeps_the_hook() {
        let fixture = Fixture::new();
        enable_hook(target(mix_a)).expect("enable");
        fault::fail(Call::SuspendThread, after_first_call());
        assert_eq!(remove_hook(target(mix_a)), Err(HookError::ThreadSuspend));
        // A disabled hook is still verified before its trampoline is freed.
        fault::clear();
        fault::fail(Call::GetContext, u64::MAX);
        assert_eq!(remove_hook(target(mix_b)), Err(HookError::ThreadContext));
        fault::clear();
        fixture.assert_threads_run();
        assert!(hooked(mix_a));
        assert_eq!(enable_hook(target(mix_b)), Ok(()));
        remove_hook(target(mix_a)).expect("remove");
        assert!(!hooked(mix_a));
    }

    #[test]
    fn failed_uninitialize_stays_initialized() {
        let fixture = Fixture::new();
        enable_hook(target(mix_a)).expect("enable");
        fault::fail(Call::GetContext, u64::MAX);
        assert_eq!(uninitialize(), Err(HookError::ThreadContext));
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(initialize(), Err(HookError::AlreadyInitialized));
        assert!(hooked(mix_a));
        uninitialize().expect("uninitialize");
        assert!(!hooked(mix_a));
    }

    #[test]
    fn transient_resume_failure_is_retried() {
        let fixture = Fixture::new();
        fault::stick(fixture.spinners[0], 1);
        enable_hook(target(mix_a)).expect("a retried resume succeeds");
        assert!(!thaw_failed());
        fixture.assert_threads_run();
        assert!(hooked(mix_a));
    }

    #[test]
    fn stuck_thread_is_terminal_and_records_the_applied_change() {
        let fixture = Fixture::new();
        fault::stick(fixture.spinners[0], u32::MAX);
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadResume));
        assert!(thaw_failed());
        // Usually the jump was written first. If a disturbed attempt thawed before
        // writing (test threads come and go), nothing was. Either way the record
        // matches the image.
        let applied = hooked(mix_a);
        assert_eq!(recorded_enabled(mix_a), applied);
        if applied {
            assert!(retain_buffers());
        }
        assert_eq!(enable_hook(target(mix_b)), Err(HookError::ThreadResume));
        assert!(!hooked(mix_b));
        assert_eq!(fault::release_stuck(), 1);
        fault::clear();
        fixture.assert_threads_run();
        let expected = if applied {
            Err(HookError::Enabled)
        } else {
            Ok(())
        };
        assert_eq!(enable_hook(target(mix_a)), expected);
    }

    #[test]
    fn stuck_thread_on_an_early_abort_reports_the_resume_failure() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        fault::fail(Call::GetContext, 0b1);
        fault::stick(fixture.spinners[0], u32::MAX);
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadResume));
        assert!(thaw_failed());
        assert_eq!(bytes(mix_a), before);
        assert_eq!(fault::release_stuck(), 1);
        fault::clear();
        fixture.assert_threads_run();
        enable_hook(target(mix_a)).expect("nothing was applied");
    }

    #[test]
    fn stuck_thread_after_a_rolled_back_change_reports_the_resume_failure() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        fault::set_force_moves(true);
        fault::fail(Call::SetContext, 0b10);
        fault::stick(fixture.spinners[0], u32::MAX);
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadResume));
        assert_eq!(bytes(mix_a), before);
        assert_eq!(fault::release_stuck(), 1);
        fault::clear();
        fixture.assert_threads_run();
        enable_hook(target(mix_a)).expect("the change was rolled back");
    }

    #[test]
    fn failed_protection_restore_is_reported_and_the_rest_restored() {
        let fixture = Fixture::new();
        // Every attempt to restore the newest journal entry fails.
        fault::fail(Call::Reprotect, 0b111);
        enable_hook(ALL_HOOKS).expect("the hooks are in; only a protection is left changed");
        fault::clear();
        fixture.assert_threads_run();
        assert!(protection_lost());
        assert!(!flush_failed());
        assert!(hooked(mix_a) && hooked(mix_b));
    }

    #[test]
    fn transient_protection_restore_failure_is_retried() {
        let _fixture = Fixture::new();
        fault::fail(Call::Reprotect, 0b1);
        enable_hook(target(mix_a)).expect("enable");
        assert!(!protection_lost());
    }

    #[test]
    fn failed_flush_is_reported_on_its_own() {
        let fixture = Fixture::new();
        fault::fail(Call::Flush, 0b1);
        enable_hook(ALL_HOOKS).expect("the hooks are in");
        fault::clear();
        fixture.assert_threads_run();
        assert!(flush_failed());
        assert!(!protection_lost());
        assert!(hooked(mix_a) && hooked(mix_b));
    }

    #[test]
    fn a_range_across_two_pages_restores_each_page() {
        let _fixture = Fixture::new();
        let mut journal = Vec::with_capacity(MAX_PATCH_PAGES);
        // SAFETY: allocates two committed pages, read-only first and execute-read second.
        let base = unsafe {
            VirtualAlloc(
                ptr::null(),
                2 * PAGE_SIZE,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_READONLY,
            )
        } as usize;
        assert_ne!(base, 0);
        let mut old = 0u32;
        // SAFETY: the second page is part of the allocation above.
        assert_ne!(
            unsafe {
                VirtualProtect(
                    (base + PAGE_SIZE) as *mut c_void,
                    PAGE_SIZE,
                    PAGE_EXECUTE_READ,
                    &mut old,
                )
            },
            0
        );
        assert!(make_writable(&mut journal, base + PAGE_SIZE - 3, 7));
        assert_eq!(journal.len(), 2);
        restore_protection(&mut journal);
        let protection = |address: usize| {
            // SAFETY: zeroed MEMORY_BASIC_INFORMATION is valid; VirtualQuery fills it.
            let mut info = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
            // SAFETY: `info` is a valid out-buffer of the size given.
            unsafe { VirtualQuery(address as *const c_void, &mut info, size_of_val(&info)) };
            info.Protect
        };
        assert_eq!(protection(base), PAGE_READONLY);
        assert_eq!(protection(base + PAGE_SIZE), PAGE_EXECUTE_READ);
        assert!(!protection_lost());
        // SAFETY: frees the allocation above.
        unsafe { VirtualFree(base as *mut c_void, 0, MEM_RELEASE) };
    }

    #[test]
    fn a_thread_that_appears_during_the_freeze_restarts_it() {
        let fixture = Fixture::new();
        // The first snapshot misses one thread; the check after suspending finds
        // it, so the attempt is thawed and a second one sees every thread.
        fault::hide(&[1]);
        enable_hook(target(mix_a)).expect("enable");
        assert_eq!(fault::rounds(), 4);
        fault::clear();
        fixture.assert_threads_run();
        assert!(hooked(mix_a));
    }

    #[test]
    fn threads_that_keep_appearing_abandon_the_freeze() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        // Every attempt's check finds a thread its snapshot missed.
        fault::hide(&[1, 0].repeat(FREEZE_ATTEMPTS));
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadSuspend));
        assert_eq!(fault::rounds(), 2 * FREEZE_ATTEMPTS);
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(bytes(mix_a), before);
        enable_hook(target(mix_a)).expect("retry");
    }

    #[test]
    fn unconfirmed_suspension_is_retried() {
        let fixture = Fixture::new();
        fault::fail(Call::GetContext, 0b1);
        enable_hook(target(mix_a)).expect("the second attempt confirms every suspension");
        assert_eq!(fault::rounds(), 3);
        fault::clear();
        fixture.assert_threads_run();
        assert!(hooked(mix_a));
    }

    #[test]
    fn suspension_that_is_never_confirmed_patches_nothing() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        fault::fail(Call::GetContext, u64::MAX);
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadContext));
        assert_eq!(fault::rounds(), FREEZE_ATTEMPTS);
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(bytes(mix_a), before);
    }

    #[test]
    fn id_set_is_bounded_and_deduplicates() {
        let mut set = IdSet::new();
        set.insert(9).unwrap();
        set.insert(9).unwrap();
        assert_eq!(set.as_slice(), &[9]);
        for id in 0..u32::try_from(MAX_THREADS).unwrap() - 1 {
            set.insert(1000 + id).unwrap();
        }
        assert_eq!(set.insert(9), Ok(()));
        assert_eq!(set.insert(1), Err(HookError::ThreadSuspend));
    }

    fn process_entry(next: u32, pid: u64, tids: &[u64]) -> Vec<u8> {
        let mut entry = vec![0u8; PROCESS_ENTRY_SIZE + tids.len() * THREAD_ENTRY_SIZE];
        entry[0..4].copy_from_slice(&next.to_le_bytes());
        entry[4..8].copy_from_slice(&u32::try_from(tids.len()).unwrap().to_le_bytes());
        entry[PROCESS_ID..PROCESS_ID + 8].copy_from_slice(&pid.to_le_bytes());
        for (index, tid) in tids.iter().enumerate() {
            let at = PROCESS_ENTRY_SIZE + index * THREAD_ENTRY_SIZE + THREAD_CLIENT_ID_THREAD;
            entry[at..at + 8].copy_from_slice(&tid.to_le_bytes());
        }
        entry
    }

    #[test]
    fn parses_the_own_process_and_skips_the_caller() {
        let next = u32::try_from(PROCESS_ENTRY_SIZE + THREAD_ENTRY_SIZE).unwrap();
        let mut buffer = process_entry(next, 3, &[1]);
        buffer.extend_from_slice(&process_entry(0, 77, &[10, 11, 12]));
        let mut ids = IdSet::new();
        parse_process_threads(&buffer, 77, 11, &mut ids).unwrap();
        assert_eq!(ids.as_slice(), &[10, 12]);
    }

    #[test]
    fn missing_process_or_truncated_buffer_is_an_error() {
        let buffer = process_entry(0, 3, &[1]);
        let mut ids = IdSet::new();
        let invalid = Err(HookError::ThreadSuspend);
        assert_eq!(parse_process_threads(&buffer, 77, 0, &mut ids), invalid);
        let full = process_entry(0, 77, &[1, 2]);
        let truncated = &full[..PROCESS_ENTRY_SIZE + THREAD_ENTRY_SIZE + THREAD_CLIENT_ID_THREAD];
        assert_eq!(parse_process_threads(truncated, 77, 0, &mut ids), invalid);
        let looping = process_entry(u32::MAX, 3, &[]);
        assert_eq!(parse_process_threads(&looping, 77, 0, &mut ids), invalid);
    }

    #[test]
    fn a_thread_that_has_not_started_restarts_the_freeze() {
        let fixture = Fixture::new();
        // The first thread checked has no TEB yet: its context is never read.
        fault::fail(Call::Started, 0b1);
        enable_hook(target(mix_a)).expect("the second attempt finds every thread started");
        assert_eq!(fault::rounds(), 3);
        fault::clear();
        fixture.assert_threads_run();
        assert!(hooked(mix_a));
    }

    #[test]
    fn a_refused_suspension_of_a_live_thread_is_retried() {
        let fixture = Fixture::new();
        // As Windows refuses a terminating thread whose handle is not yet signaled.
        fault::fail(Call::SuspendThread, 0b1);
        enable_hook(target(mix_a)).expect("the retry suspends it");
        assert_eq!(fault::rounds(), 3);
        fault::clear();
        fixture.assert_threads_run();
        assert!(hooked(mix_a));
    }

    #[test]
    fn a_refused_suspension_with_an_unknown_state_fails_closed() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        fault::fail(Call::SuspendThread, 0b1);
        fault::fail(Call::Wait, 0b1);
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadSuspend));
        assert_eq!(fault::rounds(), 1);
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(bytes(mix_a), before);
    }

    #[test]
    fn a_failed_wait_on_the_recheck_fails_closed() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        // A spinner looks gone; reopening it on the check works, but the wait that
        // would confirm it exited fails. No retry follows.
        fault::gone(fixture.spinners[0], 1);
        fault::fail(Call::Wait, u64::MAX);
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadSuspend));
        assert!(fault::rounds() <= 2);
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(bytes(mix_a), before);
    }

    fn slots(starts: &[usize]) -> SlotSet {
        SlotSet::new(starts.iter().copied())
    }

    #[test]
    fn slot_set_is_half_open_and_sorted() {
        let set = slots(&[0x9000, 0x1000]);
        assert!(!set.is_empty());
        assert!(set.contains(0x1000));
        assert!(set.contains(0x1000 + MEMORY_SLOT_SIZE - 1));
        assert!(!set.contains(0x1000 + MEMORY_SLOT_SIZE));
        assert!(!set.contains(0x0FFF));
        assert!(set.contains(0x9010));
        assert!(!set.contains(0x5000));
        assert!(!set.contains(0));
        assert!(slots(&[]).is_empty());
        assert!(!slots(&[]).contains(0x1000));
        assert!(!set.malformed);
        assert!(slots(&[usize::MAX - 8]).malformed);
    }

    /// A fake stack of `words` starting at `rsp`, read like `sys::read_stack`.
    /// `fail_at` fails the read that covers that address.
    fn reader(
        rsp: usize,
        words: &[u64],
        fail_at: Option<usize>,
    ) -> impl FnMut(usize, &mut [u64]) -> bool + '_ {
        move |address, out| {
            let end = address + out.len() * 8;
            if fail_at.is_some_and(|at| (address..end).contains(&at)) {
                return false;
            }
            let first = (address - rsp) / 8;
            match words.get(first..first + out.len()) {
                Some(found) => {
                    out.copy_from_slice(found);
                    true
                }
                None => false,
            }
        }
    }

    #[test]
    fn stack_scan_finds_a_slot_word_past_the_first_chunk() {
        let set = slots(&[0x7000]);
        let rsp = 0x10_0000;
        let mut words = vec![0u64; 3 * STACK_CHUNK_WORDS + 5];
        let base = rsp + words.len() * 8;
        let mut budget = MAX_TOTAL_SCAN_BYTES;
        assert_eq!(
            scan_stack(rsp, base, &set, &mut budget, reader(rsp, &words, None)),
            Reach::Clear
        );
        assert_eq!(budget, MAX_TOTAL_SCAN_BYTES - words.len() * 8);
        words[2 * STACK_CHUNK_WORDS + 3] = 0x7000 + 0x3F;
        assert_eq!(
            scan_stack(rsp, base, &set, &mut budget, reader(rsp, &words, None)),
            Reach::Stack
        );
        // The word just past the slot does not count.
        words[2 * STACK_CHUNK_WORDS + 3] = 0x7040;
        assert_eq!(
            scan_stack(rsp, base, &set, &mut budget, reader(rsp, &words, None)),
            Reach::Clear
        );
        // The topmost word, just below the base, is read.
        let last = words.len() - 1;
        words[last] = 0x7001;
        assert_eq!(
            scan_stack(rsp, base, &set, &mut budget, reader(rsp, &words, None)),
            Reach::Stack
        );
        // An unaligned RSP is scanned from the word that holds it.
        assert_eq!(
            scan_stack(rsp + 3, base, &set, &mut budget, reader(rsp, &words, None)),
            Reach::Stack
        );
    }

    #[test]
    fn stack_scan_uncertainty_is_unknown_never_clear() {
        let set = slots(&[0x7000]);
        let rsp = 0x10_0000;
        let words = vec![0u64; 2 * STACK_CHUNK_WORDS];
        let base = rsp + words.len() * 8;
        let full = MAX_TOTAL_SCAN_BYTES;
        let scan = |rsp: usize, base: usize, budget: usize, fail_at: Option<usize>| {
            let mut budget = budget;
            scan_stack(
                rsp,
                base,
                &set,
                &mut budget,
                reader(0x10_0000, &words, fail_at),
            )
        };
        // A read failing in the second chunk, after a clean first one.
        assert_eq!(
            scan(rsp, base, full, Some(rsp + STACK_CHUNK_WORDS * 8)),
            Reach::Unknown
        );
        assert_eq!(scan(0, base, full, None), Reach::Unknown);
        assert_eq!(scan(rsp, 0, full, None), Reach::Unknown);
        assert_eq!(scan(base + 8, base, full, None), Reach::Unknown);
        assert_eq!(scan(rsp, base + 4, full, None), Reach::Unknown);
        assert_eq!(scan(rsp, base, words.len() * 8 - 1, None), Reach::Unknown);
        assert_eq!(
            scan(rsp, rsp + MAX_STACK_SCAN_BYTES + 8, full, None),
            Reach::Unknown
        );
        // An empty live stack (RSP at the base) holds nothing.
        assert_eq!(scan(base, base, full, None), Reach::Clear);
    }

    #[test]
    fn every_register_and_the_moved_ip_are_checked() {
        let set = slots(&[0x7000]);
        // SAFETY: `CONTEXT` is plain data; all-zero is a valid value.
        let blank: CONTEXT = unsafe { std::mem::zeroed() };
        let rsp = 0x10_0000usize;
        let words = [0u64; 4];
        let base = Some(rsp + 32);
        let check = |context: &CONTEXT, new_ip: usize, base: Option<usize>| {
            let mut budget = MAX_TOTAL_SCAN_BYTES;
            reach(
                context,
                new_ip,
                base,
                &set,
                &mut budget,
                reader(rsp, &words, None),
            )
        };
        let mut clean = blank;
        clean.Rsp = rsp as u64;
        assert_eq!(check(&clean, 0x1234, base), Reach::Clear);
        assert_eq!(check(&clean, 0x7008, base), Reach::Rip);
        assert_eq!(check(&clean, 0x1234, None), Reach::Unknown);
        for index in 0..16 {
            let mut context = clean;
            let fields = [
                &mut context.Rax,
                &mut context.Rbx,
                &mut context.Rcx,
                &mut context.Rdx,
                &mut context.Rsi,
                &mut context.Rdi,
                &mut context.Rbp,
                &mut context.Rsp,
                &mut context.R8,
                &mut context.R9,
                &mut context.R10,
                &mut context.R11,
                &mut context.R12,
                &mut context.R13,
                &mut context.R14,
                &mut context.R15,
            ];
            *fields.into_iter().nth(index).unwrap() = 0x7010;
            assert_eq!(
                check(&context, 0x1234, base),
                Reach::Register,
                "register {index}"
            );
        }
        let malformed = slots(&[usize::MAX - 8]);
        let mut budget = MAX_TOTAL_SCAN_BYTES;
        assert_eq!(
            reach(
                &clean,
                0x1234,
                base,
                &malformed,
                &mut budget,
                reader(rsp, &words, None)
            ),
            Reach::Unknown
        );
    }

    #[test]
    fn moves_write_only_the_control_registers() {
        let mut captured = AlignedContext::captured();
        assert_eq!(
            captured.0.ContextFlags,
            CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64
        );
        captured.0.Rip = 0x1000;
        captured.0.R13 = 0x5555;
        let moved = captured.moved_to(0x2000);
        assert_eq!(moved.0.ContextFlags, CONTEXT_CONTROL_AMD64);
        assert_eq!(moved.0.Rip, 0x2000);
        assert_eq!(moved.0.R13, 0x5555);
        assert_eq!(captured.0.Rip, 0x1000);
    }

    /// XOR mask that keeps a held address out of memory in readable form.
    const MASK: u64 = 0x5A5A_5A5A_5A5A_5A5A;

    /// Spins with `masked ^ MASK` only in r13 (or only in a word it pushed) until
    /// `*stop` is nonzero, after setting `*ready` once the address is held.
    fn hold(masked: u64, on_stack: bool, ready: *mut u8, stop: *const u8) {
        if on_stack {
            // SAFETY: pushes one word and pops it before the block ends; reads and
            // writes only the two live flags.
            unsafe {
                std::arch::asm!(
                    "xor {value}, {mask}",
                    "push {value}",
                    "xor {value}, {value}",
                    "mov byte ptr [{ready}], 1",
                    "2:",
                    "pause",
                    "cmp byte ptr [{stop}], 0",
                    "je 2b",
                    "add rsp, 8",
                    value = inout(reg) masked => _,
                    mask = in(reg) MASK,
                    ready = in(reg) ready,
                    stop = in(reg) stop,
                );
            }
        } else {
            // SAFETY: touches only r13 (declared clobbered) and the two live flags.
            unsafe {
                std::arch::asm!(
                    "xor r13, {mask}",
                    "mov byte ptr [{ready}], 1",
                    "2:",
                    "pause",
                    "cmp byte ptr [{stop}], 0",
                    "je 2b",
                    "xor r13, r13",
                    mask = in(reg) MASK,
                    ready = in(reg) ready,
                    stop = in(reg) stop,
                    inout("r13") masked => _,
                );
            }
        }
    }

    /// A thread holding an address only in a register or only on its stack. Drop
    /// stops and joins it, so a failed assertion cannot leave it spinning.
    struct Holder {
        id: u32,
        stop: Arc<std::sync::atomic::AtomicU8>,
        thread: Option<JoinHandle<()>>,
    }

    impl Holder {
        fn start(address: usize, on_stack: bool) -> Self {
            use std::sync::atomic::AtomicU8;
            let stop = Arc::new(AtomicU8::new(0));
            let ready = Arc::new(AtomicU8::new(0));
            let masked = address as u64 ^ MASK;
            let (ids, id) = std::sync::mpsc::channel();
            let thread = std::thread::spawn({
                let (stop, ready) = (stop.clone(), ready.clone());
                move || {
                    // SAFETY: reads the calling thread's id.
                    let _ = ids.send(unsafe { GetCurrentThreadId() });
                    hold(masked, on_stack, ready.as_ptr(), stop.as_ptr());
                }
            });
            // The guard exists before anything can panic, so the thread is always
            // stopped and joined.
            let mut holder = Self {
                id: 0,
                stop,
                thread: Some(thread),
            };
            holder.id = id.recv().expect("holder id");
            let deadline = Instant::now() + Duration::from_secs(5);
            while ready.load(Ordering::Acquire) == 0 {
                assert!(Instant::now() < deadline, "holder never became ready");
                std::thread::yield_now();
            }
            holder
        }
    }

    impl Drop for Holder {
        fn drop(&mut self) {
            self.stop.store(1, Ordering::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    fn trampoline_of(f: MixFn) -> usize {
        let manager = get_manager().lock().unwrap();
        let pos = manager.find_hook_entry(target(f));
        manager.hooks.items[pos].trampoline as usize
    }

    fn is_created(f: MixFn) -> bool {
        get_manager().lock().unwrap().find_hook_entry(target(f)) != INVALID_HOOK_POS
    }

    fn slot_bytes(trampoline: usize) -> [u8; 16] {
        // SAFETY: the slot is kept allocated (retained) whenever this is called.
        unsafe { ptr::read_volatile(trampoline as *const [u8; 16]) }
    }

    /// Asserts a remove kept `mix_a`'s slot: the hook is gone, the buffers are
    /// retained, the slot's bytes are untouched and its trampoline still runs the
    /// original function, and a new hook is given a different slot.
    fn assert_slot_kept(trampoline: usize, before: [u8; 16], original: u64) {
        assert!(!is_created(mix_a));
        assert!(retain_buffers());
        assert_eq!(slot_bytes(trampoline), before);
        // SAFETY: the kept trampoline runs the original `mix_a`, of type `MixFn`.
        let through: MixFn = unsafe { std::mem::transmute::<usize, MixFn>(trampoline) };
        assert_eq!(through(7), original);
        create_hook(target(mix_a), detour as MixFn as *mut c_void).expect("recreate");
        assert_ne!(trampoline_of(mix_a), trampoline);
    }

    #[test]
    fn a_clean_remove_frees_the_slot() {
        let fixture = Fixture::new();
        let trampoline = trampoline_of(mix_a);
        remove_hook(target(mix_a)).expect("remove");
        let reaches = fault::reaches();
        assert!(!reaches.is_empty());
        // The spinners hold nothing in a slot, and their stacks read in full.
        for &spinner in &fixture.spinners {
            assert_eq!(fault::reach_of(spinner), Some(Reach::Clear));
        }
        // Another thread of the runtime may hold a stale copy, which keeps the slot
        // conservatively. Only a fully clean check must free it.
        if reaches.iter().all(|&found| found == Reach::Clear) {
            assert!(!retain_buffers());
            // The free list is LIFO and mix_b keeps the block mapped, so a freed
            // slot is the next one handed out.
            create_hook(target(mix_a), detour as MixFn as *mut c_void).expect("recreate");
            assert_eq!(trampoline_of(mix_a), trampoline);
        } else {
            assert!(retain_buffers());
        }
    }

    #[test]
    fn a_slot_held_only_in_a_register_is_kept() {
        let fixture = Fixture::new();
        let original = mix_a(7);
        let trampoline = trampoline_of(mix_a);
        let before = slot_bytes(trampoline);
        let holder = Holder::start(trampoline + 8, false);
        remove_hook(target(mix_a)).expect("a kept slot is not an error");
        assert_eq!(fault::reach_of(holder.id), Some(Reach::Register));
        drop(holder);
        fixture.assert_threads_run();
        assert_slot_kept(trampoline, before, original);
    }

    #[test]
    fn a_slot_held_only_on_a_stack_is_kept() {
        let fixture = Fixture::new();
        let original = mix_a(7);
        let trampoline = trampoline_of(mix_a);
        let before = slot_bytes(trampoline);
        let holder = Holder::start(trampoline + 8, true);
        remove_hook(target(mix_a)).expect("a kept slot is not an error");
        assert_eq!(fault::reach_of(holder.id), Some(Reach::Stack));
        drop(holder);
        fixture.assert_threads_run();
        assert_slot_kept(trampoline, before, original);
    }

    #[test]
    fn an_unreadable_stack_keeps_the_slot() {
        let fixture = Fixture::new();
        let original = mix_a(7);
        let trampoline = trampoline_of(mix_a);
        let before = slot_bytes(trampoline);
        fault::fail(Call::ReadStack, u64::MAX);
        remove_hook(target(mix_a)).expect("a kept slot is not an error");
        fault::clear();
        assert_eq!(fault::reach_of(fixture.spinners[0]), Some(Reach::Unknown));
        fixture.assert_threads_run();
        assert_slot_kept(trampoline, before, original);
    }

    #[test]
    fn a_missing_stack_base_keeps_the_slot() {
        let fixture = Fixture::new();
        let original = mix_a(7);
        let trampoline = trampoline_of(mix_a);
        let before = slot_bytes(trampoline);
        fault::fail(Call::StackBase, u64::MAX);
        remove_hook(target(mix_a)).expect("a kept slot is not an error");
        fault::clear();
        assert_eq!(fault::reach_of(fixture.spinners[0]), Some(Reach::Unknown));
        fixture.assert_threads_run();
        assert_slot_kept(trampoline, before, original);
    }

    #[test]
    fn an_unreadable_stack_keeps_the_buffers_on_uninitialize() {
        let fixture = Fixture::new();
        let original = mix_a(7);
        let trampoline = trampoline_of(mix_a);
        let before = slot_bytes(trampoline);
        enable_hook(target(mix_a)).expect("enable");
        fault::fail(Call::ReadStack, u64::MAX);
        uninitialize().expect("kept buffers are not an error");
        fault::clear();
        assert_eq!(fault::reach_of(fixture.spinners[0]), Some(Reach::Unknown));
        fixture.assert_threads_run();
        assert!(!hooked(mix_a));
        assert!(retain_buffers());
        assert_eq!(slot_bytes(trampoline), before);
        // SAFETY: the kept trampoline runs the original `mix_a`, of type `MixFn`.
        let through: MixFn = unsafe { std::mem::transmute::<usize, MixFn>(trampoline) };
        assert_eq!(through(7), original);
        initialize().expect("uninitialize completed");
    }
}
