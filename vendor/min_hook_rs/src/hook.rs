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
use std::sync::{Mutex, OnceLock};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::LibraryLoader::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Hook module only supports x86_64 architecture");

/// Initial capacity for the hook entry buffer.
const INITIAL_HOOK_CAPACITY: usize = 32;
/// Initial capacity for the thread ID buffer.
const INITIAL_THREAD_CAPACITY: usize = 128;
/// Special value indicating an invalid hook position.
const INVALID_HOOK_POS: usize = usize::MAX;
/// Thread access rights for suspending/resuming threads.
const THREAD_ACCESS: u32 =
    THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION | THREAD_SET_CONTEXT;

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

    /// Returns true if `ip` lies in the hook's trampoline slot, which also holds the relay.
    fn slot_contains(&self, ip: usize) -> bool {
        let start = self.trampoline as usize;
        ip >= start && ip < start + MEMORY_SLOT_SIZE
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
    fn control() -> Self {
        // SAFETY: `CONTEXT` is plain data; all-zero is a valid value.
        let mut context = Self(unsafe { std::mem::zeroed::<CONTEXT>() });
        context.0.ContextFlags = CONTEXT_CONTROL_AMD64;
        context
    }
}

/// A suspended thread whose instruction pointer must move.
struct ThreadMove {
    handle: HANDLE,
    context: AlignedContext,
    original_ip: u64,
}

/// Threads suspended by [`FrozenThreads::freeze`]. Each handle stays open until its
/// thread is resumed, which happens on drop, so every early return resumes them.
struct FrozenThreads {
    handles: Vec<HANDLE>,
}

impl FrozenThreads {
    /// Suspends every thread in `ids`. Fails closed: if any live thread of this
    /// process cannot be opened or suspended, the threads already suspended are
    /// resumed and an error is returned. A thread that has exited is skipped.
    fn freeze(ids: &[u32]) -> Result<Self> {
        // Allocate before suspending: a suspended thread may hold the heap lock.
        let mut frozen = Self {
            handles: Vec::with_capacity(ids.len()),
        };
        // SAFETY: plain Win32 calls on handles this function opens and owns.
        unsafe {
            let process_id = GetCurrentProcessId();
            for &id in ids {
                let handle = sys::open_thread(id);
                if handle.is_null() {
                    // The id no longer names a thread: it exited after the snapshot.
                    if GetLastError() == ERROR_INVALID_PARAMETER {
                        continue;
                    }
                    return Err(HookError::ThreadSuspend);
                }
                let owner = GetProcessIdOfThread(handle);
                if owner != process_id {
                    CloseHandle(handle);
                    // A reused id now names another process's thread; ours exited.
                    if owner != 0 {
                        continue;
                    }
                    return Err(HookError::ThreadSuspend);
                }
                if !sys::suspend_thread(handle) {
                    let mut exit_code = 0u32;
                    let exited = GetExitCodeThread(handle, &mut exit_code) != 0
                        && exit_code != STILL_ACTIVE.cast_unsigned();
                    CloseHandle(handle);
                    if exited {
                        continue;
                    }
                    return Err(HookError::ThreadSuspend);
                }
                frozen.handles.push(handle);
            }
        }
        Ok(frozen)
    }
}

impl Drop for FrozenThreads {
    fn drop(&mut self) {
        for &handle in &self.handles {
            // SAFETY: `handle` was opened and suspended by `freeze` and is still open.
            unsafe {
                ResumeThread(handle);
                CloseHandle(handle);
            }
        }
    }
}

/// Enumerates all threads in the current process except the current thread.
fn enumerate_threads() -> Result<Vec<u32>> {
    let mut threads = Vec::with_capacity(INITIAL_THREAD_CAPACITY);
    // SAFETY: Toolhelp calls on a snapshot handle this function owns.
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == INVALID_HANDLE_VALUE {
            return Err(HookError::ThreadSuspend);
        }
        let mut te = THREADENTRY32 {
            dwSize: size_of::<THREADENTRY32>() as u32,
            cntUsage: 0,
            th32ThreadID: 0,
            th32OwnerProcessID: 0,
            tpBasePri: 0,
            tpDeltaPri: 0,
            dwFlags: 0,
        };
        let mut succeeded = false;
        if Thread32First(snapshot, &mut te) != 0 {
            loop {
                if te.dwSize >= 16
                    && te.th32OwnerProcessID == GetCurrentProcessId()
                    && te.th32ThreadID != GetCurrentThreadId()
                {
                    threads.push(te.th32ThreadID);
                }
                te.dwSize = size_of::<THREADENTRY32>() as u32;
                if Thread32Next(snapshot, &mut te) == 0 {
                    break;
                }
            }
            succeeded = GetLastError() == ERROR_NO_MORE_FILES;
        }
        CloseHandle(snapshot);
        if !succeeded {
            return Err(HookError::ThreadSuspend);
        }
    }
    Ok(threads)
}

/// Syscalls the freeze depends on. Under `cfg(test)` each can be made to fail.
mod sys {
    use super::*;

    pub(super) unsafe fn open_thread(id: u32) -> HANDLE {
        #[cfg(test)]
        if let Some(error) = fault::open_thread() {
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

    pub(super) unsafe fn get_context(handle: HANDLE, context: &mut AlignedContext) -> bool {
        #[cfg(test)]
        if fault::hit(fault::Call::GetContext) {
            return false;
        }
        // SAFETY: the caller passes an open, suspended thread; the buffer is aligned.
        unsafe { GetThreadContext(handle, &mut context.0) != 0 }
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

    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub(crate) enum Call {
        OpenThread,
        SuspendThread,
        GetContext,
        SetContext,
        Protect,
    }

    thread_local! {
        /// The call to fail, a bitmask of which calls (by index) fail, and the next index.
        static PLAN: Cell<Option<(Call, u64, u32)>> = const { Cell::new(None) };
        /// The last-error value an injected `OpenThread` failure reports.
        static OPEN_ERROR: Cell<u32> = const { Cell::new(5) };
        static FORCE_MOVES: Cell<bool> = const { Cell::new(false) };
    }

    /// Fails the calls to `call` whose zero-based index is set in `mask`.
    pub(crate) fn fail(call: Call, mask: u64) {
        PLAN.with(|plan| plan.set(Some((call, mask, 0))));
    }

    /// Sets the last error an injected `OpenThread` failure reports.
    pub(crate) fn open_error(error: u32) {
        OPEN_ERROR.with(|value| value.set(error));
    }

    pub(crate) fn set_force_moves(force: bool) {
        FORCE_MOVES.with(|value| value.set(force));
    }

    pub(crate) fn clear() {
        PLAN.with(|plan| plan.set(None));
        OPEN_ERROR.with(|value| value.set(5));
        FORCE_MOVES.with(|value| value.set(false));
    }

    pub(super) fn hit(call: Call) -> bool {
        PLAN.with(|plan| match plan.get() {
            Some((planned, mask, index)) if planned == call => {
                plan.set(Some((planned, mask, index + 1)));
                index < 64 && mask & (1 << index) != 0
            }
            _ => false,
        })
    }

    pub(super) fn open_thread() -> Option<u32> {
        hit(Call::OpenThread).then(|| OPEN_ERROR.with(Cell::get))
    }

    pub(super) fn force_moves() -> bool {
        FORCE_MOVES.with(Cell::get)
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
    /// 1. read each thread's context and compute where it must resume (no writes);
    /// 2. make every patch range writable, then write the bytes;
    /// 3. write the moved contexts.
    ///
    /// On failure nothing changes: the bytes and the contexts already written are
    /// restored. If a context cannot be restored, every hook in the batch is left
    /// disabled (a moved thread is then either in a kept trampoline or at original
    /// code), the trampoline buffers are retained for good, and an error is returned.
    ///
    /// Returns whether every thread was verified to be outside the trampoline slots
    /// of the hooks in `watch` once the batch applied.
    fn transact(&mut self, batch: &[(usize, bool)], watch: &[usize]) -> Result<bool> {
        if batch.is_empty() && watch.is_empty() {
            return Ok(true);
        }
        let ids = enumerate_threads()?;
        // Allocate before freezing: a suspended thread may hold the heap lock.
        let mut moves: Vec<ThreadMove> = Vec::with_capacity(ids.len());
        let mut protections: Vec<u32> = Vec::with_capacity(batch.len());
        let frozen = FrozenThreads::freeze(&ids)?;
        let hooks = &self.hooks.items;

        // Step 1: read contexts and plan the moves.
        let mut clear = true;
        for &handle in &frozen.handles {
            let mut context = AlignedContext::control();
            // SAFETY: `handle` is an open, suspended thread of this process.
            if !unsafe { sys::get_context(handle, &mut context) } {
                return Err(HookError::ThreadContext);
            }
            let ip = context.0.Rip;
            let new_ip = plan_ip(hooks, batch, ip as usize);
            if watch.iter().any(|&pos| hooks[pos].slot_contains(new_ip)) {
                clear = false;
            }
            if new_ip as u64 != ip || sys::force_moves() {
                context.0.Rip = new_ip as u64;
                moves.push(ThreadMove {
                    handle,
                    context,
                    original_ip: ip,
                });
            }
        }

        // Step 2: unprotect every range first, so the byte writes cannot fail.
        for &(pos, _) in batch {
            let (address, size) = hooks[pos].patch_range();
            let mut old_protect = 0u32;
            // SAFETY: the patch range lies in the hooked, mapped function.
            if !unsafe { sys::protect(address, size, PAGE_EXECUTE_READWRITE, &mut old_protect) } {
                Self::reprotect(hooks, batch, &protections);
                return Err(HookError::MemoryProtect);
            }
            protections.push(old_protect);
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

        Self::reprotect(hooks, batch, &protections);
        drop(frozen);

        if end_disabled {
            self.retain_buffers = true;
            for &(pos, _) in batch {
                self.hooks.items[pos].is_enabled = false;
                self.hooks.items[pos].queue_enable = false;
            }
        }
        result?;
        for &(pos, enable) in batch {
            self.hooks.items[pos].is_enabled = enable;
            self.hooks.items[pos].queue_enable = enable;
        }
        Ok(clear)
    }

    /// Restores the protections saved for the first `protections.len()` batch entries,
    /// in reverse so shared pages end with their original protection, then flushes.
    fn reprotect(hooks: &[HookEntry], batch: &[(usize, bool)], protections: &[u32]) {
        for (&(pos, _), &old) in batch.iter().zip(protections).rev() {
            let (address, size) = hooks[pos].patch_range();
            let mut ignored = 0u32;
            // SAFETY: restores the protection this transaction changed on a mapped range.
            unsafe {
                VirtualProtect(address as *mut c_void, size, old, &mut ignored);
                FlushInstructionCache(GetCurrentProcess(), address as *const c_void, size);
            }
        }
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
        if !is_executable_address(target) || !is_executable_address(detour) {
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

    /// A fault mask hitting the last thread the freeze visits, so every other
    /// thread (spinners included) is suspended first and must be resumed.
    fn last_thread() -> u64 {
        1 << (enumerate_threads().expect("enumerate").len() - 1)
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
            let threads = (0..2)
                .map(|_| {
                    let (stop, count) = (stop.clone(), count.clone());
                    std::thread::spawn(move || {
                        while !stop.load(Ordering::Relaxed) {
                            count.fetch_add(1, Ordering::Relaxed);
                            std::hint::spin_loop();
                        }
                    })
                })
                .collect();
            // Make sure the spinners exist before the test freezes anything.
            let fixture = Self {
                stop,
                count,
                threads,
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

        assert!(hooks[0].slot_contains(0x2010));
        assert!(!hooks[0].slot_contains(0x2000 + MEMORY_SLOT_SIZE));
    }

    #[test]
    fn open_failure_resumes_threads_and_patches_nothing() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        fault::fail(Call::OpenThread, last_thread());
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
        fault::fail(Call::SuspendThread, last_thread());
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadSuspend));
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(bytes(mix_a), before);
        enable_hook(target(mix_a)).expect("retry");
    }

    #[test]
    fn exited_thread_is_skipped() {
        let _fixture = Fixture::new();
        fault::open_error(ERROR_INVALID_PARAMETER);
        fault::fail(Call::OpenThread, 0b1);
        enable_hook(target(mix_a)).expect("an exited thread does not block the freeze");
        assert!(hooked(mix_a));
    }

    #[test]
    fn context_read_failure_patches_nothing() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        fault::fail(Call::GetContext, 0b10);
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
        fault::fail(Call::OpenThread, last_thread());
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
        fault::fail(Call::SuspendThread, last_thread());
        assert_eq!(remove_hook(target(mix_a)), Err(HookError::ThreadSuspend));
        // A disabled hook is still verified before its trampoline is freed.
        fault::fail(Call::GetContext, 0b1);
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
        fault::fail(Call::GetContext, 0b1);
        assert_eq!(uninitialize(), Err(HookError::ThreadContext));
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(initialize(), Err(HookError::AlreadyInitialized));
        assert!(hooked(mix_a));
        uninitialize().expect("uninitialize");
        assert!(!hooked(mix_a));
    }
}
