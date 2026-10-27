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
use crate::trampoline::{SNAPSHOT_CODE, Snapshot, create_trampoline};
use std::ffi::c_void;
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use thread_freeze::{AcquireError, Context, Freeze, FreezeError, Scan};
use windows_sys::Win32::System::Diagnostics::Debug::{FlushInstructionCache, ReadProcessMemory};
use windows_sys::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// The live freeze ops in a release build; the fault-injecting wrapper under test.
#[cfg(not(test))]
type Ops = thread_freeze::LiveOps;
#[cfg(test)]
type Ops = fault::FaultOps;

#[cfg(not(target_arch = "x86_64"))]
compile_error!("Hook module only supports x86_64 architecture");

/// Initial capacity for the hook entry buffer.
const INITIAL_HOOK_CAPACITY: usize = 32;
/// Upper bound on the threads one freeze may hold. A game process has far fewer.
const MAX_THREADS: usize = thread_freeze::MAX_THREADS;
/// Special value indicating an invalid hook position.
const INVALID_HOOK_POS: usize = usize::MAX;
/// Mirrors the engine's bound, for the hide schedule and the tests' round counts.
#[cfg(test)]
const FREEZE_ATTEMPTS: usize = 16;
/// How many times a failed protection restore is retried.
const RESTORE_ATTEMPTS: usize = 3;
const PAGE_SIZE: usize = 0x1000;
/// Most source bytes a trampoline copies: an instruction starts at offset 4 or less
/// and is at most 15 bytes long.
const MAX_SOURCE_LEN: usize = size_of::<JmpRel>() - 1 + 15;
/// Most bytes one hook's footprint covers: the hot-patch bytes above the target and
/// the source bytes from it.
const MAX_FOOTPRINT: usize = size_of::<JmpRel>() + MAX_SOURCE_LEN;
/// Most pages one footprint (at most 24 bytes) can touch.
const MAX_PATCH_PAGES: usize = 2;

/// True once a freeze left a live thread suspended. Terminal for the process. The
/// engine owns the single latch both callers share.
pub fn thaw_failed() -> bool {
    thread_freeze::thaw_failed()
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
    /// The footprint's bytes as the trampoline was built from them (see
    /// [`HookEntry::footprint`]). The first `patch_range().1` are the bytes a disable
    /// writes back.
    original: [u8; MAX_FOOTPRINT],
    /// How many bytes from `target` the trampoline copied or relocated.
    source_len: u8,
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
            original: [0; MAX_FOOTPRINT],
            source_len: 0,
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

    /// The bytes the hook depends on, as `(start, len)`: its patch range together
    /// with the source bytes its trampoline copied. The trampoline is a copy of those
    /// bytes, and one that ran out of room jumps back to `target + source_len`, so a
    /// write anywhere in the footprint would break it even where it misses the patch
    /// range. Both start at the same address. Never longer than [`MAX_FOOTPRINT`].
    fn footprint(&self) -> (usize, usize) {
        let (start, patch_len) = self.patch_range();
        let start = start as usize;
        let end = (start + patch_len).max(self.target as usize + usize::from(self.source_len));
        (start, end - start)
    }

    /// The bytes an enabled hook holds in its patch range, and how many there are:
    /// a 5-byte jump to the relay, and with the hot patch, a 2-byte short jump back
    /// to it at the target.
    fn patch_bytes(&self) -> ([u8; size_of::<JmpRel>() + size_of::<JmpRelShort>()], usize) {
        let (patch_target, len) = self.patch_range();
        let jmp = JmpRel::new_jmp(
            (self.detour as isize - (patch_target as isize + size_of::<JmpRel>() as isize)) as i32,
        );
        let mut bytes = [0u8; size_of::<JmpRel>() + size_of::<JmpRelShort>()];
        // SAFETY: `JmpRel` and `JmpRelShort` are packed plain bytes of these sizes.
        unsafe {
            ptr::copy_nonoverlapping(
                &jmp as *const JmpRel as *const u8,
                bytes.as_mut_ptr(),
                size_of::<JmpRel>(),
            );
            if self.patch_above {
                let short_jmp =
                    JmpRelShort::new(-(size_of::<JmpRelShort>() as i8 + size_of::<JmpRel>() as i8));
                ptr::copy_nonoverlapping(
                    &short_jmp as *const JmpRelShort as *const u8,
                    bytes.as_mut_ptr().add(size_of::<JmpRel>()),
                    size_of::<JmpRelShort>(),
                );
            }
        }
        (bytes, len)
    }

    /// What the footprint holds when the hook is `enabled`, or not: the original
    /// bytes, with the patch range replaced by the jumps when enabled.
    fn image(&self, enabled: bool) -> [u8; MAX_FOOTPRINT] {
        let mut image = self.original;
        if enabled {
            let (bytes, len) = self.patch_bytes();
            image[..len].copy_from_slice(&bytes[..len]);
        }
        image
    }

    /// Writes the jump (`enable`) or the original prologue (`!enable`).
    ///
    /// # Safety
    ///
    /// The patch range must be writable and no thread may be executing it.
    unsafe fn write_patch(&self, enable: bool) {
        let (patch_target, len) = self.patch_range();
        let image = self.image(enable);
        // SAFETY: the caller made the patch range writable and froze every other thread.
        unsafe { ptr::copy_nonoverlapping(image.as_ptr(), patch_target, len) };
    }

    /// Whether the footprint in memory holds what it must while the hook is
    /// `enabled` (or not). Reads without faulting and without allocating; a failed
    /// read counts as a mismatch.
    fn footprint_matches(&self, enabled: bool) -> bool {
        let (start, len) = self.footprint();
        let mut live = [0u8; MAX_FOOTPRINT];
        // SAFETY: the read is validated and fails instead of faulting.
        let read = unsafe { sys::read_code(start, &mut live[..len]) };
        read && live[..len] == self.image(enabled)[..len]
    }
}

/// True when the half-open ranges `[a, a + a_len)` and `[b, b + b_len)` share a byte.
fn ranges_overlap(a: usize, a_len: usize, b: usize, b_len: usize) -> bool {
    a_len != 0 && b_len != 0 && a < b.saturating_add(b_len) && b < a.saturating_add(a_len)
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

/// Most stack bytes one transaction reads across every thread, so the time threads
/// stay frozen is bounded. Past it the remaining threads count as unknown.
const MAX_TOTAL_SCAN_BYTES: usize = 256 * 1024 * 1024;

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

/// A frozen thread whose instruction pointer must move, by index into the freeze.
struct ThreadMove {
    index: usize,
    moved: Context,
    original: Context,
}

/// Thaws `frozen` after an error, returning `error`, or [`HookError::ThreadResume`]
/// when a thread stayed suspended (the engine has set the terminal latch).
fn abort(frozen: Freeze<Ops>, error: HookError) -> HookError {
    match frozen.thaw() {
        Ok(()) => error,
        Err(_) => HookError::ThreadResume,
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

/// Reads the target's code once, without faulting: the hot-patch bytes above it,
/// and as much of [`SNAPSHOT_CODE`] from it as is readable. The read is split at a
/// page boundary, so code that ends at the end of a mapping still yields its
/// readable part; [`create_trampoline`] refuses what it would need beyond that.
fn snapshot(target: usize) -> Snapshot {
    let mut snapshot = Snapshot {
        above: None,
        code: [0; SNAPSHOT_CODE],
        len: 0,
    };
    if let Some(above) = target.checked_sub(size_of::<JmpRel>()) {
        let mut bytes = [0u8; size_of::<JmpRel>()];
        // SAFETY: the read is validated and fails instead of faulting.
        if unsafe { sys::read_raw(above, &mut bytes) } {
            snapshot.above = Some(bytes);
        }
    }
    let first = (PAGE_SIZE - target % PAGE_SIZE).min(SNAPSHOT_CODE);
    // SAFETY: as above.
    if unsafe { sys::read_raw(target, &mut snapshot.code[..first]) } {
        snapshot.len = first;
        // SAFETY: as above.
        if first < SNAPSHOT_CODE
            && unsafe { sys::read_raw(target + first, &mut snapshot.code[first..]) }
        {
            snapshot.len = SNAPSHOT_CODE;
        }
    }
    snapshot
}

/// The `len` bytes at `start` from a snapshot of the code at `target`, `start`
/// being at most the hot-patch size below it. `None` if the snapshot lacks them.
fn snapshot_bytes(
    snapshot: &Snapshot,
    target: usize,
    start: usize,
    len: usize,
) -> Option<[u8; MAX_FOOTPRINT]> {
    let mut out = [0u8; MAX_FOOTPRINT];
    for (index, byte) in out[..len].iter_mut().enumerate() {
        let address = start.checked_add(index)?;
        *byte = if address < target {
            let above = snapshot.above.as_ref()?;
            *above.get(size_of::<JmpRel>() - (target - address))?
        } else {
            *snapshot.code[..snapshot.len].get(address - target)?
        };
    }
    Some(out)
}

/// The non-freeze memory syscalls. Under `cfg(test)` each can be made to fail. The
/// freeze's own syscalls live in the `thread_freeze` engine.
mod sys {
    use super::*;

    /// Reads a hook's footprint just before a write, failing instead of faulting.
    pub(super) unsafe fn read_code(address: usize, out: &mut [u8]) -> bool {
        #[cfg(test)]
        if fault::hit(fault::Call::ReadCode) {
            return false;
        }
        // SAFETY: forwarded from the caller.
        unsafe { read_raw(address, out) }
    }

    /// Reads `out.len()` bytes at `address` of this process; a short read fails.
    pub(super) unsafe fn read_raw(address: usize, out: &mut [u8]) -> bool {
        let mut copied = 0usize;
        // SAFETY: ReadProcessMemory validates the source range and fails instead of
        // faulting; `out` is writable for its length.
        let read = unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                address as *const c_void,
                out.as_mut_ptr().cast(),
                out.len(),
                &mut copied,
            )
        };
        read != 0 && copied == out.len()
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

    /// Whether every suspended thread is given a (no-op) context write, so tests can
    /// reach the context-apply step without parking a thread in a hook.
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
    use windows_sys::Win32::System::Threading::{
        GetThreadId, OpenThread, ResumeThread, THREAD_SUSPEND_RESUME,
    };

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
        ReadCode,
    }

    const CALLS: usize = 12;
    /// Most freeze rounds a hide schedule covers (one enumeration per attempt).
    const MAX_ROUNDS: usize = super::FREEZE_ATTEMPTS;

    thread_local! {
        /// Per call: a bitmask of which calls (by zero-based index) fail, and the next index.
        static PLAN: Cell<[(u64, u32); CALLS]> = const { Cell::new([(0, 0); CALLS]) };
        static FORCE_MOVES: Cell<bool> = const { Cell::new(false) };
        /// A thread id whose resumes fail, and how many more of them fail.
        static STICK: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
        /// A thread id whose opens report it gone, and how many more of them do.
        static GONE: Cell<(u32, u32)> = const { Cell::new((0, 0)) };
        /// Per freeze attempt, how many trailing candidate ids the enumeration hides,
        /// so a hidden thread shows only in the frozen recheck. And how many ran.
        static HIDE: Cell<([u8; MAX_ROUNDS], usize)> = const { Cell::new(([0; MAX_ROUNDS], 0)) };
    }

    /// Hides `schedule[round]` trailing ids from each freeze round's enumeration.
    pub(crate) fn hide(schedule: &[u8]) {
        let mut rounds = [0; MAX_ROUNDS];
        rounds[..schedule.len()].copy_from_slice(schedule);
        HIDE.with(|hide| hide.set((rounds, 0)));
    }

    pub(super) fn hide_threads(ids: &mut thread_freeze::IdSet) {
        HIDE.with(|hide| {
            let (schedule, round) = hide.get();
            let count = schedule.get(round).copied().unwrap_or(0);
            ids.drop_last(usize::from(count));
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

    /// Resumes the thread the thaw left suspended (the one [`stick`] targets), then
    /// clears the engine's terminal latch. Returns how many it resumed. The engine
    /// leaked the original handle on purpose; a fresh handle resumes the thread.
    pub(crate) fn release_stuck() -> usize {
        let id = STICK.with(|stick| stick.get().0);
        let mut released = 0;
        if id != 0 {
            // SAFETY: OpenThread/ResumeThread on a thread id; failure is ignored.
            unsafe {
                let handle = OpenThread(THREAD_SUSPEND_RESUME, 0, id);
                if !handle.is_null() {
                    ResumeThread(handle);
                    CloseHandle(handle);
                    released = 1;
                }
            }
        }
        thread_freeze::reset_thaw_failed();
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

    /// Whether a resume of `handle`'s thread should fail now (the [`stick`] target).
    pub(super) fn resume_should_fail(handle: usize) -> bool {
        resume_fails(handle)
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

    pub(super) fn resume_fails(handle: usize) -> bool {
        STICK.with(|stick| {
            let (id, times) = stick.get();
            // SAFETY: `handle` is an open thread handle.
            if times == 0 || unsafe { GetThreadId(handle as HANDLE) } != id {
                return false;
            }
            stick.set((id, times - 1));
            true
        })
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
    pub(super) fn record_reach(id: u32, found: super::Reach) {
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

    /// A `ThreadOps` that wraps the live ops and injects the failures above, so the
    /// hook tests drive the real engine freeze through the fault plan.
    pub(crate) struct FaultOps(thread_freeze::LiveOps);

    impl FaultOps {
        pub(crate) fn new() -> Result<Self, thread_freeze::FreezeError> {
            thread_freeze::LiveOps::new().map(Self)
        }
    }

    impl thread_freeze::ThreadOps for FaultOps {
        type Handle = <thread_freeze::LiveOps as thread_freeze::ThreadOps>::Handle;

        fn enumerate(
            &mut self,
            ids: &mut thread_freeze::IdSet,
        ) -> Result<(), thread_freeze::FreezeError> {
            self.0.enumerate(ids)?;
            hide_threads(ids);
            Ok(())
        }
        fn fingerprint(&mut self) -> Option<usize> {
            self.0.fingerprint()
        }
        fn walks_when_frozen(&self) -> bool {
            self.0.walks_when_frozen()
        }
        fn open(&mut self, id: u32) -> Result<Self::Handle, thread_freeze::OpenError> {
            match open_thread(id) {
                Some(ERROR_INVALID_PARAMETER) => Err(thread_freeze::OpenError::Gone),
                Some(_) => Err(thread_freeze::OpenError::Failed),
                None => self.0.open(id),
            }
        }
        fn suspend(&mut self, handle: Self::Handle) -> bool {
            if hit(Call::SuspendThread) {
                return false;
            }
            self.0.suspend(handle)
        }
        fn resume(&mut self, handle: Self::Handle) -> bool {
            if resume_should_fail(handle) {
                return false;
            }
            self.0.resume(handle)
        }
        fn liveness(&mut self, handle: Self::Handle) -> thread_freeze::Liveness {
            if hit(Call::Wait) {
                return thread_freeze::Liveness::Unknown;
            }
            self.0.liveness(handle)
        }
        fn started(&mut self, handle: Self::Handle) -> Option<bool> {
            if hit(Call::Started) {
                return Some(false);
            }
            self.0.started(handle)
        }
        fn capture(&mut self, handle: Self::Handle, context: &mut thread_freeze::Context) -> bool {
            if hit(Call::GetContext) {
                return false;
            }
            self.0.capture(handle, context)
        }
        fn set_context(&mut self, handle: Self::Handle, context: &thread_freeze::Context) -> bool {
            if hit(Call::SetContext) {
                return false;
            }
            self.0.set_context(handle, context)
        }
        fn stack_base(&mut self, handle: Self::Handle) -> Option<usize> {
            if hit(Call::StackBase) {
                return None;
            }
            self.0.stack_base(handle)
        }
        fn read_words(&mut self, address: usize, out: &mut [u64]) -> bool {
            if hit(Call::ReadStack) {
                return false;
            }
            self.0.read_words(address, out)
        }
        fn close(&mut self, handle: Self::Handle) {
            self.0.close(handle);
        }
        fn pause(&mut self) {
            self.0.pause();
        }
        fn next_thread(
            &mut self,
            cursor: Option<Self::Handle>,
        ) -> thread_freeze::NextThread<Self::Handle> {
            self.0.next_thread(cursor)
        }
        fn thread_id(&mut self, handle: Self::Handle) -> Option<u32> {
            self.0.thread_id(handle)
        }
        fn current_thread_id(&self) -> u32 {
            self.0.current_thread_id()
        }
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
        let ops = Ops::new().map_err(|_| HookError::ThreadSuspend)?;
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
        let mut frozen = match Freeze::acquire(ops) {
            Ok(frozen) => frozen,
            Err(AcquireError::Aborted(FreezeError::Context)) => {
                return Err(HookError::ThreadContext);
            }
            Err(AcquireError::Aborted(_)) => return Err(HookError::ThreadSuspend),
            // The engine set the terminal latch and leaked the suspended thread. Keep
            // this scratch too: a stuck thread may hold the heap lock.
            Err(AcquireError::Terminal(_)) => {
                core::mem::forget((moves, journal, slots));
                return Err(HookError::ThreadResume);
            }
        };

        // Step 1: plan the moves from the contexts the freeze read. A second read
        // would be a second chance to block. A watched slot stays allocated while
        // any thread may still reach it, or nothing is known about one.
        let mut clear = true;
        let mut budget = MAX_TOTAL_SCAN_BYTES;
        for index in 0..frozen.len() {
            let captured = *frozen.context(index);
            let ip = captured.rip();
            let new_ip = plan_ip(&self.hooks.items, batch, ip);
            // Tests check every thread, so each holder's own finding is recorded.
            if !slots.is_empty() && (clear || cfg!(test)) {
                let found = if slots.malformed {
                    Reach::Unknown
                } else if slots.contains(new_ip) {
                    Reach::Rip
                } else if captured.registers().iter().any(|&r| slots.contains_word(r)) {
                    Reach::Register
                } else {
                    match frozen.scan_thread_stack(index, &mut budget, |w| slots.contains_word(w)) {
                        Scan::Clear => Reach::Clear,
                        Scan::Hit => Reach::Stack,
                        Scan::Unknown => Reach::Unknown,
                    }
                };
                #[cfg(test)]
                if let Some(id) = frozen.thread_id(index) {
                    fault::record_reach(id, found);
                }
                clear &= found == Reach::Clear;
            }
            if new_ip != ip || sys::force_moves() {
                moves.push(ThreadMove {
                    index,
                    moved: captured.moved_to(new_ip),
                    original: captured,
                });
            }
        }

        let hooks = &self.hooks.items;

        // Step 2: unprotect every page first, so the byte writes cannot fail. The
        // whole footprint, not only the patch range, so it can be read back even
        // where its source bytes reach an execute-only page.
        for &(pos, _) in batch {
            let (address, size) = hooks[pos].footprint();
            if !make_writable(&mut journal, address, size) {
                restore_protection(&mut journal);
                let error = abort(frozen, HookError::MemoryProtect);
                if error == HookError::ThreadResume {
                    core::mem::forget((moves, journal, slots));
                }
                return Err(error);
            }
        }
        // With every thread frozen nothing can change the bytes between this check
        // and the write: each footprint must still hold what the hook last left
        // there, the original bytes (enable) or its own jump (disable).
        if batch
            .iter()
            .any(|&(pos, enable)| !hooks[pos].footprint_matches(!enable))
        {
            restore_protection(&mut journal);
            let error = abort(frozen, HookError::TargetModified);
            if error == HookError::ThreadResume {
                core::mem::forget((moves, journal, slots));
            }
            return Err(error);
        }
        for &(pos, enable) in batch {
            // SAFETY: the range is writable and every other thread is frozen.
            unsafe { hooks[pos].write_patch(enable) };
        }

        // Step 3: move the threads.
        let mut result = Ok(());
        let mut end_disabled = false;
        for i in 0..moves.len() {
            if frozen.set_context(moves[i].index, &moves[i].moved) {
                continue;
            }
            result = Err(HookError::ThreadContext);
            let mut restored = true;
            for done in &moves[..i] {
                restored &= frozen.set_context(done.index, &done.original);
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
        let thawed = frozen.thaw().is_ok();

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
            // A thread stays suspended: keep this scratch rather than drop it, as the
            // engine keeps its own, since a stuck thread may hold the heap lock.
            core::mem::forget((moves, journal, slots));
            return Err(HookError::ThreadResume);
        }
        result?;
        Ok(clear)
    }

    /// Runs [`HookManager::transact`] with owned `batch` and `watch` vectors, kept
    /// (forgotten) rather than dropped on a terminal [`HookError::ThreadResume`]: a
    /// thread stays suspended and may hold the heap lock a drop would take.
    fn transact_owned(&mut self, batch: Vec<(usize, bool)>, watch: Vec<usize>) -> Result<bool> {
        match self.transact(&batch, &watch) {
            Err(HookError::ThreadResume) => {
                core::mem::forget((batch, watch));
                Err(HookError::ThreadResume)
            }
            other => other,
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
        self.transact_owned(batch, Vec::new()).map(|_| ())
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
        self.transact_owned(batch, Vec::new()).map(|_| ())
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
        let clear = self.transact_owned(batch, watch)?;
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

    /// Creates a new hook for the specified target and detour. A hook whose
    /// footprint (patch range, hot-patch bytes and copied source bytes) overlaps an
    /// existing one's, enabled, disabled or queued, is refused with
    /// [`HookError::Overlapping`]. The trampoline is built from one snapshot of the
    /// target's code, which is also the backup [`HookManager::transact`] checks
    /// before every write.
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
        // Before decoding: a target inside another hook's bytes may not even be an
        // instruction boundary.
        if self.overlaps_existing(target as usize, 1) {
            return Err(HookError::Overlapping);
        }
        let snapshot = snapshot(target as usize);
        let mut trampoline = Trampoline::new(target, detour, ptr::null_mut());
        if let Err(error) = create_trampoline(&mut trampoline, &snapshot) {
            // Never published: nothing points into the slot.
            free_buffer(trampoline.trampoline);
            return Err(error);
        }
        let mut entry = HookEntry::new();
        entry.target = target;
        entry.detour = trampoline.relay;
        entry.trampoline = trampoline.trampoline;
        entry.patch_above = trampoline.patch_above;
        entry.source_len = trampoline.source_len;
        entry.n_ip = trampoline.n_ip;
        entry.old_ips = trampoline.old_ips;
        entry.new_ips = trampoline.new_ips;
        let (start, len) = entry.footprint();
        let original = (len <= MAX_FOOTPRINT)
            .then(|| snapshot_bytes(&snapshot, target as usize, start, len))
            .flatten();
        let Some(original) = original else {
            free_buffer(trampoline.trampoline);
            return Err(HookError::UnsupportedFunction);
        };
        entry.original[..len].copy_from_slice(&original[..len]);
        if self.overlaps_existing(start, len) {
            free_buffer(trampoline.trampoline);
            return Err(HookError::Overlapping);
        }
        let Some(slot) = self.add_hook_entry() else {
            free_buffer(trampoline.trampoline);
            return Err(HookError::MemoryAlloc);
        };
        *slot = entry;
        Ok(slot.trampoline)
    }

    /// True when `[start, start + len)` overlaps the footprint of an existing hook.
    fn overlaps_existing(&self, start: usize, len: usize) -> bool {
        self.hooks.items[..self.hooks.size].iter().any(|hook| {
            let (other, other_len) = hook.footprint();
            ranges_overlap(start, len, other, other_len)
        })
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
    use windows_sys::Win32::System::Memory::{
        MEM_COMMIT, MEM_RELEASE, MEM_RESERVE, MEMORY_BASIC_INFORMATION, PAGE_EXECUTE,
        PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY, VirtualAlloc, VirtualFree,
        VirtualQuery,
    };
    use windows_sys::Win32::System::Threading::GetCurrentThreadId;

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
    fn plan_ip_maps_between_target_and_trampoline() {
        let mut hooks = vec![entry(0x1000, 0x2000, 0x2030), entry(0x5000, 0x6000, 0x6030)];
        let enable_both = [(0, true), (1, true)];
        // A boundary inside the enabled target moves into the trampoline, and back.
        assert_eq!(plan_ip(&hooks, &enable_both, 0x1003), 0x2009);
        assert_eq!(plan_ip(&hooks, &enable_both, 0x5000), 0x6000);
        // An address that is not an instruction boundary does not move.
        assert_eq!(plan_ip(&hooks, &enable_both, 0x1001), 0x1001);
        // A hook not in the batch moves nothing.
        assert_eq!(plan_ip(&hooks, &[(1, true)], 0x1003), 0x1003);
        let disable = [(0, false)];
        assert_eq!(plan_ip(&hooks, &disable, 0x2009), 0x1003);
        assert_eq!(plan_ip(&hooks, &disable, 0x2030), 0x1000);
        assert_eq!(plan_ip(&hooks, &disable, 0x2010), 0x2010);
        // The hot-patch jump at target-5 maps back to the target.
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
    fn a_failed_wait_on_the_recheck_fails_closed() {
        let fixture = Fixture::new();
        let before = bytes(mix_a);
        // A spinner looks gone; reopening it on the check works, but the wait that
        // would confirm it exited fails. No retry follows.
        fault::gone(fixture.spinners[0], 1);
        fault::fail(Call::Wait, u64::MAX);
        assert_eq!(enable_hook(target(mix_a)), Err(HookError::ThreadSuspend));
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(bytes(mix_a), before);
    }

    fn slots(starts: &[usize]) -> SlotSet {
        SlotSet::new(starts.iter().copied())
    }

    #[test]
    fn a_hidden_thread_is_caught_by_the_frozen_recheck() {
        let fixture = Fixture::new();
        // The first attempt's candidate snapshot omits one thread, so it is never
        // suspended; the frozen recheck (the Wine walk, or the Windows re-enumeration)
        // finds it and the attempt restarts. A later attempt sees every thread.
        fault::hide(&[1]);
        enable_hook(target(mix_a)).expect("a later attempt sees every thread");
        fault::clear();
        fixture.assert_threads_run();
        assert!(hooked(mix_a));
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

    #[test]
    fn ranges_overlap_is_half_open() {
        assert!(ranges_overlap(10, 5, 14, 5));
        assert!(!ranges_overlap(10, 5, 15, 5));
        assert!(!ranges_overlap(15, 5, 10, 5));
        assert!(ranges_overlap(10, 10, 12, 1));
        assert!(ranges_overlap(12, 1, 10, 10));
        assert!(!ranges_overlap(10, 0, 10, 5));
        assert!(!ranges_overlap(10, 5, 12, 0));
        assert!(ranges_overlap(usize::MAX - 2, 5, usize::MAX - 1, 1));
    }

    #[test]
    fn footprint_and_images_cover_the_patch_and_the_source() {
        let mut hook = entry(0x1000, 0x2000, 0x2030);
        hook.source_len = 8;
        hook.original[..8].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(hook.footprint(), (0x1000, 8));
        // The jump to the relay at 0x2030: E9 rel32 from the end of the jump.
        let (bytes, len) = hook.patch_bytes();
        assert_eq!(len, 5);
        assert_eq!(bytes[..5], [0xE9, 0x2B, 0x10, 0x00, 0x00]);
        assert_eq!(
            hook.image(true)[..8],
            [0xE9, 0x2B, 0x10, 0x00, 0x00, 6, 7, 8]
        );
        assert_eq!(hook.image(false)[..8], [1, 2, 3, 4, 5, 6, 7, 8]);
        // A source shorter than the patch: the patch range is the footprint.
        hook.source_len = 3;
        assert_eq!(hook.footprint(), (0x1000, 5));
        // With the hot patch: the jump sits above the target, and a short jump back
        // to it at the target.
        hook.patch_above = true;
        assert_eq!(hook.footprint(), (0x1000 - 5, 8));
        let (bytes, len) = hook.patch_bytes();
        assert_eq!(len, 7);
        // The jump now starts 5 bytes earlier, so its offset is 5 larger.
        assert_eq!(bytes[..7], [0xE9, 0x30, 0x10, 0x00, 0x00, 0xEB, 0xF9]);
        hook.source_len = 1;
        assert_eq!(hook.footprint(), (0x1000 - 5, 7));
    }

    // Crafted code, hooked but never executed. Offsets into the first page.
    const NOPS: usize = 0x100;
    const RET: usize = 0x200;
    const INDIRECT: usize = 0x300;
    const EXTERNAL: usize = 0x400;
    const ABOVE: usize = 0x500;
    /// Starts 5 bytes before the second page; its last copied instruction ends on it.
    const CROSS: usize = PAGE_SIZE - 5;

    /// Two pages of crafted code. Drop removes the hooks it created, by force if a
    /// remove fails, before the pages are freed.
    struct Crafted {
        base: usize,
        targets: Vec<usize>,
    }

    impl Crafted {
        fn new() -> Self {
            // SAFETY: allocates two fresh pages.
            let base = unsafe {
                VirtualAlloc(
                    ptr::null(),
                    2 * PAGE_SIZE,
                    MEM_COMMIT | MEM_RESERVE,
                    PAGE_EXECUTE_READWRITE,
                )
            } as usize;
            assert_ne!(base, 0);
            let code = Self {
                base,
                targets: Vec::new(),
            };
            code.put(0, &[0xCC; 2 * PAGE_SIZE]);
            code.put(NOPS, &[0x90; 32]);
            // xor eax, eax; ret; then int3 padding.
            code.put(RET, &[0x31, 0xC0, 0xC3]);
            // jmp [rip + 0].
            code.put(INDIRECT, &[0xFF, 0x25, 0, 0, 0, 0]);
            // jmp +1 (internal); nop; jmp rel32 (external); then nops another hook uses.
            code.put(EXTERNAL, &[0xEB, 0x01, 0x90, 0xE9, 0xB0, 0xB1, 0x90, 0x90]);
            code.put(EXTERNAL + 8, &[0x90; 8]);
            // Nop hot-patch bytes, then xor eax, eax; ret; push rbp (not padding).
            code.put(ABOVE - 10, &[0x90; 10]);
            code.put(ABOVE, &[0x31, 0xC0, 0xC3, 0x55]);
            // Four nops, then mov eax, imm32 across the page boundary.
            code.put(
                CROSS,
                &[0x90, 0x90, 0x90, 0x90, 0xB8, 0x11, 0x22, 0x33, 0x44],
            );
            code
        }

        fn address(&self, offset: usize) -> usize {
            self.base + offset
        }

        fn put(&self, offset: usize, bytes: &[u8]) {
            // SAFETY: the pages are this fixture's, writable, and never executed.
            unsafe {
                ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    (self.base + offset) as *mut u8,
                    bytes.len(),
                )
            };
        }

        fn get(&self, offset: usize, len: usize) -> Vec<u8> {
            // SAFETY: as above; the range is inside the two pages.
            unsafe { std::slice::from_raw_parts((self.base + offset) as *const u8, len) }.to_vec()
        }

        fn hook(&mut self, offset: usize) -> Result<*mut c_void> {
            let target = self.address(offset);
            let trampoline = create_hook(target as *mut c_void, detour as MixFn as *mut c_void)?;
            self.targets.push(target);
            Ok(trampoline)
        }

        fn unhook(&mut self, offset: usize) -> Result<()> {
            let target = self.address(offset);
            remove_hook(target as *mut c_void)?;
            self.targets.retain(|&other| other != target);
            Ok(())
        }

        fn create(&self, offset: usize) -> Result<*mut c_void> {
            create_hook(
                self.address(offset) as *mut c_void,
                detour as MixFn as *mut c_void,
            )
        }

        fn enable(&self, offset: usize) -> Result<()> {
            enable_hook(self.address(offset) as *mut c_void)
        }

        fn disable(&self, offset: usize) -> Result<()> {
            disable_hook(self.address(offset) as *mut c_void)
        }

        /// The hook's `(source_len, footprint offset, footprint len, patch_above)`.
        fn layout(&self, offset: usize) -> (u8, usize, usize, bool) {
            let manager = get_manager().lock().unwrap();
            let hook =
                &manager.hooks.items[manager.find_hook_entry(self.address(offset) as *mut c_void)];
            let (start, len) = hook.footprint();
            (hook.source_len, start - self.base, len, hook.patch_above)
        }

        fn image(&self, offset: usize, enabled: bool) -> Vec<u8> {
            let manager = get_manager().lock().unwrap();
            let hook =
                &manager.hooks.items[manager.find_hook_entry(self.address(offset) as *mut c_void)];
            hook.image(enabled)[..hook.footprint().1].to_vec()
        }

        fn enabled(&self, offset: usize) -> bool {
            let manager = get_manager().lock().unwrap();
            let pos = manager.find_hook_entry(self.address(offset) as *mut c_void);
            manager.hooks.items[pos].is_enabled
        }
    }

    impl Drop for Crafted {
        fn drop(&mut self) {
            for &target in &self.targets {
                if remove_hook(target as *mut c_void).is_err() {
                    let mut manager = get_manager().lock().unwrap();
                    let pos = manager.find_hook_entry(target as *mut c_void);
                    if pos != INVALID_HOOK_POS {
                        manager.delete_hook_entry(pos);
                    }
                }
            }
            // SAFETY: frees the pages allocated in `new`; no hook points at them now.
            unsafe { VirtualFree(self.base as *mut c_void, 0, MEM_RELEASE) };
        }
    }

    #[test]
    fn footprints_cover_each_way_a_trampoline_ends() {
        let _fixture = Fixture::new();
        let mut code = Crafted::new();
        for offset in [NOPS, RET, INDIRECT, EXTERNAL, ABOVE] {
            code.hook(offset).expect("create");
        }
        // Five one-byte nops, then the jump back: the sixth runs in place.
        assert_eq!(code.layout(NOPS), (5, NOPS, 5, false));
        // Ends at ret; the int3 padding after it completes the patch range.
        assert_eq!(code.layout(RET), (3, RET, 5, false));
        // Ends at the indirect jump, one byte past the patch range.
        assert_eq!(code.layout(INDIRECT), (6, INDIRECT, 6, false));
        // An internal jump, then an external one: three bytes past the patch range.
        assert_eq!(code.layout(EXTERNAL), (8, EXTERNAL, 8, false));
        // Too short and no padding after it: the hot-patch bytes above it.
        assert_eq!(code.layout(ABOVE), (3, ABOVE - 5, 8, true));
        for (offset, start) in [
            (NOPS, NOPS),
            (RET, RET),
            (INDIRECT, INDIRECT),
            (EXTERNAL, EXTERNAL),
            (ABOVE, ABOVE - 5),
        ] {
            let original = code.image(offset, false);
            assert_eq!(code.get(start, original.len()), original);
        }
    }

    #[test]
    fn overlapping_hooks_are_refused_and_give_their_slot_back() {
        let _fixture = Fixture::new();
        let mut code = Crafted::new();
        code.hook(NOPS).expect("create");
        let used = crate::buffer::used_slots();
        // Inside another hook's bytes, refused before anything is decoded.
        assert_eq!(code.create(NOPS + 2), Err(HookError::Overlapping));
        // Right after them.
        code.hook(NOPS + 5).expect("an adjacent hook");
        let used = used + 1;
        assert_eq!(crate::buffer::used_slots(), used);

        // The patch ranges [0, 5) and [6, 11) are disjoint, but the external jump's
        // source bytes reach the second hook: refused after its trampoline was built,
        // whose slot is freed again.
        code.hook(EXTERNAL + 6).expect("create");
        let used = used + 1;
        assert_eq!(code.create(EXTERNAL), Err(HookError::Overlapping));
        assert_eq!(crate::buffer::used_slots(), used);

        // A hook whose bytes reach into the hot-patch bytes above ABOVE.
        code.hook(ABOVE - 8).expect("create");
        assert_eq!(code.create(ABOVE), Err(HookError::Overlapping));
        assert_eq!(crate::buffer::used_slots(), used + 1);
        code.unhook(ABOVE - 8).expect("remove");
        // One that ends where they begin.
        code.hook(ABOVE - 10).expect("create");
        code.hook(ABOVE).expect("adjacent to the hot-patch bytes");
        assert_eq!(code.create(ABOVE - 3), Err(HookError::Overlapping));
        assert_eq!(code.create(ABOVE + 1), Err(HookError::Overlapping));
    }

    #[test]
    fn a_changed_byte_past_the_patch_range_blocks_the_enable() {
        let fixture = Fixture::new();
        let mut code = Crafted::new();
        code.hook(EXTERNAL).expect("create");
        let original = code.image(EXTERNAL, false);
        let mut changed = original.clone();
        changed[6] ^= 0x01;
        code.put(EXTERNAL + 6, &changed[6..7]);
        assert_eq!(code.enable(EXTERNAL), Err(HookError::TargetModified));
        fixture.assert_threads_run();
        assert_eq!(code.get(EXTERNAL, 8), changed);
        assert!(!code.enabled(EXTERNAL));
        assert!(!protection_lost() && !flush_failed() && !thaw_failed());
        code.put(EXTERNAL + 6, &original[6..7]);
        code.enable(EXTERNAL).expect("the original bytes are back");
        assert_eq!(code.get(EXTERNAL, 8), code.image(EXTERNAL, true));
        assert_eq!(code.get(EXTERNAL, 1), [0xE9]);
        code.disable(EXTERNAL).expect("disable");
        assert_eq!(code.get(EXTERNAL, 8), original);
    }

    #[test]
    fn a_changed_jump_blocks_the_disable_and_the_remove() {
        let fixture = Fixture::new();
        let mut code = Crafted::new();
        code.hook(NOPS).expect("create");
        code.enable(NOPS).expect("enable");
        let enabled = code.image(NOPS, true);
        assert_eq!(code.get(NOPS, 5), enabled);
        let mut changed = enabled.clone();
        changed[1] ^= 0xFF;
        code.put(NOPS + 1, &changed[1..2]);
        assert_eq!(code.disable(NOPS), Err(HookError::TargetModified));
        assert_eq!(
            remove_hook(code.address(NOPS) as *mut c_void),
            Err(HookError::TargetModified)
        );
        fixture.assert_threads_run();
        // Nothing was written back over the foreign bytes, and the hook is kept.
        assert_eq!(code.get(NOPS, 5), changed);
        assert!(code.enabled(NOPS));
        code.put(NOPS + 1, &enabled[1..2]);
        code.disable(NOPS).expect("the jump is back");
        assert_eq!(code.get(NOPS, 5), [0x90; 5]);
    }

    #[test]
    fn hot_patch_hooks_are_checked_in_both_directions() {
        let _fixture = Fixture::new();
        let mut code = Crafted::new();
        code.hook(ABOVE).expect("create");
        let original = code.get(ABOVE - 5, 8);
        code.enable(ABOVE).expect("enable");
        let enabled = code.get(ABOVE - 5, 8);
        assert_eq!(enabled, code.image(ABOVE, true));
        assert_eq!(enabled[0], 0xE9);
        assert_eq!(enabled[5..], [0xEB, 0xF9, 0xC3]);
        code.disable(ABOVE).expect("disable");
        assert_eq!(code.get(ABOVE - 5, 8), original);
        code.enable(ABOVE).expect("enable");
        // The short jump back to the hot patch, changed.
        code.put(ABOVE + 1, &[0xFA]);
        assert_eq!(code.disable(ABOVE), Err(HookError::TargetModified));
        assert!(code.enabled(ABOVE));
        code.put(ABOVE + 1, &[0xF9]);
        code.disable(ABOVE).expect("disable");
        assert_eq!(code.get(ABOVE - 5, 8), original);
    }

    #[test]
    fn an_unreadable_footprint_blocks_the_write() {
        let fixture = Fixture::new();
        let mut code = Crafted::new();
        code.hook(NOPS).expect("create");
        fault::fail(Call::ReadCode, u64::MAX);
        assert_eq!(code.enable(NOPS), Err(HookError::TargetModified));
        fault::clear();
        fixture.assert_threads_run();
        assert_eq!(code.get(NOPS, 5), [0x90; 5]);
        assert!(!code.enabled(NOPS));
        code.enable(NOPS).expect("enable");
    }

    #[test]
    fn one_changed_hook_blocks_the_whole_batch() {
        let fixture = Fixture::new();
        let mut code = Crafted::new();
        code.hook(NOPS).expect("create");
        code.hook(RET).expect("create");
        code.put(RET + 1, &[0xC1]);
        assert_eq!(enable_hook(ALL_HOOKS), Err(HookError::TargetModified));
        fixture.assert_threads_run();
        assert!(!hooked(mix_a) && !hooked(mix_b));
        assert_eq!(code.get(NOPS, 5), [0x90; 5]);
        assert!(!code.enabled(NOPS) && !code.enabled(RET));
        code.put(RET + 1, &[0xC0]);
        enable_hook(ALL_HOOKS).expect("enable");
        assert!(hooked(mix_a) && hooked(mix_b));
        assert_eq!(code.get(RET, 5), code.image(RET, true));
    }

    #[test]
    fn an_execute_only_source_page_is_checked_and_restored() {
        let _fixture = Fixture::new();
        let mut code = Crafted::new();
        code.hook(CROSS).expect("create");
        // Four nops and the five-byte mov: four of its bytes are on the second page.
        assert_eq!(code.layout(CROSS), (9, CROSS, 9, false));
        let protection = |address: usize| {
            // SAFETY: zeroed MEMORY_BASIC_INFORMATION is valid; VirtualQuery fills it.
            let mut info = unsafe { std::mem::zeroed::<MEMORY_BASIC_INFORMATION>() };
            // SAFETY: `info` is a valid out-buffer of the size given.
            unsafe { VirtualQuery(address as *const c_void, &mut info, size_of_val(&info)) };
            info.Protect
        };
        let second = code.address(PAGE_SIZE);
        let mut old = 0u32;
        // SAFETY: the second page belongs to the fixture.
        assert_ne!(
            unsafe { VirtualProtect(second as *mut c_void, PAGE_SIZE, PAGE_EXECUTE, &mut old) },
            0
        );
        code.enable(CROSS)
            .expect("the footprint is readable while it is writable");
        assert_eq!(protection(second), PAGE_EXECUTE);
        assert_eq!(protection(code.address(0)), PAGE_EXECUTE_READWRITE);
        code.disable(CROSS).expect("disable");
        assert_eq!(protection(second), PAGE_EXECUTE);
        assert!(!protection_lost());
        // SAFETY: as above.
        assert_ne!(
            unsafe {
                VirtualProtect(
                    second as *mut c_void,
                    PAGE_SIZE,
                    PAGE_EXECUTE_READWRITE,
                    &mut old,
                )
            },
            0
        );
        assert_eq!(
            code.get(CROSS, 9),
            [0x90, 0x90, 0x90, 0x90, 0xB8, 0x11, 0x22, 0x33, 0x44]
        );
    }

    #[test]
    fn the_trampoline_is_built_from_the_snapshot_not_live_memory() {
        let _fixture = Fixture::new();
        let code = Crafted::new();
        let target = code.address(NOPS);
        // Live memory holds nops; the snapshot holds xor eax, eax; ret; int3 int3, as
        // if another writer changed the code back and forth while it was read.
        let mut snapshot = snapshot(target);
        assert_eq!(snapshot.len, SNAPSHOT_CODE);
        snapshot.code[..5].copy_from_slice(&[0x31, 0xC0, 0xC3, 0xCC, 0xCC]);
        let mut built = Trampoline::new(
            target as *mut c_void,
            detour as MixFn as *mut c_void,
            ptr::null_mut(),
        );
        create_trampoline(&mut built, &snapshot).expect("build");
        assert_eq!(built.source_len, 3);
        // SAFETY: the slot was just allocated and filled by create_trampoline.
        let copied = unsafe { ptr::read(built.trampoline as *const [u8; 3]) };
        assert_eq!(copied, [0x31, 0xC0, 0xC3]);
        free_buffer(built.trampoline);

        // A snapshot cut short refuses the hook rather than decode a partial window.
        snapshot.len = 15;
        let mut short = Trampoline::new(
            target as *mut c_void,
            detour as MixFn as *mut c_void,
            ptr::null_mut(),
        );
        assert_eq!(
            create_trampoline(&mut short, &snapshot),
            Err(HookError::UnsupportedFunction)
        );
        free_buffer(short.trampoline);
    }
}
