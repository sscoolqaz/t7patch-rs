//! Arxan integrity-check bypass.
//!
//! Port of `Arxan.cpp` and `Arxan.h`. The game's anti-tamper code scans its own
//! code for known checksum instruction sequences. The sequences are stored
//! XOR-encrypted here and rewritten in memory so the scan no longer matches.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, PAGE_PROTECTION_FLAGS, VirtualProtect, VirtualQuery,
};
use windows::Win32::System::Threading::GetCurrentProcess;

use crate::build::{self, Build};
use crate::offsets;

const PATCH_KEY: u8 = 0x69;
const READY_SIGNAL_RVA: usize = 0x1686E948;
const CRC1_EXPECTED_COUNT: usize = 259;
const CRC2_EXPECTED_COUNT: usize = 259;
const CRC3_EXPECTED_COUNT: usize = 847;

const ENCRYPTED_PATCH1: [u8; 6] = [0x21, 0x58, 0xA0, 0xF9, 0xF9, 0xF9];
const ENCRYPTED_PATCH2: [u8; 8] = [0x21, 0x58, 0xA0, 0xF9, 0xF9, 0xF9, 0xF9, 0xF9];
const ENCRYPTED_PATCH3: [u8; 6] = [0x21, 0x58, 0xA9, 0x21, 0x58, 0xBB];

const CHECKSUM_PATTERN1: [u8; 6] = [0x8B, 0x0C, 0x8B, 0x33, 0x0C, 0x82];
const CHECKSUM_PATTERN2: [u8; 8] = [0x8B, 0x0C, 0x8B, 0xF7, 0xD9, 0x03, 0x0C, 0x82];
const CHECKSUM_PATTERN3: [u8; 8] = [0x8B, 0x04, 0x82, 0x8B, 0x14, 0x8B, 0x3B, 0xC2];

// Win32 page protection and memory state values used by the scan.
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;
const PAGE_GUARD: u32 = 0x100;
const MEM_COMMIT: u32 = 0x1000;
const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;

/// Result of one guarded memory write.
///
/// A write can succeed, partially succeed, or fail. `bytes_written` is set as soon
/// as the copy happens, so a caller that sees `false` from [`write_bytes`] still has
/// to treat the bytes as changed when `bytes_written` is true.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WriteReport {
    pub(crate) bytes_written: bool,
    pub(crate) cache_flushed: bool,
    pub(crate) protection_restored: bool,
}

impl WriteReport {
    /// True only when every stage succeeded.
    pub(crate) const fn complete(self) -> bool {
        self.bytes_written && self.cache_flushed && self.protection_restored
    }

    /// True when the bytes changed but a later stage failed.
    pub(crate) const fn uncertain(self) -> bool {
        self.bytes_written && !self.complete()
    }
}

/// Where one saved patch is in its write/restore lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PatchState {
    /// Collected, but no replacement bytes have been written.
    Pending,
    /// Replacement bytes are in the image.
    Written,
    /// A restore attempt failed; the original bytes may not be back.
    RestoreFailed,
}

/// One byte range rewritten by the bypass, with the bytes needed to undo it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SavedPatch {
    address: usize,
    size: usize,
    original: [u8; 8],
    replacement: [u8; 8],
    state: PatchState,
}

struct State {
    patches: Vec<SavedPatch>,
    /// A restore failed, so the image may contain a partial bypass.
    partial: bool,
}

static ACTIVE: AtomicBool = AtomicBool::new(false);
static EXTERNAL: AtomicBool = AtomicBool::new(false);
static WAITING_FOR_READY_SIGNAL: AtomicBool = AtomicBool::new(false);
static STATE: Mutex<State> = Mutex::new(State {
    patches: Vec::new(),
    partial: false,
});

fn lock_state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Reports whether a page protection allows execution and is readable.
#[must_use]
pub fn executable_protection(protection: u32) -> bool {
    if protection & (PAGE_GUARD | PAGE_NOACCESS) != 0 {
        return false;
    }
    matches!(
        protection & 0xff,
        PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY
    )
}

/// XORs an encrypted patch with the key, yielding the bytes to write.
#[must_use]
pub fn decrypt_patch(encrypted: &[u8]) -> Vec<u8> {
    encrypted.iter().map(|byte| byte ^ PATCH_KEY).collect()
}

/// Finds every (possibly overlapping) occurrence of `pattern` in `haystack`.
#[must_use]
pub fn find_all(haystack: &[u8], pattern: &[u8]) -> Vec<usize> {
    if pattern.is_empty() || haystack.len() < pattern.len() {
        return Vec::new();
    }
    haystack
        .windows(pattern.len())
        .enumerate()
        .filter_map(|(index, window)| (window == pattern).then_some(index))
        .collect()
}

/// Checks that `[address, address + size)` is committed, readable, and inside one region.
///
/// # Safety
///
/// `address` is only queried, never dereferenced, so any value is accepted.
unsafe fn memory_range(address: usize, size: usize, require_executable: bool) -> bool {
    if address == 0 || size == 0 {
        return false;
    }
    let mut information = MEMORY_BASIC_INFORMATION::default();
    // SAFETY: `information` is a valid out-buffer of the length passed to `VirtualQuery`.
    let written = unsafe {
        VirtualQuery(
            Some(address as *const _),
            &raw mut information,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if written != size_of::<MEMORY_BASIC_INFORMATION>() {
        return false;
    }
    let protect = information.Protect.0;
    if information.State.0 != MEM_COMMIT
        || protect & (PAGE_GUARD | PAGE_NOACCESS) != 0
        || (require_executable && !executable_protection(protect))
    {
        return false;
    }

    let region_start = information.BaseAddress as usize;
    address >= region_start && size <= information.RegionSize - (address - region_start)
}

fn ready_signal_set() -> bool {
    let address = offsets::address(READY_SIGNAL_RVA);
    // SAFETY: `memory_range` confirms the word is committed and readable before it is read.
    unsafe {
        memory_range(address, size_of::<usize>(), false)
            && (address as *const usize).read_unaligned() != 0
    }
}

/// Maximum number of pages one write may span. Every patch in this crate is at most
/// a pointer wide, so a range that crosses more pages is a caller bug and is refused.
const MAX_WRITE_PAGES: usize = 4;
const PAGE_SIZE: usize = 0x1000;
/// How many times a failed protection restore is retried.
const RESTORE_ATTEMPTS: usize = 3;

/// Set once a page could not be returned to its original protection. The
/// lifecycle treats this as terminal: the image is left with a writable page.
static PROTECTION_LOST: AtomicBool = AtomicBool::new(false);

/// True once a page protection could not be restored.
pub(crate) fn protection_lost() -> bool {
    PROTECTION_LOST.load(Ordering::Acquire)
}

/// Changes page protections. A seam over `VirtualProtect` for tests.
trait PageProtect {
    /// Sets `[start, start + size)` to `protection`, returning the old protection.
    fn protect(&mut self, start: usize, size: usize, protection: u32) -> Option<u32>;
}

struct LiveProtect;

impl PageProtect for LiveProtect {
    fn protect(&mut self, start: usize, size: usize, protection: u32) -> Option<u32> {
        let mut old = PAGE_PROTECTION_FLAGS(0);
        // SAFETY: callers pass committed ranges; `old` is a valid out-pointer.
        unsafe {
            VirtualProtect(
                start as *const _,
                size,
                PAGE_PROTECTION_FLAGS(protection),
                &raw mut old,
            )
        }
        .ok()
        .map(|()| old.0)
    }
}

/// The original protection of every page one write touches. Built on the stack
/// before the first change and unwound in reverse, so it needs no allocation and
/// works while threads are frozen.
struct ProtectionJournal {
    entries: [(usize, usize, u32); MAX_WRITE_PAGES],
    len: usize,
}

impl ProtectionJournal {
    const fn new() -> Self {
        Self {
            entries: [(0, 0, 0); MAX_WRITE_PAGES],
            len: 0,
        }
    }

    /// Makes every page of `[address, end)` writable, recording each original
    /// protection as it is replaced. On failure the pages already changed are
    /// restored and `false` is returned.
    fn make_writable(&mut self, ops: &mut impl PageProtect, address: usize, end: usize) -> bool {
        let first_page = address & !(PAGE_SIZE - 1);
        let last_page = (end - 1) & !(PAGE_SIZE - 1);
        let page_count = (last_page - first_page) / PAGE_SIZE + 1;
        if page_count > MAX_WRITE_PAGES {
            return false;
        }
        for index in 0..page_count {
            let page = first_page + index * PAGE_SIZE;
            let start = address.max(page);
            let stop = end.min(page + PAGE_SIZE);
            let Some(old) = ops.protect(start, stop - start, PAGE_EXECUTE_READWRITE) else {
                // Restore the pages already made writable before reporting failure.
                let _ = self.restore(ops);
                return false;
            };
            self.entries[self.len] = (start, stop - start, old);
            self.len += 1;
        }
        true
    }

    /// Puts every recorded page back, newest first, retrying failures. Returns
    /// `false`, and sets [`PROTECTION_LOST`], if any page stays changed.
    fn restore(&mut self, ops: &mut impl PageProtect) -> bool {
        let mut restored = true;
        while self.len > 0 {
            self.len -= 1;
            let (start, size, old) = self.entries[self.len];
            if !(0..RESTORE_ATTEMPTS).any(|_| ops.protect(start, size, old).is_some()) {
                restored = false;
            }
        }
        if !restored {
            PROTECTION_LOST.store(true, Ordering::Release);
        }
        restored
    }
}

/// Writes `bytes` over `address` while the caller holds the patch transaction,
/// temporarily making every touched page writable and reporting which stages
/// completed. [`crate::threads`] calls this under its freeze.
///
/// A caller must journal the original bytes before calling this: when
/// [`WriteReport::bytes_written`] is true the image already contains the new bytes,
/// even if the cache flush or the protection restore failed.
///
/// # Safety
///
/// `[address, address + bytes.len())` must lie inside committed memory, and the
/// caller must hold [`crate::threads::lock_transaction`].
pub(crate) unsafe fn write_bytes_in_transaction(address: usize, bytes: &[u8]) -> WriteReport {
    let mut report = WriteReport::default();
    if bytes.is_empty() {
        report.bytes_written = true;
        report.cache_flushed = true;
        report.protection_restored = true;
        return report;
    }
    let Some(end) = address.checked_add(bytes.len()) else {
        return report;
    };
    let mut ops = LiveProtect;
    let mut journal = ProtectionJournal::new();
    if !journal.make_writable(&mut ops, address, end) {
        return report;
    }

    // SAFETY: every touched page was made writable above, and `bytes` does not
    // overlap the target.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len()) };
    report.bytes_written = true;

    // SAFETY: the current process handle is a pseudo-handle that is always valid.
    report.cache_flushed = unsafe {
        FlushInstructionCache(GetCurrentProcess(), Some(address as *const _), bytes.len())
    }
    .is_ok();
    report.protection_restored = journal.restore(&mut ops);
    report
}

/// Writes `bytes` over `address` under the patch transaction, temporarily making
/// the pages writable. For data and code that no other thread executes; code
/// that may be running goes through [`crate::threads::write_code`].
///
/// # Safety
///
/// `[address, address + bytes.len())` must lie inside committed memory.
pub(crate) unsafe fn write_bytes_reported(address: usize, bytes: &[u8]) -> WriteReport {
    let _transaction = crate::threads::lock_transaction();
    // SAFETY: forwarded from the caller; the transaction is held.
    unsafe { write_bytes_in_transaction(address, bytes) }
}

/// Writes `bytes` over `address`, temporarily making the page writable.
///
/// Returns false when any stage failed; callers that must know whether the bytes
/// changed use [`write_bytes_reported`] instead.
///
/// # Safety
///
/// `[address, address + bytes.len())` must lie inside committed memory.
pub(crate) unsafe fn write_bytes(address: usize, bytes: &[u8]) -> bool {
    // SAFETY: forwarded from the caller.
    unsafe { write_bytes_reported(address, bytes).complete() }
}

/// Result of one pointer publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PointerWrite {
    /// The slot now holds the new value.
    pub(crate) written: bool,
    pub(crate) protection_restored: bool,
    /// The slot's value when the swap was attempted. Differs from `expected`
    /// when nothing was written because the slot had changed.
    pub(crate) observed: usize,
}

impl PointerWrite {
    pub(crate) const fn complete(self) -> bool {
        self.written && self.protection_restored
    }
}

/// Bytes in an x86 cache line. A misaligned locked access that stays inside one
/// line is atomic; one that crosses a line is a split lock.
const CACHE_LINE: usize = 64;

/// Whether the 8 bytes at `slot` sit inside one cache line.
const fn within_cache_line(slot: usize) -> bool {
    slot % CACHE_LINE + size_of::<usize>() <= CACHE_LINE
}

/// One 8-byte load from `slot`, which need not be aligned.
///
/// # Safety
///
/// `slot` must be readable for 8 bytes.
unsafe fn load_word(slot: usize) -> usize {
    let value: usize;
    // SAFETY: the caller guarantees the 8 bytes are readable. A single `mov` is
    // atomic on x86 for an access inside one cache line, aligned or not.
    unsafe {
        std::arch::asm!(
            "mov {value}, qword ptr [{slot}]",
            slot = in(reg) slot,
            value = out(reg) value,
            options(nostack, readonly, preserves_flags),
        );
    }
    value
}

/// `lock cmpxchg` on `slot`, which need not be aligned. Returns the value the
/// slot held: `expected` exactly when the swap happened.
///
/// # Safety
///
/// `slot` must be writable for 8 bytes and lie within one cache line.
unsafe fn compare_exchange_word(slot: usize, expected: usize, new: usize) -> usize {
    let previous: usize;
    // SAFETY: the caller guarantees the 8 bytes are writable and inside one cache
    // line, where x86 performs a locked misaligned access atomically.
    unsafe {
        std::arch::asm!(
            "lock cmpxchg qword ptr [{slot}], {new}",
            slot = in(reg) slot,
            new = in(reg) new,
            inout("rax") expected => previous,
            options(nostack),
        );
    }
    previous
}

/// Atomically replaces the pointer at `slot` with `new` if it still holds
/// `expected`. The swap is one `lock cmpxchg`, so a reader on another thread
/// sees either the old or the new pointer, never a torn mix. Anything `new`
/// points at must be fully initialized before this is called.
///
/// The slot need not be 8-byte aligned. The game's own import table is only
/// 4-byte aligned (`IsProcessorFeaturePresent` sits at RVA `0x1AA69E94`), and
/// upstream writes it with a plain `memcpy`. A misaligned locked access is
/// atomic while it stays inside one cache line. A slot that crosses a line falls
/// back to upstream's behaviour: compare, then a plain write, still under the
/// patch transaction.
///
/// Nothing is written when the slot is unmapped, when its page cannot be made
/// writable, or when it no longer holds `expected`. Page-protection changes are
/// serialized with code writes by the patch transaction.
///
/// # Safety
///
/// `slot` must be a committed pointer slot (an IAT, vtable, global or ntdll data
/// entry) that other code reads as a `usize`.
pub(crate) unsafe fn swap_usize(slot: usize, expected: usize, new: usize) -> PointerWrite {
    let mut result = PointerWrite {
        written: false,
        protection_restored: true,
        observed: 0,
    };
    if slot == 0 {
        return result;
    }
    // SAFETY: the range is only queried. An unmapped slot (a freed interface, say)
    // is refused before it is read.
    if !unsafe { memory_range(slot, size_of::<usize>(), false) } {
        return result;
    }
    let _transaction = crate::threads::lock_transaction();
    // SAFETY: the slot is committed and readable, checked above.
    result.observed = unsafe { load_word(slot) };
    if result.observed != expected {
        return result;
    }
    let mut ops = LiveProtect;
    let mut journal = ProtectionJournal::new();
    if !journal.make_writable(&mut ops, slot, slot + size_of::<usize>()) {
        return result;
    }
    if within_cache_line(slot) {
        // SAFETY: the page was made writable above and the slot is inside one line.
        let previous = unsafe { compare_exchange_word(slot, expected, new) };
        if previous == expected {
            result.written = true;
        } else {
            result.observed = previous;
        }
    } else {
        // SAFETY: the page was made writable above; this is upstream's plain write.
        unsafe { (slot as *mut usize).write_unaligned(new) };
        result.written = true;
    }
    result.protection_restored = journal.restore(&mut ops);
    result
}

/// Puts `original` back in `slot` if the slot still holds `ours`. Returns `true`
/// when the slot is restored or is no longer ours. A slot that someone else has
/// rewritten since, or that is no longer mapped, is left alone. Returns `false`
/// only when the slot still holds `ours` and could not be written.
///
/// # Safety
///
/// As for [`swap_usize`].
pub(crate) unsafe fn restore_usize(slot: usize, ours: usize, original: usize) -> bool {
    // SAFETY: forwarded from the caller.
    let write = unsafe { swap_usize(slot, ours, original) };
    if write.written {
        return write.protection_restored;
    }
    if write.observed != ours {
        crate::dllmain::debug_print(
            "T7 Patch: a pointer slot changed since install; left as is.\n",
        );
        return true;
    }
    false
}

/// Finds all occurrences of `pattern` in the executable sections of the image.
///
/// # Safety
///
/// Must run inside the game process, where the main module's headers are mapped.
unsafe fn find_pattern_in_executable_image(image_base: usize, pattern: &[u8]) -> Vec<usize> {
    let mut matches = Vec::new();
    // SAFETY: the main module's DOS and NT headers are mapped in the game process.
    let (image_size, sections) = unsafe {
        let dos = &*(image_base as *const windows::Win32::System::SystemServices::IMAGE_DOS_HEADER);
        let nt_offset = usize::try_from(dos.e_lfanew).unwrap_or_default();
        let nt = &*((image_base + nt_offset)
            as *const windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64);
        let optional = (&raw const nt.OptionalHeader).cast::<u8>();
        #[allow(
            clippy::cast_ptr_alignment,
            reason = "the section table follows the 8-byte aligned optional header"
        )]
        let first = optional
            .add(nt.FileHeader.SizeOfOptionalHeader as usize)
            .cast::<windows::Win32::System::Diagnostics::Debug::IMAGE_SECTION_HEADER>();
        let count = nt.FileHeader.NumberOfSections as usize;
        (
            nt.OptionalHeader.SizeOfImage as usize,
            std::slice::from_raw_parts(first, count),
        )
    };

    for section in sections {
        let virtual_address = section.VirtualAddress as usize;
        if section.Characteristics.0 & IMAGE_SCN_MEM_EXECUTE == 0 || virtual_address >= image_size {
            continue;
        }

        let section_start = image_base + virtual_address;
        let remaining = image_size - virtual_address;
        // SAFETY: `Misc` is a union; `VirtualSize` is the variant that section headers use.
        let virtual_size = unsafe { section.Misc.VirtualSize } as usize;
        let section_size = virtual_size.min(remaining);
        let section_end = section_start + section_size;
        let mut cursor = section_start;

        while cursor < section_end {
            let mut information = MEMORY_BASIC_INFORMATION::default();
            // SAFETY: `information` is a valid out-buffer; the queried address is only inspected.
            let written = unsafe {
                VirtualQuery(
                    Some(cursor as *const _),
                    &raw mut information,
                    size_of::<MEMORY_BASIC_INFORMATION>(),
                )
            };
            if written != size_of::<MEMORY_BASIC_INFORMATION>() {
                break;
            }

            let base = information.BaseAddress as usize;
            let region_start = cursor.max(base);
            let region_end = section_end.min(base + information.RegionSize);
            if region_end <= cursor {
                break;
            }

            if information.State.0 == MEM_COMMIT
                && executable_protection(information.Protect.0)
                && region_end - region_start >= pattern.len()
            {
                // SAFETY: the region is committed and executable, so it is readable for its full length.
                let bytes = unsafe {
                    std::slice::from_raw_parts(region_start as *const u8, region_end - region_start)
                };
                matches.extend(
                    find_all(bytes, pattern)
                        .into_iter()
                        .map(|offset| region_start + offset),
                );
            }

            cursor = region_end;
        }
    }

    matches
}

/// Builds the rewrite list for one checksum pattern, or explains why it cannot.
///
/// # Safety
///
/// Must run inside the game process; see [`find_pattern_in_executable_image`].
unsafe fn collect_pattern_patches(
    image_base: usize,
    pattern: &[u8],
    encrypted: &[u8],
    expected_count: usize,
) -> Result<Vec<SavedPatch>, String> {
    let replacement = decrypt_patch(encrypted);
    // SAFETY: forwarded to the caller's guarantee.
    let matches = unsafe { find_pattern_in_executable_image(image_base, pattern) };
    if matches.len() != expected_count {
        return Err(format!(
            "Arxan checksum pattern count mismatch: expected {expected_count}, found {}",
            matches.len()
        ));
    }

    let mut patches = Vec::with_capacity(matches.len());
    for address in matches {
        // SAFETY: the range is only queried; `memory_range` checks it before any read.
        if !unsafe { memory_range(address, replacement.len(), true) } {
            return Err("An Arxan checksum pattern was outside executable memory".to_owned());
        }

        let mut original = [0u8; 8];
        let mut new = [0u8; 8];
        // SAFETY: `memory_range` confirmed `replacement.len()` committed bytes at `address`.
        unsafe {
            std::ptr::copy_nonoverlapping(
                address as *const u8,
                original.as_mut_ptr(),
                replacement.len(),
            );
        }
        new[..replacement.len()].copy_from_slice(&replacement);
        patches.push(SavedPatch {
            address,
            size: replacement.len(),
            original,
            replacement: new,
            state: PatchState::Pending,
        });
    }
    Ok(patches)
}

/// Restores the first `applied` patches in reverse order.
///
/// Records whose restore could not be completed stay in [`State`] and mark the
/// bypass as partial; the lifecycle must not return to `Idle` in that case.
/// Returns true only when every recorded patch is back to its original bytes.
fn restore_applied(state: &mut State, applied: usize) -> bool {
    let batch: Vec<crate::threads::CodePatch<'_>> = state.patches[..applied]
        .iter()
        .rev()
        .filter(|patch| patch.state == PatchState::Written)
        .map(|patch| crate::threads::CodePatch {
            address: patch.address,
            bytes: &patch.original[..patch.size],
        })
        .collect();
    if batch.is_empty() {
        state.patches.clear();
        return true;
    }

    let result = unsafe { crate::threads::write_code_batch(&batch) };
    drop(batch);
    match result {
        Ok(reports) => {
            let mut failed = false;
            let mut report_index = 0usize;
            for patch in state.patches[..applied].iter_mut().rev() {
                if patch.state != PatchState::Written {
                    continue;
                }
                let report = reports.get(report_index).copied().unwrap_or_default();
                report_index += 1;
                if report.complete() {
                    patch.state = PatchState::Pending;
                } else {
                    patch.state = PatchState::RestoreFailed;
                    failed = true;
                }
            }
            if failed {
                state.partial = true;
                false
            } else {
                state.patches.clear();
                true
            }
        }
        Err(error) => {
            for patch in state.patches[..applied].iter_mut().rev() {
                if patch.state == PatchState::Written {
                    patch.state = PatchState::RestoreFailed;
                }
            }
            state.partial = true;
            crate::dllmain::debug_print(&format!(
                "T7 Patch: cannot restore the Arxan bypass: {error}\n"
            ));
            false
        }
    }
}

/// Reports whether an earlier restore left the image partially bypassed.
#[must_use]
pub fn partial() -> bool {
    lock_state().partial
}

/// Installs the bypass, or detects one that another module already installed.
///
/// Returns a status message on success. On failure, returns the reason.
pub fn install() -> Result<String, String> {
    let mut state = lock_state();
    if ACTIVE.load(Ordering::Acquire) {
        return Ok("Arxan integrity bypass is active".to_owned());
    }
    if state.partial {
        return Err(
            "T7 Patch: a previous Arxan restore is incomplete; refusing to reinstall".to_owned(),
        );
    }

    let image_base = build::image_base();
    if build::current() == Build::Unknown {
        return Err("This BO3 executable does not match a supported T7 Patch build".to_owned());
    }

    // SAFETY: the game process has its main module mapped at `image_base`.
    if unsafe { external_code_patches_installed(image_base) } {
        EXTERNAL.store(true, Ordering::Release);
        WAITING_FOR_READY_SIGNAL.store(false, Ordering::Release);
        ACTIVE.store(true, Ordering::Release);
        return Ok("Existing Arxan integrity bypass detected".to_owned());
    }

    // SAFETY: the game process has its main module mapped at `image_base`.
    state.patches = unsafe { collect_all_patches(image_base)? };

    let batch: Vec<crate::threads::CodePatch<'_>> = state
        .patches
        .iter()
        .map(|patch| crate::threads::CodePatch {
            address: patch.address,
            bytes: &patch.replacement[..patch.size],
        })
        .collect();
    let result = unsafe { crate::threads::write_code_batch(&batch) };
    drop(batch);

    let reports = match result {
        Ok(reports) => reports,
        Err(error) => {
            let attempted = match &error {
                crate::threads::CodeWriteError::Thaw { reports, .. } => reports.as_slice(),
                crate::threads::CodeWriteError::Busy
                | crate::threads::CodeWriteError::Freeze(_) => &[],
            };
            for (applied, report) in attempted.iter().copied().enumerate() {
                if report.bytes_written {
                    state.patches[applied].state = PatchState::Written;
                }
            }
            if attempted.is_empty() {
                state.patches.clear();
            } else {
                let _ = restore_applied(&mut state, attempted.len());
            }
            return Err(format!("T7 Patch: cannot apply the Arxan bypass: {error}"));
        }
    };

    let mut failure = None;
    for (applied, report) in reports.iter().copied().enumerate() {
        if report.bytes_written {
            state.patches[applied].state = PatchState::Written;
        }
        if !report.complete() {
            failure = Some(applied);
            break;
        }
    }
    if reports.len() < state.patches.len() && failure.is_none() {
        failure = Some(reports.len());
    }
    if let Some(failure) = failure {
        let restored = restore_applied(&mut state, failure + 1);
        return Err(if restored {
            "T7 Patch: could not apply the complete Arxan integrity bypass".to_owned()
        } else {
            "T7 Patch: could not apply the Arxan bypass and its rollback is incomplete".to_owned()
        });
    }

    EXTERNAL.store(false, Ordering::Release);
    WAITING_FOR_READY_SIGNAL.store(true, Ordering::Release);
    ACTIVE.store(true, Ordering::Release);
    Ok("Arxan integrity code-patch bypass is active".to_owned())
}

/// Collects the rewrite list for all three checksum patterns, or fails as a whole.
///
/// # Safety
///
/// Must run inside the game process; see [`find_pattern_in_executable_image`].
unsafe fn collect_all_patches(image_base: usize) -> Result<Vec<SavedPatch>, String> {
    // SAFETY: forwarded to the caller's guarantee.
    unsafe {
        let mut patches = collect_pattern_patches(
            image_base,
            &CHECKSUM_PATTERN1,
            &ENCRYPTED_PATCH1,
            CRC1_EXPECTED_COUNT,
        )?;
        patches.extend(collect_pattern_patches(
            image_base,
            &CHECKSUM_PATTERN2,
            &ENCRYPTED_PATCH2,
            CRC2_EXPECTED_COUNT,
        )?);
        patches.extend(collect_pattern_patches(
            image_base,
            &CHECKSUM_PATTERN3,
            &ENCRYPTED_PATCH3,
            CRC3_EXPECTED_COUNT,
        )?);
        Ok(patches)
    }
}

/// Checks whether the patched bytes are already present in the image.
///
/// # Safety
///
/// Must run inside the game process; see [`find_pattern_in_executable_image`].
unsafe fn external_code_patches_installed(image_base: usize) -> bool {
    let replacement1 = decrypt_patch(&ENCRYPTED_PATCH1);
    let replacement2 = decrypt_patch(&ENCRYPTED_PATCH2);
    let replacement3 = decrypt_patch(&ENCRYPTED_PATCH3);

    // SAFETY: forwarded to the caller's guarantee.
    unsafe {
        // The first six bytes of replacement2 are replacement1.
        find_pattern_in_executable_image(image_base, &replacement1).len()
            >= CRC1_EXPECTED_COUNT + CRC2_EXPECTED_COUNT
            && find_pattern_in_executable_image(image_base, &replacement2).len()
                >= CRC2_EXPECTED_COUNT
            && find_pattern_in_executable_image(image_base, &replacement3).len()
                >= CRC3_EXPECTED_COUNT
    }
}

/// How [`uninstall`] left the bypass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removal {
    /// The original checksum code is back, or nothing was installed.
    Restored,
    /// Another module installed the bypass; it is not ours to remove.
    External,
    /// Kept on purpose because code that depends on it may still be live.
    Retained,
}

/// Restores the original checksum code. Run it last in a rollback, once every
/// hook and code patch that the bypass hides is gone. With `dependents_live`
/// set the bypass is kept, because the integrity checks would trip over the
/// patches still in the image.
pub fn uninstall(dependents_live: bool) -> Result<Removal, String> {
    let mut state = lock_state();
    if !ACTIVE.load(Ordering::Acquire) {
        return if state.partial {
            Err("T7 Patch: Arxan restoration is incomplete".to_owned())
        } else {
            Ok(Removal::Restored)
        };
    }
    if EXTERNAL.load(Ordering::Acquire) {
        ACTIVE.store(false, Ordering::Release);
        EXTERNAL.store(false, Ordering::Release);
        return Ok(Removal::External);
    }
    if dependents_live {
        return Ok(Removal::Retained);
    }
    // Stop maintenance from re-applying the bytes while they are restored.
    WAITING_FOR_READY_SIGNAL.store(false, Ordering::Release);
    let applied = state.patches.len();
    if restore_applied(&mut state, applied) {
        ACTIVE.store(false, Ordering::Release);
        Ok(Removal::Restored)
    } else {
        ACTIVE.store(false, Ordering::Release);
        Err("T7 Patch: Arxan restoration is incomplete".to_owned())
    }
}

/// Re-applies the replacement bytes if the game restored them after the ready signal.
pub fn maintain() {
    if !ACTIVE.load(Ordering::Acquire)
        || EXTERNAL.load(Ordering::Acquire)
        || !WAITING_FOR_READY_SIGNAL.load(Ordering::Acquire)
        || !ready_signal_set()
    {
        return;
    }

    let mut state = lock_state();
    if state.partial {
        return;
    }
    if !ACTIVE.load(Ordering::Acquire) || !WAITING_FOR_READY_SIGNAL.load(Ordering::Acquire) {
        return;
    }

    for index in 0..state.patches.len() {
        let patch = state.patches[index];
        // SAFETY: the address was validated as executable memory when it was collected.
        let current = unsafe { std::slice::from_raw_parts(patch.address as *const u8, patch.size) };
        if current == &patch.replacement[..patch.size] {
            state.patches[index].state = PatchState::Written;
            continue;
        }
        // SAFETY: as above; the freeze checks that no thread is executing the site.
        match unsafe { crate::threads::write_code(patch.address, &patch.replacement[..patch.size]) }
        {
            Ok(report) if report.complete() => state.patches[index].state = PatchState::Written,
            Ok(report) => {
                if report.bytes_written {
                    state.patches[index].state = PatchState::Written;
                }
                if report.uncertain() {
                    state.partial = true;
                    ACTIVE.store(false, Ordering::Release);
                }
                return;
            }
            Err(error) => {
                if let crate::threads::CodeWriteError::Thaw { reports, .. } = &error {
                    if reports.first().is_some_and(|report| report.bytes_written) {
                        state.patches[index].state = PatchState::Written;
                    }
                    state.partial = true;
                    ACTIVE.store(false, Ordering::Release);
                    crate::dllmain::debug_print(&format!(
                        "T7 Patch: Arxan maintenance could not resume every thread: {error}\n"
                    ));
                }
                // Busy or a failed freeze: retry on the next worker tick.
                return;
            }
        }
    }
    WAITING_FOR_READY_SIGNAL.store(false, Ordering::Release);
}

/// Reports whether the bypass is installed.
pub fn active() -> bool {
    ACTIVE.load(Ordering::Acquire)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Fake pages: `protections[page]` is the current protection, and `fail`
    /// fails the given 0-based calls.
    struct FakePages {
        protections: Vec<u32>,
        calls: usize,
        fail: Vec<usize>,
    }

    impl PageProtect for FakePages {
        fn protect(&mut self, start: usize, _size: usize, protection: u32) -> Option<u32> {
            let call = self.calls;
            self.calls += 1;
            if self.fail.contains(&call) {
                return None;
            }
            let page = start / PAGE_SIZE;
            Some(std::mem::replace(&mut self.protections[page], protection))
        }
    }

    const PAGE_READONLY: u32 = 0x02;

    #[test]
    fn journal_restores_every_page_in_reverse() {
        let mut pages = FakePages {
            protections: vec![PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_EXECUTE_READ],
            calls: 0,
            fail: Vec::new(),
        };
        let mut journal = ProtectionJournal::new();
        assert!(journal.make_writable(&mut pages, 0x0FFC, 0x2004));
        assert_eq!(pages.protections, [PAGE_EXECUTE_READWRITE; 3]);
        assert!(journal.restore(&mut pages));
        assert_eq!(
            pages.protections,
            [PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_EXECUTE_READ]
        );
    }

    #[test]
    fn journal_unwinds_when_any_page_cannot_be_made_writable() {
        for failing in 0..3 {
            let mut pages = FakePages {
                protections: vec![PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_EXECUTE_READ],
                calls: 0,
                fail: vec![failing],
            };
            let mut journal = ProtectionJournal::new();
            assert!(!journal.make_writable(&mut pages, 0x0FFC, 0x2004));
            assert_eq!(
                pages.protections,
                [PAGE_EXECUTE_READ, PAGE_READONLY, PAGE_EXECUTE_READ],
                "failure at change {failing}"
            );
        }
    }

    #[test]
    fn journal_retries_a_failed_restore() {
        let mut pages = FakePages {
            protections: vec![PAGE_EXECUTE_READ],
            calls: 0,
            // Call 0 makes the page writable; the first restore attempt fails.
            fail: vec![1],
        };
        let mut journal = ProtectionJournal::new();
        assert!(journal.make_writable(&mut pages, 0x10, 0x18));
        assert!(journal.restore(&mut pages));
        assert_eq!(pages.protections, [PAGE_EXECUTE_READ]);
    }

    #[test]
    fn journal_refuses_ranges_over_the_page_limit() {
        let mut pages = FakePages {
            protections: vec![PAGE_EXECUTE_READ; 8],
            calls: 0,
            fail: Vec::new(),
        };
        let mut journal = ProtectionJournal::new();
        assert!(!journal.make_writable(&mut pages, 0, PAGE_SIZE * 5));
        assert_eq!(pages.calls, 0);
    }

    #[test]
    fn swap_usize_is_compare_and_swap_on_aligned_slots() {
        let slot = Box::new(AtomicUsize::new(5));
        let address = slot.as_ptr().addr();
        // SAFETY: `address` is a live, aligned heap `usize`.
        let stale = unsafe { swap_usize(address, 4, 9) };
        assert!(!stale.written);
        assert_eq!(stale.observed, 5);
        assert_eq!(slot.load(Ordering::Acquire), 5);
        // SAFETY: as above.
        let swapped = unsafe { swap_usize(address, 5, 9) };
        assert!(swapped.complete());
        assert_eq!(slot.load(Ordering::Acquire), 9);
        // A misaligned slot, as in the game's import table, is swapped too.
        let mut words = Box::new([0u64; 16]);
        let base = words.as_mut_ptr().addr();
        let line = (base + CACHE_LINE - 1) & !(CACHE_LINE - 1);
        let misaligned = line + 4;
        if misaligned + 8 <= base + 16 * 8 {
            // SAFETY: `misaligned` lies inside the live heap array, within one line.
            unsafe { (misaligned as *mut usize).write_unaligned(7) };
            // SAFETY: as above.
            let swapped = unsafe { swap_usize(misaligned, 7, 11) };
            assert!(swapped.complete());
            // SAFETY: as above.
            assert_eq!(unsafe { (misaligned as *const usize).read_unaligned() }, 11);
            // SAFETY: as above; a stale expected value writes nothing.
            assert!(!unsafe { swap_usize(misaligned, 7, 13) }.written);
        }
        assert!(within_cache_line(0x1000 + 0x14));
        assert!(within_cache_line(0x1000 + 0x38));
        assert!(!within_cache_line(0x1000 + 0x3C));
        // SAFETY: an unmapped slot is refused by the VirtualQuery check, not read.
        let unmapped = unsafe { swap_usize(0x10, 0, 1) };
        assert!(!unmapped.written);
        assert_eq!(unmapped.observed, 0);
    }

    #[test]
    fn decrypt_patch_xors_with_key() {
        assert_eq!(decrypt_patch(&[0x69, 0x00]), vec![0x00, 0x69]);
    }

    #[test]
    fn decrypted_patch1_matches_known_bytes() {
        // `xor rcx, rcx` followed by three `nop`s.
        assert_eq!(
            decrypt_patch(&ENCRYPTED_PATCH1),
            vec![0x48, 0x31, 0xC9, 0x90, 0x90, 0x90]
        );
    }

    #[test]
    fn find_all_reports_overlapping_matches() {
        assert_eq!(find_all(b"aaaa", b"aa"), vec![0, 1, 2]);
        assert_eq!(find_all(b"abc", b"abcd"), Vec::<usize>::new());
        assert_eq!(find_all(b"", b"a"), Vec::<usize>::new());
    }

    #[test]
    fn write_report_distinguishes_partial_writes() {
        let complete = WriteReport {
            bytes_written: true,
            cache_flushed: true,
            protection_restored: true,
        };
        assert!(complete.complete());
        assert!(!complete.uncertain());

        let partial = WriteReport {
            bytes_written: true,
            cache_flushed: false,
            protection_restored: true,
        };
        assert!(!partial.complete());
        assert!(partial.uncertain());

        assert!(!WriteReport::default().complete());
        assert!(!WriteReport::default().uncertain());
    }

    #[test]
    fn executable_protection_rejects_guarded_and_non_executable_pages() {
        assert!(executable_protection(PAGE_EXECUTE_READ));
        assert!(executable_protection(PAGE_EXECUTE_READWRITE));
        assert!(!executable_protection(PAGE_EXECUTE_READ | PAGE_GUARD));
        assert!(!executable_protection(PAGE_NOACCESS));
        assert!(!executable_protection(0x04)); // PAGE_READWRITE
    }
}
