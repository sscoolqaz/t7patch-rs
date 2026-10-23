//! Arxan integrity-check bypass.
//!
//! Port of `Arxan.cpp` and `Arxan.h`. The game's anti-tamper code scans its own
//! code for known checksum instruction sequences. The sequences are stored
//! XOR-encrypted here and rewritten in memory so the scan no longer matches.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use windows::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualProtect, VirtualQuery};
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

/// One byte range rewritten by the bypass, with the bytes needed to undo it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SavedPatch {
    address: usize,
    size: usize,
    original: [u8; 8],
    replacement: [u8; 8],
}

struct State {
    patches: Vec<SavedPatch>,
}

static ACTIVE: AtomicBool = AtomicBool::new(false);
static EXTERNAL: AtomicBool = AtomicBool::new(false);
static WAITING_FOR_READY_SIGNAL: AtomicBool = AtomicBool::new(false);
static STATE: Mutex<State> = Mutex::new(State {
    patches: Vec::new(),
});

fn lock_state() -> MutexGuard<'static, State> {
    STATE.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Reports whether a page protection allows execution and is readable.
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
pub fn decrypt_patch(encrypted: &[u8]) -> Vec<u8> {
    encrypted.iter().map(|byte| byte ^ PATCH_KEY).collect()
}

/// Finds every (possibly overlapping) occurrence of `pattern` in `haystack`.
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

/// Writes `bytes` over `address`, temporarily making the page writable.
///
/// # Safety
///
/// `[address, address + bytes.len())` must lie inside committed executable memory.
pub(crate) unsafe fn write_bytes(address: usize, bytes: &[u8]) -> bool {
    let mut old = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    // SAFETY: the caller guarantees the range is committed executable memory.
    let changed = unsafe {
        VirtualProtect(
            address as *const _,
            bytes.len(),
            windows::Win32::System::Memory::PAGE_EXECUTE_READWRITE,
            &raw mut old,
        )
    };
    if changed.is_err() {
        return false;
    }

    // SAFETY: the range was made writable above and `bytes` does not overlap the target.
    unsafe { std::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len()) };
    // SAFETY: the current process handle is a pseudo-handle that is always valid.
    let flushed = unsafe {
        FlushInstructionCache(GetCurrentProcess(), Some(address as *const _), bytes.len())
    };

    let mut ignored = windows::Win32::System::Memory::PAGE_PROTECTION_FLAGS(0);
    // SAFETY: restores the protection captured above for the same range.
    let restored =
        unsafe { VirtualProtect(address as *const _, bytes.len(), old, &raw mut ignored) };
    flushed.is_ok() && restored.is_ok()
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
        });
    }
    Ok(patches)
}

/// Undoes the first `applied` patches in reverse order and forgets them all.
fn rollback_applied(state: &mut State, applied: usize) {
    for patch in state.patches[..applied].iter().rev() {
        // SAFETY: the address was validated as executable memory when the patch was collected.
        unsafe { write_bytes(patch.address, &patch.original[..patch.size]) };
    }
    state.patches.clear();
}

/// Installs the bypass, or detects one that another module already installed.
///
/// Returns a status message on success. On failure, returns the reason.
pub fn install() -> Result<String, String> {
    let mut state = lock_state();
    if ACTIVE.load(Ordering::Acquire) {
        return Ok("Arxan integrity bypass is active".to_owned());
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

    for applied in 0..state.patches.len() {
        let patch = state.patches[applied];
        // SAFETY: the address was validated as executable memory when it was collected.
        if unsafe { write_bytes(patch.address, &patch.replacement[..patch.size]) } {
            continue;
        }
        // SAFETY: as above; restores the bytes already rewritten in this pass.
        unsafe { write_bytes(patch.address, &patch.original[..patch.size]) };
        rollback_applied(&mut state, applied);
        return Err("Could not apply the complete Arxan integrity bypass".to_owned());
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

/// Re-applies the replacement bytes if the game restored them after the ready signal.
pub fn maintain() {
    if !ACTIVE.load(Ordering::Acquire)
        || EXTERNAL.load(Ordering::Acquire)
        || !WAITING_FOR_READY_SIGNAL.load(Ordering::Acquire)
        || !ready_signal_set()
    {
        return;
    }

    let state = lock_state();
    if !ACTIVE.load(Ordering::Acquire) || !WAITING_FOR_READY_SIGNAL.load(Ordering::Acquire) {
        return;
    }

    for patch in &state.patches {
        // SAFETY: the address was validated as executable memory when it was collected.
        let current = unsafe { std::slice::from_raw_parts(patch.address as *const u8, patch.size) };
        if current == &patch.replacement[..patch.size] {
            continue;
        }
        // SAFETY: as above.
        if !unsafe { write_bytes(patch.address, &patch.replacement[..patch.size]) } {
            return;
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
    fn executable_protection_rejects_guarded_and_non_executable_pages() {
        assert!(executable_protection(PAGE_EXECUTE_READ));
        assert!(executable_protection(PAGE_EXECUTE_READWRITE));
        assert!(!executable_protection(PAGE_EXECUTE_READ | PAGE_GUARD));
        assert!(!executable_protection(PAGE_NOACCESS));
        assert!(!executable_protection(0x04)); // PAGE_READWRITE
    }
}
