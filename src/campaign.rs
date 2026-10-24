//! Campaign script fix for the "Demon Within" damage transition.
//!
//! Port of `CampaignFixes.cpp` and `CampaignFixes.h`. The stock campaign
//! scripts compile a damage condition that never fires. After the script
//! linker finishes, the condition bytes are swapped for a lethal check.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};

use windows::Win32::System::Diagnostics::Debug::OutputDebugStringA;
use windows::core::s;

use crate::arxan::write_bytes;
use crate::ffi::{self, MinHookError};
use crate::offsets;

/// RVA of `Scr_GscObjLink`. The same in the February and September builds.
const SCR_GSC_OBJ_LINK_RVA: usize = 0x12CC320;

const DAMAGE_OVERRIDE_FUNCTION: u32 = 0x56F9_AB2E;
const INFECTION_ZOMBIES_NAMESPACE: u32 = 0xB0A8_7E94;

const COMPILED_SCRIPT_MAGIC: [u8; 7] = [0x80, 0x47, 0x53, 0x43, 0x0D, 0x0A, 0x00];
const MAX_SCRIPT_SIZE: u32 = 64 * 1024 * 1024;
const MAX_EXPORT_COUNT: u16 = 4096;
const EXPORT_SIZE: usize = 0x14;

// Decrypted `0x1B` bytecode: `self.numhits === 5`.
const ORIGINAL_CONDITION_1B: [u8; 7] = [0xD9, 0xCA, 0xB7, 0x6E, 0xE2, 0x05, 0x28];
// Decrypted `0x1B` bytecode: `self.health <= idamage`.
const LETHAL_CONDITION_1B: [u8; 7] = [0x6B, 0xF1, 0x90, 0x3A, 0x5D, 0x08, 0x42];

// Protected `0x1C` bytecode from the stock campaign fastfile. The replacement
// encodings were copied from matching operations in the same script.
const ORIGINAL_CONDITION_1C: [u8; 10] = [
    0xD9, 0xCA, 0xB7, 0x6E, // self.numhits field hash
    0xA2, 0x03, 0x05, 0x34, // GetByte 5
    0x0D, 0x12, // SuperEqual
];
const LETHAL_CONDITION_1C: [u8; 10] = [
    0x6B, 0xF1, 0x90, 0x3A, // self.health field hash
    0xBB, 0x09, 0x08, 0x51, // EvalLocalVariableCached idamage
    0x53, 0x0E, // LessThanOrEqualTo
];

/// Describes one supported script version and the condition to swap.
struct DamagePatch {
    script_version: u8,
    checksum: u32,
    minimum_function_size: u32,
    condition_offset: u32,
    original: &'static [u8],
    replacement: &'static [u8],
}

const PATCH_1B: DamagePatch = DamagePatch {
    script_version: 0x1B,
    checksum: 0xC5BA_252D,
    minimum_function_size: 0xD5,
    condition_offset: 0xB4,
    original: &ORIGINAL_CONDITION_1B,
    replacement: &LETHAL_CONDITION_1B,
};

const PATCH_1C: DamagePatch = DamagePatch {
    script_version: 0x1C,
    checksum: 0x6BA4_A2E4,
    minimum_function_size: 0xFA,
    condition_offset: 0xC4,
    original: &ORIGINAL_CONDITION_1C,
    replacement: &LETHAL_CONDITION_1C,
};

/// A byte range inside a compiled script that should be rewritten.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatchSite {
    /// Offset from the start of the compiled script.
    pub offset: usize,
    /// Bytes to write at `offset`.
    pub replacement: &'static [u8],
}

fn damage_patch_for(script_version: u8) -> Option<&'static DamagePatch> {
    match script_version {
        version if version == PATCH_1B.script_version => Some(&PATCH_1B),
        version if version == PATCH_1C.script_version => Some(&PATCH_1C),
        _ => None,
    }
}

fn read_u32(buffer: &[u8], offset: usize) -> Option<u32> {
    let bytes = buffer.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u16(buffer: &[u8], offset: usize) -> Option<u16> {
    let bytes = buffer.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

/// Finds the damage condition in a linked compiled script, if it needs patching.
///
/// Returns `None` when the buffer is not a supported script, when the target
/// function is absent, or when the condition is already replaced or unexpected.
#[must_use]
pub fn find_damage_patch(buffer: &[u8]) -> Option<PatchSite> {
    if buffer.len() < 0x40 || !buffer.starts_with(&COMPILED_SCRIPT_MAGIC) {
        return None;
    }

    let patch = damage_patch_for(buffer[7])?;

    // The compiled-script header stores its complete buffer size at 0x28.
    let size = usize::try_from(read_u32(buffer, 0x28)?).ok()?;
    if !(0x40..=MAX_SCRIPT_SIZE as usize).contains(&size) || size > buffer.len() {
        return None;
    }
    let buffer = &buffer[..size];

    let export_offset = usize::try_from(read_u32(buffer, 0x20)?).ok()?;
    let export_count = read_u16(buffer, 0x3A)?;
    let export_table_size = usize::from(export_count) * EXPORT_SIZE;
    if export_count > MAX_EXPORT_COUNT
        || export_offset > size
        || export_table_size > size - export_offset
    {
        return None;
    }

    for index in 0..usize::from(export_count) {
        let base = export_offset + index * EXPORT_SIZE;
        let checksum = read_u32(buffer, base)?;
        let bytecode_offset = usize::try_from(read_u32(buffer, base + 4)?).ok()?;
        let function_name = read_u32(buffer, base + 8)?;
        let function_namespace = read_u32(buffer, base + 12)?;

        if function_name != DAMAGE_OVERRIDE_FUNCTION
            || function_namespace != INFECTION_ZOMBIES_NAMESPACE
            || checksum != patch.checksum
        {
            continue;
        }

        if bytecode_offset > size
            || usize::try_from(patch.minimum_function_size).ok()? > size - bytecode_offset
        {
            return None;
        }

        let condition_start = bytecode_offset + usize::try_from(patch.condition_offset).ok()?;
        let end = condition_start.checked_add(patch.original.len())?;
        if end > size {
            return None;
        }

        let current = &buffer[condition_start..end];
        if current == patch.replacement || current != patch.original {
            return None;
        }
        return Some(PatchSite {
            offset: condition_start,
            replacement: patch.replacement,
        });
    }

    None
}

/// Serializes calls to the script patcher, which runs on the linker thread.
static PATCH_LOCK: Mutex<()> = Mutex::new(());
static ORIGINAL_SCR_GSC_OBJ_LINK: AtomicUsize = AtomicUsize::new(0);

fn lock_patch() -> MutexGuard<'static, ()> {
    PATCH_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Patches the compiled script at `script`, if it is one that needs the fix.
///
/// # Safety
///
/// `script` must point to a compiled script object of at least 0x40 readable bytes.
unsafe fn patch_compiled_script(script: *mut u8) {
    if script.is_null() {
        return;
    }
    let _guard = lock_patch();

    // SAFETY: the caller guarantees the script header is readable.
    let header = unsafe { std::slice::from_raw_parts(script, 0x40) };
    if !header.starts_with(&COMPILED_SCRIPT_MAGIC) {
        return;
    }
    let Some(size) = read_u32(header, 0x28) else {
        return;
    };
    if !(0x40..=MAX_SCRIPT_SIZE).contains(&size) {
        return;
    }

    // SAFETY: the header declares `size` bytes of script, which the linker has finished writing.
    let bytes = unsafe { std::slice::from_raw_parts(script, size as usize) };
    let Some(found) = find_damage_patch(bytes) else {
        return;
    };

    // The script is bytecode read by the GSC VM, not executable instructions, so the
    // RIP-based freeze used for code writes does not apply. This runs in the linker
    // detour after the linker finished writing the script and before the VM runs it.
    // SAFETY: `find_damage_patch` checked the site lies inside the declared script.
    if unsafe { write_bytes(script as usize + found.offset, found.replacement) } {
        // SAFETY: the debug string is a static, NUL-terminated literal.
        unsafe {
            OutputDebugStringA(s!(
                "T7 Patch: fixed Demon Within Realistic damage transition.\n"
            ));
        }
    }
}

/// Detour for `Scr_GscObjLink`. Calls the original linker, then patches the script.
///
/// # Safety
///
/// Called by the game's script linker with the linker's own arguments.
unsafe extern "system" fn scr_gsc_obj_link_hook(instance: i32, script_object: *mut u8) -> i64 {
    // SAFETY: `ORIGINAL_SCR_GSC_OBJ_LINK` holds the trampoline MinHook returned for this signature.
    let original: unsafe extern "system" fn(i32, *mut u8) -> i64 =
        unsafe { std::mem::transmute(ORIGINAL_SCR_GSC_OBJ_LINK.load(Ordering::Acquire)) };

    // Some stock campaign scripts reach this linker without a named lookup. Patch
    // only after linking so BO3 has resolved field identifiers.
    // SAFETY: the linker has just returned, so the script object is fully linked.
    let result = unsafe { original(instance, script_object) };
    // SAFETY: as above.
    unsafe { patch_compiled_script(script_object) };
    result
}

/// Creates the `Scr_GscObjLink` detour. Hooks are enabled later with the rest.
pub fn install_hooks() -> Result<(), MinHookError> {
    let target = offsets::address(SCR_GSC_OBJ_LINK_RVA);
    // SAFETY: the RVA is `Scr_GscObjLink`, whose signature matches `scr_gsc_obj_link_hook`.
    let original =
        unsafe { ffi::create_hook(target, scr_gsc_obj_link_hook as *const () as usize)? };
    ORIGINAL_SCR_GSC_OBJ_LINK.store(original, Ordering::Release);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a minimal compiled script with one matching export.
    fn script(version: u8, checksum: u32, bytecode_offset: u32, condition: &[u8]) -> Vec<u8> {
        let mut buffer = vec![0u8; 0x200];
        buffer[..7].copy_from_slice(&COMPILED_SCRIPT_MAGIC);
        buffer[7] = version;
        buffer[0x28..0x2C].copy_from_slice(&0x200u32.to_le_bytes());
        buffer[0x20..0x24].copy_from_slice(&0x40u32.to_le_bytes());
        buffer[0x3A..0x3C].copy_from_slice(&1u16.to_le_bytes());

        let export = 0x40;
        buffer[export..export + 4].copy_from_slice(&checksum.to_le_bytes());
        buffer[export + 4..export + 8].copy_from_slice(&bytecode_offset.to_le_bytes());
        buffer[export + 8..export + 12].copy_from_slice(&DAMAGE_OVERRIDE_FUNCTION.to_le_bytes());
        buffer[export + 12..export + 16]
            .copy_from_slice(&INFECTION_ZOMBIES_NAMESPACE.to_le_bytes());

        let site = bytecode_offset as usize + 0xB4;
        if let Some(target) = buffer.get_mut(site..site + condition.len()) {
            target.copy_from_slice(condition);
        }
        buffer
    }

    #[test]
    fn finds_original_condition_for_1b_script() {
        let buffer = script(0x1B, PATCH_1B.checksum, 0x100, &ORIGINAL_CONDITION_1B);
        assert_eq!(
            find_damage_patch(&buffer),
            Some(PatchSite {
                offset: 0x1B4,
                replacement: &LETHAL_CONDITION_1B,
            })
        );
    }

    #[test]
    fn skips_script_that_is_already_patched() {
        let buffer = script(0x1B, PATCH_1B.checksum, 0x100, &LETHAL_CONDITION_1B);
        assert_eq!(find_damage_patch(&buffer), None);
    }

    #[test]
    fn skips_unknown_script_version() {
        let buffer = script(0x1D, PATCH_1B.checksum, 0x100, &ORIGINAL_CONDITION_1B);
        assert_eq!(find_damage_patch(&buffer), None);
    }

    #[test]
    fn skips_export_with_wrong_checksum() {
        let buffer = script(0x1B, 0, 0x100, &ORIGINAL_CONDITION_1B);
        assert_eq!(find_damage_patch(&buffer), None);
    }

    #[test]
    fn rejects_buffers_without_script_magic() {
        let mut buffer = script(0x1B, PATCH_1B.checksum, 0x100, &ORIGINAL_CONDITION_1B);
        buffer[0] = 0;
        assert_eq!(find_damage_patch(&buffer), None);
    }

    #[test]
    fn rejects_function_that_would_run_past_the_script() {
        let buffer = script(0x1B, PATCH_1B.checksum, 0x1F0, &ORIGINAL_CONDITION_1B);
        assert_eq!(find_damage_patch(&buffer), None);
    }
}
