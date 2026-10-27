//! Dynamic x64 unwind metadata for relocated prologues (VENDORED patch 17).
//!
//! Translation and all function-table APIs run before a freeze or after thaw.
//! Missing/uncertain source information preserves compatibility: no table is
//! installed. A failed table API is an error, never permission to free its memory.

use crate::error::{HookError, Result};
use crate::instruction::Trampoline;
use crate::trampoline::Snapshot;
use iced_x86::{Decoder, DecoderOptions, FlowControl};
use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::System::Diagnostics::Debug::{
    IMAGE_RUNTIME_FUNCTION_ENTRY, ReadProcessMemory, RtlAddFunctionTable, RtlDeleteFunctionTable,
    RtlLookupFunctionEntry,
};
use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQuery};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

/// Header plus the maximum 255 two-byte unwind slots, rounded to four bytes.
const INFO_SIZE: usize = 516;

/// Lives beside, never inside, the 64-byte executable slot. Its address is stable
/// until deletion succeeds; retained slots retain this structure as well.
#[repr(C)]
pub(crate) struct Metadata {
    entries: [IMAGE_RUNTIME_FUNCTION_ENTRY; 2],
    info: [u8; INFO_SIZE],
    leaf: [u8; 4],
    registered: bool,
    described: bool,
    base: usize,
}

/// Source/relocated instruction starts plus the actual end of the relocated body.
/// The existing MinHook map additionally contains a jump-back boundary, if any.
struct Layout<'a> {
    old: &'a [u8],
    new: &'a [u8],
    source_len: u8,
    body_len: u8,
    end: u8,
}

impl Layout<'_> {
    fn validate(&self) -> Option<()> {
        if self.old.is_empty()
            || self.old.len() != self.new.len()
            || self.old.len() > 8
            || self.old[0] != 0
            || self.new[0] != 0
            || self.source_len == 0
            || self.body_len == 0
            || self.body_len > self.end
            || self.end > 50
            || !self.old.windows(2).all(|w| w[0] < w[1])
            || !self.new.windows(2).all(|w| w[0] < w[1])
            || *self.old.last()? >= self.source_len
            || *self.new.last()? >= self.body_len
        {
            return None;
        }
        Some(())
    }

    fn offset(&self, old: u8) -> Option<u8> {
        if old == self.source_len {
            return Some(self.body_len);
        }
        self.old.iter().position(|&o| o == old).map(|i| self.new[i])
    }
}

fn nonvolatile(reg: u8) -> bool {
    matches!(reg, 3 | 5..=7 | 12..=15)
}

/// Translate only certain version-1/2 prologue records. Every record is parsed,
/// including dropped operations. No source metadata is ever dereferenced here.
fn translate(input: &[u8], layout: &Layout<'_>) -> Option<[u8; INFO_SIZE]> {
    layout.validate()?;
    let header = input.get(..4)?;
    if !matches!(header[0], 1 | 2) || header[1] < layout.source_len {
        return None; // flags, unknown version, or stolen original body/epilogue
    }
    let count = usize::from(header[2]);
    let size = (4 + count * 2 + 3) & !3;
    if input.len() != size || size > INFO_SIZE {
        return None;
    }
    let frame = header[3] & 15;
    if (frame == 0 && header[3] != 0) || (frame != 0 && !nonvolatile(frame)) {
        return None;
    }
    let mut output = [0u8; INFO_SIZE];
    // Version 2 with no EPILOG descriptors declares no epilogue. Windows' v1
    // heuristic otherwise treats FF25 (jump back) or EB08 (an expanded call's
    // return) as an epilogue even within SizeOfProlog, skipping frame recovery.
    // The supported prologue operations have identical meanings in v1/v2.
    output[0] = 2;
    // Include the injected tail in the prologue. Its JmpAbs otherwise resembles
    // an epilogue, even though the stolen frame has NOT been dismantled yet.
    output[1] = layout.end;
    let mut index = 0;
    let mut written = 0;
    let mut previous = u8::MAX;
    let mut setters = 0;
    let mut kept_setter = false;
    let mut kept_save = false;
    let mut dropped_frame_change = false;
    while index < count {
        let pos = 4 + index * 2;
        let offset = input[pos];
        let op = input[pos + 1] & 15;
        let arg = input[pos + 1] >> 4;
        if offset == 0 || offset > header[1] || (index != 0 && offset >= previous) {
            return None;
        }
        previous = offset;
        let slots = match op {
            0 if nonvolatile(arg) => 1,            // PUSH_NONVOL
            1 if arg <= 1 => 2 + usize::from(arg), // ALLOC_LARGE
            2 => 1,                                // ALLOC_SMALL
            3 if arg == 0 && frame != 0 => {
                setters += 1;
                1 // SET_FPREG
            }
            4 if nonvolatile(arg) => 2, // SAVE_NONVOL
            5 if nonvolatile(arg) => 3, // SAVE_NONVOL_FAR
            8 if arg >= 6 => 2,         // SAVE_XMM128
            9 if arg >= 6 => 3,         // SAVE_XMM128_FAR
            // 6/7: obsolete v1 SAVE_XMM forms or v2 EPILOG/SPARE; no sound
            // translation of epilog scopes. 10: synthetic PUSH_MACHFRAME, not
            // an executed prologue instruction. All are explicitly unsupported.
            _ => return None,
        };
        if index + slots > count {
            return None;
        }
        let bytes = &input[pos..pos + slots * 2];
        if op == 1 {
            let amount = if arg == 0 {
                u32::from(u16::from_le_bytes([bytes[2], bytes[3]])) * 8
            } else {
                u32::from_le_bytes(bytes[2..6].try_into().ok()?)
            };
            if amount == 0 || amount % 8 != 0 {
                return None;
            }
        }
        if matches!(op, 5 | 9) {
            let amount = u32::from_le_bytes(bytes[2..6].try_into().ok()?);
            if amount % if op == 5 { 8 } else { 16 } != 0 {
                return None;
            }
        }
        if offset <= layout.source_len {
            let mapped = layout.offset(offset)?;
            output[4 + written * 2..4 + (written + slots) * 2].copy_from_slice(bytes);
            output[4 + written * 2] = mapped;
            written += slots;
            kept_setter |= op == 3;
            kept_save |= matches!(op, 4 | 5 | 8 | 9);
        } else {
            dropped_frame_change |= matches!(op, 0..=3);
        }
        index += slots;
    }
    if setters != usize::from(frame != 0)
        || (kept_save && (frame != 0 || dropped_frame_change))
        || (kept_setter && dropped_frame_change)
    {
        return None;
    }
    output[2] = u8::try_from(written).ok()?;
    output[3] = if kept_setter { header[3] } else { 0 };
    Some(output)
}

/// Non-faulting reads; the OS lookup itself trusts its registered table registry
/// (and any third-party lookup callbacks), as it does for normal stack walks.
fn read(address: usize, bytes: &mut [u8]) -> Option<()> {
    address.checked_add(bytes.len())?;
    let mut done = 0;
    // SAFETY: RPM validates the source; the destination is our writable slice.
    let ok = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address as *const c_void,
            bytes.as_mut_ptr().cast(),
            bytes.len(),
            &mut done,
        )
    };
    (ok != 0 && done == bytes.len()).then_some(())
}

fn source(target: usize, source_len: u8) -> Option<[u8; INFO_SIZE]> {
    let mut base = 0;
    // SAFETY: no history pointer is supplied. Called only outside any freeze.
    let entry = unsafe { RtlLookupFunctionEntry(target as u64, &mut base, ptr::null_mut()) };
    if entry.is_null() {
        return None;
    }
    let mut data = [0u8; 12];
    read(entry as usize, &mut data)?;
    let word = |offset| u32::from_le_bytes(data[offset..offset + 4].try_into().unwrap());
    let base = usize::try_from(base).ok()?;
    let begin = base.checked_add(word(0) as usize)?;
    let end = base.checked_add(word(4) as usize)?;
    let rva = word(8);
    if begin != target || end <= begin || rva == 0 || rva % 4 != 0 {
        return None;
    }
    let address = base.checked_add(rva as usize)?;
    let mut info = [0u8; INFO_SIZE];
    read(address, &mut info[..4])?;
    if end.checked_sub(begin)? < usize::from(info[1].max(source_len)) {
        return None;
    }
    let size = (4 + usize::from(info[2]) * 2 + 3) & !3;
    // Original metadata must belong to the same image/allocation as the target.
    // This deliberately declines otherwise valid external dynamic xdata, rather
    // than accepting an out-of-image RVA merely because it happens to be readable.
    let allocation = |address: usize| {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        // SAFETY: queries the mapping, never dereferences the queried address.
        let queried = unsafe {
            VirtualQuery(
                address as *const c_void,
                &mut mbi,
                size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        (queried != 0).then_some(mbi.AllocationBase)
    };
    let owner = allocation(target)?;
    if allocation(address)? != owner
        || allocation(address.checked_add(size - 1)?)? != owner
        || allocation(end.checked_sub(1)?)? != owner
    {
        return None;
    }
    let header: [u8; 4] = info[..4].try_into().ok()?;
    read(address, &mut info[..size])?;
    if info[..4] != header {
        return None;
    }
    Some(info)
}

/// A branch or return can skip/undo frame effects. Do not describe such a stub
/// by linear prologue offsets, even if the original table declares it a prologue.
fn linear(snapshot: &Snapshot, source_len: u8) -> bool {
    let Some(bytes) = snapshot
        .code
        .get(..snapshot.len)
        .and_then(|b| b.get(..usize::from(source_len)))
    else {
        return false;
    };
    let mut decoder = Decoder::new(64, bytes, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.is_invalid()
            || !matches!(
                instruction.flow_control(),
                FlowControl::Next | FlowControl::Call | FlowControl::IndirectCall
            )
        {
            return false;
        }
    }
    true
}

impl Metadata {
    /// Register in the live slot's metadata. `base` is the start of this code slot.
    /// The caller owns this stable memory, and has not published the hook yet.
    pub(crate) fn register(
        &mut self,
        base: usize,
        ct: &Trampoline,
        snapshot: &Snapshot,
    ) -> Result<()> {
        if !linear(snapshot, ct.source_len) {
            return Ok(());
        }
        let Some(info) = source(ct.target as usize, ct.source_len) else {
            return Ok(());
        };
        let count = ct.n_ip as usize;
        let back = count > 0 && ct.old_ips[count - 1] == ct.source_len;
        let starts = count - usize::from(back);
        let end = u8::try_from(ct.relay as usize - ct.trampoline as usize)
            .map_err(|_| HookError::UnsupportedFunction)?;
        let layout = Layout {
            old: &ct.old_ips[..starts],
            new: &ct.new_ips[..starts],
            source_len: ct.source_len,
            body_len: if back { ct.new_ips[count - 1] } else { end },
            end,
        };
        let size = (4 + usize::from(info[2]) * 2 + 3) & !3;
        let Some(translated) = translate(&info[..size], &layout) else {
            return Ok(());
        };
        self.info = translated;
        self.leaf = [1, 0, 0, 0];
        let rva = |address: usize| -> Result<u32> {
            address
                .checked_sub(base)
                .and_then(|offset| u32::try_from(offset).ok())
                .ok_or(HookError::UnsupportedFunction)
        };
        self.entries = [
            IMAGE_RUNTIME_FUNCTION_ENTRY {
                BeginAddress: rva(ct.trampoline as usize)?,
                EndAddress: rva(ct.relay as usize)?,
                Anonymous:
                    windows_sys::Win32::System::Diagnostics::Debug::IMAGE_RUNTIME_FUNCTION_ENTRY_0 {
                        UnwindData: rva(self.info.as_ptr() as usize)?,
                    },
            },
            IMAGE_RUNTIME_FUNCTION_ENTRY {
                BeginAddress: rva(ct.relay as usize)?,
                EndAddress: rva(ct.relay as usize + 14)?,
                Anonymous:
                    windows_sys::Win32::System::Diagnostics::Debug::IMAGE_RUNTIME_FUNCTION_ENTRY_0 {
                        UnwindData: rva(self.leaf.as_ptr() as usize)?,
                    },
            },
        ];
        // SAFETY: entries are sorted, in the block's RVA window, and self lives
        // beside its code until delete succeeds. No threads are frozen.
        if !unsafe { add(self.entries.as_ptr(), base) } {
            return Err(HookError::UnwindRegistration);
        }
        self.registered = true;
        self.described = true;
        self.base = base;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn described_table(&self) -> Option<(usize, usize)> {
        self.described
            .then_some((self.base, self.entries.as_ptr() as usize))
    }

    /// Repair a table removed by an incomplete bulk cleanup, outside a freeze.
    pub(crate) fn restore(&mut self) -> Result<()> {
        if self.described && !self.registered {
            // SAFETY: the same stable entries and metadata are still allocated.
            if !unsafe { add(self.entries.as_ptr(), self.base) } {
                return Err(HookError::UnwindRegistration);
            }
            self.registered = true;
        }
        Ok(())
    }

    pub(crate) fn release(&mut self) -> Result<()> {
        self.unregister()?;
        self.described = false;
        Ok(())
    }

    pub(crate) fn unregister(&mut self) -> Result<()> {
        if self.registered {
            // SAFETY: exactly the table previously added, still in owned memory;
            // called after thaw and before reuse or release, never in a freeze.
            if !unsafe { delete(self.entries.as_ptr()) } {
                return Err(HookError::UnwindDeletion);
            }
            self.registered = false;
        }
        Ok(())
    }
}

unsafe fn add(entries: *const IMAGE_RUNTIME_FUNCTION_ENTRY, base: usize) -> bool {
    #[cfg(test)]
    if fault::ADD_FAIL.with(std::cell::Cell::get) {
        return false;
    }
    // SAFETY: forwarded from the registration caller.
    unsafe { RtlAddFunctionTable(entries, 2, base as u64) }
}

unsafe fn delete(entries: *const IMAGE_RUNTIME_FUNCTION_ENTRY) -> bool {
    #[cfg(test)]
    if fault::DELETE_FAIL.with(std::cell::Cell::get) {
        let skip = fault::DELETE_SKIP.with(std::cell::Cell::get);
        if skip == 0 {
            return false;
        }
        fault::DELETE_SKIP.with(|f| f.set(skip - 1));
    }
    // SAFETY: forwarded from the deletion caller.
    unsafe { RtlDeleteFunctionTable(entries) }
}

#[cfg(test)]
pub(crate) mod fault {
    use std::cell::Cell;
    thread_local! {
        pub(crate) static ADD_FAIL: Cell<bool> = const { Cell::new(false) };
        pub(crate) static DELETE_FAIL: Cell<bool> = const { Cell::new(false) };
        pub(crate) static DELETE_SKIP: Cell<usize> = const { Cell::new(0) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn layout() -> Layout<'static> {
        Layout {
            old: &[0, 1, 3],
            new: &[0, 2, 10],
            source_len: 5,
            body_len: 14,
            end: 28,
        }
    }

    fn record(prolog: u8, frame: u8, codes: &[u8]) -> Vec<u8> {
        assert_eq!(codes.len() % 2, 0);
        let mut input = vec![1, prolog, u8::try_from(codes.len() / 2).unwrap(), frame];
        input.extend_from_slice(codes);
        input.resize((input.len() + 3) & !3, 0);
        input
    }

    #[test]
    fn every_supported_operation_is_kept_translated_or_dropped() {
        for bytes in [
            &[3, 0x30][..],         // push rbx
            &[3, 0x01, 4, 0],       // alloc large scaled
            &[3, 0x11, 0, 1, 0, 0], // alloc large unscaled
            &[3, 0x42],             // alloc small
            &[3, 0x34, 4, 0],       // save rbx scaled
            &[3, 0x35, 0, 1, 0, 0], // save rbx far
            &[3, 0x68, 4, 0],       // save xmm6 scaled
            &[3, 0x69, 0, 1, 0, 0], // save xmm6 far
        ] {
            for version in [1, 2] {
                let mut input = record(8, 0, bytes);
                input[0] = version;
                let output = translate(&input, &layout()).unwrap();
                assert_eq!(output[0..4], [2, 28, bytes.len() as u8 / 2, 0]);
                assert_eq!(output[4], 10);
                assert_eq!(&output[5..4 + bytes.len()], &bytes[1..]);
                input[4] = 8;
                assert_eq!(translate(&input, &layout()).unwrap()[2], 0);
            }
        }
    }

    #[test]
    fn frame_register_is_present_only_when_setup_is_stolen() {
        let kept = record(8, 0x25, &[3, 3, 1, 0x50]);
        let output = translate(&kept, &layout()).unwrap();
        assert_eq!(output[3], 0x25);
        assert_eq!(&output[4..8], &[10, 3, 2, 0x50]);
        let dropped = record(8, 0x25, &[8, 3, 1, 0x50]);
        let output = translate(&dropped, &layout()).unwrap();
        assert_eq!(output[3], 0);
        assert_eq!(&output[4..6], &[2, 0x50]);
    }

    #[test]
    fn instruction_end_uses_grown_shrunk_and_final_boundaries() {
        let mut map = layout();
        map.new = &[0, 2, 3];
        map.body_len = 4;
        map.end = 18;
        let output = translate(&record(8, 0, &[5, 2, 3, 0x30, 1, 0x50]), &map).unwrap();
        assert_eq!(&output[4..10], &[4, 2, 3, 0x30, 2, 0x50]);
    }

    #[test]
    fn partial_frame_save_offsets_are_not_guessed() {
        // Saved offsets refer to a final frame the truncated stub never creates.
        assert!(translate(&record(8, 0, &[8, 0x42, 3, 0x34, 4, 0]), &layout()).is_none());
        assert!(translate(&record(8, 0, &[8, 0x50, 3, 0x34, 4, 0]), &layout()).is_none());
        assert!(translate(&record(8, 0x25, &[8, 3, 3, 0x34, 4, 0]), &layout()).is_none());
        assert!(translate(&record(8, 0x25, &[8, 0x42, 3, 3]), &layout()).is_none());
    }

    #[test]
    fn unsupported_operations_flags_versions_and_frames_are_refused() {
        for op in [6, 7, 10, 11, 12, 13, 14, 15] {
            assert!(
                translate(&record(8, 0, &[3, op]), &layout()).is_none(),
                "op {op}"
            );
        }
        for flags in [0, 3, 4, 1 | 8, 1 | 16, 1 | 32, 1 | 64] {
            let mut input = record(8, 0, &[]);
            input[0] = flags;
            assert!(translate(&input, &layout()).is_none());
        }
        for frame in [0x10, 1, 4, 0x24] {
            assert!(translate(&record(8, frame, &[]), &layout()).is_none());
        }
        assert!(translate(&record(8, 5, &[]), &layout()).is_none());
        assert!(translate(&record(8, 5, &[3, 0x13]), &layout()).is_none());
        assert!(translate(&record(8, 0, &[3, 3]), &layout()).is_none());
    }

    #[test]
    fn bad_offsets_order_payloads_and_truncation_are_refused_even_if_dropped() {
        for codes in [
            &[2, 0x30][..],         // off a boundary
            &[0, 0x30],             // zero offset
            &[9, 0x30],             // after prologue
            &[1, 0x30, 3, 0x50],    // ascending
            &[3, 0x30, 3, 0x50],    // duplicate
            &[8, 1],                // dropped, truncated alloc large
            &[8, 0x21, 1, 0],       // dropped, invalid opinfo
            &[8, 0x11, 7, 0, 0, 0], // unaligned large allocation
            &[8, 0x01, 0, 0],       // zero allocation
            &[8, 0x45, 8, 0, 0, 0], // save volatile rsp
            &[8, 0x35, 1, 0, 0, 0], // unaligned far save
            &[8, 0x59, 0, 1, 0, 0], // volatile xmm5
            &[8, 0x69, 8, 0, 0, 0], // unaligned xmm save
        ] {
            assert!(
                translate(&record(8, 0, codes), &layout()).is_none(),
                "{codes:02x?}"
            );
        }
        for input in [
            &[][..],
            &[1, 8, 0],
            &[1, 8, 255, 0],
            &[1, 8, 0, 0, 0, 0, 0, 0],
        ] {
            assert!(translate(input, &layout()).is_none());
        }
    }

    #[test]
    fn invalid_maps_and_original_body_are_refused() {
        let input = record(8, 0, &[1, 0x30]);
        let mut map = layout();
        map.new = &[0, 2];
        assert!(translate(&input, &map).is_none());
        map = layout();
        map.old = &[0, 3, 1];
        assert!(translate(&input, &map).is_none());
        map = layout();
        map.new = &[0, 2, 2];
        assert!(translate(&input, &map).is_none());
        map = layout();
        map.end = 51;
        assert!(translate(&input, &map).is_none());
        map = layout();
        map.old = &[];
        map.new = &[];
        assert!(translate(&input, &map).is_none());
        assert!(translate(&record(4, 0, &[]), &layout()).is_none());
    }
}
