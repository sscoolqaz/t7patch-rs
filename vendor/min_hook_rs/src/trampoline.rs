//! Trampoline function creation for MinHook-rs
//!
//! The stolen prologue is decoded and relocated with iced-x86 (patch 16 in
//! `VENDORED.md`): [`relocate`] builds the trampoline into an owned buffer and
//! validates it, and only then does [`create_trampoline`] publish it into the slot.

use crate::buffer::{MEMORY_SLOT_SIZE, allocate_buffer, is_executable_address};
use crate::error::{HookError, Result};
use crate::instruction::*;
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, Instruction,
    InstructionBlock, Mnemonic, OpKind, Register,
};
use std::ffi::c_void;
use std::ptr;

/// Maximum size of a trampoline function
const TRAMPOLINE_MAX_SIZE: usize = MEMORY_SLOT_SIZE - size_of::<JmpAbs>();

/// Bytes the hook overwrites at the target (without the hot patch).
const PATCH_LEN: usize = size_of::<JmpRel>();
/// Longest x86 instruction.
const MAX_INSTRUCTION: usize = 15;
/// Bytes of target code a snapshot holds: the last instruction the scan decodes
/// starts at offset 4 or less and is up to 15 bytes long. The decoder fails on an
/// instruction cut off by the end of what was read; it never shortens it.
pub const SNAPSHOT_CODE: usize = PATCH_LEN - 1 + MAX_INSTRUCTION;
/// Entries of the instruction boundary map (`Trampoline::old_ips`).
const MAX_BOUNDARIES: usize = 8;

/// A copy of the target's code taken once, before the trampoline is built. The
/// trampoline is decoded and copied from it, never from live memory, so the hook's
/// backup is exactly what its trampoline was built from even if another writer
/// changes the code meanwhile.
pub struct Snapshot {
    /// The hot-patch bytes `[target - 5, target)`, if they could be read.
    pub above: Option<[u8; size_of::<JmpRel>()]>,
    /// The code from `target` on.
    pub code: [u8; SNAPSHOT_CODE],
    /// How many bytes of `code` could be read.
    pub len: usize,
}

impl Snapshot {
    /// The `len` bytes at `offset`, or `None` past what was read (or for a `len`
    /// field larger than the buffer).
    fn bytes(&self, offset: usize, len: usize) -> Option<&[u8]> {
        self.code
            .get(..self.len)?
            .get(offset..offset.checked_add(len)?)
    }
}

/// How one source instruction is carried into the trampoline.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
enum Kind {
    /// Copied byte for byte.
    #[default]
    Copied,
    /// An external branch out of rel32 reach of the slot, replaced by MinHook's
    /// absolute form (`JmpAbs`, `CallAbs` or `JccAbs`).
    Absolute,
    /// Re-encoded by iced: a relative branch or a RIP-relative operand.
    Relocated,
}

/// One source instruction and what the trampoline must hold for it.
#[derive(Clone, Copy, Default)]
struct Unit {
    kind: Kind,
    /// The instruction as decoded at its real address.
    instruction: Instruction,
    /// For `Copied` and `Absolute`: the exact bytes the unit must encode to.
    bytes: [u8; 16],
    bytes_len: usize,
}

/// A trampoline built and validated in owned memory, not yet published.
struct Built {
    code: [u8; TRAMPOLINE_MAX_SIZE],
    len: usize,
    /// Bytes of target code the trampoline copied or relocated.
    source_len: u8,
    /// Whether it ends in a jump back to `target + source_len`.
    jump_back: bool,
    n_ip: u32,
    old_ips: [u8; MAX_BOUNDARIES],
    new_ips: [u8; MAX_BOUNDARIES],
}

/// The bytes of a packed instruction structure.
fn raw<T: Copy>(value: &T) -> &[u8] {
    // SAFETY: only used with the `#[repr(C, packed)]` plain-byte structures of
    // `instruction.rs`, which have no padding.
    unsafe { std::slice::from_raw_parts(ptr::from_ref(value).cast::<u8>(), size_of::<T>()) }
}

/// Whether a rel32 operand anywhere in a slot starting at `trampoline` reaches
/// `dest`. The next IP lies in `(trampoline, trampoline + MEMORY_SLOT_SIZE]`.
fn in_reach(dest: u64, trampoline: u64) -> bool {
    let distance = i128::from(dest) - i128::from(trampoline);
    let limit = i128::from(i32::MAX) - MEMORY_SLOT_SIZE as i128;
    -limit <= distance && distance <= limit
}

/// Whether the instruction has a relative branch operand.
fn has_near_branch(instruction: &Instruction) -> bool {
    instruction.op_kinds().any(|kind| {
        matches!(
            kind,
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
    })
}

/// MinHook's absolute replacement for an external branch out of rel32 reach.
fn absolute_form(instruction: &Instruction, dest: u64) -> Result<([u8; 16], usize)> {
    let mut bytes = [0u8; 16];
    let mut put = |form: &[u8]| {
        bytes[..form.len()].copy_from_slice(form);
        form.len()
    };
    let len = if instruction.is_call_near() {
        put(raw(&CallAbs::new(dest)))
    } else if instruction.is_jmp_short_or_near() {
        put(raw(&JmpAbs::new(dest)))
    } else {
        // ConditionCode is the x86 condition nibble plus one; None is 0.
        let condition = (instruction.condition_code() as u8)
            .checked_sub(1)
            .filter(|&condition| condition < 16)
            .ok_or(HookError::UnsupportedFunction)?;
        put(raw(&JccAbs::new(condition ^ 1, dest)))
    };
    Ok((bytes, len))
}

/// Builds the trampoline for the code at `target`, to run at `trampoline`, from
/// `snapshot` alone. Pure: allocates no slot and writes no game memory. Every
/// uncertainty refuses the hook with `UnsupportedFunction`.
fn relocate(target: u64, trampoline: u64, snapshot: &Snapshot) -> Result<Built> {
    let unsupported = HookError::UnsupportedFunction;
    let code = snapshot.code.get(..snapshot.len).ok_or(unsupported)?;
    let mut decoder = Decoder::with_ip(64, code, target, DecoderOptions::NONE);
    let mut units = [Unit::default(); MAX_BOUNDARIES];
    let mut count = 0usize;
    let mut old_pos = 0usize;
    // Furthest destination of an internal jump: the scan may not finish before it.
    let mut jmp_dest = 0u64;
    let patch_end = target.checked_add(PATCH_LEN as u64).ok_or(unsupported)?;
    // The whole slot must have addresses, so no offset into it wraps.
    trampoline
        .checked_add(MEMORY_SLOT_SIZE as u64)
        .ok_or(unsupported)?;

    // Decode, mirroring MinHook's rules for where the trampoline ends.
    let jump_back = loop {
        if old_pos >= PATCH_LEN {
            break true;
        }
        if count == MAX_BOUNDARIES || !decoder.can_decode() {
            return Err(unsupported);
        }
        let instruction = decoder.decode();
        // Invalid, or cut off by the end of the snapshot.
        if instruction.is_invalid() {
            return Err(unsupported);
        }
        let len = instruction.len();
        let ip = instruction.ip();
        let mut unit = Unit {
            instruction,
            ..Unit::default()
        };
        let mut finished = false;
        if has_near_branch(&instruction) {
            let jump = instruction.is_jmp_short_or_near();
            // LOOP, JrCXZ, XBEGIN and the like are not relocated.
            if !(jump || instruction.is_call_near() || instruction.is_jcc_short_or_near()) {
                return Err(unsupported);
            }
            let dest = instruction.near_branch_target();
            let internal = (target..patch_end).contains(&dest);
            if internal {
                if !instruction.is_call_near() {
                    jmp_dest = jmp_dest.max(dest);
                }
                unit.kind = Kind::Relocated;
            } else if in_reach(dest, trampoline) {
                unit.kind = Kind::Relocated;
            } else {
                unit.kind = Kind::Absolute;
                (unit.bytes, unit.bytes_len) = absolute_form(&instruction, dest)?;
            }
            if jump && !internal {
                finished = ip >= jmp_dest;
            }
        } else if instruction.is_ip_rel_memory_operand() {
            // An EIP-relative operand is not relocated.
            if instruction.memory_base() != Register::RIP {
                return Err(unsupported);
            }
            unit.kind = Kind::Relocated;
            // jmp [rip + x]: nothing after it runs.
            finished = matches!(instruction.code(), Code::Jmp_rm64 | Code::Jmp_rm16);
        } else {
            unit.bytes[..len].copy_from_slice(&code[old_pos..old_pos + len]);
            unit.bytes_len = len;
            finished = instruction.mnemonic() == Mnemonic::Ret && ip >= jmp_dest;
        }
        units[count] = unit;
        count += 1;
        old_pos += len;
        if finished {
            break false;
        }
    };
    if jump_back && count == MAX_BOUNDARIES {
        return Err(unsupported);
    }
    let source_len = old_pos;
    let units = &units[..count];

    // Before encoding: the bytes the hook overwrites, or that the trampoline copied,
    // must not be reached from the copied code except at an instruction boundary.
    let window_start = target.saturating_sub(PATCH_LEN as u64);
    let window_end = target
        .checked_add(source_len.max(PATCH_LEN) as u64)
        .ok_or(unsupported)?;
    let boundary = |address: u64| {
        units
            .iter()
            .position(|unit| unit.instruction.ip() == address)
    };
    for unit in units {
        let instruction = &unit.instruction;
        if has_near_branch(instruction) {
            let dest = instruction.near_branch_target();
            let above = (window_start..target).contains(&dest);
            if above || ((target..patch_end).contains(&dest) && boundary(dest).is_none()) {
                return Err(unsupported);
            }
        } else if instruction.is_ip_rel_memory_operand() {
            let address = instruction.ip_rel_memory_address();
            if instruction.mnemonic() == Mnemonic::Lea {
                // Only computes the address, but iced would re-target it.
                if (window_start..window_end).contains(&address) {
                    return Err(unsupported);
                }
            } else {
                // A bit test with a register index reaches past the operand by
                // that register: its access has no bound.
                let bit_test = matches!(
                    instruction.mnemonic(),
                    Mnemonic::Bt | Mnemonic::Bts | Mnemonic::Btr | Mnemonic::Btc
                ) && instruction.op1_kind() == OpKind::Register;
                // An FS or GS base is added to the address: not this code's.
                let segment = matches!(instruction.memory_segment(), Register::FS | Register::GS);
                let size = instruction.memory_size().size() as u64;
                let end = address.checked_add(size).ok_or(unsupported)?;
                if bit_test || segment || size == 0 || (address < window_end && end > window_start)
                {
                    return Err(unsupported);
                }
            }
        }
    }

    // Encode. Copied and absolute-form units are declared bytes at their original
    // IP, so iced still re-targets an internal branch to them.
    let mut block = [Instruction::default(); MAX_BOUNDARIES];
    for (slot, unit) in block.iter_mut().zip(units) {
        *slot = if unit.kind == Kind::Relocated {
            unit.instruction
        } else {
            let mut declared = Instruction::with_declare_byte(&unit.bytes[..unit.bytes_len])
                .map_err(|_| unsupported)?;
            declared.set_ip(unit.instruction.ip());
            declared
        };
    }
    let encoded = BlockEncoder::encode(
        64,
        InstructionBlock::new(&block[..count], trampoline),
        BlockEncoderOptions::RETURN_NEW_INSTRUCTION_OFFSETS,
    )
    .map_err(|_| unsupported)?;
    assemble(
        target,
        trampoline,
        units,
        &encoded.code_buffer,
        &encoded.new_instruction_offsets,
        source_len,
        jump_back,
    )
}

/// Validates iced's encoding of `units` (`body`, with each unit's start in
/// `offsets`) against the source instructions, independently of how iced built
/// it, and stages it with the jump back in owned memory. Nothing is published.
fn assemble(
    target: u64,
    trampoline: u64,
    units: &[Unit],
    body: &[u8],
    offsets: &[u32],
    source_len: usize,
    jump_back: bool,
) -> Result<Built> {
    let unsupported = HookError::UnsupportedFunction;
    let count = units.len();
    let boundary = |address: u64| {
        units
            .iter()
            .position(|unit| unit.instruction.ip() == address)
    };
    if count == 0 || count + usize::from(jump_back) > MAX_BOUNDARIES {
        return Err(unsupported);
    }
    let full_len = body.len() + if jump_back { size_of::<JmpAbs>() } else { 0 };
    if offsets.len() != count || full_len > TRAMPOLINE_MAX_SIZE {
        return Err(unsupported);
    }

    // Validate the encoding before anything is published. Offsets start at 0 and
    // strictly increase; u32::MAX would be one of iced's long forms.
    let mut starts = [0usize; MAX_BOUNDARIES];
    for (index, &offset) in offsets.iter().enumerate() {
        let offset = usize::try_from(offset).map_err(|_| unsupported)?;
        let ordered = if index == 0 {
            offset == 0
        } else {
            offset > starts[index - 1]
        };
        if !ordered || offset >= body.len() {
            return Err(unsupported);
        }
        starts[index] = offset;
    }
    for (index, unit) in units.iter().enumerate() {
        let start = starts[index];
        let end = if index + 1 < count {
            starts[index + 1]
        } else {
            body.len()
        };
        let encoded_unit = &body[start..end];
        if unit.kind != Kind::Relocated {
            if encoded_unit != &unit.bytes[..unit.bytes_len] {
                return Err(unsupported);
            }
            continue;
        }
        let address = trampoline + start as u64;
        let decoded = Decoder::with_ip(64, encoded_unit, address, DecoderOptions::NONE).decode();
        if decoded.is_invalid() || decoded.len() != encoded_unit.len() {
            return Err(unsupported);
        }
        let original = &unit.instruction;
        if has_near_branch(original) {
            let dest = original.near_branch_target();
            let expected = boundary(dest).map_or(dest, |j| trampoline + starts[j] as u64);
            if decoded.code().as_near_branch() != original.code().as_near_branch()
                || decoded.near_branch_target() != expected
            {
                return Err(unsupported);
            }
        } else if decoded.memory_base() != Register::RIP || decoded != *original {
            // Same instruction and the same absolute address, RIP-relative.
            return Err(unsupported);
        }
    }

    let mut built = Built {
        code: [0; TRAMPOLINE_MAX_SIZE],
        len: full_len,
        source_len: u8::try_from(source_len).map_err(|_| unsupported)?,
        jump_back,
        n_ip: 0,
        old_ips: [0; MAX_BOUNDARIES],
        new_ips: [0; MAX_BOUNDARIES],
    };
    built.code[..body.len()].copy_from_slice(body);
    for (index, unit) in units.iter().enumerate() {
        let old = unit.instruction.ip() - target;
        built.old_ips[index] = u8::try_from(old).map_err(|_| unsupported)?;
        built.new_ips[index] = u8::try_from(starts[index]).map_err(|_| unsupported)?;
    }
    let mut entries = count;
    if jump_back {
        // The jump back is not a copy: the instruction there runs in place.
        let back = JmpAbs::new(target + source_len as u64);
        built.code[body.len()..full_len].copy_from_slice(raw(&back));
        built.old_ips[count] = built.source_len;
        built.new_ips[count] = u8::try_from(body.len()).map_err(|_| unsupported)?;
        entries += 1;
    }
    built.n_ip = u32::try_from(entries).map_err(|_| unsupported)?;
    Ok(built)
}

/// Create a trampoline function from `snapshot`, the target's code read beforehand.
/// Addresses (relative displacements, the jump back) are still computed from the
/// target's real address. The trampoline is built and validated in owned memory;
/// the slot is written only once every check passed.
pub fn create_trampoline(ct: &mut Trampoline, snapshot: &Snapshot) -> Result<()> {
    ct.patch_above = false;
    ct.n_ip = 0;
    ct.old_ips.fill(0);
    ct.new_ips.fill(0);
    ct.source_len = 0;

    // Allocate trampoline buffer
    ct.trampoline = allocate_buffer(ct.target)?;

    let built = relocate(ct.target as u64, ct.trampoline as u64, snapshot)?;
    let old_pos = usize::from(built.source_len);

    // Check if we have enough space for the hook
    if !built.jump_back && old_pos < size_of::<JmpRel>() {
        let padding_size = size_of::<JmpRel>() - old_pos;
        let padding = snapshot.bytes(old_pos, padding_size);

        // Check if there's padding after the function
        if !padding.is_some_and(is_code_padding) {
            // Check for short jump space
            if old_pos < size_of::<JmpRelShort>() {
                let short_padding_size = size_of::<JmpRelShort>() - old_pos;
                let short = snapshot.bytes(old_pos, short_padding_size);
                if !short.is_some_and(is_code_padding) {
                    return Err(HookError::UnsupportedFunction);
                }
            }

            // Try to use hot patch area above the function
            let hot_patch_addr = (ct.target as usize)
                .checked_sub(size_of::<JmpRel>())
                .ok_or(HookError::UnsupportedFunction)?;
            if !is_executable_address(hot_patch_addr) {
                return Err(HookError::UnsupportedFunction);
            }

            if !snapshot
                .above
                .as_ref()
                .is_some_and(|above| is_code_padding(above))
            {
                return Err(HookError::UnsupportedFunction);
            }

            ct.patch_above = true;
        }
    }

    // Publish: the validated code, then the relay function after it.
    let jmp = JmpAbs::new(ct.detour as u64);
    ct.relay = ((ct.trampoline as usize) + built.len) as *mut c_void;
    // SAFETY: the slot is MEMORY_SLOT_SIZE bytes, freshly allocated and not yet
    // published; `built.len <= TRAMPOLINE_MAX_SIZE` leaves room for the relay.
    unsafe {
        ptr::copy_nonoverlapping(built.code.as_ptr(), ct.trampoline.cast::<u8>(), built.len);
        ptr::copy_nonoverlapping(
            raw(&jmp).as_ptr(),
            ct.relay.cast::<u8>(),
            size_of::<JmpAbs>(),
        );
    }

    ct.source_len = built.source_len;
    ct.n_ip = built.n_ip;
    ct.old_ips = built.old_ips;
    ct.new_ips = built.new_ips;
    Ok(())
}

/// Check if the bytes are all one padding byte (`00`, `90` or `CC`).
fn is_code_padding(bytes: &[u8]) -> bool {
    match bytes.first() {
        None => true,
        Some(&first) => {
            matches!(first, 0x00 | 0x90 | 0xCC) && bytes.iter().all(|&byte| byte == first)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Where the crafted code pretends to live, above 4 GiB.
    const TARGET: u64 = 0x1_4000_0000;
    /// A slot a page above it.
    const NEAR: u64 = TARGET + 0x1000;
    /// A slot 1 GiB below it, the farthest `allocate_buffer` looks.
    const BELOW: u64 = TARGET - 0x4000_0000;
    /// 1.75 GiB past the end of the patch range: rel32 from the target, but not
    /// from `BELOW`.
    const FAR: i32 = 0x7000_0000;

    fn snapshot(bytes: &[u8]) -> Snapshot {
        let mut snapshot = Snapshot {
            above: None,
            code: [0xCC; SNAPSHOT_CODE],
            len: SNAPSHOT_CODE,
        };
        snapshot.code[..bytes.len()].copy_from_slice(bytes);
        snapshot
    }

    fn build(bytes: &[u8], trampoline: u64) -> Result<Built> {
        relocate(TARGET, trampoline, &snapshot(bytes))
    }

    fn refused(bytes: &[u8]) {
        assert_eq!(
            build(bytes, NEAR).err(),
            Some(HookError::UnsupportedFunction),
            "{bytes:02X?}"
        );
    }

    /// The `(old, new)` boundary map.
    fn map(built: &Built) -> Vec<(u8, u8)> {
        (0..built.n_ip as usize)
            .map(|i| (built.old_ips[i], built.new_ips[i]))
            .collect()
    }

    /// Decodes the trampoline's instruction at `offset`, as it will run.
    fn at(built: &Built, trampoline: u64, offset: u8) -> Instruction {
        let offset = usize::from(offset);
        Decoder::with_ip(
            64,
            &built.code[offset..built.len],
            trampoline + offset as u64,
            DecoderOptions::NONE,
        )
        .decode()
    }

    /// Asserts the trampoline ends in `JmpAbs(TARGET + back)` at `offset`.
    fn jumps_back(built: &Built, offset: usize, back: u64) {
        assert!(built.jump_back);
        assert_eq!(built.len, offset + size_of::<JmpAbs>());
        assert_eq!(
            &built.code[offset..built.len],
            raw(&JmpAbs::new(TARGET + back))
        );
    }

    fn rel32(value: i32) -> [u8; 4] {
        value.to_le_bytes()
    }

    #[test]
    fn plain_instructions_are_copied_byte_for_byte() {
        // push rbp; mov rbp, rsp; sub rsp, 0x20.
        let code = [0x55, 0x48, 0x89, 0xE5, 0x48, 0x83, 0xEC, 0x20];
        let built = build(&code, NEAR).unwrap();
        assert_eq!(built.code[..8], code);
        assert_eq!(built.source_len, 8);
        assert_eq!(map(&built), [(0, 0), (1, 1), (4, 4), (8, 8)]);
        jumps_back(&built, 8, 8);
    }

    #[test]
    fn rip_relative_operands_are_rebased() {
        // mov rax, [rip + 0x10]; lea rcx, [rip + 0x100].
        let code = [
            0x48, 0x8B, 0x05, 0x10, 0, 0, 0, 0x48, 0x8D, 0x0D, 0x00, 0x01, 0, 0,
        ];
        for trampoline in [NEAR, BELOW] {
            let built = build(&code[..7], trampoline).unwrap();
            let mov = at(&built, trampoline, 0);
            assert_eq!(mov.code(), Code::Mov_r64_rm64);
            assert_eq!(mov.memory_base(), Register::RIP);
            assert_eq!(mov.ip_rel_memory_address(), TARGET + 7 + 0x10);
            assert_eq!(map(&built), [(0, 0), (7, 7)]);
            jumps_back(&built, 7, 7);
        }
        // Only the first instruction is needed: the jump back follows it.
        assert_eq!(build(&code, NEAR).unwrap().source_len, 7);
        let built = build(&code[7..], BELOW).unwrap();
        let lea = at(&built, BELOW, 0);
        assert_eq!(lea.code(), Code::Lea_r64_m);
        assert_eq!(lea.memory_base(), Register::RIP);
        assert_eq!(lea.ip_rel_memory_address(), TARGET + 7 + 0x100);
        jumps_back(&built, 7, 7);
    }

    #[test]
    fn a_bit_test_with_an_immediate_index_is_relocated() {
        // bt dword [rip + 0x100], 3: reads four bytes at a fixed address.
        let built = build(&[0x0F, 0xBA, 0x25, 0x00, 0x01, 0, 0, 0x03], NEAR).unwrap();
        let bt = at(&built, NEAR, 0);
        assert_eq!(bt.mnemonic(), Mnemonic::Bt);
        assert_eq!(bt.ip_rel_memory_address(), TARGET + 8 + 0x100);
        // A slot whose end would wrap the address space.
        assert_eq!(
            build(&[0x90; 5], u64::MAX - 0x20).err(),
            Some(HookError::UnsupportedFunction)
        );
    }

    #[test]
    fn a_rip_relative_operand_out_of_reach_is_refused() {
        // mov rax, [rip + 0x10] with the slot 3 GiB away: no rel32 reaches it.
        let code = [0x48, 0x8B, 0x05, 0x10, 0, 0, 0];
        assert_eq!(
            build(&code, TARGET + 0xC000_0000).err(),
            Some(HookError::UnsupportedFunction)
        );
        // Below 4 GiB iced would fall back to an EIP-relative operand, which is not
        // the same instruction: refused too.
        let low = 0x1000_0000;
        assert_eq!(
            relocate(low, low + 0xC000_0000, &snapshot(&code)).err(),
            Some(HookError::UnsupportedFunction)
        );
    }

    #[test]
    fn an_external_call_is_retargeted_or_made_absolute() {
        let mut code = [0xE8, 0, 0, 0, 0];
        code[1..].copy_from_slice(&rel32(0x100));
        let built = build(&code, NEAR).unwrap();
        let call = at(&built, NEAR, 0);
        assert_eq!(call.code(), Code::Call_rel32_64);
        assert_eq!(call.near_branch_target(), TARGET + 5 + 0x100);
        assert_eq!(map(&built), [(0, 0), (5, 5)]);
        jumps_back(&built, 5, 5);

        // Out of reach of the slot: MinHook's absolute call.
        code[1..].copy_from_slice(&rel32(FAR));
        let built = build(&code, BELOW).unwrap();
        let dest = TARGET + 5 + FAR.cast_unsigned() as u64;
        assert_eq!(&built.code[..16], raw(&CallAbs::new(dest)));
        assert_eq!(map(&built), [(0, 0), (5, 16)]);
        jumps_back(&built, 16, 5);
    }

    #[test]
    fn an_external_jump_ends_the_trampoline() {
        // jmp +0x10 (rel8), external: nothing after it is copied.
        let built = build(&[0xEB, 0x10], NEAR).unwrap();
        assert!(!built.jump_back);
        assert_eq!(built.source_len, 2);
        assert_eq!(map(&built), [(0, 0)]);
        assert_eq!(at(&built, NEAR, 0).near_branch_target(), TARGET + 0x12);

        // jmp rel32 out of reach of the slot: MinHook's absolute jump.
        let mut code = [0xE9, 0, 0, 0, 0];
        code[1..].copy_from_slice(&rel32(FAR));
        let built = build(&code, BELOW).unwrap();
        let dest = TARGET + 5 + FAR.cast_unsigned() as u64;
        assert!(!built.jump_back);
        assert_eq!(built.len, 14);
        assert_eq!(&built.code[..14], raw(&JmpAbs::new(dest)));
    }

    #[test]
    fn an_internal_jump_lands_on_the_relocated_boundary() {
        // jmp +1 (internal, to the nop's successor); nop; jmp rel32 (external).
        let mut code = [0xEB, 0x01, 0x90, 0xE9, 0, 0, 0, 0];
        code[4..].copy_from_slice(&rel32(0x200));
        let built = build(&code, NEAR).unwrap();
        assert!(!built.jump_back);
        assert_eq!(built.source_len, 8);
        let entries = map(&built);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[..2], [(0, 0), (2, 2)]);
        let (old, new) = entries[2];
        assert_eq!(old, 3);
        assert_eq!(
            at(&built, NEAR, 0).near_branch_target(),
            NEAR + u64::from(new)
        );
        assert_eq!(
            at(&built, NEAR, new).near_branch_target(),
            TARGET + 8 + 0x200
        );
    }

    #[test]
    fn conditional_jumps_are_relocated() {
        // je +0x10; three nops.
        let built = build(&[0x74, 0x10, 0x90, 0x90, 0x90], NEAR).unwrap();
        let je = at(&built, NEAR, 0);
        assert_eq!(je.code().as_near_branch(), Code::Je_rel32_64);
        assert_eq!(je.near_branch_target(), TARGET + 0x12);
        let (_, after) = map(&built)[1];
        assert_eq!(built.code[usize::from(after)..][..3], [0x90; 3]);
        jumps_back(&built, usize::from(after) + 3, 5);

        // jne rel32 (0F 85).
        let mut code = [0x0F, 0x85, 0, 0, 0, 0];
        code[2..].copy_from_slice(&rel32(0x300));
        let built = build(&code, NEAR).unwrap();
        let jne = at(&built, NEAR, 0);
        assert_eq!(jne.code(), Code::Jne_rel32_64);
        assert_eq!(jne.near_branch_target(), TARGET + 6 + 0x300);
        jumps_back(&built, 6, 6);

        // Out of reach of the slot: MinHook's inverted short jcc over an absolute
        // jump.
        code[2..].copy_from_slice(&rel32(FAR));
        let built = build(&code, BELOW).unwrap();
        let dest = TARGET + 6 + FAR.cast_unsigned() as u64;
        assert_eq!(&built.code[..16], raw(&JccAbs::new(0x5 ^ 1, dest)));
        assert_eq!(built.code[0], 0x74);
        jumps_back(&built, 16, 6);
    }

    #[test]
    fn an_internal_jcc_to_copied_bytes_is_retargeted() {
        // je +1 (to the third nop); four nops. The nops are declared bytes, which
        // iced still indexes by their original IP.
        let built = build(&[0x74, 0x01, 0x90, 0x90, 0x90, 0x90], NEAR).unwrap();
        let entries = map(&built);
        assert_eq!(
            entries[..4].iter().map(|e| e.0).collect::<Vec<_>>(),
            [0, 2, 3, 4]
        );
        let (_, third) = entries[2];
        assert_eq!(
            at(&built, NEAR, 0).near_branch_target(),
            NEAR + u64::from(third)
        );
        assert_eq!(built.source_len, 5);
    }

    #[test]
    fn ret_ends_the_trampoline_once_past_internal_jumps() {
        for (code, len) in [(&[0xC3][..], 1u8), (&[0xC2, 0x08, 0x00][..], 3)] {
            let built = build(code, NEAR).unwrap();
            assert!(!built.jump_back);
            assert_eq!(built.source_len, len);
            assert_eq!(built.code[..usize::from(len)], *code);
        }
        // je +2 skips the ret, so the scan goes on past it.
        let built = build(&[0x74, 0x02, 0xC3, 0x90, 0x90], NEAR).unwrap();
        assert_eq!(built.source_len, 5);
        assert!(built.jump_back);
    }

    #[test]
    fn indirect_jumps_end_only_when_rip_relative() {
        // jmp [rip + 0].
        let built = build(&[0xFF, 0x25, 0, 0, 0, 0], NEAR).unwrap();
        assert!(!built.jump_back);
        assert_eq!(built.source_len, 6);
        assert_eq!(at(&built, NEAR, 0).ip_rel_memory_address(), TARGET + 6);
        // jmp rax is copied and the scan goes on, as upstream does.
        let built = build(&[0xFF, 0xE0, 0x90, 0x90, 0x90], NEAR).unwrap();
        assert_eq!(built.code[..5], [0xFF, 0xE0, 0x90, 0x90, 0x90]);
        jumps_back(&built, 5, 5);
    }

    #[test]
    fn a_snapshot_that_cuts_an_instruction_off_is_refused() {
        // mov eax, imm32 with only three of its five bytes read.
        let mut short = snapshot(&[0xB8, 0x11, 0x22, 0x33, 0x44]);
        short.len = 3;
        assert_eq!(
            relocate(TARGET, NEAR, &short).err(),
            Some(HookError::UnsupportedFunction)
        );
        // Five one-byte nops need only five bytes.
        let mut nops = snapshot(&[0x90; 5]);
        nops.len = 5;
        assert!(relocate(TARGET, NEAR, &nops).is_ok());
        // An undecodable byte.
        refused(&[0x06]);
    }

    #[test]
    fn branches_into_overwritten_or_split_bytes_are_refused() {
        // jmp +2, into the middle of the mov after it.
        refused(&[0xEB, 0x02, 0xB8, 0x11, 0x22, 0x33, 0x44]);
        // jmp -7, into the hot-patch bytes above the target.
        refused(&[0xEB, 0xF9]);
        // call -1: into its own last byte, not a boundary.
        refused(&[0xE8, 0xFF, 0xFF, 0xFF, 0xFF]);
    }

    #[test]
    fn rip_relative_access_to_the_patched_bytes_is_refused() {
        // mov rax, [rip - 13]: reads target - 6 .. target + 2.
        refused(&[0x48, 0x8B, 0x05, 0xF3, 0xFF, 0xFF, 0xFF]);
        // lea rax, [rip - 7]: the target itself.
        refused(&[0x48, 0x8D, 0x05, 0xF9, 0xFF, 0xFF, 0xFF]);
        // bt [rip + 0x100], rax: rax moves the access anywhere, the target too.
        refused(&[0x48, 0x0F, 0xA3, 0x05, 0x00, 0x01, 0, 0]);
        // mov rax, gs:[rip + 0x100] and fs:[...]: the segment base moves it.
        refused(&[0x65, 0x48, 0x8B, 0x05, 0x00, 0x01, 0, 0]);
        refused(&[0x64, 0x48, 0x8B, 0x05, 0x00, 0x01, 0, 0]);
        // xsave [rip + 0x100]: no fixed size.
        refused(&[0x0F, 0xAE, 0x25, 0x00, 0x01, 0, 0]);
        // An EIP-relative operand.
        refused(&[0x67, 0x8B, 0x05, 0x00, 0x01, 0, 0]);
    }

    #[test]
    fn loops_jrcxz_and_xbegin_are_refused() {
        refused(&[0xE2, 0x10]); // loop
        refused(&[0xE1, 0x10]); // loope
        refused(&[0xE3, 0x10]); // jrcxz
        refused(&[0x67, 0xE3, 0x10]); // jecxz
        refused(&[0xC7, 0xF8, 0x00, 0x01, 0, 0]); // xbegin
    }

    #[test]
    fn the_largest_layouts_fit_the_map_and_the_slot() {
        // Five one-byte instructions and the jump back: six of the eight entries.
        let built = build(&[0x90; 5], NEAR).unwrap();
        assert_eq!(built.n_ip, 6);
        // Four nops and a 15-byte instruction: 19 bytes and the jump back.
        let mut code = [0x90u8; 19];
        code[4..].copy_from_slice(&[
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x2E, 0x0F, 0x1F, 0x84, 0, 0, 0, 0, 0,
        ]);
        let built = build(&code, NEAR).unwrap();
        assert_eq!(built.code[..19], code);
        assert_eq!(built.source_len, 19);
        jumps_back(&built, 19, 19);
    }

    /// The units `relocate` builds for five nops, for feeding `assemble` directly.
    fn nop_units() -> Vec<Unit> {
        let mut decoder = Decoder::with_ip(64, &[0x90; 5], TARGET, DecoderOptions::NONE);
        (0..5)
            .map(|_| {
                let mut unit = Unit {
                    instruction: decoder.decode(),
                    ..Unit::default()
                };
                unit.bytes[0] = 0x90;
                unit.bytes_len = 1;
                unit
            })
            .collect()
    }

    #[test]
    fn an_inconsistent_encoding_is_refused() {
        let units = nop_units();
        let check = |units: &[Unit], body: &[u8], offsets: &[u32], jump_back| {
            assemble(TARGET, NEAR, units, body, offsets, 5, jump_back).err()
        };
        let unsupported = Some(HookError::UnsupportedFunction);
        let body = [0x90; 5];
        let offsets = [0, 1, 2, 3, 4];
        assert_eq!(check(&units, &body, &offsets, true), None);
        // One of iced's long forms reports no offset.
        assert_eq!(
            check(&units, &body, &[0, 1, u32::MAX, 3, 4], true),
            unsupported
        );
        // Out of order, not starting at 0, past the end, or missing.
        assert_eq!(check(&units, &body, &[0, 2, 1, 3, 4], true), unsupported);
        assert_eq!(check(&units, &body, &[1, 2, 3, 4, 5], true), unsupported);
        assert_eq!(check(&units, &body, &[0, 1, 2, 3, 5], true), unsupported);
        assert_eq!(check(&units, &body, &[0, 1, 2, 3], true), unsupported);
        // A copied unit whose bytes changed.
        let changed = [0x90, 0x90, 0xCC, 0x90, 0x90];
        assert_eq!(check(&units, &changed, &offsets, true), unsupported);
        // One byte more than the slot leaves room for, with the jump back.
        let big = [0x90; TRAMPOLINE_MAX_SIZE - size_of::<JmpAbs>() + 1];
        assert_eq!(check(&units, &big, &offsets, true), unsupported);
        // No units, or more than the map holds with the jump back.
        assert_eq!(check(&[], &[], &[], false), unsupported);
        let eight = [units[0]; MAX_BOUNDARIES];
        let eight_offsets = [0, 1, 2, 3, 4, 5, 6, 7];
        assert_eq!(check(&eight, &[0x90; 8], &eight_offsets, true), unsupported);
    }
}
