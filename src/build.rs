//! Game build detection and RVA translation.
//!
//! Port of `GameBuild.h`. The September 2026 build removed `0x6C0` bytes from
//! the later part of the primary code section, so February-era RVAs must be
//! shifted before they are used on the September executable.

use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::SystemInformation::IMAGE_FILE_MACHINE_AMD64;
use windows::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE,
};

pub const FEBRUARY_2026_TIMESTAMP: u32 = 0x693D_731E;
pub const FEBRUARY_2026_RETAIL_IMAGE_SIZE: u32 = 0x1D74_AC00;
pub const FEBRUARY_2026_DUMP_IMAGE_SIZE: u32 = 0x1D74_B000;
pub const SEPTEMBER_2026_TIMESTAMP: u32 = 0x6A7B_6355;
pub const SEPTEMBER_2026_RETAIL_IMAGE_SIZE: u32 = 0x1D75_BC00;
pub const SEPTEMBER_2026_DUMP_IMAGE_SIZE: u32 = 0x1D75_C000;

pub const SEPTEMBER_SHIFT_START_RVA: usize = 0x1D29C20;
pub const PRIMARY_CODE_END_RVA: usize = 0x2EFF000;
pub const SEPTEMBER_CODE_DELTA: usize = 0x6C0;

/// The executable build this DLL was loaded into.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Build {
    Unknown,
    February2026,
    September2026,
}

/// Classifies a build from the PE timestamp and image size.
///
/// IDA's reconstructed memory images round `SizeOfImage` to the next page, while
/// the retail executable keeps its 0x200 alignment. Both fingerprints are
/// accepted because the timestamp and RVA layout are identical.
pub const fn classify(timestamp: u32, image_size: u32) -> Build {
    if timestamp == SEPTEMBER_2026_TIMESTAMP
        && (image_size == SEPTEMBER_2026_RETAIL_IMAGE_SIZE
            || image_size == SEPTEMBER_2026_DUMP_IMAGE_SIZE)
    {
        Build::September2026
    } else if timestamp == FEBRUARY_2026_TIMESTAMP
        && (image_size == FEBRUARY_2026_RETAIL_IMAGE_SIZE
            || image_size == FEBRUARY_2026_DUMP_IMAGE_SIZE)
    {
        Build::February2026
    } else {
        Build::Unknown
    }
}

/// Reads the loaded executable's PE headers and classifies it.
///
/// # Safety
///
/// Must be called from inside the game process, where the main module's PE
/// headers are mapped and readable.
pub unsafe fn detect_build() -> Build {
    // SAFETY: a null module name asks for the calling process's executable; no pointers are passed.
    let Ok(module) = (unsafe { GetModuleHandleW(None) }) else {
        return Build::Unknown;
    };
    let base = module.0 as usize;
    if base == 0 {
        return Build::Unknown;
    }

    // SAFETY: the caller guarantees the main module is mapped, so the DOS header is readable.
    let dos = unsafe { &*(base as *const IMAGE_DOS_HEADER) };
    if dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew <= 0 {
        return Build::Unknown;
    }

    // SAFETY: `e_lfanew` points inside the mapped image, as checked above.
    let nt_offset = usize::try_from(dos.e_lfanew).unwrap_or_default();
    // SAFETY: `e_lfanew` is a positive offset inside the mapped image, checked above.
    let nt = unsafe { &*((base + nt_offset) as *const IMAGE_NT_HEADERS64) };
    if nt.Signature != IMAGE_NT_SIGNATURE || nt.FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64 {
        return Build::Unknown;
    }

    classify(nt.FileHeader.TimeDateStamp, nt.OptionalHeader.SizeOfImage)
}

/// Maps a February-2026 RVA to the RVA that exists in `build`.
pub const fn live_rva(february_rva: usize, build: Build) -> usize {
    if matches!(build, Build::September2026)
        && february_rva >= SEPTEMBER_SHIFT_START_RVA
        && february_rva < PRIMARY_CODE_END_RVA
    {
        february_rva - SEPTEMBER_CODE_DELTA
    } else {
        february_rva
    }
}

/// Maps a live RVA in `build` back to its February-2026 equivalent.
pub const fn february_rva(live_rva: usize, build: Build) -> usize {
    if matches!(build, Build::September2026)
        && live_rva >= SEPTEMBER_SHIFT_START_RVA
        && live_rva < PRIMARY_CODE_END_RVA
    {
        live_rva + SEPTEMBER_CODE_DELTA
    } else {
        live_rva
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_both_fingerprints_of_each_build() {
        assert_eq!(
            classify(SEPTEMBER_2026_TIMESTAMP, SEPTEMBER_2026_RETAIL_IMAGE_SIZE),
            Build::September2026
        );
        assert_eq!(
            classify(SEPTEMBER_2026_TIMESTAMP, SEPTEMBER_2026_DUMP_IMAGE_SIZE),
            Build::September2026
        );
        assert_eq!(
            classify(FEBRUARY_2026_TIMESTAMP, FEBRUARY_2026_RETAIL_IMAGE_SIZE),
            Build::February2026
        );
        assert_eq!(
            classify(FEBRUARY_2026_TIMESTAMP, FEBRUARY_2026_DUMP_IMAGE_SIZE),
            Build::February2026
        );
    }

    #[test]
    fn rejects_mismatched_timestamp_or_size() {
        assert_eq!(
            classify(SEPTEMBER_2026_TIMESTAMP, FEBRUARY_2026_RETAIL_IMAGE_SIZE),
            Build::Unknown
        );
        assert_eq!(classify(0, 0), Build::Unknown);
    }

    #[test]
    fn shifts_september_rvas_inside_the_code_section() {
        assert_eq!(live_rva(0x1DECFD0, Build::September2026), 0x1DEC910);
        assert_eq!(live_rva(0x226B0A0, Build::September2026), 0x226A9E0);
        assert_eq!(live_rva(0x1686E948, Build::September2026), 0x1686E948);
        assert_eq!(live_rva(0x1DECFD0, Build::February2026), 0x1DECFD0);
    }

    #[test]
    fn round_trips_through_both_directions() {
        for rva in [0x1DECFD0, 0x226B0A0] {
            assert_eq!(
                february_rva(live_rva(rva, Build::September2026), Build::September2026),
                rva
            );
        }
    }
}
