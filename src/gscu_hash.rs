//! Name hashes used by the GSC linker and notification tables.
//!
//! Port of `gscu_hashing.cpp` and the `const_canon_hash` / `const_notify_hash`
//! helpers in `gscu_hashing.h`. The 32-bit canon hash and the 64-bit notify
//! hash must match the game byte-for-byte, so every arithmetic step wraps.

const CANON_SEED: u32 = 0x4B9A_CE2F;
const CANON_MULTIPLIER: u32 = 0x8001;

const NOTIFY_OFFSET: u64 = 14_695_981_039_346_656_037;
const NOTIFY_PRIME: u64 = 1_099_511_628_211;

/// Lowercases an ASCII byte the same way the C runtime `tolower` does.
const fn to_lower(byte: u8) -> u8 {
    byte.to_ascii_lowercase()
}

/// Canonical 32-bit hash of a GSC name, case-insensitive.
///
/// The C++ source feeds `char` (signed on MSVC) into the arithmetic, so bytes
/// at or above 0x80 are sign-extended before mixing. That is reproduced here.
#[must_use]
pub fn canon_hash(input: &[u8]) -> u32 {
    let mut hash = CANON_SEED;
    for &byte in input {
        let lower = to_lower(byte);
        let c = i32::from(lower.cast_signed()).cast_unsigned();
        let mixed = c.wrapping_add(hash);
        let mixed = mixed ^ mixed.wrapping_shl(10);
        hash = mixed.wrapping_add(mixed >> 6);
    }
    CANON_MULTIPLIER.wrapping_mul((hash.wrapping_mul(9)) ^ (hash.wrapping_mul(9) >> 11))
}

/// Case-insensitive 64-bit FNV-1a notification hash. The top bit is cleared.
///
/// The C++ `char` is signed, so bytes at or above 0x80 are sign-extended before
/// the XOR. This matches `canon_hash64` in `Protection.cpp`.
#[must_use]
pub fn notify_hash(input: &[u8]) -> u64 {
    let hash = input.iter().fold(NOTIFY_OFFSET, |hash, &byte| {
        let widened = i64::from(to_lower(byte).cast_signed()).cast_unsigned();
        (hash ^ widened).wrapping_mul(NOTIFY_PRIME)
    });
    0x7FFF_FFFF_FFFF_FFFF & hash
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canon_hash_is_case_insensitive() {
        assert_eq!(canon_hash(b"Maps/Mp/Test"), canon_hash(b"maps/mp/test"));
    }

    #[test]
    fn canon_hash_of_empty_input_is_seed_derived() {
        let mixed = CANON_SEED.wrapping_mul(9);
        let expected = CANON_MULTIPLIER.wrapping_mul(mixed ^ (mixed >> 11));
        assert_eq!(canon_hash(b""), expected);
    }

    #[test]
    fn notify_hash_clears_top_bit() {
        assert_eq!(notify_hash(b"anything") >> 63, 0);
    }

    #[test]
    fn notify_hash_is_case_insensitive() {
        assert_eq!(notify_hash(b"ZBR_Notify"), notify_hash(b"zbr_notify"));
    }

    #[test]
    fn notify_hash_sign_extends_high_bytes_like_the_game() {
        let expected =
            (NOTIFY_OFFSET ^ u64::MAX).wrapping_mul(NOTIFY_PRIME) & 0x7FFF_FFFF_FFFF_FFFF;
        assert_eq!(notify_hash(&[0xFF]), expected);
    }

    #[test]
    fn notify_hash_of_empty_input_is_offset_basis() {
        assert_eq!(notify_hash(b""), NOTIFY_OFFSET & 0x7FFF_FFFF_FFFF_FFFF);
    }
}
