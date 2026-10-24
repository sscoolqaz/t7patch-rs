//! 32-bit FNV-1a variant used by the game's script tables.
//!
//! Port of `fnv1a` and `fnv1a_const` in `framework.h`. The game applies one
//! extra multiply after the loop ("bo3 wtf lol" in the original), so this is
//! not the textbook FNV-1a.

const OFFSET_BASIS: u32 = 0x4B9A_CE2F;
const PRIME: u32 = 0x0100_0193;

/// Hashes a NUL-free byte string with the game's FNV-1a variant (`fnv1a`).
#[must_use]
pub fn hash(input: &[u8]) -> u32 {
    let mut hash = OFFSET_BASIS;
    let mut index = 0;
    while index < input.len() {
        // The C++ `char` is signed, so bytes are sign-extended before the XOR.
        hash ^= i32::from(input[index].cast_signed()).cast_unsigned();
        hash = hash.wrapping_mul(PRIME);
        index += 1;
    }
    hash.wrapping_mul(PRIME)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_input_applies_single_trailing_multiply() {
        assert_eq!(hash(b""), OFFSET_BASIS.wrapping_mul(PRIME));
    }
}
