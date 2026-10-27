//! A bounded, allocation-free scan of a thread's live stack.

/// Most bytes of one thread's stack a scan reads. A larger span is `Unknown`.
pub const MAX_STACK_SCAN_BYTES: usize = 64 * 1024 * 1024;
/// Words read at a time, into a fixed buffer.
const CHUNK_WORDS: usize = 64;

/// What a stack scan found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scan {
    Clear,
    Hit,
    /// The stack could not be read in full.
    Unknown,
}

/// Scans `[rsp, base)` for a word `want` accepts, `CHUNK_WORDS` at a time, charging
/// the bytes read to `budget`. `read` fills its buffer from an address and fails
/// instead of faulting. A zero or misaligned base, an RSP outside the stack, a span
/// past the per-thread limit or the budget, or a failed read is `Unknown`.
/// Allocation-free; never writes the stack.
pub fn scan_stack(
    rsp: usize,
    base: usize,
    budget: &mut usize,
    mut want: impl FnMut(u64) -> bool,
    mut read: impl FnMut(usize, &mut [u64]) -> bool,
) -> Scan {
    if rsp == 0 || base == 0 || !base.is_multiple_of(8) || rsp > base {
        return Scan::Unknown;
    }
    let mut cursor = rsp & !7;
    let span = base - cursor;
    if span > MAX_STACK_SCAN_BYTES || span > *budget {
        return Scan::Unknown;
    }
    *budget -= span;
    let mut chunk = [0u64; CHUNK_WORDS];
    while cursor < base {
        let words = ((base - cursor) / 8).min(CHUNK_WORDS);
        if !read(cursor, &mut chunk[..words]) {
            return Scan::Unknown;
        }
        if chunk[..words].iter().copied().any(&mut want) {
            return Scan::Hit;
        }
        cursor += words * 8;
    }
    Scan::Clear
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reader(
        rsp: usize,
        words: &[u64],
        fail_at: Option<usize>,
    ) -> impl FnMut(usize, &mut [u64]) -> bool + '_ {
        move |address, out| {
            let end = address + out.len() * 8;
            if fail_at.is_some_and(|at| (address..end).contains(&at)) {
                return false;
            }
            let first = (address - rsp) / 8;
            match words.get(first..first + out.len()) {
                Some(found) => {
                    out.copy_from_slice(found);
                    true
                }
                None => false,
            }
        }
    }

    fn in_slot(word: u64) -> bool {
        (0x7000..0x7040).contains(&word)
    }

    #[test]
    fn finds_a_word_past_the_first_chunk() {
        let rsp = 0x10_0000;
        let mut words = vec![0u64; 3 * CHUNK_WORDS + 5];
        let base = rsp + words.len() * 8;
        let mut budget = usize::MAX;
        assert_eq!(
            scan_stack(rsp, base, &mut budget, in_slot, reader(rsp, &words, None)),
            Scan::Clear
        );
        words[2 * CHUNK_WORDS + 3] = 0x703F;
        assert_eq!(
            scan_stack(rsp, base, &mut budget, in_slot, reader(rsp, &words, None)),
            Scan::Hit
        );
        words[2 * CHUNK_WORDS + 3] = 0x7040;
        assert_eq!(
            scan_stack(rsp, base, &mut budget, in_slot, reader(rsp, &words, None)),
            Scan::Clear
        );
        let last = words.len() - 1;
        words[last] = 0x7001;
        assert_eq!(
            scan_stack(rsp, base, &mut budget, in_slot, reader(rsp, &words, None)),
            Scan::Hit
        );
        assert_eq!(
            scan_stack(
                rsp + 3,
                base,
                &mut budget,
                in_slot,
                reader(rsp, &words, None)
            ),
            Scan::Hit
        );
    }

    #[test]
    fn uncertainty_is_unknown_never_clear() {
        let rsp = 0x10_0000;
        let words = vec![0u64; 2 * CHUNK_WORDS];
        let base = rsp + words.len() * 8;
        let scan = |rsp: usize, base: usize, budget: usize, fail_at: Option<usize>| {
            let mut budget = budget;
            scan_stack(
                rsp,
                base,
                &mut budget,
                in_slot,
                reader(0x10_0000, &words, fail_at),
            )
        };
        assert_eq!(
            scan(rsp, base, usize::MAX, Some(rsp + CHUNK_WORDS * 8)),
            Scan::Unknown
        );
        assert_eq!(scan(0, base, usize::MAX, None), Scan::Unknown);
        assert_eq!(scan(rsp, 0, usize::MAX, None), Scan::Unknown);
        assert_eq!(scan(base + 8, base, usize::MAX, None), Scan::Unknown);
        assert_eq!(scan(rsp, base + 4, usize::MAX, None), Scan::Unknown);
        assert_eq!(scan(rsp, base, words.len() * 8 - 1, None), Scan::Unknown);
        assert_eq!(
            scan(rsp, rsp + MAX_STACK_SCAN_BYTES + 8, usize::MAX, None),
            Scan::Unknown
        );
        assert_eq!(scan(base, base, usize::MAX, None), Scan::Clear);
    }

    #[test]
    fn the_budget_is_charged_and_bounds_the_total() {
        let rsp = 0x10_0000;
        let words = vec![0u64; CHUNK_WORDS];
        let base = rsp + words.len() * 8;
        let mut budget = words.len() * 8 + 4;
        assert_eq!(
            scan_stack(rsp, base, &mut budget, in_slot, reader(rsp, &words, None)),
            Scan::Clear
        );
        assert_eq!(budget, 4);
        // The next thread's span no longer fits.
        assert_eq!(
            scan_stack(rsp, base, &mut budget, in_slot, reader(rsp, &words, None)),
            Scan::Unknown
        );
    }
}
