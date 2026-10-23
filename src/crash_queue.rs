//! Fixed-capacity queue for one fatal crash session.
//!
//! Port of the C++ fork's `CrashQueue.h` (Scroptss/T7Patch-src fork, commit `93e515c`).
//! Admission and closure share one atomic word: a producer reserves a slot before it
//! looks for the dump owner, and sealing fails if any reservation arrived after the
//! owner's last drain. Nothing reopens a session once it is sealed. The queue neither
//! allocates nor locks, so it is safe to use inside the exception dispatcher.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// High bit of the admission word: set once the session is sealed.
const CLOSED: u32 = 0x8000_0000;

struct Slot<T> {
    record: UnsafeCell<MaybeUninit<T>>,
    ready: AtomicBool,
}

impl<T> Slot<T> {
    const fn new() -> Self {
        Self {
            record: UnsafeCell::new(MaybeUninit::uninit()),
            ready: AtomicBool::new(false),
        }
    }
}

/// A queue of at most `N` records, each written once by the producer that reserved it.
pub struct CrashQueue<T: Copy, const N: usize> {
    slots: [Slot<T>; N],
    /// Number of reserved slots, plus [`CLOSED`] once sealed.
    admission: AtomicU32,
}

// SAFETY: a slot's record is written only by the one producer that reserved its index
// (`reserve` hands each index out once, and indices never return), before that producer
// sets `ready` with release ordering. Readers access the record only after observing
// `ready` with acquire ordering, and nobody writes it again. `T: Copy` means records hold
// no drop glue or interior references, so sharing copies across threads is sound when
// `T: Send`.
unsafe impl<T: Copy + Send, const N: usize> Sync for CrashQueue<T, N> {}

impl<T: Copy, const N: usize> CrashQueue<T, N> {
    const CAPACITY_FITS: () = assert!(N > 0 && N < CLOSED as usize);

    /// An empty, open queue. Usable in a `static`.
    pub const fn new() -> Self {
        let () = Self::CAPACITY_FITS;
        Self {
            slots: [const { Slot::new() }; N],
            admission: AtomicU32::new(0),
        }
    }

    /// Reserves the next slot, or `None` when the queue is full or sealed.
    pub fn reserve(&self) -> Option<usize> {
        let mut state = self.admission.load(Ordering::Acquire);
        loop {
            if state & CLOSED != 0 || state as usize >= N {
                return None;
            }
            match self.admission.compare_exchange_weak(
                state,
                state + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(state as usize),
                Err(current) => state = current,
            }
        }
    }

    /// Writes `record` into `slot` and marks it ready.
    ///
    /// `slot` must come from [`reserve`](Self::reserve) on this queue and be published
    /// once. An index out of range is ignored.
    pub fn publish(&self, slot: usize, record: T) {
        let Some(entry) = self.slots.get(slot) else {
            return;
        };
        if entry.ready.load(Ordering::Acquire) {
            return;
        }
        // SAFETY: the caller reserved `slot`, so no other thread writes it, and no reader
        // touches it until `ready` is set below.
        unsafe { (*entry.record.get()).write(record) };
        entry.ready.store(true, Ordering::Release);
    }

    /// A copy of the record in `slot`, or `None` if it has not been published.
    pub fn published(&self, slot: usize) -> Option<T> {
        let entry = self.slots.get(slot)?;
        if !entry.ready.load(Ordering::Acquire) {
            return None;
        }
        // SAFETY: `ready` was set with release ordering after the record was written, and
        // the record is never written again.
        Some(unsafe { (*entry.record.get()).assume_init() })
    }

    /// Number of reserved slots, ignoring the sealed bit.
    pub fn count(&self) -> usize {
        (self.admission.load(Ordering::Acquire) & !CLOSED) as usize
    }

    /// Seals the queue if exactly `consumed` slots were ever reserved. Returns `false`
    /// when a reservation arrived after the drain, so the caller must drain again.
    pub fn seal_if_drained(&self, consumed: usize) -> bool {
        let Ok(expected) = u32::try_from(consumed) else {
            return false;
        };
        if expected & CLOSED != 0 {
            return false;
        }
        self.admission
            .compare_exchange(
                expected,
                expected | CLOSED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
    }
}

impl<T: Copy, const N: usize> Default for CrashQueue<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    static STATIC_QUEUE: CrashQueue<u64, 4> = CrashQueue::new();

    #[test]
    fn reserves_up_to_capacity() {
        let queue: CrashQueue<u32, 3> = CrashQueue::new();
        assert_eq!(queue.reserve(), Some(0));
        assert_eq!(queue.reserve(), Some(1));
        assert_eq!(queue.reserve(), Some(2));
        assert_eq!(queue.reserve(), None);
        assert_eq!(queue.count(), 3);
    }

    #[test]
    fn publish_round_trips() {
        let queue: CrashQueue<(i64, u32), 2> = CrashQueue::new();
        let slot = queue.reserve().unwrap();
        assert_eq!(queue.published(slot), None);
        queue.publish(slot, (-5, 0xC000_0005));
        assert_eq!(queue.published(slot), Some((-5, 0xC000_0005)));
        assert_eq!(queue.published(1), None);
        assert_eq!(queue.published(7), None);
    }

    #[test]
    fn seals_when_drained() {
        let queue: CrashQueue<u8, 4> = CrashQueue::new();
        queue.reserve();
        queue.reserve();
        assert!(queue.seal_if_drained(2));
        assert_eq!(queue.reserve(), None);
        assert_eq!(queue.count(), 2);
    }

    #[test]
    fn seal_fails_after_late_reservation() {
        let queue: CrashQueue<u8, 4> = CrashQueue::new();
        queue.reserve();
        let drained = queue.count();
        assert_eq!(queue.reserve(), Some(1));
        assert!(!queue.seal_if_drained(drained));
        assert!(queue.seal_if_drained(queue.count()));
        assert_eq!(queue.reserve(), None);
    }

    #[test]
    fn seal_rejects_values_with_closed_bit() {
        let queue: CrashQueue<u8, 4> = CrashQueue::new();
        assert!(!queue.seal_if_drained(CLOSED as usize));
        assert!(!queue.seal_if_drained(usize::MAX));
        assert!(queue.seal_if_drained(0));
        assert!(!queue.seal_if_drained(0));
    }

    #[test]
    fn works_as_static() {
        let slot = STATIC_QUEUE.reserve().unwrap();
        STATIC_QUEUE.publish(slot, 0xDEAD_BEEF);
        assert_eq!(STATIC_QUEUE.published(slot), Some(0xDEAD_BEEF));
    }
}
