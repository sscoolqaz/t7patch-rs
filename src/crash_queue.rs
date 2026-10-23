//! Fixed-capacity queue for one fatal crash session.
//!
//! Port of the C++ fork's `CrashQueue.h` (Scroptss/T7Patch-src fork, commit `93e515c`).
//! Admission and closure share one atomic word: a producer reserves a slot before it
//! looks for the dump owner, and sealing fails if any reservation arrived after the
//! owner's last drain. Nothing reopens a session once it is sealed. The queue neither
//! allocates nor locks, so it is safe to use inside the exception dispatcher.
//!
//! A reservation is a [`Reservation`] token, not an index. It cannot be copied,
//! so a slot is published at most once and only by the thread that reserved it.
//! A token dropped without publishing marks its slot abandoned, and the owner's
//! drain skips it instead of waiting.

use std::cell::UnsafeCell;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicU8, AtomicU32, Ordering};

/// High bit of the admission word: set once the session is sealed.
const CLOSED: u32 = 0x8000_0000;

/// Slot states. A slot leaves `EMPTY` exactly once, to `READY` or `ABANDONED`.
const EMPTY: u8 = 0;
const READY: u8 = 1;
const ABANDONED: u8 = 2;

struct Slot<T> {
    record: UnsafeCell<MaybeUninit<T>>,
    state: AtomicU8,
}

impl<T> Slot<T> {
    const fn new() -> Self {
        Self {
            record: UnsafeCell::new(MaybeUninit::uninit()),
            state: AtomicU8::new(EMPTY),
        }
    }
}

/// What the owner sees in a reserved slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotState<T> {
    /// Reserved, not yet published.
    Pending,
    Ready(T),
    /// The reserving thread dropped its token without publishing.
    Abandoned,
}

/// The right to publish one slot. Neither `Clone` nor `Copy`; consumed by
/// [`CrashQueue::publish`].
///
/// ```compile_fail
/// use t7patch::crash_queue::CrashQueue;
/// let queue: CrashQueue<u8, 2> = CrashQueue::new();
/// let token = queue.reserve().unwrap();
/// queue.publish(token, 1);
/// queue.publish(token, 2); // use of moved value
/// ```
#[must_use = "dropping a reservation abandons its slot"]
pub struct Reservation<'q, T: Copy, const N: usize> {
    queue: &'q CrashQueue<T, N>,
    slot: usize,
}

impl<T: Copy, const N: usize> Reservation<'_, T, N> {
    /// The reserved slot index.
    pub fn slot(&self) -> usize {
        self.slot
    }
}

impl<T: Copy, const N: usize> Drop for Reservation<'_, T, N> {
    fn drop(&mut self) {
        // `publish` forgets the token, so reaching here means it was never published.
        self.queue.slots[self.slot]
            .state
            .store(ABANDONED, Ordering::Release);
    }
}

/// A queue of at most `N` records, each written once by the producer that reserved it.
pub struct CrashQueue<T: Copy, const N: usize> {
    slots: [Slot<T>; N],
    /// Number of reserved slots, plus [`CLOSED`] once sealed.
    admission: AtomicU32,
}

// SAFETY: a slot's record is written only through the one `Reservation` for its index
// (`reserve` hands each index out once, indices never return, and the token is neither
// `Clone` nor `Copy`), before the state is set to READY with release ordering. Readers
// access the record only after observing READY with acquire ordering, and nobody writes
// it again. `T: Copy` means records hold
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
    pub fn reserve(&self) -> Option<Reservation<'_, T, N>> {
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
                Ok(_) => {
                    return Some(Reservation {
                        queue: self,
                        slot: state as usize,
                    });
                }
                Err(current) => state = current,
            }
        }
    }

    /// Writes `record` into the reserved slot and marks it ready.
    ///
    /// # Panics
    ///
    /// If `reservation` came from a different queue.
    pub fn publish(&self, reservation: Reservation<'_, T, N>, record: T) {
        assert!(
            std::ptr::eq(reservation.queue, self),
            "reservation from another queue"
        );
        let entry = &self.slots[reservation.slot];
        std::mem::forget(reservation);
        // SAFETY: the token was the only right to write this slot and it is consumed
        // above, so no other thread writes it, and no reader touches it until READY.
        unsafe { (*entry.record.get()).write(record) };
        entry.state.store(READY, Ordering::Release);
    }

    /// The state of `slot`. Out-of-range or unreserved slots read as `Pending`.
    pub fn slot_state(&self, slot: usize) -> SlotState<T> {
        let Some(entry) = self.slots.get(slot) else {
            return SlotState::Pending;
        };
        match entry.state.load(Ordering::Acquire) {
            READY => {
                // SAFETY: READY was stored with release ordering after the record was
                // written, and the record is never written again.
                SlotState::Ready(unsafe { (*entry.record.get()).assume_init() })
            }
            ABANDONED => SlotState::Abandoned,
            _ => SlotState::Pending,
        }
    }

    /// A copy of the record in `slot`, or `None` if it has not been published.
    pub fn published(&self, slot: usize) -> Option<T> {
        match self.slot_state(slot) {
            SlotState::Ready(record) => Some(record),
            SlotState::Pending | SlotState::Abandoned => None,
        }
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

    fn slots<T: Copy, const N: usize>(
        reservations: &[Option<Reservation<'_, T, N>>],
    ) -> Vec<Option<usize>> {
        reservations
            .iter()
            .map(|r| r.as_ref().map(Reservation::slot))
            .collect()
    }

    #[test]
    fn reserves_up_to_capacity() {
        let queue: CrashQueue<u32, 3> = CrashQueue::new();
        let held: Vec<_> = (0..4).map(|_| queue.reserve()).collect();
        assert_eq!(slots(&held), [Some(0), Some(1), Some(2), None]);
        assert_eq!(queue.count(), 3);
    }

    #[test]
    fn publish_round_trips() {
        let queue: CrashQueue<(i64, u32), 2> = CrashQueue::new();
        let token = queue.reserve().unwrap();
        let slot = token.slot();
        assert_eq!(queue.slot_state(slot), SlotState::Pending);
        queue.publish(token, (-5, 0xC000_0005));
        assert_eq!(queue.published(slot), Some((-5, 0xC000_0005)));
        assert_eq!(queue.published(1), None);
        assert_eq!(queue.published(7), None);
    }

    #[test]
    fn dropped_reservation_is_abandoned_and_still_sealable() {
        let queue: CrashQueue<u8, 4> = CrashQueue::new();
        drop(queue.reserve());
        let token = queue.reserve().unwrap();
        queue.publish(token, 9);
        assert_eq!(queue.slot_state(0), SlotState::Abandoned);
        assert_eq!(queue.slot_state(1), SlotState::Ready(9));
        // The abandoned slot still counts as reserved, so a drain of both seals.
        assert!(!queue.seal_if_drained(1));
        assert!(queue.seal_if_drained(2));
    }

    #[test]
    #[should_panic(expected = "reservation from another queue")]
    fn foreign_reservation_is_rejected() {
        let first: CrashQueue<u8, 2> = CrashQueue::new();
        let second: CrashQueue<u8, 2> = CrashQueue::new();
        second.publish(first.reserve().unwrap(), 1);
    }

    #[test]
    fn seals_when_drained() {
        let queue: CrashQueue<u8, 4> = CrashQueue::new();
        let _a = queue.reserve();
        let _b = queue.reserve();
        assert!(queue.seal_if_drained(2));
        assert!(queue.reserve().is_none());
        assert_eq!(queue.count(), 2);
    }

    #[test]
    fn seal_fails_after_late_reservation() {
        let queue: CrashQueue<u8, 4> = CrashQueue::new();
        let _a = queue.reserve();
        let drained = queue.count();
        let late = queue.reserve();
        assert_eq!(late.as_ref().map(Reservation::slot), Some(1));
        assert!(!queue.seal_if_drained(drained));
        assert!(queue.seal_if_drained(queue.count()));
        assert!(queue.reserve().is_none());
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
        let token = STATIC_QUEUE.reserve().unwrap();
        let slot = token.slot();
        STATIC_QUEUE.publish(token, 0xDEAD_BEEF);
        assert_eq!(STATIC_QUEUE.published(slot), Some(0xDEAD_BEEF));
    }
}
