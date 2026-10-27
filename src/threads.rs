//! Executable code writes behind a process-wide thread freeze.
//!
//! A code patch may only be written while no other thread can be executing the
//! instruction sequence being replaced. The freeze mechanics — suspend every other
//! thread, capture each one's context, fail closed on any uncertainty — live in the
//! [`thread_freeze`] engine crate, shared with the vendored `MinHook` port. This
//! module keeps the application-side policy: the patch-transaction lock, the hazard
//! window around a write, the bounded busy-defer retry, the optional stack guard,
//! and the Arxan-aware write path.
//!
//! The freeze stays allocation-free and lock-free after the first suspension (a
//! suspended thread may hold the process heap or loader lock), so every buffer is
//! sized before the first `SuspendThread` and errors are static.

use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use thread_freeze::{AcquireError, Freeze, FreezeError, LiveOps};

use crate::arxan::WriteReport;

/// How many times a busy patch is retried before the caller defers it.
const BUSY_ATTEMPTS: usize = 5;
/// Longest x86-64 instruction. A patch at `address` can affect an instruction that
/// starts up to 14 bytes earlier.
const MAX_INSTRUCTION_BYTES: usize = 15;
/// Most stack bytes one guard scan reads across every thread.
const MAX_TOTAL_SCAN_BYTES: usize = 256 * 1024 * 1024;

/// Serializes every freeze in the process. Two concurrent freezes could suspend
/// each other, so code writes never overlap.
static PATCH_TRANSACTION: Mutex<()> = Mutex::new(());

/// True once a freeze, here or in the hooking library, left a live thread suspended.
/// The engine owns the single latch both callers share.
pub(crate) fn thaw_failed() -> bool {
    thread_freeze::thaw_failed()
}

/// One code patch and the bytes to write.
#[derive(Clone, Copy)]
pub(crate) struct CodePatch<'a> {
    pub(crate) address: usize,
    pub(crate) bytes: &'a [u8],
}

/// Why a code write did not complete.
#[derive(Debug)]
pub(crate) enum CodeWriteError {
    /// A thread was executing the hazard window; nothing was written.
    Busy,
    /// Threads could not be suspended or their contexts could not be read. Every
    /// thread was resumed and nothing was written.
    Freeze(String),
    /// Some threads could not be resumed. Terminal: the stuck threads' handles stay
    /// open and no later code write runs. `reports` says what was written; it is
    /// empty when the freeze failed before any write.
    Thaw {
        reports: Vec<WriteReport>,
        message: &'static str,
    },
}

impl fmt::Display for CodeWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => formatter.write_str("a game thread is executing the patch site"),
            Self::Freeze(message) => formatter.write_str(message),
            Self::Thaw { message, .. } => formatter.write_str(message),
        }
    }
}

fn hazard_range(address: usize, length: usize) -> (usize, usize) {
    (
        address.saturating_sub(MAX_INSTRUCTION_BYTES - 1),
        address.saturating_add(length),
    )
}

/// Serializes code writes, pointer publication and page-protection changes.
pub(crate) fn lock_transaction() -> MutexGuard<'static, ()> {
    PATCH_TRANSACTION
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// Freezes every other live thread. Allocation happens before suspension. The
/// caller holds the patch transaction.
fn freeze_live() -> Result<Freeze<LiveOps>, CodeWriteError> {
    if thaw_failed() {
        return Err(CodeWriteError::Freeze(
            FreezeError::Disabled.as_str().to_owned(),
        ));
    }
    let ops = LiveOps::new().map_err(|error| CodeWriteError::Freeze(error.as_str().to_owned()))?;
    match Freeze::acquire(ops) {
        Ok(freeze) => Ok(freeze),
        Err(AcquireError::Aborted(error)) => Err(CodeWriteError::Freeze(error.as_str().to_owned())),
        Err(AcquireError::Terminal(_error)) => {
            // The engine set the terminal latch and leaked the suspended thread's
            // handle; nothing here allocates (a suspended thread may hold the heap
            // lock), so the message is static and `reports` is empty.
            Err(CodeWriteError::Thaw {
                reports: Vec::new(),
                message: FreezeError::Resume.as_str(),
            })
        }
    }
}

/// Thaws `freeze`, mapping a failed resume to a terminal [`CodeWriteError::Thaw`]
/// carrying `reports`.
fn thaw(
    freeze: Freeze<LiveOps>,
    reports: Vec<WriteReport>,
) -> Result<Vec<WriteReport>, CodeWriteError> {
    match freeze.thaw() {
        Ok(()) => Ok(reports),
        Err(error) => Err(CodeWriteError::Thaw {
            reports,
            message: error.as_str(),
        }),
    }
}

/// Writes one executable code range after freezing every other thread.
///
/// # Safety
///
/// `[address, address + bytes.len())` must be committed executable memory whose
/// instruction boundaries are preserved by the replacement.
pub(crate) unsafe fn write_code(
    address: usize,
    bytes: &[u8],
) -> Result<WriteReport, CodeWriteError> {
    let patch = CodePatch { address, bytes };
    // SAFETY: forwarded from the caller.
    let result = unsafe { write_code_batch(std::slice::from_ref(&patch)) };
    result.map(|mut reports| reports.pop().unwrap_or_default())
}

/// Writes several executable ranges under one freeze. The caller must journal the
/// original bytes first; a reported write can partially succeed.
///
/// # Safety
///
/// Every range must be committed executable memory whose instruction boundaries are
/// preserved by its replacement.
pub(crate) unsafe fn write_code_batch(
    patches: &[CodePatch<'_>],
) -> Result<Vec<WriteReport>, CodeWriteError> {
    // SAFETY: forwarded from the caller.
    unsafe { write_code_batch_guarded(patches, None) }
}

/// Writes one range like [`write_code`], and also treats the patch as busy while any
/// thread's stack holds a word in `[guard.0, guard.1)`. For code that other threads
/// call out of, so a pending return address must not land in new bytes.
///
/// # Safety
///
/// As for [`write_code`].
pub(crate) unsafe fn write_code_guarded(
    address: usize,
    bytes: &[u8],
    guard: (usize, usize),
) -> Result<WriteReport, CodeWriteError> {
    let patch = CodePatch { address, bytes };
    // SAFETY: forwarded from the caller.
    let result = unsafe { write_code_batch_guarded(std::slice::from_ref(&patch), Some(guard)) };
    result.map(|mut reports| reports.pop().unwrap_or_default())
}

unsafe fn write_code_batch_guarded(
    patches: &[CodePatch<'_>],
    guard: Option<(usize, usize)>,
) -> Result<Vec<WriteReport>, CodeWriteError> {
    if patches.is_empty() {
        return Ok(Vec::new());
    }
    let _transaction = lock_transaction();
    // Reserve before any thread is suspended; `clear` keeps the allocation.
    let mut reports = Vec::with_capacity(patches.len());

    for _attempt in 0..BUSY_ATTEMPTS {
        let mut freeze = match freeze_live() {
            Ok(freeze) => freeze,
            // A terminal thaw left a thread suspended; keep `reports` rather than
            // drop it, as a stuck thread may hold the heap lock.
            Err(error) => {
                if matches!(error, CodeWriteError::Thaw { .. }) {
                    std::mem::forget(reports);
                }
                return Err(error);
            }
        };
        let mut busy = patches.iter().any(|patch| {
            let (start, end) = hazard_range(patch.address, patch.bytes.len());
            freeze.any_rip_in(start, end)
        });
        let mut scan_error = None;
        if let (false, Some((start, end))) = (busy, guard) {
            let mut budget = MAX_TOTAL_SCAN_BYTES;
            match freeze.scan_stacks(&mut budget, |word| {
                usize::try_from(word).is_ok_and(|word| word >= start && word < end)
            }) {
                Ok(hit) => busy = hit,
                Err(error) => scan_error = Some(error),
            }
        }
        if let Some(error) = scan_error {
            return match thaw(freeze, Vec::new()) {
                Ok(_) => Err(CodeWriteError::Freeze(error.as_str().to_owned())),
                // Terminal: keep `reports` rather than drop it.
                Err(thaw) => {
                    std::mem::forget(reports);
                    Err(thaw)
                }
            };
        }
        if busy {
            if let Err(thaw) = thaw(freeze, Vec::new()) {
                // Terminal: keep `reports` rather than drop it.
                std::mem::forget(reports);
                return Err(thaw);
            }
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }

        reports.clear();
        for patch in patches {
            // SAFETY: forwarded from the caller; no other thread can execute the range.
            let report =
                unsafe { crate::arxan::write_bytes_in_transaction(patch.address, patch.bytes) };
            reports.push(report);
            if !report.complete() {
                break;
            }
        }

        return thaw(freeze, reports);
    }

    Err(CodeWriteError::Busy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hazard_covers_instruction_starts_before_the_write() {
        assert_eq!(hazard_range(0x1000, 5), (0x1000 - 14, 0x1005));
        assert_eq!(hazard_range(2, 1), (0, 3));
    }

    #[test]
    fn hazard_handles_overflow() {
        assert_eq!(hazard_range(8, 1), (0, 9));
        assert_eq!(hazard_range(usize::MAX, 1), (usize::MAX - 14, usize::MAX));
    }

    #[test]
    fn live_freeze_stops_and_releases_a_real_thread() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

        const SENTINEL: u64 = 0x5EAF_00D5_1234_5678;
        let counter = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let (counter, stop) = (Arc::clone(&counter), Arc::clone(&stop));
            std::thread::spawn(move || {
                let marker = std::hint::black_box([SENTINEL; 4]);
                while !stop.load(Ordering::Relaxed) {
                    counter.fetch_add(1, Ordering::Relaxed);
                }
                std::hint::black_box(marker);
            })
        };
        while counter.load(Ordering::Relaxed) == 0 {
            std::thread::yield_now();
        }

        let _transaction = lock_transaction();
        let mut freeze = Freeze::acquire(LiveOps::new().expect("buffer")).expect("freeze");
        // Nothing below may allocate or panic until the thaw.
        let frozen = freeze.len();
        let sentinel = usize::try_from(SENTINEL).unwrap_or(0);
        let mut budget = MAX_TOTAL_SCAN_BYTES;
        let found = freeze.scan_stacks(&mut budget, |word| {
            usize::try_from(word).is_ok_and(|word| word == sentinel)
        });
        let before = counter.load(Ordering::Relaxed);
        std::thread::sleep(Duration::from_millis(20));
        let after = counter.load(Ordering::Relaxed);
        freeze.thaw().expect("thaw");
        assert!(frozen > 0);
        assert_eq!(found, Ok(true), "stack scan missed the worker's sentinel");
        assert_eq!(before, after, "worker ran while frozen");

        let resumed = counter.load(Ordering::Relaxed);
        while counter.load(Ordering::Relaxed) == resumed {
            std::thread::yield_now();
        }
        stop.store(true, Ordering::Relaxed);
        worker.join().unwrap();
    }
}
