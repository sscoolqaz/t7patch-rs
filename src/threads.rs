//! Process-local thread freezing for executable code writes.
//!
//! A code patch may only be written while no other thread can be executing the
//! instruction sequence being replaced. This module suspends every thread in the
//! process, records its instruction pointer, and lets the caller write only when
//! no RIP lies in the hazard window of the patch.
//!
//! The freeze path must stay allocation-free and lock-free after the first
//! suspension: a suspended thread may hold the process heap lock or a loader
//! lock, so allocating or taking a lock while it is frozen can deadlock. All
//! vectors used here reserve their capacity before the first `SuspendThread`.

use std::fmt;
use std::mem::size_of;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use windows::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{CONTEXT, CONTEXT_FULL_AMD64, GetThreadContext};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, GetCurrentThreadId, GetExitCodeThread, OpenThread, ResumeThread,
    SuspendThread, THREAD_ACCESS_RIGHTS, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION,
    THREAD_SUSPEND_RESUME,
};

use crate::arxan::WriteReport;

/// Upper bound on the threads one freeze may hold. A game process has far fewer.
const MAX_THREADS: usize = 512;
/// How many times a busy patch is retried before the caller defers it.
const BUSY_ATTEMPTS: usize = 5;
/// Longest x86-64 instruction. A patch at `address` can affect an instruction
/// that starts up to 14 bytes earlier.
const MAX_INSTRUCTION_BYTES: usize = 15;
/// How many times re-enumeration may find a newly created thread before the
/// freeze is abandoned.
const ENUMERATION_ROUNDS: usize = 3;
/// `GetExitCodeThread` reports this while a thread is still running.
const STILL_ACTIVE_CODE: u32 = 259;

/// Serializes every freeze in the process. Two concurrent freezes could suspend
/// each other, so code writes never overlap.
static PATCH_TRANSACTION: Mutex<()> = Mutex::new(());

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
    /// Threads could not be suspended or their contexts could not be read.
    Freeze(String),
    /// The write happened, but some threads could not be resumed.
    Thaw {
        reports: Vec<WriteReport>,
        message: String,
    },
}

impl fmt::Display for CodeWriteError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => formatter.write_str("a game thread is executing the patch site"),
            Self::Freeze(message) | Self::Thaw { message, .. } => formatter.write_str(message),
        }
    }
}

struct FrozenThread {
    handle: HANDLE,
    rip: usize,
    suspended: bool,
}

/// A suspended set of threads and the RIP captured for each.
pub(crate) struct Freeze {
    threads: Vec<FrozenThread>,
    active: bool,
}

impl Freeze {
    /// Suspends every thread other than the caller.
    fn acquire() -> Result<Self, String> {
        // SAFETY: both queries take no arguments and cannot fail.
        let process_id = unsafe { GetCurrentProcessId() };
        // SAFETY: as above.
        let current_thread = unsafe { GetCurrentThreadId() };

        // All allocation happens before the first suspension.
        let mut seen: Vec<u32> = Vec::with_capacity(MAX_THREADS);
        let mut fresh: Vec<u32> = Vec::with_capacity(MAX_THREADS);
        let mut threads: Vec<FrozenThread> = Vec::with_capacity(MAX_THREADS);

        collect_thread_ids(&mut seen, process_id, current_thread).map_err(str::to_owned)?;
        if let Err(message) = open_threads(&seen, &mut threads) {
            close_all(&mut threads);
            return Err(message.to_owned());
        }
        if let Err((suspended, message)) = suspend_all(&mut threads) {
            resume_prefix(&mut threads, suspended);
            close_all(&mut threads[suspended..]);
            return Err(message.to_owned());
        }

        // Toolhelp is a snapshot, not a creation barrier. Suspend any thread that
        // appeared after the first snapshot, within a bounded number of rounds.
        // Thread ids are assumed not to be reused during the freeze: an opened
        // thread keeps its handle (and so its id) alive, and a thread that exited
        // before `OpenThread` cannot execute. A kill-and-reuse inside the short
        // freeze window is accepted as a residual risk rather than guessed around.
        let mut rounds = 0;
        loop {
            fresh.clear();
            if let Err(message) = collect_thread_ids(&mut fresh, process_id, current_thread) {
                resume_all(&mut threads);
                return Err(message.to_owned());
            }
            let mut added = false;
            for id in &fresh {
                if seen.contains(id) {
                    continue;
                }
                if seen.len() >= MAX_THREADS {
                    resume_all(&mut threads);
                    return Err("too many threads to freeze".to_owned());
                }
                seen.push(*id);
                match open_suspend(*id) {
                    Ok(thread) => {
                        threads.push(thread);
                        added = true;
                    }
                    Err(OpenSuspendError::Gone) => {}
                    Err(OpenSuspendError::Failed(message)) => {
                        resume_all(&mut threads);
                        return Err(message.to_owned());
                    }
                }
            }
            if !added {
                break;
            }
            rounds += 1;
            if rounds >= ENUMERATION_ROUNDS {
                resume_all(&mut threads);
                return Err("game threads kept appearing during the freeze".to_owned());
            }
        }

        for index in 0..threads.len() {
            let mut context = CONTEXT {
                ContextFlags: CONTEXT_FULL_AMD64,
                ..Default::default()
            };
            // SAFETY: the thread is suspended and the context is a valid out-buffer.
            if unsafe { GetThreadContext(threads[index].handle, &raw mut context) }.is_err() {
                resume_all(&mut threads);
                return Err("cannot read a game thread context".to_owned());
            }
            threads[index].rip = usize::try_from(context.Rip).unwrap_or_default();
        }

        Ok(Self {
            threads,
            active: true,
        })
    }

    /// True when a suspended thread is executing `[start, end)`.
    fn any_rip_in(&self, start: usize, end: usize) -> bool {
        self.threads
            .iter()
            .any(|thread| rip_in(thread.rip, start, end))
    }

    /// Resumes every thread exactly once and closes its handle.
    fn thaw(mut self) -> Result<(), String> {
        self.thaw_inner()
    }

    fn thaw_inner(&mut self) -> Result<(), String> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        let mut failed = false;
        for thread in &mut self.threads {
            if thread.suspended {
                if unsafe { ResumeThread(thread.handle) } == u32::MAX
                    && !thread_exited(thread.handle)
                {
                    failed = true;
                }
                thread.suspended = false;
            }
            // SAFETY: every handle was opened in `acquire` and is closed once.
            let _ = unsafe { CloseHandle(thread.handle) };
        }
        if failed {
            Err("cannot resume every game thread".to_owned())
        } else {
            Ok(())
        }
    }
}

impl Drop for Freeze {
    fn drop(&mut self) {
        // Safety net for an early return or panic: never leave the game suspended.
        let _ = self.thaw_inner();
    }
}

fn collect_thread_ids(
    out: &mut Vec<u32>,
    process_id: u32,
    current_thread: u32,
) -> Result<(), &'static str> {
    // SAFETY: the snapshot takes only flag and process-id arguments.
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }
        .map_err(|_| "cannot enumerate game threads")?;
    let mut entry = THREADENTRY32 {
        dwSize: u32::try_from(size_of::<THREADENTRY32>()).unwrap_or_default(),
        ..Default::default()
    };
    let mut result = Ok(());
    // SAFETY: `snapshot` is open and `entry` is a valid THREADENTRY32 with `dwSize` set.
    unsafe {
        if Thread32First(snapshot, &raw mut entry).is_err() {
            result = Err("cannot enumerate game threads");
        } else {
            loop {
                if entry.th32OwnerProcessID == process_id && entry.th32ThreadID != current_thread {
                    if out.len() >= MAX_THREADS {
                        result = Err("too many threads to freeze");
                        break;
                    }
                    if !out.contains(&entry.th32ThreadID) {
                        out.push(entry.th32ThreadID);
                    }
                }
                if Thread32Next(snapshot, &raw mut entry).is_err() {
                    break;
                }
            }
        }
    }
    // SAFETY: `snapshot` was opened above and is not used again.
    let _ = unsafe { CloseHandle(snapshot) };
    result
}

fn open_threads(ids: &[u32], out: &mut Vec<FrozenThread>) -> Result<(), &'static str> {
    for id in ids {
        match open(*id) {
            Ok(handle) => out.push(FrozenThread {
                handle,
                rip: 0,
                suspended: false,
            }),
            Err(OpenSuspendError::Gone) => {}
            Err(OpenSuspendError::Failed(message)) => return Err(message),
        }
    }
    Ok(())
}

enum OpenSuspendError {
    Gone,
    Failed(&'static str),
}

fn open(id: u32) -> Result<HANDLE, OpenSuspendError> {
    // SAFETY: the access mask only permits suspension and context reads.
    match unsafe {
        OpenThread(
            THREAD_ACCESS_RIGHTS(
                THREAD_SUSPEND_RESUME.0 | THREAD_GET_CONTEXT.0 | THREAD_QUERY_INFORMATION.0,
            ),
            false,
            id,
        )
    } {
        Ok(handle) => Ok(handle),
        Err(_error) => {
            let last = unsafe { GetLastError() };
            // A thread that exited between the snapshot and OpenThread needs no
            // suspension. Any other failure means the freeze is incomplete.
            if last == ERROR_INVALID_PARAMETER {
                Err(OpenSuspendError::Gone)
            } else {
                Err(OpenSuspendError::Failed("cannot open a game thread"))
            }
        }
    }
}

fn thread_exited(handle: HANDLE) -> bool {
    let mut code = 0u32;
    // SAFETY: `handle` is an open thread handle and `code` is a valid out-buffer.
    unsafe { GetExitCodeThread(handle, &raw mut code) }.is_ok() && code != STILL_ACTIVE_CODE
}

fn open_suspend(id: u32) -> Result<FrozenThread, OpenSuspendError> {
    let handle = open(id)?;
    // SAFETY: `handle` was opened with THREAD_SUSPEND_RESUME.
    if unsafe { SuspendThread(handle) } == u32::MAX {
        let exited = thread_exited(handle);
        // SAFETY: `handle` was opened above and is not used again.
        let _ = unsafe { CloseHandle(handle) };
        return if exited {
            Err(OpenSuspendError::Gone)
        } else {
            Err(OpenSuspendError::Failed("cannot suspend a game thread"))
        };
    }
    Ok(FrozenThread {
        handle,
        rip: 0,
        suspended: true,
    })
}

/// Returns the number suspended, and the reason if one could not be.
fn suspend_all(threads: &mut [FrozenThread]) -> Result<(), (usize, &'static str)> {
    for (index, thread) in threads.iter_mut().enumerate() {
        // SAFETY: the handle was opened with THREAD_SUSPEND_RESUME.
        if unsafe { SuspendThread(thread.handle) } == u32::MAX {
            if thread_exited(thread.handle) {
                // Exited between OpenThread and SuspendThread; it cannot execute code.
                continue;
            }
            return Err((index, "cannot suspend a game thread"));
        }
        thread.suspended = true;
    }
    Ok(())
}

/// Resumes and closes the first `count` threads.
fn resume_prefix(threads: &mut [FrozenThread], count: usize) {
    for thread in &mut threads[..count] {
        if thread.suspended {
            // SAFETY: this handle was suspended by `suspend_all`.
            let _ = unsafe { ResumeThread(thread.handle) };
            thread.suspended = false;
        }
        // SAFETY: every handle in this slice is open and is closed once.
        let _ = unsafe { CloseHandle(thread.handle) };
    }
}

/// Resumes and closes every thread. Only call this after `suspend_all` or
/// `open_suspend` established the suspend count for each handle.
fn resume_all(threads: &mut [FrozenThread]) {
    for thread in threads {
        if thread.suspended {
            // SAFETY: this handle was suspended by `suspend_all` or `open_suspend`.
            let _ = unsafe { ResumeThread(thread.handle) };
            thread.suspended = false;
        }
        // SAFETY: every handle in this slice is open and is closed once.
        let _ = unsafe { CloseHandle(thread.handle) };
    }
}

/// Closes handles whose threads were never suspended.
fn close_all(threads: &mut [FrozenThread]) {
    for thread in threads {
        // SAFETY: every handle in this slice is open and is closed once.
        let _ = unsafe { CloseHandle(thread.handle) };
    }
}

fn rip_in(rip: usize, start: usize, end: usize) -> bool {
    rip >= start && rip < end
}

fn hazard_range(address: usize, length: usize) -> (usize, usize) {
    (
        address.saturating_sub(MAX_INSTRUCTION_BYTES - 1),
        address.saturating_add(length),
    )
}

fn lock_transaction() -> MutexGuard<'static, ()> {
    PATCH_TRANSACTION
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
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
    match result {
        Ok(mut reports) => Ok(reports.pop().unwrap_or_default()),
        Err(error) => Err(error),
    }
}

/// Writes several executable ranges under one freeze. The caller must journal the
/// original bytes first; a reported write can partially succeed.
///
/// # Safety
///
/// Every range must be committed executable memory whose instruction boundaries
/// are preserved by its replacement.
pub(crate) unsafe fn write_code_batch(
    patches: &[CodePatch<'_>],
) -> Result<Vec<WriteReport>, CodeWriteError> {
    if patches.is_empty() {
        return Ok(Vec::new());
    }
    let _transaction = lock_transaction();
    // Reserve before any thread is suspended; `clear` keeps the allocation.
    let mut reports = Vec::with_capacity(patches.len());

    for _attempt in 0..BUSY_ATTEMPTS {
        let freeze = Freeze::acquire().map_err(CodeWriteError::Freeze)?;
        let busy = patches.iter().any(|patch| {
            let (start, end) = hazard_range(patch.address, patch.bytes.len());
            freeze.any_rip_in(start, end)
        });
        if busy {
            if let Err(message) = freeze.thaw() {
                return Err(CodeWriteError::Thaw {
                    reports: Vec::new(),
                    message,
                });
            }
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }

        reports.clear();
        for patch in patches {
            // SAFETY: forwarded from the caller; no other thread can execute the range.
            let report = unsafe { crate::arxan::write_bytes_reported(patch.address, patch.bytes) };
            reports.push(report);
            if !report.complete() {
                break;
            }
        }

        match freeze.thaw() {
            Ok(()) => return Ok(reports),
            Err(message) => return Err(CodeWriteError::Thaw { reports, message }),
        }
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
    fn rip_membership_is_half_open() {
        assert!(rip_in(0x1000, 0x1000, 0x1005));
        assert!(rip_in(0x1004, 0x1000, 0x1005));
        assert!(!rip_in(0x1005, 0x1000, 0x1005));
        assert!(!rip_in(0x0FFF, 0x1000, 0x1005));
    }

    #[test]
    fn hazard_handles_overflow() {
        assert_eq!(hazard_range(8, 1), (0, 9));
        assert_eq!(hazard_range(usize::MAX, 1), (usize::MAX - 14, usize::MAX));
    }
}
