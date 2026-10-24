//! Process-local thread freezing for executable code writes.
//!
//! A code patch may only be written while no other thread can be executing the
//! instruction sequence being replaced. This module suspends every thread in the
//! process, records its instruction pointer, and lets the caller write only when
//! no RIP lies in the hazard window of the patch.
//!
//! The freeze path must stay allocation-free and lock-free after the first
//! suspension: a suspended thread may hold the process heap lock or a loader
//! lock, so allocating or taking a lock while it is frozen can deadlock. Thread
//! ids live in fixed arrays, the enumeration buffer and the thread vector are
//! sized before the first `SuspendThread`, and errors are static until every
//! thread is resumed.
//!
//! The Win32 calls sit behind [`ThreadOps`], so the freeze and thaw logic is
//! tested with a fake that fails any call on demand.

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SystemProcessInformation};
use windows::Wdk::System::Threading::{NtQueryInformationThread, ThreadBasicInformation};
use windows::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_PARAMETER, GetLastError, HANDLE, STATUS_INFO_LENGTH_MISMATCH,
};
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_FULL_AMD64, GetThreadContext, ReadProcessMemory,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId, GetExitCodeThread,
    GetProcessIdOfThread, OpenThread, ResumeThread, Sleep, SuspendThread, THREAD_ACCESS_RIGHTS,
    THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME,
};

use crate::arxan::WriteReport;

/// Upper bound on the threads one freeze may hold. A game process has far fewer.
pub(crate) const MAX_THREADS: usize = 512;
/// How many times a busy patch is retried before the caller defers it.
const BUSY_ATTEMPTS: usize = 5;
/// Longest x86-64 instruction. A patch at `address` can affect an instruction
/// that starts up to 14 bytes earlier.
const MAX_INSTRUCTION_BYTES: usize = 15;
/// How many times re-enumeration may find a newly created thread before the
/// freeze is abandoned.
const ENUMERATION_ROUNDS: usize = 3;
/// How many times a failed `ResumeThread` is retried before the thread is
/// declared stuck.
const RESUME_ATTEMPTS: usize = 3;
/// `GetExitCodeThread` reports this while a thread is still running.
const STILL_ACTIVE_CODE: u32 = 259;
/// Smallest process-information buffer; grown before the freeze when too small.
const MIN_PROCESS_BUFFER: usize = 256 * 1024;

/// Serializes every freeze in the process. Two concurrent freezes could suspend
/// each other, so code writes never overlap.
static PATCH_TRANSACTION: Mutex<()> = Mutex::new(());
/// Set once a thread could not be resumed. Its handle is leaked on purpose and
/// no further code write is attempted; the lifecycle treats this as terminal.
static THAW_FAILED: AtomicBool = AtomicBool::new(false);

/// True once a freeze left a live thread suspended.
pub(crate) fn thaw_failed() -> bool {
    THAW_FAILED.load(Ordering::Acquire)
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
    /// Threads could not be suspended or their contexts could not be read.
    /// Every thread was resumed and nothing was written.
    Freeze(String),
    /// Some threads could not be resumed. This is terminal: the stuck threads'
    /// handles stay open and no later code write runs. `reports` says what was
    /// written; it is empty when the freeze failed before any write.
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

/// A freeze failure. Static, so it can be built while threads are suspended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FreezeError {
    Enumerate,
    BufferTooSmall,
    TooManyThreads,
    Open,
    Suspend,
    Context,
    KeptAppearing,
    Resume,
    Disabled,
    Stack,
}

impl FreezeError {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Enumerate => "cannot enumerate game threads",
            Self::BufferTooSmall => "game thread list outgrew the preallocated buffer",
            Self::TooManyThreads => "too many threads to freeze",
            Self::Open => "cannot open a game thread",
            Self::Suspend => "cannot suspend a game thread",
            Self::Context => "cannot read a game thread context",
            Self::KeptAppearing => "game threads kept appearing during the freeze",
            Self::Resume => "cannot resume every game thread",
            Self::Disabled => "code writes are disabled after a failed thread resume",
            Self::Stack => "cannot read a game thread stack",
        }
    }
}

/// How an acquire failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AcquireError {
    /// Every suspended thread was resumed.
    Aborted(FreezeError),
    /// The abort itself could not resume a thread.
    Terminal(FreezeError),
}

/// Why an open did not produce a handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum OpenError {
    /// The thread exited before it was opened; it cannot execute.
    Gone,
    Failed,
}

/// A fixed-capacity, duplicate-free set of thread ids.
pub(crate) struct IdSet {
    ids: [u32; MAX_THREADS],
    len: usize,
}

impl IdSet {
    pub(crate) const fn new() -> Self {
        Self {
            ids: [0; MAX_THREADS],
            len: 0,
        }
    }

    pub(crate) fn clear(&mut self) {
        self.len = 0;
    }

    pub(crate) fn as_slice(&self) -> &[u32] {
        &self.ids[..self.len]
    }

    pub(crate) fn contains(&self, id: u32) -> bool {
        self.as_slice().contains(&id)
    }

    /// Adds `id` unless it is already present.
    pub(crate) fn insert(&mut self, id: u32) -> Result<(), FreezeError> {
        if self.contains(id) {
            return Ok(());
        }
        if self.len >= MAX_THREADS {
            return Err(FreezeError::TooManyThreads);
        }
        self.ids[self.len] = id;
        self.len += 1;
        Ok(())
    }
}

/// The thread operations a freeze needs. None of them may allocate.
pub(crate) trait ThreadOps {
    type Handle: Copy;
    /// Fills `ids` with every thread of the process except the caller.
    fn enumerate(&mut self, ids: &mut IdSet) -> Result<(), FreezeError>;
    fn open(&mut self, id: u32) -> Result<Self::Handle, OpenError>;
    fn suspend(&mut self, handle: Self::Handle) -> bool;
    fn resume(&mut self, handle: Self::Handle) -> bool;
    fn exited(&mut self, handle: Self::Handle) -> bool;
    /// The suspended thread's `(rip, rsp)`.
    fn registers(&mut self, handle: Self::Handle) -> Option<(usize, usize)>;
    /// The top (highest address) of the suspended thread's stack.
    fn stack_base(&mut self, handle: Self::Handle) -> Option<usize>;
    /// Reads `out.len()` words at `address` without faulting.
    fn read_words(&mut self, address: usize, out: &mut [u64]) -> bool;
    fn close(&mut self, handle: Self::Handle);
    /// Waits briefly before a resume is retried.
    fn pause(&mut self);
}

struct FrozenThread<H> {
    handle: H,
    rip: usize,
    rsp: usize,
}

/// A suspended set of threads and the RIP captured for each.
pub(crate) struct Freeze<O: ThreadOps> {
    ops: O,
    threads: Vec<FrozenThread<O::Handle>>,
    active: bool,
}

impl<O: ThreadOps> Freeze<O> {
    /// Suspends every thread `ops` enumerates. On failure every suspended
    /// thread is resumed before this returns, or the error is terminal.
    pub(crate) fn acquire(ops: O) -> Result<Self, AcquireError> {
        // All allocation happens before the first suspension.
        let mut freeze = Self {
            ops,
            threads: Vec::with_capacity(MAX_THREADS),
            active: true,
        };
        let mut seen = IdSet::new();
        let mut fresh = IdSet::new();
        if let Err(error) = freeze.suspend_rounds(&mut seen, &mut fresh) {
            return Err(freeze.abort(error));
        }
        Ok(freeze)
    }

    // An enumeration is a snapshot, not a creation barrier. Suspend any thread
    // that appeared after the first one, within a bounded number of rounds.
    //
    // `SuspendThread` is asynchronous: a thread told to suspend may still run,
    // and create a thread, until it is synchronized. Each round therefore reads
    // the context of every thread it suspended (which waits for the suspension
    // to take effect) before enumerating again, so the final "nothing new"
    // enumeration happens with every known thread really stopped.
    //
    // An id enters `seen` only once its thread is held open and suspended. An
    // opened thread keeps its id alive, so it cannot be reused under us. An id
    // that was gone or exited is looked at again if it reappears, in case a new
    // thread was given the recycled id.
    fn suspend_rounds(&mut self, seen: &mut IdSet, fresh: &mut IdSet) -> Result<(), FreezeError> {
        for _pass in 0..=ENUMERATION_ROUNDS {
            fresh.clear();
            self.ops.enumerate(fresh)?;
            let first_new = self.threads.len();
            for &id in fresh.as_slice() {
                if seen.contains(id) {
                    continue;
                }
                if self.open_suspend(id)? {
                    seen.insert(id)?;
                }
            }
            if self.threads.len() == first_new {
                return Ok(());
            }
            for index in first_new..self.threads.len() {
                let handle = self.threads[index].handle;
                let (rip, rsp) = self.ops.registers(handle).ok_or(FreezeError::Context)?;
                self.threads[index].rip = rip;
                self.threads[index].rsp = rsp;
            }
        }
        Err(FreezeError::KeptAppearing)
    }

    /// Opens and suspends `id`. Returns `false` when the thread had already exited.
    fn open_suspend(&mut self, id: u32) -> Result<bool, FreezeError> {
        let handle = match self.ops.open(id) {
            Ok(handle) => handle,
            Err(OpenError::Gone) => return Ok(false),
            Err(OpenError::Failed) => return Err(FreezeError::Open),
        };
        if !self.ops.suspend(handle) {
            let exited = self.ops.exited(handle);
            self.ops.close(handle);
            return if exited {
                Ok(false)
            } else {
                Err(FreezeError::Suspend)
            };
        }
        if self.threads.len() >= self.threads.capacity() {
            // Unreachable while `seen` caps ids at MAX_THREADS, but never grow here.
            self.resume_one(handle);
            return Err(FreezeError::TooManyThreads);
        }
        self.threads.push(FrozenThread {
            handle,
            rip: 0,
            rsp: 0,
        });
        Ok(true)
    }

    fn abort(&mut self, error: FreezeError) -> AcquireError {
        if self.thaw_inner().is_ok() {
            AcquireError::Aborted(error)
        } else {
            AcquireError::Terminal(error)
        }
    }

    /// True when a suspended thread is executing `[start, end)`.
    pub(crate) fn any_rip_in(&self, start: usize, end: usize) -> bool {
        self.threads
            .iter()
            .any(|thread| rip_in(thread.rip, start, end))
    }

    /// True when any suspended thread has a word in `[start, end)` anywhere on
    /// its live stack, from RSP up to the stack base. A return address into the
    /// range means the thread will execute it again. The scan is conservative:
    /// a stale value that only looks like such an address also counts.
    pub(crate) fn any_stack_word_in(
        &mut self,
        start: usize,
        end: usize,
    ) -> Result<bool, FreezeError> {
        const CHUNK_WORDS: usize = 64;
        let mut chunk = [0u64; CHUNK_WORDS];
        for index in 0..self.threads.len() {
            let FrozenThread { handle, rsp, .. } = self.threads[index];
            let base = self.ops.stack_base(handle).ok_or(FreezeError::Stack)?;
            if rsp == 0 || rsp > base {
                return Err(FreezeError::Stack);
            }
            let mut cursor = rsp & !7;
            while cursor < base {
                let words = ((base - cursor) / 8).min(CHUNK_WORDS);
                if words == 0 {
                    break;
                }
                if !self.ops.read_words(cursor, &mut chunk[..words]) {
                    return Err(FreezeError::Stack);
                }
                if chunk[..words]
                    .iter()
                    .any(|&word| usize::try_from(word).is_ok_and(|word| rip_in(word, start, end)))
                {
                    return Ok(true);
                }
                cursor += words * 8;
            }
        }
        Ok(false)
    }

    /// Resumes every thread exactly once.
    pub(crate) fn thaw(mut self) -> Result<(), FreezeError> {
        self.thaw_inner()
    }

    fn thaw_inner(&mut self) -> Result<(), FreezeError> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        let mut failed = false;
        for index in 0..self.threads.len() {
            let handle = self.threads[index].handle;
            if !self.resume_one(handle) {
                failed = true;
            }
        }
        self.threads.clear();
        if failed {
            Err(FreezeError::Resume)
        } else {
            Ok(())
        }
    }

    /// Resumes `handle`, retrying a failure. The handle is closed only once the
    /// thread is running again or has exited; a thread that stays suspended
    /// keeps its handle, so its id cannot be reused under us.
    fn resume_one(&mut self, handle: O::Handle) -> bool {
        for attempt in 0..RESUME_ATTEMPTS {
            if attempt > 0 {
                self.ops.pause();
            }
            if self.ops.resume(handle) {
                self.ops.close(handle);
                return true;
            }
        }
        if self.ops.exited(handle) {
            self.ops.close(handle);
            return true;
        }
        false
    }
}

impl<O: ThreadOps> Drop for Freeze<O> {
    fn drop(&mut self) {
        // Safety net for an early return or panic: never leave the game suspended.
        let _ = self.thaw_inner();
    }
}

/// The live Win32 and ntdll implementation of [`ThreadOps`].
struct LiveOps {
    process_id: u32,
    current_thread: u32,
    /// `SYSTEM_PROCESS_INFORMATION` buffer, 8-byte aligned, sized before the freeze.
    buffer: Vec<u64>,
}

impl LiveOps {
    /// Sizes the enumeration buffer with headroom. Allocates, so it runs before
    /// any thread is suspended.
    fn new() -> Result<Self, FreezeError> {
        // SAFETY: both queries take no arguments and cannot fail.
        let process_id = unsafe { GetCurrentProcessId() };
        // SAFETY: as above.
        let current_thread = unsafe { GetCurrentThreadId() };
        let mut bytes = MIN_PROCESS_BUFFER;
        for _attempt in 0..8 {
            let mut buffer = vec![0u64; bytes / 8];
            let mut needed = 0u32;
            let status = query_processes(&mut buffer, &mut needed);
            if status.is_ok() {
                // Leave room for threads created before the freeze queries again.
                let used = usize::try_from(needed).unwrap_or(bytes);
                if used.saturating_mul(2) > bytes {
                    buffer = vec![0u64; used.saturating_mul(2).div_ceil(8)];
                }
                return Ok(Self {
                    process_id,
                    current_thread,
                    buffer,
                });
            }
            if status != STATUS_INFO_LENGTH_MISMATCH {
                return Err(FreezeError::Enumerate);
            }
            let needed = usize::try_from(needed).unwrap_or(0);
            bytes = needed.max(bytes).saturating_mul(2);
        }
        Err(FreezeError::Enumerate)
    }
}

fn query_processes(buffer: &mut [u64], needed: &mut u32) -> windows::Win32::Foundation::NTSTATUS {
    let length = u32::try_from(buffer.len() * 8).unwrap_or(u32::MAX);
    // SAFETY: `buffer` is writable for `length` bytes and `needed` is a valid out-pointer.
    unsafe {
        NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.as_mut_ptr().cast(),
            length,
            needed,
        )
    }
}

impl ThreadOps for LiveOps {
    type Handle = HANDLE;

    fn enumerate(&mut self, ids: &mut IdSet) -> Result<(), FreezeError> {
        let mut needed = 0u32;
        let status = query_processes(&mut self.buffer, &mut needed);
        if status == STATUS_INFO_LENGTH_MISMATCH {
            return Err(FreezeError::BufferTooSmall);
        }
        if status.is_err() {
            return Err(FreezeError::Enumerate);
        }
        // SAFETY: the buffer is a live `Vec<u64>`, so its bytes are initialized.
        let bytes = unsafe {
            std::slice::from_raw_parts(self.buffer.as_ptr().cast::<u8>(), self.buffer.len() * 8)
        };
        parse_process_threads(bytes, self.process_id, self.current_thread, ids)
    }

    fn open(&mut self, id: u32) -> Result<HANDLE, OpenError> {
        // SAFETY: the access mask only permits suspension, context and exit-code reads.
        match unsafe {
            OpenThread(
                THREAD_ACCESS_RIGHTS(
                    THREAD_SUSPEND_RESUME.0 | THREAD_GET_CONTEXT.0 | THREAD_QUERY_INFORMATION.0,
                ),
                false,
                id,
            )
        } {
            Ok(handle) => {
                // SAFETY: `handle` was opened with THREAD_QUERY_INFORMATION.
                if unsafe { GetProcessIdOfThread(handle) } == self.process_id {
                    Ok(handle)
                } else {
                    // The id was reused by another process's thread: ours is gone.
                    self.close(handle);
                    Err(OpenError::Gone)
                }
            }
            Err(_error) => {
                // SAFETY: reads this thread's last-error value.
                let last = unsafe { GetLastError() };
                // A thread that exited between the enumeration and OpenThread needs
                // no suspension. Any other failure means the freeze is incomplete.
                if last == ERROR_INVALID_PARAMETER {
                    Err(OpenError::Gone)
                } else {
                    Err(OpenError::Failed)
                }
            }
        }
    }

    fn suspend(&mut self, handle: HANDLE) -> bool {
        // SAFETY: `handle` was opened with THREAD_SUSPEND_RESUME.
        unsafe { SuspendThread(handle) != u32::MAX }
    }

    fn resume(&mut self, handle: HANDLE) -> bool {
        // SAFETY: `handle` was opened with THREAD_SUSPEND_RESUME and suspended by us.
        unsafe { ResumeThread(handle) != u32::MAX }
    }

    fn exited(&mut self, handle: HANDLE) -> bool {
        let mut code = 0u32;
        // SAFETY: `handle` is an open thread handle and `code` is a valid out-buffer.
        unsafe { GetExitCodeThread(handle, &raw mut code) }.is_ok() && code != STILL_ACTIVE_CODE
    }

    fn registers(&mut self, handle: HANDLE) -> Option<(usize, usize)> {
        let mut context = CONTEXT {
            ContextFlags: CONTEXT_FULL_AMD64,
            ..Default::default()
        };
        // SAFETY: the thread is suspended and the context is a valid out-buffer.
        unsafe { GetThreadContext(handle, &raw mut context) }.ok()?;
        Some((
            usize::try_from(context.Rip).ok()?,
            usize::try_from(context.Rsp).ok()?,
        ))
    }

    fn stack_base(&mut self, handle: HANDLE) -> Option<usize> {
        // x64 THREAD_BASIC_INFORMATION is 0x30 bytes; TebBaseAddress is at +8.
        let mut information = [0u64; 6];
        let mut returned = 0u32;
        // SAFETY: the handle has THREAD_QUERY_INFORMATION and the buffer is 0x30 bytes.
        let status = unsafe {
            NtQueryInformationThread(
                handle,
                ThreadBasicInformation,
                information.as_mut_ptr().cast(),
                u32::try_from(size_of_val(&information)).ok()?,
                &raw mut returned,
            )
        };
        if status.is_err() {
            return None;
        }
        let teb = usize::try_from(information[1]).ok()?;
        // NT_TIB.StackBase is the second word of the TEB.
        let mut base = [0u64; 1];
        (teb != 0 && self.read_words(teb + 8, &mut base))
            .then(|| usize::try_from(base[0]).ok())
            .flatten()
    }

    fn read_words(&mut self, address: usize, out: &mut [u64]) -> bool {
        let bytes = size_of_val(out);
        let mut copied = 0usize;
        // SAFETY: ReadProcessMemory validates the source range and fails instead of
        // faulting; `out` is a writable buffer of `bytes` bytes.
        unsafe {
            ReadProcessMemory(
                GetCurrentProcess(),
                address as *const _,
                out.as_mut_ptr().cast(),
                bytes,
                Some(&raw mut copied),
            )
        }
        .is_ok()
            && copied == bytes
    }

    fn close(&mut self, handle: HANDLE) {
        // SAFETY: every handle is opened by `open` and closed once.
        let _ = unsafe { CloseHandle(handle) };
    }

    fn pause(&mut self) {
        // SAFETY: Sleep takes a plain duration.
        unsafe { Sleep(1) };
    }
}

// x64 `SYSTEM_PROCESS_INFORMATION` and `SYSTEM_THREAD_INFORMATION` layout.
const PROCESS_NEXT_OFFSET: usize = 0x00;
const PROCESS_THREAD_COUNT: usize = 0x04;
const PROCESS_ID: usize = 0x50;
const PROCESS_ENTRY_SIZE: usize = 0x100;
const THREAD_ENTRY_SIZE: usize = 0x50;
const THREAD_CLIENT_ID_THREAD: usize = 0x30;

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let slice = bytes.get(offset..offset.checked_add(4)?)?;
    Some(u32::from_le_bytes(slice.try_into().ok()?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    let slice = bytes.get(offset..offset.checked_add(8)?)?;
    Some(u64::from_le_bytes(slice.try_into().ok()?))
}

/// Collects the thread ids of `process_id`, except `skip`, from a
/// `SystemProcessInformation` buffer. Every read is bounds-checked.
pub(crate) fn parse_process_threads(
    bytes: &[u8],
    process_id: u32,
    skip: u32,
    ids: &mut IdSet,
) -> Result<(), FreezeError> {
    let mut offset = 0usize;
    loop {
        let next = read_u32(bytes, offset + PROCESS_NEXT_OFFSET).ok_or(FreezeError::Enumerate)?;
        let count = read_u32(bytes, offset + PROCESS_THREAD_COUNT).ok_or(FreezeError::Enumerate)?;
        let pid = read_u64(bytes, offset + PROCESS_ID).ok_or(FreezeError::Enumerate)?;
        if pid == u64::from(process_id) {
            let count = usize::try_from(count).map_err(|_| FreezeError::Enumerate)?;
            for index in 0..count {
                let entry = offset + PROCESS_ENTRY_SIZE + index * THREAD_ENTRY_SIZE;
                let tid = read_u64(bytes, entry + THREAD_CLIENT_ID_THREAD)
                    .ok_or(FreezeError::Enumerate)?;
                let tid = u32::try_from(tid).map_err(|_| FreezeError::Enumerate)?;
                if tid != skip {
                    ids.insert(tid)?;
                }
            }
            return Ok(());
        }
        if next == 0 {
            return Err(FreezeError::Enumerate);
        }
        offset = offset
            .checked_add(usize::try_from(next).map_err(|_| FreezeError::Enumerate)?)
            .ok_or(FreezeError::Enumerate)?;
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
        Err(AcquireError::Terminal(error)) => {
            THAW_FAILED.store(true, Ordering::Release);
            // A thread stays suspended and may hold the heap lock, so nothing
            // here allocates: `Vec::new` does not, and the message is static.
            let _ = error;
            Err(CodeWriteError::Thaw {
                reports: Vec::new(),
                message: FreezeError::Resume.as_str(),
            })
        }
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
    // SAFETY: forwarded from the caller.
    unsafe { write_code_batch_guarded(patches, None) }
}

/// Writes one range like [`write_code`], and also treats the patch as busy while
/// any thread's stack holds a word in `[guard.0, guard.1)`. For code that other
/// threads call out of, so a pending return address must not land in new bytes.
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
        let mut freeze = freeze_live()?;
        let mut busy = patches.iter().any(|patch| {
            let (start, end) = hazard_range(patch.address, patch.bytes.len());
            freeze.any_rip_in(start, end)
        });
        let mut scan_error = None;
        if let (false, Some((start, end))) = (busy, guard) {
            match freeze.any_stack_word_in(start, end) {
                Ok(hit) => busy = hit,
                Err(error) => scan_error = Some(error),
            }
        }
        if let Some(error) = scan_error {
            return match freeze.thaw() {
                Ok(()) => Err(CodeWriteError::Freeze(error.as_str().to_owned())),
                Err(thaw) => {
                    THAW_FAILED.store(true, Ordering::Release);
                    Err(CodeWriteError::Thaw {
                        reports: Vec::new(),
                        message: thaw.as_str(),
                    })
                }
            };
        }
        if busy {
            if let Err(error) = freeze.thaw() {
                THAW_FAILED.store(true, Ordering::Release);
                return Err(CodeWriteError::Thaw {
                    reports: Vec::new(),
                    message: error.as_str(),
                });
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

        match freeze.thaw() {
            Ok(()) => return Ok(reports),
            Err(error) => {
                THAW_FAILED.store(true, Ordering::Release);
                return Err(CodeWriteError::Thaw {
                    reports,
                    message: error.as_str(),
                });
            }
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

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Op {
        Enumerate,
        Open,
        Suspend,
        Resume,
        Rip,
        Stack,
    }

    #[derive(Clone, Copy)]
    struct FakeThread {
        id: u32,
        alive: bool,
        suspend_count: u32,
        open: bool,
        /// Its context was read since it was last suspended, so the suspension
        /// has taken effect.
        synced: bool,
    }

    /// A fake process. `fail` fails the `nth` call (0-based) of `op`, or every
    /// call from `nth` on when `sticky` is set.
    struct Fake {
        threads: Vec<FakeThread>,
        /// Threads that appear after the given enumeration call.
        spawn_after: Vec<(usize, u32)>,
        fail: Vec<(Op, usize, bool)>,
        calls: [usize; 6],
        /// Words on each thread's stack, lowest address first; RSP is at 0x10000 * (index + 1).
        stacks: Vec<Vec<u64>>,
        /// The enumerate error to inject.
        enumerate_error: FreezeError,
        /// Marks a thread exited when its resume fails.
        exit_on_failed_resume: bool,
    }

    impl Fake {
        fn new(ids: &[u32]) -> Self {
            Self {
                threads: ids
                    .iter()
                    .map(|&id| FakeThread {
                        id,
                        alive: true,
                        suspend_count: 0,
                        open: false,
                        synced: false,
                    })
                    .collect(),
                spawn_after: Vec::new(),
                fail: Vec::new(),
                calls: [0; 6],
                stacks: Vec::new(),
                enumerate_error: FreezeError::Enumerate,
                exit_on_failed_resume: false,
            }
        }

        fn failing(mut self, op: Op, nth: usize, sticky: bool) -> Self {
            self.fail.push((op, nth, sticky));
            self
        }

        fn should_fail(&mut self, op: Op) -> bool {
            let slot = op as usize;
            let call = self.calls[slot];
            self.calls[slot] += 1;
            self.fail.iter().any(|&(fail_op, nth, sticky)| {
                fail_op == op && (call == nth || (sticky && call > nth))
            })
        }

        fn thread(&mut self, handle: usize) -> &mut FakeThread {
            &mut self.threads[handle]
        }
    }

    impl ThreadOps for &mut Fake {
        type Handle = usize;

        fn enumerate(&mut self, ids: &mut IdSet) -> Result<(), FreezeError> {
            let call = self.calls[Op::Enumerate as usize];
            // SuspendThread is asynchronous: a later enumeration is only meaningful
            // once every suspended thread has really stopped.
            assert!(
                self.threads
                    .iter()
                    .all(|thread| thread.suspend_count == 0 || thread.synced),
                "enumerated again before every suspend was synchronized"
            );
            if self.should_fail(Op::Enumerate) {
                return Err(self.enumerate_error);
            }
            let spawned: Vec<u32> = self
                .spawn_after
                .iter()
                .filter(|(after, _)| *after < call)
                .map(|(_, id)| *id)
                .collect();
            for id in spawned {
                if !self.threads.iter().any(|thread| thread.id == id) {
                    self.threads.push(FakeThread {
                        id,
                        alive: true,
                        suspend_count: 0,
                        open: false,
                        synced: false,
                    });
                }
            }
            for thread in &self.threads {
                if thread.alive {
                    ids.insert(thread.id)?;
                }
            }
            Ok(())
        }

        fn open(&mut self, id: u32) -> Result<usize, OpenError> {
            if self.should_fail(Op::Open) {
                return Err(OpenError::Failed);
            }
            let index = self
                .threads
                .iter()
                .position(|thread| thread.id == id)
                .ok_or(OpenError::Gone)?;
            assert!(!self.threads[index].open, "thread opened twice");
            self.threads[index].open = true;
            Ok(index)
        }

        fn suspend(&mut self, handle: usize) -> bool {
            if self.should_fail(Op::Suspend) {
                return false;
            }
            let thread = self.thread(handle);
            thread.suspend_count += 1;
            thread.synced = false;
            true
        }

        fn resume(&mut self, handle: usize) -> bool {
            assert!(self.thread(handle).open, "resume on a closed handle");
            if self.should_fail(Op::Resume) {
                if self.exit_on_failed_resume {
                    self.thread(handle).alive = false;
                }
                return false;
            }
            let thread = self.thread(handle);
            assert!(thread.suspend_count > 0, "resume without suspend");
            thread.suspend_count -= 1;
            true
        }

        fn exited(&mut self, handle: usize) -> bool {
            !self.thread(handle).alive
        }

        fn registers(&mut self, handle: usize) -> Option<(usize, usize)> {
            if self.should_fail(Op::Rip) {
                return None;
            }
            self.thread(handle).synced = true;
            Some((0x1000 + handle, 0x10000 * (handle + 1)))
        }

        fn stack_base(&mut self, handle: usize) -> Option<usize> {
            let words = self.stacks.get(handle).map_or(0, Vec::len);
            Some(0x10000 * (handle + 1) + words * 8)
        }

        fn read_words(&mut self, address: usize, out: &mut [u64]) -> bool {
            if self.should_fail(Op::Stack) {
                return false;
            }
            let handle = address / 0x10000 - 1;
            let first = (address % 0x10000) / 8;
            let Some(stack) = self.stacks.get(handle) else {
                return false;
            };
            let Some(words) = stack.get(first..first + out.len()) else {
                return false;
            };
            out.copy_from_slice(words);
            true
        }

        fn close(&mut self, handle: usize) {
            let thread = self.thread(handle);
            assert!(thread.open, "handle closed twice");
            thread.open = false;
        }

        fn pause(&mut self) {}
    }

    /// Every live thread is running and every handle is closed.
    fn assert_released(fake: &Fake) {
        for thread in &fake.threads {
            if thread.alive {
                assert_eq!(
                    thread.suspend_count, 0,
                    "thread {} left suspended",
                    thread.id
                );
            }
            assert!(!thread.open, "thread {} handle left open", thread.id);
        }
    }

    #[test]
    fn freeze_suspends_everything_and_thaw_releases_it() {
        let mut fake = Fake::new(&[1, 2, 3]);
        let freeze = Freeze::acquire(&mut fake).expect("freeze");
        assert!(freeze.any_rip_in(0x1000, 0x1001));
        assert!(!freeze.any_rip_in(0x2000, 0x3000));
        assert_eq!(freeze.threads.len(), 3);
        freeze.thaw().expect("thaw");
        assert_released(&fake);
    }

    #[test]
    fn drop_thaws_a_freeze() {
        let mut fake = Fake::new(&[1, 2]);
        drop(Freeze::acquire(&mut fake).expect("freeze"));
        assert_released(&fake);
    }

    #[test]
    fn every_single_acquire_failure_aborts_and_releases() {
        // Three threads, so each op runs several times; fail each call in turn.
        for op in [Op::Enumerate, Op::Open, Op::Suspend, Op::Rip] {
            for nth in 0..4 {
                let mut fake = Fake::new(&[1, 2, 3]);
                fake = fake.failing(op, nth, false);
                let outcome = Freeze::acquire(&mut fake).map(Freeze::thaw);
                let reached = fake.calls[op as usize] > nth;
                match outcome {
                    Ok(thawed) => {
                        assert!(!reached, "{op:?} #{nth} failure was ignored");
                        thawed.expect("thaw");
                    }
                    Err(error) => {
                        assert!(reached);
                        assert!(matches!(error, AcquireError::Aborted(_)), "{op:?} #{nth}");
                    }
                }
                assert_released(&fake);
            }
        }
    }

    #[test]
    fn enumeration_status_errors_abort_rather_than_finish() {
        let mut fake = Fake::new(&[1, 2]).failing(Op::Enumerate, 1, false);
        fake.enumerate_error = FreezeError::BufferTooSmall;
        let error = Freeze::acquire(&mut fake).err().expect("abort");
        assert_eq!(error, AcquireError::Aborted(FreezeError::BufferTooSmall));
        assert_released(&fake);
    }

    #[test]
    fn late_threads_are_suspended() {
        let mut fake = Fake::new(&[1]);
        fake.spawn_after = vec![(0, 7)];
        let freeze = Freeze::acquire(&mut fake).expect("freeze");
        assert_eq!(freeze.threads.len(), 2);
        freeze.thaw().expect("thaw");
        assert_released(&fake);
    }

    #[test]
    fn threads_that_keep_appearing_abort_the_freeze() {
        let mut fake = Fake::new(&[1]);
        fake.spawn_after = (0..10)
            .map(|call| (call, 100 + u32::try_from(call).unwrap()))
            .collect();
        let error = Freeze::acquire(&mut fake).err().expect("abort");
        assert_eq!(error, AcquireError::Aborted(FreezeError::KeptAppearing));
        assert_released(&fake);
    }

    #[test]
    fn transient_resume_failure_is_retried() {
        let mut fake = Fake::new(&[1, 2]).failing(Op::Resume, 0, false);
        let freeze = Freeze::acquire(&mut fake).expect("freeze");
        freeze.thaw().expect("retry succeeds");
        assert_released(&fake);
    }

    #[test]
    fn stuck_thread_keeps_its_handle_and_reports_failure() {
        let mut fake = Fake::new(&[1, 2]).failing(Op::Resume, 0, true);
        let freeze = Freeze::acquire(&mut fake).expect("freeze");
        assert_eq!(freeze.thaw(), Err(FreezeError::Resume));
        for thread in &fake.threads {
            assert_eq!(thread.suspend_count, 1);
            assert!(thread.open, "a stuck thread's handle must stay open");
        }
    }

    #[test]
    fn resume_failure_on_an_exited_thread_is_not_terminal() {
        let mut fake = Fake::new(&[1]).failing(Op::Resume, 0, true);
        fake.exit_on_failed_resume = true;
        let freeze = Freeze::acquire(&mut fake).expect("freeze");
        freeze.thaw().expect("exited thread needs no resume");
        assert_released(&fake);
    }

    #[test]
    fn abort_that_cannot_resume_is_terminal() {
        let mut fake = Fake::new(&[1, 2])
            .failing(Op::Rip, 1, false)
            .failing(Op::Resume, 0, true);
        let error = Freeze::acquire(&mut fake).err().expect("abort");
        assert_eq!(error, AcquireError::Terminal(FreezeError::Context));
        assert!(
            fake.threads
                .iter()
                .all(|thread| thread.open && thread.suspend_count == 1)
        );
    }

    #[test]
    fn dropping_a_freeze_with_a_stuck_thread_keeps_its_handle() {
        let mut fake = Fake::new(&[1, 2]).failing(Op::Resume, 1, true);
        drop(Freeze::acquire(&mut fake).expect("freeze"));
        // Thread 1 resumed on the first try; thread 2 never does.
        assert!(!fake.threads[0].open);
        assert!(fake.threads[1].open);
    }

    #[test]
    fn live_freeze_stops_and_releases_a_real_thread() {
        use std::sync::Arc;
        use std::sync::atomic::AtomicU64;

        const SENTINEL: u64 = 0x5EAF_00D5_1234_5678;
        let counter = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let (counter, stop) = (Arc::clone(&counter), Arc::clone(&stop));
            std::thread::spawn(move || {
                // Keep a recognizable word on this thread's stack for the scan.
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
        let freeze = Freeze::acquire(LiveOps::new().expect("buffer")).expect("freeze");
        // Nothing below may allocate or panic until the thaw: a frozen test
        // thread may hold the heap lock.
        let mut freeze = freeze;
        let frozen = freeze.threads.len();
        let sentinel = usize::try_from(SENTINEL).unwrap_or(0);
        let found = freeze.any_stack_word_in(sentinel, sentinel + 1);
        let before = counter.load(Ordering::Relaxed);
        // SAFETY: Sleep takes a plain duration.
        unsafe { Sleep(20) };
        let after = counter.load(Ordering::Relaxed);
        let thawed = freeze.thaw();
        thawed.expect("thaw");
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

    #[test]
    fn stack_scan_finds_a_return_address_anywhere_on_any_stack() {
        let mut fake = Fake::new(&[1, 2]);
        let mut deep = vec![0u64; 200];
        deep[150] = 0x5005;
        fake.stacks = vec![vec![1, 2, 3], deep];
        let mut freeze = Freeze::acquire(&mut fake).expect("freeze");
        assert_eq!(freeze.any_stack_word_in(0x5000, 0x5010), Ok(true));
        assert_eq!(freeze.any_stack_word_in(0x5006, 0x5010), Ok(false));
        assert_eq!(freeze.any_stack_word_in(1, 2), Ok(true));
        freeze.thaw().expect("thaw");
        assert_released(&fake);
    }

    #[test]
    fn unreadable_stack_is_an_error_not_a_clean_scan() {
        let mut fake = Fake::new(&[1]).failing(Op::Stack, 0, false);
        fake.stacks = vec![vec![0; 4]];
        let mut freeze = Freeze::acquire(&mut fake).expect("freeze");
        assert_eq!(freeze.any_stack_word_in(0, 1), Err(FreezeError::Stack));
        freeze.thaw().expect("thaw");
        assert_released(&fake);
    }

    #[test]
    fn id_set_is_bounded_and_deduplicated() {
        let mut set = IdSet::new();
        set.insert(5).unwrap();
        set.insert(5).unwrap();
        assert_eq!(set.as_slice(), &[5]);
        for id in 0..u32::try_from(MAX_THREADS).unwrap() - 1 {
            set.insert(1000 + id).unwrap();
        }
        assert_eq!(set.insert(9), Err(FreezeError::TooManyThreads));
    }

    fn process_entry(next: u32, pid: u64, tids: &[u64]) -> Vec<u8> {
        let mut entry = vec![0u8; PROCESS_ENTRY_SIZE + tids.len() * THREAD_ENTRY_SIZE];
        entry[0..4].copy_from_slice(&next.to_le_bytes());
        entry[4..8].copy_from_slice(&u32::try_from(tids.len()).unwrap().to_le_bytes());
        entry[PROCESS_ID..PROCESS_ID + 8].copy_from_slice(&pid.to_le_bytes());
        for (index, tid) in tids.iter().enumerate() {
            let at = PROCESS_ENTRY_SIZE + index * THREAD_ENTRY_SIZE + THREAD_CLIENT_ID_THREAD;
            entry[at..at + 8].copy_from_slice(&tid.to_le_bytes());
        }
        entry
    }

    #[test]
    fn parses_the_own_process_and_skips_the_caller() {
        let next = u32::try_from(PROCESS_ENTRY_SIZE + THREAD_ENTRY_SIZE).unwrap();
        let mut buffer = process_entry(next, 3, &[1]);
        buffer.extend_from_slice(&process_entry(0, 77, &[10, 11, 12]));
        let mut ids = IdSet::new();
        parse_process_threads(&buffer, 77, 11, &mut ids).unwrap();
        assert_eq!(ids.as_slice(), &[10, 12]);
    }

    #[test]
    fn missing_process_or_truncated_buffer_is_an_error() {
        let buffer = process_entry(0, 3, &[1]);
        let mut ids = IdSet::new();
        assert_eq!(
            parse_process_threads(&buffer, 77, 0, &mut ids),
            Err(FreezeError::Enumerate)
        );
        let full = process_entry(0, 77, &[1, 2]);
        let truncated = &full[..PROCESS_ENTRY_SIZE + THREAD_ENTRY_SIZE + THREAD_CLIENT_ID_THREAD];
        assert_eq!(
            parse_process_threads(truncated, 77, 0, &mut ids),
            Err(FreezeError::Enumerate)
        );
        let looping = process_entry(u32::MAX, 3, &[]);
        assert_eq!(
            parse_process_threads(&looping, 77, 0, &mut ids),
            Err(FreezeError::Enumerate)
        );
    }
}
