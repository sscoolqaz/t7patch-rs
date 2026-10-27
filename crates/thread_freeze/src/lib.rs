//! Process-local thread freezing, shared by T7Patch-rs and its vendored `MinHook`
//! port.
//!
//! Writing executable code, or moving a thread out of a trampoline, may only
//! happen while no other thread can be executing the bytes being replaced. This
//! crate suspends every other thread of the process, captures one register context
//! per thread, and lets the caller decide what to do from the captured state. The
//! policy — bounded attempts, late threads never suspended, a thread counted exited
//! only when its handle is signaled, a terminal latch on a failed resume — is the
//! one both callers used to carry separately.
//!
//! Nothing here allocates, frees, formats, panics or takes a lock once a thread is
//! suspended: a suspended thread may hold the process heap or loader lock. Buffers
//! are sized before the first suspension, ids live in fixed arrays, and a failed
//! thaw leaks its handles and buffers rather than dropping them (a dropped
//! allocation could deadlock on the held heap lock).
//!
//! The Win32 and ntdll calls sit behind [`ThreadOps`], so the logic is tested with
//! a fake that fails any call on demand.

#![cfg_attr(not(test), no_std)]

// A release build must never carry the test seams. Dev-dependencies enable the
// feature for the callers' tests, where debug assertions are on.
#[cfg(all(feature = "test-seams", not(debug_assertions)))]
compile_error!(
    "the `test-seams` feature is for tests only and must not be enabled in a release build"
);

extern crate alloc;

use alloc::vec::Vec;
use core::mem::ManuallyDrop;

mod live;
mod scan;

pub use live::{LiveOps, parse_process_threads};
pub use scan::{Scan, scan_stack};

/// Clears the terminal thaw latch. Test-only: production never clears it. The
/// `test-seams` feature exposes it to the callers' test wrappers, and the
/// `compile_error!` above makes a release build that enables the feature fail.
#[cfg(any(test, feature = "test-seams"))]
pub fn reset_thaw_failed() {
    live::clear_thaw_failed();
}

/// Upper bound on the threads one freeze may hold. A game process has far fewer.
pub const MAX_THREADS: usize = 512;
/// How many freeze attempts may be disturbed before the freeze is abandoned.
const FREEZE_ATTEMPTS: usize = 16;
/// How many times a failed resume is retried before the thread is declared stuck.
const RESUME_ATTEMPTS: usize = 3;
/// Most results one `NtGetNextThread` walk may return before it is treated as a
/// disturbance: the thread list can be walked while it is changing, so a creation
/// storm must not spin here forever. Counts self, duplicates and exited threads.
const MAX_WALK: usize = 2 * MAX_THREADS;

/// A freeze failure. Static, so it can be built while threads are suspended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FreezeError {
    Enumerate,
    BufferTooSmall,
    TooManyThreads,
    Open,
    Suspend,
    Context,
    Wait,
    Starting,
    KeptAppearing,
    Resume,
    Disabled,
    Stack,
}

impl FreezeError {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enumerate => "cannot enumerate game threads",
            Self::BufferTooSmall => "game thread list outgrew the preallocated buffer",
            Self::TooManyThreads => "too many threads to freeze",
            Self::Open => "cannot open a game thread",
            Self::Suspend => "cannot suspend a game thread",
            Self::Context => "cannot read a game thread context",
            Self::Wait => "cannot tell whether a game thread exited",
            Self::Starting => "a game thread kept starting during the freeze",
            Self::KeptAppearing => "game threads kept appearing during the freeze",
            Self::Resume => "cannot resume every game thread",
            Self::Disabled => "code writes are disabled after a failed thread resume",
            Self::Stack => "cannot read a game thread stack",
        }
    }
}

/// How an acquire failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcquireError {
    /// Every suspended thread was resumed.
    Aborted(FreezeError),
    /// The abort itself could not resume a thread. Terminal for the process.
    Terminal(FreezeError),
}

/// Whether a thread has terminated, from its handle's signaled state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Liveness {
    Exited,
    Running,
    /// The query failed, so nothing is known.
    Unknown,
}

/// Why an open did not produce a handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenError {
    /// The thread exited before it was opened; it cannot execute.
    Gone,
    Failed,
}

/// One step of an [`ThreadOps::next_thread`] walk.
pub enum NextThread<H> {
    /// A handle the walk opened for us; the caller owns and closes it.
    Thread(H),
    /// The walk is finished.
    Done,
    /// The walk failed.
    Failed,
}

/// A captured thread context. The control registers (RIP, RSP) and the integer
/// registers (RAX..R15) are captured; a move writes back the control set only.
#[derive(Clone, Copy)]
pub struct Context(live::AlignedContext);

impl Context {
    #[must_use]
    fn blank() -> Self {
        Self(live::AlignedContext::captured())
    }

    /// The instruction pointer.
    #[must_use]
    pub fn rip(&self) -> usize {
        self.0.rip()
    }

    /// The stack pointer.
    #[must_use]
    pub fn rsp(&self) -> usize {
        self.0.rsp()
    }

    /// The general-purpose registers, RSP included.
    #[must_use]
    pub fn registers(&self) -> [u64; 16] {
        self.0.registers()
    }

    /// A copy that resumes at `ip`, writing back only the control registers.
    #[must_use]
    pub fn moved_to(&self, ip: usize) -> Self {
        Self(self.0.moved_to(ip))
    }

    /// A blank captured context. Test-only.
    #[cfg(any(test, feature = "test-seams"))]
    #[must_use]
    pub fn test_blank() -> Self {
        Self::blank()
    }

    /// Sets RIP and RSP directly. Test-only, for a fake `ThreadOps::capture`.
    #[cfg(any(test, feature = "test-seams"))]
    pub fn set_test(&mut self, rip: usize, rsp: usize) {
        self.0.set_test(rip, rsp);
    }

    /// Sets R13 directly. Test-only, to check a move preserves the integer registers.
    #[cfg(any(test, feature = "test-seams"))]
    pub fn set_test_r13(&mut self, value: u64) {
        self.0.set_test_r13(value);
    }

    /// Whether only the control registers would be written back. Test-only.
    #[cfg(any(test, feature = "test-seams"))]
    #[must_use]
    pub fn is_control_only(&self) -> bool {
        self.0.is_control_only()
    }
}

/// The thread operations a freeze needs. None of them may allocate.
pub trait ThreadOps {
    type Handle: Copy;

    /// Fills `ids` with every thread of the process except the caller. May allocate
    /// (it runs only while nothing is suspended).
    ///
    /// # Errors
    ///
    /// Returns why the process could not be enumerated.
    fn enumerate(&mut self, ids: &mut IdSet) -> Result<(), FreezeError>;

    /// A value that changes whenever a thread or process starts or exits anywhere in
    /// the prefix, read without allocating, or `None` if it could not be read. Used
    /// on Wine to notice a thread the frozen walk could not see. `None` on a platform
    /// that rechecks by [`ThreadOps::enumerate`] instead.
    fn fingerprint(&mut self) -> Option<usize>;

    /// Whether the frozen recheck walks with [`ThreadOps::next_thread`] (Wine) or
    /// re-enumerates with [`ThreadOps::enumerate`] (Windows).
    fn walks_when_frozen(&self) -> bool;

    /// Opens a handle to thread `id`.
    ///
    /// # Errors
    ///
    /// Returns [`OpenError::Gone`] if the thread has exited, or [`OpenError::Failed`]
    /// if it could not be opened for another reason.
    fn open(&mut self, id: u32) -> Result<Self::Handle, OpenError>;
    fn suspend(&mut self, handle: Self::Handle) -> bool;
    fn resume(&mut self, handle: Self::Handle) -> bool;
    fn liveness(&mut self, handle: Self::Handle) -> Liveness;
    /// Whether the suspended thread has started (has a TEB), or `None` if that
    /// cannot be read. Never blocks.
    fn started(&mut self, handle: Self::Handle) -> Option<bool>;
    /// Reads the suspended thread's control and integer registers.
    fn capture(&mut self, handle: Self::Handle, context: &mut Context) -> bool;
    /// Writes a thread's control registers back.
    fn set_context(&mut self, handle: Self::Handle, context: &Context) -> bool;
    /// The top (highest address) of the suspended thread's stack.
    fn stack_base(&mut self, handle: Self::Handle) -> Option<usize>;
    /// Reads `out.len()` words at `address` without faulting.
    fn read_words(&mut self, address: usize, out: &mut [u64]) -> bool;
    fn close(&mut self, handle: Self::Handle);
    /// Waits briefly before a resume is retried.
    fn pause(&mut self);

    /// One step of a frozen-recheck walk: `None` cursor starts it, otherwise it
    /// continues from the handle last returned. Only called when
    /// [`ThreadOps::walks_when_frozen`] is true. The caller closes each handle.
    fn next_thread(&mut self, cursor: Option<Self::Handle>) -> NextThread<Self::Handle>;
    /// The thread id of a handle, or `None` on failure.
    fn thread_id(&mut self, handle: Self::Handle) -> Option<u32>;
    /// This thread's id.
    fn current_thread_id(&self) -> u32;
}

/// A fixed-capacity, duplicate-free set of thread ids. Never allocates.
pub struct IdSet {
    ids: [u32; MAX_THREADS],
    len: usize,
}

impl Default for IdSet {
    fn default() -> Self {
        Self::new()
    }
}

impl IdSet {
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ids: [0; MAX_THREADS],
            len: 0,
        }
    }

    pub fn clear(&mut self) {
        self.len = 0;
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u32] {
        &self.ids[..self.len]
    }

    #[must_use]
    pub fn contains(&self, id: u32) -> bool {
        self.as_slice().contains(&id)
    }

    /// Drops the last `n` ids. Test-only, for a fault wrapper that hides threads
    /// from one enumeration so they appear only in the frozen recheck.
    #[cfg(any(test, feature = "test-seams"))]
    pub fn drop_last(&mut self, n: usize) {
        self.len = self.len.saturating_sub(n);
    }

    /// Adds `id` unless it is already present. Used by live enumeration too.
    ///
    /// # Errors
    ///
    /// Returns [`FreezeError::TooManyThreads`] if the set is full.
    pub fn insert(&mut self, id: u32) -> Result<(), FreezeError> {
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

struct FrozenThread<H> {
    handle: H,
    context: Context,
}

/// What [`Freeze::open_suspend`] found.
enum Suspension {
    Held,
    Gone,
    Disturbed(FreezeError),
}

/// A suspended set of threads and the context captured for each. The handles,
/// contexts and ops are held in [`ManuallyDrop`] fields so that a failed thaw can
/// leak them deliberately: dropping a `Vec` could take the heap lock a stuck thread
/// holds.
pub struct Freeze<O: ThreadOps> {
    ops: ManuallyDrop<O>,
    threads: ManuallyDrop<Vec<FrozenThread<O::Handle>>>,
    active: bool,
    /// Set once a thaw left a thread suspended. Neither `thaw` nor `Drop` may free
    /// the handles or buffers after this: a stuck thread may hold the heap lock.
    leaked: bool,
}

impl<O: ThreadOps> Freeze<O> {
    /// Suspends every other thread of the process. A disturbed attempt is thawed and
    /// retried, up to [`FREEZE_ATTEMPTS`] times. On failure every suspended thread is
    /// resumed before this returns, or the error is [`AcquireError::Terminal`].
    ///
    /// # Errors
    ///
    /// Returns why the freeze could not be taken.
    pub fn acquire(ops: O) -> Result<Self, AcquireError> {
        // All allocation happens before the first suspension.
        let mut freeze = Self {
            ops: ManuallyDrop::new(ops),
            threads: ManuallyDrop::new(Vec::with_capacity(MAX_THREADS)),
            active: false,
            leaked: false,
        };
        let mut seen = IdSet::new();
        let mut gone = IdSet::new();
        let mut fresh = IdSet::new();
        let mut disturbed = FreezeError::KeptAppearing;
        for attempt in 0..FREEZE_ATTEMPTS {
            if attempt > 0 {
                // Let a starting or exiting thread settle. Never wait while threads
                // are suspended: the thread may need one of them.
                freeze.ops.pause();
            }
            seen.clear();
            gone.clear();
            freeze.active = true;
            match freeze.attempt(&mut seen, &mut gone, &mut fresh) {
                Ok(None) => return Ok(freeze),
                Ok(Some(error)) => {
                    disturbed = error;
                    if freeze.thaw_inner().is_err() {
                        return Err(AcquireError::Terminal(error));
                    }
                }
                Err(error) => return Err(freeze.abort(error)),
            }
        }
        Err(AcquireError::Aborted(disturbed))
    }

    // One attempt. A full enumeration (which may allocate) snapshots the candidate
    // ids while nothing is suspended; only those ids are ever suspended, so a thread
    // created during the freeze is never suspended. Under Wine a fingerprint of the
    // whole prefix is read first, so a thread the frozen walk cannot see still shows
    // as a change. Returns the disturbance, or `None` once frozen.
    fn attempt(
        &mut self,
        seen: &mut IdSet,
        gone: &mut IdSet,
        fresh: &mut IdSet,
    ) -> Result<Option<FreezeError>, FreezeError> {
        let fingerprint_before = if self.ops.walks_when_frozen() {
            match self.ops.fingerprint() {
                Some(value) => Some(value),
                None => return Ok(Some(FreezeError::Enumerate)),
            }
        } else {
            None
        };

        fresh.clear();
        self.ops.enumerate(fresh)?;
        for &id in fresh.as_slice() {
            match self.open_suspend(id)? {
                Suspension::Held => seen.insert(id)?,
                Suspension::Gone => gone.insert(id)?,
                Suspension::Disturbed(error) => return Ok(Some(error)),
            }
        }
        for index in 0..self.threads.len() {
            let handle = self.threads[index].handle;
            match self.ops.started(handle) {
                Some(true) => {}
                Some(false) => return Ok(Some(FreezeError::Starting)),
                None => return Ok(Some(FreezeError::Context)),
            }
            let mut context = Context::blank();
            if !self.ops.capture(handle, &mut context) {
                return Ok(Some(FreezeError::Context));
            }
            self.threads[index].context = context;
        }

        if self.ops.walks_when_frozen() {
            self.recheck_walk(seen, fingerprint_before)
        } else {
            self.recheck_enumerate(seen, gone, fresh)
        }
    }

    /// Windows recheck: enumerate again (a plain syscall there) and require every id
    /// to be held or confirmed gone.
    fn recheck_enumerate(
        &mut self,
        seen: &mut IdSet,
        gone: &mut IdSet,
        fresh: &mut IdSet,
    ) -> Result<Option<FreezeError>, FreezeError> {
        fresh.clear();
        self.ops.enumerate(fresh)?;
        for &id in fresh.as_slice() {
            let known = seen.contains(id) || (gone.contains(id) && self.still_gone(id)?);
            if !known {
                return Ok(Some(FreezeError::KeptAppearing));
            }
        }
        Ok(None)
    }

    /// Wine recheck: walk the live thread list with `NtGetNextThread`, which does not
    /// allocate on Wine's Unix side, and confirm the prefix fingerprint is unchanged.
    /// A listed thread that is neither this one nor already held, and has not exited,
    /// was created during the freeze: never suspended, the attempt restarts.
    fn recheck_walk(
        &mut self,
        seen: &mut IdSet,
        fingerprint_before: Option<usize>,
    ) -> Result<Option<FreezeError>, FreezeError> {
        let current = self.ops.current_thread_id();
        let mut cursor = None;
        for _ in 0..MAX_WALK {
            let handle = match self.ops.next_thread(cursor) {
                NextThread::Thread(handle) => handle,
                NextThread::Done => {
                    if let Some(cursor) = cursor {
                        self.ops.close(cursor);
                    }
                    return Ok(self.check_fingerprint(fingerprint_before));
                }
                NextThread::Failed => {
                    if let Some(cursor) = cursor {
                        self.ops.close(cursor);
                    }
                    return Err(FreezeError::Enumerate);
                }
            };
            if let Some(cursor) = cursor {
                self.ops.close(cursor);
            }
            cursor = Some(handle);

            let Some(id) = self.ops.thread_id(handle) else {
                self.ops.close(handle);
                return Err(FreezeError::Enumerate);
            };
            if id == current || seen.contains(id) {
                continue;
            }
            // A thread the snapshot missed: never suspend it.
            match self.ops.liveness(handle) {
                Liveness::Exited => {}
                Liveness::Running => {
                    self.ops.close(handle);
                    return Ok(Some(FreezeError::KeptAppearing));
                }
                Liveness::Unknown => {
                    self.ops.close(handle);
                    return Err(FreezeError::Wait);
                }
            }
        }
        // The walk never settled: treat it as threads that keep appearing.
        if let Some(cursor) = cursor {
            self.ops.close(cursor);
        }
        Ok(Some(FreezeError::KeptAppearing))
    }

    fn check_fingerprint(&mut self, before: Option<usize>) -> Option<FreezeError> {
        match self.ops.fingerprint() {
            Some(after) if Some(after) == before => None,
            Some(_) => Some(FreezeError::KeptAppearing),
            None => Some(FreezeError::Enumerate),
        }
    }

    /// Opens and suspends `id`.
    fn open_suspend(&mut self, id: u32) -> Result<Suspension, FreezeError> {
        let handle = match self.ops.open(id) {
            Ok(handle) => handle,
            Err(OpenError::Gone) => return Ok(Suspension::Gone),
            Err(OpenError::Failed) => return Ok(Suspension::Disturbed(FreezeError::Open)),
        };
        if !self.ops.suspend(handle) {
            let state = self.ops.liveness(handle);
            self.ops.close(handle);
            return match state {
                Liveness::Exited => Ok(Suspension::Gone),
                Liveness::Running => Ok(Suspension::Disturbed(FreezeError::Suspend)),
                Liveness::Unknown => Err(FreezeError::Wait),
            };
        }
        if self.threads.len() >= self.threads.capacity() {
            // Unreachable while `seen` caps ids at MAX_THREADS, but never grow here.
            self.resume_one(handle);
            return Err(FreezeError::TooManyThreads);
        }
        self.threads.push(FrozenThread {
            handle,
            context: Context::blank(),
        });
        Ok(Suspension::Held)
    }

    /// True when `id` names no live thread of this process. An id that cannot be
    /// opened counts as live, so the caller retries rather than trusting it.
    fn still_gone(&mut self, id: u32) -> Result<bool, FreezeError> {
        match self.ops.open(id) {
            Ok(handle) => {
                let state = self.ops.liveness(handle);
                self.ops.close(handle);
                match state {
                    Liveness::Exited => Ok(true),
                    Liveness::Running => Ok(false),
                    Liveness::Unknown => Err(FreezeError::Wait),
                }
            }
            Err(OpenError::Gone) => Ok(true),
            Err(OpenError::Failed) => Ok(false),
        }
    }

    fn abort(&mut self, error: FreezeError) -> AcquireError {
        if self.thaw_inner().is_ok() {
            AcquireError::Aborted(error)
        } else {
            AcquireError::Terminal(error)
        }
    }

    /// How many threads are frozen.
    #[must_use]
    pub fn len(&self) -> usize {
        self.threads.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.threads.is_empty()
    }

    /// The captured context of frozen thread `index`.
    #[must_use]
    pub fn context(&self, index: usize) -> &Context {
        &self.threads[index].context
    }

    /// Writes thread `index`'s control registers back to resume at `context`'s RIP.
    #[must_use]
    pub fn set_context(&mut self, index: usize, context: &Context) -> bool {
        let handle = self.threads[index].handle;
        self.ops.set_context(handle, context)
    }

    /// The thread id of frozen thread `index`, or `None` if it could not be read.
    #[must_use]
    pub fn thread_id(&mut self, index: usize) -> Option<u32> {
        let handle = self.threads[index].handle;
        self.ops.thread_id(handle)
    }

    /// Scans frozen thread `index`'s live stack, from RSP up to its stack base, for a
    /// word `want` accepts. A missing stack base or a short read is [`Scan::Unknown`].
    pub fn scan_thread_stack(
        &mut self,
        index: usize,
        budget: &mut usize,
        want: impl FnMut(u64) -> bool,
    ) -> Scan {
        let handle = self.threads[index].handle;
        let rsp = self.threads[index].context.rsp();
        let Some(base) = self.ops.stack_base(handle) else {
            return Scan::Unknown;
        };
        scan::scan_stack(rsp, base, budget, want, |address, out| {
            self.ops.read_words(address, out)
        })
    }

    /// True when any frozen thread's instruction pointer is in `[start, end)`.
    #[must_use]
    pub fn any_rip_in(&self, start: usize, end: usize) -> bool {
        self.threads
            .iter()
            .any(|thread| half_open(thread.context.rip(), start, end))
    }

    /// Scans every frozen thread's live stack, from RSP up to its stack base, for a
    /// word `want` accepts. `Clear` only if every stack was fully readable.
    ///
    /// # Errors
    ///
    /// Returns [`FreezeError::Stack`] if any stack could not be read in full.
    pub fn scan_stacks(
        &mut self,
        budget: &mut usize,
        mut want: impl FnMut(u64) -> bool,
    ) -> Result<bool, FreezeError> {
        for index in 0..self.threads.len() {
            let handle = self.threads[index].handle;
            let rsp = self.threads[index].context.rsp();
            let Some(base) = self.ops.stack_base(handle) else {
                return Err(FreezeError::Stack);
            };
            let hit = scan::scan_stack(rsp, base, budget, &mut want, |address, out| {
                self.ops.read_words(address, out)
            });
            match hit {
                Scan::Clear => {}
                Scan::Hit => return Ok(true),
                Scan::Unknown => return Err(FreezeError::Stack),
            }
        }
        Ok(false)
    }

    /// Resumes every thread exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`FreezeError::Resume`] if a thread stayed suspended. The handles and
    /// buffers are then leaked (see the type docs); the caller must treat the freeze
    /// as terminal.
    pub fn thaw(mut self) -> Result<(), FreezeError> {
        let result = self.thaw_inner();
        if !self.leaked {
            // SAFETY: nothing is leaked, so `threads` is empty; drop ops and the
            // empty vec now. A leaked freeze keeps both, forgotten below.
            unsafe {
                ManuallyDrop::drop(&mut self.threads);
                ManuallyDrop::drop(&mut self.ops);
            }
        }
        core::mem::forget(self);
        result
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
        if failed {
            // A thread stays suspended: leak the handles and buffers rather than drop
            // them, and mark the process terminal. The caller stops here.
            self.leaked = true;
            live::set_thaw_failed();
            return Err(FreezeError::Resume);
        }
        self.threads.clear();
        Ok(())
    }

    /// Resumes `handle`, retrying a failure. Closed only once the thread runs again
    /// or has exited; a thread that stays suspended keeps its handle.
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
        if self.ops.liveness(handle) == Liveness::Exited {
            self.ops.close(handle);
            return true;
        }
        false
    }
}

impl<O: ThreadOps> Drop for Freeze<O> {
    fn drop(&mut self) {
        // Safety net for an early return or panic. A failed thaw (here or earlier)
        // leaves `leaked` set, and then the handles and buffers are kept, never
        // dropped: a stuck thread may hold the heap lock.
        let _ = self.thaw_inner();
        if !self.leaked {
            // SAFETY: nothing leaked, so `threads` is empty; this drop runs once.
            unsafe {
                ManuallyDrop::drop(&mut self.threads);
                ManuallyDrop::drop(&mut self.ops);
            }
        }
    }
}

#[must_use]
fn half_open(value: usize, start: usize, end: usize) -> bool {
    value >= start && value < end
}

/// True once a freeze anywhere in the process left a live thread suspended.
#[must_use]
pub fn thaw_failed() -> bool {
    live::thaw_failed()
}

#[cfg(test)]
mod tests;
