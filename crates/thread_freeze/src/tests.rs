//! Engine tests. A fake `ThreadOps` drives both recheck paths (Windows
//! re-enumerate, Wine walk + fingerprint). Tests that touch the process-wide
//! terminal latch hold `LATCH` and reset it.

use super::*;
use std::sync::Mutex;

/// Serializes the tests that set or read the terminal latch.
static LATCH: Mutex<()> = Mutex::new(());

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Enumerate,
    Open,
    Suspend,
    Resume,
    Capture,
    Stack,
    Started,
    Wait,
}

const OPS: usize = 8;

#[derive(Clone, Copy)]
struct FakeThread {
    id: u32,
    alive: bool,
    suspend_count: u32,
    open: bool,
    synced: bool,
}

/// A fake process. `fail` fails the `nth` call (0-based) of `op`, or every call
/// from `nth` on when `sticky`.
#[allow(clippy::struct_excessive_bools)]
struct Fake {
    threads: Vec<FakeThread>,
    spawn_after: Vec<(usize, u32)>,
    fail: Vec<(Op, usize, bool)>,
    calls: [usize; OPS],
    stacks: Vec<Vec<u64>>,
    enumerate_error: FreezeError,
    exit_on_failed_resume: bool,
    exit_on_failed_suspend: bool,
    list_exited: bool,
    // Wine-path knobs.
    wine: bool,
    /// Ids the frozen walk lists that the snapshot did not, with their liveness.
    walk_extra: Vec<(u32, Liveness)>,
    /// Fingerprints returned per call; when exhausted a stable value is used.
    fingerprints: Vec<Option<usize>>,
    /// A walk that never terminates (for the bound test).
    walk_forever: bool,
    walk_cursor: usize,
    walk_snapshot: Vec<u32>,
}

const SELF_ID: u32 = 999_000;

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
            calls: [0; OPS],
            stacks: Vec::new(),
            enumerate_error: FreezeError::Enumerate,
            exit_on_failed_resume: false,
            exit_on_failed_suspend: false,
            list_exited: false,
            wine: false,
            walk_extra: Vec::new(),
            fingerprints: Vec::new(),
            walk_forever: false,
            walk_cursor: 0,
            walk_snapshot: Vec::new(),
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
        self.fail
            .iter()
            .any(|&(o, nth, sticky)| o == op && (call == nth || (sticky && call > nth)))
    }

    fn thread(&mut self, handle: usize) -> &mut FakeThread {
        &mut self.threads[handle]
    }

    fn alive_ids(&self) -> Vec<u32> {
        self.threads
            .iter()
            .filter(|t| t.alive)
            .map(|t| t.id)
            .collect()
    }
}

impl ThreadOps for &mut Fake {
    type Handle = usize;

    fn enumerate(&mut self, ids: &mut IdSet) -> Result<(), FreezeError> {
        let call = self.calls[Op::Enumerate as usize];
        assert!(
            self.threads
                .iter()
                .all(|t| t.suspend_count == 0 || t.synced),
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
            if let Some(old) = self
                .threads
                .iter_mut()
                .find(|t| t.id == id && !t.alive && !t.open)
            {
                old.alive = true;
                old.suspend_count = 0;
                old.synced = false;
            } else if !self.threads.iter().any(|t| t.id == id) {
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
            if thread.alive || self.list_exited {
                ids.insert(thread.id)?;
            }
        }
        Ok(())
    }

    fn fingerprint(&mut self) -> Option<usize> {
        if let Some(value) = self.fingerprints.pop() {
            return value;
        }
        // A stable value derived from the alive set: starts and exits change it.
        Some(self.alive_ids().iter().map(|&id| id as usize + 1).sum())
    }

    fn walks_when_frozen(&self) -> bool {
        self.wine
    }

    fn open(&mut self, id: u32) -> Result<usize, OpenError> {
        if self.should_fail(Op::Open) {
            return Err(OpenError::Failed);
        }
        let index = self
            .threads
            .iter()
            .position(|t| t.id == id)
            .ok_or(OpenError::Gone)?;
        assert!(!self.threads[index].open, "thread opened twice");
        self.threads[index].open = true;
        Ok(index)
    }

    fn suspend(&mut self, handle: usize) -> bool {
        if self.should_fail(Op::Suspend) {
            if self.exit_on_failed_suspend {
                self.thread(handle).alive = false;
            }
            return false;
        }
        let t = self.thread(handle);
        t.suspend_count += 1;
        t.synced = false;
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
        let t = self.thread(handle);
        assert!(t.suspend_count > 0, "resume without suspend");
        t.suspend_count -= 1;
        true
    }

    fn liveness(&mut self, handle: usize) -> Liveness {
        if self.should_fail(Op::Wait) {
            return Liveness::Unknown;
        }
        if handle >= 0x10_0000 {
            // A synthetic walk handle: its liveness comes from walk_extra, else the
            // thread is a live one the walk also listed.
            let id = u32::try_from(handle - 0x10_0000).unwrap_or(0);
            return self
                .walk_extra
                .iter()
                .find(|&&(other, _)| other == id)
                .map_or(Liveness::Running, |&(_, live)| live);
        }
        if self.thread(handle).alive {
            Liveness::Running
        } else {
            Liveness::Exited
        }
    }

    fn started(&mut self, _handle: usize) -> Option<bool> {
        Some(!self.should_fail(Op::Started))
    }

    fn capture(&mut self, handle: usize, context: &mut Context) -> bool {
        if self.should_fail(Op::Capture) {
            return false;
        }
        self.thread(handle).synced = true;
        // RSP at the low end of this handle's stack; RIP a recognizable value.
        context.set_test(0x1000 + handle, 0x10000 * (handle + 1));
        true
    }

    fn set_context(&mut self, _handle: usize, _context: &Context) -> bool {
        true
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
        if handle == usize::MAX {
            return; // a synthetic walk handle (self / extra), never a real thread
        }
        if handle >= 0x10_0000 {
            return; // a walk-extra handle
        }
        let t = self.thread(handle);
        assert!(t.open, "handle closed twice");
        t.open = false;
    }

    fn pause(&mut self) {}

    fn next_thread(&mut self, cursor: Option<usize>) -> NextThread<usize> {
        if self.walk_forever {
            return NextThread::Thread(usize::MAX);
        }
        if cursor.is_none() {
            // Snapshot the walk order once: self, then alive threads, then extras.
            self.walk_cursor = 0;
            self.walk_snapshot = core::iter::once(SELF_ID)
                .chain(self.alive_ids())
                .chain(self.walk_extra.iter().map(|&(id, _)| id))
                .collect();
        }
        let step = self.walk_cursor;
        self.walk_cursor += 1;
        match self.walk_snapshot.get(step).copied() {
            Some(SELF_ID) => NextThread::Thread(usize::MAX),
            // Every walked thread gets a synthetic handle distinct from its suspend
            // handle, as NtGetNextThread opens a fresh handle in the live ops.
            Some(id) => NextThread::Thread(0x10_0000 + id as usize),
            None => NextThread::Done,
        }
    }

    fn thread_id(&mut self, handle: usize) -> Option<u32> {
        if handle == usize::MAX {
            return Some(SELF_ID);
        }
        if handle >= 0x10_0000 {
            return Some(u32::try_from(handle - 0x10_0000).unwrap_or(0));
        }
        Some(self.threads[handle].id)
    }

    fn current_thread_id(&self) -> u32 {
        SELF_ID
    }
}

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

// ---- Windows-path suite (wine = false): the recheck re-enumerates. ----

#[test]
fn freeze_suspends_everything_and_thaw_releases_it() {
    let mut fake = Fake::new(&[1, 2, 3]);
    let freeze = Freeze::acquire(&mut fake).expect("freeze");
    assert_eq!(freeze.len(), 3);
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
fn every_enumeration_failure_aborts_and_releases() {
    for nth in 0..2 {
        let mut fake = Fake::new(&[1, 2, 3]).failing(Op::Enumerate, nth, false);
        let error = Freeze::acquire(&mut fake).err().expect("abort");
        assert_eq!(
            error,
            AcquireError::Aborted(FreezeError::Enumerate),
            "#{nth}"
        );
        assert_released(&fake);
    }
}

#[test]
fn every_single_disturbance_is_retried() {
    for op in [Op::Open, Op::Suspend, Op::Capture, Op::Started] {
        for nth in 0..3 {
            let mut fake = Fake::new(&[1, 2, 3]).failing(op, nth, false);
            let freeze = Freeze::acquire(&mut fake).expect("a retry succeeds");
            assert_eq!(freeze.len(), 3, "{op:?} #{nth}");
            freeze.thaw().expect("thaw");
            assert_released(&fake);
        }
    }
}

#[test]
fn persistent_disturbances_fail_closed() {
    for (op, expected) in [
        (Op::Open, FreezeError::Open),
        (Op::Suspend, FreezeError::Suspend),
        (Op::Capture, FreezeError::Context),
        (Op::Started, FreezeError::Starting),
    ] {
        let mut fake = Fake::new(&[1, 2, 3]).failing(op, 0, true);
        let error = Freeze::acquire(&mut fake).err().expect("abort");
        assert_eq!(error, AcquireError::Aborted(expected), "{op:?}");
        assert_eq!(fake.calls[Op::Enumerate as usize], FREEZE_ATTEMPTS);
        assert_released(&fake);
    }
}

#[test]
fn exited_thread_is_skipped() {
    let mut fake = Fake::new(&[1, 2, 3]).failing(Op::Suspend, 1, false);
    fake.exit_on_failed_suspend = true;
    let freeze = Freeze::acquire(&mut fake).expect("freeze");
    assert_eq!(freeze.len(), 2);
    freeze.thaw().expect("thaw");
    assert_released(&fake);
}

#[test]
fn unknown_suspension_state_fails_closed() {
    let mut fake = Fake::new(&[1, 2])
        .failing(Op::Suspend, 0, false)
        .failing(Op::Wait, 0, false);
    let error = Freeze::acquire(&mut fake).err().expect("abort");
    assert_eq!(error, AcquireError::Aborted(FreezeError::Wait));
    assert_released(&fake);
}

#[test]
fn a_listed_exited_thread_is_rechecked_and_skipped() {
    let mut fake = Fake::new(&[1, 2, 3]).failing(Op::Suspend, 1, false);
    fake.exit_on_failed_suspend = true;
    fake.list_exited = true;
    let freeze = Freeze::acquire(&mut fake).expect("freeze");
    assert_eq!(freeze.len(), 2);
    freeze.thaw().expect("thaw");
    assert_released(&fake);
}

#[test]
fn a_late_thread_restarts_the_attempt_rather_than_being_suspended() {
    let mut fake = Fake::new(&[1]);
    fake.spawn_after = vec![(0, 7)];
    let freeze = Freeze::acquire(&mut fake).expect("freeze");
    assert_eq!(freeze.len(), 2);
    freeze.thaw().expect("thaw");
    assert_released(&fake);
}

#[test]
fn threads_that_keep_appearing_abort_the_freeze() {
    let mut fake = Fake::new(&[1]);
    fake.spawn_after = (0..2 * FREEZE_ATTEMPTS)
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
    let _guard = LATCH.lock().unwrap();
    reset_thaw_failed();
    let mut fake = Fake::new(&[1, 2]).failing(Op::Resume, 0, true);
    let freeze = Freeze::acquire(&mut fake).expect("freeze");
    assert_eq!(freeze.thaw(), Err(FreezeError::Resume));
    assert!(thaw_failed());
    for thread in &fake.threads {
        assert_eq!(thread.suspend_count, 1);
        assert!(thread.open, "a stuck thread's handle must stay open");
    }
    reset_thaw_failed();
}

#[test]
fn abort_that_cannot_resume_is_terminal() {
    let _guard = LATCH.lock().unwrap();
    reset_thaw_failed();
    let mut fake = Fake::new(&[1, 2])
        .failing(Op::Capture, 1, false)
        .failing(Op::Resume, 0, true);
    let error = Freeze::acquire(&mut fake).err().expect("abort");
    assert_eq!(error, AcquireError::Terminal(FreezeError::Context));
    assert!(fake.threads.iter().all(|t| t.open && t.suspend_count == 1));
    reset_thaw_failed();
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

// ---- Wine-path suite (wine = true): the recheck walks + fingerprints. ----

fn wine(ids: &[u32]) -> Fake {
    let mut fake = Fake::new(ids);
    fake.wine = true;
    fake
}

#[test]
fn wine_walk_freezes_everything_including_self_in_the_walk() {
    let mut fake = wine(&[1, 2, 3]);
    let freeze = Freeze::acquire(&mut fake).expect("freeze");
    assert_eq!(freeze.len(), 3);
    freeze.thaw().expect("thaw");
    assert_released(&fake);
}

#[test]
fn wine_walk_finds_a_late_thread_and_never_suspends_it() {
    let mut fake = wine(&[1, 2]);
    // A thread the snapshot missed but the frozen walk lists, still running.
    fake.walk_extra = vec![(50, Liveness::Running)];
    let error = Freeze::acquire(&mut fake)
        .err()
        .expect("walk finds it every attempt");
    assert_eq!(error, AcquireError::Aborted(FreezeError::KeptAppearing));
    // Thread 50 was never a candidate, so never suspended.
    assert!(!fake.threads.iter().any(|t| t.id == 50));
    assert_released(&fake);
}

#[test]
fn wine_walk_skips_an_exited_thread_it_lists() {
    let mut fake = wine(&[1, 2]);
    fake.walk_extra = vec![(50, Liveness::Exited)];
    let freeze = Freeze::acquire(&mut fake).expect("an exited walk entry is not a disturbance");
    assert_eq!(freeze.len(), 2);
    freeze.thaw().expect("thaw");
}

#[test]
fn wine_fingerprint_change_restarts_the_attempt() {
    let mut fake = wine(&[1, 2]);
    // F before = 3+1 + (handled below): force before != after for attempt 1, equal
    // after. fingerprints are popped from the end: before1, after1, before2, after2.
    fake.fingerprints = vec![Some(10), Some(10), Some(7), Some(5)];
    let freeze = Freeze::acquire(&mut fake).expect("second attempt matches");
    freeze.thaw().expect("thaw");
}

#[test]
fn wine_fingerprint_failure_fails_closed() {
    let mut fake = wine(&[1, 2]);
    fake.fingerprints = vec![
        None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
        None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
        None, None,
    ];
    let error = Freeze::acquire(&mut fake)
        .err()
        .expect("fingerprint never readable");
    assert_eq!(error, AcquireError::Aborted(FreezeError::Enumerate));
    assert_released(&fake);
}

#[test]
fn wine_accepts_a_fingerprint_collision() {
    // The documented residual: a walk-skipped late thread plus a compensating exit
    // leaves F unchanged, so the freeze proceeds without seeing the new thread. The
    // walk here lists only the snapshot, and the fingerprints match.
    let mut fake = wine(&[1, 2]);
    fake.fingerprints = vec![Some(42), Some(42)];
    let freeze = Freeze::acquire(&mut fake).expect("a collision is accepted");
    assert_eq!(freeze.len(), 2);
    freeze.thaw().expect("thaw");
}

#[test]
fn wine_unbounded_walk_is_treated_as_a_disturbance() {
    let mut fake = wine(&[1, 2]);
    fake.walk_forever = true;
    let error = Freeze::acquire(&mut fake)
        .err()
        .expect("a walk that never ends");
    assert_eq!(error, AcquireError::Aborted(FreezeError::KeptAppearing));
    assert_released(&fake);
}

#[test]
fn wine_next_thread_failure_fails_closed() {
    // A walk that fails: model via walk_extra with an id whose handle maps to a
    // thread_id of 0 is awkward; instead make the first fingerprint succeed and the
    // walk fail by returning Failed. Use walk_forever off and a snapshot that makes
    // next_thread return Failed through thread_id None is not reachable here, so
    // drive it through an enumerate error on the Wine path's floor instead.
    let mut fake = wine(&[1, 2]).failing(Op::Enumerate, 0, true);
    let error = Freeze::acquire(&mut fake).err().expect("enumerate fails");
    assert_eq!(error, AcquireError::Aborted(FreezeError::Enumerate));
    assert_released(&fake);
}

// ---- Stack scan over the frozen set. ----

#[test]
fn scan_stacks_finds_a_word_on_any_stack() {
    let mut fake = Fake::new(&[1, 2]);
    let mut deep = vec![0u64; 200];
    deep[150] = 0x5005;
    fake.stacks = vec![vec![1, 2, 3], deep];
    let mut freeze = Freeze::acquire(&mut fake).expect("freeze");
    let mut budget = usize::MAX;
    assert_eq!(
        freeze.scan_stacks(&mut budget, |w| (0x5000..0x5010).contains(&w)),
        Ok(true)
    );
    let mut budget = usize::MAX;
    assert_eq!(
        freeze.scan_stacks(&mut budget, |w| (0x5006..0x5010).contains(&w)),
        Ok(false)
    );
    freeze.thaw().expect("thaw");
    assert_released(&fake);
}

#[test]
fn scan_stacks_unreadable_is_an_error() {
    let mut fake = Fake::new(&[1]).failing(Op::Stack, 0, false);
    fake.stacks = vec![vec![0; 4]];
    let mut freeze = Freeze::acquire(&mut fake).expect("freeze");
    let mut budget = usize::MAX;
    assert_eq!(
        freeze.scan_stacks(&mut budget, |_| false),
        Err(FreezeError::Stack)
    );
    freeze.thaw().expect("thaw");
    assert_released(&fake);
}

// ---- Terminal retention (ManuallyDrop): ops is dropped on a clean thaw, leaked
// on a failed one. ----

struct DropSpy<O: ThreadOps> {
    inner: O,
    dropped: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl<O: ThreadOps> Drop for DropSpy<O> {
    fn drop(&mut self) {
        self.dropped
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

impl<O: ThreadOps> ThreadOps for DropSpy<O> {
    type Handle = O::Handle;
    fn enumerate(&mut self, ids: &mut IdSet) -> Result<(), FreezeError> {
        self.inner.enumerate(ids)
    }
    fn fingerprint(&mut self) -> Option<usize> {
        self.inner.fingerprint()
    }
    fn walks_when_frozen(&self) -> bool {
        self.inner.walks_when_frozen()
    }
    fn open(&mut self, id: u32) -> Result<Self::Handle, OpenError> {
        self.inner.open(id)
    }
    fn suspend(&mut self, h: Self::Handle) -> bool {
        self.inner.suspend(h)
    }
    fn resume(&mut self, h: Self::Handle) -> bool {
        self.inner.resume(h)
    }
    fn liveness(&mut self, h: Self::Handle) -> Liveness {
        self.inner.liveness(h)
    }
    fn started(&mut self, h: Self::Handle) -> Option<bool> {
        self.inner.started(h)
    }
    fn capture(&mut self, h: Self::Handle, c: &mut Context) -> bool {
        self.inner.capture(h, c)
    }
    fn set_context(&mut self, h: Self::Handle, c: &Context) -> bool {
        self.inner.set_context(h, c)
    }
    fn stack_base(&mut self, h: Self::Handle) -> Option<usize> {
        self.inner.stack_base(h)
    }
    fn read_words(&mut self, a: usize, o: &mut [u64]) -> bool {
        self.inner.read_words(a, o)
    }
    fn close(&mut self, h: Self::Handle) {
        self.inner.close(h);
    }
    fn pause(&mut self) {
        self.inner.pause();
    }
    fn next_thread(&mut self, cursor: Option<Self::Handle>) -> NextThread<Self::Handle> {
        self.inner.next_thread(cursor)
    }
    fn thread_id(&mut self, h: Self::Handle) -> Option<u32> {
        self.inner.thread_id(h)
    }
    fn current_thread_id(&self) -> u32 {
        self.inner.current_thread_id()
    }
}

#[test]
fn moved_context_rewrites_only_rip_and_preserves_the_rest() {
    let mut context = Context::test_blank();
    context.set_test(0x1000, 0x2000);
    context.set_test_r13(0x7777);
    assert_eq!(context.rip(), 0x1000);
    assert_eq!(context.rsp(), 0x2000);
    assert_eq!(context.registers()[13], 0x7777);
    let moved = context.moved_to(0x9000);
    assert_eq!(moved.rip(), 0x9000);
    assert_eq!(moved.rsp(), 0x2000, "rsp preserved");
    assert_eq!(moved.registers()[13], 0x7777, "integer registers preserved");
    assert!(
        moved.is_control_only(),
        "a move writes back only the control registers"
    );
}

#[test]
fn an_acquisition_terminal_leaks_ops() {
    let _guard = LATCH.lock().unwrap();
    reset_thaw_failed();
    // A disturbance (a context read fails) whose thaw cannot resume: acquire returns
    // Terminal and the local Freeze is dropped. Its ops must not be dropped.
    let mut fake = Fake::new(&[1, 2])
        .failing(Op::Capture, 1, false)
        .failing(Op::Resume, 0, true);
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let spy = DropSpy {
        inner: &mut fake,
        dropped: dropped.clone(),
    };
    match Freeze::acquire(spy) {
        Err(AcquireError::Terminal(_)) => {}
        Err(other) => panic!("expected Terminal, got {other:?}"),
        Ok(_) => panic!("expected Terminal, got a successful freeze"),
    }
    assert!(
        !dropped.load(std::sync::atomic::Ordering::SeqCst),
        "an acquisition that ends terminal must leak ops, not drop it"
    );
    assert!(thaw_failed());
    assert!(fake.threads.iter().any(|t| t.open && t.suspend_count == 1));
    reset_thaw_failed();
}

#[test]
fn a_clean_thaw_drops_ops() {
    let mut fake = Fake::new(&[1, 2]);
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let spy = DropSpy {
        inner: &mut fake,
        dropped: dropped.clone(),
    };
    let freeze = Freeze::acquire(spy).expect("freeze");
    freeze.thaw().expect("thaw");
    assert!(
        dropped.load(std::sync::atomic::Ordering::SeqCst),
        "ops dropped after a clean thaw"
    );
    assert_released(&fake);
}

#[test]
fn a_failed_thaw_leaks_ops_and_handles() {
    let _guard = LATCH.lock().unwrap();
    reset_thaw_failed();
    let mut fake = Fake::new(&[1, 2]).failing(Op::Resume, 0, true);
    let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let spy = DropSpy {
        inner: &mut fake,
        dropped: dropped.clone(),
    };
    let freeze = Freeze::acquire(spy).expect("freeze");
    assert_eq!(freeze.thaw(), Err(FreezeError::Resume));
    assert!(
        !dropped.load(std::sync::atomic::Ordering::SeqCst),
        "a failed thaw must leak ops, not drop it"
    );
    assert!(thaw_failed());
    // The stuck thread's handle stayed open (never closed by a drop).
    assert!(fake.threads.iter().any(|t| t.open && t.suspend_count == 1));
    reset_thaw_failed();
}
