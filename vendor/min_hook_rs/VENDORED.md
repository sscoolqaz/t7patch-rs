# Vendored `min_hook_rs`

- Upstream: [`min_hook_rs`](https://github.com/Rukkhadevata123/min_hook_rs) 2.2.1 from crates.io,
  by Rukkhadevata123, MIT (see `LICENSE`). A pure-Rust port of MinHook.
- Copied from the cargo registry source. `src/disasm.rs`, `src/instruction.rs`,
  `README.md` and `LICENSE` are unchanged. `src/buffer.rs`, `src/trampoline.rs` and
  `src/lib.rs` carry only the lint and format changes listed under "Lint changes".
- T7Patch-rs reaches it only through `src/ffi.rs`. It is a workspace member, so
  `cargo test --workspace` and `cargo clippy --workspace` cover it.

## Packaging changes

- `Cargo.toml` is upstream's `Cargo.toml.orig`, minus its `[profile.release]`
  section (profiles of a non-root package are ignored and Cargo warns about them).
  It adds the `Wdk_System_SystemInformation` feature of `windows-sys` for patch 9.
- The registry files `.cargo-ok`, `.cargo_vcs_info.json`, `.gitignore` and
  `Cargo.lock` are not copied.

## Patches

All behaviour patches are in `src/hook.rs` and `src/error.rs`.

1. **Error codes.** `HookError::ThreadSuspend` (13), `HookError::ThreadContext`
   (14) and `HookError::ThreadResume` (15) are new, with `as_str` and `from_code`
   entries. Codes 1 to 12 still match `MH_STATUS`.
2. **Fail-closed freeze.** `FrozenThreads::freeze` suspends every thread of the
   process or none. If `OpenThread` or `SuspendThread` fails for a live thread of
   this process, the threads already suspended are resumed and `ThreadSuspend` is
   returned. Upstream zeroed the failed entry and reported success. A failed
   enumeration also returns `ThreadSuspend` (upstream: `MemoryAlloc`).
   Three cases are skipped as "thread is gone", because a thread that no longer
   exists cannot be parked in a patched range:
   - `OpenThread` fails with `ERROR_INVALID_PARAMETER` (the id no longer exists);
   - `GetProcessIdOfThread` names another process (the id was reused);
   - `SuspendThread` fails and `GetExitCodeThread` reports the thread exited.
   `SuspendThread`'s failure value is compared as `u32::MAX`.
3. **Handles stay open until resume.** `FrozenThreads` owns the handles of the
   threads it suspended. Upstream closed each handle after suspending and reopened
   by id to resume. This also fixes upstream `remove_hook`, which returned on a
   patch error without resuming the frozen threads.
4. **Context errors propagate.** `GetThreadContext` and `SetThreadContext` failures
   return `ThreadContext`. Upstream ignored both.
5. **Aligned contexts.** Contexts live in `#[repr(C, align(16))] AlignedContext`.
   The `windows-sys` `CONTEXT` has no 16-byte alignment, which x64
   `Get/SetThreadContext` require; upstream's stack `CONTEXT` could fail silently.
6. **Transactional enable/disable** (`HookManager::transact`). One code path serves
   single hooks, `ALL_HOOKS`, `apply_queued`, `remove_hook` and `uninitialize`:
   1. read each thread's context and compute its new RIP with the pure `plan_ip`
      (no writes);
   2. `VirtualProtect` every page of every patch range first, one call per page,
      journaling each page's original protection and restoring them all if one
      fails, then write the bytes, which can no longer fail;
   3. write the moved contexts. If a write fails, the contexts already written get
      their original RIP back, the bytes are restored, the instruction cache is
      flushed, and `ThreadContext` is returned.
   `is_enabled` and `queue_enable` change only after the transaction succeeds.
   If restoring a context also fails, every hook in the batch is left disabled.
   That state is safe for both directions: a moved thread sits in a trampoline
   (enable) or at original code (disable). Trampoline buffers are then retained
   for the process lifetime.
   All allocation happens before any thread is suspended, because a suspended
   thread may hold the heap lock.
7. **Correct direction for single-hook disable.** Upstream's `enable_hook` always
   froze with `ACTION_ENABLE`, so disabling one hook never moved threads out of its
   trampoline. The batch now carries each hook's real direction.
8. **Trampolines are freed only when verified unreachable.** `remove_hook` freezes
   even for a disabled hook. It frees the slot only if no thread's RIP lies in the
   64-byte slot, which holds the trampoline and the relay. `uninitialize` calls
   `uninitialize_buffer` only if no thread is in any slot. Otherwise the buffers
   are kept, and `retain_buffers` stays set so later calls never free them either.
   On error, `remove_hook` keeps the hook and `uninitialize` stays initialized with
   its hooks intact.
9. **Threads created during the freeze are caught.** Upstream enumerated once
   with Toolhelp, so a thread created after the snapshot kept running while code
   was patched. Now each freeze attempt suspends every thread of a snapshot, reads
   their contexts (which waits for `SuspendThread` to take effect), and enumerates
   again. If the second list has a thread the first did not, the attempt is thawed
   and retried after a 1 ms pause. That thread is never suspended: under Wine a
   thread caught mid-startup may never reach its suspension, and reading its
   context then hangs with every other thread frozen. (Suspending such threads
   deadlocked the T7Patch-rs test binary in 4 of 6 runs.) An attempt whose context
   read fails is retried the same way, since under Wine that happens to a thread
   that is starting or exiting. An id whose thread had exited may still be listed,
   so it is not counted as new. After 16 disturbed attempts the freeze gives up
   with `ThreadSuspend`, or `ThreadContext` if the last one failed a context read.
   Enumeration uses `NtQuerySystemInformation(SystemProcessInformation)` into a
   buffer sized with headroom before the freeze, and ids go into fixed arrays, so
   nothing allocates while threads are suspended. Toolhelp is not used: Wine's
   `CreateToolhelp32Snapshot` allocates from the process heap, which a suspended
   thread may hold locked. Every buffer is sized for 512 threads before the first
   suspension; more fails closed. The enumeration and the parser are ports of
   `src/threads.rs` in T7Patch-rs. This needs the `Wdk_System_SystemInformation`
   feature of `windows-sys`.
10. **Resume failures are terminal.** `FrozenThreads::thaw` resumes each thread
   once, retrying a failed `ResumeThread` up to three times; a thread that has
   exited counts as resumed. Every error path thaws explicitly, and drop thaws as a
   safety net, so nothing is resumed twice. A thread that stays suspended keeps its
   handle open (its id cannot be reused) and sets a process-wide latch,
   `thaw_failed()`. The call then returns `ThreadResume` in place of any other
   result, after recording the hook state the image actually holds, and the
   trampoline buffers are retained. Every later hook change is refused with
   `ThreadResume`. Upstream ignored `ResumeThread` failures.
11. **Protection and flush failures are reported.** After the writes, every
    journaled page is restored newest first (so a page two ranges share ends at its
    original protection), each restore retried up to three times. Then every patch
    range is flushed. Upstream saved one protection per range, which loses the
    second page's protection when a range crosses pages that differ, and ignored
    both `VirtualProtect` and `FlushInstructionCache` failures. A page that stays
    changed sets `protection_lost()`; a failed flush sets `flush_failed()`. Both
    are process-wide latches. The other pages and ranges are still restored and
    flushed, and the call's result is unchanged: the hook change itself applied.
12. **Test seam.** Under `cfg(test)`, the `sys` wrappers consult the per-thread
   `fault` module. It can fail chosen calls to `OpenThread` (with a chosen last
   error), `SuspendThread`, the context read that synchronizes a new suspension,
   `Get/SetThreadContext`, `VirtualProtect` (making a page
   writable and restoring it separately) or `FlushInstructionCache`, fail the
   resumes of one chosen thread, and force a no-op context write for every thread so
   the rollback path runs. It can also hide trailing ids from chosen enumerations,
   so a thread seems to appear mid-freeze. Plans for different calls combine. A test resumes a
   thread the thaw left suspended itself (`fault::release_stuck`), which also clears
   that latch; `fault::reset_latches` clears the other two. Production code cannot
   clear any of them. Tests: `hook::tests`.

## Lint changes

T7Patch-rs keeps no lint or format exceptions, so the vendored crate's own two are
removed. Neither changes behaviour.

- `buffer::is_executable_address` takes `address: usize` instead of `*mut c_void`.
  It only passes the address to `VirtualQuery` and never dereferences it, so the
  `#[allow(clippy::not_unsafe_ptr_arg_deref)]` is gone. The callers in
  `src/trampoline.rs` and `src/hook.rs` pass `ptr as usize`; a null pointer is
  still rejected (address 0).
- `src/lib.rs` drops `#[rustfmt::skip]` on the `pub use hook::{...}` list, which
  rustfmt now formats.

## Known limits

- A thread left suspended by a failed resume may hold the process heap lock. The
  vectors dropped after the thaw, and the caller formatting the error, may then
  deadlock. `src/threads.rs` in T7Patch-rs has the same exposure. Wine's
  `NtQuerySystemInformation` may allocate on its Unix side, from an allocator a
  suspended thread could hold (not verified); `src/threads.rs` shares that too.
- Only RIP is checked (unchanged from upstream). A return address into a trampoline (from a relocated
  `call` in the prologue) on some thread's stack is not detected.
