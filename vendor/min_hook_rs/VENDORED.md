# Vendored `min_hook_rs`

- Upstream: [`min_hook_rs`](https://github.com/Rukkhadevata123/min_hook_rs) 2.2.1 from crates.io,
  by Rukkhadevata123, MIT (see `LICENSE`). A pure-Rust port of MinHook.
- Copied from the cargo registry source. `src/disasm.rs`, `README.md` and `LICENSE`
  are unchanged. `src/lib.rs` carries only the lint and format changes listed under
  "Lint changes". `src/buffer.rs` has those plus a test-only slot counter
  (`used_slots`). `src/trampoline.rs` and `src/instruction.rs` change for patches 13
  and 14. `src/hook.rs` drives the shared `thread_freeze` engine (patch 15).
- T7Patch-rs reaches it only through `src/ffi.rs`. It is a workspace member, so
  `cargo test --workspace` and `cargo clippy --workspace` cover it.

## Packaging changes

- `Cargo.toml` is upstream's `Cargo.toml.orig`, minus its `[profile.release]`
  section (profiles of a non-root package are ignored and Cargo warns about them).
  It adds the `Wdk_System_SystemInformation` and `Wdk_System_Threading` features of
  `windows-sys` for patch 9, and a path dependency on the workspace's
  `thread_freeze` crate (patch 15; a dev-dependency on it with the `test-seams`
  feature for the hook tests' fault wrapper).
- The registry files `.cargo-ok`, `.cargo_vcs_info.json`, `.gitignore` and
  `Cargo.lock` are not copied.

## Patches

The behaviour patches are in `src/hook.rs` and `src/error.rs`, and for patches 13
and 14 also in `src/trampoline.rs` and `src/instruction.rs`.

Since patch 15 the thread-freeze mechanics (patches 2–5, 9, 10) live in the
workspace crate `thread_freeze`, shared with `src/threads.rs` in T7Patch-rs, so
the two callers no longer carry the same policy twice. `src/hook.rs` keeps
MinHook's own policy — moving a suspended thread's RIP out of a trampoline, the
slot reach check (patch 8), the footprint re-check (patch 14), the protection
journal and flush — and drives the engine's `Freeze`. The engine owns the single
terminal thaw latch both callers read, captures one `CONTEXT_CONTROL |
CONTEXT_INTEGER` context per thread, and leaks its handles and buffers (and the
caller's scratch) rather than dropping them after a failed thaw. The patch
descriptions below are of behaviour the engine now provides; the names
(`FrozenThreads`, `ThreadList`) are historical.

1. **Error codes.** `HookError::ThreadSuspend` (13), `HookError::ThreadContext`
   (14) and `HookError::ThreadResume` (15) are new, with `as_str` and `from_code`
   entries. Codes 1 to 12 still match `MH_STATUS`.
2. **Fail-closed freeze.** `FrozenThreads::freeze` suspends every thread of the
   process or none. If `OpenThread` or `SuspendThread` fails for a thread not
   confirmed to have exited, the threads already suspended are resumed and the
   attempt is retried (patch 9); when every attempt fails, `ThreadSuspend` is
   returned. Upstream zeroed the failed entry and reported success. A failed
   enumeration also returns `ThreadSuspend` (upstream: `MemoryAlloc`).
   Three cases are skipped as "thread is gone", because a thread that no longer
   exists cannot be parked in a patched range:
   - `OpenThread` fails with `ERROR_INVALID_PARAMETER` (the id no longer exists);
   - `GetProcessIdOfThread` names another process (the id was reused); zero means
     the query failed and is retried, not skipped;
   - `SuspendThread` fails and the thread's handle is signaled (a zero-timeout
     wait; the handle is opened with `SYNCHRONIZE`). The exit code cannot tell:
     Windows refuses to suspend a terminating thread
     (`STATUS_THREAD_IS_TERMINATING`, reported as `ERROR_ACCESS_DENIED`) while its
     exit code still reads `STILL_ACTIVE`, and such a thread may still run DLL
     detach code. A handle that is not signaled retries the attempt; a failed
     wait fails closed at once.
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
   1. compute each thread's new RIP with the pure `plan_ip`, from the context
      the freeze read while confirming its suspension (no writes, and no second
      context read);
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
   even for a disabled hook. It frees the slot only if no frozen thread can reach the
   64-byte slot, which holds the trampoline and the relay: no thread's RIP (after its
   move), none of its general-purpose registers (RAX to R15, RSP included), and no
   word of its live stack, from RSP up to its `NT_TIB.StackBase`, lies in the slot.
   `uninitialize` calls `uninitialize_buffer` only if no thread can reach any slot.
   Otherwise the buffers are kept, and `retain_buffers` stays set so later calls
   never free them either. On error, `remove_hook` keeps the hook and `uninitialize`
   stays initialized with its hooks intact.
   The check reuses the freeze's one context read per thread, which now asks for
   `CONTEXT_CONTROL | CONTEXT_INTEGER`; a move still writes back only
   `CONTEXT_CONTROL`. The stack base is the TEB's second word, from
   `NtQueryInformationThread(ThreadBasicInformation)` and `ReadProcessMemory`; the
   stack is read with `ReadProcessMemory` in 64-word chunks into a fixed buffer. The
   watched slots are a sorted array built before the freeze. Stack words are only
   read. Uncertainty keeps the slot and is not an error: a missing or misaligned
   stack base, an RSP of zero or above the base, a failed or short read, a stack span
   over 64 MiB, more than 256 MiB read across all threads, or a slot whose end
   overflows. The scan is conservative: a stale word that only looks like a slot
   address also keeps it.
9. **Threads created during the freeze are caught.** Upstream enumerated once
   with Toolhelp, so a thread created after the snapshot kept running while code
   was patched. Now each freeze attempt suspends every thread of a snapshot,
   checks that each has started, reads their contexts (which waits for
   `SuspendThread` to take effect), and enumerates again. If the second list has a
   thread the first did not, the attempt is thawed and retried after a 1 ms
   pause. That thread is never suspended.
   Under Wine a thread whose creator was suspended between registering it and
   starting it never reaches its suspension, so `GetThreadContext` on it waits
   forever with every other thread frozen. (A `winedbg` capture of the T7Patch-rs
   test binary showed exactly that; suspending late threads hung it in 4 of 6
   runs.) Such a thread has no TEB yet: Wine sets it when the thread starts. So a
   context is read only once `NtQueryInformationThread(ThreadBasicInformation)`
   shows a TEB; a thread without one retries the attempt. That check eliminated
   the hang in a build that still suspended late threads (0 of 14 runs hung, 9
   of 14 without it). On Windows the TEB is set when the thread is created.
   An attempt whose context read fails, or whose open or suspend was disturbed
   (patch 2), is retried the same way. An id whose thread had exited and that is
   listed again is opened once more: if it now names a live thread of this
   process (a new thread given the recycled id), or its owner cannot be read, the
   attempt is retried too; if the wait that would confirm its exit fails, the
   freeze fails closed.
   After 16 disturbed attempts the freeze gives up with `ThreadSuspend`, or
   `ThreadContext` if the last one failed a context read.
   Since patch 15 the second enumeration (the frozen recheck) differs by host.
   On Windows it re-enumerates with `NtQuerySystemInformation`, a plain syscall
   there. On Wine that call allocates on its Unix side (see Known limits), so the
   recheck instead walks the live thread list with `NtGetNextThread` (one
   wineserver call, no Unix-side allocation, bounded) and confirms a size-0
   `SystemProcessInformation` length fingerprint of the whole prefix is unchanged
   across the freeze. A listed thread that is neither this one nor already held,
   and has not exited, was created during the freeze: it is never suspended and
   the attempt restarts. The idea is from neohook; see below.
   Enumeration uses `NtQuerySystemInformation(SystemProcessInformation)` into a
   buffer sized with headroom before the freeze, and ids go into fixed arrays, so
   nothing allocates on the Rust side while threads are suspended. Toolhelp is
   not used: Wine's `CreateToolhelp32Snapshot` allocates from the process heap,
   which a suspended thread may hold locked. Every buffer, including the saved
   contexts, is sized for 512 threads before the first suspension; more fails
   closed. The enumeration and the parser are ports of `src/threads.rs` in
   T7Patch-rs, which applies the same policy. This needs the
   `Wdk_System_SystemInformation` and `Wdk_System_Threading` features of
   `windows-sys`.
10. **Resume failures are terminal.** `FrozenThreads::thaw` resumes each thread
   once, retrying a failed `ResumeThread` up to three times; a thread whose handle
   is signaled counts as resumed. Every error path thaws explicitly, and drop thaws as a
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
   `fault` module. It can fail chosen calls to `OpenThread`, make a chosen thread
   look gone to it, `SuspendThread`, the started (TEB) check, the zero-timeout wait,
   `Get/SetThreadContext`, `VirtualProtect` (making a page
   writable and restoring it separately), `FlushInstructionCache`, the stack-base
   read or the stack read of the slot check (patch 8), the footprint read before a
   write (patch 14), fail the
   resumes of one chosen thread, and force a no-op context write for every thread so
   the rollback path runs. It can also hide trailing ids from chosen enumerations,
   so a thread seems to appear mid-freeze. Plans for different calls combine, and
   bit 63 of a mask covers every later call. A test resumes a
   thread the thaw left suspended itself (`fault::release_stuck`), which also clears
   that latch; `fault::reset_latches` clears the other two. Production code cannot
   clear any of them. The last transaction's slot check is recorded per thread id
   in fixed storage (`fault::reach_of`), so a test can tell which thread kept a slot,
   and why. Tests: `hook::tests`.

13. **Overlapping hooks are refused.** Upstream refused only a hook on the same
   target. Each hook now has a *footprint*: its patch range (5 bytes, or with the hot
   patch the 5 bytes above the target and 2 at it) together with the source bytes its
   trampoline copied or relocated (`Trampoline::source_len`, at most 19: an
   instruction starts at offset 4 or less). The trampoline is a copy of the source
   bytes, and one that ran out of room jumps back to `target + source_len` (one that
   ends at a `ret` or a jump does not return there), so a write anywhere in the
   footprint would break it even where it misses the patch range. `create_hook` refuses a target inside an existing hook's
   footprint before decoding it (it may not be an instruction boundary), and a new
   footprint that overlaps any existing one, enabled, disabled or queued, after the
   trampoline is built, with `HookError::Overlapping` (16). The refused trampoline's
   slot is freed: nothing was published that points into it. A failed
   `create_trampoline` now frees its slot too (upstream leaked it).
14. **The original bytes are re-checked just before every write.** `create_hook`
   reads the target's code once, without faulting (`ReadProcessMemory`, split at a
   page boundary): the hot-patch bytes above it and 35 bytes from it. The trampoline
   is decoded and copied from that snapshot, never from live memory, so a writer that
   changes the code and changes it back while the trampoline is built cannot leave a
   trampoline that differs from the backup. Each decode gets a full 16-byte window or
   the hook is refused (`UnsupportedFunction`): the decoder silently shortens an
   instruction its input cuts off. The footprint's bytes from the snapshot are the
   hook's backup (`HookEntry::original`; a disable writes back its patch range). In
   `transact`, with every thread frozen and after every footprint was made writable
   (the whole footprint, so a source byte on an execute-only page can be read back),
   each footprint is read without faulting and compared with what the hook last left
   there: the original bytes before an enable, the original bytes with its own jumps
   before a disable. A mismatch, or a failed read, writes nothing, restores the
   protections, thaws, and returns `HookError::TargetModified` (17). No hook changes
   state. This also covers `remove_hook` and `uninitialize` of an enabled hook, so
   foreign bytes over a hook's jump are never overwritten with the backup. The code
   is not re-checked after a rollback write in the same freeze.

15. **One shared freeze engine.** The thread-freeze policy, which `src/hook.rs`
   and `src/threads.rs` in T7Patch-rs carried separately, moved to the workspace
   crate `thread_freeze` (the vendor depends on it by path; it never depends on the
   application crate). The engine's `Freeze<O>` is generic over a `ThreadOps`
   trait, so the hook tests drive the real freeze through a fault-injecting wrapper
   (`FaultOps`, behind the engine's `test-seams` feature) and the engine has its own
   fake-ops unit tests. `src/hook.rs` keeps every MinHook-specific policy and maps
   the engine's `FreezeError`/`AcquireError` to `ThreadSuspend`/`ThreadContext`/
   `ThreadResume` as before. The single terminal thaw latch now lives in the engine,
   read by both callers. On a failed thaw the engine keeps (leaks) its handles,
   contexts and ops rather than dropping them, and each caller keeps its own
   scratch (`moves`/`journal`/`slots`; `batch`/`watch`; `reports`), because a stuck
   thread may hold the heap lock a drop would take. The enumeration's Wine recheck
   now uses `NtGetNextThread` (patch 9).

## Ideas borrowed from neohook

[neohook](https://github.com/aliendwarf/neohook) 0.16.0 (crates.io), by AlienDwarf,
is dual-licensed MIT OR Apache-2.0. T7Patch-rs takes the MIT option; its notice is
in `LICENSE-neohook-MIT`. Only ideas are borrowed, no code. neohook was read, never
built or linked, and is not a dependency.

- Patch 8, from `src/reclaim.rs` (`inspect_thread`, `scan_stack`): a trampoline is
  reachable while a suspended thread's general-purpose registers or its stack, from
  RSP up, hold an address inside it, not only its instruction pointer. The register
  list and the whole-stack scan are that idea. The implementation is new and differs
  on purpose: it reuses the existing freeze and its saved contexts, bounds the span
  by the TEB's stack base instead of walking `VirtualQuery` regions, and treats an
  unreadable page as a reason to keep the slot (neohook skips uncommitted or guarded
  pages). neohook's retire queue, its suspend and reclamation code, and its
  return-address handling are not used.
- The `NtGetNextThread` enumeration (patch 9, `thread_freeze` crate), from
  `src/reclaim.rs` (`nt_get_next_thread`): walk the process's threads with the
  allocation-free `NtGetNextThread` instead of a heap-allocating snapshot while
  threads are suspended. neohook resolves it with `GetProcAddress` and falls back
  to Toolhelp, and its `catch_up_new_threads` suspends threads that appear late;
  this engine does neither (the Wine hang fixed in commit 95213b1 means late
  threads are never suspended), binds `NtGetNextThread` as a raw-dylib import, and
  pairs the walk with the prefix fingerprint above.
- Patch 13, from `src/transaction.rs` (the stolen-bytes check at attach, lines
  971-981, repeated at commit, lines 1414-1421, and `ranges_overlap`, line 2800):
  refuse a hook whose bytes overlap a queued or installed hook's. Ours compares
  footprints, which add the hot-patch bytes and every relocated source byte, and
  checks once, under the hook-manager lock that every change holds.
- Patch 14 is not from neohook. neohook checks only that its patch has the stolen
  length before writing (`src/transaction.rs` line 2058), not that the bytes are
  still the ones it saved.

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

Wine findings below were read from source: upstream Wine 11.20 (the tests'
`wine`, tag `wine-11.20`), upstream 11.0, and the Wine that GE-Proton11-9 builds
(Valve's fork at `981e2f0b9007`, wine-staging `v11.0` at `6cc805ea5713`, and the
GE patches at `01bfbf67b354`; GE-Proton11-11 reports the same `wine-11.0
(Staging)`). Every function named below is the same in all of them apart from
refactors. glibc is 2.44. Windows findings were read from the disassembly of
Windows 11 26100 `kernelbase.dll` 10.0.26100.9278 and `ntdll.dll` 10.0.26100.9549.

- **How Wine suspends.** `SuspendThread` reaches the thread as SIGUSR1, and
  `usr1_handler` parks it in `wait_suspend`. SIGUSR1 is in `server_block_set`,
  which `server_enter_uninterrupted_section` masks before taking its mutex and
  which every Wine signal handler runs under (`sa_mask`). A thread blocked in a
  wineserver wait (`server_select`) holds no mutex while it waits. So a thread
  whose suspension the freeze confirmed holds no Wine mutex taken that way,
  `virtual_mutex` included. It can still hold anything taken with SIGUSR1
  unmasked: the PE-side process heap lock and loader lock, and, while it runs
  Unix-side code (a Wine Unix library, a graphics driver), glibc's `malloc`
  arena mutexes and its stdio `list_all_lock`.
- **The frozen recheck no longer allocates inside Wine (patch 9).** The second
  enumeration, which runs while threads are suspended, used
  `NtQuerySystemInformation(SystemProcessInformation)`;
  `get_system_process_info` `malloc`s a buffer and `fopen`s `/proc/<pid>/status`
  and `/proc/<pid>/task/<tid>/stat` for every thread of every Wine process, and
  glibc `malloc`/`fopen` take an arena mutex / the stdio `list_all_lock`, so a
  thread suspended inside one would deadlock the freeze. On Wine the recheck now
  walks `NtGetNextThread` (one wineserver call, no Unix-side allocation) plus a
  size-0 fingerprint. Residual, Wine only: `NtGetNextThread` silently skips a
  thread the wineserver cannot hand out a handle for (a thread created with a
  restrictive security descriptor — threads get none by default, so this needs a
  deliberately set one — or a wineserver out of memory), so a thread created in
  the freeze window that is both unhandleable and exactly offset by another
  thread or process exiting in the same window would be missed. On Windows the
  recheck still re-enumerates (a plain syscall). The first, pre-suspend
  enumeration still uses `SystemProcessInformation` on both hosts, which is safe
  because nothing is suspended then.
- **The slot check's own calls take no lock and allocate nothing, verified.**
  Under Wine, `NtQueryInformationThread(ThreadBasicInformation)` is one
  `wine_server_call` (per-thread request and reply pipes, signal masking, no
  mutex, no allocation). An own-process `ReadProcessMemory` is `memmove` under
  `__TRY` after `virtual_check_buffer_for_write` on our own buffer, with no
  wineserver call. Only a fault (an unreadable source page) goes further:
  `segv_handler` takes `virtual_mutex`, which no confirmed-suspended thread can
  hold (above), then recovers through `longjmp`; Valve's fork adds a lock-free
  `steamclient_handle_fault` lookup there. Debug traces, when `WINEDEBUG`
  enables them, are formatted into a per-thread buffer and written with
  `write(2)`. On Windows, `kernelbase!ReadProcessMemory` calls
  `ntdll!NtReadVirtualMemory`, and on failure `RtlNtStatusToDosError` and
  `RtlSetLastWin32Error` (not disassembled further); `NtReadVirtualMemory` and
  `NtQueryInformationThread` are bare `syscall` stubs. `src/threads.rs` makes
  the same calls.
- A thread left suspended by a failed resume may hold the process heap lock. The
  vectors dropped after the thaw, and the caller formatting the error, may then
  deadlock. `src/threads.rs` in T7Patch-rs has the same exposure.
- A thread that has started (has a TEB) but cannot reach its suspension point
  would still make `GetThreadContext` block under Wine; nothing bounds that call.
  No such case has been observed. A bounded design would read contexts on a
  pre-created helper thread with a timeout.
- The slot check (patch 8) sees only frozen threads' registers and live stacks.
  It does not see the calling thread's own stack (a `remove_hook` called from code
  that a trampoline's relocated `call` is returning into), trampoline pointers
  saved in heap or global data, or the saved contexts and stacks of idle fibers.
