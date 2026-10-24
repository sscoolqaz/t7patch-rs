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
- The registry files `.cargo-ok`, `.cargo_vcs_info.json`, `.gitignore` and
  `Cargo.lock` are not copied.

## Patches

All behaviour patches are in `src/hook.rs` and `src/error.rs`.

1. **Error codes.** `HookError::ThreadSuspend` (13) and `HookError::ThreadContext`
   (14) are new, with `as_str` and `from_code` entries. Codes 1 to 12 still match
   `MH_STATUS`.
2. **Fail-closed freeze.** `FrozenThreads::freeze` suspends every enumerated thread
   or none. If `OpenThread` or `SuspendThread` fails for a live thread of this
   process, the threads already suspended are resumed and `ThreadSuspend` is
   returned. Upstream zeroed the failed entry and reported success. A failed
   Toolhelp snapshot also returns `ThreadSuspend` (upstream: `MemoryAlloc`).
   Three cases are skipped as "thread is gone", because a thread that no longer
   exists cannot be parked in a patched range:
   - `OpenThread` fails with `ERROR_INVALID_PARAMETER` (the id no longer exists);
   - `GetProcessIdOfThread` names another process (the id was reused);
   - `SuspendThread` fails and `GetExitCodeThread` reports the thread exited.
   `SuspendThread`'s failure value is compared as `u32::MAX`.
3. **Handles stay open until resume.** `FrozenThreads` owns the handles of the
   threads it suspended and resumes and closes them on drop, so every early return
   resumes. Upstream closed each handle after suspending and reopened by id to
   resume. This also fixes upstream `remove_hook`, which returned on a patch error
   without resuming the frozen threads.
4. **Context errors propagate.** `GetThreadContext` and `SetThreadContext` failures
   return `ThreadContext`. Upstream ignored both.
5. **Aligned contexts.** Contexts live in `#[repr(C, align(16))] AlignedContext`.
   The `windows-sys` `CONTEXT` has no 16-byte alignment, which x64
   `Get/SetThreadContext` require; upstream's stack `CONTEXT` could fail silently.
6. **Transactional enable/disable** (`HookManager::transact`). One code path serves
   single hooks, `ALL_HOOKS`, `apply_queued`, `remove_hook` and `uninitialize`:
   1. read each thread's context and compute its new RIP with the pure `plan_ip`
      (no writes);
   2. `VirtualProtect` every patch range first, restoring them all if one fails,
      then write the bytes, which can no longer fail;
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
9. **Test seam.** Under `cfg(test)`, the `sys` wrappers consult the per-thread
   `fault` module. It can fail chosen calls to `OpenThread` (with a chosen last
   error), `SuspendThread`, `Get/SetThreadContext` or `VirtualProtect`, and it can
   force a no-op context write for every thread so the rollback path runs. Tests:
   `hook::tests`.

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

## Known limits (unchanged from upstream)

- Threads created after the Toolhelp snapshot are not frozen.
- Only RIP is checked. A return address into a trampoline (from a relocated
  `call` in the prologue) on some thread's stack is not detected.
