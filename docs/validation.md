# Validation and limitations

This records the evidence for the current implementation, rather than treating
one successful game session as coverage of every protection.

## In-game evidence

- The documented Proton runs hosted lobbies and played rounds with the full
  patch at `d068a9f`. See [the run log](in-game-run-log.md) for build IDs,
  component selections and observed faults.
- After iced-x86 relocation (`3aafada`), an informal smoke test found the patch appears
  to work in game. That smoke test has no captured binary hash or detailed path
  coverage and does not validate the subsequent unwind changes.
- Dynamic unwind metadata (`dd65e26`) has not been exercised in game. Campaign
  fixes, the Lua resolver and Windows in-game behavior remain unverified.

## Automated validation

The implementation at `dd65e26` passed the repository gates on 2026-10-27:

- `cargo fmt --all --check`.
- Clippy with `-D warnings`, workspace/all targets, for both
  `x86_64-pc-windows-gnu` and `x86_64-pc-windows-msvc`.
- Wine workspace tests: 158 application, 71 vendored hook-library and 31
  thread-freeze tests, plus two doctests.
- A workspace/all-target check with Rust 1.87.0, targeting Windows GNU.

Final test binaries also passed repeated runs with a 60-second timeout per
process and no failures or hangs:

| Suite | Wine runs | Native Windows 11 runs |
| --- | ---: | ---: |
| Application | 12/12 | 40/40 |
| Vendored hook library | 5/5 | 20/20 |
| Shared freeze engine | 5/5 | 20/20 |

The Windows copies matched the local binaries' SHA-256 hashes. Live tests cover
hook execution, rollback, thread/register/stack retirement, metadata lifetime,
partial table-cleanup failure and repair, and public virtual unwind through a
trampoline's stolen call to the real caller. The test harness retries bounded
safe freeze refusals only after checking unchanged bytes/behavior and a resumed
process; production freeze limits are unchanged.

## Hardening and remaining limits

The five completed hardening phases added trampoline reach checks, overlap and
original-byte checks, the shared freeze engine, iced-x86 relocation, and dynamic
unwind metadata. The implementation and source/disassembly evidence live in
[vendor notes](../vendor/min_hook_rs/VENDORED.md).

- Uncertain relocation refuses the hook. Missing or untranslatable original
  unwind data preserves compatibility by installing without metadata; a guessed
  unwind entry is never registered.
- Unwind metadata is limited to eligible linear function-start prologues.
  Chained/handler records, unsupported operations and uncertain partial frames
  are declined. Registration/deletion/repair runs outside freezes.
- On the tested Windows 11 `ntdll`, the fast `RtlCaptureStackBackTrace` path
  stops at dynamic code. Public lookup/virtual unwind crosses it, and the
  exception dispatcher consults dynamic tables. Actual raised-exception
  propagation through a trampoline and older Windows versions are untested.
- Retirement conservatively retains slots if a frozen thread may reach code or
  metadata, or its stack cannot be inspected. It does not discover pointers in
  heap/global storage, idle fibers, or the removing thread's own stack.
- `Unload` is logical deactivation. The pinned DLL, retained exception dispatcher
  after induced-exception patches, and changed dvars have lifetime limits
  described in [upstream differences](upstream-differences.md#state-retained-after-unload).
- Wine thread enumeration and suspension have the residual limits documented
  in [VENDORED.md](../vendor/min_hook_rs/VENDORED.md#known-limits).

See [the contributor checks](../AGENTS.md#build-and-check) to reproduce the
standard gates, and [Proton testing](testing-under-proton.md) for game testing.
