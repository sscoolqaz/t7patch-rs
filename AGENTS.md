# T7Patch-rs: contributor and agent guide

T7Patch-rs is a Rust fork of upstream
[Scroptss/T7Patch-src](https://github.com/Scroptss/T7Patch-src) (C++, MSVC),
the anti-crash and security patch for Call of Duty: Black Ops III. It targets
Windows x64 only. This guide applies to people and to coding agents alike.

## Build and check

These gates must pass before every commit:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu -- -D warnings
cargo clippy --workspace --all-targets --target x86_64-pc-windows-msvc -- -D warnings
CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine cargo test --workspace --target x86_64-pc-windows-gnu
```

- Pedantic lints are on in `Cargo.toml`.
- The tests are pure logic and need no game. The crate only builds for
  Windows targets, so on Linux they run under Wine (the last command). On
  Windows, `cargo test --workspace` runs them natively.
- `cargo build --release --target x86_64-pc-windows-msvc` produces
  `t7patch.dll`. The mingw target `x86_64-pc-windows-gnu` must also build,
  including when cross-compiled on Linux, and the DLL must load under Wine.
- Enable the pre-commit gate once per clone: `git config core.hooksPath .githooks`.
  It runs the same commands.
- The same steps are written up as a step-by-step workflow in
  [`.skills/rust-checks/SKILL.md`](.skills/rust-checks/SKILL.md), which an
  agent can be pointed at.

The project is Rust only: no C or C++ sources, no `cc` build scripts, no
prebuilt `.lib` files, and no dependency that compiles C. Hooking uses
`min_hook_rs`, a pure-Rust port of MinHook, vendored in `vendor/min_hook_rs`
with fail-closed freeze patches (see its `VENDORED.md`). It is a workspace
member, so run clippy and the tests with `--workspace`. Reach the hooking
library only through `src/ffi.rs`.

## Conventions

- Edition 2024, `rust-version = 1.87`. Use `cast_signed` and `cast_unsigned`
  rather than `as` for sign changes.
- `#![deny(unsafe_op_in_unsafe_fn)]` is set in `src/lib.rs`. Every `unsafe`
  block needs a `// SAFETY:` comment.
- `unsafe` is confined to FFI and game-memory code. Keep pure logic (hashing,
  RVA maps, layouts) safe and testable.
- Game addresses stay in IDA-style hex (`0x1DECFD0`). For that reason
  `unreadable_literal` is the only crate-wide clippy allow. No item-level
  `#[allow]` or `#[rustfmt::skip]` remains; fix a lint rather than silencing it.
- Each module mirrors one C++ file. Note the source file in the module doc
  comment, and keep the original author credits there.

## Game build

- Two builds are supported: February 2026 and September 2026. Detection is by
  PE timestamp and image size (`src/build.rs`).
- September moved code by `-0x6C0` in the range `0x1D29C20..0x2EFF000`. Write
  addresses as February-2026 RVAs and translate them with `build::live_rva`.
- Do not hardcode a live RVA. Always go through the translation.

## Provenance

This is a Rust fork of upstream
[Scroptss/T7Patch-src](https://github.com/Scroptss/T7Patch-src), based on
commit `16b9b50662c68149526039cdf2ebdad348b9ca70` (2026-10-01, "Fix Campaign
Transitioning and Fix Linux Password Sanitization"), with additional safety
fixes on top. Thanks to the upstream maintainers, shiversoftdev and Scropts,
for their work. Where the port departs from upstream on purpose, or found an
upstream bug, it is recorded in
[`docs/upstream-differences.md`](docs/upstream-differences.md) with its
evidence. Add new departures there.

## Commits

- Subject: `Area: description`, for example `hash: port canon_hash and notify_hash`.
- The body ends with a `Files touched:` section listing the paths changed.
- AI-assisted commits end with a `Co-Authored-By:` trailer naming the model
  that made them, for example
  `Co-Authored-By: Claude Haiku 5.5 <noreply@anthropic.com>`.

## Status

Ports upstream T7Patch plus safety fixes: bounded chat, IM and event-index
handling, a staged lifecycle with rollback, a managed config worker, restore on
unload of hooks, Steam vtable slots, the lobby marker and the update-preload
pointer, and a fixed crash queue with a safe stack probe. Further hardening:

- Code writes freeze threads through `NtQuerySystemInformation`, with no
  allocation after the first suspend. A thread that cannot be resumed keeps
  its handle and disables further code writes (terminal).
- Each freeze, here and in the vendored hook library, is a bounded run of
  attempts. A thread created during the freeze is never suspended; it, a
  thread with no TEB yet (one Wine has not started, whose context read would
  block), or a thread that cannot be suspended and whose handle is not
  signaled (Windows refuses a terminating thread) thaws the attempt and
  retries it. A thread counts as exited only when its handle is signaled.
- A removed hook's trampoline is freed only when no frozen thread's RIP,
  general-purpose register or live stack word points into it. A stack that cannot
  be read in full keeps the trampoline for the process lifetime.
- Page protections are journaled and restored. Pointer slots are swapped with
  an aligned compare-and-swap.
- The Arxan bypass is restored last on rollback, and kept while dependent
  patches may still be live.
- The DLL pins itself when the dispatcher is installed, so Unload is logical
  deactivation only.
- Induced faults are repaired even when the handler is inactive.
- The Wine dispatcher stub is written, and restored on unload, only after a
  frozen stack scan finds no thread inside or returning into it.
- A fatal fault's waiters are bounded to 5 s, after which the process terminates.

The full patch has been exercised in game under Proton: it hosts a lobby and
plays rounds ([`docs/in-game-run-log.md`](docs/in-game-run-log.md)). That
does not mean every protection, campaign or Lua path has been verified. It is
untested in game on Windows. The tests pass under Wine and on native Windows 11
(a VM), including live freeze and stack-scan tests. How to run and diagnose the patch in game is in
[`docs/testing-under-proton.md`](docs/testing-under-proton.md).

Known limits, also listed in `docs/upstream-differences.md`: the exception
dispatcher is retained for the process lifetime once an induced-exception
patch has been live, and the dvar settings changed at install
(`ui_error_callstack_ship`, `g_allowvote`, `maxvoicepacketsperframe`) are not
restored, because that needs a verified dvar finder address.
`MAX_SCRIPT_VMS = 2` comes from the engine enum and was not checked against
the Arxan-encrypted binary.
