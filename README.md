# T7Patch-rs

A Rust fork of upstream [Scroptss/T7Patch-src](https://github.com/Scroptss/T7Patch-src),
the anti-crash and security patch for Call of Duty: Black Ops III (Windows x64). It is
based on commit `16b9b50662c68149526039cdf2ebdad348b9ca70` (2026-10-01, "Fix Campaign
Transitioning and Fix Linux Password Sanitization"), with additional safety fixes on top.

Status: ports upstream T7Patch plus safety fixes: bounded chat, IM and event-index
handling, a staged lifecycle with rollback, a managed config worker, restore on unload of
hooks, Steam vtable slots, the lobby marker and the update-preload pointer, and a fixed
crash queue with a safe stack probe. The full patch has been exercised in game under
Proton: it hosts a lobby and plays rounds. That does not mean every protection, campaign
or Lua path has been verified. It is untested on Windows. The tests pass under Wine.

Two states are deliberately retained after unload: the exception dispatcher once an
induced-exception patch (the lobby marker or the `IsProcessorFeaturePresent` detour) has
been live, or on the Wine stub layout while a frozen stack scan still finds a thread in
the stub, and the three dvar settings changed at
install, because there is no verified dvar finder address to restore them.

## Documentation

- [`docs/testing-under-proton.md`](docs/testing-under-proton.md): running the patch in
  game under Proton, switching components off with `T7PATCH_ONLY`, reading
  `crashes.log` and the trace lines, and capturing live game memory.
- [`docs/upstream-differences.md`](docs/upstream-differences.md): every deliberate
  departure from upstream and every upstream bug found, with the evidence.
- [`docs/in-game-run-log.md`](docs/in-game-run-log.md): the in-game runs so far and
  what each showed.
- [`AGENTS.md`](AGENTS.md): conventions and the checks every commit must pass.

## Port checklist

| C++ source | Rust module | Status |
| --- | --- | --- |
| `gscu_hashing.cpp/.h` | `src/gscu_hash.rs` | ported, tested |
| `framework.h` (`fnv1a`) | `src/fnv.rs` | ported, tested |
| `GameBuild.h` | `src/build.rs` | ported, tested; September build detected in game |
| `structs.h` | `src/structs.rs` | ported, layout asserts |
| `offsets.h/.cpp` | `src/offsets.rs` | ported |
| `Arxan.cpp/.h` | `src/arxan.rs` | ported, exercised in game |
| `Hooks.cpp/.h` | `src/hooks.rs` | ported, exercised in game (detours and VMT hook) |
| `Protection.cpp/.h` | `src/protection.rs` | ported, exercised in game (lobby and info-response paths) |
| `CampaignFixes.cpp/.h` | `src/campaign.rs` | ported, not exercised in game |
| `LuaSymbols.cpp/.h` | `src/lua_symbols.rs` | ported, not exercised in game |
| `dllmain.cpp` | `src/dllmain.rs` | ported, exercised in game |
| exception-dispatch hook (in `dllmain.cpp`) | `src/exception.rs` | ported, exercised in game (Proton's Windows dispatcher layout); undocumented ntdll internals |
| `CrashQueue.h`, `StackProbe.h` (fork) | `src/crash_queue.rs`, `src/exception.rs` | ported, tested |

## Build

The project is Rust only. Hooking uses `min_hook_rs`, a pure-Rust port of
MinHook vendored in `vendor/min_hook_rs` with fail-closed freeze patches, so no C compiler is needed, only the toolchain's linker. The crate builds
only for Windows targets, so on Linux the tests run under Wine (below).

On Windows with MSVC:

```bash
cargo test --workspace
cargo build --release --target x86_64-pc-windows-msvc
```

Cross-compiling on Linux needs mingw-w64 as the linker (for example
`pacman -S mingw-w64-gcc` or `apt install gcc-mingw-w64-x86-64`):

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

The DLL is `target/x86_64-pc-windows-gnu/release/t7patch.dll`. It needs no
mingw runtime DLLs, and it loads in the game under Proton. Run the tests under Wine
with:

```bash
CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine cargo test --workspace --target x86_64-pc-windows-gnu
```

The C++ hook on `__report_gsfailure` is not ported. It catches MSVC `/GS`
stack-cookie failures, and a Rust-only DLL has no `/GS` checks.
Other departures from upstream are listed in
[`docs/upstream-differences.md`](docs/upstream-differences.md).

## Credits

Original T7Patch by shiversoftdev, with updates by Scropts. Thanks to the upstream
maintainers for their work.

Hooking uses `min_hook_rs` by Rukkhadevata123, a pure-Rust port of MinHook, vendored in `vendor/min_hook_rs`
under its MIT licence (`vendor/min_hook_rs/LICENSE`; changes in `VENDORED.md`).
