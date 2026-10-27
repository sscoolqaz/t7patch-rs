# T7Patch-rs

A Rust fork of upstream [Scroptss/T7Patch-src](https://github.com/Scroptss/T7Patch-src),
the anti-crash and security patch for Call of Duty: Black Ops III (Windows x64). It is
based on commit `16b9b50662c68149526039cdf2ebdad348b9ca70` (2026-10-01, "Fix Campaign
Transitioning and Fix Linux Password Sanitization"), with additional safety fixes on top.

The upstream patch is ported, with additional safety fixes for packet parsing,
hook relocation and lifetime, thread freezing, rollback, configuration and crash
handling. This is a Windows x64 DLL; Linux support means running it through
Proton/Wine.

In-game testing under Proton has hosted lobbies and played rounds. The later
iced-x86 relocation changes also have a reported in-game smoke test. The latest
dynamic unwind metadata changes have passed Wine and native Windows 11 tests,
but have not been exercised in game. Campaign and Lua paths remain unverified
in game, and there has been no Windows in-game test. See
[validation and limitations](docs/validation.md) for the tested scope.

Supported executable fingerprints are the February and September 2026 builds,
detected by PE timestamp and image size in [`src/build.rs`](src/build.rs).

Two states are deliberately retained after unload: the exception dispatcher once an
induced-exception patch (the lobby marker or the `IsProcessorFeaturePresent` detour) has
been live, or on the Wine stub layout while the stub cannot be restored yet (a thread is
in or returning into it, or the guarded write fails; it stays until a later successful
install and Unload restores it), and the three dvar settings changed at install, because
there is no verified dvar finder address to restore them.

## Documentation

- [`docs/validation.md`](docs/validation.md): current test evidence, hardening
  coverage and remaining limitations.
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

Rust 1.87 or newer is required. The project is Rust only, with no C/C++ build
scripts or prebuilt native libraries. Hooking uses the vendored pure-Rust
`min_hook_rs`, iced-x86 relocation, a shared thread-freeze engine, and dynamic
unwind metadata where the original prologue can be described safely. Details
and dependency notices are in
[`vendor/min_hook_rs/VENDORED.md`](vendor/min_hook_rs/VENDORED.md).

Both build paths need the target's linker. On Linux, tests run under Wine;
ordinary `cargo test` on a Linux target cannot build this Windows-only crate.

On Windows with the MSVC linker and Windows SDK installed:

```bash
rustup target add x86_64-pc-windows-msvc
cargo test --workspace
cargo build --release --target x86_64-pc-windows-msvc
```

Cross-compiling on Linux needs mingw-w64 as the linker (for example
`pacman -S mingw-w64-gcc` or `apt install gcc-mingw-w64-x86-64`):

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

The output is `target/<target>/release/t7patch.dll`, for example
`target/x86_64-pc-windows-gnu/release/t7patch.dll`. It needs no
mingw runtime DLLs, and it loads in the game under Proton. Run the tests under Wine
with:

```bash
CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine cargo test --workspace --target x86_64-pc-windows-gnu
```

The C++ hook on `__report_gsfailure` is not ported. It catches MSVC `/GS`
stack-cookie failures, and a Rust-only DLL has no `/GS` checks.
Other departures from upstream are listed in
[`docs/upstream-differences.md`](docs/upstream-differences.md).

## Loading and configuration

This project builds only `t7patch.dll`, a drop-in replacement for upstream's
DLL. Install it the normal T7Patch way:

1. Install upstream T7Patch with
   [its instructions](https://github.com/Scroptss/T7Patch#windows-instructions)
   (Windows, or the Linux/Steam Deck zip and launch options under Proton). This
   provides the `dsound.dll` and `t7patchloader.dll` loader and `t7patch.conf`.
2. Replace `t7patch.dll` in the game folder with the one from
   [this project's releases](https://github.com/sscoolqaz/t7patch-rs/releases/latest)
   or your own build.

The loader, launch options and config stay upstream's, so setups that expect the
standard T7Patch layout keep working. On its own, `t7patch.dll` in the game
folder does nothing: the loader calls its installation exports. Diagnostic
launch options are in [Proton testing](docs/testing-under-proton.md).

`t7patch.conf` is created in the game's working directory and watched for
changes. It contains `playername`, `isfriendsonly`, `autoinstallmods`, and
`networkpassword`. The default is friends-only, automatic mod installation off,
and an empty password. Keep your populated config and raw crash/memory captures
out of commits and public issue reports.

`Unload` deactivates the patch logically; it does not physically unload the DLL.
The retained dispatcher/dvar state is described above and in
[upstream differences](docs/upstream-differences.md#state-retained-after-unload).

## Contributing

Read [`AGENTS.md`](AGENTS.md) for address translation, unsafe-code conventions,
provenance and commit requirements. Enable the checks with:

```bash
git config core.hooksPath .githooks
```

Every commit must pass formatting, Clippy for both Windows targets, and the
workspace tests. The exact commands are in
[the Rust checks workflow](.skills/rust-checks/SKILL.md).

## License status

No project-wide license is declared for this port, matching the pinned upstream.
Third-party dependencies and vendored components retain their own licenses;
their notices do not constitute a license for the entire project.

## Credits

Original T7Patch by shiversoftdev, with updates by Scropts. Thanks to the upstream
maintainers for their work.

Hooking uses `min_hook_rs` by Rukkhadevata123, a pure-Rust port of MinHook, vendored in `vendor/min_hook_rs`
under its MIT licence (`vendor/min_hook_rs/LICENSE`; changes in `VENDORED.md`).

Relocation uses [iced-x86](https://github.com/icedland/iced) under MIT. Selected
hardening ideas come from [neohook](https://github.com/aliendwarf/neohook)
0.16.0; no neohook code or dependency is included. Its retained MIT notice and
the exact provenance are documented in the vendored notes.
