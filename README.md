# T7Patch-rs

A Rust port of [shiversoftdev's T7Patch](https://github.com/Scroptss/T7Patch-src) for Call of Duty: Black Ops III (Windows x64).

Status: ports upstream T7Patch plus the C++ fork's safety fixes: bounded chat, IM and
event-index handling, a staged lifecycle with rollback, a managed config worker, restore on
unload, and a fixed crash queue with a safe stack probe. The tests pass under Wine. It has
not yet been run in the game.

## Port checklist

| C++ source | Rust module | Status |
| --- | --- | --- |
| `gscu_hashing.cpp/.h` | `src/gscu_hash.rs` | ported, tested |
| `framework.h` (`fnv1a`) | `src/fnv.rs` | ported, tested |
| `GameBuild.h` | `src/build.rs` | ported, tested (detection itself needs the game) |
| `structs.h` | `src/structs.rs` | ported, layout asserts |
| `offsets.h/.cpp` | `src/offsets.rs` | ported |
| `Arxan.cpp/.h` | `src/arxan.rs` | ported, untested in game |
| `Hooks.cpp/.h` | `src/hooks.rs` | ported, untested in game |
| `Protection.cpp/.h` | `src/protection.rs` | ported, untested in game |
| `CampaignFixes.cpp/.h` | `src/campaign.rs` | ported, untested in game |
| `LuaSymbols.cpp/.h` | `src/lua_symbols.rs` | ported, untested in game |
| `dllmain.cpp` | `src/dllmain.rs` | ported, untested in game |
| exception-dispatch hook (in `dllmain.cpp`) | `src/exception.rs` | ported, untested in game; undocumented ntdll internals |
| `CrashQueue.h`, `StackProbe.h` (fork) | `src/crash_queue.rs`, `src/exception.rs` | ported, tested |

## Build

The project is Rust only. Hooking uses `min_hook_rs`, a pure-Rust port of
MinHook, so no C compiler is needed, only the toolchain's linker. The crate builds
only for Windows targets, so on Linux the tests run under Wine (below).

On Windows with MSVC:

```bash
cargo test
cargo build --release --target x86_64-pc-windows-msvc
```

Cross-compiling on Linux needs mingw-w64 as the linker (for example
`pacman -S mingw-w64-gcc` or `apt install gcc-mingw-w64-x86-64`):

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

The DLL is `target/x86_64-pc-windows-gnu/release/t7patch.dll`. It needs no
mingw runtime DLLs, so it is expected to load under Wine and Proton as on
Windows; that has not been verified in the game. Run the tests under Wine with:

```bash
CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine cargo test --target x86_64-pc-windows-gnu
```

The C++ hook on `__report_gsfailure` is not ported. It catches MSVC `/GS`
stack-cookie failures, and a Rust-only DLL has no `/GS` checks.

## Credits

Original T7Patch by shiversoftdev, with updates by Scropts. The source repository has no licence file; the port is made with the owner's permission.
