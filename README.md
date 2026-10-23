# T7Patch-rs

A Rust port of [shiversoftdev's T7Patch](https://github.com/Scroptss/T7Patch-src) for Call of Duty: Black Ops III (Windows x64).

Status: all C++ modules ported; not yet run inside the game. See the checklist below.

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

## Build

`MinHook` comes from the `minhook-sys` crate, which compiles it from source, so
both the MSVC and the mingw targets build.

On Windows with MSVC:

```bash
cargo test
cargo build --release --target x86_64-pc-windows-msvc
```

Cross-compiling on Linux with mingw-w64 (for example `pacman -S mingw-w64-gcc`
or `apt install gcc-mingw-w64-x86-64`):

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

The DLL is `target/x86_64-pc-windows-gnu/release/t7patch.dll`. It needs no
mingw runtime DLLs, so it loads under Wine as it does on Windows. Run the tests
under Wine with:

```bash
CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUNNER=wine cargo test --target x86_64-pc-windows-gnu
```

A mingw build does not install the `__report_gsfailure` hook. That hook only
exists for MSVC's `/GS` stack cookies, which gcc does not emit.

## Credits

Original T7Patch by shiversoftdev, with updates by Scropts. The source repository has no licence file; the port is made with the owner's permission.
