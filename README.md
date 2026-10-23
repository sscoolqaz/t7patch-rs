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

```bash
cargo test
cargo build --release --target x86_64-pc-windows-msvc
```

## Credits

Original T7Patch by shiversoftdev, with updates by Scropts. The source repository has no licence file; the port is made with the owner's permission.
