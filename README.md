# T7Patch-rs

A Rust port of [shiversoftdev's T7Patch](https://github.com/Scroptss/T7Patch-src) for Call of Duty: Black Ops III (Windows x64).

Status: partial. See the checklist below.

## Port checklist

| C++ source | Rust module | Status |
| --- | --- | --- |
| `gscu_hashing.cpp/.h` | `src/gscu_hash.rs` | ported, tested |
| `framework.h` (`fnv1a`) | `src/fnv.rs` | ported, tested |
| `GameBuild.h` | `src/build.rs` | ported, tested (detection itself needs the game) |
| `structs.h` | `src/structs.rs` | ported, layout asserts |
| `offsets.h/.cpp` | — | not started |
| `Arxan.cpp/.h` | — | not started |
| `Hooks.cpp/.h` | — | not started |
| `Protection.cpp/.h` | — | not started |
| `CampaignFixes.cpp/.h` | — | not started |
| `LuaSymbols.cpp/.h` | — | not started |
| `dllmain.cpp` | — | not started |
| exception-dispatch hook (in `dllmain.cpp`) | — | not started; undocumented ntdll internals |

## Build

```bash
cargo test
cargo build --release --target x86_64-pc-windows-msvc
```

## Credits

Original T7Patch by shiversoftdev, with updates by Scropts. The source repository has no licence file; the port is made with the owner's permission.
