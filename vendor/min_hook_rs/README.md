# MinHook-rs

[![Crates.io](https://img.shields.io/crates/v/min_hook_rs)](https://crates.io/crates/min_hook_rs)
[![Documentation](https://docs.rs/min_hook_rs/badge.svg)](https://docs.rs/min_hook_rs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Rust implementation of the MinHook library for Windows x64 function hooking.

## Installation

```toml
[dependencies]
min_hook_rs = "2.2"
windows-sys = { version = "0.61", features = [
    "Win32_UI_WindowsAndMessaging",
    "Win32_Foundation"
] }
```

## Quick Start

Every hook follows the same six-step lifecycle:

```
initialize → create_hook_api → enable_hook → [use] → disable_hook → remove_hook → uninitialize
```

Here is a minimal `MessageBoxA` hook that intercepts the call and replaces the message text:

```rust
use min_hook_rs::*;
use std::ffi::c_void;
use std::ptr;
use windows_sys::Win32::Foundation::HWND;
use windows_sys::Win32::UI::WindowsAndMessaging::{MessageBoxA, MB_OK};
use windows_sys::core::PCSTR;

type MessageBoxAFn = unsafe extern "system" fn(HWND, PCSTR, PCSTR, u32) -> i32;

static mut ORIGINAL: Option<MessageBoxAFn> = None;

unsafe extern "system" fn hooked(hwnd: HWND, _text: PCSTR, caption: PCSTR, utype: u32) -> i32 {
    let msg = "Hooked!\0";
    unsafe {
        ORIGINAL.unwrap()(hwnd, msg.as_ptr(), caption, utype)
    }
}

fn main() -> Result<()> {
    initialize()?;

    let (trampoline, target) =
        create_hook_api("user32", "MessageBoxA", hooked as *mut c_void)?;
    unsafe { ORIGINAL = Some(std::mem::transmute(trampoline)); }

    enable_hook(target)?;

    // MessageBoxA calls are now intercepted
    unsafe { MessageBoxA(ptr::null_mut(), b"Hello\0".as_ptr(), b"Test\0".as_ptr(), MB_OK); }

    disable_hook(target)?;
    remove_hook(target)?;
    uninitialize()
}
```

## API Reference

### Library Management

```rust
initialize() -> Result<()>
uninitialize() -> Result<()>
```

### Hook Creation

```rust
// Hook by address — returns trampoline
create_hook(target: *mut c_void, detour: *mut c_void) -> Result<*mut c_void>

// Hook by API name — returns (trampoline, target)
create_hook_api(module: &str, proc: &str, detour: *mut c_void) -> Result<(*mut c_void, *mut c_void)>

remove_hook(target: *mut c_void) -> Result<()>
```

### Hook Control

```rust
enable_hook(target: *mut c_void) -> Result<()>   // pass ALL_HOOKS to affect all
disable_hook(target: *mut c_void) -> Result<()>

// Deferred batch operations
queue_enable_hook(target: *mut c_void) -> Result<()>
queue_disable_hook(target: *mut c_void) -> Result<()>
apply_queued() -> Result<()>   // commits all queued changes atomically
```

## Usage Patterns

### Hook by Address

Use `create_hook` when you already have a function pointer.

```rust
initialize()?;
let trampoline = create_hook(my_fn as *mut c_void, detour as *mut c_void)?;
enable_hook(my_fn as *mut c_void)?;
```

### Bulk Enable / Disable

`ALL_HOOKS` (a null pointer sentinel) targets every registered hook at once.

```rust
enable_hook(ALL_HOOKS)?;
disable_hook(ALL_HOOKS)?;
```

### Queued (Atomic) Operations

Queue multiple changes and apply them in a single atomic step:

```rust
queue_enable_hook(target1)?;
queue_disable_hook(target2)?;
apply_queued()?;
```

### Error Handling

```rust
match create_hook_api("user32", "MessageBoxA", detour as *mut c_void) {
    Ok((trampoline, target)) => { /* ... */ }
    Err(HookError::ModuleNotFound)   => eprintln!("module not loaded"),
    Err(HookError::FunctionNotFound) => eprintln!("function not found"),
    Err(e) => eprintln!("{}", status_to_string(e)),
}
```

## Error Types

| Error | Description |
|---|---|
| `NotInitialized` | Call `initialize()` first |
| `AlreadyCreated` | Hook already exists for this target |
| `NotCreated` | No hook registered for this target |
| `Enabled` / `Disabled` | Hook already in the requested state |
| `ModuleNotFound` | Specified module is not loaded |
| `FunctionNotFound` | Function not exported by the module |
| `UnsupportedFunction` | Prologue too short or contains unhookable instructions |
| `MemoryAlloc` / `MemoryProtect` | Windows memory operation failed |

## x86_64 Instruction Structure

x86_64 uses **variable-length encoding** (1–15 bytes per instruction). Understanding the encoding is essential for trampoline generation, because the library must copy whole instructions out of the target prologue without splitting one in the middle.

```
[Legacy Prefixes] [REX] [Opcode] [ModR/M] [SIB] [Displacement] [Immediate]
      0–4          0–1    1–3      0–1     0–1       0–4/8          0–4/8
```

### Legacy Prefixes

| Byte | Meaning |
|---|---|
| `F0` | LOCK |
| `F2` / `F3` | REPNE / REP |
| `66` | Operand-size override (switches to 16-bit) |
| `67` | Address-size override |
| `2E 36 3E 26 64 65` | Segment overrides |

### REX Prefix (x64 only)

Occupies one byte in the range `40`–`4F`. Its four low bits extend register fields:

```
Bit 3 (W)  — 64-bit operand size
Bit 2 (R)  — extends ModR/M reg
Bit 1 (X)  — extends SIB index
Bit 0 (B)  — extends ModR/M r/m or SIB base
```

`REX.W = 1` is required for most 64-bit operations (`mov rax, ...`, `add rbx, ...`, etc.).

### ModR/M and SIB

**ModR/M** (1 byte) encodes the addressing mode and operands:

```
bits 7–6  mod   — 00: [reg], 01: [reg+disp8], 10: [reg+disp32], 11: reg direct
bits 5–3  reg   — source/destination register or opcode extension
bits 2–0  r/m   — second operand or memory base register
```

When `mod != 11` and `r/m == 100` (RSP), a **SIB** byte follows:

```
bits 7–6  scale — multiplier: 1/2/4/8
bits 5–3  index — index register (RSP here means no index)
bits 2–0  base  — base register (RBP here with mod=00 means disp32 only)
```

### RIP-relative Addressing

The most important case for hooking. When `mod == 00` and `r/m == 101`, the effective address is `RIP + disp32`:

```asm
mov rax, [rip + 0x1234]   ; 48 8B 05 34 12 00 00
lea rcx, [rip + label]    ; 48 8D 0D ...
call [rip + iat_slot]     ; FF 15 ...
```

When copying these instructions into a trampoline buffer at a different address, the `disp32` must be recalculated so the operand still points at the original target. This is the main transformation `trampoline.rs` performs.

### Relative Jumps and Calls

Branches use a **signed offset from the end of the instruction**, not an absolute address:

```asm
jmp  rel8    ; EB xx          — ±127 bytes
jmp  rel32   ; E9 xx xx xx xx — ±2 GB
call rel32   ; E8 xx xx xx xx — ±2 GB
jz   rel32   ; 0F 84 xx xx xx xx
```

Trampolines replace these with absolute indirect jumps (`FF 25 00000000 <addr>`) so they work regardless of where the trampoline buffer was allocated.

## Requirements

- **Architecture**: x86_64 only
- **OS**: Windows
- **Rust**: 1.85.0+
- **Privileges**: Administrator required for system-level hooks

## License

MIT — see [LICENSE](LICENSE).
