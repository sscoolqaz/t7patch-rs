//! Rust port of `T7Patch`, a community patch for Call of Duty: Black Ops III.
//!
//! Ported: name hashing, the FNV variant, build detection, game struct layouts,
//! the offset table, the `MinHook` bindings, the Arxan bypass, the campaign
//! script fix, the protection module, the Lua symbol tables, the hooks, the
//! exception-dispatch hook, the staged patch lifecycle, thread freezing for
//! executable code writes, and the DLL entry point. None of it has run in the
//! game yet.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod arxan;
pub mod build;
pub mod campaign;
pub mod crash_queue;
pub mod dllmain;
pub mod exception;
pub mod ffi;
pub mod fnv;
pub mod gscu_hash;
pub mod hooks;
pub mod lifecycle;
pub mod lua_symbols;
pub mod offsets;
pub mod protection;
pub mod structs;
mod threads;
