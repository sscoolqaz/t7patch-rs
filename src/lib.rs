//! Rust port of `T7Patch`, a community patch for Call of Duty: Black Ops III.
//!
//! Ported so far: name hashing, the FNV variant, build detection, game struct
//! layouts, the offset table, the `MinHook` bindings, the Arxan bypass, and the
//! campaign script fix. Still to port: hooks, protection, Lua symbols, the
//! exception-dispatch hook, and the DLL entry point.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod arxan;
pub mod build;
pub mod campaign;
pub mod dllmain;
pub mod exception;
pub mod ffi;
pub mod fnv;
pub mod gscu_hash;
pub mod hooks;
pub mod lua_symbols;
pub mod offsets;
pub mod protection;
pub mod structs;
