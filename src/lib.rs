//! Rust port of `T7Patch`, a community patch for Call of Duty: Black Ops III.
//!
//! Ported so far: name hashing, the FNV variant, build detection, game struct
//! layouts, the offset table, and the `MinHook` bindings. Still to port: hooks,
//! protection, Arxan bypass, Lua symbols, campaign fixes, the exception-dispatch
//! hook, and the DLL entry point.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod build;
pub mod ffi;
pub mod fnv;
pub mod gscu_hash;
pub mod offsets;
pub mod structs;
