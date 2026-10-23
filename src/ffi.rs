//! Wrappers over `min_hook_rs`, a pure-Rust port of `MinHook`.
//!
//! The port keeps `MinHook`'s design: the HDE64 length decoder, trampolines
//! allocated within 2 GB of the target, and thread suspension while patching.
//! Its functions are safe to call in Rust's type system, but hooking arbitrary
//! addresses is not, so the wrappers below keep `unsafe` contracts. They take
//! addresses as `usize`, as the rest of the port does.

use std::ffi::c_void;

use min_hook_rs::{ALL_HOOKS, HookError};

/// Failure reported by the hooking library. The codes match `MH_STATUS`.
pub type MinHookError = HookError;

/// Initializes the hooking library. Call once before creating hooks.
pub fn initialize() -> Result<(), MinHookError> {
    min_hook_rs::initialize()
}

/// Tears the hooking library down, disabling and removing every hook it created.
pub fn uninitialize() -> Result<(), MinHookError> {
    min_hook_rs::uninitialize()
}

/// Creates a hook from `target` to `detour` and returns the trampoline that
/// calls the original function.
///
/// # Safety
///
/// `target` must be the entry point of a function whose signature matches
/// `detour`. `detour` must stay valid for the lifetime of the hook.
pub unsafe fn create_hook(target: usize, detour: usize) -> Result<usize, MinHookError> {
    let original = min_hook_rs::create_hook(target as *mut c_void, detour as *mut c_void)?;
    Ok(original as usize)
}

/// Enables a previously created hook.
///
/// # Safety
///
/// `target` must be the address passed to [`create_hook`].
pub unsafe fn enable_hook(target: usize) -> Result<(), MinHookError> {
    min_hook_rs::enable_hook(target as *mut c_void)
}

/// Disables a hook without removing it. A `target` of 0 disables every hook.
///
/// # Safety
///
/// `target` must be 0 or the address passed to [`create_hook`].
pub unsafe fn disable_hook(target: usize) -> Result<(), MinHookError> {
    min_hook_rs::disable_hook(target as *mut c_void)
}

/// Removes a hook entirely.
///
/// # Safety
///
/// `target` must be the address passed to [`create_hook`].
pub unsafe fn remove_hook(target: usize) -> Result<(), MinHookError> {
    min_hook_rs::remove_hook(target as *mut c_void)
}

/// Enables every hook created so far.
pub fn enable_all_hooks() -> Result<(), MinHookError> {
    min_hook_rs::enable_hook(ALL_HOOKS)
}

#[cfg(test)]
mod tests {
    use super::*;

    type MixFn = extern "system" fn(u64) -> u64;

    // Long enough for the 5-byte jump the hook writes over its prologue.
    #[inline(never)]
    extern "system" fn mix(seed: u64) -> u64 {
        let mut value = seed;
        for round in 0..std::hint::black_box(8u64) {
            value = value.wrapping_mul(31).wrapping_add(round);
        }
        value
    }

    extern "system" fn mix_detour(seed: u64) -> u64 {
        seed ^ 0xA5A5
    }

    #[test]
    fn hook_redirects_and_trampoline_calls_original() {
        let call: MixFn = std::hint::black_box(mix);
        let original = call(7);
        let target = mix as MixFn as usize;

        let _ = initialize();
        // SAFETY: `mix` and `mix_detour` share the signature `MixFn` and live for the test.
        let trampoline =
            unsafe { create_hook(target, mix_detour as MixFn as usize) }.expect("create_hook");
        // SAFETY: `target` was hooked above.
        unsafe { enable_hook(target) }.expect("enable_hook");
        assert_eq!(call(7), 7 ^ 0xA5A5);

        // SAFETY: the trampoline runs the original `mix`, so it has the type `MixFn`.
        let through: MixFn = unsafe { std::mem::transmute::<usize, MixFn>(trampoline) };
        assert_eq!(through(7), original);

        // SAFETY: `target` was hooked above.
        unsafe { disable_hook(target) }.expect("disable_hook");
        assert_eq!(call(7), original);
        // SAFETY: `target` was hooked above.
        unsafe { remove_hook(target) }.expect("remove_hook");
        uninitialize().expect("uninitialize");
    }
}
