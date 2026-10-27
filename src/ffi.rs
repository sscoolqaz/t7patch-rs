//! Wrappers over `min_hook_rs`, a pure-Rust port of `MinHook`, vendored and
//! patched in `vendor/min_hook_rs` (see its `VENDORED.md`).
//!
//! The port keeps `MinHook`'s design: trampolines allocated near the target
//! (within 1 GB) and thread suspension while patching. Trampolines are relocated
//! with iced-x86 and validated before they are written.
//! The vendored copy freezes fail closed and applies each change as one
//! transaction: on an error no hook changes state, with two exceptions. After
//! [`HookError::ThreadResume`] the change may have applied. After
//! [`HookError::ThreadContext`], if a moved thread's context could not be restored,
//! every hook in the change is left disabled.
//!
//! Every wrapper holds [`crate::threads::lock_transaction`], so a hook change never
//! runs alongside the crate's own code writes: two freezes at once could suspend each
//! other. The lock order is the patch transaction, then the library's own lock. Once
//! any freeze has left a thread suspended, every wrapper refuses.
//! Its functions are safe to call in Rust's type system, but hooking arbitrary
//! addresses is not, so the wrappers below keep `unsafe` contracts. They take
//! addresses as `usize`, as the rest of the port does.

use std::ffi::c_void;

use std::sync::MutexGuard;

use min_hook_rs::{ALL_HOOKS, HookError};

/// Failure reported by the hooking library. Codes 1 to 12 match `MH_STATUS`.
/// The vendored copy adds three:
///
/// - [`HookError::ThreadSuspend`] (13): a thread could not be enumerated,
///   opened or suspended, so nothing was patched.
/// - [`HookError::ThreadContext`] (14): a suspended thread's context could not
///   be read or written, and the change was rolled back. If a moved thread's
///   context could not be restored either, every hook in the change is left
///   disabled instead.
/// - [`HookError::ThreadResume`] (15): a frozen thread could not be resumed. The
///   change may have applied. Terminal: every later call is refused with it.
/// - [`HookError::Overlapping`] (16): the new hook's bytes (its patch range, the
///   hot-patch bytes above it, or the source bytes its trampoline copies) overlap
///   another hook's. Nothing was created.
/// - [`HookError::TargetModified`] (17): just before a write, a hook's bytes no longer
///   held what the hook left there (the original code, or its own jump once
///   enabled), or could not be read. Nothing was written and no hook changed state.
pub type MinHookError = HookError;

/// True once the hooking library could not flush the instruction cache over a patch.
#[must_use]
pub fn flush_failed() -> bool {
    min_hook_rs::flush_failed()
}

/// Takes the patch transaction for one library call, or refuses once a freeze has
/// left a thread suspended.
fn transaction() -> Result<MutexGuard<'static, ()>, MinHookError> {
    let guard = crate::threads::lock_transaction();
    if crate::threads::thaw_failed() {
        return Err(HookError::ThreadResume);
    }
    Ok(guard)
}

/// Initializes the hooking library. Call once before creating hooks.
///
/// # Errors
///
/// Returns the hooking library's error when it is already initialized or its internal
/// lock is poisoned, and [`HookError::ThreadResume`] once a freeze has left a thread
/// suspended.
pub fn initialize() -> Result<(), MinHookError> {
    let _transaction = transaction()?;
    min_hook_rs::initialize()
}

/// Tears the hooking library down, disabling and removing every hook it created.
/// The trampolines are freed only if no frozen thread's instruction pointer,
/// general-purpose register or live stack word points into one, and every stack
/// could be read in full; otherwise they are kept for the process lifetime. On
/// error the library stays initialized.
///
/// # Errors
///
/// Returns the hooking library's error when a hook cannot be disabled or threads cannot be frozen. The library then stays initialized.
pub fn uninitialize() -> Result<(), MinHookError> {
    let _transaction = transaction()?;
    min_hook_rs::uninitialize()
}

/// Creates a hook from `target` to `detour` and returns the trampoline that
/// calls the original function.
///
/// # Safety
///
/// `target` must be the entry point of a function whose signature matches
/// `detour`. `detour` must stay valid for the lifetime of the hook.
///
/// # Errors
///
/// Returns the hooking library's error when `target` is already hooked, is not executable, its bytes overlap another hook's ([`HookError::Overlapping`]), or its prologue cannot be relocated into a trampoline.
pub unsafe fn create_hook(target: usize, detour: usize) -> Result<usize, MinHookError> {
    let _transaction = transaction()?;
    let original = min_hook_rs::create_hook(target as *mut c_void, detour as *mut c_void)?;
    Ok(original as usize)
}

/// Enables a previously created hook.
///
/// # Safety
///
/// `target` must be the address passed to [`create_hook`].
///
/// # Errors
///
/// Returns the hooking library's error when the hook does not exist or its jump cannot be written safely, including [`HookError::TargetModified`] when the target's bytes changed since the hook was created.
pub unsafe fn enable_hook(target: usize) -> Result<(), MinHookError> {
    let _transaction = transaction()?;
    min_hook_rs::enable_hook(target as *mut c_void)
}

/// Disables a hook without removing it. A `target` of 0 disables every hook.
///
/// # Safety
///
/// `target` must be 0 or the address passed to [`create_hook`].
///
/// # Errors
///
/// Returns the hooking library's error when the hook does not exist or the original bytes cannot be written back safely.
pub unsafe fn disable_hook(target: usize) -> Result<(), MinHookError> {
    let _transaction = transaction()?;
    min_hook_rs::disable_hook(target as *mut c_void)
}

/// Removes a hook entirely. Its trampoline is freed only if no frozen thread's
/// instruction pointer, general-purpose register or live stack word points into
/// it, and every stack could be read in full; otherwise it is kept for the process
/// lifetime. On error the hook is kept.
///
/// # Safety
///
/// `target` must be the address passed to [`create_hook`].
///
/// # Errors
///
/// Returns the hooking library's error when the hook does not exist or cannot be disabled. The hook is then kept.
pub unsafe fn remove_hook(target: usize) -> Result<(), MinHookError> {
    let _transaction = transaction()?;
    min_hook_rs::remove_hook(target as *mut c_void)
}

/// Enables every hook created so far.
///
/// # Errors
///
/// Returns the hooking library's error when a jump cannot be written safely. Hooks enabled before the failure may stay enabled.
pub fn enable_all_hooks() -> Result<(), MinHookError> {
    let _transaction = transaction()?;
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

    #[test]
    fn freeze_errors_have_stable_codes_and_messages() {
        assert_eq!(MinHookError::ThreadSuspend as i32, 13);
        assert_eq!(MinHookError::ThreadContext as i32, 14);
        assert_eq!(MinHookError::from_code(13), MinHookError::ThreadSuspend);
        assert_eq!(MinHookError::from_code(14), MinHookError::ThreadContext);
        assert_eq!(MinHookError::ThreadResume as i32, 15);
        assert_eq!(MinHookError::from_code(15), MinHookError::ThreadResume);
        assert_eq!(MinHookError::Overlapping as i32, 16);
        assert_eq!(MinHookError::from_code(16), MinHookError::Overlapping);
        assert_eq!(MinHookError::TargetModified as i32, 17);
        assert_eq!(MinHookError::from_code(17), MinHookError::TargetModified);
        assert_eq!(
            MinHookError::ThreadResume.to_string(),
            "Thread resume failed"
        );
        assert_eq!(
            MinHookError::ThreadSuspend.to_string(),
            "Thread suspension failed"
        );
        assert_eq!(
            MinHookError::ThreadContext.to_string(),
            "Thread context access failed"
        );
    }
}
