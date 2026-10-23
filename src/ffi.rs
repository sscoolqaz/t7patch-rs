//! Bindings to the vendored `MinHook` library.
//!
//! The library is linked by `build.rs` from `vendor/minhook/lib`. Only the
//! functions the patch uses are declared. Safe wrappers return `Result` so
//! callers do not compare raw status codes.

use std::fmt;

/// Raw `MH_STATUS` value.
pub type RawStatus = i32;

const MH_OK: RawStatus = 0;

/// Failure reported by `MinHook`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MinHookError(pub RawStatus);

impl fmt::Display for MinHookError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MinHook status {}", self.0)
    }
}

impl std::error::Error for MinHookError {}

fn check(status: RawStatus) -> Result<(), MinHookError> {
    if status == MH_OK {
        Ok(())
    } else {
        Err(MinHookError(status))
    }
}

unsafe extern "system" {
    fn MH_Initialize() -> RawStatus;
    fn MH_Uninitialize() -> RawStatus;
    fn MH_CreateHook(target: *mut u8, detour: *mut u8, original: *mut *mut u8) -> RawStatus;
    fn MH_RemoveHook(target: *mut u8) -> RawStatus;
    fn MH_EnableHook(target: *mut u8) -> RawStatus;
    fn MH_DisableHook(target: *mut u8) -> RawStatus;
}

/// Initializes `MinHook`. Call once before creating hooks.
pub fn initialize() -> Result<(), MinHookError> {
    // SAFETY: `MinHook` takes no arguments and is safe to call once at startup.
    check(unsafe { MH_Initialize() })
}

/// Tears `MinHook` down, disabling and removing every hook it created.
pub fn uninitialize() -> Result<(), MinHookError> {
    // SAFETY: `MinHook` takes no arguments; the caller must not call hooked functions afterwards.
    check(unsafe { MH_Uninitialize() })
}

/// Creates a hook from `target` to `detour` and returns the trampoline that
/// calls the original function.
///
/// # Safety
///
/// `target` must be the entry point of a function whose signature matches
/// `detour`. `detour` must stay valid for the lifetime of the hook.
pub unsafe fn create_hook(target: usize, detour: usize) -> Result<usize, MinHookError> {
    let mut original: *mut u8 = std::ptr::null_mut();
    // SAFETY: the caller guarantees `target` is a valid function and `detour` a matching function.
    check(unsafe { MH_CreateHook(target as *mut u8, detour as *mut u8, &raw mut original) })?;
    Ok(original as usize)
}

/// Enables a previously created hook.
///
/// # Safety
///
/// `target` must be the address passed to [`create_hook`].
pub unsafe fn enable_hook(target: usize) -> Result<(), MinHookError> {
    // SAFETY: the caller guarantees `target` was hooked by [`create_hook`].
    check(unsafe { MH_EnableHook(target as *mut u8) })
}

/// Disables a hook without removing it.
///
/// # Safety
///
/// `target` must be the address passed to [`create_hook`].
pub unsafe fn disable_hook(target: usize) -> Result<(), MinHookError> {
    // SAFETY: the caller guarantees `target` was hooked by [`create_hook`].
    check(unsafe { MH_DisableHook(target as *mut u8) })
}

/// Removes a hook entirely.
///
/// # Safety
///
/// `target` must be the address passed to [`create_hook`].
pub unsafe fn remove_hook(target: usize) -> Result<(), MinHookError> {
    // SAFETY: the caller guarantees `target` was hooked by [`create_hook`].
    check(unsafe { MH_RemoveHook(target as *mut u8) })
}
