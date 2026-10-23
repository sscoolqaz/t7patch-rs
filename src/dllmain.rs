//! DLL entry points and the patch lifecycle.
//!
//! Port of the entry points in `dllmain.cpp`: `RunPatching`, the exported
//! `zbr_run_gamemode_lui` / `EnableInjectorlessInstall` / `Unload`, and `DllMain`.
//! The staged install and the rollback follow the fork's `PatchOperations`
//! (`2aa0d3e`); the state machine itself is [`crate::lifecycle`].

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Diagnostics::Debug::OutputDebugStringA;
use windows::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::{
    ABOVE_NORMAL_PRIORITY_CLASS, GetCurrentProcess, GetPriorityClass, PROCESS_CREATION_FLAGS,
    SetPriorityClass,
};
use windows::core::{BOOL, PCSTR};

use crate::lifecycle::{Lifecycle, Operations};
use crate::{arxan, exception, ffi, gscu_hash, hooks, protection};

const DEFAULT_PLAYER_NAME: &[u8] = b"Unknown Soldier";
const PATCH_KEY_PHRASE: &[u8] = b"serious_anticrash_2023";

/// Writes `message` to the debugger output stream.
pub(crate) fn debug_print(message: &str) {
    let Ok(text) = CString::new(message) else {
        return;
    };
    // SAFETY: `text` is a valid NUL-terminated string that lives for the call.
    unsafe { OutputDebugStringA(PCSTR(text.as_ptr().cast())) };
}

static LIFECYCLE: Lifecycle = Lifecycle::new();
/// Set once every hook has been created. Created hooks are kept for the life of the
/// process, because in-flight callbacks may still hold their trampolines.
static HOOKS_PREPARED: AtomicBool = AtomicBool::new(false);
/// Set while this module holds an initialized hooking library.
static HOOK_LIB_INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Set before the hooks are enabled, since enabling can fail after a subset is live.
static HOOKS_MAY_BE_ENABLED: AtomicBool = AtomicBool::new(false);
/// Process priority class before `activate`, or 0 when there is nothing to restore.
static ORIGINAL_PRIORITY: AtomicU32 = AtomicU32::new(0);

/// Port of the fork's `PatchOperations`. Its state lives in the statics above, so every
/// transition sees what earlier ones did.
struct PatchOps;

impl Operations for PatchOps {
    fn report_failure(&mut self, message: &str) {
        debug_print(&format!("T7 Patch installation failure: {message}\n"));
    }

    fn prepare(&mut self) -> Result<(), String> {
        arxan::install()?;
        // SAFETY: runs inside the game process once its executable is mapped.
        unsafe { protection::initialize() }?;
        if protection::CUSTOM_NAME[0].load(Ordering::Relaxed) == 0 {
            // As in the C++, only the local copy is set here, not the game's name buffers.
            let _ = protection::set_custom_name(DEFAULT_PLAYER_NAME);
        }
        protection::ZW_CONTINUE.store(exception::zw_continue_address(), Ordering::Relaxed);

        if !HOOKS_PREPARED.load(Ordering::Acquire) {
            if !HOOK_LIB_INITIALIZED.load(Ordering::Acquire) {
                ffi::initialize()
                    .map_err(|error| format!("T7 Patch: MinHook initialize failed: {error}"))?;
                HOOK_LIB_INITIALIZED.store(true, Ordering::Release);
            }
            hooks::create_hooks()?;
            HOOKS_PREPARED.store(true, Ordering::Release);
        }
        Ok(())
    }

    fn install_dispatcher(&mut self) -> Result<(), String> {
        // SAFETY: runs inside the game process, after ntdll is loaded.
        unsafe { exception::install() }
    }

    fn install_protection(&mut self) -> Result<(), String> {
        // SAFETY: `prepare` ran `protection::initialize` in this process.
        unsafe { protection::install() }?;
        hooks::apply_memory_patches()
    }

    fn activate(&mut self) -> Result<(), String> {
        // SAFETY: the current process handle is a pseudo-handle.
        let priority = unsafe { GetPriorityClass(GetCurrentProcess()) };
        if priority == 0 {
            return Err("T7 Patch: cannot set process priority".to_owned());
        }
        ORIGINAL_PRIORITY.store(priority, Ordering::Release);
        // SAFETY: as above.
        unsafe { SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS) }
            .map_err(|_| "T7 Patch: cannot set process priority".to_owned())?;

        hooks::apply_vmt_hooks()?;
        // Enabling can fail after a subset of hooks is live, so mark them first.
        HOOKS_MAY_BE_ENABLED.store(true, Ordering::Release);
        ffi::enable_all_hooks().map_err(|error| format!("T7 Patch: MinHook enable failed: {error}"))
    }

    fn start_worker(&mut self) -> Result<(), String> {
        protection::start_worker()
    }

    fn rollback(&mut self) -> Result<(), String> {
        // A stopped worker cannot race with restoring config and password state. If it
        // cannot be joined, leave all code and data it can use intact.
        protection::stop_worker()?;

        let mut failures = Vec::new();
        if HOOKS_MAY_BE_ENABLED.load(Ordering::Acquire) {
            match hooks::destroy_hooks() {
                Ok(()) => HOOKS_MAY_BE_ENABLED.store(false, Ordering::Release),
                Err(error) => failures.push(error),
            }
        }
        if let Err(error) = hooks::restore_vmt_hooks() {
            failures.push(error);
        }
        // SAFETY: runs inside the game process; uninstall undoes only what install recorded.
        if let Err(error) = unsafe { protection::uninstall() } {
            failures.push(error);
        }
        if let Err(error) = hooks::restore_memory_patches() {
            failures.push(error);
        }
        // SAFETY: as above.
        if let Err(error) = unsafe { exception::uninstall() } {
            failures.push(error);
        }
        let priority = ORIGINAL_PRIORITY.load(Ordering::Acquire);
        if priority != 0 {
            // SAFETY: the current process handle is a pseudo-handle.
            match unsafe { SetPriorityClass(GetCurrentProcess(), PROCESS_CREATION_FLAGS(priority)) }
            {
                Ok(()) => ORIGINAL_PRIORITY.store(0, Ordering::Release),
                Err(_) => failures.push("T7 Patch: cannot restore process priority".to_owned()),
            }
        }
        // In-flight callbacks may still hold trampolines, so completed hook tables are kept.
        // A partial creation never enabled any hook and can safely release its trampolines.
        if HOOK_LIB_INITIALIZED.load(Ordering::Acquire) && !HOOKS_PREPARED.load(Ordering::Acquire) {
            match ffi::uninitialize() {
                Ok(()) => HOOK_LIB_INITIALIZED.store(false, Ordering::Release),
                Err(error) => {
                    failures.push(format!("T7 Patch: MinHook uninitialize failed: {error}"));
                }
            }
        }

        if failures.is_empty() {
            Ok(())
        } else {
            debug_print("T7 Patch: restoration failed; further lifecycle transitions disabled.\n");
            Err(failures.join("; "))
        }
    }
}

/// Port of `RunPatching`: installs every patch through the lifecycle.
fn run_patching() {
    if !LIFECYCLE.install(&mut PatchOps) {
        debug_print("T7 Patch: install failed or another lifecycle transition is active.\n");
    }
}

/// Port of the exported `SetFriendsOnly`.
#[unsafe(no_mangle)]
pub extern "C" fn SetFriendsOnly(is_friends_only: u8) {
    protection::IS_FRIENDS_ONLY.store(is_friends_only != 0, Ordering::Relaxed);
}

/// Port of the exported `SetAutoInstallMods`.
#[unsafe(no_mangle)]
pub extern "C" fn SetAutoInstallMods(is_enabled: u8) {
    protection::IS_AUTO_INSTALL_MODS_ENABLED.store(is_enabled != 0, Ordering::Relaxed);
}

/// Port of the exported `SetPlayerName`. Names longer than 15 bytes are ignored.
///
/// # Safety
///
/// `name` must be null or a NUL-terminated string, and the game must be running.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SetPlayerName(name: *const c_char) {
    if name.is_null() {
        return;
    }
    // SAFETY: the caller passes a NUL-terminated string, checked for null above.
    let name = unsafe { CStr::from_ptr(name) }.to_bytes();
    // SAFETY: the caller guarantees the game, and so its name buffers, are running.
    unsafe { protection::set_player_name(name) };
}

/// Port of the exported `SetNetworkPassword`. An empty password clears it.
///
/// # Safety
///
/// `password` must be null or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn SetNetworkPassword(password: *const c_char) {
    let password = if password.is_null() {
        &[][..]
    } else {
        // SAFETY: the caller passes a NUL-terminated string, checked for null above.
        unsafe { CStr::from_ptr(password) }.to_bytes()
    };
    protection::set_network_password_text(password);
}

/// Enables the injectorless install path. Must be called before `zbr_run_gamemode_lui`.
#[unsafe(no_mangle)]
pub extern "C" fn EnableInjectorlessInstall() {
    protection::IS_INJECTORLESS_INSTALL.store(true, Ordering::Relaxed);
}

/// Starts the patch if `input` is the expected launch phrase.
///
/// # Safety
///
/// `input` must be null or a NUL-terminated string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn zbr_run_gamemode_lui(input: *const c_char) {
    if input.is_null() {
        return;
    }
    // SAFETY: the caller passes a NUL-terminated string, checked for null above.
    let phrase = unsafe { CStr::from_ptr(input) }.to_bytes();
    if gscu_hash::canon_hash(PATCH_KEY_PHRASE) == gscu_hash::canon_hash(phrase) {
        run_patching();
    }
}

/// Port of the fork's `Unload`: a logical deactivation that restores everything the patch
/// changed. Callers must not `FreeLibrary` while game callbacks are in flight.
#[unsafe(no_mangle)]
pub extern "C" fn Unload() {
    if !LIFECYCLE.unload(&mut PatchOps) {
        debug_print("T7 Patch: unload failed or the patch is not active.\n");
    }
}

/// DLL entry point. Disables thread-attach notifications, which the patch never uses.
///
/// # Safety
///
/// Called only by the Windows loader with a valid module handle.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    module: HMODULE,
    reason: u32,
    _reserved: *mut c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        // SAFETY: `module` is the handle the loader passed to `DllMain`.
        let _ = unsafe { DisableThreadLibraryCalls(module) };
    }
    BOOL(1)
}
