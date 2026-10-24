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
use crate::{arxan, diag, exception, ffi, gscu_hash, hooks, protection};

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

/// Patch components for in-game diagnosis, chosen with the `T7PATCH_ONLY`
/// environment variable: a comma-separated subset of `arxan`, `dispatcher`,
/// `protection` and the hook names below. Unset, everything is installed, as upstream
/// does. `hooks` means every hook stage. To split it, `create` creates the `MinHook`
/// detours without enabling them, `detours` creates and enables them, and `vmt` applies
/// the lobby VMT hook, which is independent of the detours. `trace` adds the
/// diagnostic hook in [`crate::diag`]; it is not part of the default set, and it
/// enables every hook that was created.
/// Proton passes launch-option variables through to the game, so a component
/// can be switched off without a rebuild.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Components(u8);

impl Components {
    const NONE: Self = Self(0);
    const ARXAN: Self = Self(1 << 0);
    const DISPATCHER: Self = Self(1 << 1);
    const CREATE_HOOKS: Self = Self(1 << 2);
    const ENABLE_HOOKS: Self = Self(1 << 3);
    const VMT_HOOK: Self = Self(1 << 4);
    const PROTECTION: Self = Self(1 << 5);
    const TRACE: Self = Self(1 << 6);
    /// Everything upstream installs. `TRACE` is diagnostic and never part of it.
    const ALL: Self = Self::ARXAN
        .with(Self::DISPATCHER)
        .with(Self::CREATE_HOOKS)
        .with(Self::ENABLE_HOOKS)
        .with(Self::VMT_HOOK)
        .with(Self::PROTECTION);

    /// The named components, in the order the diagnostic line prints them.
    const NAMES: [(&'static str, Self); 7] = [
        ("arxan", Self::ARXAN),
        ("dispatcher", Self::DISPATCHER),
        ("create_hooks", Self::CREATE_HOOKS),
        ("enable_hooks", Self::ENABLE_HOOKS),
        ("vmt_hook", Self::VMT_HOOK),
        ("protection", Self::PROTECTION),
        ("trace", Self::TRACE),
    ];

    const fn with(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Parses a `T7PATCH_ONLY` value. Unknown names are ignored. Enabled detours imply
    /// created ones.
    fn parse(value: &str) -> Self {
        let has = |name: &str| {
            value
                .split(',')
                .any(|part| part.trim().eq_ignore_ascii_case(name))
        };
        let mut components = Self::NONE;
        let mut add = |present: bool, component: Self| {
            if present {
                components = components.with(component);
            }
        };
        let all_hooks = has("hooks");
        let enable_hooks = all_hooks || has("detours");
        add(has("arxan"), Self::ARXAN);
        add(has("dispatcher"), Self::DISPATCHER);
        add(enable_hooks || has("create"), Self::CREATE_HOOKS);
        add(enable_hooks, Self::ENABLE_HOOKS);
        add(all_hooks || has("vmt"), Self::VMT_HOOK);
        add(has("protection"), Self::PROTECTION);
        add(has("trace"), Self::TRACE);
        components
    }

    fn current() -> Self {
        static CURRENT: std::sync::OnceLock<Components> = std::sync::OnceLock::new();
        *CURRENT.get_or_init(|| {
            let components =
                std::env::var("T7PATCH_ONLY").map_or(Self::ALL, |value| Self::parse(&value));
            if components != Self::ALL {
                debug_print(&format!("T7 Patch: diagnostic components {components:?}\n"));
            }
            components
        })
    }
}

/// Prints the same `Components { arxan: true, ... }` form as the earlier struct, so the
/// diagnostic line in the Proton log keeps its format.
impl std::fmt::Debug for Components {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out = f.debug_struct("Components");
        for (name, component) in Self::NAMES {
            out.field(name, &self.contains(component));
        }
        out.finish()
    }
}

/// Port of the fork's `PatchOperations`. Its state lives in the statics above, so every
/// transition sees what earlier ones did.
struct PatchOps;

impl Operations for PatchOps {
    fn report_failure(&mut self, message: &str) {
        debug_print(&format!("T7 Patch installation failure: {message}\n"));
    }

    fn prepare(&mut self) -> Result<(), String> {
        let components = Components::current();
        if components.contains(Components::ARXAN) {
            arxan::install()?;
        }
        // SAFETY: runs inside the game process once its executable is mapped.
        unsafe { protection::initialize() }?;
        if protection::custom_name_is_empty() {
            // As in the C++, only the local copy is set here, not the game's name buffers.
            let _ = protection::set_custom_name(DEFAULT_PLAYER_NAME);
        }
        protection::ZW_CONTINUE.store(exception::zw_continue_address(), Ordering::Relaxed);

        if (components.contains(Components::CREATE_HOOKS) || components.contains(Components::TRACE))
            && !HOOKS_PREPARED.load(Ordering::Acquire)
        {
            if !HOOK_LIB_INITIALIZED.load(Ordering::Acquire) {
                ffi::initialize()
                    .map_err(|error| format!("T7 Patch: MinHook initialize failed: {error}"))?;
                HOOK_LIB_INITIALIZED.store(true, Ordering::Release);
            }
            if components.contains(Components::CREATE_HOOKS) {
                hooks::create_all()?;
            }
            if components.contains(Components::TRACE) {
                diag::create_trace_hook()?;
            }
            HOOKS_PREPARED.store(true, Ordering::Release);
        }
        Ok(())
    }

    fn install_dispatcher(&mut self) -> Result<(), String> {
        if !Components::current().contains(Components::DISPATCHER) {
            return Ok(());
        }
        // SAFETY: runs inside the game process, after ntdll is loaded.
        unsafe { exception::install() }
    }

    fn install_protection(&mut self) -> Result<(), String> {
        if !Components::current().contains(Components::PROTECTION) {
            return Ok(());
        }
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

        let components = Components::current();
        if components.contains(Components::VMT_HOOK) {
            hooks::apply_vmt()?;
        }
        if !components.contains(Components::ENABLE_HOOKS) && !components.contains(Components::TRACE)
        {
            return Ok(());
        }
        // Enabling can fail after a subset of hooks is live, so mark them first.
        HOOKS_MAY_BE_ENABLED.store(true, Ordering::Release);
        ffi::enable_all_hooks().map_err(|error| format!("T7 Patch: MinHook enable failed: {error}"))
    }

    fn start_worker(&mut self) -> Result<(), String> {
        if !Components::current().contains(Components::PROTECTION) {
            return Ok(());
        }
        protection::start_worker()
    }

    fn rollback(&mut self) -> Result<(), String> {
        // A stopped worker cannot race with restoring config and password state. If it
        // cannot be joined, leave all code and data it can use intact.
        protection::stop_worker()?;

        let mut failures = Vec::new();
        if HOOKS_MAY_BE_ENABLED.load(Ordering::Acquire) {
            match hooks::disable_all() {
                Ok(()) => HOOKS_MAY_BE_ENABLED.store(false, Ordering::Release),
                Err(error) => failures.push(error),
            }
        }
        if let Err(error) = hooks::restore_vmt() {
            failures.push(error);
        }
        // SAFETY: runs inside the game process; uninstall undoes only what install recorded.
        if let Err(error) = unsafe { protection::uninstall() } {
            failures.push(error);
        }
        if let Err(error) = hooks::restore_memory_patches() {
            failures.push(error);
        }
        // SAFETY: as above. The dispatcher is retained after any producer was exposed.
        if let Err(error) =
            unsafe { exception::uninstall(protection::exception_producers_remaining()) }
        {
            failures.push(error);
        }
        // The bypass goes last: it hides every code patch removed above, so it is
        // kept while any of them may still be in the image.
        match arxan::uninstall(!failures.is_empty() || HOOKS_MAY_BE_ENABLED.load(Ordering::Acquire))
        {
            Ok(arxan::Removal::Retained) => failures.push(
                "T7 Patch: Arxan bypass retained; dependent patches are still live".to_owned(),
            ),
            Ok(arxan::Removal::Restored | arxan::Removal::External) => {}
            Err(error) => failures.push(error),
        }
        if arxan::protection_lost() {
            failures.push("T7 Patch: a page protection could not be restored".to_owned());
        }
        if crate::threads::thaw_failed() {
            failures.push("T7 Patch: a game thread could not be resumed".to_owned());
        }
        if ffi::flush_failed() {
            failures.push("T7 Patch: a hook's instruction cache flush failed".to_owned());
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
/// The game buffers are updated on the next game-thread username lookup.
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

/// Port of the fork's `Unload`: a logical deactivation. Hooks, Steam vtable slots, the lobby
/// marker and the update-preload pointer are restored. The exception dispatcher stays
/// installed once an induced-exception patch has been live, and the dvar settings changed at
/// install stay applied. Physical unloading is not available: installing the dispatcher pins
/// this module (`GET_MODULE_HANDLE_EX_FLAG_PIN`), so `FreeLibrary` leaves it mapped and every
/// callback address it handed out stays valid.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostic_components_parse_a_subset() {
        assert_eq!(Components::parse("dispatcher"), Components::DISPATCHER);
        assert!(Components::parse(" Arxan , DISPATCHER,bogus").contains(Components::ARXAN));
        assert_eq!(
            Components::parse("arxan,dispatcher,hooks,protection"),
            Components::ALL
        );
        assert_eq!(Components::parse(""), Components::NONE);
    }

    #[test]
    fn diagnostic_components_split_the_hook_stage() {
        let base = Components::parse("arxan,dispatcher,protection");
        assert_eq!(
            Components::parse("arxan,dispatcher,protection,create"),
            base.with(Components::CREATE_HOOKS)
        );
        assert_eq!(
            Components::parse("arxan,dispatcher,protection,detours"),
            base.with(Components::CREATE_HOOKS)
                .with(Components::ENABLE_HOOKS)
        );
        assert_eq!(
            Components::parse("arxan,dispatcher,protection,vmt"),
            base.with(Components::VMT_HOOK)
        );
        assert_eq!(
            Components::parse("arxan,dispatcher,protection,detours,vmt"),
            Components::ALL
        );
        assert_eq!(
            Components::parse("arxan,dispatcher,protection,detours,trace"),
            base.with(Components::CREATE_HOOKS)
                .with(Components::ENABLE_HOOKS)
                .with(Components::TRACE)
        );
        // `trace` alone stays independent of the hook stages.
        assert_eq!(Components::parse("trace"), Components::TRACE);
        assert!(!Components::ALL.contains(Components::TRACE));
    }

    #[test]
    fn diagnostic_components_keep_the_logged_format() {
        assert_eq!(
            format!("{:?}", Components::parse("arxan,detours,trace")),
            "Components { arxan: true, dispatcher: false, create_hooks: true, \
             enable_hooks: true, vmt_hook: false, protection: false, trace: true }"
        );
    }
}
