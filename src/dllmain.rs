//! DLL entry points and the patch lifecycle.
//!
//! Port of the entry points in `dllmain.cpp`: `RunPatching`, the exported
//! `zbr_run_gamemode_lui` / `EnableInjectorlessInstall` / `Unload`, and `DllMain`.

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::atomic::Ordering;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HMODULE};
use windows::Win32::System::Diagnostics::Debug::{
    CONTEXT, CONTEXT_FLAGS, GetThreadContext, OutputDebugStringA, SetThreadContext,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows::Win32::System::LibraryLoader::DisableThreadLibraryCalls;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::System::Threading::{
    ABOVE_NORMAL_PRIORITY_CLASS, GetCurrentProcess, GetCurrentProcessId, GetCurrentThreadId,
    OpenThread, ResumeThread, SetPriorityClass, SuspendThread, THREAD_ALL_ACCESS,
};
use windows::core::{BOOL, PCSTR};

use crate::{arxan, exception, ffi, gscu_hash, hooks, protection};

/// `CONTEXT_DEBUG_REGISTERS` for x64: the flag set that covers Dr0 through Dr7.
const CONTEXT_DEBUG_REGISTERS: u32 = 0x0010_0010;
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

/// Thread ids of every thread in this process except the calling one.
fn other_thread_ids() -> Vec<u32> {
    let mut ids = Vec::new();
    // SAFETY: a thread snapshot has no preconditions; it is closed below.
    let Ok(snapshot) = (unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }) else {
        return ids;
    };

    // SAFETY: the process and thread id queries have no preconditions.
    let (process, current) = unsafe { (GetCurrentProcessId(), GetCurrentThreadId()) };
    let mut entry = THREADENTRY32 {
        dwSize: u32::try_from(size_of::<THREADENTRY32>()).unwrap_or_default(),
        ..Default::default()
    };
    // SAFETY: `entry` is sized as the API requires.
    if unsafe { Thread32First(snapshot, &raw mut entry) }.is_ok() {
        loop {
            if entry.th32OwnerProcessID == process && entry.th32ThreadID != current {
                ids.push(entry.th32ThreadID);
            }
            // SAFETY: as above.
            if unsafe { Thread32Next(snapshot, &raw mut entry) }.is_err() {
                break;
            }
        }
    }

    // SAFETY: `snapshot` was opened above and is not used afterwards.
    let _ = unsafe { CloseHandle(snapshot) };
    ids
}

/// Opens a thread with full access, or `None` if it has already exited.
fn open_thread(id: u32) -> Option<HANDLE> {
    // SAFETY: opening a thread has no memory preconditions.
    unsafe { OpenThread(THREAD_ALL_ACCESS, false, id) }.ok()
}

/// Installs every patch in the order the original uses.
fn run_patching() {
    // SAFETY: the current process handle is a pseudo-handle.
    let _ = unsafe { SetPriorityClass(GetCurrentProcess(), ABOVE_NORMAL_PRIORITY_CLASS) };

    if let Err(message) = arxan::install() {
        debug_print(&format!("T7 Patch: {message}\n"));
        return;
    }

    let _ = ffi::initialize();

    if protection::CUSTOM_NAME[0].load(Ordering::Relaxed) == 0 {
        // As in the C++, only the local copy is set here, not the game's name buffers.
        let _ = protection::set_custom_name(DEFAULT_PLAYER_NAME);
    }

    protection::ZW_CONTINUE.store(exception::zw_continue_address(), Ordering::Relaxed);

    hooks::apply_vmt_hooks();
    hooks::apply_hooks();
    hooks::apply_memory_patches();

    // SAFETY: called once from inside the game process, after its patches are in place.
    unsafe { exception::install() };
    // SAFETY: as above.
    unsafe { protection::install() };
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

/// Removes the patch: clears debug registers, unhooks, and resumes the other threads.
#[unsafe(no_mangle)]
pub extern "C" fn Unload() {
    for id in other_thread_ids() {
        let Some(thread) = open_thread(id) else {
            continue;
        };
        // SAFETY: `thread` is a valid handle; it is closed after use.
        unsafe {
            SuspendThread(thread);
            let mut context = CONTEXT {
                ContextFlags: CONTEXT_FLAGS(CONTEXT_DEBUG_REGISTERS),
                ..Default::default()
            };
            if GetThreadContext(thread, &raw mut context).is_ok() {
                context.Dr7 = 0;
                context.ContextFlags = CONTEXT_FLAGS(CONTEXT_DEBUG_REGISTERS);
                let _ = SetThreadContext(thread, &raw const context);
            }
            let _ = CloseHandle(thread);
        }
    }

    // SAFETY: the protection hooks were installed by `run_patching`.
    unsafe { protection::uninstall() };
    exception::IS_UNHOOKING.store(true, Ordering::Release);
    // SAFETY: the exception hook was installed by `run_patching`.
    unsafe { exception::uninstall() };
    // Not in the C++: disable the detours so none jumps into this DLL after it is freed.
    hooks::destroy_hooks();

    for id in other_thread_ids() {
        if let Some(thread) = open_thread(id) {
            // SAFETY: `thread` is a valid handle; it is closed after use.
            unsafe {
                ResumeThread(thread);
                let _ = CloseHandle(thread);
            }
        }
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
