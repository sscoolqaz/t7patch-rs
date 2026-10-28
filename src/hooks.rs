//! Port of `Hooks.cpp` and `Hooks.h`: the `MinHook` detours, the lobby VMT swap,
//! and the byte patches applied to the game image.
//!
//! The C++ `hooks::functions` namespace becomes the `hk_*` detours below. The
//! `isModLoadedAddrs` list is credited in the C++ source to Scropts-QOL.
//!
//! Each detour that calls the original does so through the `MinHook` trampoline
//! stored in an `Original` slot, as the C++ does through its globals. Game
//! functions the C++ calls without a hook are resolved directly with
//! [`offsets::function`].
//!
//! `SPOOF_UNLOCK`, `SPOOF_RANKED`, `SPOOF_SKIP_CWL` and `SPOOF_OWNERSHIP` are
//! `false` in `framework.h`, so every `#if SPOOF_*` branch is compiled out of the
//! C++ build and is not ported here.

use std::ffi::{CStr, c_char, c_void};
use std::marker::PhantomData;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, PoisonError};

use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::Win32::System::Threading::GetCurrentProcess;

use crate::arxan;
use crate::campaign;
use crate::ffi;
use crate::lua_symbols;
use crate::offsets;
use crate::protection::{
    self, CbufAddTextFn, IS_AUTO_INSTALL_MODS_ENABLED, IS_FRIENDS_ONLY, IStricmpFn,
    PRIVATE_PASSWORD,
};
use crate::structs::{LobbyMsg, Msg, NetAdr};

// ---------------------------------------------------------------------------
// Addresses
// ---------------------------------------------------------------------------
//
// February-2026 RVAs. Names follow `offsets.h`. Each is resolved with
// `offsets::address` at the point of use. Functions that already have a
// `PTR_*` or `DW_LOBBY` name in `offsets.rs` use that name instead.

const LOBBY_MSG_RW_PREP_READ_MSG: usize = 0x1EEB8D0;
const COD_GET_BUILD_TITLE: usize = 0x20E31C0;
const LIVE_SYSTEM_INFO: usize = 0x1E016C0;
const LOBBY_TYPES_GET_MSG_TYPE_NAME: usize = 0x1EDFA60;
const QMEMCPY: usize = 0x2BC4EB0;
const FLSOME_WEIRD_CHARACTER_INDEX: usize = 0x22C9650;
const SEH_REPLACE_DIRECTIVE_IN_STRING_WITH_BINDING: usize = 0x221CE90;
const UI_DO_MODEL_STRING_REPLACEMENT: usize = 0x1F27400;
const LIVE_STEAM_INIT_SERVER: usize = 0x1EA9C80;
const CMD_MENU_RESPONSE_F: usize = 0x195F100;
const CMD_MENU_RESPONSE_CACHED_F: usize = 0x195EFA0;
const UI_MODEL_GET_MODEL_FROM_PATH_0: usize = 0x200CF00;
const UI_MODEL_GET_MODEL_FROM_PATH: usize = 0x200D5B0;
const UI_MODEL_CREATE_MODEL_FROM_PATH: usize = 0x200CFC0;
const UI_MODEL_ALLOCATE_NODE: usize = 0x200CD00;
const SYS_VERIFY_PACKET_CHECKSUM: usize = 0x211F5A0;
const SYS_CHECKSUM_COPY: usize = 0x211F500;
const SYS_CHECKSUM: usize = 0x211F430;
const LOBBY_MSG_RW_PRINT_MESSAGE: usize = 0x1EEA940;
const LOBBY_MSG_RW_PRINT_DEBUG_MESSAGE: usize = 0x1EEA680;
const EXEC_LUA_CMD: usize = 0x1EF8A60;
const LIVE_USER_GET_NAME: usize = 0x1EBB200;
const LIVE_BASE_USER_GET_NAME: usize = 0x1EA4960;
const CL_CONNECTIONLESS_CMD: usize = 0x134CD70;
const LIVE_PRESENCE_SERIALIZE: usize = 0x1E85450;
const MODS_SUBSCRIBE_UGC: usize = 0x20CB0C0;
const LIVE_INVITES_ACCEPT_INVITE: usize = 0x1E19B30;
const LIVE_INVITES_SEND_JOIN_INFO: usize = 0x1E724A0;
const LIVE_INVITES_JOIN_MESSAGE_ACTION: usize = 0x1E72040;
const UI_BROWSER_OPEN: usize = 0x1EA4E30;
const USER_HAS_LICENSE_FOR_APP: usize = 0x1EAAD60;
const LIVE_INVENTORY_GET_ITEM_QUANTITY: usize = 0x1DFCC60;
const LIVE_ENTITLEMENTS_IS_ENTITLEMENT_ACTIVE_FOR_CONTROLLER: usize = 0x1E06110;
const LIVE_INVENTORY_ARE_EXTRA_SLOTS_PURCHASED: usize = 0x1DFC580;
const LIVE_INVENTORY_IS_VALID: usize = 0x1DFDFE0;
const INFO_VALUE_FOR_KEY: usize = 0x227BDA0;
const MODS_IS_MODS_LOADED: usize = 0x20C8F60;
const MODS_IS_MODS_LOADED_1: usize = 0x20C9AE0;

const SV_CMD_ARGV_BUFFER: usize = 0x20E2FD0;
const BG_CACHE_GET_SCRIPT_MENU_NAME_FOR_INDEX: usize = 0xA7DE0;
const BG_CACHE_GET_EVENT_STRING_NAME_FOR_INDEX: usize = 0xA78A0;
const LOBBY_HOST_IS_HOST: usize = 0x1ECCDC0;
const SCR_ADD_STRING: usize = 0x12E9A50;
const SCR_EXEC_ENT_THREAD: usize = 0x1B20280;
const SCR_FREE_THREAD: usize = 0x12EAB70;
const SYS_GET_TLS: usize = 0x212B3D0;
const CL_STORE_CONFIG_STRING: usize = 0x13667E0;
const COM_SESSION_MODE_GET_MODE_NAME: usize = 0x20EAD00;
const LOBBY_MSG_HANDLE_IM: usize = 0x1EEA130;
const MSG_INIT_READ_ONLY: usize = 0x20FCC10;
const MSG_BEGIN_READING: usize = 0x20FC900;
const MEMSET: usize = 0x2BC53B0;

const DATAMASK_STATE: usize = 0x1686E874;
const MENU_NESTING: usize = 0x1681BEB0;
const MENU_NUM_ARGS: usize = 0x1681BF14;
const MENU_SV_ID: usize = 0x17679580;
const MENU_SCR_THREAD_FN: usize = 0xA5A6810;
const MODEL_PATHS_FREE: usize = 0x16293150;

const ZBR_WINDOW_TEXT: &CStr = c"Call of Duty: Black Ops III (community patch by serious) (Rust)";
const ZBR_VERSION_FULL: &str = "Patch 3.09r - by serious <3";
const BAD_STR: &CStr = c"bad";

/// Lobby message keys whose values must stay inside the lobby-type range.
const LOBBY_TYPE_KEYS: [&CStr; 3] = [c"lobbytype", c"srclobbytype", c"destlobbytype"];

/// `LOBBY_TYPE_FIRST` and `LOBBY_TYPE_LAST` from `structs.h`.
const LOBBY_TYPE_FIRST: i32 = 0x0;
const LOBBY_TYPE_LAST: i32 = 0x2;

/// `MESSAGE_TYPE_DEMO_STATE` from `structs.h`. Higher message types are reported as "invalid".
const MESSAGE_TYPE_DEMO_STATE: i32 = 0x20;

/// Size of the menu-response scratch buffers in `CMD_MenuReponse_f`.
const MENU_BUF_LEN: usize = 1024;
type MenuBuf = [u8; MENU_BUF_LEN];

/// Packet-type bytes that the dispatch hook rejects or checks.
const PACKET_TYPE_CBUF_A: u8 = 0x65;
const PACKET_TYPE_CBUF_B: u8 = 0x6D;
const PACKET_TYPE_JOIN_REQUEST: u8 = 0x66;
const PACKET_TYPE_INFO_REQUEST_PENDING: u8 = 0x68;

/// Blocklisted-mod-check callsites from Scropts-QOL. Dormant in this build
/// because `SPOOF_RANKED` is `false`; kept for the port.
pub const IS_MOD_LOADED_ADDRS: [usize; 20] = [
    0x20EB3C4, 0x20EB3E4, 0x20EB324, 0x20EB2F4, 0x20EAD97, 0x13E6A74, 0x15E7EDB, 0x15E87DB,
    0x15EBAE9, 0x15F1F29, 0x15F1FD9, 0x15F20A0, 0x15F7F60, 0x1A80D1D, 0x1A9AD29, 0x1E9432B,
    0x1E9C8AE, 0x1EA5669, 0x1EBF6CD, 0x20EAD5D,
];

/// Packet names the connectionless filter lets through. Matched exactly, case-sensitively.
pub const LEGIT_PACKETS: [&str; 15] = [
    "connectResponse",
    "statresponse",
    "LM",
    "disconnect",
    "loadoutResponse",
    "infoResponse",
    "statusResponse",
    "keyAuthorize",
    "error",
    "print",
    "fastrestart",
    "ping",
    "pinga",
    "steamAuthReq",
    "cfl",
];

// ---------------------------------------------------------------------------
// Function types
// ---------------------------------------------------------------------------

type PrepWriteMsgFn = unsafe extern "system" fn(i64, i64, i32, i32) -> bool;
type PrepReadMsgFn = unsafe extern "system" fn(i64) -> bool;
type BuildTitleFn = unsafe extern "system" fn() -> *const c_char;
type LiveSystemInfoFn = unsafe extern "system" fn(i32, i32, *mut c_char, i32) -> bool;
type MsgTypeNameFn = unsafe extern "system" fn(i32) -> *const c_char;
type QmemcpyFn = unsafe extern "system" fn(*mut c_char, *mut c_char, i32) -> i64;
type WeirdCharacterIndexFn = unsafe extern "system" fn(i64, i32, i32) -> f32;
type SehReplaceFn = unsafe extern "system" fn(i32, *const c_char, *mut c_char) -> *const c_char;
type PackageIntFn = unsafe extern "system" fn(*mut LobbyMsg, *const c_char, *mut i32) -> bool;
type PackageUIntFn = unsafe extern "system" fn(*mut LobbyMsg, *const c_char, *mut u32) -> bool;
type PackageUCharFn = unsafe extern "system" fn(*mut LobbyMsg, *const c_char, *mut u8) -> bool;
type ModelStringFn =
    unsafe extern "system" fn(i32, *mut c_char, *const c_char, *mut c_char, u32) -> bool;
type ModelPathFn = unsafe extern "system" fn(i64, *const c_char) -> i32;
type AllocateNodeFn = unsafe extern "system" fn(i32, *const c_char, bool) -> i32;
type VerifyChecksumFn = unsafe extern "system" fn(*const c_char, i32) -> i64;
type ChecksumCopyFn = unsafe extern "system" fn(*const c_char, *const c_char, i32) -> u16;
type LiveUserGetNameFn = unsafe extern "system" fn(i32, *mut c_char, i32) -> bool;
type DispatchMessageFn = unsafe extern "system" fn(i64, u32, *const c_char, u32) -> i64;
type ConnectionlessFn = unsafe extern "system" fn(i32, *mut NetAdr, *mut Msg) -> bool;
type PresenceSerializeFn = unsafe extern "system" fn(i64, i64) -> i64;
type GetConfigStringFn = unsafe extern "system" fn(i32) -> *const c_char;
type SubscribeUgcFn = unsafe extern "system" fn(i64) -> bool;
type InviteFn = unsafe extern "system" fn(u32, *mut u32, i64);
type SendJoinInfoFn = unsafe extern "system" fn(u32, i64, i64) -> i64;
type BrowserOpenFn = unsafe extern "system" fn(i64) -> c_char;
type LicenseFn = unsafe extern "system" fn(i64, *mut i64) -> bool;
type ItemQuantityFn = unsafe extern "system" fn(i32, i32) -> i64;
type ControllerPairBoolFn = unsafe extern "system" fn(i32, i32) -> bool;
type ControllerBoolFn = unsafe extern "system" fn(i32) -> bool;
type ValueForKeyFn = unsafe extern "system" fn(*mut c_char, i64) -> *const c_char;
type ModsLoadedFn = unsafe extern "system" fn() -> bool;
type MenuFn = unsafe extern "system" fn(*mut c_char);
type VoidFn = unsafe extern "system" fn();
type PrintDebugFn = unsafe extern "system" fn() -> i32;
type GlobalInstantMessageFn =
    unsafe extern "system" fn(usize, u64, *const c_char, usize, u32) -> bool;

// Game functions the C++ calls without a hook. Resolved with `offsets::function`.
type SvCmdArgvBufferFn = unsafe extern "system" fn(i32, *mut c_char, i32);
type BgCacheNameFn = unsafe extern "system" fn(i32, i32) -> *const c_char;
type LobbyHostIsHostFn = unsafe extern "system" fn(i32) -> bool;
type ScrAddStringFn = unsafe extern "system" fn(i32, *const c_char);
type ScrExecEntThreadFn = unsafe extern "system" fn(*mut c_void, *mut c_void, i32) -> i32;
type ScrFreeThreadFn = unsafe extern "system" fn(i32, i32);
type SysChecksumFn = unsafe extern "system" fn(*const c_char, i32) -> u16;
type SysGetTlsFn = unsafe extern "system" fn() -> i64;
type StoreConfigStringFn = unsafe extern "system" fn(i32, *const c_char) -> *const c_char;
type SessionModeNameFn = unsafe extern "system" fn() -> *const c_char;
type HandleImFn = unsafe extern "system" fn(u32, i64, *mut c_void, i32) -> i64;
type MsgInitReadOnlyFn = unsafe extern "system" fn(*mut Msg, *const c_char, i32);
type MsgBeginReadingFn = unsafe extern "system" fn(*mut Msg);
type MsgReadByteFn = unsafe extern "system" fn(*mut c_void) -> u8;
type MsgReadDataFn = unsafe extern "system" fn(*mut Msg, *mut c_void, i32);
type MsgWriteByteFn = unsafe extern "system" fn(i64, u8);
type MemsetFn = unsafe extern "system" fn(*mut c_char, i64, u64) -> i32;
type LiveBaseUserGetNameFn = unsafe extern "system" fn(*mut u8, i32, c_char) -> u8;

// ---------------------------------------------------------------------------
// Trampolines
// ---------------------------------------------------------------------------

/// Holds the `MinHook` trampoline that calls the original of one hooked game function.
///
/// The C++ keeps these in globals that `MH_CreateHook` overwrites. The slot is 0
/// until its hook is created, and no detour that uses it may run before then.
struct Original<F> {
    address: AtomicUsize,
    signature: PhantomData<fn() -> F>,
}

impl<F: Copy> Original<F> {
    const fn new() -> Self {
        Self {
            address: AtomicUsize::new(0),
            signature: PhantomData,
        }
    }

    fn store(&self, trampoline: usize) {
        self.address.store(trampoline, Ordering::Release);
    }

    /// Returns the trampoline as the function type `F`.
    ///
    /// # Safety
    ///
    /// The slot must have been stored by [`hook`] for a function whose signature is `F`.
    unsafe fn get(&self) -> F {
        const { assert!(size_of::<F>() == size_of::<usize>()) };
        let address = self.address.load(Ordering::Acquire);
        // SAFETY: `F` is a function pointer, the same size as `usize`, and the caller
        // guarantees the slot holds a trampoline of that signature.
        unsafe { std::mem::transmute_copy(&address) }
    }
}

static ORIG_LOBBY_MSG_RW_PREP_WRITE_MSG: Original<PrepWriteMsgFn> = Original::new();
static ORIG_LOBBY_MSG_RW_PREP_READ_MSG: Original<PrepReadMsgFn> = Original::new();
static ORIG_LIVE_SYSTEM_INFO: Original<LiveSystemInfoFn> = Original::new();
static ORIG_LOBBY_TYPES_GET_MSG_TYPE_NAME: Original<MsgTypeNameFn> = Original::new();
static ORIG_QMEMCPY: Original<QmemcpyFn> = Original::new();
static ORIG_FLSOME_WEIRD_CHARACTER_INDEX: Original<WeirdCharacterIndexFn> = Original::new();
static ORIG_SEH_REPLACE: Original<SehReplaceFn> = Original::new();
static ORIG_PACKAGE_INT: Original<PackageIntFn> = Original::new();
static ORIG_PACKAGE_UINT: Original<PackageUIntFn> = Original::new();
static ORIG_PACKAGE_UCHAR: Original<PackageUCharFn> = Original::new();
static ORIG_UI_DO_MODEL_STRING_REPLACEMENT: Original<ModelStringFn> = Original::new();
static ORIG_UI_MODEL_GET_MODEL_FROM_PATH_0: Original<ModelPathFn> = Original::new();
static ORIG_UI_MODEL_GET_MODEL_FROM_PATH: Original<ModelPathFn> = Original::new();
static ORIG_UI_MODEL_CREATE_MODEL_FROM_PATH: Original<ModelPathFn> = Original::new();
static ORIG_UI_MODEL_ALLOCATE_NODE: Original<AllocateNodeFn> = Original::new();
static ORIG_SYS_VERIFY_PACKET_CHECKSUM: Original<VerifyChecksumFn> = Original::new();
static ORIG_SYS_CHECKSUM_COPY: Original<ChecksumCopyFn> = Original::new();
static ORIG_CL_CONNECTIONLESS_CMD: Original<ConnectionlessFn> = Original::new();
static ORIG_LIVE_PRESENCE_SERIALIZE: Original<PresenceSerializeFn> = Original::new();
static ORIG_CL_GET_CONFIG_STRING: Original<GetConfigStringFn> = Original::new();
static ORIG_MODS_SUBSCRIBE_UGC: Original<SubscribeUgcFn> = Original::new();
static ORIG_LIVE_INVITES_ACCEPT_INVITE: Original<InviteFn> = Original::new();
static ORIG_LIVE_INVITES_SEND_JOIN_INFO: Original<SendJoinInfoFn> = Original::new();
static ORIG_LIVE_INVITES_JOIN_MESSAGE_ACTION: Original<InviteFn> = Original::new();
static ORIG_USER_HAS_LICENSE_FOR_APP: Original<LicenseFn> = Original::new();
static ORIG_LIVE_INVENTORY_GET_ITEM_QUANTITY: Original<ItemQuantityFn> = Original::new();
static ORIG_LIVE_ENTITLEMENTS_IS_ACTIVE: Original<ControllerPairBoolFn> = Original::new();
static ORIG_LIVE_INVENTORY_ARE_EXTRA_SLOTS_PURCHASED: Original<ControllerBoolFn> = Original::new();
static ORIG_LIVE_INVENTORY_IS_VALID: Original<ControllerBoolFn> = Original::new();
static ORIG_INFO_VALUE_FOR_KEY: Original<ValueForKeyFn> = Original::new();
static ORIG_MODS_IS_MODS_LOADED: Original<ModsLoadedFn> = Original::new();
static ORIG_MODS_IS_MODS_LOADED_1: Original<ModsLoadedFn> = Original::new();

// ---------------------------------------------------------------------------
// Memory and call helpers
// ---------------------------------------------------------------------------

/// Reads a `T` from game memory, unaligned.
///
/// # Safety
///
/// `address` must be readable for `size_of::<T>()` bytes and hold a valid `T`.
unsafe fn read_game<T: Copy>(address: usize) -> T {
    // SAFETY: the caller guarantees `address` holds a readable `T`.
    unsafe { (address as *const T).read_unaligned() }
}

/// Writes a `T` into game memory, unaligned.
///
/// # Safety
///
/// `address` must be writable for `size_of::<T>()` bytes.
unsafe fn write_game<T: Copy>(address: usize, value: T) {
    // SAFETY: the caller guarantees `address` is writable for a `T`.
    unsafe { (address as *mut T).write_unaligned(value) };
}

/// Converts a 64-bit value from the game into an address. Negative values map to 0.
fn addr(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

/// `base + offset` for a signed byte offset, with wrapping arithmetic.
fn add_signed(base: usize, offset: i64) -> usize {
    base.wrapping_add_signed(isize::try_from(offset).unwrap_or(0))
}

/// Keeps the low 16 bits of `value`, as the C++ `(unsigned __int16)` casts do.
fn low16(value: i64) -> u16 {
    u16::try_from(value & 0xFFFF).unwrap_or_default()
}

/// The bytes before the first NUL in a fixed-size buffer.
fn until_nul(buffer: &[u8]) -> &[u8] {
    buffer
        .iter()
        .position(|&byte| byte == 0)
        .map_or(buffer, |end| &buffer[..end])
}

/// The NUL-terminated string at `ptr`, without the NUL. A null pointer gives an empty slice.
///
/// # Safety
///
/// If `ptr` is non-null it must point to a NUL-terminated string that stays valid for `'a`.
unsafe fn c_slice<'a>(ptr: *const c_char) -> &'a [u8] {
    if ptr.is_null() {
        return &[];
    }
    // SAFETY: the caller guarantees a NUL-terminated string at `ptr`.
    unsafe { CStr::from_ptr(ptr) }.to_bytes()
}

/// A mutable byte slice over `len` bytes at `ptr`. A null pointer or zero length gives an empty slice.
///
/// # Safety
///
/// If `ptr` is non-null and `len` is non-zero, `ptr` must be writable for `len` bytes.
unsafe fn raw_slice_mut<'a>(ptr: *mut c_char, len: usize) -> &'a mut [u8] {
    if ptr.is_null() || len == 0 {
        return &mut [];
    }
    // SAFETY: the caller guarantees `len` writable bytes at `ptr`.
    unsafe { std::slice::from_raw_parts_mut(ptr.cast::<u8>(), len) }
}

/// Pointer to the start of a byte buffer, typed for C string arguments.
fn buf_ptr(buffer: &[u8]) -> *const c_char {
    buffer.as_ptr().cast()
}

/// `strstr` over `hay` from byte `from`, returning the index of the match.
fn find_bytes(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let tail = hay.get(from..)?;
    tail.windows(needle.len())
        .position(|window| window == needle)
        .map(|position| position + from)
}

/// `strlen` over a fixed-size buffer.
fn c_len(buffer: &[u8]) -> usize {
    until_nul(buffer).len()
}

/// MSVC `strcpy_s`: copies `src` and a NUL into `dst`. When it does not fit, writes
/// an empty string to `dst[0]` and reports failure.
fn strcpy_s(dst: &mut [u8], src: &[u8]) -> bool {
    if src.len() >= dst.len() {
        if let Some(first) = dst.first_mut() {
            *first = 0;
        }
        return false;
    }
    dst[..src.len()].copy_from_slice(src);
    dst[src.len()] = 0;
    true
}

/// C `snprintf(buf, buf.len(), ...)`: copies at most `buf.len() - 1` bytes and
/// NUL-terminates.
fn snprintf_into(buf: &mut [u8], text: &[u8]) {
    let Some(last) = buf.len().checked_sub(1) else {
        return;
    };
    let count = text.len().min(last);
    buf[..count].copy_from_slice(&text[..count]);
    buf[count] = 0;
}

/// Current tick count in milliseconds.
fn tick_ms() -> u64 {
    // SAFETY: `GetTickCount64` takes no arguments.
    unsafe { GetTickCount64() }
}

/// Snapshot of the lobby password state, as `Protection::PrivatePassword`.
fn private_password() -> [i64; 3] {
    *PRIVATE_PASSWORD
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

/// `!Protection::I_stricmp(a, b)`: true when the two C strings match ignoring ASCII case.
///
/// A null `a` is reported as not equal. The C++ would pass NULL to the game.
///
/// # Safety
///
/// `a` must be null or point to a NUL-terminated string.
unsafe fn stricmp_eq(a: *const c_char, b: &CStr) -> bool {
    if a.is_null() {
        return false;
    }
    // SAFETY: `PTR_I_STRICMP` is the game's `I_stricmp`, with this signature.
    let stricmp = unsafe { offsets::function::<IStricmpFn>(offsets::PTR_I_STRICMP) };
    // SAFETY: both pointers are NUL-terminated.
    unsafe { stricmp(a, b.as_ptr()) == 0 }
}

/// True when `key` matches any of `names` under [`stricmp_eq`].
///
/// # Safety
///
/// `key` must be null or NUL-terminated.
unsafe fn stricmp_any(key: *const c_char, names: &[&CStr]) -> bool {
    // SAFETY: the caller guarantees `key` is null or NUL-terminated.
    names.iter().any(|name| unsafe { stricmp_eq(key, name) })
}

// Direct calls to unhooked game functions. The C++ calls these through the same
// `const static` pointers, which no hook overwrites.

/// # Safety
///
/// `buffer` must be writable for `size` bytes.
unsafe fn sv_cmd_argv_buffer(index: i32, buffer: *mut c_char, size: i32) {
    // SAFETY: `SV_Cmd_ArgvBuffer` has this signature; the caller owns `buffer`.
    unsafe { offsets::function::<SvCmdArgvBufferFn>(SV_CMD_ARGV_BUFFER)(index, buffer, size) };
}

/// # Safety
///
/// Must run inside the game process.
unsafe fn bg_script_menu_name(instance: i32, index: i32) -> *const c_char {
    // SAFETY: `BG_Cache_GetScriptMenuNameForIndex` has this signature.
    unsafe {
        offsets::function::<BgCacheNameFn>(BG_CACHE_GET_SCRIPT_MENU_NAME_FOR_INDEX)(instance, index)
    }
}

/// # Safety
///
/// Must run inside the game process.
unsafe fn bg_event_string_name(instance: i32, index: i32) -> *const c_char {
    // SAFETY: `BG_Cache_GetEventStringNameForIndex` has this signature.
    unsafe {
        offsets::function::<BgCacheNameFn>(BG_CACHE_GET_EVENT_STRING_NAME_FOR_INDEX)(
            instance, index,
        )
    }
}

/// # Safety
///
/// Must run inside the game process.
unsafe fn lobby_host_is_host(value: i32) -> bool {
    // SAFETY: `LobbyHost_IsHost` has this signature.
    unsafe { offsets::function::<LobbyHostIsHostFn>(LOBBY_HOST_IS_HOST)(value) }
}

/// # Safety
///
/// `text` must be NUL-terminated.
unsafe fn scr_add_string(index: i32, text: *const c_char) {
    // SAFETY: `Scr_AddString` has this signature.
    unsafe { offsets::function::<ScrAddStringFn>(SCR_ADD_STRING)(index, text) };
}

/// # Safety
///
/// `ent` and `function` must be the values the game passes to `Scr_ExecEntThread`.
unsafe fn scr_exec_ent_thread(ent: *mut c_void, function: *mut c_void, arg: i32) -> i32 {
    // SAFETY: `Scr_ExecEntThread` has this signature; the caller supplies the values.
    unsafe { offsets::function::<ScrExecEntThreadFn>(SCR_EXEC_ENT_THREAD)(ent, function, arg) }
}

/// # Safety
///
/// Must run inside the game process.
unsafe fn scr_free_thread(index: i32, thread: i32) {
    // SAFETY: `Scr_FreeThread` has this signature.
    unsafe { offsets::function::<ScrFreeThreadFn>(SCR_FREE_THREAD)(index, thread) };
}

/// # Safety
///
/// `data` must be readable for `len` bytes.
unsafe fn sys_checksum(data: *const c_char, len: i32) -> u16 {
    // SAFETY: `Sys_Checksum` has this signature; the caller guarantees the data.
    unsafe { offsets::function::<SysChecksumFn>(SYS_CHECKSUM)(data, len) }
}

/// # Safety
///
/// Must run inside the game process.
unsafe fn sys_get_tls() -> i64 {
    // SAFETY: `Sys_GetTLS` takes no arguments.
    unsafe { offsets::function::<SysGetTlsFn>(SYS_GET_TLS)() }
}

/// # Safety
///
/// `text` must be NUL-terminated.
unsafe fn cl_store_config_string(index: i32, text: *const c_char) {
    // SAFETY: `CL_StoreConfigString` has this signature.
    unsafe { offsets::function::<StoreConfigStringFn>(CL_STORE_CONFIG_STRING)(index, text) };
}

/// # Safety
///
/// Must run inside the game process.
unsafe fn com_session_mode_get_mode_name() -> *const c_char {
    // SAFETY: `Com_SessionMode_GetModeName` takes no arguments.
    unsafe { offsets::function::<SessionModeNameFn>(COM_SESSION_MODE_GET_MODE_NAME)() }
}

/// # Safety
///
/// `data` must be readable for `len` bytes and `lobby_msg` must be the game's lobby message.
unsafe fn lobby_msg_handle_im(target: u32, sender: i64, data: *mut c_void, len: i32) -> i64 {
    // SAFETY: `LobbyMsg_HandleIM` has this signature; the caller supplies the data.
    unsafe { offsets::function::<HandleImFn>(LOBBY_MSG_HANDLE_IM)(target, sender, data, len) }
}

/// # Safety
///
/// `msg` must be writable, `data` must be readable for `size` bytes.
unsafe fn msg_init_read_only(msg: *mut Msg, data: *const c_char, size: i32) {
    // SAFETY: `MSG_InitReadOnly` has this signature.
    unsafe { offsets::function::<MsgInitReadOnlyFn>(MSG_INIT_READ_ONLY)(msg, data, size) };
}

/// # Safety
///
/// `msg` must point to a valid `msg_t`.
unsafe fn msg_begin_reading(msg: *mut Msg) {
    // SAFETY: `MSG_BeginReading` has this signature.
    unsafe { offsets::function::<MsgBeginReadingFn>(MSG_BEGIN_READING)(msg) };
}

/// `MSG_ReadByte`. The C++ passes both a `msg_t*` and a `LobbyMsg*`, which share the call.
///
/// # Safety
///
/// `msg` must point to a valid message buffer.
unsafe fn msg_read_byte(msg: *mut c_void) -> u8 {
    // SAFETY: `MSG_ReadByte` has this signature; the caller supplies a valid message.
    unsafe { offsets::function::<MsgReadByteFn>(offsets::PTR_MSG_READ_BYTE)(msg) }
}

/// # Safety
///
/// `msg` must be a valid `msg_t`, and `data` writable for `size` bytes.
unsafe fn msg_read_data(msg: *mut Msg, data: *mut c_void, size: i32) {
    // SAFETY: `MSG_ReadData` has this signature; the caller supplies the buffers.
    unsafe { offsets::function::<MsgReadDataFn>(offsets::PTR_MSG_READ_DATA)(msg, data, size) };
}

/// # Safety
///
/// `lobby_msg` must be a valid lobby message handle.
unsafe fn msg_write_byte(lobby_msg: i64, value: u8) {
    // SAFETY: `MSG_WriteByte` has this signature.
    unsafe { offsets::function::<MsgWriteByteFn>(offsets::PTR_MSG_WRITE_BYTE)(lobby_msg, value) };
}

/// # Safety
///
/// `buf` must be writable for `len` bytes.
unsafe fn game_memset(buf: *mut c_char, len: u64) {
    // SAFETY: the game's `Memset` has this signature; the caller owns `buf`.
    unsafe { offsets::function::<MemsetFn>(MEMSET)(buf, 0, len) };
}

/// # Safety
///
/// `buf` must be writable for `size` bytes.
unsafe fn live_base_user_get_name(buf: *mut u8, size: i32) {
    // SAFETY: `Live_Base_UserGetName` has this signature; the caller owns `buf`.
    unsafe { offsets::function::<LiveBaseUserGetNameFn>(LIVE_BASE_USER_GET_NAME)(buf, size, 1) };
}

/// # Safety
///
/// `text` must be NUL-terminated.
unsafe fn cbuf_add_text(text: *const c_char) -> bool {
    // SAFETY: `Cbuf_AddText` has this signature; `text` is NUL-terminated.
    unsafe { offsets::function::<CbufAddTextFn>(offsets::PTR_CBUF_ADD_TEXT)(0, text, 0) }
}

// ---------------------------------------------------------------------------
// Pure logic
// ---------------------------------------------------------------------------

/// Port of `GetCallsiteFromReturn`. Finds the `E8` call opcode that ends just
/// before `return_address`, looking 5 bytes back and then up to 16 bytes back.
///
/// `byte_at` reads one byte at an address. Returns `return_address` if no call is found.
#[must_use]
pub fn callsite_from_return(return_address: usize, byte_at: impl Fn(usize) -> u8) -> usize {
    if byte_at(return_address.wrapping_sub(5)) == 0xE8 {
        return return_address.wrapping_sub(5);
    }
    for back in 1..=16 {
        let candidate = return_address.wrapping_sub(back);
        if byte_at(candidate) == 0xE8 {
            return candidate;
        }
    }
    return_address
}

/// True when `message` is one of [`LEGIT_PACKETS`], compared exactly.
#[must_use]
pub fn is_legit_packet(message: &[u8]) -> bool {
    LEGIT_PACKETS
        .iter()
        .any(|legit| legit.as_bytes() == message)
}

/// The connectionless filter's decision: a `requeststats` in campaign mode, or a legit packet name.
#[must_use]
pub fn connectionless_passes(requeststats: bool, campaign: bool, legit: bool) -> bool {
    (requeststats && campaign) || legit
}

/// True when a config string starts with `mspreload`, ignoring case. The C++ `is_equal`
/// truncates the string to nine characters before comparing.
#[must_use]
pub fn is_mspreload_prefix(config: &[u8]) -> bool {
    const COMMAND: &[u8] = b"mspreload";
    config[..config.len().min(COMMAND.len())].eq_ignore_ascii_case(COMMAND)
}

/// True for config string indices the C++ checks for `mspreload` (3514 and 3627).
#[must_use]
pub fn is_watched_config_string(index: i32) -> bool {
    [3514, 3627].contains(&index)
}

/// True when an index is at or past `limit`. The C++ rejects these before calling into the cache.
#[must_use]
pub fn index_out_of_range(index: u32, limit: u32) -> bool {
    index >= limit
}

/// True when a lobby message type index is in the range the C++ accepts (-1 through `DEMO_STATE`).
#[must_use]
pub fn msg_type_index_valid(index: i32) -> bool {
    (-1..=MESSAGE_TYPE_DEMO_STATE).contains(&index)
}

/// Lobby-type range check for signed package values.
#[must_use]
pub fn lobby_type_in_range(value: i32) -> bool {
    (LOBBY_TYPE_FIRST..=LOBBY_TYPE_LAST).contains(&value)
}

/// Lobby-type check for unsigned package values, which only checks the upper bound.
#[must_use]
pub fn lobby_type_unsigned_ok(value: u32) -> bool {
    value <= LOBBY_TYPE_LAST.cast_unsigned()
}

/// Port of the `datamask` check in `hkLobbyMsgRW_PackageUInt`. `state` is the raw
/// `i32` global, and only its low four bits are used.
#[must_use]
pub fn datamask_accepted(value: u32, state: i32) -> bool {
    if value == 0 {
        return false;
    }
    let state = (state << 28) >> 28;
    if state != 0 { true } else { (value & 512) == 0 }
}

/// Clamps a NAT type to the highest valid value, 4 ("unknown").
#[must_use]
pub fn clamp_nat_type(value: u8) -> u8 {
    value.min(4)
}

/// Clamps the player count stored in a presence word to 18, leaving other bits as they are.
#[must_use]
pub fn clamp_presence_count(packed: i32) -> i32 {
    const MAX_PLAYERS: i32 = 18;
    let count = (packed >> 2) & 0x1F;
    if count > MAX_PLAYERS {
        (packed & !(0x1F << 2)) | ((MAX_PLAYERS & 0x1F) << 2)
    } else {
        packed
    }
}

/// The packet-checksum acceptance test. `key1` and `key0` are the low 16 bits of the
/// password history, and `recent` says whether the password changed within 1.5 s.
#[must_use]
pub fn checksum_trailer_accepted(
    computed: u16,
    trailer: u16,
    key1: u16,
    key0: u16,
    recent: bool,
) -> bool {
    let checksum = key1 ^ computed;
    if trailer == checksum {
        return true;
    }
    recent && trailer == (checksum ^ key1 ^ key0)
}

/// True when a model path has a dot-separated segment of 64 or more bytes.
#[must_use]
pub fn model_key_too_long(path: &[u8]) -> bool {
    path.split(|&byte| byte == b'.')
        .any(|segment| segment.len() >= 64)
}

/// Port of the `^B` pass in `hkSEH_ReplaceDirectiveInStringWithBinding`. An unterminated
/// `^B` block, or one longer than 0x40 bytes, has its `^` changed to `.`.
pub fn neutralize_binding_directives(input: &mut [u8]) {
    let max = c_len(input);
    let mut i = 0;
    while i < max {
        if input[i] != b'^' || i + 1 >= max || input[i + 1] != b'B' {
            i += 1;
            continue;
        }
        let start = i + 2;
        let close = (start..max)
            .find(|&j| input[j] == b'^')
            .filter(|&j| j - start < 0x40);
        if let Some(end) = close {
            i = end + 1;
        } else {
            input[i] = b'.';
            i += 2;
        }
    }
}

/// Port of the `[{` pass in `hkSEH_ReplaceDirectiveInStringWithBinding`. A `[{` with no
/// matching `}]` within 0x100 bytes has its brackets changed to `..`.
pub fn neutralize_binding_tokens(input: &mut [u8]) {
    let len = c_len(input);
    let mut token = find_bytes(&input[..len], b"[{", 0);
    while let Some(start) = token {
        let end = find_bytes(&input[..len], b"}]", start + 2);
        if end.is_none_or(|end| end - start >= 0x100) {
            input[start] = b'.';
            input[start + 1] = b'.';
        }
        token = find_bytes(&input[..len], b"[{", start + 2);
    }
}

/// Both binding-directive passes, in the order the C++ applies them.
pub fn sanitize_binding_input(input: &mut [u8]) {
    neutralize_binding_directives(input);
    neutralize_binding_tokens(input);
}

/// Port of the `$(` pass in `hkUI_DoModelStringReplacement`. An unterminated `$(` has its
/// two bytes changed to `..`. Returns true if any change was made.
pub fn sanitize_model_string(input: &mut [u8]) -> bool {
    let max = c_len(input);
    let mut replaced = false;
    let mut i = 0;
    while i < max {
        if input[i] != b'$' || i + 1 >= max || input[i + 1] != b'(' {
            i += 1;
            continue;
        }
        let close = (i + 2..max).find(|&j| input[j] == b')');
        if let Some(end) = close {
            i = end + 1;
        } else {
            replaced = true;
            input[i] = b'.';
            input[i + 1] = b'.';
            i += 2;
        }
    }
    replaced
}

/// C `atoi`: skips leading whitespace, reads an optional sign and digits, and clamps to
/// the `int` range the way `strtol` does on Windows.
#[must_use]
pub fn c_atoi(text: &[u8]) -> i32 {
    let mut i = 0;
    while i < text.len() && matches!(text[i], b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r') {
        i += 1;
    }
    let mut negative = false;
    match text.get(i) {
        Some(b'-') => {
            negative = true;
            i += 1;
        }
        Some(b'+') => i += 1,
        _ => {}
    }
    let limit = i64::from(i32::MAX) + 1;
    let mut value: i64 = 0;
    while let Some(&digit) = text.get(i).filter(|byte| byte.is_ascii_digit()) {
        value = (value * 10 + i64::from(digit - b'0')).min(limit);
        i += 1;
    }
    let signed = if negative { -value } else { value };
    i32::try_from(signed.clamp(i64::from(i32::MIN), i64::from(i32::MAX))).unwrap_or(0)
}

/// The text `snprintf(mres, 1024, "tempBanClient %i\n", client)` produces.
#[must_use]
pub fn temp_ban_command(client: i32) -> String {
    format!("tempBanClient {client}\n")
}

/// The menu verb a `CMD_MenuResponse` string names. The C++ tests these strings one at
/// a time, and at most one matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuVerb {
    None,
    KillServer,
    EndGame,
    EndRound,
    RestartLevel,
}

/// True when a non-host client's verb must get a `tempBanClient`.
#[must_use]
pub fn menu_non_host_bans(verb: MenuVerb, is_campaign: bool) -> bool {
    matches!(verb, MenuVerb::KillServer | MenuVerb::RestartLevel)
        || (!is_campaign && matches!(verb, MenuVerb::EndGame | MenuVerb::EndRound))
}

/// True when the verb may run without the host check: anything except the
/// kill and end verbs, or a campaign transition.
#[must_use]
pub fn menu_allowed_without_host(verb: MenuVerb, is_campaign: bool) -> bool {
    let special = matches!(
        verb,
        MenuVerb::KillServer | MenuVerb::EndGame | MenuVerb::EndRound
    );
    let transition = is_campaign && matches!(verb, MenuVerb::EndGame | MenuVerb::EndRound);
    !special || transition
}

// ---------------------------------------------------------------------------
// Detours
// ---------------------------------------------------------------------------

unsafe extern "system" fn hk_lobby_msg_rw_prep_write_msg(
    lobby_msg: i64,
    data: i64,
    length: i32,
    msg_type: i32,
) -> bool {
    // SAFETY: the trampoline was created for `LobbyMsgRW_PrepWriteMsg` with this signature.
    if !unsafe { ORIG_LOBBY_MSG_RW_PREP_WRITE_MSG.get()(lobby_msg, data, length, msg_type) } {
        return false;
    }
    if let Some((prefix1, prefix2)) = protection::zbr_prefix() {
        // SAFETY: `lobby_msg` is the handle the original just wrote into.
        unsafe { msg_write_byte(lobby_msg, prefix1) };
        // SAFETY: as above.
        unsafe { msg_write_byte(lobby_msg, prefix2) };
    }
    true
}

unsafe extern "system" fn hk_lobby_msg_rw_prep_read_msg(lm: i64) -> bool {
    // SAFETY: the trampoline was created for `LobbyMsgRW_PrepReadMsg` with this signature.
    if !unsafe { ORIG_LOBBY_MSG_RW_PREP_READ_MSG.get()(lm) } {
        return false;
    }
    let Some((expected1, expected2)) = protection::zbr_prefix() else {
        return true;
    };
    // SAFETY: `lm` is the lobby message the original just prepared for reading.
    let prefix1 = unsafe { msg_read_byte(addr(lm) as *mut c_void) };
    // SAFETY: as above.
    let prefix2 = unsafe { msg_read_byte(addr(lm) as *mut c_void) };
    prefix1 == expected1 && prefix2 == expected2
}

unsafe extern "system" fn hk_cod_get_build_title() -> *const c_char {
    ZBR_WINDOW_TEXT.as_ptr()
}

unsafe extern "system" fn hk_live_system_info(
    controller: i32,
    info_type: i32,
    output: *mut c_char,
    output_len: i32,
) -> bool {
    if info_type != 0 {
        // SAFETY: the trampoline was created for `Live_SystemInfo` with this signature.
        return unsafe { ORIG_LIVE_SYSTEM_INFO.get()(controller, info_type, output, output_len) };
    }
    let len = usize::try_from(output_len).unwrap_or(0);
    // SAFETY: the game passes an output buffer of `output_len` bytes.
    let dst = unsafe { raw_slice_mut(output, len) };
    strcpy_s(dst, ZBR_VERSION_FULL.as_bytes());
    true
}

unsafe extern "system" fn hk_lobby_types_get_msg_type_name(index: i32) -> *const c_char {
    if !msg_type_index_valid(index) {
        return c"invalid".as_ptr();
    }
    // SAFETY: the trampoline was created for `LobbyTypes_GetMsgTypeName` with this signature.
    unsafe { ORIG_LOBBY_TYPES_GET_MSG_TYPE_NAME.get()(index) }
}

unsafe extern "system" fn hk_qmemcpy(dest: *mut c_char, source: *mut c_char, size: i32) -> i64 {
    if size < 0 {
        // Reject without touching either buffer. The C++ wrote a NUL through both
        // pointers here, but `source` is an input and may be read-only or shared.
        return 0;
    }
    // SAFETY: the trampoline was created for `qmemcpy` with this signature.
    unsafe { ORIG_QMEMCPY.get()(dest, source, size) }
}

unsafe extern "system" fn hk_flsome_weird_character_index(a1: i64, a2: i32, a3: i32) -> f32 {
    // SAFETY: `a1` is the game's array base; the entry at `a1 + 24 * a2 + 56` is readable.
    let entry = unsafe { read_game::<u64>(add_signed(addr(a1), i64::from(a2) * 24 + 56)) };
    if entry != 0 {
        // SAFETY: the trampoline was created for this function with this signature.
        return unsafe { ORIG_FLSOME_WEIRD_CHARACTER_INDEX.get()(a1, a2, a3) };
    }
    -1.0
}

unsafe extern "system" fn hk_seh_replace_directive_in_string_with_binding(
    local_client_num: i32,
    translated: *const c_char,
    final_string: *mut c_char,
) -> *const c_char {
    let mut input = [0u8; 4096];
    // SAFETY: the game passes a NUL-terminated string, or null.
    let source = unsafe { c_slice(translated) };
    if source.len() > 4095 {
        return std::ptr::null();
    }
    if final_string.is_null() {
        return std::ptr::null();
    }
    strcpy_s(&mut input, source);
    input[4095] = 0;
    sanitize_binding_input(&mut input);
    // SAFETY: the trampoline was created for this function with this signature; `final_string` is the game's output buffer.
    unsafe { ORIG_SEH_REPLACE.get()(local_client_num, input.as_ptr().cast(), final_string) }
}

unsafe extern "system" fn hk_lobby_msg_rw_package_int(
    lobby_msg: *mut LobbyMsg,
    key: *const c_char,
    val: *mut i32,
) -> bool {
    // SAFETY: the trampoline was created for `LobbyMsgRW_PackageInt` with this signature.
    let result = unsafe { ORIG_PACKAGE_INT.get()(lobby_msg, key, val) };
    // SAFETY: the game passes a NUL-terminated key.
    if result && unsafe { stricmp_any(key, &LOBBY_TYPE_KEYS) } {
        // SAFETY: the original wrote `val`, so it is readable.
        if !lobby_type_in_range(unsafe { val.read_unaligned() }) {
            return false;
        }
    }
    result
}

unsafe extern "system" fn hk_lobby_msg_rw_package_uint(
    lobby_msg: *mut LobbyMsg,
    key: *const c_char,
    val: *mut u32,
) -> bool {
    // SAFETY: the trampoline was created for `LobbyMsgRW_PackageUInt` with this signature.
    let result = unsafe { ORIG_PACKAGE_UINT.get()(lobby_msg, key, val) };
    // SAFETY: the game passes a NUL-terminated key.
    if result && unsafe { stricmp_any(key, &LOBBY_TYPE_KEYS) } {
        // SAFETY: the original wrote `val`, so it is readable.
        if !lobby_type_unsigned_ok(unsafe { val.read_unaligned() }) {
            return false;
        }
    }
    // SAFETY: as above.
    if result && unsafe { stricmp_eq(key, c"datamask") } {
        // SAFETY: as above.
        let value = unsafe { val.read_unaligned() };
        // SAFETY: the datamask state is a global `i32` in the game image.
        let state = unsafe { read_game::<i32>(offsets::address(DATAMASK_STATE)) };
        return datamask_accepted(value, state);
    }
    result
}

unsafe extern "system" fn hk_lobby_msg_rw_package_uchar(
    lobby_msg: *mut LobbyMsg,
    key: *const c_char,
    val: *mut u8,
) -> bool {
    // SAFETY: the trampoline was created for `LobbyMsgRW_PackageUChar` with this signature.
    let result = unsafe { ORIG_PACKAGE_UCHAR.get()(lobby_msg, key, val) };
    // SAFETY: the game passes a NUL-terminated key.
    if result && unsafe { stricmp_eq(key, c"nattype") } {
        // SAFETY: the original wrote `val`, so it is readable and writable.
        let value = unsafe { val.read_unaligned() };
        let clamped = clamp_nat_type(value);
        if clamped != value {
            // SAFETY: as above.
            unsafe { val.write_unaligned(clamped) };
        }
    }
    result
}

unsafe extern "system" fn hk_ui_do_model_string_replacement(
    controller: i32,
    element: *mut c_char,
    source: *const c_char,
    dest: *mut c_char,
    dest_size: u32,
) -> bool {
    let mut input = [0u8; 4096];
    // SAFETY: the game passes a NUL-terminated string, or null.
    let text = unsafe { c_slice(source) };
    strcpy_s(&mut input, text);
    input[4095] = 0;
    if sanitize_model_string(&mut input) {
        let len = usize::try_from(dest_size).unwrap_or(0);
        // SAFETY: the game passes a destination buffer of `dest_size` bytes.
        let out = unsafe { raw_slice_mut(dest, len) };
        strcpy_s(out, until_nul(&input));
        if let Some(last) = out.last_mut() {
            *last = 0;
        }
        return true;
    }
    // SAFETY: the trampoline was created for `UI_DoModelStringReplacement` with this signature.
    unsafe {
        ORIG_UI_DO_MODEL_STRING_REPLACEMENT.get()(
            controller,
            element,
            input.as_ptr().cast(),
            dest,
            dest_size,
        )
    }
}

unsafe extern "system" fn hk_live_steam_init_server() {}

/// Reads the menu arguments, as `CMD_MenuReponse_f` and its cached variant do.
/// Returns false when the C++ returns early because the server id does not match.
///
/// # Safety
///
/// Must run inside the game process, where the menu argument globals are readable.
unsafe fn read_menu_args(mres: &mut MenuBuf, menu_name: &mut MenuBuf, cached: bool) -> bool {
    // SAFETY: the nesting counter is a global `i32` in the game image.
    let nesting = unsafe { read_game::<i32>(offsets::address(MENU_NESTING)) };
    let slot = offsets::address(MENU_NUM_ARGS)
        .wrapping_add_signed(isize::try_from(nesting).unwrap_or(0) * 4);
    // SAFETY: the argument-count table is a global array of `i32`, indexed by nesting.
    let num_args = unsafe { read_game::<i32>(slot) };
    if num_args != 4 {
        strcpy_s(mres, b"bad");
        return true;
    }

    // SAFETY: `SV_Cmd_ArgvBuffer` writes at most 1024 bytes into the buffer.
    unsafe { sv_cmd_argv_buffer(1, menu_name.as_mut_ptr().cast(), 1024) };
    let sv_id = c_atoi(until_nul(menu_name));
    // SAFETY: the server id is a global `i32` in the game image.
    if sv_id != unsafe { read_game::<i32>(offsets::address(MENU_SV_ID)) } {
        return false;
    }

    // SAFETY: as above.
    unsafe { sv_cmd_argv_buffer(2, menu_name.as_mut_ptr().cast(), 1024) };
    let menu_index = c_atoi(until_nul(menu_name));
    if index_out_of_range(menu_index.cast_unsigned(), 0x40) {
        menu_name[0] = 0;
    } else {
        // SAFETY: `BG_Cache_GetScriptMenuNameForIndex` is not hooked, so this is the game function.
        let name = unsafe { bg_script_menu_name(0, menu_index) };
        // SAFETY: the game returns a NUL-terminated name, or null.
        strcpy_s(menu_name, unsafe { c_slice(name) });
    }

    // SAFETY: as above.
    unsafe { sv_cmd_argv_buffer(3, mres.as_mut_ptr().cast(), 1024) };
    if cached {
        let event_index = c_atoi(until_nul(mres)).cast_unsigned();
        // The index comes from the client: bound it as the C++ command does (fork `629f4b4`).
        // SAFETY: the bounded wrapper returns `"bad"` for an index outside the cache.
        let name = unsafe { bg_cache_get_event_string_name_for_index(0, event_index) };
        if name.is_null() {
            strcpy_s(mres, b"bad");
        } else {
            // SAFETY: the game returns a NUL-terminated string.
            strcpy_s(mres, unsafe { c_slice(name) });
        }
    }
    true
}

/// Reads the menu verb a buffer names.
///
/// # Safety
///
/// `name` must be NUL-terminated.
unsafe fn menu_verb(name: *const c_char) -> MenuVerb {
    // SAFETY: the caller guarantees `name` is NUL-terminated.
    unsafe {
        if stricmp_eq(name, c"killserverpc") {
            MenuVerb::KillServer
        } else if stricmp_eq(name, c"endgame") {
            MenuVerb::EndGame
        } else if stricmp_eq(name, c"endround") {
            MenuVerb::EndRound
        } else if stricmp_eq(name, c"restart_level_zm") {
            MenuVerb::RestartLevel
        } else {
            MenuVerb::None
        }
    }
}

/// Sends `tempBanClient` for the sender of `ent`, the C++ `Protection::Cbuf_AddText` path.
///
/// # Safety
///
/// `ent` must point to the game's client record, whose first `i32` is the client number.
unsafe fn ban_client(ent: *mut c_char, mres: &mut MenuBuf) {
    // SAFETY: `ent` is the client record, and its first `i32` is the client number.
    let client = unsafe { read_game::<i32>(ent as usize) };
    snprintf_into(mres, temp_ban_command(client).as_bytes());
    // SAFETY: `mres` is NUL-terminated by `snprintf_into`.
    unsafe { cbuf_add_text(buf_ptr(mres)) };
}

/// The shared tail of `CMD_MenuReponse_f` and `CMD_MenuResponseCached_f`.
///
/// # Safety
///
/// `ent` must be the client record the game passes to the menu command.
unsafe fn dispatch_menu_response(ent: *mut c_char, mres: &mut MenuBuf, menu_name: &MenuBuf) {
    // SAFETY: `mres` is NUL-terminated by the argument readers.
    if unsafe { stricmp_eq(buf_ptr(mres), c"badspawn") } {
        return;
    }
    // SAFETY: the game returns a NUL-terminated mode name, or null.
    let mode = unsafe { com_session_mode_get_mode_name() };
    // SAFETY: `mode` is null or NUL-terminated.
    let is_campaign = !mode.is_null() && unsafe { stricmp_eq(mode, c"CP") };
    // SAFETY: as above.
    let verb = unsafe { menu_verb(buf_ptr(mres)) };

    // SAFETY: `ent` is the client record, and its first `i32` is the client number.
    let client = unsafe { read_game::<i32>(ent as usize) };
    if client != 0 && menu_non_host_bans(verb, is_campaign) {
        // SAFETY: as above.
        unsafe { ban_client(ent, mres) };
        return;
    }

    // SAFETY: `LobbyHost_IsHost` is only consulted when the verb check fails.
    let allowed = menu_allowed_without_host(verb, is_campaign) || unsafe { lobby_host_is_host(1) };
    if allowed {
        // SAFETY: both buffers are NUL-terminated, and the game's thread function pointer is readable.
        unsafe {
            scr_add_string(0, buf_ptr(mres));
            scr_add_string(0, buf_ptr(menu_name));
            let function = read_game::<usize>(offsets::address(MENU_SCR_THREAD_FN));
            let thread = scr_exec_ent_thread(ent.cast(), function as *mut c_void, 2);
            scr_free_thread(0, thread);
        }
    } else {
        // SAFETY: as above.
        unsafe { ban_client(ent, mres) };
    }
}

unsafe extern "system" fn hk_cmd_menu_response_f(ent: *mut c_char) {
    let mut mres: MenuBuf = [0; MENU_BUF_LEN];
    let mut menu_name: MenuBuf = [0; MENU_BUF_LEN];
    // SAFETY: the game calls this with a client record, and the argument globals are mapped.
    if unsafe { read_menu_args(&mut mres, &mut menu_name, false) } {
        // SAFETY: `ent` is the client record the game passed in.
        unsafe { dispatch_menu_response(ent, &mut mres, &menu_name) };
    }
}

unsafe extern "system" fn hk_cmd_menu_response_cached_f(ent: *mut c_char) {
    let mut mres: MenuBuf = [0; MENU_BUF_LEN];
    let mut menu_name: MenuBuf = [0; MENU_BUF_LEN];
    // SAFETY: the game calls this with a client record, and the argument globals are mapped.
    if unsafe { read_menu_args(&mut mres, &mut menu_name, true) } {
        // SAFETY: `ent` is the client record the game passed in.
        unsafe { dispatch_menu_response(ent, &mut mres, &menu_name) };
    }
}

/// Shared check for the three `UI_Model_*FromPath` detours: a null path, or any
/// dot-separated key of 64 bytes or more, is refused.
///
/// # Safety
///
/// `path` must be null or NUL-terminated.
unsafe fn model_path_refused(path: *const c_char) -> bool {
    if path.is_null() {
        return true;
    }
    // SAFETY: the game passes a NUL-terminated path.
    model_key_too_long(unsafe { c_slice(path) })
}

unsafe extern "system" fn hk_ui_model_get_model_from_path_0(
    parent_node_index: i64,
    path: *const c_char,
) -> i32 {
    // SAFETY: `path` is null or NUL-terminated.
    if unsafe { model_path_refused(path) } {
        return 0;
    }
    // SAFETY: the trampoline was created for this function with this signature.
    unsafe { ORIG_UI_MODEL_GET_MODEL_FROM_PATH_0.get()(parent_node_index, path) }
}

unsafe extern "system" fn hk_ui_model_get_model_from_path(
    parent_node_index: i64,
    path: *const c_char,
) -> i32 {
    // SAFETY: `path` is null or NUL-terminated.
    if unsafe { model_path_refused(path) } {
        return 0;
    }
    // SAFETY: the trampoline was created for this function with this signature.
    unsafe { ORIG_UI_MODEL_GET_MODEL_FROM_PATH.get()(parent_node_index, path) }
}

unsafe extern "system" fn hk_ui_model_create_model_from_path(
    parent_node_index: i64,
    path: *const c_char,
) -> i32 {
    // SAFETY: `path` is null or NUL-terminated.
    if unsafe { model_path_refused(path) } {
        return 0;
    }
    // SAFETY: the trampoline was created for this function with this signature.
    unsafe { ORIG_UI_MODEL_CREATE_MODEL_FROM_PATH.get()(parent_node_index, path) }
}

unsafe extern "system" fn hk_ui_model_allocate_node(
    ancestor_index: i32,
    path: *const c_char,
    persistent: bool,
) -> i32 {
    if path.is_null() {
        return 0;
    }
    // SAFETY: the free-path count is a global `i16` in the game image.
    if unsafe { read_game::<i16>(offsets::address(MODEL_PATHS_FREE)) } == 0 {
        return 0;
    }
    // SAFETY: the game passes a NUL-terminated path.
    if unsafe { c_slice(path) }.len() >= 64 {
        return 0;
    }
    // SAFETY: the trampoline was created for this function with this signature.
    unsafe { ORIG_UI_MODEL_ALLOCATE_NODE.get()(ancestor_index, path, persistent) }
}

unsafe extern "system" fn hk_sys_verify_packet_checksum(
    payload: *const c_char,
    payload_len: i32,
) -> i64 {
    if payload_len < 2 {
        return -1;
    }
    let new_len = payload_len - 2;
    let password = private_password();
    // SAFETY: `payload` holds `payload_len` readable bytes.
    let computed = unsafe { sys_checksum(payload, new_len) };
    // SAFETY: the trailer is the two bytes at `payload + new_len`, inside `payload_len`.
    let trailer = unsafe { read_game::<u16>(add_signed(payload as usize, i64::from(new_len))) };
    let recent = i128::from(tick_ms()) <= i128::from(password[2]) + 1500;
    if checksum_trailer_accepted(
        computed,
        trailer,
        low16(password[1]),
        low16(password[0]),
        recent,
    ) {
        i64::from(new_len)
    } else {
        -1
    }
}

unsafe extern "system" fn hk_sys_checksum_copy(
    desta: *const c_char,
    srca: *const c_char,
    length: i32,
) -> u16 {
    // SAFETY: the trampoline was created for `Sys_ChecksumCopy` with this signature.
    let value = unsafe { ORIG_SYS_CHECKSUM_COPY.get()(desta, srca, length) };
    value ^ low16(private_password()[1])
}

unsafe extern "system" fn hk_lobby_msg_rw_print_message() {}

unsafe extern "system" fn hk_lobby_msg_rw_print_debug_message() -> i32 {
    0
}

unsafe extern "system" fn hk_exec_lua_cmd() {}

unsafe extern "system" fn hk_live_user_get_name(
    _controller: i32,
    buf: *mut c_char,
    buf_size: i32,
) -> bool {
    let len = u64::try_from(buf_size).unwrap_or(0);
    // SAFETY: the game passes a buffer of `buf_size` bytes.
    unsafe { game_memset(buf, len) };
    // SAFETY: as above; `Live_Base_UserGetName` writes the user name into it.
    unsafe { live_base_user_get_name(buf.cast(), buf_size) };
    true
}

unsafe extern "system" fn hk_dw_instant_dispatch_message(
    sender_xuid: i64,
    _controller_index: u32,
    message: *const c_char,
    message_size: u32,
) -> i64 {
    // SAFETY: a zeroed `msg_t` is valid: all its fields are integers, bools, null pointers, or `NetSrc::Client1`.
    let mut msg: Msg = unsafe { std::mem::zeroed() };
    // SAFETY: `message` is the game's `msg_t`, and `msg` is a valid local.
    unsafe {
        msg_init_read_only(&raw mut msg, message, message_size.cast_signed());
        msg_begin_reading(&raw mut msg);
    }

    let mut is_valid = true;
    let mut packet_type: u8 = 0;
    // SAFETY: `msg` was initialised above.
    if unsafe { msg_read_byte((&raw mut msg).cast()) } == b'1' {
        // SAFETY: as above.
        packet_type = unsafe { msg_read_byte((&raw mut msg).cast()) };
    }

    // `message` is the raw payload, not a `msg_t`: the C++ reads a header out of
    // it, which is peer-controlled data. The header is the local `msg` read from it.
    let remaining = msg.cursize.wrapping_sub(msg.readcount);

    if packet_type == PACKET_TYPE_CBUF_A || packet_type == PACKET_TYPE_CBUF_B {
        is_valid = false;
    } else if packet_type == PACKET_TYPE_JOIN_REQUEST {
        if msg.overflowed || msg.readcount > msg.cursize || remaining != 0x64 {
            is_valid = false;
        }
        let packet_data = add_signed(msg.data as usize, i64::from(msg.readcount));
        // SAFETY: `cursize - readcount == 0x64`, so at least four payload bytes follow the cursor.
        if is_valid && unsafe { read_game::<i32>(packet_data) } == 0 {
            is_valid = false;
        }
    }

    // SAFETY: `msg` is the local message over the payload, positioned after the header.
    if is_valid
        && packet_type == PACKET_TYPE_INFO_REQUEST_PENDING
        && unsafe { protection::check_pending_info_requests(sender_xuid, &raw mut msg) }
    {
        return 0;
    }

    if !is_valid {
        return 0;
    }
    dispatch_im_payload(
        &mut msg,
        |msg, data, size| {
            // SAFETY: `data` holds 2048 bytes and `size` is below that.
            unsafe { msg_read_data(msg, data.as_mut_ptr().cast(), size) };
        },
        |data, size| {
            // SAFETY: `data` holds `size` bytes just read from the message.
            unsafe { lobby_msg_handle_im(0, sender_xuid, data.as_mut_ptr().cast(), size) }
        },
    )
}

/// Copies the rest of `msg` into a 2048-byte buffer with `read` and passes it to
/// `handle` (`LobbyMsg_HandleIM`). Returns 0 without calling `handle` when the
/// payload doesn't fit or the read overflowed, as the game's own
/// `dwInstantHandleLobbyMessage` does; upstream dispatched overflowed reads.
fn dispatch_im_payload(
    msg: &mut Msg,
    read: impl FnOnce(&mut Msg, &mut [u8; 2048], i32),
    handle: impl FnOnce(&mut [u8; 2048], i32) -> i64,
) -> i64 {
    let size = msg.cursize.wrapping_sub(msg.readcount);
    let Ok(size) = i32::try_from(size) else {
        return 0;
    };
    if size >= 2048 {
        return 0;
    }
    let mut data = [0u8; 2048];
    read(msg, &mut data, size);
    if msg.overflowed {
        return 0;
    }
    handle(&mut data, size)
}

unsafe extern "system" fn hk_cl_connectionless_cmd(
    client_num: i32,
    from: *mut NetAdr,
    msg: *mut Msg,
) -> bool {
    // SAFETY: `Sys_GetTLS` returns the thread-local block of the calling thread.
    let tls = unsafe { sys_get_tls() };
    // SAFETY: the TLS block holds a pointer to the int array at +24.
    let array = unsafe { read_game::<usize>(add_signed(addr(tls), 24)) };
    // SAFETY: the array's first word is the element count used to index it.
    let count = unsafe { read_game::<i32>(array) };
    let slot = add_signed(array, (2 * i64::from(count) + 34) * 4);
    // SAFETY: the slot holds a pointer to a pointer to the message name, as the C++ dereferences it.
    let name_ptr = unsafe { read_game::<usize>(slot) };
    // SAFETY: as above.
    let message = unsafe { read_game::<usize>(name_ptr) } as *const c_char;

    // SAFETY: `message` is the NUL-terminated packet name.
    let (requeststats, legit) = unsafe {
        (
            stricmp_eq(message, c"requeststats") || stricmp_eq(message, c"requeststats\n"),
            is_legit_packet(c_slice(message)),
        )
    };
    // SAFETY: the game returns a NUL-terminated mode name, or null.
    let mode = unsafe { com_session_mode_get_mode_name() };
    // SAFETY: `mode` is null or NUL-terminated.
    let campaign = unsafe { stricmp_eq(mode, c"CP") };

    if connectionless_passes(requeststats, campaign, legit) {
        // SAFETY: the trampoline was created for `CL_ConnectionlessCMD` with this signature.
        return unsafe { ORIG_CL_CONNECTIONLESS_CMD.get()(client_num, from, msg) };
    }
    true
}

unsafe extern "system" fn hk_cl_get_config_string(index: i32) -> *const c_char {
    // SAFETY: the game returns a NUL-terminated mode name, or null.
    let mode = unsafe { com_session_mode_get_mode_name() };
    // SAFETY: `mode` is null or NUL-terminated.
    if !mode.is_null() && unsafe { stricmp_eq(mode, c"CP") } {
        // SAFETY: the trampoline was created for `CL_GetConfigString` with this signature.
        return unsafe { ORIG_CL_GET_CONFIG_STRING.get()(index) };
    }

    if is_watched_config_string(index) {
        // SAFETY: the trampoline was created for `CL_GetConfigString` with this signature.
        let config = unsafe { ORIG_CL_GET_CONFIG_STRING.get()(index) };
        // SAFETY: the game returns a NUL-terminated string, or null.
        if is_mspreload_prefix(unsafe { c_slice(config) }) {
            // SAFETY: the empty string is NUL-terminated.
            unsafe { cl_store_config_string(index, c"".as_ptr()) };
        }
    }

    // SAFETY: as above.
    unsafe { ORIG_CL_GET_CONFIG_STRING.get()(index) }
}

/// Clamps the player count in a presence word. Returns the original's result.
unsafe extern "system" fn hk_live_presence_serialize(a1: i64, a2: i64) -> i64 {
    if a1 == 0 || a2 == 0 {
        return 0;
    }
    // SAFETY: `a1 + 16` holds a pointer to the packed presence word.
    let packed_ptr = unsafe { read_game::<usize>(add_signed(addr(a1), 16)) };
    if packed_ptr == 0 {
        return 0;
    }
    // SAFETY: the packed word is a readable `i32`.
    let packed = unsafe { read_game::<i32>(packed_ptr) };
    let clamped = clamp_presence_count(packed);
    if clamped != packed {
        // SAFETY: as above, and the word is writable.
        unsafe { write_game::<i32>(packed_ptr, clamped) };
    }
    // SAFETY: the trampoline was created for `LivePresence_Serialize` with this signature.
    unsafe { ORIG_LIVE_PRESENCE_SERIALIZE.get()(a1, a2) }
}

unsafe extern "system" fn hk_mods_subscribe_ugc(a1: i64) -> bool {
    if !IS_AUTO_INSTALL_MODS_ENABLED.load(Ordering::Relaxed) {
        return false;
    }
    // SAFETY: the trampoline was created for `Mods_SubscribeUGC` with this signature.
    unsafe { ORIG_MODS_SUBSCRIBE_UGC.get()(a1) }
}

unsafe extern "system" fn hk_live_invites_accept_invite(
    controller_index: u32,
    message: *mut u32,
    recipient_xuid: i64,
) {
    if IS_FRIENDS_ONLY.load(Ordering::Relaxed) {
        // SAFETY: called inside the game process, where the friends cache is usable.
        if !unsafe { protection::is_friend_by_xuid_uncached(recipient_xuid) } {
            return;
        }
    }
    // SAFETY: the trampoline was created for `LiveInvites_AcceptInvite` with this signature.
    unsafe { ORIG_LIVE_INVITES_ACCEPT_INVITE.get()(controller_index, message, recipient_xuid) };
}

unsafe extern "system" fn hk_live_invites_join_message_action(
    controller_index: u32,
    message: *mut u32,
    recipient_xuid: i64,
) {
    if IS_FRIENDS_ONLY.load(Ordering::Relaxed) {
        // SAFETY: called inside the game process, where the friends cache is usable.
        if !unsafe { protection::is_friend_by_xuid_uncached(recipient_xuid) } {
            return;
        }
    }
    // SAFETY: the trampoline was created for `LiveInvites_JoinMessageAction` with this signature.
    unsafe {
        ORIG_LIVE_INVITES_JOIN_MESSAGE_ACTION.get()(controller_index, message, recipient_xuid);
    };
}

unsafe extern "system" fn hk_live_invites_send_join_info(
    controller_index: u32,
    recipient_xuid: i64,
    a3: i64,
) -> i64 {
    if IS_FRIENDS_ONLY.load(Ordering::Relaxed) {
        // SAFETY: called inside the game process, where the friends cache is usable.
        if !unsafe { protection::is_friend_by_xuid_uncached(recipient_xuid) } {
            return 0;
        }
    }
    // SAFETY: the trampoline was created for `LiveInvites_SendJoinInfo` with this signature.
    unsafe { ORIG_LIVE_INVITES_SEND_JOIN_INFO.get()(controller_index, recipient_xuid, a3) }
}

unsafe extern "system" fn hk_ui_browser_open(_a1: i64) -> c_char {
    0
}

unsafe extern "system" fn hk_user_has_license_for_app(map_info: i64, user_obj: *mut i64) -> bool {
    // SAFETY: the trampoline was created for `UserHasLicenseForApp` with this signature.
    unsafe { ORIG_USER_HAS_LICENSE_FOR_APP.get()(map_info, user_obj) }
}

unsafe extern "system" fn hk_live_inventory_get_item_quantity(
    controller_index: i32,
    item_id: i32,
) -> i64 {
    // SAFETY: the trampoline was created for `LiveInventory_GetItemQuantity` with this signature.
    unsafe { ORIG_LIVE_INVENTORY_GET_ITEM_QUANTITY.get()(controller_index, item_id) }
}

unsafe extern "system" fn hk_live_entitlements_is_entitlement_active_for_controller(
    controller_index: i32,
    incentive_id: i32,
) -> bool {
    // SAFETY: the trampoline was created for this function with this signature.
    unsafe { ORIG_LIVE_ENTITLEMENTS_IS_ACTIVE.get()(controller_index, incentive_id) }
}

unsafe extern "system" fn hk_live_inventory_are_extra_slots_purchased(
    controller_index: i32,
) -> bool {
    // SAFETY: the trampoline was created for this function with this signature.
    unsafe { ORIG_LIVE_INVENTORY_ARE_EXTRA_SLOTS_PURCHASED.get()(controller_index) }
}

unsafe extern "system" fn hk_live_inventory_is_valid(controller_index: i32) -> bool {
    // SAFETY: the trampoline was created for this function with this signature.
    unsafe { ORIG_LIVE_INVENTORY_IS_VALID.get()(controller_index) }
}

unsafe extern "system" fn hk_info_value_for_key(a1: *mut c_char, a2: i64) -> *const c_char {
    // SAFETY: the trampoline was created for `Info_ValueForKey` with this signature.
    unsafe { ORIG_INFO_VALUE_FOR_KEY.get()(a1, a2) }
}

unsafe extern "system" fn hk_mods_is_mods_loaded() -> bool {
    // SAFETY: the trampoline was created for `Mods_IsModsLoaded` with this signature.
    unsafe { ORIG_MODS_IS_MODS_LOADED.get()() }
}

unsafe extern "system" fn hk_mods_is_mods_loaded_1() -> bool {
    // SAFETY: the trampoline was created for `Mods_IsModsLoaded_1` with this signature.
    unsafe { ORIG_MODS_IS_MODS_LOADED_1.get()() }
}

/// Returns false for every instant message. Installed in the lobby VMT by [`apply_vmt`].
unsafe extern "system" fn global_instant_message(
    _thisptr: usize,
    _sender_id: u64,
    _sender_name: *const c_char,
    _msg: usize,
    _size: u32,
) -> bool {
    false
}

// The five `BG_Cache_*` detours below are not installed. Their hook calls are
// commented out in the C++, and they are kept here for parity.

/// Not installed (the C++ hook call is commented out).
///
/// # Safety
///
/// Must run inside the game process.
#[must_use]
pub unsafe extern "system" fn bg_cache_get_script_menu_name_for_index(
    instance: u32,
    index: u32,
) -> *const c_char {
    if index_out_of_range(index, 64) {
        return BAD_STR.as_ptr();
    }
    // SAFETY: the original is the unhooked game function.
    unsafe { bg_script_menu_name(instance.cast_signed(), index.cast_signed()) }
}

/// Not installed (the C++ hook call is commented out).
///
/// # Safety
///
/// Must run inside the game process.
#[must_use]
pub unsafe extern "system" fn bg_cache_get_event_string_name_for_index(
    instance: u32,
    index: u32,
) -> *const c_char {
    if index_out_of_range(index, 256) {
        return BAD_STR.as_ptr();
    }
    // SAFETY: the original is the unhooked game function.
    unsafe { bg_event_string_name(instance.cast_signed(), index.cast_signed()) }
}

/// Not installed (the C++ hook call is commented out).
///
/// # Safety
///
/// Must run inside the game process.
#[must_use]
pub unsafe extern "system" fn bg_cache_get_loc_string_name_for_index(
    instance: u32,
    index: u32,
) -> *const c_char {
    if index_out_of_range(index, 2048) {
        return BAD_STR.as_ptr();
    }
    // SAFETY: the original is the unhooked game function.
    unsafe {
        offsets::function::<BgCacheNameFn>(0xA7AB0)(instance.cast_signed(), index.cast_signed())
    }
}

/// Not installed (the C++ hook call is commented out).
///
/// # Safety
///
/// Must run inside the game process.
#[must_use]
pub unsafe extern "system" fn bg_cache_get_lui_menu_for_index(
    instance: u32,
    index: u32,
) -> *const c_char {
    if index_out_of_range(index, 64) {
        return BAD_STR.as_ptr();
    }
    // SAFETY: the original is the unhooked game function.
    unsafe {
        offsets::function::<BgCacheNameFn>(0xA7A00)(instance.cast_signed(), index.cast_signed())
    }
}

/// Not installed (the C++ hook call is commented out).
///
/// # Safety
///
/// Must run inside the game process.
#[must_use]
pub unsafe extern "system" fn bg_cache_get_lui_menu_data_for_index(
    instance: u32,
    index: u32,
) -> *const c_char {
    if index_out_of_range(index, 128) {
        return BAD_STR.as_ptr();
    }
    // SAFETY: the original is the unhooked game function.
    unsafe {
        offsets::function::<BgCacheNameFn>(0xA7990)(instance.cast_signed(), index.cast_signed())
    }
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

const LOBBY_VTABLE_LEN: usize = 50;
/// Lobby vtable copy that slot 24 is redirected through. It has a fixed address and is never
/// freed, so callbacks still in flight after a restore or reinstall keep a valid table.
static LOBBY_VTABLE: [AtomicUsize; LOBBY_VTABLE_LEN] =
    [const { AtomicUsize::new(0) }; LOBBY_VTABLE_LEN];
/// Slot 24 (byte offset 192): `Global_InstantMessage`.
const LOBBY_VTABLE_INSTANT_MESSAGE: usize = 192 / 8;
/// Offset of the lobby object pointer inside the `DW_LOBBY` object.
const LOBBY_OBJECT_OFFSET: usize = 1384;
/// Address of the lobby object's vtable pointer while the VMT hook is applied, or 0.
static LOBBY_VTABLE_SLOT: AtomicUsize = AtomicUsize::new(0);
/// The vtable pointer the slot held before the VMT hook, or 0.
static ORIGINAL_LOBBY_VTABLE: AtomicUsize = AtomicUsize::new(0);

/// Port of `hooks::ApplyVMTHooks`. Copies the lobby object's vtable into `LOBBY_VTABLE`,
/// points slot 24 at `global_instant_message`, and swaps the object onto the copy.
///
/// # Errors
///
/// Returns an error when the lobby object or its vtable is not initialized or unreadable, or when the vtable pointer cannot be swapped.
pub fn apply_vmt() -> Result<(), String> {
    // SAFETY: `DW_LOBBY` is the game's global lobby pointer, readable once the game runs.
    let lobby = unsafe { read_game::<usize>(offsets::address(offsets::DW_LOBBY)) };
    if lobby == 0 {
        return Err("T7 Patch: lobby is not initialized".to_owned());
    }
    // SAFETY: `lobby + 1384` holds the lobby object pointer.
    let object = unsafe { read_game::<usize>(lobby + LOBBY_OBJECT_OFFSET) };
    if object == 0 {
        return Err("T7 Patch: lobby VMT is not initialized".to_owned());
    }
    // SAFETY: the lobby object begins with its vtable pointer.
    let vtable = unsafe { read_game::<usize>(object) };
    if vtable == 0 {
        return Err("T7 Patch: lobby VMT is not initialized".to_owned());
    }

    let mut entries = [0usize; LOBBY_VTABLE_LEN];
    // An unreadable or short vtable fails the install (and rolls back) instead of faulting.
    if !read_memory(vtable, &mut entries) {
        return Err("T7 Patch: unreadable lobby VMT".to_owned());
    }
    for (entry, value) in LOBBY_VTABLE.iter().zip(entries) {
        entry.store(value, Ordering::Relaxed);
    }
    LOBBY_VTABLE[LOBBY_VTABLE_INSTANT_MESSAGE].store(
        global_instant_message as GlobalInstantMessageFn as *const () as usize,
        Ordering::Relaxed,
    );

    LOBBY_VTABLE_SLOT.store(object, Ordering::Release);
    ORIGINAL_LOBBY_VTABLE.store(vtable, Ordering::Release);
    // `AtomicUsize` has the layout of `usize`, so the array is a plain pointer table.
    let table = LOBBY_VTABLE.as_ptr().addr();
    // SAFETY: `object` is the lobby object, whose first word is its vtable pointer.
    if !unsafe { arxan::swap_usize(object, vtable, table) }.complete() {
        return Err("T7 Patch: cannot write the lobby VMT".to_owned());
    }
    Ok(())
}

/// Port of `hooks::RestoreVMTHooks`. Points the lobby object back at its original vtable.
///
/// # Errors
///
/// Returns an error when the lobby object's vtable slot cannot be read or written back. The ownership records are kept, so a later attempt can retry.
pub fn restore_vmt() -> Result<(), String> {
    let slot = LOBBY_VTABLE_SLOT.load(Ordering::Acquire);
    let original = ORIGINAL_LOBBY_VTABLE.load(Ordering::Acquire);
    if slot == 0 || original == 0 {
        return Ok(());
    }
    // Restore only while the object still points at our table: if the game freed and
    // reused it, the slot is no longer a vtable pointer and must not be written.
    let mut current = [0usize; 1];
    let ours = LOBBY_VTABLE.as_ptr().addr();
    if !read_memory(slot, &mut current) {
        // Keep the ownership records: a later attempt must not lose the snapshot.
        return Err("T7 Patch: cannot read the lobby VMT slot".to_owned());
    }
    if current[0] == ours {
        // SAFETY: `slot` is the lobby object's vtable pointer that `apply_vmt` replaced.
        if !unsafe { arxan::restore_usize(slot, ours, original) } {
            return Err("T7 Patch: cannot restore the lobby VMT".to_owned());
        }
    }
    LOBBY_VTABLE_SLOT.store(0, Ordering::Release);
    ORIGINAL_LOBBY_VTABLE.store(0, Ordering::Release);
    Ok(())
}

/// Bytes a memory patch replaced, so the patch can be undone.
#[derive(Clone)]
struct MemoryPatch {
    address: usize,
    original: Vec<u8>,
}

/// Every applied memory patch, in the order applied.
static MEMORY_PATCHES: Mutex<Vec<MemoryPatch>> = Mutex::new(Vec::new());

/// Copies `out.len()` values from `address` with `ReadProcessMemory`, which reports an
/// unreadable range instead of faulting. Returns false unless every byte was copied.
fn read_memory<T: Copy>(address: usize, out: &mut [T]) -> bool {
    let size = size_of_val(out);
    let mut copied = 0usize;
    // SAFETY: `out` is writable for `size` bytes and any bit pattern is accepted by the
    // callers' plain-integer `T`; `ReadProcessMemory` checks the source range.
    let read = unsafe {
        ReadProcessMemory(
            GetCurrentProcess(),
            address as *const c_void,
            out.as_mut_ptr().cast(),
            size,
            Some(&raw mut copied),
        )
    };
    read.is_ok() && copied == size
}

/// Port of `SaveMemoryPatch`. Saves the bytes at `address`, then writes `bytes` over them
/// with the protection changes the C++ makes around each patch.
fn patch(address: usize, bytes: &[u8]) -> Result<(), String> {
    let mut original = vec![0u8; bytes.len()];
    if !read_memory(address, &mut original) {
        return Err("T7 Patch: unreadable memory patch target".to_owned());
    }
    MEMORY_PATCHES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .push(MemoryPatch {
            address,
            original: original.clone(),
        });

    // SAFETY: the callers pass addresses inside the game image, which is committed
    // executable memory, and `write_code` freezes every other thread first.
    match unsafe { crate::threads::write_code(address, bytes) } {
        Ok(report) if report.complete() => Ok(()),
        Ok(report) => {
            if !report.bytes_written {
                pop_unjournaled_patch(address, &original);
            }
            Err("T7 Patch: cannot write a memory patch".to_owned())
        }
        Err(error) => {
            if matches!(
                error,
                crate::threads::CodeWriteError::Busy | crate::threads::CodeWriteError::Freeze(_)
            ) {
                pop_unjournaled_patch(address, &original);
            }
            Err(format!("T7 Patch: cannot write a memory patch: {error}"))
        }
    }
}

/// Removes the record `patch` pushed when no bytes were written.
fn pop_unjournaled_patch(address: usize, original: &[u8]) {
    let mut patches = MEMORY_PATCHES
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    if patches
        .last()
        .is_some_and(|saved| saved.address == address && saved.original == original)
    {
        patches.pop();
    }
}

/// Port of `hooks::ApplyMemoryPatches`. Applies the SL, movsx, process-priority and
/// tokenizer byte patches to the game image, saving each original first.
///
/// # Errors
///
/// Returns an error when a patch site cannot be written. Patches applied before it stay applied and saved, for [`restore_memory_patches`] to undo.
pub fn apply_memory_patches() -> Result<(), String> {
    // SL fix: nop out the calls to com_error.
    patch(offsets::address(0x1964766), &[0x90; 5])?;
    patch(offsets::address(0x19646A7), &[0x90; 5])?;

    // Fix movsx issue with package readglob: the opcode byte after 0x1EEACF2 becomes movzx.
    patch(offsets::address(0x1EEACF2) + 1, &[0xB7])?;

    patch(
        offsets::address(offsets::PTR_CMP_TOKENIZE_STRING_INTERNAL),
        &[0x2F],
    )?;

    // Process priority: above normal.
    patch(offsets::address(0x22BC1CD), &0x8000u32.to_le_bytes())?;
    patch(offsets::address(0x22BC1D2), &0x8000u32.to_le_bytes())?;

    // movsx -> movzx.
    patch(offsets::address(0x1F21EF8), &[0xB6])?;
    patch(offsets::address(0x1CA4C84), &[0xB6])?;
    Ok(())
}

/// Port of `hooks::RestoreMemoryPatches`. Restores every saved patch in reverse order,
/// trying all of them. The saved list is cleared only when every restore succeeds.
///
/// # Errors
///
/// Returns an error when any saved patch cannot be written back. The saved list is then kept for a retry.
pub fn restore_memory_patches() -> Result<(), String> {
    let saved = MEMORY_PATCHES
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone();
    let mut failed = false;
    let mut restored: Vec<(usize, Vec<u8>)> = Vec::new();
    for record in saved.iter().rev() {
        // SAFETY: each address was patched by `patch`, which read the same range first.
        match unsafe { crate::threads::write_code(record.address, &record.original) } {
            Ok(report) if report.complete() => {
                restored.push((record.address, record.original.clone()));
            }
            Ok(_) | Err(_) => failed = true,
        }
    }

    let mut patches = MEMORY_PATCHES
        .lock()
        .unwrap_or_else(PoisonError::into_inner);
    patches.retain(|patch| {
        !restored
            .iter()
            .any(|(address, original)| *address == patch.address && *original == patch.original)
    });
    if failed {
        return Err("T7 Patch: memory restoration failed".to_owned());
    }
    Ok(())
}

/// Creates one `MinHook` hook at `rva`, pointing it at `detour`. When `slot` is given, the
/// trampoline is stored there.
///
/// As in the fork's `CreatePatchHook`, a failed create is an error.
fn hook<F: Copy>(rva: usize, detour: F, slot: Option<&Original<F>>) -> Result<(), String> {
    const { assert!(size_of::<F>() == size_of::<usize>()) };
    // SAFETY: `F` is a function pointer, so its bytes are the detour's entry address.
    let detour_address: usize = unsafe { std::mem::transmute_copy(&detour) };
    // SAFETY: the callers pair `rva` with a detour of the matching signature `F`.
    let trampoline = unsafe { ffi::create_hook(offsets::address(rva), detour_address) }
        .map_err(|error| format!("T7 Patch: MH_CreateHook failed at {rva:#X}: {error}"))?;
    if let Some(slot) = slot {
        slot.store(trampoline);
    }
    Ok(())
}

/// Port of `hooks::ApplyHooks`. Creates the campaign and Lua hooks, then every `MinHook`
/// hook in the C++ order. Nothing is enabled here: the lifecycle enables every hook at once
/// after the protection module is installed.
///
/// # Errors
///
/// Returns an error naming the first hook that cannot be created. Hooks created before it stay created and disabled.
pub fn create_all() -> Result<(), String> {
    // The campaign and Lua hooks are created by their own modules, as in the C++.
    campaign::install_hooks()
        .map_err(|error| format!("T7 Patch: campaign hook creation failed: {error}"))?;
    lua_symbols::install_hooks()?;

    create_lobby_message_hooks()?;
    create_ui_and_menu_hooks()?;
    create_network_hooks()?;
    create_entitlement_hooks()?;
    Ok(())
}

/// Part of [`create_all`], in the C++ order: lobby message packaging, build title, system info, message type names and string handling.
fn create_lobby_message_hooks() -> Result<(), String> {
    hook(
        offsets::PTR_LOBBY_MSG_RW_PREP_WRITE_MSG,
        hk_lobby_msg_rw_prep_write_msg as PrepWriteMsgFn,
        Some(&ORIG_LOBBY_MSG_RW_PREP_WRITE_MSG),
    )?;
    hook(
        LOBBY_MSG_RW_PREP_READ_MSG,
        hk_lobby_msg_rw_prep_read_msg as PrepReadMsgFn,
        Some(&ORIG_LOBBY_MSG_RW_PREP_READ_MSG),
    )?;
    hook(
        COD_GET_BUILD_TITLE,
        hk_cod_get_build_title as BuildTitleFn,
        None,
    )?;
    hook(
        LIVE_SYSTEM_INFO,
        hk_live_system_info as LiveSystemInfoFn,
        Some(&ORIG_LIVE_SYSTEM_INFO),
    )?;
    hook(
        LOBBY_TYPES_GET_MSG_TYPE_NAME,
        hk_lobby_types_get_msg_type_name as MsgTypeNameFn,
        Some(&ORIG_LOBBY_TYPES_GET_MSG_TYPE_NAME),
    )?;
    hook(QMEMCPY, hk_qmemcpy as QmemcpyFn, Some(&ORIG_QMEMCPY))?;
    hook(
        FLSOME_WEIRD_CHARACTER_INDEX,
        hk_flsome_weird_character_index as WeirdCharacterIndexFn,
        Some(&ORIG_FLSOME_WEIRD_CHARACTER_INDEX),
    )?;
    hook(
        SEH_REPLACE_DIRECTIVE_IN_STRING_WITH_BINDING,
        hk_seh_replace_directive_in_string_with_binding as SehReplaceFn,
        Some(&ORIG_SEH_REPLACE),
    )?;
    hook(
        offsets::PTR_LOBBY_MSG_RW_PACKAGE_INT,
        hk_lobby_msg_rw_package_int as PackageIntFn,
        Some(&ORIG_PACKAGE_INT),
    )?;
    hook(
        offsets::PTR_LOBBY_MSG_RW_PACKAGE_UINT,
        hk_lobby_msg_rw_package_uint as PackageUIntFn,
        Some(&ORIG_PACKAGE_UINT),
    )?;
    hook(
        offsets::PTR_LOBBY_MSG_RW_PACKAGE_UCHAR,
        hk_lobby_msg_rw_package_uchar as PackageUCharFn,
        Some(&ORIG_PACKAGE_UCHAR),
    )?;
    Ok(())
}

/// Part of [`create_all`], in the C++ order: UI models, menu responses, packet checksums, lobby message printing, Lua commands and the user name.
fn create_ui_and_menu_hooks() -> Result<(), String> {
    hook(
        UI_DO_MODEL_STRING_REPLACEMENT,
        hk_ui_do_model_string_replacement as ModelStringFn,
        Some(&ORIG_UI_DO_MODEL_STRING_REPLACEMENT),
    )?;
    hook(
        LIVE_STEAM_INIT_SERVER,
        hk_live_steam_init_server as VoidFn,
        None,
    )?;
    hook(CMD_MENU_RESPONSE_F, hk_cmd_menu_response_f as MenuFn, None)?;
    hook(
        CMD_MENU_RESPONSE_CACHED_F,
        hk_cmd_menu_response_cached_f as MenuFn,
        None,
    )?;
    hook(
        UI_MODEL_GET_MODEL_FROM_PATH_0,
        hk_ui_model_get_model_from_path_0 as ModelPathFn,
        Some(&ORIG_UI_MODEL_GET_MODEL_FROM_PATH_0),
    )?;
    hook(
        UI_MODEL_GET_MODEL_FROM_PATH,
        hk_ui_model_get_model_from_path as ModelPathFn,
        Some(&ORIG_UI_MODEL_GET_MODEL_FROM_PATH),
    )?;
    hook(
        UI_MODEL_CREATE_MODEL_FROM_PATH,
        hk_ui_model_create_model_from_path as ModelPathFn,
        Some(&ORIG_UI_MODEL_CREATE_MODEL_FROM_PATH),
    )?;
    hook(
        UI_MODEL_ALLOCATE_NODE,
        hk_ui_model_allocate_node as AllocateNodeFn,
        Some(&ORIG_UI_MODEL_ALLOCATE_NODE),
    )?;
    hook(
        SYS_VERIFY_PACKET_CHECKSUM,
        hk_sys_verify_packet_checksum as VerifyChecksumFn,
        Some(&ORIG_SYS_VERIFY_PACKET_CHECKSUM),
    )?;
    hook(
        SYS_CHECKSUM_COPY,
        hk_sys_checksum_copy as ChecksumCopyFn,
        Some(&ORIG_SYS_CHECKSUM_COPY),
    )?;
    hook(
        LOBBY_MSG_RW_PRINT_MESSAGE,
        hk_lobby_msg_rw_print_message as VoidFn,
        None,
    )?;
    hook(
        LOBBY_MSG_RW_PRINT_DEBUG_MESSAGE,
        hk_lobby_msg_rw_print_debug_message as PrintDebugFn,
        None,
    )?;
    hook(EXEC_LUA_CMD, hk_exec_lua_cmd as VoidFn, None)?;
    hook(
        LIVE_USER_GET_NAME,
        hk_live_user_get_name as LiveUserGetNameFn,
        None,
    )?;
    Ok(())
}

/// Part of [`create_all`], in the C++ order: instant messages, connectionless commands, presence, config strings, UGC and invites.
fn create_network_hooks() -> Result<(), String> {
    // Not ported: the C++ hooks its own CRT's `__report_gsfailure` here, so that a
    // `/GS` stack-cookie failure in T7Patch.dll faults where the exception handler
    // can catch it. This DLL is Rust only and has no `/GS` checks to fail.
    hook(
        offsets::PTR_DW_INSTANT_DISPATCH_MESSAGE,
        hk_dw_instant_dispatch_message as DispatchMessageFn,
        None,
    )?;
    hook(
        CL_CONNECTIONLESS_CMD,
        hk_cl_connectionless_cmd as ConnectionlessFn,
        Some(&ORIG_CL_CONNECTIONLESS_CMD),
    )?;
    hook(
        LIVE_PRESENCE_SERIALIZE,
        hk_live_presence_serialize as PresenceSerializeFn,
        Some(&ORIG_LIVE_PRESENCE_SERIALIZE),
    )?;
    hook(
        offsets::PTR_CL_GET_CONFIG_STRING,
        hk_cl_get_config_string as GetConfigStringFn,
        Some(&ORIG_CL_GET_CONFIG_STRING),
    )?;
    hook(
        MODS_SUBSCRIBE_UGC,
        hk_mods_subscribe_ugc as SubscribeUgcFn,
        Some(&ORIG_MODS_SUBSCRIBE_UGC),
    )?;
    hook(
        LIVE_INVITES_ACCEPT_INVITE,
        hk_live_invites_accept_invite as InviteFn,
        Some(&ORIG_LIVE_INVITES_ACCEPT_INVITE),
    )?;
    hook(
        LIVE_INVITES_SEND_JOIN_INFO,
        hk_live_invites_send_join_info as SendJoinInfoFn,
        Some(&ORIG_LIVE_INVITES_SEND_JOIN_INFO),
    )?;
    hook(
        LIVE_INVITES_JOIN_MESSAGE_ACTION,
        hk_live_invites_join_message_action as InviteFn,
        Some(&ORIG_LIVE_INVITES_JOIN_MESSAGE_ACTION),
    )?;
    hook(UI_BROWSER_OPEN, hk_ui_browser_open as BrowserOpenFn, None)?;
    Ok(())
}

/// Part of [`create_all`], in the C++ order: licences, inventory, entitlements, info keys and the mods-loaded checks.
fn create_entitlement_hooks() -> Result<(), String> {
    // The five BG_Cache hooks are commented out in the C++ and are not created here.
    hook(
        USER_HAS_LICENSE_FOR_APP,
        hk_user_has_license_for_app as LicenseFn,
        Some(&ORIG_USER_HAS_LICENSE_FOR_APP),
    )?;
    hook(
        LIVE_INVENTORY_GET_ITEM_QUANTITY,
        hk_live_inventory_get_item_quantity as ItemQuantityFn,
        Some(&ORIG_LIVE_INVENTORY_GET_ITEM_QUANTITY),
    )?;
    hook(
        LIVE_ENTITLEMENTS_IS_ENTITLEMENT_ACTIVE_FOR_CONTROLLER,
        hk_live_entitlements_is_entitlement_active_for_controller as ControllerPairBoolFn,
        Some(&ORIG_LIVE_ENTITLEMENTS_IS_ACTIVE),
    )?;
    hook(
        LIVE_INVENTORY_ARE_EXTRA_SLOTS_PURCHASED,
        hk_live_inventory_are_extra_slots_purchased as ControllerBoolFn,
        Some(&ORIG_LIVE_INVENTORY_ARE_EXTRA_SLOTS_PURCHASED),
    )?;
    hook(
        LIVE_INVENTORY_IS_VALID,
        hk_live_inventory_is_valid as ControllerBoolFn,
        Some(&ORIG_LIVE_INVENTORY_IS_VALID),
    )?;
    hook(
        INFO_VALUE_FOR_KEY,
        hk_info_value_for_key as ValueForKeyFn,
        Some(&ORIG_INFO_VALUE_FOR_KEY),
    )?;
    hook(
        MODS_IS_MODS_LOADED,
        hk_mods_is_mods_loaded as ModsLoadedFn,
        Some(&ORIG_MODS_IS_MODS_LOADED),
    )?;
    hook(
        MODS_IS_MODS_LOADED_1,
        hk_mods_is_mods_loaded_1 as ModsLoadedFn,
        Some(&ORIG_MODS_IS_MODS_LOADED_1),
    )?;
    Ok(())
}

/// Port of `hooks::DestroyHooks`. Disables every hook. The hooks are not removed, so a
/// callback still running through a trampoline stays valid.
///
/// # Errors
///
/// Returns an error when the hooking library cannot disable the hooks.
pub fn disable_all() -> Result<(), String> {
    // SAFETY: a null target is MinHook's `MH_ALL_HOOKS`, which disables every hook.
    unsafe { ffi::disable_hook(0) }
        .map_err(|error| format!("T7 Patch: MinHook disable failed: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A zeroed message with `remaining` unread bytes.
    fn msg_with_remaining(remaining: u32) -> Msg {
        // SAFETY: a zeroed `msg_t` is valid, as in `hk_dw_instant_dispatch_message`.
        let mut msg: Msg = unsafe { std::mem::zeroed() };
        msg.cursize = remaining + 4;
        msg.readcount = 4;
        msg
    }

    #[test]
    fn im_payload_is_dispatched_when_the_read_succeeds() {
        let mut msg = msg_with_remaining(3);
        let result = dispatch_im_payload(
            &mut msg,
            |_, data, size| {
                assert_eq!(size, 3);
                data[..3].copy_from_slice(b"abc");
            },
            |data, size| {
                assert_eq!(&data[..3], b"abc");
                i64::from(size) + 100
            },
        );
        assert_eq!(result, 103);
    }

    #[test]
    fn overflowed_im_payload_is_not_dispatched() {
        let mut msg = msg_with_remaining(3);
        let result = dispatch_im_payload(
            &mut msg,
            |msg, _, _| msg.overflowed = true,
            |_, _| panic!("an overflowed read reached LobbyMsg_HandleIM"),
        );
        assert_eq!(result, 0);
    }

    #[test]
    fn oversized_or_negative_im_payload_is_not_read() {
        for (cursize, readcount) in [(2048 + 4, 4), (2, 4)] {
            // SAFETY: as in `msg_with_remaining`.
            let mut msg: Msg = unsafe { std::mem::zeroed() };
            msg.cursize = cursize;
            msg.readcount = readcount;
            let result = dispatch_im_payload(
                &mut msg,
                |_, _, _| panic!("read an oversized payload"),
                |_, _| panic!("dispatched an oversized payload"),
            );
            assert_eq!(result, 0);
        }
    }

    /// A byte source over a fixed table, for `callsite_from_return`.
    fn bytes_at(table: &[(usize, u8)]) -> impl Fn(usize) -> u8 + '_ {
        move |address| {
            table
                .iter()
                .find(|(at, _)| *at == address)
                .map_or(0, |(_, value)| *value)
        }
    }

    #[test]
    fn callsite_finds_call_five_bytes_before_return() {
        let ret = 0x1000;
        let bytes = [(ret - 5, 0xE8)];
        assert_eq!(callsite_from_return(ret, bytes_at(&bytes)), ret - 5);
    }

    #[test]
    fn callsite_scans_back_up_to_sixteen_bytes() {
        let ret = 0x1000;
        let bytes = [(ret - 9, 0xE8)];
        assert_eq!(callsite_from_return(ret, bytes_at(&bytes)), ret - 9);
    }

    #[test]
    fn callsite_returns_return_address_when_no_call_found() {
        let ret = 0x1000;
        let bytes = [(ret - 17, 0xE8)];
        assert_eq!(callsite_from_return(ret, bytes_at(&bytes)), ret);
    }

    #[test]
    fn legit_packets_match_exactly_and_case_sensitively() {
        assert!(is_legit_packet(b"connectResponse"));
        assert!(is_legit_packet(b"cfl"));
        assert!(!is_legit_packet(b"connectresponse"));
        assert!(!is_legit_packet(b"connectResponse\n"));
        assert!(!is_legit_packet(b"requeststats"));
    }

    #[test]
    fn connectionless_filter_rules() {
        // requeststats passes only in campaign mode.
        assert!(connectionless_passes(true, true, false));
        assert!(!connectionless_passes(true, false, false));
        // Legit packets pass in any mode.
        assert!(connectionless_passes(false, false, true));
        assert!(!connectionless_passes(false, false, false));
    }

    #[test]
    fn mspreload_prefix_truncates_to_nine_bytes_and_ignores_case() {
        assert!(is_mspreload_prefix(b"mspreload"));
        assert!(is_mspreload_prefix(b"MSPRELOAD extra"));
        assert!(!is_mspreload_prefix(b"mspreloa"));
        assert!(!is_mspreload_prefix(b""));
    }

    #[test]
    fn watched_config_strings_are_3514_and_3627() {
        assert!(is_watched_config_string(3514));
        assert!(is_watched_config_string(3627));
        assert!(!is_watched_config_string(3515));
    }

    #[test]
    fn index_limits_reject_at_and_above_limit() {
        assert!(!index_out_of_range(63, 64));
        assert!(index_out_of_range(64, 64));
        assert!(!index_out_of_range(255, 256));
        assert!(index_out_of_range(256, 256));
        assert!(!index_out_of_range(2047, 2048));
        assert!(index_out_of_range(2048, 2048));
        assert!(!index_out_of_range(127, 128));
        assert!(index_out_of_range(128, 128));
    }

    #[test]
    fn message_type_index_bounds() {
        assert!(!msg_type_index_valid(-2));
        assert!(msg_type_index_valid(-1));
        assert!(msg_type_index_valid(0x20));
        assert!(!msg_type_index_valid(0x21));
    }

    #[test]
    fn lobby_type_ranges() {
        assert!(lobby_type_in_range(0));
        assert!(lobby_type_in_range(2));
        assert!(!lobby_type_in_range(-1));
        assert!(!lobby_type_in_range(3));
        assert!(lobby_type_unsigned_ok(2));
        assert!(!lobby_type_unsigned_ok(3));
    }

    #[test]
    fn datamask_rules() {
        assert!(!datamask_accepted(0, 0));
        // Low nibble of the state is sign-extended; a non-zero result accepts.
        assert!(datamask_accepted(1, 0x1));
        assert!(datamask_accepted(512, 0xF));
        // With a zero state, bit 512 is refused.
        assert!(!datamask_accepted(512, 0));
        assert!(datamask_accepted(1, 0));
        // State 0x10 has a zero low nibble, so the bit rule applies.
        assert!(datamask_accepted(1, 0x10));
    }

    #[test]
    fn nat_type_clamps_to_four() {
        assert_eq!(clamp_nat_type(4), 4);
        assert_eq!(clamp_nat_type(5), 4);
        assert_eq!(clamp_nat_type(255), 4);
        assert_eq!(clamp_nat_type(1), 1);
    }

    #[test]
    fn presence_count_clamps_to_eighteen_and_keeps_other_bits() {
        let packed = (19 << 2) | 0b11 | (1 << 8);
        let clamped = clamp_presence_count(packed);
        assert_eq!((clamped >> 2) & 0x1F, 18);
        assert_eq!(clamped & 0b11, 0b11);
        assert_eq!(clamped & (1 << 8), 1 << 8);
        assert_eq!(clamp_presence_count(18 << 2), 18 << 2);
        assert_eq!(clamp_presence_count(17 << 2), 17 << 2);
    }

    #[test]
    fn checksum_accepts_first_key_and_second_key_only_when_recent() {
        let computed = 0x1234;
        let key1 = 0x00AA;
        let key0 = 0x0055;
        let first = key1 ^ computed;
        assert!(checksum_trailer_accepted(
            computed, first, key1, key0, false
        ));
        let second = first ^ key1 ^ key0;
        assert!(!checksum_trailer_accepted(
            computed, second, key1, key0, false
        ));
        assert!(checksum_trailer_accepted(
            computed, second, key1, key0, true
        ));
        assert!(!checksum_trailer_accepted(
            computed, 0xFFFF, key1, key0, true
        ));
    }

    #[test]
    fn model_key_rejects_segment_of_sixty_four_bytes() {
        let long = "a".repeat(64);
        let ok = "a".repeat(63);
        assert!(model_key_too_long(long.as_bytes()));
        assert!(!model_key_too_long(ok.as_bytes()));
        let dotted = format!("x.{long}");
        assert!(model_key_too_long(dotted.as_bytes()));
        assert!(!model_key_too_long(b"a.b.c"));
    }

    #[test]
    fn binding_directives_neutralise_unterminated_caret_b() {
        let mut input = *b"^Babc\0\0\0\0";
        neutralize_binding_directives(&mut input);
        assert_eq!(until_nul(&input), b".Babc");
    }

    #[test]
    fn binding_directives_keep_terminated_caret_b() {
        let mut input = *b"^Babc^def\0";
        neutralize_binding_directives(&mut input);
        assert_eq!(until_nul(&input), b"^Babc^def");
    }

    #[test]
    fn binding_directives_reject_caret_b_longer_than_limit() {
        let mut text = b"^B".to_vec();
        text.extend(std::iter::repeat_n(b'x', 0x40));
        text.push(b'^');
        text.push(0);
        neutralize_binding_directives(&mut text);
        assert_eq!(text[0], b'.');
    }

    #[test]
    fn binding_tokens_neutralise_unclosed_bracket() {
        let mut input = *b"[{abc\0\0\0";
        neutralize_binding_tokens(&mut input);
        assert_eq!(until_nul(&input), b"..abc");
    }

    #[test]
    fn binding_tokens_keep_closed_bracket() {
        let mut input = *b"[{a}]\0";
        neutralize_binding_tokens(&mut input);
        assert_eq!(until_nul(&input), b"[{a}]");
    }

    #[test]
    fn model_string_neutralises_unclosed_dollar_paren() {
        let mut input = *b"$(abc\0\0\0";
        assert!(sanitize_model_string(&mut input));
        assert_eq!(until_nul(&input), b"..abc");
    }

    #[test]
    fn model_string_keeps_closed_dollar_paren() {
        let mut input = *b"$(abc)\0\0";
        assert!(!sanitize_model_string(&mut input));
        assert_eq!(until_nul(&input), b"$(abc)");
    }

    #[test]
    fn atoi_matches_strtol_clamping() {
        assert_eq!(c_atoi(b" 42x"), 42);
        assert_eq!(c_atoi(b"-7"), -7);
        assert_eq!(c_atoi(b"+9"), 9);
        assert_eq!(c_atoi(b""), 0);
        assert_eq!(c_atoi(b"abc"), 0);
        assert_eq!(c_atoi(b"99999999999"), i32::MAX);
        assert_eq!(c_atoi(b"-99999999999"), i32::MIN);
    }

    #[test]
    fn strcpy_s_fails_when_it_does_not_fit() {
        let mut buffer = [9u8; 4];
        assert!(strcpy_s(&mut buffer, b"abc"));
        assert_eq!(&buffer, b"abc\0");
        let mut small = [9u8; 3];
        assert!(!strcpy_s(&mut small, b"abc"));
        assert_eq!(small[0], 0);
    }

    #[test]
    fn strcpy_s_into_empty_buffer_writes_nothing() {
        let mut empty: [u8; 0] = [];
        assert!(!strcpy_s(&mut empty, b"x"));
    }

    #[test]
    fn snprintf_truncates_and_terminates() {
        let mut buffer = [9u8; 5];
        snprintf_into(&mut buffer, b"abcdefgh");
        assert_eq!(&buffer, b"abcd\0");
    }

    #[test]
    fn temp_ban_text_matches_format() {
        assert_eq!(temp_ban_command(3), "tempBanClient 3\n");
        assert_eq!(temp_ban_command(-1), "tempBanClient -1\n");
    }

    #[test]
    fn menu_policy_matches_c_logic() {
        // A non-host sending killserverpc is banned, even in campaign.
        assert!(menu_non_host_bans(MenuVerb::KillServer, true));
        assert!(menu_non_host_bans(MenuVerb::RestartLevel, false));
        // End verbs are banned outside campaign only.
        assert!(menu_non_host_bans(MenuVerb::EndGame, false));
        assert!(!menu_non_host_bans(MenuVerb::EndGame, true));
        assert!(!menu_non_host_bans(MenuVerb::None, false));
        // Non-special verbs pass without the host check.
        assert!(menu_allowed_without_host(MenuVerb::None, false));
        assert!(!menu_allowed_without_host(MenuVerb::KillServer, false));
        // Campaign transitions pass without the host check.
        assert!(menu_allowed_without_host(MenuVerb::EndRound, true));
        assert!(!menu_allowed_without_host(MenuVerb::EndRound, false));
    }

    #[test]
    fn add_signed_moves_both_ways() {
        assert_eq!(add_signed(100, 4), 104);
        assert_eq!(add_signed(100, -4), 96);
    }

    #[test]
    fn low16_keeps_low_bits() {
        assert_eq!(low16(0x1_2345), 0x2345);
        assert_eq!(low16(-1), 0xFFFF);
    }

    #[test]
    fn is_mod_loaded_addrs_has_twenty_entries() {
        assert_eq!(IS_MOD_LOADED_ADDRS.len(), 20);
        assert_eq!(IS_MOD_LOADED_ADDRS[0], 0x20EB3C4);
        assert_eq!(IS_MOD_LOADED_ADDRS[19], 0x20EAD5D);
    }
}
