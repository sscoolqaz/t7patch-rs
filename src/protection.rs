//! Port of `Protection.cpp` and `Protection.h`.
//!
//! The original `T7Patch` is by shiversoftdev (Scroptss/T7Patch-src). This module
//! covers the lobby-message inspectors that drop malformed packets, the Steam
//! API vtable overrides (ownership, DLC progress, friends, usernames, lobby
//! chat), the `t7patch.conf` settings watcher, and the exception fixups for the
//! Lua and character-index crashes.
//!
//! Game RVAs live in `offsets.rs` and the shared structs in `structs.rs`.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, OsString, c_char, c_void};
use std::fs;
use std::os::windows::ffi::OsStringExt;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicPtr, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, OnceLock, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use windows::Win32::Foundation::{CloseHandle, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows::Win32::System::Diagnostics::Debug::{CONTEXT, EXCEPTION_RECORD, RaiseException};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::Memory::{
    MEMORY_BASIC_INFORMATION, PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_WRITECOPY,
    PAGE_GUARD, PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, VirtualQuery,
};
use windows::Win32::System::SystemInformation::GetTickCount64;
use windows::Win32::System::Threading::{
    CreateEventW, CreateThread, GetCurrentThreadId, GetThreadId, INFINITE, SetEvent,
    THREAD_CREATION_FLAGS, WaitForSingleObject,
};
use windows::core::PCWSTR;

use crate::fnv::fnv1a;
use crate::gscu_hash::notify_hash;
use crate::offsets::{self, address};
use crate::structs::{
    JoinPartyMember, LobbyMsg, Msg, MsgInfoResponse, MsgType, NetAdr, SessionClient,
};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Settings file, relative to the game directory (`PATCH_CONFIG_LOCATION`).
pub const PATCH_CONFIG_LOCATION: &str = "t7patch.conf";

/// `SPOOF_OWNERSHIP` in framework.h. It is `false`, so the spoof branch of the
/// ownership hooks is compiled out and not ported.
const PLAYER_NAME_LEN: usize = 16;
const MAX_PLAYER_NAME: usize = 15;
const MAX_LOBBY_CLIENTS: usize = 18;
const MAX_LOBBY_VOTES: usize = 216;
const MAX_SETTINGS_VALUE: usize = 1023;
const REQUEST_OUT_LEN: usize = 0x20000;
const LOBBY_MSG_COPY_LEN: usize = 0x50;
const LOBBY_MSG_COPY_READ: usize = 0x44;
/// Value written into the lobby-message print global. Its appearance in `rcx`
/// marks an exception raised by the game's print hook.
const LOBBY_MSG_MARKER: u64 = 0xFFEEDDCC44332212;

/// A 64-bit game word as a pointer-sized value. The crate is x64-only.
const fn word(value: u64) -> usize {
    const _: () = assert!(size_of::<usize>() == size_of::<u64>());
    usize::from_ne_bytes(value.to_ne_bytes())
}
const DROPPED_MSG_TYPE: i32 = 0xFF;
const FRIENDS_REFRESH_MS: u64 = 30 * 1000;
const DLC_PROGRESS_TTL_MS: u64 = 60 * 5 * 1000;
/// Returned by the inspectors when the game table has not been installed. A
/// nonzero result drops the message, which is the safe choice.
const NOT_INSTALLED: i32 = -1;
/// `MAX_PATH` in UTF-16 units.
const MAX_PATH: usize = 260;
/// Mask and expected value of the friend-check fast path in `CheckPendingInfoRequests`.
const EXPECTED_MASK: i64 = 0x110000000000000;
const AND_MASK: i64 = 0xFFFF00000000000;

const LOBBY_MODULE_CLIENT: i32 = 0x1;
const LOBBY_TYPE_PRIVATE: u32 = 0x0;
const LOBBY_TYPE_GAME: u32 = 0x1;

/// Message-type key used by the lobby-state packet handlers.
const MSG_LOBBY_HOST_HEARTBEAT: u8 = MsgType::LobbyHostHeartbeat as u8;
const MSG_INFO_RESPONSE: i32 = MsgType::InfoResponse as i32;

/// `STEAMVTO(x)` from Protection.h: the vtable index of a byte offset.
const fn steamvto(offset: usize) -> usize {
    offset / 8
}

pub const STEAMAPI_STEAMUSER_GETUSERNAME: usize = steamvto(0x0);
pub const STEAMAPI_STEAMUSER_VT_NAMEBYXUID: usize = steamvto(0x38);
pub const STEAMAPI_INTERFACE_IS_VAC_BANNED: usize = steamvto(0x18);
pub const STEAMAPI_INTERFACE_CHECK_OWNS_CONTENT2: usize = steamvto(0x30);
pub const STEAMAPI_INTERFACE_CHECK_OWNS_CONTENT: usize = steamvto(0x38);
pub const STEAMAPI_INTERFACE_GET_DLC_DOWNLOAD_PROGRESS: usize = steamvto(0xB0);
pub const STEAMAPI_MATCHMAKING_GETLOBBYCHATENTRY: usize = steamvto(0xD8);
pub const STEAMAPI_MATCHMAKING_CREATELOBBY: usize = steamvto(0x68);
pub const STEAMAPI_NETWORKING_READP2PPACKET: usize = steamvto(0x10);

/// Byte offsets into `ISteamFriends` used by the friends snapshot.
const STEAM_FRIENDS_GET_COUNT_OFFSET: usize = 0x18;
const STEAM_FRIENDS_GET_BY_INDEX_OFFSET: usize = 0x20;
const STEAM_FRIEND_FLAG_IMMEDIATE: i32 = 4;

/// `SD`/`SS` string table from Protection.cpp, in the order `install` assigns it.
/// The call sites below use the same text as C string literals. `dlcBits` is
/// assigned three times in the original and is kept that way here.
pub const FIELD_NAMES: &[&CStr] = &[
    c"targetlobby",
    c"sourcelobby",
    c"jointype",
    c"probedxuid",
    c"playlistid",
    c"playlistver",
    c"ffotdver",
    c"networkmode",
    c"netchecksum",
    c"protocol",
    c"changelist",
    c"pingband",
    c"dlcbits",
    c"joinnonce",
    c"chunk",
    c"isStarterPack",
    c"password",
    c"membercount",
    c"members",
    c"xuid",
    c"lobbyid",
    c"skillrating",
    c"skillvariance",
    c"pprobation",
    c"aprobation",
    c"statenum",
    c"mainmode",
    c"partyprivacy",
    c"lobbytype",
    c"lobbymode",
    c"sessionstatus",
    c"uiscreen",
    c"leaderactivity",
    c"key",
    c"leader",
    c"platformsession",
    c"maxclients",
    c"isadvertised",
    c"clientcount",
    c"sessionid",
    c"sessioninfo",
    c"ugcName",
    c"ugcVersion",
    c"clientlist",
    c"clientNum",
    c"gamertag",
    c"isGuest",
    c"connectbit",
    c"score",
    c"address",
    c"qport",
    c"band",
    c"netsrc",
    c"joinorder",
    c"dlcBits",
    c"migratebits",
    c"lasthosttimems",
    c"nomineelist",
    c"dlcBits",
    c"dlcBits",
    c"serverstatus",
    c"launchnonce",
    c"matchhashlow",
    c"matchhashhigh",
    c"status",
    c"statusvalue",
    c"gamemode",
    c"gametype",
    c"map",
    c"cpqueuedlevel",
    c"movieskipped",
    c"team",
    c"mapvote",
    c"readyup",
    c"plistid",
    c"plistcurr",
    c"plistentries",
    c"plistnext",
    c"plistprev",
    c"plistprevcount",
    c"votecount",
    c"votes",
    c"itemtype",
    c"item",
    c"itemgroup",
    c"attachment",
    c"votetype",
    c"votexuid",
    c"pregamepos",
    c"pregamestate",
    c"clvotecount",
    c"character",
    c"loadout",
    c"settingssize",
    c"compstate",
    c"heartbeatnum",
    c"nonce",
    c"nattype",
    c"lobbies",
    c"valid",
    c"hostxuid",
    c"hostname",
    c"secid",
    c"seckey",
    c"addrbuff",
];

/// Strings that `offsets`-era code compares against in other modules.
pub const S_MSTART: &CStr = c"mstart";
pub const S_MDATA: &CStr = c"mdata";
pub const S_MHEAD: &CStr = c"mhead";
pub const S_MSTATE: &CStr = c"mstate";
pub const S_CONNECT_RESPONSE: &CStr = c"connectResponseMigration";
pub const S_RCON: &CStr = c"rcon";
pub const S_REQUEST_STATS: &CStr = c"requeststats";
pub const S_REQUEST_STATS2: &CStr = c"requeststats\n";
pub const S_LOADING: &CStr = c"loadingnewmap";
pub const S_RA: &CStr = c"RA";
pub const S_V: &CStr = c"v";
pub const S_VT: &CStr = c"vt";
pub const S_RELAY: &CStr = c"relay";
pub const S_LMGI: &CStr = c"LMgetinfo";

// ---------------------------------------------------------------------------
// Game function types
// ---------------------------------------------------------------------------

pub type PackageIntFn = unsafe extern "system" fn(*mut c_void, *const c_char, *mut i32) -> bool;
pub type PackageUCharFn =
    unsafe extern "system" fn(*mut c_void, *const c_char, *mut c_char) -> bool;
pub type PackageStringFn =
    unsafe extern "system" fn(*mut c_void, *const c_char, *const c_char, i32) -> bool;
pub type PackageXuidFn = unsafe extern "system" fn(*mut c_void, *const c_char, *mut u64) -> bool;
pub type PackageBoolFn = unsafe extern "system" fn(*mut c_void, *const c_char, *mut c_char) -> bool;
pub type PackageUIntFn = unsafe extern "system" fn(*mut c_void, *const c_char, *mut u32) -> bool;
pub type PackageShortFn = unsafe extern "system" fn(*mut c_void, *const c_char, *mut i16) -> bool;
pub type PackageUShortFn = unsafe extern "system" fn(*mut c_void, *const c_char, *mut u16) -> bool;
pub type PackageUInt64Fn = unsafe extern "system" fn(*mut c_void, *const c_char, *mut u64) -> bool;
pub type PackageArrayStartFn = unsafe extern "system" fn(*mut c_void, *const c_char) -> bool;
pub type PackageElementFn = unsafe extern "system" fn(*mut c_void, i32) -> bool;
pub type PackageGlobFn =
    unsafe extern "system" fn(*mut c_void, *const c_char, *const c_char, i32) -> bool;
pub type PackageFloatFn = unsafe extern "system" fn(*mut c_void, *const c_char, *mut f32) -> bool;
pub type PackageCharFn = unsafe extern "system" fn(*mut c_void, *const c_char, *mut c_char) -> bool;

pub type ProbeLobbyInfoFn = unsafe extern "system" fn(i32, i32, i64) -> i32;
/// `dwInstantHandleLobbyMessage(sender, controller, msg)`. The third argument is a
/// `msg_t` positioned after the IM header: the function (Feb `0x143A7A0`, read
/// live) copies `cursize - readcount` bytes (at most 0x800) out of it with
/// `MSG_ReadData` and, unless it overflowed, calls `LobbyMsg_HandleIM`.
pub type DwInstantHandleLobbyMessageFn = unsafe extern "system" fn(i64, i32, *mut Msg) -> i32;
pub type DwInstantSendMessageFn =
    unsafe extern "system" fn(i32, *mut i64, u32, i8, *const c_char, u32) -> i32;
pub type NetOutOfBandPrintFn = unsafe extern "system" fn(i32, NetAdr, *const c_char) -> i32;
pub type NetOutOfBandDataFn = unsafe extern "system" fn(i32, NetAdr, *mut c_char, i32) -> i32;
pub type DwCommonAddrToNetadrFn =
    unsafe extern "system" fn(*mut NetAdr, *const c_void, *const c_void);
pub type DwRegisterSecIdAndKeyFn = unsafe extern "system" fn(*mut c_void, *mut c_void);
pub type LobbyMsgTansportSendOutOfBandFn =
    unsafe extern "system" fn(i32, i64, NetAdr, *mut LobbyMsg, i32);
pub type LobbyMsgRwPrepWriteMsgFn =
    unsafe extern "system" fn(*mut LobbyMsg, *mut c_char, i32, i32) -> bool;
pub type LobbyMsgRwPrepReadDataFn =
    unsafe extern "system" fn(*mut LobbyMsg, *mut c_char, i32) -> bool;
pub type MsgInitFn = unsafe extern "system" fn(*mut Msg, *mut c_char, i32);
pub type MsgWriteStringFn = unsafe extern "system" fn(*mut Msg, *const c_char);
pub type MsgWriteShortFn = unsafe extern "system" fn(*mut Msg, i16);
pub type MsgWriteByteFn = unsafe extern "system" fn(*mut Msg, u8);
pub type MsgWriteDataFn = unsafe extern "system" fn(*mut Msg, *mut c_char, i32);
pub type MsgReadDataFn = unsafe extern "system" fn(*mut Msg, *mut c_char, i32);
pub type MsgInfoResponseFn = unsafe extern "system" fn(*mut c_void, *mut LobbyMsg) -> bool;
pub type ComControllerIndexGetLocalClientNumFn = unsafe extern "system" fn(i32) -> i32;
pub type ComLocalClientGetNetworkIdFn = unsafe extern "system" fn(i32) -> i32;
pub type LobbyMsgTransportSendToAdrFn =
    unsafe extern "system" fn(i32, i32, i32, NetAdr, u64, *mut Msg, i32) -> i32;
pub type LobbySessionGetControllingFn = unsafe extern "system" fn(i32) -> bool;
pub type LobbySessionGetSessionFn = unsafe extern "system" fn(u32) -> *mut c_void;
pub type LobbySessionGetClientByClientNumFn =
    unsafe extern "system" fn(*mut c_void, i32) -> *mut SessionClient;
pub type LobbySessionGetClientNetAdrByIndexFn = unsafe extern "system" fn(i32, i32) -> NetAdr;
pub type LobbyJoinReserveFn =
    unsafe extern "system" fn(i32, *mut JoinPartyMember, i32, i64, i64, *mut i64) -> i32;
pub type ClGetConfigStringFn = unsafe extern "system" fn(i32) -> *const c_char;
pub type CbufAddTextFn = unsafe extern "system" fn(i32, *const c_char, i32) -> bool;
pub type IStricmpFn = unsafe extern "system" fn(*const c_char, *const c_char) -> i32;

type OwnsContentFn = unsafe extern "system" fn(i64, i32) -> bool;
type DlcProgressFn = unsafe extern "system" fn(i64, i32, *mut i64, *mut i64);
type LobbyChatEntryFn = unsafe extern "system" fn(i64, i64, i64, i64, i64, i64, i64) -> i32;
type CreateLobbyFn = unsafe extern "system" fn(i64, i64, i64) -> i64;
type GetUsernameXuidFn = unsafe extern "system" fn(i64, i64) -> *const c_char;
type ReadP2PPacketFn =
    unsafe extern "system" fn(usize, *mut c_void, u32, *mut u32, *mut u64, i32) -> bool;
type SteamFriendCountFn = unsafe extern "system" fn(usize, i32) -> i32;
type SteamFriendByIndexFn = unsafe extern "system" fn(usize, *mut i64, i32, i32);
type ComSessionModeGetModeNameFn = unsafe extern "system" fn() -> *const c_char;
type ClSwitchStateIdleUpdateFn = unsafe extern "system" fn(i64) -> i32;
type DvarSetFromStringFn = unsafe extern "system" fn(*const c_char, *const c_char, bool) -> usize;
type ZwContinueFn = unsafe extern "system" fn(*mut CONTEXT, u8) -> u64;
type IsProcessorFeaturePresentFn = unsafe extern "system" fn(u32) -> i32;
type CreateLobbyAgainFn = unsafe extern "system" fn(i64);

/// Game function table filled by [`install`]. Each field is a game function
/// the lobby and Steam code calls. The fields are public, as the header made
/// the `Protection::*` statics public.
pub struct Game {
    pub lobby_msg_rw_package_int: PackageIntFn,
    pub lobby_msg_rw_package_uchar: PackageUCharFn,
    pub lobby_msg_rw_package_string: PackageStringFn,
    pub lobby_msg_rw_package_xuid: PackageXuidFn,
    pub lobby_msg_rw_package_bool: PackageBoolFn,
    pub lobby_msg_rw_package_uint: PackageUIntFn,
    pub lobby_msg_rw_package_short: PackageShortFn,
    pub lobby_msg_rw_package_uint64: PackageUInt64Fn,
    pub lobby_msg_rw_package_array_start: PackageArrayStartFn,
    pub lobby_msg_rw_package_element: PackageElementFn,
    pub lobby_msg_rw_package_glob: PackageGlobFn,
    pub msg_mutable_client_info_package: unsafe extern "system" fn(*mut c_void, *mut c_void) -> i32,
    pub probe_lobby_info: ProbeLobbyInfoFn,
    pub dw_instant_handle_lobby_message: DwInstantHandleLobbyMessageFn,
    pub net_out_of_band_print: NetOutOfBandPrintFn,
    pub dw_common_addr_to_netadr: DwCommonAddrToNetadrFn,
    pub dw_register_sec_id_and_key: DwRegisterSecIdAndKeyFn,
    pub lobby_msg_rw_prep_write_msg: LobbyMsgRwPrepWriteMsgFn,
    pub lobby_msg_rw_package_ushort: PackageUShortFn,
    pub lobby_msg_rw_package_float: PackageFloatFn,
    pub msg_init: MsgInitFn,
    pub msg_write_string: MsgWriteStringFn,
    pub msg_write_short: MsgWriteShortFn,
    pub msg_write_byte: MsgWriteByteFn,
    pub msg_write_data: MsgWriteDataFn,
    pub com_controller_index_get_local_client_num: ComControllerIndexGetLocalClientNumFn,
    pub com_local_client_get_network_id: ComLocalClientGetNetworkIdFn,
    pub net_out_of_band_data: NetOutOfBandDataFn,
    pub lobby_msg_transport_send_to_adr: LobbyMsgTransportSendToAdrFn,
    pub msg_read_data: MsgReadDataFn,
    pub lobby_msg_rw_prep_read_data: LobbyMsgRwPrepReadDataFn,
    pub msg_info_response: MsgInfoResponseFn,
    pub lobby_msg_rw_package_char: PackageCharFn,
    pub dw_instant_send_message: DwInstantSendMessageFn,
    pub lobby_session_get_controlling_lobby_session: LobbySessionGetControllingFn,
    pub lobby_session_get_session: LobbySessionGetSessionFn,
    pub lobby_session_get_client_by_client_num: LobbySessionGetClientByClientNumFn,
    pub lobby_session_get_client_net_adr_by_index: LobbySessionGetClientNetAdrByIndexFn,
    pub lobby_join_reserve: LobbyJoinReserveFn,
    pub cl_get_config_string: ClGetConfigStringFn,
    pub cbuf_add_text: CbufAddTextFn,
    pub i_stricmp: IStricmpFn,
}

static GAME: OnceLock<Game> = OnceLock::new();

/// The game function table, or `None` before [`install`].
pub fn game() -> Option<&'static Game> {
    GAME.get()
}

impl Game {
    /// Resolves every game function from the February-2026 RVAs in `offsets.rs`.
    ///
    /// # Safety
    ///
    /// Must run inside the game process once its executable is mapped. Each RVA
    /// must name a function whose signature matches its field type.
    unsafe fn resolve() -> Self {
        // SAFETY: each RVA names the game function whose signature matches the field.
        unsafe {
            Self {
                lobby_msg_rw_package_int: offsets::function(offsets::PTR_LOBBY_MSG_RW_PACKAGE_INT),
                lobby_msg_rw_package_uchar: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PACKAGE_UCHAR,
                ),
                lobby_msg_rw_package_string: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PACKAGE_STRING,
                ),
                lobby_msg_rw_package_xuid: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PACKAGE_XUID,
                ),
                lobby_msg_rw_package_bool: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PACKAGE_BOOL,
                ),
                lobby_msg_rw_package_uint: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PACKAGE_UINT,
                ),
                lobby_msg_rw_package_short: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PACKAGE_SHORT,
                ),
                lobby_msg_rw_package_uint64: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PACKAGE_UINT64,
                ),
                lobby_msg_rw_package_array_start: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PACKAGE_ARRAY_START,
                ),
                lobby_msg_rw_package_element: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PACKAGE_ELEMENT,
                ),
                lobby_msg_rw_package_glob: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PACKAGE_GLOB,
                ),
                msg_mutable_client_info_package: offsets::function(
                    offsets::PTR_MSG_MUTABLE_CLIENT_INFO_PACKAGE,
                ),
                probe_lobby_info: offsets::function(offsets::PTR_PROBE_LOBBY_INFO),
                dw_instant_handle_lobby_message: offsets::function(
                    offsets::PTR_DW_INSTANT_HANDLE_LOBBY_MESSAGE,
                ),
                net_out_of_band_print: offsets::function(offsets::PTR_NET_OUT_OF_BAND_PRINT),
                dw_common_addr_to_netadr: offsets::function(offsets::PTR_DW_COMMON_ADDR_TO_NETADR),
                dw_register_sec_id_and_key: offsets::function(
                    offsets::PTR_DW_REGISTER_SEC_IDAND_KEY,
                ),
                lobby_msg_rw_prep_write_msg: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PREP_WRITE_MSG,
                ),
                lobby_msg_rw_package_ushort: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PACKAGE_USHORT,
                ),
                lobby_msg_rw_package_float: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PACKAGE_FLOAT,
                ),
                msg_init: offsets::function(offsets::PTR_MSG_INIT),
                msg_write_string: offsets::function(offsets::PTR_MSG_WRITE_STRING),
                msg_write_short: offsets::function(offsets::PTR_MSG_WRITE_SHORT),
                msg_write_byte: offsets::function(offsets::PTR_MSG_WRITE_BYTE),
                msg_write_data: offsets::function(offsets::PTR_MSG_WRITE_DATA),
                com_controller_index_get_local_client_num: offsets::function(
                    offsets::PTR_COM_CONTROLLER_INDEX_GET_LOCAL_CLIENT_NUM,
                ),
                com_local_client_get_network_id: offsets::function(
                    offsets::PTR_COM_LOCAL_CLIENT_GET_NETWORK_ID,
                ),
                net_out_of_band_data: offsets::function(offsets::PTR_NET_OUT_OF_BAND_DATA),
                lobby_msg_transport_send_to_adr: offsets::function(
                    offsets::PTR_LOBBY_MSG_TRANSPORT_SEND_TO_ADR,
                ),
                msg_read_data: offsets::function(offsets::PTR_MSG_READ_DATA),
                lobby_msg_rw_prep_read_data: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PREP_READ_DATA,
                ),
                msg_info_response: offsets::function(offsets::PTR_MSG_INFO_RESPONSE),
                lobby_msg_rw_package_char: offsets::function(
                    offsets::PTR_LOBBY_MSG_RW_PACKAGE_CHAR,
                ),
                dw_instant_send_message: offsets::function(offsets::PTR_DW_INSTANT_SEND_MESSAGE),
                lobby_session_get_controlling_lobby_session: offsets::function(
                    offsets::PTR_LOBBY_SESSION_GET_CONTROLLING_LOBBY_SESSION,
                ),
                lobby_session_get_session: offsets::function(
                    offsets::PTR_LOBBY_SESSION_GET_SESSION,
                ),
                lobby_session_get_client_by_client_num: offsets::function(
                    offsets::PTR_LOBBY_SESSION_GET_CLIENT_BY_CLIENT_NUM,
                ),
                lobby_session_get_client_net_adr_by_index: offsets::function(
                    offsets::PTR_LOBBY_SESSION_GET_CLIENT_NET_ADR_BY_INDEX,
                ),
                lobby_join_reserve: offsets::function(offsets::PTR_LOBBY_JOIN_RESERVE),
                cl_get_config_string: offsets::function(offsets::PTR_CL_GET_CONFIG_STRING),
                cbuf_add_text: offsets::function(offsets::PTR_CBUF_ADD_TEXT),
                i_stricmp: offsets::function(offsets::PTR_I_STRICMP),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Statics
// ---------------------------------------------------------------------------

/// One immutable player-name snapshot, NUL-padded to 16 bytes.
type NameBytes = [u8; PLAYER_NAME_LEN];

/// Empty name used before the first snapshot is published.
static NAME_DEFAULT: NameBytes = [0; PLAYER_NAME_LEN];
/// The snapshot the game currently sees.
static NAME_CURRENT: AtomicPtr<u8> = AtomicPtr::new(std::ptr::null_mut());
/// Every snapshot ever published. A game thread may keep the pointer returned by
/// `get_username_ptr` indefinitely, so a replaced snapshot is transferred here
/// instead of being freed.
#[allow(
    clippy::vec_box,
    reason = "each published name keeps a stable address because the game retains the pointer"
)]
static NAME_RETAINED: Mutex<Vec<Box<NameBytes>>> = Mutex::new(Vec::new());
/// Set when the local snapshot changed and the game buffers still need updating.
static NAME_PENDING: AtomicBool = AtomicBool::new(false);
pub static OLD_LOBBYMSG_PRINTS: AtomicI64 = AtomicI64::new(0);
pub static CACHED_RETN_ADDY: AtomicI64 = AtomicI64::new(0);
pub static CACHED_XUID: AtomicI64 = AtomicI64::new(0);
pub static IS_FRIENDS_ONLY: AtomicBool = AtomicBool::new(false);
pub static IS_AUTO_INSTALL_MODS_ENABLED: AtomicBool = AtomicBool::new(false);
pub static IS_INJECTORLESS_INSTALL: AtomicBool = AtomicBool::new(true);
/// `ZwContinue`, resolved from ntdll by `DllMain`'s patch entry point. Zero until then.
pub static ZW_CONTINUE: AtomicUsize = AtomicUsize::new(0);
/// Original `oReadP2PPacket` (the value the C++ reads at `STEAMAPI_NETWORKING+0x10`).
pub static O_READ_P2P_PACKET: AtomicUsize = AtomicUsize::new(0);
/// Original `IsProcessorFeaturePresent` from the IAT hook.
pub static O_IS_PROCESSOR_FEATURE_PRESENT: AtomicUsize = AtomicUsize::new(0);
/// `PrivatePassword[3]`: previous password hash, current hash, and tick count.
pub static PRIVATE_PASSWORD: Mutex<[i64; 3]> = Mutex::new([0; 3]);
/// Originals of hooked Steam vtable slots, keyed by interface address then slot index.
/// Filled once by [`initialize`] and never changed afterwards.
pub static STEAM_API_HOOKS: Mutex<BTreeMap<usize, BTreeMap<usize, usize>>> =
    Mutex::new(BTreeMap::new());
/// One Steam vtable slot [`swap_steam_api_pointer`] wrote: the slot's address and the
/// exact values before and after the swap.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SwappedSlot {
    slot: usize,
    original: usize,
    replacement: usize,
}

/// Every Steam vtable slot written, so `uninstall` puts back exactly those values. It
/// writes a slot only while it still holds our replacement, so an interface that was
/// replaced or freed since install is never written.
static STEAM_SWAPPED: Mutex<Vec<SwappedSlot>> = Mutex::new(Vec::new());
/// Lobby message handlers keyed by message type (a `BYTE` in the original).
pub static PACKET_CALLBACKS: Mutex<BTreeMap<u8, PacketCallback>> = Mutex::new(BTreeMap::new());

/// Handler for one lobby message type. It may set the type slot to `0xFF` to drop the message.
pub type PacketCallback = unsafe fn(*mut i32, i64);

struct FriendsCache {
    next_update_ms: u64,
    set: BTreeSet<i64>,
}

static FRIENDS: Mutex<FriendsCache> = Mutex::new(FriendsCache {
    next_update_ms: 0,
    set: BTreeSet::new(),
});
static INSTALLED_DLC: Mutex<BTreeMap<i32, bool>> = Mutex::new(BTreeMap::new());
static SUBSCRIBED_APP: Mutex<BTreeMap<i32, bool>> = Mutex::new(BTreeMap::new());

#[derive(Clone, Copy, Default)]
struct DownloadProgress {
    a: i64,
    b: i64,
    next_ms: u64,
}

static DLC_PROGRESS: Mutex<BTreeMap<i32, DownloadProgress>> = Mutex::new(BTreeMap::new());

static USER_CONFIG: Mutex<PatchConfig> = Mutex::new(PatchConfig::DEFAULT);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Memory and call helpers
// ---------------------------------------------------------------------------

/// Converts a 64-bit address value from the game into a `usize`. Negative values map to 0.
fn addr(value: i64) -> usize {
    usize::try_from(value).unwrap_or(0)
}

fn addr_i64(value: usize) -> i64 {
    i64::try_from(value).unwrap_or(0)
}

fn ptr_from_i64(value: i64) -> *mut u8 {
    addr(value) as *mut u8
}

/// `(char*)base + bytes`.
fn at_bytes(base: *mut u8, bytes: usize) -> *mut u8 {
    base.wrapping_add(bytes)
}

/// `(__int32*)base + words`, as a byte pointer.
fn at_words(base: *mut u8, words: usize) -> *mut u8 {
    base.wrapping_add(words * 4)
}

/// Reads a readable `i32` at `ptr`.
///
/// # Safety
///
/// `ptr` must be readable for four bytes.
unsafe fn i32_at(ptr: *mut u8) -> i32 {
    // SAFETY: the caller guarantees four readable bytes at `ptr`.
    unsafe { ptr.cast::<i32>().read_unaligned() }
}

/// Reads a `usize` at `address`.
///
/// # Safety
///
/// `address` must be readable for eight bytes.
unsafe fn read_usize(address: usize) -> usize {
    // SAFETY: the caller guarantees eight readable bytes at `address`.
    unsafe { (address as *const usize).read_unaligned() }
}

/// # Safety
///
/// `address` must be readable for eight bytes.
unsafe fn read_i64(address: usize) -> i64 {
    // SAFETY: the caller guarantees eight readable bytes at `address`.
    unsafe { (address as *const i64).read_unaligned() }
}

/// # Safety
///
/// `address` must be writable for four bytes.
unsafe fn write_u32(address: usize, value: u32) {
    // SAFETY: the caller guarantees four writable bytes at `address`.
    unsafe { (address as *mut u32).write_unaligned(value) }
}

/// # Safety
///
/// `address` must be writable for four bytes.
unsafe fn write_i32(address: usize, value: i32) {
    // SAFETY: the caller guarantees four writable bytes at `address`.
    unsafe { (address as *mut i32).write_unaligned(value) }
}

/// Copies `src` to `dst`, as `memcpy` does.
///
/// # Safety
///
/// `dst` must be writable for `src.len()` bytes and must not overlap `src`.
unsafe fn copy_bytes(dst: *mut u8, src: &[u8]) {
    // SAFETY: the caller guarantees the destination is writable and does not overlap.
    unsafe { std::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()) }
}

/// Reinterprets a code address as the function pointer type `F`.
///
/// # Safety
///
/// `addr` must be the entry point of a function whose signature matches `F`.
unsafe fn fn_from_addr<F: Copy>(addr: usize) -> F {
    const { assert!(size_of::<F>() == size_of::<usize>()) };
    // SAFETY: `F` is a function pointer of the same size, and the caller names its signature.
    unsafe { std::mem::transmute_copy(&addr) }
}

fn tick_ms() -> u64 {
    // SAFETY: `GetTickCount64` takes no arguments.
    unsafe { GetTickCount64() }
}

/// The bytes before the first NUL, as a C string reads.
fn c_prefix(bytes: &[u8]) -> &[u8] {
    bytes
        .iter()
        .position(|&byte| byte == 0)
        .map_or(bytes, |end| &bytes[..end])
}

/// The original `SteamHAPIHooks` lookup. Returns 0 when the slot was never swapped.
#[must_use]
pub fn get_original_steam_ptr(library: usize, index: usize) -> usize {
    lock(&STEAM_API_HOOKS)
        .get(&library)
        .and_then(|slots| slots.get(&index))
        .copied()
        .unwrap_or(0)
}

/// Loads the original Steam entry for `library`/`index` as `F`, or `None` if unhooked.
///
/// # Safety
///
/// `F` must be the `unsafe extern "system"` type matching that Steam entry.
unsafe fn steam_original<F: Copy>(library: usize, index: usize) -> Option<F> {
    let original = get_original_steam_ptr(library, index);
    if original == 0 {
        return None;
    }
    // SAFETY: `original` is the saved entry of the slot the caller's `F` describes.
    Some(unsafe { fn_from_addr::<F>(original) })
}

// ---------------------------------------------------------------------------
// Pure logic
// ---------------------------------------------------------------------------

/// Parses a leading integer the way `std::istream >> int` does: skip whitespace,
/// accept one sign, read digits, and stop at the first non-digit. Returns `None`
/// when no digit is read or the value does not fit in `i32`.
#[must_use]
pub fn parse_leading_int(text: &[u8]) -> Option<i32> {
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
    let digits_start = i;
    let mut value: i64 = 0;
    while let Some(&digit) = text.get(i).filter(|byte| byte.is_ascii_digit()) {
        value = value * 10 + i64::from(digit - b'0');
        if value > i64::from(i32::MAX) + 1 {
            return None;
        }
        i += 1;
    }
    if i == digits_start {
        return None;
    }
    let signed = if negative { -value } else { value };
    i32::try_from(signed).ok()
}

/// The value passed to `SetNetworkPassword` for a typed password. An empty
/// password maps to 0.
#[must_use]
pub fn network_password_key(password: &[u8]) -> i64 {
    let text = c_prefix(password);
    if text.is_empty() {
        0
    } else {
        notify_hash(text).cast_signed()
    }
}

/// Shifts the password history: previous ← current, current ← `password`, stamp ← `now`.
pub fn rotate_private_password(state: &mut [i64; 3], password: i64, now: u64) {
    state[0] = state[1];
    state[1] = password;
    state[2] = now.cast_signed();
}

/// Extracts one byte of a password hash, as `ZBR_PREFIX_BYTE` does.
fn byte_at(value: i64, shift: u32) -> u8 {
    u8::try_from((value >> shift) & 0xFF).unwrap_or_default()
}

/// `(ZBR_PREFIX_BYTE, ZBR_PREFIX_BYTE2)` of one password hash: bits 16..24 and 24..32.
#[must_use]
pub fn zbr_prefix_of(hash: i64) -> (u8, u8) {
    (byte_at(hash, 16), byte_at(hash, 24))
}

/// Both prefix bytes of the current password hash, read under one lock, so a
/// packet never mixes bytes from a password before and after a rotation.
#[must_use]
pub fn zbr_prefix() -> (u8, u8) {
    zbr_prefix_of(lock(&PRIVATE_PASSWORD)[1])
}

/// Validates a player name, returning the NUL-padded buffer. Names longer than
/// 15 bytes are rejected, as `SetPlayerName` does.
#[must_use]
pub fn player_name_fields(name: &[u8]) -> Option<[u8; PLAYER_NAME_LEN]> {
    let text = c_prefix(name);
    if text.len() > MAX_PLAYER_NAME {
        return None;
    }
    let mut out = [0u8; PLAYER_NAME_LEN];
    out[..text.len()].copy_from_slice(text);
    Some(out)
}

/// Replaces control and sequence-breaking characters in chat with `.`, as
/// `GetLobbyChatEntry` does. Bytes at or above 0x80 count as control characters
/// because the C `char` is signed.
///
/// `buffer` is every byte Steam copied. A peer's message need not be
/// NUL-terminated, so the scan stops at the first NUL or the end of `buffer`; a
/// message that fills the buffer is cut to `len - 1` bytes so the game's own
/// string reads stop inside it (port of the fork's `ChatSanitize.h`).
pub fn sanitize_chat(buffer: &mut [u8]) {
    let len = buffer.iter().position(|&b| b == 0).unwrap_or(buffer.len());
    for i in 0..len {
        // The lookahead reads the next byte before it is rewritten; past the text it is the NUL.
        let next = if i + 1 < len { buffer[i + 1] } else { 0 };
        let replace = match buffer[i] {
            b'^' | b'%' => true,
            b'$' => next == b'(',
            b'[' => next == b'{',
            byte => !(0x20..=126).contains(&byte),
        };
        if replace {
            buffer[i] = b'.';
        }
    }
    if len == buffer.len() {
        if let Some(last) = buffer.last_mut() {
            *last = 0;
        }
    }
}

/// Decides whether `ReadP2PPacket` drops a packet. `game_im` is the byte at
/// offset 5. `is_friend` runs only for info requests while friends-only is on.
pub fn p2p_packet_is_dropped(
    game_im: u8,
    friends_only: bool,
    is_friend: impl FnOnce() -> bool,
) -> bool {
    match game_im {
        104 => friends_only && !is_friend(),
        102 | 101 | 109 => true,
        _ => false,
    }
}

/// The `.xpak` file the game requires for a content app, or `None` for other apps.
#[must_use]
pub fn content_file_for_app(app_id: i32) -> Option<&'static str> {
    match app_id {
        366840 => Some("cp_common.xpak"),
        366841 => Some("mp_common.xpak"),
        366842 => Some("zm_common.xpak"),
        _ => None,
    }
}

/// Whether a `VirtualQuery` protection value makes a pointer unreadable, as `IsBadReadPtr` decides.
#[must_use]
pub fn protect_is_bad(protect: u32) -> bool {
    let readable = PAGE_READONLY.0
        | PAGE_READWRITE.0
        | PAGE_WRITECOPY.0
        | PAGE_EXECUTE_READ.0
        | PAGE_EXECUTE_READWRITE.0
        | PAGE_EXECUTE_WRITECOPY.0;
    let blocked = PAGE_GUARD.0 | PAGE_NOACCESS.0;
    (protect & readable) == 0 || (protect & blocked) != 0
}

/// MSVC CRT `rand()`: a 15-bit value from a 32-bit linear congruential state.
pub fn msvc_rand(state: &mut u32) -> i32 {
    *state = state.wrapping_mul(214_013).wrapping_add(2_531_011);
    i32::try_from((*state >> 16) & 0x7FFF).unwrap_or_default()
}

fn unix_time_seed() -> u32 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    u32::try_from(secs).unwrap_or_default()
}

fn current_name_pointer() -> *const u8 {
    let pointer = NAME_CURRENT.load(Ordering::Acquire);
    if pointer.is_null() {
        NAME_DEFAULT.as_ptr()
    } else {
        pointer
    }
}

/// The player name as the game stores it, up to the NUL.
fn custom_name_snapshot() -> NameBytes {
    let pointer = current_name_pointer();
    // SAFETY: every pointer published to `NAME_CURRENT` comes from a Box<NameBytes>
    // retained for the process lifetime, so the read is of immutable memory.
    unsafe { std::ptr::read(pointer.cast::<NameBytes>()) }
}

fn custom_name_ptr() -> *const c_char {
    current_name_pointer().cast()
}

/// True when no custom name has been set.
pub(crate) fn custom_name_is_empty() -> bool {
    custom_name_snapshot()[0] == 0
}

/// # Safety
///
/// Reads the game's `s_playerData` pointer chain. Returns 0 when a link is null.
unsafe fn local_player_xuid() -> i64 {
    // SAFETY: `s_playerData_ptr` is a game global that holds a pointer to player data.
    let player_data = unsafe { read_usize(address(offsets::S_PLAYER_DATA_PTR)) };
    if player_data == 0 {
        return 0;
    }
    // SAFETY: the player-data object begins with its XUID.
    unsafe { read_i64(player_data) }
}

/// Port of `Protection::IsBadReadPtr`. Queries the page protection and never dereferences `p`.
#[must_use]
pub fn is_bad_read_ptr(p: *const c_void) -> bool {
    let mut info = MEMORY_BASIC_INFORMATION::default();
    // SAFETY: `VirtualQuery` only reads metadata about the address and does not dereference it.
    let written = unsafe {
        VirtualQuery(
            Some(p),
            &raw mut info,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if written == 0 {
        return true;
    }
    protect_is_bad(info.Protect.0)
}

// ---------------------------------------------------------------------------
// Import-table hooks (Iat_hook_)
// ---------------------------------------------------------------------------

/// Port of the `Iat_hook_` namespace from Protection.h.
pub mod iat_hook {
    use std::ffi::{CStr, c_char};

    use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
    use windows::Win32::System::SystemServices::{IMAGE_DOS_HEADER, IMAGE_IMPORT_DESCRIPTOR};

    /// Index of the import directory in `DataDirectory`.
    const IMPORT_DIRECTORY: usize = 1;

    /// Returns the IAT slot that imports `function`. `module == 0` means the main executable.
    ///
    /// # Safety
    ///
    /// `module` must be a mapped PE image with a valid import directory.
    pub unsafe fn find(function: &CStr, module: usize) -> Option<*mut usize> {
        let base = if module == 0 {
            crate::build::image_base()
        } else {
            module
        };
        if base == 0 {
            return None;
        }
        // SAFETY: the caller guarantees `base` is a mapped PE image.
        unsafe {
            let dos = base as *const IMAGE_DOS_HEADER;
            let nt_offset = usize::try_from((*dos).e_lfanew).unwrap_or(0);
            let nt = (base + nt_offset) as *const IMAGE_NT_HEADERS64;
            let import_rva = (*nt).OptionalHeader.DataDirectory[IMPORT_DIRECTORY].VirtualAddress;
            let mut descriptor =
                (base + usize::try_from(import_rva).unwrap_or(0)) as *const IMAGE_IMPORT_DESCRIPTOR;
            while (*descriptor).Name != 0 {
                let first_thunk = base + usize::try_from((*descriptor).FirstThunk).unwrap_or(0);
                let original_thunk =
                    base + usize::try_from((*descriptor).Anonymous.OriginalFirstThunk).unwrap_or(0);
                let mut index = 0usize;
                loop {
                    let slot = (first_thunk + index * 8) as *mut usize;
                    if *slot == 0 {
                        break;
                    }
                    let thunk = ((original_thunk + index * 8) as *const u64).read_unaligned();
                    // Skip ordinal imports (high bit set). Only named imports can match.
                    if thunk & (1 << 63) == 0 {
                        let hint_name = base + usize::try_from(thunk).unwrap_or(0);
                        let name = CStr::from_ptr((hint_name + 2) as *const c_char);
                        if name == function {
                            return Some(slot);
                        }
                    }
                    index += 1;
                }
                descriptor = descriptor.add(1);
            }
        }
        None
    }

    /// Replaces the IAT entry for `function` with `new_function` and returns the
    /// original value, or 0 if the import is missing or already points at `new_function`.
    ///
    /// # Safety
    ///
    /// `module` must be a mapped PE image. `new_function` must match the
    /// signature of the import it replaces.
    pub unsafe fn detour_iat_ptr(function: &CStr, new_function: usize, module: usize) -> usize {
        // SAFETY: the caller's contract on `module` covers `find`.
        let Some(slot) = (unsafe { find(function, module) }) else {
            return 0;
        };
        // SAFETY: `slot` is an IAT entry inside the mapped image.
        let current = unsafe { slot.read_unaligned() };
        if current == new_function || current == 0 {
            return 0;
        }
        // SAFETY: `slot` is an IAT entry; nothing is written if its page cannot be made writable.
        if !unsafe { crate::arxan::swap_usize(slot as usize, current, new_function) }.complete() {
            return 0;
        }
        current
    }
}

// ---------------------------------------------------------------------------
// Steam vtable hooks
// ---------------------------------------------------------------------------

/// Port of `Protection::SwapSteamAPIPointer`. Replaces vtable slot `index` of the
/// Steam interface whose global lives at `library`. The original must already be in the
/// snapshot [`initialize`] takes; this function never records anything.
///
/// # Safety
///
/// `library` must be the address of a loaded Steam interface global and `index`
/// a valid slot of its vtable. `replacement` must match that slot's signature.
pub unsafe fn swap_steam_api_pointer(
    library: usize,
    index: usize,
    replacement: usize,
) -> Result<(), String> {
    let prepared = lock(&STEAM_API_HOOKS)
        .get(&library)
        .is_some_and(|slots| slots.contains_key(&index));
    if !prepared {
        return Err("T7 Patch: Steam originals were not prepared".to_owned());
    }
    // SAFETY: the Steam interface global and its vtable are mapped while Steam is loaded.
    let vtable = unsafe { steam_vtable(library) }?;
    let slot = vtable + index * 8;
    // SAFETY: `slot` is a vtable entry inside the mapped vtable.
    let original = unsafe { read_usize(slot) };
    // SAFETY: `slot` is a vtable entry; nothing is written if it cannot be made
    // writable or no longer holds `original`.
    let write = unsafe { crate::arxan::swap_usize(slot, original, replacement) };
    if write.written {
        lock(&STEAM_SWAPPED).push(SwappedSlot {
            slot,
            original,
            replacement,
        });
    }
    if !write.complete() {
        return Err("T7 Patch: cannot write a Steam vtable slot".to_owned());
    }
    Ok(())
}

/// Reads the vtable of the Steam interface whose global lives at `library`.
///
/// # Safety
///
/// `library` must be the address of a Steam interface global.
unsafe fn steam_vtable(library: usize) -> Result<usize, String> {
    // SAFETY: the caller guarantees `library` is a readable interface global.
    let instance = unsafe { read_usize(library) };
    if instance == 0 {
        return Err("T7 Patch: Steam interface is not ready".to_owned());
    }
    // SAFETY: a non-null Steam interface begins with its vtable pointer.
    let vtable = unsafe { read_usize(instance) };
    if vtable == 0 {
        return Err("T7 Patch: Steam VMT is not ready".to_owned());
    }
    Ok(vtable)
}

/// The nine Steam vtable slots the patch replaces, as `(interface global, slot index)`.
fn steam_slots() -> [(usize, usize); 9] {
    [
        (steam_user(), STEAMAPI_STEAMUSER_GETUSERNAME),
        (steam_user(), STEAMAPI_STEAMUSER_VT_NAMEBYXUID),
        (steam_interface(), STEAMAPI_INTERFACE_CHECK_OWNS_CONTENT),
        (steam_interface(), STEAMAPI_INTERFACE_CHECK_OWNS_CONTENT2),
        (steam_interface(), STEAMAPI_INTERFACE_IS_VAC_BANNED),
        (
            steam_interface(),
            STEAMAPI_INTERFACE_GET_DLC_DOWNLOAD_PROGRESS,
        ),
        (steam_matchmaking(), STEAMAPI_MATCHMAKING_GETLOBBYCHATENTRY),
        (steam_matchmaking(), STEAMAPI_MATCHMAKING_CREATELOBBY),
        (steam_networking(), STEAMAPI_NETWORKING_READP2PPACKET),
    ]
}

/// Port of `Protection::GetUsernamePtr`.
///
/// # Safety
///
/// Called by the game through the Steam vtable.
pub unsafe extern "system" fn get_username_ptr(_this: i64) -> *const c_char {
    drain_pending_name();
    custom_name_ptr()
}

/// Port of `Protection::GetUsernameXUIDPtr`.
///
/// # Safety
///
/// Called by the game through the Steam vtable. `this` is the Steam user object.
pub unsafe extern "system" fn get_username_xuid_ptr(this: i64, xuid: i64) -> *const c_char {
    drain_pending_name();
    // SAFETY: reads the local player's XUID from the game's player data.
    if xuid == unsafe { local_player_xuid() } {
        return custom_name_ptr();
    }
    // SAFETY: the original is the Steam entry for `GetUsernameXUID`.
    match unsafe {
        steam_original::<GetUsernameXuidFn>(steam_user(), STEAMAPI_STEAMUSER_VT_NAMEBYXUID)
    } {
        // SAFETY: forwards the same arguments to the original entry.
        Some(original) => unsafe { original(this, xuid) },
        None => c"".as_ptr(),
    }
}

/// Port of `Protection::IsVacBanned`. Always reports clean.
///
/// # Safety
///
/// Called by the game through the Steam vtable.
pub unsafe extern "system" fn is_vac_banned(_this: i64) -> bool {
    false
}

fn steam_user() -> usize {
    address(offsets::STEAMAPI_STEAMUSER)
}

fn steam_interface() -> usize {
    address(offsets::STEAMAPI_INTERFACE)
}

fn steam_matchmaking() -> usize {
    address(offsets::STEAMAPI_MATCHMAKING)
}

fn steam_networking() -> usize {
    address(offsets::STEAMAPI_NETWORKING)
}

/// Port of `Protection::ReadP2PPacket`. Drops info requests from non-friends
/// while friends-only is on, and drops join, cbuf, and voice-relay packets.
///
/// # Safety
///
/// Called by the game through the Steam vtable with its own buffers.
pub unsafe extern "system" fn read_p2p_packet(
    this: usize,
    pub_dest: *mut c_void,
    cub_dest: u32,
    cub_msg_size: *mut u32,
    steam_id_remote: *mut u64,
    n_channel: i32,
) -> bool {
    // SAFETY: the original entry has the same signature as this detour.
    let Some(original) = (unsafe {
        steam_original::<ReadP2PPacketFn>(steam_networking(), STEAMAPI_NETWORKING_READP2PPACKET)
    }) else {
        return false;
    };
    // SAFETY: forwards the game's arguments unchanged.
    let result = unsafe {
        original(
            this,
            pub_dest,
            cub_dest,
            cub_msg_size,
            steam_id_remote,
            n_channel,
        )
    };
    if !result || cub_msg_size.is_null() {
        return result;
    }
    // SAFETY: `cub_msg_size` is non-null (checked above) and holds the message size.
    let size = unsafe { *cub_msg_size };
    if size <= 5 {
        return result;
    }
    // SAFETY: the message is at least six bytes, so `pub_dest[5]` is in range.
    let game_im = unsafe { *(pub_dest as *const u8).add(5) };
    let friends_only = IS_FRIENDS_ONLY.load(Ordering::Relaxed);
    let drop = p2p_packet_is_dropped(game_im, friends_only, || {
        // SAFETY: `steam_id_remote` is the game's out-parameter, valid during the call.
        let remote = unsafe { steam_id_remote.read_unaligned() };
        // SAFETY: the friends interface is read only while Steam is loaded.
        unsafe { is_friend_by_xuid_uncached(remote.cast_signed()) }
    });
    !drop && result
}

/// Friends snapshot refresh. Calls into the Steam friends interface and returns
/// `None` when the interface is missing.
///
/// # Safety
///
/// The Steam friends global and its vtable must be readable.
unsafe fn read_friends_snapshot() -> Option<Vec<i64>> {
    // SAFETY: `STEAMAPI_FRIENDS` holds the `ISteamFriends` pointer.
    let friends = unsafe { read_usize(address(offsets::STEAMAPI_FRIENDS)) };
    if friends == 0 {
        return None;
    }
    // SAFETY: an interface object begins with its vtable pointer.
    let vtable = unsafe { read_usize(friends) };
    // SAFETY: the vtable slots are the friends-count and friends-by-index entries.
    let (count_fn, by_index_fn): (SteamFriendCountFn, SteamFriendByIndexFn) = unsafe {
        (
            fn_from_addr(read_usize(vtable + STEAM_FRIENDS_GET_COUNT_OFFSET)),
            fn_from_addr(read_usize(vtable + STEAM_FRIENDS_GET_BY_INDEX_OFFSET)),
        )
    };
    // SAFETY: both entries take the interface pointer as their first argument.
    let count = unsafe { count_fn(friends, STEAM_FRIEND_FLAG_IMMEDIATE) };
    let mut out = Vec::new();
    for index in 0..count {
        let mut friend: i64 = 0;
        // SAFETY: the out-parameter is a live `i64`.
        unsafe { by_index_fn(friends, &raw mut friend, index, STEAM_FRIEND_FLAG_IMMEDIATE) };
        if friend != 0 {
            out.push(friend);
        }
    }
    Some(out)
}

/// Port of `Protection::IsFriendByXUIDUncached`. The friends snapshot refreshes
/// at most every 30 seconds, and never while the UI level is not running.
///
/// # Safety
///
/// Reads the game's UI-level byte and the Steam friends interface.
pub unsafe fn is_friend_by_xuid_uncached(xuid: i64) -> bool {
    let now = tick_ms();
    // SAFETY: `OFF_s_runningUILevel` is a game byte global.
    let ui_running = unsafe { (address(offsets::OFF_S_RUNNING_UILEVEL) as *const u8).read() } != 0;
    {
        let cache = lock(&FRIENDS);
        if now < cache.next_update_ms || !ui_running {
            return cache.set.contains(&xuid);
        }
    }
    // SAFETY: the friends interface is mapped while Steam is loaded.
    let snapshot = unsafe { read_friends_snapshot() };
    let mut cache = lock(&FRIENDS);
    if let Some(friends) = snapshot {
        cache.set = friends.into_iter().collect();
        cache.next_update_ms = tick_ms() + FRIENDS_REFRESH_MS;
    }
    cache.set.contains(&xuid)
}

/// Port of `Protection::GetOwnsContent`.
///
/// # Safety
///
/// Called by the game through the Steam vtable.
pub unsafe extern "system" fn get_owns_content(interface: i64, item_id: i32) -> bool {
    let cached = lock(&INSTALLED_DLC).get(&item_id).copied();
    if let Some(value) = cached {
        return value;
    }
    // SAFETY: the original entry has the same signature as this detour.
    let steam_reports = match unsafe {
        steam_original::<OwnsContentFn>(steam_interface(), STEAMAPI_INTERFACE_CHECK_OWNS_CONTENT)
    } {
        // SAFETY: forwards the game's arguments.
        Some(original) => unsafe { original(interface, item_id) },
        None => false,
    };
    let value = steam_reports && is_mode_content_file_present(item_id);
    lock(&INSTALLED_DLC).insert(item_id, value);
    value
}

/// Port of `Protection::GetOwnsContent2`.
///
/// # Safety
///
/// Called by the game through the Steam vtable.
pub unsafe extern "system" fn get_owns_content2(interface: i64, item_id: i32) -> bool {
    let cached = lock(&SUBSCRIBED_APP).get(&item_id).copied();
    if let Some(value) = cached {
        return value;
    }
    // SAFETY: the original entry has the same signature as this detour.
    let value = match unsafe {
        steam_original::<OwnsContentFn>(steam_interface(), STEAMAPI_INTERFACE_CHECK_OWNS_CONTENT2)
    } {
        // SAFETY: forwards the game's arguments.
        Some(original) => unsafe { original(interface, item_id) },
        None => false,
    };
    lock(&SUBSCRIBED_APP).insert(item_id, value);
    value
}

/// Whether the content `.xpak` for `app_id` exists beside the executable. Apps
/// with no content file always count as present.
fn is_mode_content_file_present(app_id: i32) -> bool {
    let Some(content_file) = content_file_for_app(app_id) else {
        return true;
    };
    let mut buffer = [0u16; MAX_PATH];
    // SAFETY: the buffer is `MAX_PATH` UTF-16 units. A null module asks for the executable.
    let length = unsafe { GetModuleFileNameW(None, &mut buffer) } as usize;
    if length == 0 || length >= MAX_PATH {
        return false;
    }
    let exe = PathBuf::from(OsString::from_wide(&buffer[..length]));
    exe.parent()
        .is_some_and(|dir| dir.join("zone").join(content_file).is_file())
}

/// Port of `Protection::GetDlcDownloadProgress`. Caches each DLC's progress for five minutes.
///
/// # Safety
///
/// `c` and `d` must be writable `i64` out-parameters.
pub unsafe extern "system" fn get_dlc_download_progress(a: i64, b: i32, c: *mut i64, d: *mut i64) {
    let now = tick_ms();
    let cached = {
        let mut map = lock(&DLC_PROGRESS);
        match map.get_mut(&b) {
            Some(entry) if now < entry.next_ms => Some((entry.a, entry.b)),
            Some(entry) => {
                entry.next_ms = tick_ms() + DLC_PROGRESS_TTL_MS;
                None
            }
            None => {
                map.insert(
                    b,
                    DownloadProgress {
                        a: 0,
                        b: 0,
                        next_ms: now + DLC_PROGRESS_TTL_MS,
                    },
                );
                None
            }
        }
    };
    if let Some((cached_a, cached_b)) = cached {
        // SAFETY: the caller's out-parameters are writable.
        unsafe {
            *c = cached_a;
            *d = cached_b;
        }
        return;
    }
    // SAFETY: the original entry has the same signature as this detour.
    if let Some(original) = unsafe {
        steam_original::<DlcProgressFn>(
            steam_interface(),
            STEAMAPI_INTERFACE_GET_DLC_DOWNLOAD_PROGRESS,
        )
    } {
        // SAFETY: forwards the game's arguments.
        unsafe { original(a, b, c, d) };
    }
    // SAFETY: the out-parameters were written by the original (or are the caller's).
    let (new_a, new_b) = unsafe { (*c, *d) };
    let mut map = lock(&DLC_PROGRESS);
    let entry = map.entry(b).or_default();
    entry.a = new_a;
    entry.b = new_b;
}

/// Port of `Protection::GetLobbyChatEntry`. Accepts chat only from a member of
/// the current lobby, and sanitizes the text.
///
/// # Safety
///
/// Called by the game through the Steam vtable with its own pointers.
pub unsafe extern "system" fn get_lobby_chat_entry(
    api: i64,
    csteamid_lobby: i64,
    chat_id: i64,
    psteamuserid: i64,
    pvdata: i64,
    cubdata: i64,
    chatentrytype: i64,
) -> i32 {
    // SAFETY: the original entry has the same signature as this detour.
    let Some(original) = (unsafe {
        steam_original::<LobbyChatEntryFn>(
            steam_matchmaking(),
            STEAMAPI_MATCHMAKING_GETLOBBYCHATENTRY,
        )
    }) else {
        return 0;
    };
    // SAFETY: forwards the game's arguments; pumps the chat queue as the original does.
    let result = unsafe {
        original(
            api,
            csteamid_lobby,
            chat_id,
            psteamuserid,
            pvdata,
            cubdata,
            chatentrytype,
        )
    };
    if psteamuserid == 0 {
        return 0;
    }
    // SAFETY: `psteamuserid` is the game's non-null out-parameter holding a SteamID.
    let steam_id = unsafe { read_i64(addr(psteamuserid)) };
    let Some(g) = game() else {
        return 0;
    };
    // SAFETY: lobby-session getters take plain integers and return game-owned pointers.
    let session = unsafe {
        let controlling = (g.lobby_session_get_controlling_lobby_session)(LOBBY_MODULE_CLIENT);
        let session_type = if controlling {
            LOBBY_TYPE_GAME
        } else {
            LOBBY_TYPE_PRIVATE
        };
        (g.lobby_session_get_session)(session_type)
    };

    let mut found = false;
    for index in 0..18 {
        // SAFETY: the session pointer is the game's and the client number is in range.
        let client = unsafe { (g.lobby_session_get_client_by_client_num)(session, index) };
        if client.is_null() {
            continue;
        }
        // SAFETY: `client` is non-null and points at a `SessionClient`.
        let active = unsafe { (*client).active_client };
        // SAFETY: `active` is non-null and points at an `ActiveClient`.
        if !active.is_null() && unsafe { (*active).fixed_client_info.xuid } == steam_id {
            found = true;
        }
    }
    if !found {
        return 0;
    }

    // `cubdata` is an `int` passed in a 64-bit slot; only its low 32 bits count.
    let cub = u32::try_from(cubdata & 0xFFFF_FFFF)
        .unwrap_or(0)
        .cast_signed();
    if result > 0 && cub > 0 && pvdata != 0 {
        // A null entry type means text, as in the fork.
        // SAFETY: a non-null `chatentrytype` points at the game's `i32` out-parameter.
        let is_text = chatentrytype == 0 || unsafe { i32_at(ptr_from_i64(chatentrytype)) } != 0;
        if is_text {
            // A peer's message need not be NUL-terminated: bound it by the bytes Steam copied.
            let cap = usize::try_from(result.min(cub)).unwrap_or(0);
            // SAFETY: Steam wrote `result` bytes into the `cubdata`-byte buffer at `pvdata`.
            let message = unsafe { std::slice::from_raw_parts_mut(addr(pvdata) as *mut u8, cap) };
            sanitize_chat(message);
        }
    }
    result
}

/// Port of `Protection::CreateLobby`. Always creates a public lobby of type 1.
///
/// # Safety
///
/// Called by the game through the Steam vtable.
pub unsafe extern "system" fn create_lobby(
    api: i64,
    _lobby_create_type: i32,
    maxplayers: i32,
) -> i64 {
    // SAFETY: the original entry has the same signature as this detour.
    let Some(original) = (unsafe {
        steam_original::<CreateLobbyFn>(steam_matchmaking(), STEAMAPI_MATCHMAKING_CREATELOBBY)
    }) else {
        return 0;
    };
    // SAFETY: forwards the arguments with the lobby type forced to 1.
    unsafe { original(api, 1, i64::from(maxplayers)) }
}

/// Port of `Protection::CL_SwitchState_Idle_Update`. Only runs the original
/// idle update while the session mode is "CP".
///
/// # Safety
///
/// Called by the game through its update-preload function pointer.
pub unsafe extern "system" fn cl_switch_state_idle_update(sw: i64) -> i32 {
    // SAFETY: the game function takes no arguments and returns a C string.
    let mode_name = unsafe {
        let get_mode_name: ComSessionModeGetModeNameFn =
            fn_from_addr(address(offsets::COM_SESSION_MODE_GET_MODE_NAME));
        get_mode_name()
    };
    // SAFETY: the game returns a NUL-terminated mode name or null.
    let is_cp = !mode_name.is_null() && unsafe { CStr::from_ptr(mode_name) }.to_bytes() == b"CP";
    if !is_cp {
        return 0;
    }
    // SAFETY: the original idle update takes the switch pointer and returns an int.
    unsafe {
        let original: ClSwitchStateIdleUpdateFn =
            fn_from_addr(address(offsets::CL_SWITCH_STATE_IDLE_UPDATE));
        original(sw)
    }
}

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

/// Port of `SetFriendsOnly`.
pub fn set_friends_only(friends_only: bool) {
    IS_FRIENDS_ONLY.store(friends_only, Ordering::Relaxed);
}

/// Port of `SetAutoInstallMods`.
pub fn set_auto_install_mods(enabled: bool) {
    IS_AUTO_INSTALL_MODS_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Stores `name` as the local custom name without touching the game's buffers.
/// Returns the stored fields, or `None` when the name is longer than 15 bytes.
pub fn set_custom_name(name: &[u8]) -> Option<NameBytes> {
    let fields = player_name_fields(name)?;
    let snapshot = Box::new(fields);
    let pointer = Box::into_raw(snapshot);
    // Serialize publishers so an older pointer is transferred to the retention list
    // exactly once.
    let mut retained = lock(&NAME_RETAINED);
    let previous = NAME_CURRENT.swap(pointer.cast::<u8>(), Ordering::AcqRel);
    if !previous.is_null() {
        // SAFETY: every non-null value in `NAME_CURRENT` was created by `Box::into_raw`
        // in this function and has not been freed.
        retained.push(unsafe { Box::from_raw(previous.cast::<NameBytes>()) });
    }
    Some(fields)
}

/// Port of `SetPlayerName`. Publishes the name and queues the copy into the game's
/// name buffers, which happens on the next game-thread username lookup. Names longer
/// than 15 bytes are ignored.
///
/// # Safety
///
/// The game's name buffers and player data must be mapped (the game is running).
pub unsafe fn set_player_name(name: &[u8]) {
    let Some(_fields) = set_custom_name(name) else {
        return;
    };
    // The caller may be the config worker. Publish the snapshot now and let the next
    // game-thread name lookup copy it into the game's buffers.
    NAME_PENDING.store(true, Ordering::Release);
}

/// Copies a pending name snapshot into the game buffers. Runs on a game thread from
/// the username hooks, where the game itself is reading the player name.
fn drain_pending_name() {
    if !NAME_PENDING.swap(false, Ordering::AcqRel) {
        return;
    }
    let fields = custom_name_snapshot();
    // SAFETY: the username hooks run inside the game process, whose name buffers are mapped.
    unsafe {
        copy_bytes((address(offsets::P_USER_DATA) + 8) as *mut u8, &fields);
        copy_bytes(address(offsets::P_NAME_BUFFER) as *mut u8, &fields);
    }
}

/// Port of the exported `SetNetworkPassword(const char*)`. Hashes the password
/// and installs it, or clears it when empty.
pub fn set_network_password_text(password: &[u8]) {
    set_network_password(network_password_key(password));
}

/// Port of `Protection::SetNetworkPassword(__int64)`. Rotates the password history.
pub fn set_network_password(password: i64) {
    let mut state = lock(&PRIVATE_PASSWORD);
    rotate_private_password(&mut state, password, tick_ms());
}

/// Settings loaded from and saved to `t7patch.conf`. Field names and defaults
/// match `patch_config` in Protection.cpp.
#[derive(Clone)]
struct PatchConfig {
    playername: [u8; PLAYER_NAME_LEN],
    isfriendsonly: i32,
    autoinstallmods: i32,
    networkpassword: Vec<u8>,
    exists: bool,
    modified: Option<SystemTime>,
}

impl PatchConfig {
    const DEFAULT: Self = Self {
        playername: *b"Unknown Soldier\0",
        isfriendsonly: 1,
        autoinstallmods: 0,
        networkpassword: Vec::new(),
        exists: false,
        modified: None,
    };

    fn playername_bytes(&self) -> &[u8] {
        c_prefix(&self.playername)
    }

    /// Port of `patch_config::saveto`. Writes CRLF line endings, as the original's text-mode stream does.
    fn saveto(&mut self, path: &Path) {
        if fs::write(path, self.serialize()).is_err() {
            return;
        }
        if let Ok(Some(time)) = observe_config(path) {
            self.exists = true;
            self.modified = Some(time);
        }
    }

    /// Port of `patch_config::loadfrom`, without side effects: reads the whole
    /// file, applies it over a copy of these settings, and returns the copy with
    /// the modification time it was read at. The caller commits the result.
    fn loadfrom(&self, path: &Path) -> Result<Self, ConfigError> {
        let before = observe_config(path)?.ok_or(ConfigError::Missing)?;
        let contents = fs::read(path).map_err(|error| ConfigError::from_io(&error))?;
        // A writer that changed the file during the read may have left it torn.
        if observe_config(path)? != Some(before) {
            return Err(ConfigError::ChangedDuringRead);
        }
        let mut candidate = self.clone();
        candidate.apply_text(&contents);
        candidate.exists = true;
        candidate.modified = Some(before);
        Ok(candidate)
    }

    /// One watcher poll. `observed` is the file's state now, and `read` loads it.
    /// Returns `true` when the settings changed and must be applied. The settings
    /// and the timestamp change together, and only after a successful read. A
    /// deleted file resets to the defaults. Any other error keeps both, so the
    /// next poll retries.
    fn refresh(
        &mut self,
        observed: Result<Option<SystemTime>, ConfigError>,
        read: impl FnOnce(&Self) -> Result<Self, ConfigError>,
    ) -> bool {
        match observed {
            Err(_) => false,
            Ok(None) => {
                if !self.exists {
                    return false;
                }
                *self = Self::DEFAULT;
                true
            }
            Ok(Some(time)) => {
                if self.exists && self.modified == Some(time) {
                    return false;
                }
                match read(self) {
                    Ok(candidate) => {
                        *self = candidate;
                        true
                    }
                    Err(ConfigError::Missing) if self.exists => {
                        *self = Self::DEFAULT;
                        true
                    }
                    Err(_) => false,
                }
            }
        }
    }

    fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"playername=");
        out.extend_from_slice(self.playername_bytes());
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(format!("isfriendsonly={}\r\n", self.isfriendsonly).as_bytes());
        out.extend_from_slice(format!("autoinstallmods={}\r\n", self.autoinstallmods).as_bytes());
        out.extend_from_slice(b"networkpassword=");
        out.extend_from_slice(&self.networkpassword);
        out.extend_from_slice(b"\r\n");
        out
    }

    /// Applies every `key=value` line in `text`, as `loadfrom` does with the file's lines.
    fn apply_text(&mut self, text: &[u8]) {
        for line in text.split(|&byte| byte == b'\n') {
            self.apply_line(line);
        }
    }

    fn apply_line(&mut self, line: &[u8]) {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(separator) = line.iter().position(|&byte| byte == b'=') else {
            return;
        };
        let token = c_prefix(&line[..separator]);
        let value = &line[separator + 1..];
        let key = fnv1a(token);

        if key == fnv1a(b"playername") {
            if value.is_empty() {
                return;
            }
            let trimmed = &value[..value.len().min(MAX_PLAYER_NAME)];
            self.playername = [0; PLAYER_NAME_LEN];
            let text = c_prefix(trimmed);
            self.playername[..text.len()].copy_from_slice(text);
        } else if key == fnv1a(b"isfriendsonly") {
            self.isfriendsonly = if value.is_empty() {
                0
            } else {
                parse_leading_int(value).unwrap_or(0)
            };
        } else if key == fnv1a(b"autoinstallmods") {
            self.autoinstallmods = if value.is_empty() {
                0
            } else {
                match parse_leading_int(value) {
                    Some(parsed) => i32::from(parsed == 1),
                    None => 0,
                }
            };
        } else if key == fnv1a(b"networkpassword") {
            let trimmed = &value[..value.len().min(MAX_SETTINGS_VALUE)];
            self.networkpassword = c_prefix(trimmed).to_vec();
        }
    }

    fn snapshot(&self) -> Self {
        self.clone()
    }
}

/// Port of `fs_exists`.
fn fs_exists(path: &Path) -> bool {
    path.exists()
}

/// Why the settings file could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConfigError {
    Missing,
    Access,
    ChangedDuringRead,
}

impl ConfigError {
    fn from_io(error: &std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::NotFound {
            Self::Missing
        } else {
            Self::Access
        }
    }
}

/// The settings file's modification time, `None` when it does not exist, or an
/// error when it exists but cannot be inspected.
fn observe_config(path: &Path) -> Result<Option<SystemTime>, ConfigError> {
    match fs::metadata(path) {
        Ok(meta) => meta.modified().map(Some).map_err(|_| ConfigError::Access),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(ConfigError::Access),
    }
}

/// Applies the settings to the running game.
///
/// # Safety
///
/// The game must be running; this writes its name buffers.
unsafe fn apply_settings(cfg: &PatchConfig) {
    // SAFETY: the game is running, so its name buffers are mapped.
    unsafe { set_player_name(cfg.playername_bytes()) };
    set_friends_only(cfg.isfriendsonly != 0);
    set_auto_install_mods(cfg.autoinstallmods != 0);
    set_network_password_text(&cfg.networkpassword);
}

/// Port of `load_settings_initial`.
///
/// # Safety
///
/// The game must be running.
unsafe fn load_settings_initial() {
    let path = Path::new(PATCH_CONFIG_LOCATION);
    let snapshot = {
        let mut cfg = lock(&USER_CONFIG);
        if fs_exists(path) {
            if let Ok(candidate) = cfg.loadfrom(path) {
                *cfg = candidate;
            }
        } else {
            cfg.saveto(path);
        }
        cfg.snapshot()
    };
    // SAFETY: the game is running.
    unsafe { apply_settings(&snapshot) };
}

/// Port of `MainThread`. Polls the settings file once a second and reapplies it on change,
/// until the stop event passed as `param` is signalled.
///
/// # Safety
///
/// Started by [`ManagedWorker::start`] with its stop event as `param`, which stays open
/// until this thread has exited.
unsafe extern "system" fn main_thread(param: *mut c_void) -> u32 {
    let stop = HANDLE(param);
    let mut seed = unix_time_seed();
    let value = msvc_rand(&mut seed);
    // SAFETY: the random-seed global is an int-sized game variable.
    unsafe { write_i32(address(offsets::RANDOM_SEED_GLOBAL), value) };
    let path = Path::new(PATCH_CONFIG_LOCATION);
    // SAFETY: `stop` is the worker's open event handle.
    while unsafe { WaitForSingleObject(stop, 1000) } == WAIT_TIMEOUT {
        // A panic must neither end the worker, which would make it unstoppable by event,
        // nor unwind into the OS thread start routine.
        let refreshed = std::panic::catch_unwind(AssertUnwindSafe(|| {
            arxan_bypass_maintain();
            let changed = {
                let mut cfg = lock(&USER_CONFIG);
                let observed = observe_config(path);
                cfg.refresh(observed, |current| current.loadfrom(path))
                    .then(|| cfg.snapshot())
            };
            if let Some(cfg) = changed {
                // SAFETY: the game is running.
                unsafe { apply_settings(&cfg) };
            }
        }));
        if refreshed.is_err() {
            crate::dllmain::debug_print(
                "T7 Patch: config refresh failed; worker remains stoppable.\n",
            );
        }
    }
    0
}

/// Port of the fork's `ManagedWorker`: a thread with a manual-reset stop event. The handles
/// are kept as integers so the worker can live in a `static Mutex`.
struct ManagedWorker {
    stop: usize,
    thread: usize,
}

impl ManagedWorker {
    const fn new() -> Self {
        Self { stop: 0, thread: 0 }
    }

    const fn running(&self) -> bool {
        self.thread != 0
    }

    /// Starts `entry` with the stop event as its parameter. Does nothing if already running.
    fn start(
        &mut self,
        entry: unsafe extern "system" fn(*mut c_void) -> u32,
    ) -> Result<(), String> {
        if self.running() {
            return Ok(());
        }
        // SAFETY: creates an unnamed manual-reset event, initially unsignalled.
        let stop = unsafe { CreateEventW(None, true, false, PCWSTR::null()) }
            .map_err(|_| "T7 Patch: cannot create worker stop event".to_owned())?;
        // SAFETY: `entry` takes the stop event, which stays open until the thread is joined.
        let thread = unsafe {
            CreateThread(
                None,
                0,
                Some(entry),
                Some(stop.0.cast_const()),
                THREAD_CREATION_FLAGS(0),
                None,
            )
        };
        let Ok(thread) = thread else {
            // SAFETY: `stop` was created above and no thread uses it.
            let _ = unsafe { CloseHandle(stop) };
            return Err("T7 Patch: cannot create config worker".to_owned());
        };
        self.stop = stop.0 as usize;
        self.thread = thread.0 as usize;
        Ok(())
    }

    /// Signals the stop event and waits for the thread to exit. Refuses to join itself.
    fn stop(&mut self) -> Result<(), String> {
        if !self.running() {
            return Ok(());
        }
        let thread = HANDLE(self.thread as *mut c_void);
        let stop = HANDLE(self.stop as *mut c_void);
        // SAFETY: `thread` is the worker's open handle; the id queries have no preconditions.
        if unsafe { GetThreadId(thread) == GetCurrentThreadId() } {
            return Err("T7 Patch: config worker cannot join itself".to_owned());
        }
        // SAFETY: both handles are open until closed below.
        let joined = unsafe {
            SetEvent(stop).is_ok() && WaitForSingleObject(thread, INFINITE) == WAIT_OBJECT_0
        };
        if !joined {
            return Err("T7 Patch: cannot join config worker".to_owned());
        }
        // SAFETY: the thread has exited, so neither handle is used again.
        unsafe {
            let _ = CloseHandle(thread);
            let _ = CloseHandle(stop);
        }
        self.thread = 0;
        self.stop = 0;
        Ok(())
    }
}

static CONFIG_WORKER: Mutex<ManagedWorker> = Mutex::new(ManagedWorker::new());

/// Port of `Protection::start_worker`. Starts the settings watcher on the injectorless path,
/// unless it is already running.
pub fn start_worker() -> Result<(), String> {
    let mut worker = lock(&CONFIG_WORKER);
    if IS_INJECTORLESS_INSTALL.load(Ordering::Relaxed) && !worker.running() {
        // SAFETY: the game is running; this is called by the patch lifecycle.
        unsafe { load_settings_initial() };
        worker.start(main_thread)?;
    }
    Ok(())
}

/// Port of `Protection::stop_worker`. Stops and joins the settings watcher if it runs.
pub fn stop_worker() -> Result<(), String> {
    lock(&CONFIG_WORKER).stop()
}

/// Re-applies the Arxan bypass if the game restored it. Called once per second by the main thread.
pub fn arxan_bypass_maintain() {
    crate::arxan::maintain();
}

// ---------------------------------------------------------------------------
// Lobby packet inspection
// ---------------------------------------------------------------------------

/// Typed wrappers over the game's lobby-message serializers. Each takes the raw
/// destination pointer and returns the game's `BOOL` as a `bool`.
mod rw {
    use super::Game;
    use std::ffi::{CStr, c_void};

    /// # Safety
    ///
    /// `lm` must be a live lobby message and `value` a writable `i32`.
    pub unsafe fn int(g: &Game, lm: *mut c_void, key: &CStr, value: *mut u8) -> bool {
        // SAFETY: the caller guarantees both pointers.
        unsafe { (g.lobby_msg_rw_package_int)(lm, key.as_ptr(), value.cast()) }
    }

    /// # Safety
    ///
    /// As [`int`], with `value` a writable `c_char`.
    pub unsafe fn uchar(g: &Game, lm: *mut c_void, key: &CStr, value: *mut u8) -> bool {
        // SAFETY: the caller guarantees both pointers.
        unsafe { (g.lobby_msg_rw_package_uchar)(lm, key.as_ptr(), value.cast()) }
    }

    /// # Safety
    ///
    /// As [`int`], with `value` a writable buffer of `max` bytes.
    pub unsafe fn string(g: &Game, lm: *mut c_void, key: &CStr, value: *mut u8, max: i32) -> bool {
        // SAFETY: the caller guarantees both pointers and the buffer length.
        unsafe { (g.lobby_msg_rw_package_string)(lm, key.as_ptr(), value.cast(), max) }
    }

    /// # Safety
    ///
    /// As [`int`], with `value` a writable `u64`.
    pub unsafe fn xuid(g: &Game, lm: *mut c_void, key: &CStr, value: *mut u8) -> bool {
        // SAFETY: the caller guarantees both pointers.
        unsafe { (g.lobby_msg_rw_package_xuid)(lm, key.as_ptr(), value.cast()) }
    }

    /// # Safety
    ///
    /// As [`int`], with `value` a writable `c_char`.
    pub unsafe fn bool_(g: &Game, lm: *mut c_void, key: &CStr, value: *mut u8) -> bool {
        // SAFETY: the caller guarantees both pointers.
        unsafe { (g.lobby_msg_rw_package_bool)(lm, key.as_ptr(), value.cast()) }
    }

    /// # Safety
    ///
    /// As [`int`], with `value` a writable `u32`.
    pub unsafe fn uint(g: &Game, lm: *mut c_void, key: &CStr, value: *mut u8) -> bool {
        // SAFETY: the caller guarantees both pointers.
        unsafe { (g.lobby_msg_rw_package_uint)(lm, key.as_ptr(), value.cast()) }
    }

    /// # Safety
    ///
    /// As [`int`], with `value` a writable `i16`.
    pub unsafe fn short(g: &Game, lm: *mut c_void, key: &CStr, value: *mut u8) -> bool {
        // SAFETY: the caller guarantees both pointers.
        unsafe { (g.lobby_msg_rw_package_short)(lm, key.as_ptr(), value.cast()) }
    }

    /// # Safety
    ///
    /// As [`int`], with `value` a writable `u64`.
    pub unsafe fn uint64(g: &Game, lm: *mut c_void, key: &CStr, value: *mut u8) -> bool {
        // SAFETY: the caller guarantees both pointers.
        unsafe { (g.lobby_msg_rw_package_uint64)(lm, key.as_ptr(), value.cast()) }
    }

    /// # Safety
    ///
    /// As [`int`], with `value` a writable `f32`.
    pub unsafe fn float(g: &Game, lm: *mut c_void, key: &CStr, value: *mut u8) -> bool {
        // SAFETY: the caller guarantees both pointers.
        unsafe { (g.lobby_msg_rw_package_float)(lm, key.as_ptr(), value.cast()) }
    }

    /// # Safety
    ///
    /// `lm` must be a live lobby message.
    pub unsafe fn array_start(g: &Game, lm: *mut c_void, key: &CStr) -> bool {
        // SAFETY: the caller guarantees the message pointer.
        unsafe { (g.lobby_msg_rw_package_array_start)(lm, key.as_ptr()) }
    }

    /// # Safety
    ///
    /// `lm` must be a live lobby message.
    pub unsafe fn element(g: &Game, lm: *mut c_void, add: bool) -> bool {
        // SAFETY: the caller guarantees the message pointer.
        unsafe { (g.lobby_msg_rw_package_element)(lm, i32::from(add)) }
    }

    /// # Safety
    ///
    /// As [`int`], with `value` a writable buffer of `max` bytes.
    pub unsafe fn glob(g: &Game, lm: *mut c_void, key: &CStr, value: *mut u8, max: i32) -> bool {
        // SAFETY: the caller guarantees both pointers and the buffer length.
        unsafe { (g.lobby_msg_rw_package_glob)(lm, key.as_ptr(), value.cast(), max) }
    }
}

/// Port of `MSG_JoinParty_Package_Inspect`. Returns 0 for a well-formed join
/// request and a nonzero code for each rejection.
///
/// # Safety
///
/// `this` must address a [`REQUEST_OUT_LEN`]-byte scratch buffer and
/// `lobby_msg` a live copy of the lobby message.
#[allow(clippy::too_many_lines)]
pub unsafe fn msg_join_party_package_inspect(this: *mut u8, lobby_msg: *mut c_void) -> i32 {
    let Some(g) = game() else {
        return NOT_INSTALLED;
    };
    let lm = lobby_msg;
    // SAFETY: every write lands below 0x7000 bytes of the 0x20000-byte scratch buffer.
    unsafe {
        let mut ok = rw::int(g, lm, c"targetlobby", this)
            && rw::int(g, lm, c"sourcelobby", at_bytes(this, 4))
            && rw::int(g, lm, c"jointype", at_bytes(this, 8))
            && rw::xuid(g, lm, c"probedxuid", at_bytes(this, 16))
            && rw::int(g, lm, c"playlistid", at_bytes(this, 612))
            && rw::int(g, lm, c"playlistver", at_bytes(this, 616))
            && rw::int(g, lm, c"ffotdver", at_bytes(this, 620))
            && rw::short(g, lm, c"networkmode", at_bytes(this, 624))
            && rw::uint(g, lm, c"netchecksum", at_bytes(this, 628))
            && rw::int(g, lm, c"protocol", at_bytes(this, 632))
            && rw::int(g, lm, c"changelist", at_bytes(this, 636))
            && rw::int(g, lm, c"pingband", at_bytes(this, 640))
            && rw::uint(g, lm, c"dlcbits", at_bytes(this, 644))
            && rw::uint64(g, lm, c"joinnonce", at_bytes(this, 648));
        for i in 0..3 {
            ok = ok && rw::uchar(g, lm, c"chunk", at_bytes(this, 689 + i));
        }
        ok = ok
            && rw::bool_(g, lm, c"isStarterPack", at_bytes(this, 656))
            && rw::string(g, lm, c"password", at_bytes(this, 657), 0x20)
            && rw::int(g, lm, c"membercount", at_bytes(this, 24))
            && rw::array_start(g, lm, c"members");
        if !ok {
            return 1;
        }
        let count = i32_at(at_bytes(this, 24));
        if !count_in_range(count, MAX_LOBBY_CLIENTS) {
            return 2;
        }
        if rw::element(g, lm, count > 0) {
            if count <= 0 {
                return 3;
            }
            for i in 0..count {
                ok = ok
                    && rw::xuid(g, lm, c"xuid", at_bytes(this, 616))
                    && rw::uint64(g, lm, c"lobbyid", at_bytes(this, 616))
                    && rw::float(g, lm, c"skillrating", at_bytes(this, 616))
                    && rw::float(g, lm, c"skillvariance", at_bytes(this, 616))
                    && rw::uint(g, lm, c"pprobation", at_bytes(this, 616))
                    && rw::uint(g, lm, c"aprobation", at_bytes(this, 616));
                if !ok {
                    return 4;
                }
                let expected = i + 1 < count;
                let result = rw::element(g, lm, expected);
                if result && !expected {
                    return 5;
                }
            }
        }
    }
    0
}

/// Port of `MSG_LobbyState_Package_Inspect`. Returns 0 for a valid packet.
///
/// # Safety
///
/// As [`msg_join_party_package_inspect`], with `this` read and written as `__int32*`.
#[allow(clippy::too_many_lines)]
pub unsafe fn msg_lobby_state_package_inspect(this: *mut u8, lobby_msg: *mut c_void) -> i32 {
    let Some(g) = game() else {
        return NOT_INSTALLED;
    };
    let lm = lobby_msg;
    let w = |words: usize| at_words(this, words);
    // SAFETY: every write lands below 0x7000 words of the scratch buffer.
    unsafe {
        let mut ok = rw::int(g, lm, c"statenum", w(0))
            && rw::int(g, lm, c"networkmode", w(1))
            && rw::int(g, lm, c"mainmode", w(2))
            && rw::int(g, lm, c"partyprivacy", w(3))
            && rw::int(g, lm, c"lobbytype", w(4))
            && rw::int(g, lm, c"lobbymode", w(5))
            && rw::int(g, lm, c"sessionstatus", w(6))
            && rw::int(g, lm, c"uiscreen", w(7))
            && rw::uchar(g, lm, c"leaderactivity", at_bytes(this, 32))
            && rw::string(g, lm, c"key", w(9), 0x20)
            && rw::xuid(g, lm, c"leader", w(9))
            && rw::xuid(g, lm, c"platformsession", w(10))
            && rw::int(g, lm, c"maxclients", w(22))
            && rw::bool_(g, lm, c"isadvertised", at_bytes(this, 92))
            && rw::int(g, lm, c"clientcount", w(24))
            && rw::string(g, lm, c"sessionid", w(5320), 0x40)
            && rw::string(g, lm, c"sessioninfo", w(5336), 0x40)
            && rw::string(g, lm, c"ugcName", w(5352), 0x20)
            && rw::uint(g, lm, c"ugcVersion", w(5360));
        if !ok {
            return 1;
        }
        rw::array_start(g, lm, c"clientlist");
        let Some(count) = checked_count(i32_at(w(24)), MAX_LOBBY_CLIENTS) else {
            return 2;
        };
        let mut index = 0usize;
        let mut has_next = rw::element(g, lm, index < count);
        while has_next && index < count {
            let base = w(26 + 292 * index);
            ok = ok
                && rw::xuid(g, lm, c"xuid", at_bytes(base, 0))
                && rw::uchar(g, lm, c"clientNum", at_bytes(base, 8))
                && rw::string(g, lm, c"gamertag", at_bytes(base, 9), 0x20)
                && rw::bool_(g, lm, c"isGuest", at_bytes(base, 41))
                && rw::uint64(g, lm, c"lobbyid", at_bytes(base, 48))
                && rw::int(g, lm, c"connectbit", at_bytes(base, 1108))
                && rw::int(g, lm, c"score", at_bytes(base, 1104))
                && rw::glob(g, lm, c"address", at_bytes(base, 1113), 37)
                && rw::int(g, lm, c"qport", at_bytes(base, 56))
                && rw::uchar(g, lm, c"band", at_bytes(base, 60))
                && rw::uint(g, lm, c"netsrc", at_bytes(base, 1152))
                && rw::uint(g, lm, c"joinorder", at_bytes(base, 1156))
                && rw::uint(g, lm, c"dlcBits", at_bytes(base, 1160))
                && (g.msg_mutable_client_info_package)(at_bytes(base, 64).cast(), lm) != 0;
            if !ok {
                return 101;
            }
            index += 1;
            has_next = rw::element(g, lm, index < count);
        }
        if has_next {
            return 102;
        }
        ok = ok
            && rw::uchar(g, lm, c"migratebits", at_bytes(this, 21128))
            && rw::int(g, lm, c"lasthosttimems", w(5283));
        if !ok {
            return 3;
        }
        rw::array_start(g, lm, c"nomineelist");
        let mut nominees = 0usize;
        has_next = rw::element(g, lm, nominees < MAX_LOBBY_CLIENTS);
        while has_next && nominees < MAX_LOBBY_CLIENTS {
            ok = ok && rw::xuid(g, lm, c"xuid", w(0x14A4 + 2 * nominees));
            nominees += 1;
            has_next = rw::element(g, lm, nominees < MAX_LOBBY_CLIENTS);
        }
        if has_next {
            return 103;
        }
        if !ok {
            return 4;
        }
    }
    0
}

/// Port of `MSG_LobbyStateGame_Package_Inspect`. Extends the lobby-state check
/// with the game-mode-specific sections. Returns 0 for a valid packet.
///
/// # Safety
///
/// As [`msg_lobby_state_package_inspect`].
#[allow(clippy::too_many_lines)]
pub unsafe fn msg_lobby_state_game_package_inspect(this: *mut u8, lobby_msg: *mut c_void) -> i32 {
    // SAFETY: forwarded with the same contract.
    let base_result = unsafe { msg_lobby_state_package_inspect(this, lobby_msg) };
    if base_result != 0 {
        return base_result;
    }
    let Some(g) = game() else {
        return NOT_INSTALLED;
    };
    let lm = lobby_msg;
    let w = |words: usize| at_words(this, words);
    // SAFETY: every write lands inside the scratch buffer.
    unsafe {
        let mut ok = rw::int(g, lm, c"serverstatus", w(5362));
        if !ok {
            return 11;
        }
        ok = ok
            && rw::int(g, lm, c"launchnonce", w(5363))
            && rw::uint64(g, lm, c"matchhashlow", w(2682))
            && rw::uint64(g, lm, c"matchhashhigh", w(2683))
            && rw::int(g, lm, c"status", w(5394))
            && rw::int(g, lm, c"statusvalue", w(5395))
            && rw::int(g, lm, c"gamemode", w(5368))
            && rw::string(g, lm, c"gametype", w(5369), 0x20)
            && rw::string(g, lm, c"map", w(5377), 0x20)
            && rw::string(g, lm, c"ugcName", w(5385), 0x20)
            && rw::uint(g, lm, c"ugcVersion", w(5393));

        if i32_at(w(2)) == 0 {
            ok = ok
                && rw::string(g, lm, c"cpqueuedlevel", w(7293), 0x20)
                && rw::bool_(g, lm, c"movieskipped", at_bytes(this, 29204));
        }

        let lobby_mode = i32_at(w(5));
        if lobby_mode == 0 {
            rw::array_start(g, lm, c"clientlist");
            let mut index = 0usize;
            let mut has_next = rw::element(g, lm, index < MAX_LOBBY_CLIENTS);
            while has_next && index < MAX_LOBBY_CLIENTS {
                let client = w(9 * index);
                ok = ok
                    && rw::int(g, lm, c"team", at_bytes(client, 28524))
                    && rw::int(g, lm, c"mapvote", at_bytes(client, 28528))
                    && rw::bool_(g, lm, c"readyup", at_bytes(client, 28532));
                if !ok {
                    return 21;
                }
                index += 1;
                has_next = rw::element(g, lm, index < MAX_LOBBY_CLIENTS);
            }
            if has_next {
                return 22;
            }
            ok = ok
                && rw::int(g, lm, c"plistid", w(7126))
                && rw::int(g, lm, c"plistcurr", w(7127))
                && rw::glob(g, lm, c"plistentries", at_bytes(this, 28512), 8)
                && rw::uchar(g, lm, c"plistnext", at_bytes(this, 28520))
                && rw::uchar(g, lm, c"plistprev", at_bytes(this, 28521))
                && rw::uchar(g, lm, c"plistprevcount", at_bytes(this, 28522));
            if !ok {
                return 5;
            }
            return 0;
        }

        if lobby_mode == 1 {
            ok = ok && rw::int(g, lm, c"votecount", w(5397));
            rw::array_start(g, lm, c"votes");
            let Some(votes) = checked_count(i32_at(w(5397)), MAX_LOBBY_VOTES) else {
                return 26;
            };
            let mut index = 0usize;
            let mut has_next = rw::element(g, lm, index < votes);
            while has_next && index < votes {
                let vote = w(8 * index + 5398);
                ok = ok
                    && rw::short(g, lm, c"itemtype", at_bytes(vote, 8))
                    && rw::uint(g, lm, c"item", at_bytes(vote, 12))
                    && rw::short(g, lm, c"itemgroup", at_bytes(vote, 16))
                    && rw::short(g, lm, c"attachment", at_bytes(vote, 20))
                    && rw::short(g, lm, c"votetype", at_bytes(vote, 24))
                    && rw::xuid(g, lm, c"votexuid", at_bytes(vote, 0));
                if !ok {
                    return 6;
                }
                index += 1;
                has_next = rw::element(g, lm, index < votes);
            }
            if has_next {
                return 23;
            }
            rw::array_start(g, lm, c"clientlist");
            index = 0;
            has_next = rw::element(g, lm, index < MAX_LOBBY_CLIENTS);
            while has_next && index < MAX_LOBBY_CLIENTS {
                let client = w(index + 8 * index + 7131);
                ok = ok
                    && rw::int(g, lm, c"team", at_bytes(client, 0))
                    && rw::int(g, lm, c"pregamepos", at_bytes(client, 4))
                    && rw::int(g, lm, c"pregamestate", at_bytes(client, 3))
                    && rw::uint(g, lm, c"clvotecount", at_bytes(client, 6))
                    && rw::uint(g, lm, c"character", at_bytes(client, 7))
                    && rw::uint(g, lm, c"loadout", at_bytes(client, 8));
                if !ok {
                    return 7;
                }
                index += 1;
                has_next = rw::element(g, lm, index < MAX_LOBBY_CLIENTS);
            }
            if has_next {
                return 24;
            }
            // The original ignores `packageOK` after this point and returns 0.
            if ok {
                rw::int(g, lm, c"settingssize", w(7350));
            }
            let settings = i32_at(w(7350));
            if settings <= 0 || settings > 0xC000 {
                return 25;
            }
            return 0;
        }

        if lobby_mode == 3 {
            ok = ok
                && rw::int(g, lm, c"compstate", w(5396))
                && rw::int(g, lm, c"votecount", w(5397));
            if !ok {
                return 10;
            }
            let Some(votes) = checked_count(i32_at(w(5397)), MAX_LOBBY_VOTES) else {
                return 27;
            };
            let mut index = 0usize;
            let mut has_next = rw::element(g, lm, index < votes);
            while has_next && index < votes {
                let vote = w(8 * index + 5398);
                ok = ok
                    && rw::short(g, lm, c"itemtype", at_bytes(vote, 8))
                    && rw::uint(g, lm, c"item", at_bytes(vote, 12))
                    && rw::short(g, lm, c"itemgroup", at_bytes(vote, 16))
                    && rw::short(g, lm, c"attachment", at_bytes(vote, 20))
                    && rw::short(g, lm, c"votetype", at_bytes(vote, 24))
                    && rw::xuid(g, lm, c"votexuid", at_bytes(vote, 0));
                if !ok {
                    return 8;
                }
                index += 1;
                has_next = rw::element(g, lm, index < votes);
            }
            if has_next {
                return 28;
            }
            rw::array_start(g, lm, c"clientlist");
            index = 0;
            has_next = rw::element(g, lm, index < MAX_LOBBY_CLIENTS);
            while has_next && index < MAX_LOBBY_CLIENTS {
                let client = w(index + 8 * index + 7131);
                ok = ok
                    && rw::int(g, lm, c"team", at_bytes(client, 0))
                    && rw::int(g, lm, c"pregamepos", at_bytes(client, 4))
                    && rw::int(g, lm, c"pregamestate", at_bytes(client, 3))
                    && rw::uint(g, lm, c"clvotecount", at_bytes(client, 6))
                    && rw::uint(g, lm, c"character", at_bytes(client, 7))
                    && rw::uint(g, lm, c"loadout", at_bytes(client, 8));
                if !ok {
                    return 9;
                }
                index += 1;
                has_next = rw::element(g, lm, index < MAX_LOBBY_CLIENTS);
            }
            if has_next {
                return 29;
            }
            return 0;
        }
    }
    0
}

/// Port of `MSG_HostHeartbeat_Inspect`. Returns 0 for a valid heartbeat.
///
/// # Safety
///
/// `this` must address a writable `i64`-sized scratch slot and `lobby_msg` a live message.
pub unsafe fn msg_host_heartbeat_inspect(this: *mut u8, lobby_msg: *mut c_void) -> i32 {
    let Some(g) = game() else {
        return NOT_INSTALLED;
    };
    let lm = lobby_msg;
    // SAFETY: `this` is the caller's scratch slot, as the function contract requires.
    unsafe {
        let mut ok = rw::int(g, lm, c"heartbeatnum", this)
            && rw::int(g, lm, c"lobbytype", this)
            && rw::int(g, lm, c"lasthosttimems", this);
        if !ok {
            return 1;
        }
        rw::array_start(g, lm, c"nomineelist");
        let mut count = 0usize;
        let mut has_next = rw::element(g, lm, count < MAX_LOBBY_CLIENTS);
        while has_next && count < MAX_LOBBY_CLIENTS {
            ok = ok && rw::xuid(g, lm, c"xuid", this);
            count += 1;
            has_next = rw::element(g, lm, count < MAX_LOBBY_CLIENTS);
        }
        if has_next {
            return 101;
        }
        if !ok {
            return 2;
        }
    }
    0
}

/// Port of `MSG_InfoResponseSafe`. Parses an info response into `info`. Returns 0 on success.
///
/// # Safety
///
/// `info` must be writable and `lm` a live lobby message.
#[allow(clippy::too_many_lines)]
pub unsafe fn msg_info_response_safe(info: *mut MsgInfoResponse, lm: *mut LobbyMsg) -> i32 {
    let Some(g) = game() else {
        return NOT_INSTALLED;
    };
    let lobby_msg = lm.cast::<c_void>();
    // SAFETY: `info` and `lm` are valid per the function contract; `lobby` indices stay below 2.
    unsafe {
        let pack_ok = rw::uint(g, lobby_msg, c"nonce", (&raw mut (*info).nonce).cast())
            && rw::int(
                g,
                lobby_msg,
                c"uiscreen",
                (&raw mut (*info).ui_screen).cast(),
            )
            && rw::uchar(g, lobby_msg, c"nattype", (&raw mut (*info).nat_type).cast());
        if !pack_ok {
            return 1;
        }

        rw::array_start(g, lobby_msg, c"lobbies");
        let mut lobbies = LiveLobbies { g, lobby_msg, info };
        if let Err(code) = read_info_lobbies(&mut lobbies) {
            return code;
        }
        if (*lm).msg.overflowed {
            return 4;
        }
    }
    0
}

/// Reads the `lobbies` array of an info response.
trait LobbyPairReader {
    /// Advances to the next array element; `false` when there is none.
    fn next_element(&mut self) -> bool;
    /// Starts a nested `lobbies` array.
    fn array_start(&mut self);
    /// Parses one inner element into output slot `index`, or returns the error code.
    fn lobby(&mut self, index: usize) -> Result<(), i32>;
}

/// Port of upstream's nested `lobbies` loop, which matches the game's own reader.
/// `MSG_InfoResponse` (Feb `0x1ED5B40`) reads up to two outer elements after the
/// outer `ArrayStart`. Each outer element is read by a helper (live `0x1ECE5B0`)
/// that starts a nested `lobbies` array and reads up to two inner elements into
/// the same output slot (`valid`, then the lobby fields when it is set). Both
/// were checked in a live September dump. The game stops after two elements of
/// either kind; like upstream, a third inner element (5) or a third outer
/// element (4) rejects the response instead. Fewer elements are accepted, as
/// the game accepts them. In read mode `PackageElement` ignores its flag, so it
/// is always passed as `true`.
fn read_info_lobbies(reader: &mut impl LobbyPairReader) -> Result<(), i32> {
    let mut more = reader.next_element();
    for response in 0..2 {
        if !more {
            break;
        }
        reader.array_start();
        let mut inner = reader.next_element();
        for _ in 0..2 {
            if !inner {
                break;
            }
            reader.lobby(response)?;
            inner = reader.next_element();
        }
        if inner {
            return Err(5);
        }
        more = reader.next_element();
    }
    if more {
        return Err(4);
    }
    Ok(())
}

struct LiveLobbies<'a> {
    g: &'a Game,
    lobby_msg: *mut c_void,
    info: *mut MsgInfoResponse,
}

impl LobbyPairReader for LiveLobbies<'_> {
    fn next_element(&mut self) -> bool {
        // SAFETY: `lobby_msg` is the live message `msg_info_response_safe` was given.
        unsafe { rw::element(self.g, self.lobby_msg, true) }
    }

    fn array_start(&mut self) {
        // SAFETY: as above.
        unsafe { rw::array_start(self.g, self.lobby_msg, c"lobbies") };
    }

    fn lobby(&mut self, index: usize) -> Result<(), i32> {
        let (g, lobby_msg) = (self.g, self.lobby_msg);
        // SAFETY: `info` is writable per `msg_info_response_safe`'s contract and
        // `index` is below 2, the length of `lobby`.
        unsafe {
            let lobby = &raw mut (*self.info).lobby[index];
            if !rw::bool_(g, lobby_msg, c"valid", (&raw mut (*lobby).is_valid).cast()) {
                return Err(2);
            }
            if (*lobby).is_valid != 0 {
                let pack_ok = rw::xuid(
                    g,
                    lobby_msg,
                    c"hostxuid",
                    (&raw mut (*lobby).host_xuid).cast(),
                ) && rw::string(
                    g,
                    lobby_msg,
                    c"hostname",
                    (&raw mut (*lobby).host_name).cast(),
                    32,
                ) && rw::int(
                    g,
                    lobby_msg,
                    c"networkmode",
                    (&raw mut (*lobby).lobby_params.network_mode).cast(),
                ) && rw::int(
                    g,
                    lobby_msg,
                    c"mainmode",
                    (&raw mut (*lobby).lobby_params.main_mode).cast(),
                ) && rw::glob(
                    g,
                    lobby_msg,
                    c"secid",
                    (&raw mut (*lobby).sec_id.id).cast(),
                    8,
                ) && rw::glob(
                    g,
                    lobby_msg,
                    c"seckey",
                    (&raw mut (*lobby).sec_key.ab).cast(),
                    16,
                ) && rw::glob(
                    g,
                    lobby_msg,
                    c"addrbuff",
                    (&raw mut (*lobby).serialized_adr.addr_buf).cast(),
                    37,
                ) && rw::string(
                    g,
                    lobby_msg,
                    c"ugcName",
                    (&raw mut (*lobby).ugc_name).cast(),
                    32,
                ) && rw::uint(
                    g,
                    lobby_msg,
                    c"ugcVersion",
                    (&raw mut (*lobby).ugc_version).cast(),
                );
                if !pack_ok {
                    return Err(3);
                }
            }
        }
        Ok(())
    }
}

/// Port of `Protection::CheckPendingInfoRequests`. Decides whether a pending
/// message from `xuid` is kept (returns false) or dropped (returns true).
///
/// # Safety
///
/// `msg` must be a live `msg_t` owned by the caller, positioned after the IM header. It is
/// inspected through a copy; a valid info response is then handed to
/// `dwInstantHandleLobbyMessage`, which reads the rest of `msg` itself. Upstream passes
/// the raw payload pointer there, which only works by not being reached (see
/// `docs/in-game-findings.md`).
pub unsafe fn check_pending_info_requests(xuid: i64, msg: *mut Msg) -> bool {
    // SAFETY: forwarded unchanged from the caller's contract.
    let (drop, reason, detail) = unsafe { pending_info_decision(xuid, msg) };
    crate::diag::trace(format_args!(
        "T7 Patch trace info-check: xuid={xuid:x} {} reason={reason} detail={detail}\n",
        if drop { "DROP" } else { "keep" },
    ));
    drop
}

/// The decision `check_pending_info_requests` makes, with the reason it returned
/// and a detail value (a size, a message type or a parser code) for the trace.
///
/// # Safety
///
/// As for [`check_pending_info_requests`].
unsafe fn pending_info_decision(xuid: i64, msg: *mut Msg) -> (bool, &'static str, i64) {
    // SAFETY: `msg` is a live message, copied as the original does.
    let mut copy = unsafe { *msg };
    let size = copy.cursize.wrapping_sub(copy.readcount);
    let Ok(length) = i32::try_from(size) else {
        return (false, "size", i64::from(size));
    };
    if size >= 2048 {
        return (false, "size", i64::from(size));
    }
    let Some(g) = game() else {
        return (false, "not-installed", 0);
    };
    let mut data = [0u8; 2048];
    // SAFETY: `data` is 2048 bytes and `length` is below 2048.
    unsafe { (g.msg_read_data)(&raw mut copy, data.as_mut_ptr().cast(), length) };
    if copy.overflowed {
        return (false, "overflowed", i64::from(length));
    }
    // SAFETY: the zeroed message is a valid all-zero bit pattern (all integers and NetSrc value 0).
    let mut lobby_msg: LobbyMsg = unsafe { std::mem::zeroed() };
    // SAFETY: `data` holds `length` bytes that the message reader just produced.
    if !unsafe {
        (g.lobby_msg_rw_prep_read_data)(&raw mut lobby_msg, data.as_mut_ptr().cast(), length)
    } {
        return (false, "prep-read-failed", i64::from(length));
    }
    if lobby_msg.msg_type == MSG_INFO_RESPONSE {
        // SAFETY: the zeroed response is a valid all-zero bit pattern.
        let mut response: MsgInfoResponse = unsafe { std::mem::zeroed() };
        // SAFETY: `response` and `lobby_msg` are live locals.
        let result = unsafe { msg_info_response_safe(&raw mut response, &raw mut lobby_msg) };
        if result != 0 {
            return (true, "info-response-rejected", i64::from(result));
        }
        // SAFETY: `msg` is the caller's live message, still positioned after the header,
        // because the inspection above read only `copy`.
        unsafe { (g.dw_instant_handle_lobby_message)(xuid, 0, msg) };
        return (true, "info-response-handled", 0);
    }

    // SAFETY: reads the local player's XUID from the game's player data.
    let local = unsafe { local_player_xuid() };
    let msg_type = i64::from(lobby_msg.msg_type);
    if xuid == 0 || xuid == local {
        return (false, "local", msg_type);
    }
    if !IS_FRIENDS_ONLY.load(Ordering::Relaxed) {
        return (false, "not-friends-only", msg_type);
    }
    if (AND_MASK & xuid) != EXPECTED_MASK {
        return (false, "server-or-splitscreen", msg_type);
    }
    // SAFETY: the friends interface is mapped while Steam is loaded.
    if unsafe { is_friend_by_xuid_uncached(xuid) } {
        return (false, "friend", msg_type);
    }
    (true, "not-a-friend", msg_type)
}

/// Copies the 0x44-byte head of the game's lobby message into a local 0x50-byte buffer.
///
/// # Safety
///
/// `lobby_msg` must address at least 0x44 readable bytes.
unsafe fn copy_lobby_msg(lobby_msg: i64) -> [u8; LOBBY_MSG_COPY_LEN] {
    let mut copy = [0u8; LOBBY_MSG_COPY_LEN];
    // SAFETY: the game's message is at least 0x44 bytes and `copy` is 0x50 bytes.
    unsafe {
        std::ptr::copy_nonoverlapping(
            ptr_from_i64(lobby_msg),
            copy.as_mut_ptr(),
            LOBBY_MSG_COPY_READ,
        );
    }
    copy
}

/// Runs `inspect` on a copy of the message and drops the message when it fails.
///
/// # Safety
///
/// `lobby_msg_type` must be the dispatcher's type slot and `lobby_msg` a live message.
unsafe fn drop_on_inspect_failure(
    lobby_msg_type: *mut i32,
    lobby_msg: i64,
    inspect: unsafe fn(*mut u8, *mut c_void) -> i32,
) {
    // SAFETY: the dispatcher passes a live message address.
    let mut copy = unsafe { copy_lobby_msg(lobby_msg) };
    let mut request_out = vec![0u8; REQUEST_OUT_LEN];
    // SAFETY: both buffers are live for the call, and `inspect` writes only inside `request_out`.
    unsafe {
        if inspect(request_out.as_mut_ptr(), copy.as_mut_ptr().cast()) != 0 {
            *lobby_msg_type = DROPPED_MSG_TYPE;
        }
    }
}

/// Packet handler for join-party requests (type 0x10).
///
/// # Safety
///
/// Called by [`inspect_lm`] with the dispatcher's type slot and message address.
unsafe fn join_party_callback(lobby_msg_type: *mut i32, lobby_msg: i64) {
    // SAFETY: forwarded from the dispatcher.
    unsafe { drop_on_inspect_failure(lobby_msg_type, lobby_msg, msg_join_party_package_inspect) };
}

/// Packet handler that drops the message unconditionally (modified stats, voice, and similar types).
///
/// # Safety
///
/// Called by [`inspect_lm`] with the dispatcher's type slot.
unsafe fn drop_message_callback(lobby_msg_type: *mut i32, _lobby_msg: i64) {
    // SAFETY: the dispatcher passes a live type slot.
    unsafe { *lobby_msg_type = DROPPED_MSG_TYPE };
}

/// Packet handler for lobby state (type 0x02).
///
/// # Safety
///
/// Called by [`inspect_lm`].
unsafe fn lobby_state_callback(lobby_msg_type: *mut i32, lobby_msg: i64) {
    // SAFETY: forwarded from the dispatcher.
    unsafe { drop_on_inspect_failure(lobby_msg_type, lobby_msg, msg_lobby_state_package_inspect) };
}

/// Packet handler for lobby state in game (type 0x03).
///
/// # Safety
///
/// Called by [`inspect_lm`].
unsafe fn lobby_state_game_callback(lobby_msg_type: *mut i32, lobby_msg: i64) {
    // SAFETY: forwarded from the dispatcher.
    unsafe {
        drop_on_inspect_failure(
            lobby_msg_type,
            lobby_msg,
            msg_lobby_state_game_package_inspect,
        );
    }
}

/// Packet handler for host heartbeats (type 0x07). Runs the full inspector on a
/// copy of the message, with a scratch buffer of at least 8 bytes for its XUID
/// reads. Any required field that fails to parse drops the message, as does a
/// nominee list longer than the lobby.
///
/// # Safety
///
/// Called by [`inspect_lm`].
unsafe fn host_heartbeat_callback(lobby_msg_type: *mut i32, lobby_msg: i64) {
    // SAFETY: forwarded from the dispatcher.
    unsafe { drop_on_inspect_failure(lobby_msg_type, lobby_msg, msg_host_heartbeat_inspect) };
}

/// Port of the lobby-message handler table in `Protection::install`.
fn register_packet_callbacks() {
    let mut map = lock(&PACKET_CALLBACKS);
    map.insert(0x10, join_party_callback);
    map.insert(0xF, drop_message_callback);
    for key in [0x1E, 0x16, 0x17, 0x18] {
        map.insert(key, drop_message_callback);
    }
    map.insert(MSG_LOBBY_HOST_HEARTBEAT, host_heartbeat_callback);
    map.insert(0x2, lobby_state_callback);
    map.insert(0x3, lobby_state_game_callback);
}

/// True when a wire count is in `0..=max`. Negative counts are rejected, not
/// read as empty.
fn count_in_range(count: i32, max: usize) -> bool {
    checked_count(count, max).is_some()
}

/// A wire count as an index bound, or `None` outside `0..=max`.
fn checked_count(count: i32, max: usize) -> Option<usize> {
    usize::try_from(count).ok().filter(|&count| count <= max)
}

/// Converts a low-order byte of `value`, as C's implicit `int` to `BYTE` conversion does.
fn low_byte(value: i32) -> u8 {
    u8::try_from(value & 0xFF).unwrap_or_default()
}

/// Port of `Protection::InspectLM`. Runs from the exception dispatcher when the
/// game's lobby-message print hook fires.
///
/// # Safety
///
/// `context` must be the live `CONTEXT` of the faulting thread.
pub unsafe fn inspect_lm(_record: *const EXCEPTION_RECORD, context: *mut CONTEXT) {
    // SAFETY: the dispatcher passes the faulting thread's live context.
    let rsp = usize::try_from(unsafe { (*context).Rsp }).unwrap_or(0);
    // SAFETY: `rsp + 0x28` is inside the faulting thread's stack.
    let return_address = unsafe { read_i64(rsp.wrapping_add(0x28)) };
    if return_address == CACHED_RETN_ADDY.load(Ordering::Relaxed) {
        let lobby_msg = rsp.wrapping_add(0x60);
        let type_slot = lobby_msg.wrapping_add(0x38);
        // SAFETY: the type slot is inside the faulting thread's stack.
        let msg_type = unsafe { i32_at(type_slot as *mut u8) };
        let callback = lock(&PACKET_CALLBACKS).get(&low_byte(msg_type)).copied();
        if let Some(callback) = callback {
            // SAFETY: the slot and message addresses come from the faulting thread's stack.
            unsafe { callback(type_slot as *mut i32, addr_i64(lobby_msg)) };
        }
    }
    let old = OLD_LOBBYMSG_PRINTS.load(Ordering::Relaxed).cast_unsigned();
    // SAFETY: the context is still the faulting thread's live context.
    unsafe {
        (*context).Rcx = old;
        (*context).Rbx = old;
    }
}

/// Repairs a fault this crate induced on purpose: a read through the lobby-print
/// marker. Returns `true` when the fault was ours. Runs before the handler-active
/// check, because a thread can hold the marker after the patch is deactivated,
/// and nothing else would repair it. Uses only statics that live for the process.
///
/// # Safety
///
/// Called by the exception dispatcher with the live record and context.
pub unsafe fn repair_induced_exception(
    record: *const EXCEPTION_RECORD,
    context: *mut CONTEXT,
) -> bool {
    // SAFETY: the dispatcher passes a live context.
    if unsafe { (*context).Rcx } != LOBBY_MSG_MARKER {
        return false;
    }
    // SAFETY: forwarded from the dispatcher.
    unsafe { inspect_lm(record, context) };
    // SAFETY: forwarded from the dispatcher.
    unsafe { resume(context) };
    true
}

/// Port of `Protection::ExceptHook`. Applies the crash fixups and resumes the thread.
///
/// # Safety
///
/// Called by the exception dispatcher with the live record and context.
pub unsafe fn except_hook(record: *const EXCEPTION_RECORD, context: *mut CONTEXT) {
    // SAFETY: the dispatcher passes live records.
    let fault = unsafe { (*record).ExceptionAddress } as usize;
    // SAFETY: forwarded from the dispatcher.
    if unsafe { repair_induced_exception(record, context) } {
        return;
    }
    if fault == address(offsets::CHARACTER_INDEX_CRASH_A)
        || fault == address(offsets::CHARACTER_INDEX_CRASH_B)
    {
        // SAFETY: the faulting thread's context is live.
        unsafe { (*context).Rip = address(offsets::CHARACTER_INDEX_RESUME) as u64 };
        // SAFETY: forwarded from the dispatcher.
        unsafe { resume(context) };
        return;
    }
    if fault == address(offsets::LUA_CRASH1) {
        // SAFETY: the faulting thread's context is live.
        unsafe { (*context).Rip = address(offsets::LUA_CRASH1_RIP) as u64 };
        // SAFETY: forwarded from the dispatcher.
        unsafe { resume(context) };
        return;
    }
    if fault == address(offsets::LUA_CRASH2) {
        // SAFETY: the faulting thread's context is live.
        unsafe { (*context).Rdx = ui_localize_default_text() };
        // SAFETY: forwarded from the dispatcher.
        unsafe { resume(context) };
        return;
    }
    if fault == address(offsets::LUA_CRASH3) {
        // SAFETY: the faulting thread's context is live.
        unsafe { (*context).Rsi = ui_localize_default_text() };
        // SAFETY: forwarded from the dispatcher.
        unsafe { resume(context) };
    }
}

/// Writable empty string, as the C++ `malloc(4)` buffer. The game may write to it.
static UI_LOCALIZE_DEFAULT_TEXT: [AtomicU8; 4] = [const { AtomicU8::new(0) }; 4];

/// Address of the empty string the Lua and localize crash fixups substitute.
pub fn ui_localize_default_text() -> u64 {
    UI_LOCALIZE_DEFAULT_TEXT.as_ptr() as usize as u64
}

/// Resumes the faulting thread with `NtContinue`-style `ZwContinue`.
///
/// # Safety
///
/// `context` must be the live context of the faulting thread.
unsafe fn resume(context: *mut CONTEXT) {
    let zw = ZW_CONTINUE.load(Ordering::Relaxed);
    if zw == 0 {
        return;
    }
    // SAFETY: `ZW_CONTINUE` holds the `ZwContinue` entry point, which takes a context and a flag.
    unsafe {
        let continue_fn: ZwContinueFn = fn_from_addr(zw);
        let _ = continue_fn(context, 0);
    }
}

// ---------------------------------------------------------------------------
// Install and uninstall
// ---------------------------------------------------------------------------

/// Port of `IsProcessorFeaturePresent` detour. Feature 0x17 raises an access
/// violation on purpose, as the original does.
///
/// # Safety
///
/// Called by the game through the IAT.
unsafe extern "system" fn is_processor_feature_present(feature: u32) -> i32 {
    if feature == 0x17 {
        const EXCEPTION_ACCESS_VIOLATION: u32 = 0xC000_0005;
        const EXCEPTION_NONCONTINUABLE: u32 = 0x1;
        const WRITE_FAULT: usize = 1;
        const FAULT_ADDRESS: usize = 0x17;
        let args = [WRITE_FAULT, FAULT_ADDRESS];
        // SAFETY: raises the same access violation the original provokes by writing address 0x17.
        unsafe {
            RaiseException(
                EXCEPTION_ACCESS_VIOLATION,
                EXCEPTION_NONCONTINUABLE,
                Some(&args),
            );
        }
    }
    let original = O_IS_PROCESSOR_FEATURE_PRESENT.load(Ordering::Relaxed);
    if original == 0 {
        return 0;
    }
    // SAFETY: the saved entry is the real `IsProcessorFeaturePresent`.
    unsafe { fn_from_addr::<IsProcessorFeaturePresentFn>(original)(feature) }
}

/// Calls `Dvar_SetFromStringByName`.
///
/// # Safety
///
/// The dvar system must be initialized (the game is running).
unsafe fn dvar_set_from_string_by_name(name: &CStr, value: &CStr, create_if_missing: bool) {
    // SAFETY: the game function takes two C strings and a bool.
    unsafe {
        let set_dvar: DvarSetFromStringFn =
            fn_from_addr(address(offsets::DVAR_SET_FROM_STRING_BY_NAME));
        let _ = set_dvar(name.as_ptr(), value.as_ptr(), create_if_missing);
    }
}

/// Clears the flags word at `+0x18` of the dvar whose pointer is stored at `global`.
///
/// # Safety
///
/// `global` must be a game global that holds a dvar pointer.
unsafe fn clear_dvar_flags(global: usize) {
    // SAFETY: `global` is a game global that holds a dvar pointer.
    let dvar = unsafe { read_usize(global) };
    if dvar != 0 {
        // SAFETY: the dvar object is at least 0x1C bytes.
        unsafe { write_u32(dvar + 0x18, 0) };
    }
}

/// Copies the configured name into the game's name buffers during install.
///
/// # Safety
///
/// The game's name buffers and player data must be mapped.
unsafe fn copy_name_into_game() {
    let name = custom_name_snapshot();
    let length = c_prefix(&name).len();
    if length == 0 {
        return;
    }
    let with_nul = &name[..=length];
    // SAFETY: the shadow and name buffers are game globals of at least 16 bytes.
    unsafe {
        copy_bytes(address(offsets::NAME_BUFFER_SHADOW) as *mut u8, with_nul);
        copy_bytes(address(offsets::PTR_NAME1) as *mut u8, with_nul);
        copy_bytes(address(offsets::PTR_NAME2) as *mut u8, with_nul);
        let player_data_slot = address(offsets::S_PLAYER_DATA_PTR);
        if !is_bad_read_ptr(player_data_slot as *const c_void) {
            let player_data = read_usize(player_data_slot);
            if player_data != 0 {
                let target = player_data + 8;
                copy_bytes(target as *mut u8, &[0u8; 16]);
                copy_bytes(target as *mut u8, with_nul);
            }
        }
    }
}

/// Set once [`initialize`] has finished. Callbacks from an earlier activation may still be
/// running, so the one-time state is never rebuilt.
static INITIALIZED: AtomicBool = AtomicBool::new(false);
/// Set before the `IsProcessorFeaturePresent` IAT entry is written.
static IAT_INSTALLED: AtomicBool = AtomicBool::new(false);
/// Set before the lobby-message print marker is written.
static LOBBY_MARKER_INSTALLED: AtomicBool = AtomicBool::new(false);
/// Set before the update-preload pointer is written.
static PRELOAD_INSTALLED: AtomicBool = AtomicBool::new(false);
/// The update-preload pointer captured before it was replaced.
static ORIGINAL_PRELOAD: AtomicUsize = AtomicUsize::new(0);
/// Set once the dvar flags/values were changed. Upstream has no way to read the
/// original values back without a `Dvar_FindVarByName` address, so they are kept.
static DVAR_SETTINGS_APPLIED: AtomicBool = AtomicBool::new(false);

/// Port of the fork's `Protection::initialize`. Runs once: resolves the game function table,
/// caches the local XUID, clears the network password, registers the lobby packet
/// callbacks, and snapshots the original of every Steam vtable slot the patch replaces.
///
/// # Safety
///
/// Must run inside the game process after the executable is mapped and Steam is loaded.
pub unsafe fn initialize() -> Result<(), String> {
    if INITIALIZED.load(Ordering::Acquire) {
        return Ok(());
    }
    // SAFETY: called inside the game process; every RVA matches its field's signature.
    let table = unsafe { Game::resolve() };
    let _ = GAME.set(table);

    // SAFETY: reads the local player's XUID from the game's player data.
    CACHED_XUID.store(unsafe { local_player_xuid() }, Ordering::Relaxed);
    set_network_password(0);
    register_packet_callbacks();

    let mut snapshot: BTreeMap<usize, BTreeMap<usize, usize>> = BTreeMap::new();
    for (library, index) in steam_slots() {
        // SAFETY: `library` is a Steam interface global of the running game.
        let vtable = unsafe { steam_vtable(library) }?;
        // SAFETY: `index` is a slot of that interface's vtable.
        let original = unsafe { read_usize(vtable + index * 8) };
        snapshot.entry(library).or_default().insert(index, original);
    }
    *lock(&STEAM_API_HOOKS) = snapshot;

    INITIALIZED.store(true, Ordering::Release);
    Ok(())
}

/// Port of `Protection::install`. Each write records what it replaced before it happens,
/// so [`uninstall`] can undo a partial install.
///
/// # Safety
///
/// Must run inside the game process after [`initialize`], before any lobby message is
/// dispatched.
pub unsafe fn install() -> Result<(), String> {
    // SAFETY: the game is running, so its name buffers are mapped.
    unsafe { copy_name_into_game() };

    // Save the actual IAT entry, which may already belong to another module.
    // SAFETY: the main module is the image whose import table holds `IsProcessorFeaturePresent`.
    let Some(iat) = (unsafe { iat_hook::find(c"IsProcessorFeaturePresent", 0) }) else {
        return Err("T7 Patch: missing IsProcessorFeaturePresent import".to_owned());
    };
    // SAFETY: `iat` is an IAT entry inside the mapped image.
    let original = unsafe { iat.read_unaligned() };
    O_IS_PROCESSOR_FEATURE_PRESENT.store(original, Ordering::Release);

    // SAFETY: reads the game's networking global at +0x10, as the original does.
    let networking_slot = unsafe { read_usize(steam_networking() + 0x10) };
    O_READ_P2P_PACKET.store(networking_slot, Ordering::Relaxed);

    let detour = is_processor_feature_present as *const () as usize;
    // SAFETY: `iat` is an IAT entry inside the mapped image.
    let report = unsafe { crate::arxan::swap_usize(iat as usize, original, detour) };
    if report.written {
        IAT_INSTALLED.store(true, Ordering::Release);
        // The detour can raise the induced 0x17 exception from now on.
        crate::exception::note_exception_producer();
    }
    if !report.complete() {
        return Err("T7 Patch: cannot write the IsProcessorFeaturePresent import".to_owned());
    }

    let replacements = [
        get_username_ptr as *const () as usize,
        get_username_xuid_ptr as *const () as usize,
        get_owns_content as *const () as usize,
        get_owns_content2 as *const () as usize,
        is_vac_banned as *const () as usize,
        get_dlc_download_progress as *const () as usize,
        get_lobby_chat_entry as *const () as usize,
        create_lobby as *const () as usize,
        read_p2p_packet as *const () as usize,
    ];
    for ((library, index), replacement) in steam_slots().into_iter().zip(replacements) {
        // SAFETY: each slot is a valid vtable entry and each replacement matches its signature.
        unsafe { swap_steam_api_pointer(library, index, replacement) }?;
    }

    let preload = address(offsets::PTR_UPDATE_PRELOAD_IDLE_FN);
    // SAFETY: the update-preload pointer is a game global.
    ORIGINAL_PRELOAD.store(unsafe { read_usize(preload) }, Ordering::Release);
    // SAFETY: as above; nothing is written if it cannot be made writable.
    let write = unsafe {
        crate::arxan::swap_usize(
            preload,
            ORIGINAL_PRELOAD.load(Ordering::Acquire),
            cl_switch_state_idle_update as *const () as usize,
        )
    };
    if write.written {
        PRELOAD_INSTALLED.store(true, Ordering::Release);
    }
    if !write.complete() {
        return Err("T7 Patch: cannot write the update-preload pointer".to_owned());
    }

    let prints = address(offsets::PTR_LOBBYMSGPRINTS);
    // SAFETY: the print global is a game variable.
    OLD_LOBBYMSG_PRINTS.store(unsafe { read_i64(prints) }, Ordering::Release);
    // Publish the return address before the marker that makes the exception path read it.
    CACHED_RETN_ADDY.store(
        addr_i64(address(offsets::PTR_SAVE_LOBBY_MSG_EXCEPT_ADDY)),
        Ordering::Release,
    );
    // SAFETY: as above; the marker global is a game variable.
    let report = unsafe {
        crate::arxan::swap_usize(
            prints,
            word(OLD_LOBBYMSG_PRINTS.load(Ordering::Acquire).cast_unsigned()),
            word(LOBBY_MSG_MARKER),
        )
    };
    if report.written {
        LOBBY_MARKER_INSTALLED.store(true, Ordering::Release);
        // The invalid marker can raise the induced lobby-print exception from now on.
        crate::exception::note_exception_producer();
    }
    if !report.complete() {
        return Err("T7 Patch: cannot write the lobby-message marker".to_owned());
    }

    // SAFETY: the create-lobby function takes one pointer-sized argument and has no return value.
    unsafe {
        let create_lobby_again: CreateLobbyAgainFn =
            fn_from_addr(address(offsets::CREATE_LOBBY_AGAIN_FN));
        create_lobby_again(addr_i64(address(offsets::CREATE_LOBBY_AGAIN_ARG)));
    }

    // SAFETY: the dvar globals hold dvar pointers, and the dvar functions run during install.
    unsafe {
        clear_dvar_flags(address(offsets::DVAR_UI_ERROR_CALLSTACK_PTR));
        dvar_set_from_string_by_name(c"ui_error_callstack_ship", c"1", true);
        clear_dvar_flags(address(offsets::DVAR_G_ALLOWVOTE_PTR));
        dvar_set_from_string_by_name(c"g_allowvote", c"0", true);
        dvar_set_from_string_by_name(c"maxvoicepacketsperframe", c"0", true);
    }
    DVAR_SETTINGS_APPLIED.store(true, Ordering::Release);
    Ok(())
}

/// True while a patch that can induce an exception is still applied.
///
/// Once either is set, the dispatcher must not be removed: a thread that already
/// loaded the lobby marker or the IAT detour can still fault.
pub(crate) fn exception_producers_remaining() -> bool {
    LOBBY_MARKER_INSTALLED.load(Ordering::Acquire) || IAT_INSTALLED.load(Ordering::Acquire)
}

/// Port of `Protection::uninstall`. Restores the Steam vtable snapshot and every game entry
/// [`install`] recorded, trying all of them, then reports any failure. The snapshot and the
/// trampolines stay alive for callbacks already in flight.
///
/// The dvar changes are not restored: doing so needs a `Dvar_FindVarByName` address, and
/// guessing one is worse than leaving them. `DVAR_SETTINGS_APPLIED` records that they were
/// applied so unload can report the residual.
///
/// # Safety
///
/// Must run inside the game process while the game is still running.
pub unsafe fn uninstall() -> Result<(), String> {
    let mut failures: Vec<&str> = Vec::new();

    let swapped: Vec<SwappedSlot> = lock(&STEAM_SWAPPED).clone();
    for record in swapped {
        // SAFETY: `restore_usize` checks that the slot is still mapped, and writes only
        // while it holds our replacement. A replaced interface is left alone.
        if unsafe { crate::arxan::restore_usize(record.slot, record.replacement, record.original) }
        {
            lock(&STEAM_SWAPPED).retain(|kept| *kept != record);
        } else {
            failures.push("Steam vtable slot");
        }
    }

    if LOBBY_MARKER_INSTALLED.load(Ordering::Acquire) {
        let old = OLD_LOBBYMSG_PRINTS.load(Ordering::Acquire);
        // SAFETY: the print global is the game variable `install` wrote.
        if unsafe {
            crate::arxan::restore_usize(
                address(offsets::PTR_LOBBYMSGPRINTS),
                word(LOBBY_MSG_MARKER),
                word(old.cast_unsigned()),
            )
        } {
            LOBBY_MARKER_INSTALLED.store(false, Ordering::Release);
        } else {
            failures.push("lobby-message marker");
        }
    }

    if PRELOAD_INSTALLED.load(Ordering::Acquire) {
        let original = ORIGINAL_PRELOAD.load(Ordering::Acquire);
        // SAFETY: the update-preload pointer is the game global `install` wrote.
        if unsafe {
            crate::arxan::restore_usize(
                address(offsets::PTR_UPDATE_PRELOAD_IDLE_FN),
                cl_switch_state_idle_update as *const () as usize,
                original,
            )
        } {
            PRELOAD_INSTALLED.store(false, Ordering::Release);
        } else {
            failures.push("update-preload pointer");
        }
    }

    if IAT_INSTALLED.load(Ordering::Acquire) {
        let original = O_IS_PROCESSOR_FEATURE_PRESENT.load(Ordering::Acquire);
        // SAFETY: the main module's import table was read by `install`.
        let restored = unsafe { iat_hook::find(c"IsProcessorFeaturePresent", 0) }.is_some_and(
            // SAFETY: `slot` is the IAT entry `install` replaced, and `original` its old value.
            |slot| unsafe {
                crate::arxan::restore_usize(
                    slot as usize,
                    is_processor_feature_present as *const () as usize,
                    original,
                )
            },
        );
        if restored {
            IAT_INSTALLED.store(false, Ordering::Release);
        } else {
            failures.push("IsProcessorFeaturePresent import");
        }
    }

    set_network_password(0);
    if DVAR_SETTINGS_APPLIED.load(Ordering::Acquire) {
        crate::dllmain::debug_print(
            "T7 Patch: dvar settings are retained after unload; there is no dvar finder address.\n",
        );
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "T7 Patch: protection restoration failed: {}",
            failures.join(", ")
        ))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_leading_int_follows_stream_extraction() {
        assert_eq!(parse_leading_int(b"12"), Some(12));
        assert_eq!(parse_leading_int(b"  -3x"), Some(-3));
        assert_eq!(parse_leading_int(b"+7"), Some(7));
        assert_eq!(parse_leading_int(b"1.5"), Some(1));
        assert_eq!(parse_leading_int(b""), None);
        assert_eq!(parse_leading_int(b"abc"), None);
        assert_eq!(parse_leading_int(b"-"), None);
        assert_eq!(parse_leading_int(b"99999999999"), None);
        assert_eq!(parse_leading_int(b"2147483647"), Some(i32::MAX));
        assert_eq!(parse_leading_int(b"-2147483648"), Some(i32::MIN));
    }

    #[test]
    fn default_config_serializes_to_original_layout() {
        let text = PatchConfig::DEFAULT.serialize();
        assert_eq!(
            text,
            b"playername=Unknown Soldier\r\nisfriendsonly=1\r\nautoinstallmods=0\r\nnetworkpassword=\r\n"
        );
    }

    #[test]
    fn config_round_trips_through_text() {
        let mut cfg = PatchConfig::DEFAULT;
        cfg.apply_text(b"playername=Serious\r\nisfriendsonly=0\r\nautoinstallmods=1\r\nnetworkpassword=abc\r\n");
        assert_eq!(cfg.playername_bytes(), b"Serious");
        assert_eq!(cfg.isfriendsonly, 0);
        assert_eq!(cfg.autoinstallmods, 1);
        assert_eq!(cfg.networkpassword, b"abc");
        let reread = {
            let mut next = PatchConfig::DEFAULT;
            next.apply_text(&cfg.serialize());
            next
        };
        assert_eq!(reread.serialize(), cfg.serialize());
    }

    #[test]
    fn config_truncates_long_name_and_treats_bad_values_as_off() {
        let mut cfg = PatchConfig::DEFAULT;
        cfg.apply_text(b"playername=ABCDEFGHIJKLMNOPQRST\n");
        assert_eq!(cfg.playername_bytes(), b"ABCDEFGHIJKLMNO");

        let mut cfg = PatchConfig::DEFAULT;
        cfg.apply_text(b"isfriendsonly=\nautoinstallmods=2\n");
        assert_eq!(cfg.isfriendsonly, 0);
        assert_eq!(cfg.autoinstallmods, 0);

        let mut cfg = PatchConfig::DEFAULT;
        cfg.apply_text(b"isfriendsonly=junk\n");
        assert_eq!(cfg.isfriendsonly, 0);
    }

    #[test]
    fn empty_playername_value_keeps_previous_name() {
        let mut cfg = PatchConfig::DEFAULT;
        cfg.apply_text(b"playername=\n");
        assert_eq!(cfg.playername_bytes(), b"Unknown Soldier");
    }

    #[test]
    fn sanitize_replaces_sequences_and_controls() {
        let mut msg = *b"a^b%c$(d[{e\x01f\x80g~h\0";
        sanitize_chat(&mut msg);
        assert_eq!(&msg, b"a.b.c.(d.{e.f.g~h\0");
    }

    #[test]
    fn sanitize_keeps_lone_dollar_and_bracket() {
        let mut msg = *b"$x[y\0";
        sanitize_chat(&mut msg);
        assert_eq!(&msg, b"$x[y\0");
    }

    #[test]
    fn sanitize_cuts_an_unterminated_message() {
        let mut msg = *b"ab^cd";
        sanitize_chat(&mut msg);
        assert_eq!(&msg, b"ab.c\0");
    }

    #[test]
    fn sanitize_stops_at_the_first_nul() {
        let mut msg = *b"a^\0^%";
        sanitize_chat(&mut msg);
        assert_eq!(&msg, b"a.\0^%");
    }

    #[test]
    fn sanitize_lookahead_stops_at_the_nul() {
        // `$` then NUL then `(`: the `(` is past the text, so the `$` stays.
        let mut msg = *b"x$\0(";
        sanitize_chat(&mut msg);
        assert_eq!(&msg, b"x$\0(");
    }

    #[test]
    fn sanitize_handles_an_empty_buffer() {
        let mut msg: [u8; 0] = [];
        sanitize_chat(&mut msg);
    }

    #[test]
    fn sanitize_treats_trailing_dollar_as_plain() {
        let mut msg = *b"cost$\0";
        sanitize_chat(&mut msg);
        assert_eq!(&msg, b"cost$\0");
    }

    #[test]
    fn p2p_drop_rules() {
        assert!(p2p_packet_is_dropped(104, true, || false));
        assert!(!p2p_packet_is_dropped(104, true, || true));
        assert!(!p2p_packet_is_dropped(104, false, || false));
        assert!(p2p_packet_is_dropped(102, false, || true));
        assert!(p2p_packet_is_dropped(101, false, || true));
        assert!(p2p_packet_is_dropped(109, false, || true));
        assert!(!p2p_packet_is_dropped(0, true, || false));
    }

    #[test]
    fn content_files_match_app_ids() {
        assert_eq!(content_file_for_app(366840), Some("cp_common.xpak"));
        assert_eq!(content_file_for_app(366841), Some("mp_common.xpak"));
        assert_eq!(content_file_for_app(366842), Some("zm_common.xpak"));
        assert_eq!(content_file_for_app(1), None);
    }

    #[test]
    fn readable_pages_are_not_bad() {
        assert!(!protect_is_bad(PAGE_READWRITE.0));
        assert!(!protect_is_bad(PAGE_EXECUTE_READ.0));
        assert!(protect_is_bad(0));
        assert!(protect_is_bad(PAGE_NOACCESS.0));
        assert!(protect_is_bad(PAGE_READWRITE.0 | PAGE_GUARD.0));
    }

    #[test]
    fn msvc_rand_matches_crt_sequence() {
        let mut state = 1;
        assert_eq!(msvc_rand(&mut state), 41);
        assert_eq!(msvc_rand(&mut state), 18467);
    }

    #[test]
    fn network_password_key_maps_empty_to_zero() {
        assert_eq!(network_password_key(b""), 0);
        assert_eq!(network_password_key(b"\0junk"), 0);
        assert_ne!(network_password_key(b"pw"), 0);
        assert!(network_password_key(b"pw") >= 0);
    }

    #[test]
    fn rotate_shifts_history() {
        let mut state = [0, 0, 0];
        rotate_private_password(&mut state, 5, 100);
        rotate_private_password(&mut state, 9, 200);
        assert_eq!(state, [5, 9, 200]);
    }

    /// A fake `lobbies` array: `markers` are the successive `PackageElement`
    /// results (past the end, `false`); `bad` fails slot `index` with a code.
    struct FakeLobbies {
        markers: Vec<bool>,
        cursor: usize,
        arrays: usize,
        bad: Option<(usize, i32)>,
        parsed: Vec<usize>,
    }

    impl LobbyPairReader for FakeLobbies {
        fn next_element(&mut self) -> bool {
            let present = self.markers.get(self.cursor).copied().unwrap_or(false);
            self.cursor += 1;
            present
        }

        fn array_start(&mut self) {
            self.arrays += 1;
        }

        fn lobby(&mut self, index: usize) -> Result<(), i32> {
            match self.bad {
                Some((bad, code)) if bad == index => return Err(code),
                _ => {}
            }
            self.parsed.push(index);
            Ok(())
        }
    }

    fn lobbies(
        markers: &[bool],
        bad: Option<(usize, i32)>,
    ) -> (Result<(), i32>, Vec<usize>, usize) {
        let mut fake = FakeLobbies {
            markers: markers.to_vec(),
            cursor: 0,
            arrays: 0,
            bad,
            parsed: Vec::new(),
        };
        (read_info_lobbies(&mut fake), fake.parsed, fake.arrays)
    }

    /// What the game's own writer emits: two outer elements, each a nested array
    /// of two inner elements, each array closed by a `false` marker.
    const GAME_WRITER: [bool; 9] = [true, true, true, false, true, true, true, false, false];

    #[test]
    fn info_response_reads_the_games_nested_layout() {
        assert_eq!(lobbies(&GAME_WRITER, None), (Ok(()), vec![0, 0, 1, 1], 2));
        // Fewer elements are accepted, as the game accepts them.
        assert_eq!(lobbies(&[false], None), (Ok(()), vec![], 0));
        assert_eq!(
            lobbies(&[true, true, false, false], None),
            (Ok(()), vec![0], 1)
        );
        // An outer element whose nested array is empty.
        assert_eq!(lobbies(&[true, false, false], None), (Ok(()), vec![], 1));
        // A third inner element, or a third outer one, rejects the response.
        assert_eq!(
            lobbies(&[true, true, true, true], None),
            (Err(5), vec![0, 0], 1)
        );
        let mut extra_outer = GAME_WRITER;
        extra_outer[8] = true;
        assert_eq!(lobbies(&extra_outer, None), (Err(4), vec![0, 0, 1, 1], 2));
        // A field error in either response rejects it at once.
        assert_eq!(lobbies(&GAME_WRITER, Some((0, 3))), (Err(3), vec![], 1));
        assert_eq!(lobbies(&GAME_WRITER, Some((1, 2))), (Err(2), vec![0, 0], 2));
    }

    #[test]
    fn counts_must_be_inside_the_inclusive_range() {
        assert_eq!(checked_count(0, MAX_LOBBY_CLIENTS), Some(0));
        assert_eq!(checked_count(18, MAX_LOBBY_CLIENTS), Some(18));
        assert_eq!(checked_count(19, MAX_LOBBY_CLIENTS), None);
        assert_eq!(checked_count(-1, MAX_LOBBY_CLIENTS), None);
        assert_eq!(checked_count(i32::MIN, MAX_LOBBY_VOTES), None);
        assert_eq!(checked_count(216, MAX_LOBBY_VOTES), Some(216));
        assert_eq!(checked_count(217, MAX_LOBBY_VOTES), None);
        assert!(!count_in_range(-5, MAX_LOBBY_CLIENTS));
    }

    fn at(seconds: u64) -> SystemTime {
        SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(seconds)
    }

    fn loaded(name: &[u8], seconds: u64) -> PatchConfig {
        let mut cfg = PatchConfig::DEFAULT;
        cfg.apply_line(&[b"playername=", name].concat());
        cfg.exists = true;
        cfg.modified = Some(at(seconds));
        cfg
    }

    #[test]
    fn refresh_commits_settings_and_time_only_on_success() {
        let mut cfg = loaded(b"Old", 1);
        // Unchanged time: no read at all.
        assert!(!cfg.refresh(Ok(Some(at(1))), |_| panic!("read")));
        // A failed read keeps the old settings and the old time, so it retries.
        assert!(!cfg.refresh(Ok(Some(at(2))), |_| Err(ConfigError::Access)));
        assert_eq!(cfg.playername_bytes(), b"Old");
        assert_eq!(cfg.modified, Some(at(1)));
        assert!(!cfg.refresh(Ok(Some(at(2))), |_| Err(ConfigError::ChangedDuringRead)));
        assert_eq!(cfg.modified, Some(at(1)));
        // The retry succeeds and commits both together.
        assert!(cfg.refresh(Ok(Some(at(2))), |_| Ok(loaded(b"New", 2))));
        assert_eq!(cfg.playername_bytes(), b"New");
        assert_eq!(cfg.modified, Some(at(2)));
    }

    #[test]
    fn refresh_keeps_settings_when_metadata_fails() {
        let mut cfg = loaded(b"Kept", 1);
        assert!(!cfg.refresh(Err(ConfigError::Access), |_| panic!("read")));
        assert_eq!(cfg.playername_bytes(), b"Kept");
        assert!(cfg.exists);
    }

    #[test]
    fn refresh_resets_to_defaults_when_the_file_is_deleted() {
        let mut cfg = loaded(b"Gone", 1);
        assert!(cfg.refresh(Ok(None), |_| panic!("read")));
        assert_eq!(cfg.playername_bytes(), b"Unknown Soldier");
        assert!(!cfg.exists);
        // Still missing: nothing more to apply.
        assert!(!cfg.refresh(Ok(None), |_| panic!("read")));
        // Deleted between the metadata check and the read.
        let mut cfg = loaded(b"Racy", 1);
        assert!(cfg.refresh(Ok(Some(at(2))), |_| Err(ConfigError::Missing)));
        assert!(!cfg.exists);
    }

    #[test]
    fn loadfrom_reads_a_real_file_without_committing() {
        let dir = std::env::temp_dir().join(format!("t7patch-cfg-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        let path = dir.join("t7patch.conf");
        fs::write(&path, b"playername=Disk\r\nisfriendsonly=0\r\n").unwrap();
        let cfg = PatchConfig::DEFAULT;
        let candidate = cfg.loadfrom(&path).expect("read");
        assert_eq!(candidate.playername_bytes(), b"Disk");
        assert_eq!(candidate.isfriendsonly, 0);
        assert!(candidate.modified.is_some());
        assert_eq!(cfg.playername_bytes(), b"Unknown Soldier");
        fs::remove_file(&path).unwrap();
        assert_eq!(cfg.loadfrom(&path).err(), Some(ConfigError::Missing));
        let _ = fs::remove_dir(&dir);
    }

    #[test]
    fn prefix_bytes_come_from_one_hash() {
        assert_eq!(zbr_prefix_of(0x0000_0000_AABB_CCDD), (0xBB, 0xAA));
        assert_eq!(zbr_prefix_of(0), (0, 0));
        assert_eq!(zbr_prefix_of(-1), (0xFF, 0xFF));
    }

    #[test]
    fn password_prefix_bytes_take_their_shifted_byte() {
        assert_eq!(byte_at(0x00AB_CDEF, 16), 0xAB);
        assert_eq!(byte_at(0x0102_0304_0000_0000, 24), 0x00);
        assert_eq!(byte_at(0x0102_0304_0000_0000, 32), 0x04);
        assert_eq!(byte_at(0x7F00_0000_0000_0000, 56), 0x7F);
    }

    #[test]
    fn published_name_snapshots_are_immutable() {
        static NAME_LOCK: Mutex<()> = Mutex::new(());
        let _guard = NAME_LOCK.lock().unwrap_or_else(PoisonError::into_inner);

        let first = set_custom_name(b"Alice").expect("first name");
        let first_ptr = custom_name_ptr();
        let second = set_custom_name(b"Bob").expect("second name");
        let second_ptr = custom_name_ptr();

        assert_ne!(first_ptr, second_ptr);
        assert_eq!(custom_name_snapshot(), second);
        assert!(!custom_name_is_empty());
        // A game thread may still hold the old pointer; its bytes must not change.
        // SAFETY: every published pointer addresses a retained Box<NameBytes>.
        let old = unsafe { std::ptr::read(first_ptr.cast::<NameBytes>()) };
        assert_eq!(old, first);
    }

    #[test]
    fn player_name_length_limit() {
        assert!(player_name_fields(b"123456789012345").is_some());
        assert!(player_name_fields(b"1234567890123456").is_none());
        let fields = player_name_fields(b"Ab").unwrap();
        assert_eq!(&fields[..3], b"Ab\0");
        assert_eq!(fields[15], 0);
    }

    #[test]
    fn steam_vtable_indices_follow_steamvto() {
        assert_eq!(STEAMAPI_STEAMUSER_GETUSERNAME, 0);
        assert_eq!(STEAMAPI_STEAMUSER_VT_NAMEBYXUID, 7);
        assert_eq!(STEAMAPI_INTERFACE_IS_VAC_BANNED, 3);
        assert_eq!(STEAMAPI_INTERFACE_CHECK_OWNS_CONTENT2, 6);
        assert_eq!(STEAMAPI_INTERFACE_CHECK_OWNS_CONTENT, 7);
        assert_eq!(STEAMAPI_INTERFACE_GET_DLC_DOWNLOAD_PROGRESS, 22);
        assert_eq!(STEAMAPI_MATCHMAKING_GETLOBBYCHATENTRY, 27);
        assert_eq!(STEAMAPI_MATCHMAKING_CREATELOBBY, 13);
        assert_eq!(STEAMAPI_NETWORKING_READP2PPACKET, 2);
    }

    #[test]
    fn field_name_table_keeps_original_order() {
        assert_eq!(FIELD_NAMES.len(), 105);
        assert_eq!(FIELD_NAMES[0], c"targetlobby");
        assert_eq!(FIELD_NAMES[12], c"dlcbits");
        assert_eq!(FIELD_NAMES[54], c"dlcBits");
        assert_eq!(FIELD_NAMES[58], c"dlcBits");
        assert_eq!(FIELD_NAMES[104], c"addrbuff");
    }

    #[test]
    fn low_byte_truncates_like_c_byte_conversion() {
        assert_eq!(low_byte(0x110), 0x10);
        assert_eq!(low_byte(0xFF), 0xFF);
        assert_eq!(low_byte(-1), 0xFF);
    }
}
