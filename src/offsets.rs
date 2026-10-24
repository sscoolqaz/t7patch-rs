//! February-2026 RVAs for game functions and data.
//!
//! Port of the address macros in `offsets.h`. Each constant is a February-2026
//! RVA; resolve it with [`address`] so September builds are shifted correctly.

use crate::build;

/// Resolves a February-2026 RVA to a live address in the running executable.
pub fn address(february_rva: usize) -> usize {
    let base = build::image_base();
    base + build::live_rva(february_rva, build::current())
}

/// Reinterprets the address of `rva` as a function pointer of type `F`.
///
/// # Safety
///
/// `F` must be a `extern "system"` function pointer whose signature matches the
/// game function at `rva` in the running build.
pub unsafe fn function<F: Copy>(rva: usize) -> F {
    const { assert!(size_of::<F>() == size_of::<usize>()) };
    // SAFETY: the caller guarantees `F` is a function pointer of the game function at `rva`.
    unsafe { std::mem::transmute_copy(&address(rva)) }
}

pub const SCRVM_ERROR: usize = 0x12EA4E0;
pub const OFF_SCRVM_RUNTIME_ERROR: usize = 0x12EA450;
pub const SCRVM_FS: usize = 0x513DD30;
pub const LUA_CRASH1: usize = 0x1C9F121;
pub const LUA_CRASH1_RIP: usize = 0x1C9F2CE;
pub const LUA_CRASH2: usize = 0x221CEC3;
pub const LUA_CRASH3: usize = 0x221C726;
pub const SCR_VM_ERROR_STRING: usize = 0x52660F0;
pub const SCR_VMCONTEXT: usize = 0x5124850;
pub const INT3_2_BO3: usize = 0x1059;
pub const BO3_HWND: usize = 0x17DF74A0;
pub const ROP_RETN: usize = 0x1048;
pub const S_PLAYER_DATA_PTR: usize = 0x3390190;
pub const PTR_LOBBY_VM: usize = 0x157588D0;
pub const PTR_CL_DISPATCH_CONNECTIONLESS: usize = 0x134CDCD;
pub const PTR_NAME1: usize = 0x113A4970;
pub const PTR_NAME2: usize = 0x113A48F0;
pub const PTR_UPDATE_PRELOAD_IDLE_FN: usize = 0x32A75A8;
pub const PTR_LOBBY_MSG_RW_PACKAGE_INT: usize = 0x1EEA3E0;
pub const PTR_LOBBY_MSG_RW_PACKAGE_UCHAR: usize = 0x1EEA450;
pub const PTR_LOBBY_MSG_RW_PACKAGE_STRING: usize = 0x1EEA420;
pub const PTR_LOBBY_MSG_RW_PACKAGE_XUID: usize = 0x1EEA4D0;
pub const PTR_LOBBY_MSG_RW_PACKAGE_BOOL: usize = 0x1EEA2E0;
pub const PTR_LOBBY_MSG_RW_PACKAGE_UINT: usize = 0x1EEA490;
pub const PTR_LOBBY_MSG_RW_PACKAGE_SHORT: usize = 0x1EEA400;
pub const PTR_LOBBY_MSG_RW_PACKAGE_UINT64: usize = 0x1EEA470;
pub const PTR_LOBBY_MSG_RW_PACKAGE_ARRAY_START: usize = 0x1EEA260;
pub const PTR_LOBBY_MSG_RW_PACKAGE_ELEMENT: usize = 0x1EEA320;
pub const PTR_LOBBY_MSG_RW_PACKAGE_GLOB: usize = 0x1EEA3B0;
pub const PTR_DW_INSTANT_HANDLE_LOBBY_MESSAGE: usize = 0x143A7A0;
pub const PTR_PROBE_LOBBY_INFO: usize = 0x1EDA510;
pub const PTR_NET_OUT_OF_BAND_PRINT: usize = 0x211B310;
pub const PTR_DW_COMMON_ADDR_TO_NETADR: usize = 0x143C380;
pub const PTR_DW_REGISTER_SEC_IDAND_KEY: usize = 0x143E140;
pub const PTR_LOBBY_MSG_TANSPORT_SEND_OUT_OF_BAND: usize = 0x1EEC360;
pub const PTR_LOBBY_MSG_RW_PREP_WRITE_MSG: usize = 0x1EEA560;
pub const PTR_LOBBY_MSG_RW_PACKAGE_USHORT: usize = 0x1EEA4B0;
pub const PTR_LOBBY_SESSION_GET_SESSION: usize = 0x1EC1650;
pub const PTR_LOBBY_SESSION_GET_CLIENT_BY_CLIENT_NUM: usize = 0x1EF3FB0;
pub const PTR_LOBBY_SESSION_GET_CONTROLLING_LOBBY_SESSION: usize = 0x1EBFDA0;
pub const PTR_MSG_MUTABLE_CLIENT_INFO_PACKAGE: usize = 0x1EC8400;
pub const PTR_MSG_INIT: usize = 0x20FCB80;
pub const PTR_MSG_WRITE_STRING: usize = 0x20FFE20;
pub const PTR_MSG_WRITE_SHORT: usize = 0x211A2D0;
pub const PTR_MSG_WRITE_BYTE: usize = 0x20FF3C0;
pub const PTR_MSG_WRITE_DATA: usize = 0x20FF3E0;
pub const PTR_COM_CONTROLLER_INDEX_GET_LOCAL_CLIENT_NUM: usize = 0x20E3700;
pub const PTR_COM_LOCAL_CLIENT_GET_NETWORK_ID: usize = 0x20E3890;
pub const PTR_NET_OUT_OF_BAND_DATA: usize = 0x211B200;
pub const PTR_LOBBY_MSG_TRANSPORT_SEND_TO_ADR: usize = 0x1EEC740;
pub const PTR_MSG_READ_DATA: usize = 0x20FD0B0;
/// Upstream has `0x1EEA150`, which is the `call LobbyMsgRW_PrepReadData`
/// instruction 0x20 bytes into `LobbyMsg_HandleIM` (`0x1EEA130`), not the
/// function. Calling it ran the rest of `HandleIM` on the caller's frame and
/// crashed in `LobbyMsgRW_PackageUInt` (in-game runs 2, 9, 11 to 13). The
/// function, verified in a live September dump at `0x1EE9E30`, is `MSG_Init`,
/// then `msg+0x1c = size`, then a tail jump to `LobbyMsgRW_PrepReadMsg`.
pub const PTR_LOBBY_MSG_RW_PREP_READ_DATA: usize = 0x1EEA4F0;
pub const PTR_MSG_INFO_RESPONSE: usize = 0x1ED5B40;
pub const PTR_LOBBY_MSG_RW_PACKAGE_CHAR: usize = 0x1EEA300;
pub const PTR_LOBBY_MSG_RW_PACKAGE_FLOAT: usize = 0x1EEA390;
pub const PTR_DW_INSTANT_SEND_MESSAGE: usize = 0x143A830;
pub const PTR_DW_INSTANT_DISPATCH_MESSAGE: usize = 0x143A620;
pub const PTR_I_STRICMP: usize = 0x227CB20;
pub const PTR_CBUF_ADD_TEXT: usize = 0x20DFF50;
pub const PTR_LOBBY_SESSION_GET_CLIENT_NET_ADR_BY_INDEX: usize = 0x1EBFCC0;
pub const PTR_LOBBY_JOIN_RESERVE: usize = 0x1EDBA00;
pub const PTR_CL_GET_CONFIG_STRING: usize = 0x1321130;
pub const PTR_LIVE_FRIENDS_IS_FRIEND_BY_XUID: usize = 0x1DECFD0;
pub const STEAMAPI_STEAMUSER: usize = 0x10B3DC20;
pub const STEAMAPI_INTERFACE: usize = 0x10B3DC40;
pub const STEAMAPI_FRIENDS: usize = 0x10B3DC20;
pub const STEAMAPI_MATCHMAKING: usize = 0x10B3DC30;
pub const STEAMAPI_NETWORKING: usize = 0x10B3DC50;
pub const DW_LOBBY: usize = 0x9B35878;
pub const P_USER_DATA: usize = 0x14F344B0;
pub const P_NAME_BUFFER: usize = 0x15E056C8;
pub const OFF_S_RUNNING_UILEVEL: usize = 0x1686E99E;
pub const PTR_MSG_READ_BYTE: usize = 0x20FD050;
pub const PTR_LOBBYMSGPRINTS: usize = 0x156CE8D0;
pub const PTR_SAVE_LOBBY_MSG_EXCEPT_ADDY: usize = 0x1EEBF74;
pub const PTR_CMP_TOKENIZE_STRING_INTERNAL: usize = 0x20E2A3E + 0x3;

// Game RVAs used by `protection.rs` and `lua_symbols.rs`, from `offsets.h` and their C++ sources.
pub const NAME_BUFFER_SHADOW: usize = 0x15E84638;
pub const CREATE_LOBBY_AGAIN_FN: usize = 0x1EA6010;
pub const CREATE_LOBBY_AGAIN_ARG: usize = 0x113A4A60;
pub const DVAR_UI_ERROR_CALLSTACK_PTR: usize = 0x1686ED20;
pub const DVAR_G_ALLOWVOTE_PTR: usize = 0xA0378B8;
pub const DVAR_SET_FROM_STRING_BY_NAME: usize = 0x226B0A0;
pub const COM_SESSION_MODE_GET_MODE_NAME: usize = 0x20EAD00;
pub const CL_SWITCH_STATE_IDLE_UPDATE: usize = 0x131E350;
pub const CHARACTER_INDEX_CRASH_A: usize = 0x22C965C;
pub const CHARACTER_INDEX_CRASH_B: usize = 0x22C9676;
pub const CHARACTER_INDEX_RESUME: usize = 0x22C9686;
pub const RANDOM_SEED_GLOBAL: usize = 0x11250898;
pub const LUA_STATE_MANAGER_ERROR_RVA: usize = 0x1F05CE0;
pub const HKSI_LUA_GET_INFO_RVA: usize = 0x1D41500;
pub const HKS_OBJECT_TO_STRING_RVA: usize = 0x1D3F2F0;
pub const LUA_PUSH_LSTRING_RVA: usize = 0x0A18430;
pub const ACTIVE_MOD_NAME_RVA: usize = 0x1670DD84;
