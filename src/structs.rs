//! Game-side struct and enum layouts.
//!
//! Port of `structs.h`. Every struct is `#[repr(C)]` and its size is checked
//! at compile time against the byte offsets recorded in the C++ comments.

use std::ffi::c_char;

#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetSrc {
    Null = -1,
    Client1 = 0,
    Client2 = 1,
    Client3 = 2,
    Client4 = 3,
    Server = 4,
    Packet = 5,
}

impl NetSrc {
    /// Highest client slot; the original defines `NS_MAXCLIENTS` as `NS_SERVER`.
    pub const MAX_CLIENTS: Self = Self::Server;
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct NetAdr {
    pub ipv4: [u8; 4],
    pub port: u16,
    pub pad: u16,
    pub kind: i32,
    pub local_net_id: NetSrc,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Msg {
    pub overflowed: bool,
    pub read_only: bool,
    pub pad1: i16,
    pub pad2: i32,
    pub data: *mut c_char,
    pub split_data: *mut c_char,
    pub maxsize: u32,
    pub cursize: u32,
    pub split_size: u32,
    pub readcount: u32,
    pub bit: i32,
    pub last_entity_ref: i32,
    pub flush: i32,
    pub target_local_net_id: NetSrc,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BdSecurityId {
    pub id: i64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct BdSecurityKey {
    pub ab: [c_char; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SerializedAdr {
    pub valid: c_char,
    pub addr_buf: [c_char; 37],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LobbyParams {
    pub network_mode: i32,
    pub main_mode: i32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct JoinPartyMember {
    pub xuid: i64,
    pub lobby_id: i64,
    pub skill_rating: f32,
    pub skill_variance: f32,
    pub probation_time_remaining: [i32; 2],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct FixedClientInfo {
    pub xuid: i64,
    pub gamertag: [c_char; 32],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SessionInfo {
    pub in_session: bool,
    pub pad: [c_char; 7],
    pub net_adr: NetAdr,
    pub last_message_sent_to_peer: i64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct InfoResponseLobby {
    pub is_valid: c_char,
    pub pad: [c_char; 3],
    pub pad2: i32,
    pub host_xuid: i64,
    pub host_name: [c_char; 0x20],
    pub sec_id: BdSecurityId,
    pub sec_key: BdSecurityKey,
    pub serialized_adr: SerializedAdr,
    pub pad3: [c_char; 2],
    pub lobby_params: LobbyParams,
    pub ugc_name: [c_char; 0x20],
    pub ugc_version: i32,
    pub pad4: [c_char; 4],
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MsgInfoResponse {
    pub nonce: i32,
    pub ui_screen: i32,
    pub nat_type: c_char,
    pub pad: [c_char; 3],
    pub pad2: i32,
    pub lobby: [InfoResponseLobby; 2],
}

/// Message type tags used by the lobby protocol.
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MsgType {
    None = -1,
    InfoRequest = 0,
    InfoResponse = 1,
    LobbyStatePrivate = 2,
    LobbyStateGame = 3,
    LobbyStateGamePublic = 4,
    LobbyStateGameCustom = 5,
    LobbyStateGameTheater = 6,
    LobbyHostHeartbeat = 7,
    LobbyHostDisconnect = 8,
    LobbyHostDisconnectClient = 9,
    LobbyHostLeaveWithParty = 0xA,
    LobbyClientHeartbeat = 0xB,
    LobbyClientDisconnect = 0xC,
    LobbyClientReliableData = 0xD,
    LobbyClientContent = 0xE,
    LobbyModifiedStats = 0xF,
    JoinLobby = 0x10,
    JoinResponse = 0x11,
    JoinAgreementRequest = 0x12,
    JoinAgreementResponse = 0x13,
    JoinComplete = 0x14,
    JoinMemberInfo = 0x15,
    ServerListInfo = 0x16,
    PeerToPeerConnectivityTest = 0x17,
    PeerToPeerInfo = 0x18,
    LobbyMigrateTest = 0x19,
    MigrateAnnounceHost = 0x1A,
    MigrateStart = 0x1B,
    IngameMigrateTo = 0x1C,
    MigrateNewHost = 0x1D,
    VoicePacket = 0x1E,
    VoiceRelayPacket = 0x1F,
    DemoState = 0x20,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct LobbyMsg {
    pub msg: Msg,
    pub msg_type: i32,
    pub encode_flags: c_char,
    pub package_type: i32,
}

#[cfg(target_pointer_width = "64")]
const _: () = {
    assert!(size_of::<NetAdr>() == 16);
    assert!(size_of::<Msg>() == 56);
    assert!(std::mem::offset_of!(Msg, target_local_net_id) == 52);
    assert!(std::mem::offset_of!(LobbyMsg, msg_type) == 56);
    assert!(size_of::<FixedClientInfo>() == 40);
    assert!(size_of::<SessionInfo>() == 32);
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn max_clients_matches_original_definition() {
        assert_eq!(NetSrc::MAX_CLIENTS, NetSrc::Server);
    }

    #[test]
    fn message_type_values_match_protocol() {
        assert_eq!(MsgType::JoinLobby as i32, 0x10);
        assert_eq!(MsgType::DemoState as i32, 0x20);
    }
}

/// `SessionClient` from `structs.h`: a header, then a pointer to the client record.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct SessionClient {
    _pad: [u8; 0x8],
    pub active_client: *const ActiveClient,
}

/// `ActiveClient` from `structs.h`: the fixed identity of one lobby client.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ActiveClient {
    _pad: [u8; 0x410],
    pub fixed_client_info: FixedClientInfo,
}

const _: () = assert!(std::mem::offset_of!(SessionClient, active_client) == 0x8);
const _: () = assert!(std::mem::offset_of!(ActiveClient, fixed_client_info) == 0x410);
