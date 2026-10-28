# Differences from upstream

T7Patch-rs is a Rust fork of
[Scroptss/T7Patch-src](https://github.com/Scroptss/T7Patch-src), based on
commit `16b9b50662c68149526039cdf2ebdad348b9ca70`. Most of it is a direct port.
This page lists every place it departs from upstream on purpose, and every
upstream bug the in-game runs found, each with its evidence. Run numbers refer
to [`in-game-run-log.md`](in-game-run-log.md).

Addresses are February 2026 RVAs unless marked live; live addresses are from
the September 2026 build, where code in `0x1D29C20..0x2EFF000` moved by
`-0x6C0`. "Disassembled live" means read from the decrypted image of a running
game (see [`testing-under-proton.md`](testing-under-proton.md)), because the
exe on disk is Arxan-encrypted.

## What matches upstream

- The Arxan bypass: patterns, counts, key and ready-signal maintenance.
- Address translation: upstream's `REBASE` and `OFFSET` both map to
  `build::live_rva`.
- Install order: prepare, dispatcher, protection, activate, worker.
- Exception-handler order: marker, fix-up list, fatal path.
- The hook bodies, apart from the fixes below.

The main structural difference is the hooking library. Upstream links C
MinHook; this port uses `min_hook_rs`, vendored with fail-closed freeze
patches. A Wine test placed the live prologues of all 47 hooked functions in
executable memory and built trampolines with it: every relocation was correct
(RIP-relative `lea`/`cmp`, a `jne` rewritten as an inverted `je` plus an
absolute jump, and a relative `call`).

Eligible relocated prologues now have dynamic x64 unwind metadata (vendored
patch 17). Unknown or untranslatable original metadata preserves compatibility
without registering a table. Native lookup/virtual unwind can cross those
trampolines; the tested Windows fast `RtlCaptureStackBackTrace` implementation
still stops at dynamic code. The complete eligibility, lifetime rules and
Wine/Windows evidence are in
[`VENDORED.md`](../vendor/min_hook_rs/VENDORED.md#known-limits).

## Upstream bugs found in game

### `LobbyMsgRW_PrepReadData` pointed into `LobbyMsg_HandleIM`

Upstream's `offsets.h` has `REBASE(0x1EEA150)` for PrepReadData. That address
is not a function. It is the `call LobbyMsgRW_PrepReadData` instruction 0x20
bytes into `LobbyMsg_HandleIM` (`0x1EEA130`, live `0x1EE9A70`).
`check_pending_info_requests` called it for packet type `0x68`. The `call` ran
the real PrepReadData with our arguments, then the rest of `HandleIM` ran on
our stack frame: it took a stack slot as its LobbyMsg (with NULL data) and
another as message type 0, then called `LobbyMsgRW_PackageUInt`, which read
through the NULL pointer.

Evidence: runs 2, 9, 11, 12 and 13 crashed at the same live RVA `0x20FC9CF`
(the byte reader under PackageUInt) with identical registers (data NULL, size
`0x16`, cursor 0). A trace hook on `HandleIM`'s entry recorded no call even
though its body was on the crash stack (run 12). A 0x2000-byte stack dump put
the return point of `check_pending_info_requests` above the frame (run 13).
Disassembled live, the real function is at live `0x1EE9E30` (February
`0x1EEA4F0`): it calls `MSG_Init` (`PTR_MSG_INIT`, `0x20FCB80`), stores the
size at `msg+0x1c`, and tail-jumps to `LobbyMsgRW_PrepReadMsg` (`0x1EEB8D0`).
`PTR_LOBBY_MSG_RW_PREP_READ_DATA` is now `0x1EEA4F0`. Run 14 survived past the
old crash window, and the same sender's messages reached `HandleIM` through
its entry. A prologue audit of all constants in `src/offsets.rs` found no
other call site; the constants without a usual prologue are data, deliberate
mid-function patch sites, or leaf functions.

### Upstream's `CheckPendingInfoRequests` is effectively a no-op

Upstream copies a `msg_t` out of the raw payload pointer instead of the
message. Its size is then usually garbage, and it returns before reaching
PrepReadData or the info-response parser. That is why upstream never hit the
bug above, and why the C++ build reached a lobby in the comparison run. This
port builds a proper local `msg`, which made the path reachable: only runs
with enabled detours crashed.

### `dwInstantHandleLobbyMessage` takes a `msg_t`

On a valid info response, upstream passes the raw payload pointer to
`dwInstantHandleLobbyMessage`. Disassembled live, its body (`0x143A7A0`)
treats the third argument as a `msg_t`: it copies `cursize - readcount` bytes
(at most 0x800) with `MSG_ReadData`, then, unless the message overflowed,
calls `LobbyMsg_HandleIM(controller, sender, buf, size)`. With the raw payload
it read a garbage size, and hosting failed (run 17). The port now passes the
caller's `msg`, still positioned after the IM header, because the inspection
only reads a copy. Upstream never reaches this line (see above). Run 18
confirmed that hosting works.

### The `lobbies` array is nested

The info response's `lobbies` array is nested, as upstream decompiled it. An
earlier version of this port rewrote it as a flat array, which was wrong: it
read the inner element marker as the `valid` bool and rejected the local
player's own info response with code 2, so hosting failed (run 15).

Disassembled live, `MSG_InfoResponse` (`0x1ED5B40`, live `0x1ED5480`) reads
`nonce`, `uiscreen` and `nattype`, starts the `lobbies` array, and reads up to
two outer elements, each with a helper (live `0x1ECE5B0`, captured in run 16).
The helper starts a nested `lobbies` array and reads up to two inner elements
into the **same** output slot: `valid`, then, when it is set, `hostxuid`,
`hostname` (0x20), `networkmode`, `mainmode`, `secid` (8), `seckey` (0x10),
`addrbuff` (0x25), `ugcName` (0x20) and `ugcVersion`. Upstream's loop,
including writing `lobby[cResponse]` twice, is therefore faithful. In read
mode (`[lm+0x40] == 2`) `PackageElement` ignores its flag, so upstream's
always-`true` flags are harmless; read-mode `ArrayStart` does consume input.
The parser is now `read_info_lobbies`, a port of upstream's loop, and run 17
parsed the local player's response.

## Deliberate departures

### Info-response strictness codes

The game's reader stops quietly after two elements of either kind. Like
upstream, `msg_info_response_safe` rejects the response instead: code 5 for a
third inner element, code 4 for a third outer element or an overflowed
message. Code 1 is an unreadable header field, 2 an unreadable `valid`, and 3
an unreadable lobby field. Fewer elements are accepted, as the game accepts
them.

### The lobby password prefix gates every set password

Upstream appends the two prefix bytes (bits 16..24 and 24..32 of the password
hash) only when the first byte is non-zero, and its reader skips the check
the same way. A zero first byte doubled as "no password", so about 1 in 256
passwords turned the check off. `zbr_prefix` now returns `None` only when no
password is set (hash 0), and any set password writes and checks both bytes.
For those 1-in-256 passwords, a lobby with this port and upstream peers
won't agree: upstream sends no prefix and this port expects one.

### Overflowed instant messages are not dispatched

The `dwInstantDispatchMessage` detour copies the payload with `MSG_ReadData`
and then calls `LobbyMsg_HandleIM`. Upstream dispatches even when the read
overflowed. `dispatch_im_payload` now returns 0 instead, as the game's own
`dwInstantHandleLobbyMessage` does.

### `__report_gsfailure` is not hooked

Upstream hooks `__report_gsfailure` to catch MSVC `/GS` stack-cookie
failures. A Rust-only DLL has no `/GS` checks, so the hook is not ported.

### State retained after unload

Unload restores the hooks, but two kinds of state stay:

- The exception dispatcher is retained for the process lifetime once an
  induced-exception patch (the lobby marker or the `IsProcessorFeaturePresent`
  detour) has been live. On the Wine stub layout the stub is kept while it
  cannot be restored yet (a thread is in or returning into it, or the guarded
  write fails); it stays until a later successful install and Unload restores
  it. The DLL pins
  itself when the dispatcher is installed, so Unload is logical deactivation.
- The dvar settings changed at install (`ui_error_callstack_ship`,
  `g_allowvote`, `maxvoicepacketsperframe`) are not restored, because that
  needs a verified dvar finder address.

### The `IsProcessorFeaturePresent` import slot is 4-byte aligned

The game's IAT slot sits at RVA `0x1AA69E94` in `.idata`, which is only 4-byte
aligned. Upstream writes it with `VirtualProtect` plus `memcpy`. The port
swaps pointer slots with a compare-and-swap, and at first refused any slot
that was not 8-byte aligned, so install failed (run 1). It now uses an inline
`lock cmpxchg`, which x86 does atomically inside one cache line, and falls back
to upstream's plain write for a slot that crosses a cache line.

### Larger crash-log stack dump

Upstream dumps 0x400 bytes of stack (0x1200 for an illegal instruction). The
port dumps 0x2000 for every fault, which was needed to reach the frames above
a 2048-byte stack buffer in run 13.

## Open

- `MAX_SCRIPT_VMS = 2` comes from the engine enum and was not checked against
  the Arxan-encrypted binary.
