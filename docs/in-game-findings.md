# In-game findings: first runs (2026-10-23)

These are the first runs of this port inside Black Ops III. The game ran under
Proton-GE-git (`GE-Proton11-9`, wine-staging 11.0) on Linux. This note records
what the runs showed, what is fixed, and what is still open.

## Setup

- Game: `BlackOps3.exe`, September 2026 retail (PE timestamp `0x6A7B6355`,
  image size `0x1D75BC00`), Steam app 311210.
- Load chain: `dsound.dll` (proxy) loads `t7patchloader.dll`, which loads
  `t7patch.dll` and calls `EnableInjectorlessInstall`, then
  `zbr_run_gamemode_lui("serious_anticrash_2023")`.
- Launch options:
  `PROTON_LOG=1 WINEDEBUG=+timestamp,+pid,+tid,+debugstr,+loaddll,+seh` placed
  before the usual
  `WINEDLLOVERRIDES="dxgi=n,b;d3dcompiler_47=n;dsound=n,b" sh -c 'xrandr --output DP-1 --primary; exec "$@"' -- %command%`.
  The log goes to `~/steam-311210.log`.
- Reference: the DLL that was in the game folder before this work, saved as
  `t7patch.dll.pre-083656f.bak` (mingw, stripped, from an earlier Rust port with
  no surviving source). It reaches a lobby.

## Dispatcher layout on this Proton

On this Proton build, `KiUserExceptionDispatcher` has the Windows layout:
`cld; mov rax, [Wow64PrepareForException]; ...; call rax; ...; call
dispatch_exception`. Its first word matches `KI_DISPATCH_PTR_PATTERN`, so the
patch installs its handler into the `Wow64PrepareForException` slot
(`install_pointer_hook`). The Wine stub layout is not used here.

## Run log

| Run | DLL | Result |
|---|---|---|
| 1 | `083656f` | Install failed: `cannot write the IsProcessorFeaturePresent import`. After rollback, about 23 s later: execute AV at `0x700004541BB0` (unmapped), then the game's own fail-fast `c0000409`. |
| 2 | `2aba7a2` | Installed silently. About 42 s later: fault at game live RVA `0x20FC9CF`, inside the original `LobbyMsgRW_PackageUInt` called from our hook (`t7patch.dll+0xC158`). Logged by our handler. |
| 3 | `2aba7a2` | About 3 s after load: AV in Wine `ntdll+0x4A7CD` (`dispatch_exception`). |
| 4 | `d3ec07b` (no thread freezing) | Same as run 3. The log has 1438 `c0000005` faults: 1 execute AV at `0x7000228F5B70`, plus 1437 recursive faults at `ntdll+0x4A7CD`. |
| ref | old DLL | Reached a lobby. Zero `c0000005`; 631 `0x80000003` (Arxan int3), which is normal. |
| 5 | `2aba7a2` | Execute AV at `0x7000224CA8A0` (unmapped) on the main thread. |
| 6 | `2aba7a2` | Execute AV at `0x7000225BDEF0`. A memory-map snapshot of the real game process shows the address unmapped, with nothing mapped within 256 MB. |
| ref 2 | old DLL | **Same crash**: execute AV at `0x7000224F3980` (image base + `0x42803980`), logged by the old DLL's own handler. The first reference run only survived because the game was quit at the lobby. |
| C++ | upstream `T7Patch-src` (MSVC, `t7patch.dll.bak`) | Reached a lobby; quit by the user after 64 s. Zero `c0000005`; 651 Arxan int3, which is normal. |
| 7 | `6f44075`, `T7PATCH_ONLY=arxan,dispatcher,protection` (hooks off) | The log confirms `hooks: false`. Ran 148 s after load and was quit by the user. Zero `c0000005`, zero `c0000409`, 1576 Arxan int3. Nothing written to `crashes.log`. |
| 8 | `eabdd62`, `T7PATCH_ONLY=arxan,dispatcher,protection,create` | The log confirms `create_hooks: true, enable_hooks: false, vmt_hook: false`. Ran 211 s after load, then exited cleanly. Zero `c0000005`, zero `c0000409`, 1800 Arxan int3. Nothing written to `crashes.log`. |
| 9 | `eabdd62`, `T7PATCH_ONLY=arxan,dispatcher,protection,detours` | The log confirms `enable_hooks: true, vmt_hook: false`. 38 s after load our handler logged a fatal fault at live RVA `0x20FC9CF` and terminated the process. The registers and stack match run 2 exactly. Wine logged no `c0000005`, because the handler runs in the `Wow64PrepareForException` slot before Wine traces the exception. |
| 10 | `d2ac9e4`, `detours` | Died about 1.5 s after `prepare` began. The execute AV at `0x70002250BDD0` (base + `0x4281BDD0`) came 0.28 s after `t7patch.dll` was mapped and 1.7 s **before** `prepare` ran. See "The execute fault is not caused by our patching". |
| 11 | `d2ac9e4`, `detours` | 54 s after load: the same fault as runs 2 and 9, with identical registers. The new log fields show a read AV at address 0. Live hook bytes were captured about 25 s in. |
| 12 | `9bf9835`, `detours,trace` | The log confirms `trace: true` and the trace hook was created. 40 s after load: the same PackageUInt fault, the fourth time. The trace hook on `LobbyMsg_HandleIM` logged **no** calls, although its body was on the crash stack. |
| 13 | `8715fa0`, `detours,trace` | 32 s after load: the same fault, the fifth time. The 0x2000-byte stack dump shows `t7patch+C71B` above the zeroed buffer: the return point of `protection::check_pending_info_requests` in `hk_dw_instant_dispatch_message`. The live capture shows the trace hook's `jmp` in place at `HandleIM`'s entry. Root cause found (see "Root cause: PrepReadData pointed into HandleIM"). |
| 14 | `7cc3f5a` (PrepReadData fix), `detours,trace` | Ran 93 s after load and shut down cleanly (modules unloaded, NvAPI session destroyed). Zero `c0000005`, no `crashes.log` entry, 659 Arxan int3 (the C++ run had 651). The trace hook logged two `HandleIM` calls from our IM detour (`t7patch+C7DF`) with a valid stack buffer and size `0x14`, from the same sender that used to crash. |
| 15 | `cee873f` (verdict trace), `detours,trace` | The user could click into a lobby, but hosting failed. Our own client's info response was dropped: `info-check: xuid=<local-xuid> DROP reason=info-response-rejected detail=2`. Code 2 is a failure to read the `valid` bool of the first lobby element. The sender is the local player (P_USER_DATA). Exited after 80 s with zero `c0000005`. |

## Findings

### Fixed: the IAT slot is only 4-byte aligned (`2aba7a2`)

The game's `IsProcessorFeaturePresent` IAT slot sits at RVA `0x1AA69E94` in
`.idata`, so it is 4-byte aligned, not 8. The F07 `swap_usize` refused any
slot that was not 8-byte aligned. Upstream writes it with `WritePatchMemory`
(`VirtualProtect` plus `memcpy`) and has no alignment requirement.
`swap_usize` now uses an inline-asm `mov` and `lock cmpxchg`, which x86 does
atomically for an access inside one cache line. A slot that crosses a cache
line falls back to upstream's plain write.

### Open: an execute fault at image base + about `0x428xxxxx`

Every crashing run, with new builds, pre-freeze builds **and the old working
DLL**, has one thread jump to an unmapped address. Since the old DLL does it
too, the crash is not caused by this port's changes. It is intermittent:
whether a run reaches a lobby depends on timing. Relative to that run's image base:

| Run | Fault address | Minus image base |
|---|---|---|
| 1 | `0x700004541BB0` | `+0x427C1BB0` |
| 4 | `0x7000228F5B70` | `+0x42C05B70` |
| 5 | `0x7000224CA8A0` | `+0x4280A8A0` |
| 6 | `0x7000225BDEF0` | `+0x428FDEF0` |
| ref 2 (old DLL) | `0x7000224F3980` | `+0x42803980` |

The image is `0x1D75BC00` bytes, so these targets lie far beyond it. In
runs 4 and 6 the faulting thread had just been through Arxan's own vectored
handlers, at `BlackOps3.exe+0x1C19E352`, `+0x1C18908B` and `+0x...771E4`. Those
handlers return `EXCEPTION_CONTINUE_EXECUTION`, so Arxan sets RIP from its
handler. A computed target that is consistently "base + a near-constant
offset" fits Arxan's checksum-keyed control flow: a jump target derived from
an integrity checksum that comes out wrong because code it covers was changed.

The first hypothesis was that this port changes a byte covered by an Arxan
check that the old DLL leaves alone. The old DLL's crash rules out a
port-only cause. Remaining candidates:

- an Arxan check that both T7Patch ports trip, intermittently, on this game
  build. Upstream T7Patch has the same three checksum patterns and the same
  hooks;
- an interaction between Arxan's VEH-driven control flow and something both
  T7Patch ports do. The vanilla game runs fine on this setup (per the user;
  not logged), so the game and Proton alone are not the cause.

### Secondary: Wine's VEH list walk faults recursively

In runs 3 and 4, a second thread faulted in Wine's `dispatch_exception` while
walking `vectored_exception_handlers`. The current entry was NULL, giving a
read of `[0+0x10]`. Dispatching that fault walks the same list again, which
causes the 1437-fault storm. It starts in the same millisecond as the execute
fault, and only in crashing runs, so it is most likely a consequence of the
broken Arxan state, not an independent bug.

### Noted, not yet acted on

- The crash log does not record the exception code. `dump_exception` takes it
  but never prints it.
- With `ptrace_scope=0`, `/proc/<pid>/maps` and `/proc/<pid>/mem` give a
  decrypted image. The on-disk exe is Arxan-encrypted: Ghidra's
  `BlackOps3.exe` shows ciphertext at the fault sites.
- `pgrep -f BlackOps3.exe` also matches a launcher wrapper. Pick the pid whose
  maps contain `BlackOps3.exe`.

### Image diff (inconclusive)

There are decrypted dumps of a crashing run with the new build (1.5 s after
load) and of a run with the old DLL (1.5 s and 16.5 s after load). After
normalizing DIR64 relocations, the first `.text` differs in 778 stable byte
groups and the second `.text` (Arxan) in 232. Almost all are scattered 2- to
4-byte values that look like Arxan runtime state, not patches. Bytes that also
changed between the two old-DLL dumps were left out. Because the old DLL
crashes too, these diffs cannot isolate a cause.

## Comparison with upstream `T7Patch-src`

The Rust port matches upstream in:

- the Arxan bypass: patterns, counts, key and ready-signal maintenance;
- address translation: `REBASE` = `OFFSET` = `get_live_rva`;
- install order: prepare, dispatcher, protection, activate, worker;
- exception-handler order: marker, fix-up list, fatal path.

The main structural difference is the hooking library. Upstream links C MinHook
(`minhook/lib/libMinHook.x64.lib`), while both Rust ports use `min_hook_rs`.

A Wine test placed the real prologues of all 47 hooked functions, taken from
the decrypted dump, into executable memory and built trampolines with the
vendored `min_hook_rs`. Every relocation was correct: the RIP-relative
`lea`/`cmp` instructions, `jne` (rewritten as an inverted `je` plus an
absolute jump) and the relative `call`. MinHook's buffer in the game is a
single RWX page at image base - `0x10000`. No bad jump target lies in any
buffer or module.

### Hooks off survives (run 7)

With the Arxan bypass, the dispatcher and protection installed but no hooks
created or enabled, the game ran 148 s with no fault. That is about 3.5 times the
longest crash delay seen so far (42 s). This is one run of an intermittent
crash, so it is strong but not conclusive. It puts the cause in the hook
stage: `min_hook_rs` creating or enabling hooks, the VMT hooks, or the hook
bodies themselves.

### Creating hooks without enabling them survives (run 8)

`T7PATCH_ONLY` can split the hook stage: `create` builds the `MinHook`
detours without enabling them, `detours` builds and enables them, and `vmt`
applies the lobby VMT hook alone. With `create`, the game ran 211 s with no
fault. Building trampolines, allocating the hook buffer and running
`ffi::initialize` are therefore not the trigger. What is left is enabling the
detours or the VMT hook. Enabling covers the vendored `transact`, its thread
freeze and RIP moves, the prologue writes, and the hook bodies running.

### Enabled detours fault through `LobbyMsgRW_PackageUInt` (runs 2 and 9)

Runs 2 and 9 crashed at the same place, with identical registers (`Rcx=1`,
`Rdx=0x16`, `Rax=0`) and stack. The fault is at live RVA `0x20FC9CF`, with
the return address `game+0x1EEA9C5` at RSP. Deeper in the stack is
`t7patch+0xBCE8` (`t7patch+0xC158` in run 2's build). That address is the
return point after `call *ORIG_PACKAGE_UINT` in
`hk_lobby_msg_rw_package_uint`. So the detour had called the trampoline, and
the original `LobbyMsgRW_PackageUInt` was running when the fault happened.
The game frames above the detour are `+0x1EE214B`, `+0x1EE9E45` and
`+0x1EE9B1B`. The hook body matches upstream's `hkLobbyMsgRW_PackageUInt`,
and upstream treats the same fault as fatal, so the C++ build never reaches
this fault.

This crash is deterministic. The execute fault at base + `0x428xxxxx` is
intermittent, and it did not occur in run 9. Whether the two share a cause is
open.

Run 11 reproduced it a third time. The extended crash log gives
`c0000005`, read, target `0`. Live bytes captured with
`t7patch-debug/scripts/capture_hooks.py` show:

- **The trampoline is correct.** The entry `jmp` at live `0x1EE9DD0` stole
  exactly `mov eax,[rcx+0x40]; test eax,eax` (5 bytes). The trampoline runs
  those two instructions, then `jmp [rip]` back to `0x1EE9DD5`, whose `jne`
  uses the preserved flags. The relay is in the RWX page at image base -
  `0x10000`.
- **`LobbyMsgRW_PackageUInt`** checks the mode at `msg+0x40`. Mode 0 returns,
  mode 1 tail-jumps to the writer at live `0x1EEB030`, and any other mode
  tail-jumps to the reader at live `0x1EEA9A0`. The reader calls the byte
  reader at live `0x20FC990`.
- **The byte reader** loads `movzx eax, byte [msg->data + msg->cursor]`, with
  `data` at `msg+8`, the first buffer's size at `msg+0x1c` and the cursor at
  `msg+0x24`. At the fault, `data` is NULL, the size is `0x16` and the
  cursor is 0. The faulting instruction is at `0x20FC9CF`.
- **The caller** is a game function at live `0x1EE9A70` (Feb `0x1EEA130`),
  `F(ecx, rdx, data = r8, size = r9d)`. It builds the LobbyMsg on its own
  stack through live `0x1EE9E30` (Feb `0x1EEA4F0`). When the message type at
  `msg+0x38` is 0, it calls `PackageUInt(&msg, key@0x2FA0248, &local)`.

So `F` was handed a NULL buffer with a size of 22 bytes, and the original
reader faults on it whether or not it is hooked. Our detour only passes the
message through. `F`'s caller is not visible: past `F`'s frame the stack holds
encoded values (Arxan call obfuscation), not return addresses. Every string `F`
uses is encrypted on disk. `F` is `LobbyMsg_HandleIM` (`offsets.h`: `OFFSET(0x1EEA130)`), with the
signature `(targetController, senderXuid, buff, len)`. Our
`hk_dw_instant_dispatch_message` calls it, as upstream does, with a zeroed
2048-byte stack buffer, so that call cannot pass NULL. The sender XUID in
`F`'s frame is a real Steam ID (`0x<local-xuid>`). Everything above `F`'s
frame, as far as the 0x400-byte dump reaches, is zeros: a large zeroed local
buffer like that detour's. In run 12 the trace hook on `F`'s entry recorded
no call at all, so the crashing call did not pass through `F`'s entry
`jmp`. Either the entry bytes were no longer patched, or execution entered
`F` past its entry. The crash log now dumps 0x2000 bytes of stack (upstream
dumps 0x400) to reach the frames above that buffer. The capture script also
reads `F`'s live entry bytes. Still open: why only enabled-detour runs hand
`F` a NULL buffer. Candidates are a Rust detour on an outer path passing a wrong
argument or return value, or the C++ run never having reached the same event.

### Root cause: PrepReadData pointed into HandleIM (fixed)

`PTR_LOBBY_MSG_RW_PREP_READ_DATA` was `0x1EEA150`, copied from upstream
(`offsets.h`: `REBASE(0x1EEA150)`). That address is not a function. It is the
`call LobbyMsgRW_PrepReadData` instruction 0x20 bytes into
`LobbyMsg_HandleIM` (`0x1EEA130`; live `0x1EE9A70` + 0x20 = `0x1EE9A90`).
`check_pending_info_requests` called it for packet type `0x68`. The `call`
ran the real PrepReadData with our arguments, then the rest of `HandleIM`
ran on our stack frame. It took our `[rsp+0x30]` as its LobbyMsg (NULL
data) and `[rsp+0x68]` as message type 0, then called PackageUInt, which
faulted. That explains the invisible caller, the garbage return slot, and
why the trace hook on `HandleIM`'s entry never fired.

The real function is at live `0x1EE9E30`, which is Feb `0x1EEA4F0`. It calls
`MSG_Init` (live `0x20FC4C0`, which is Feb `0x20FCB80` = `PTR_MSG_INIT`),
stores the size at `msg+0x1c`, and tail-jumps to `LobbyMsgRW_PrepReadMsg`
(live `0x1EEB210`, which is Feb `0x1EEB8D0`). The constant is now `0x1EEA4F0`.
A Codex review agreed.

Upstream has the same wrong constant, but rarely reaches it. Its
`CheckPendingInfoRequests` copies a `msg_t` out of the raw payload pointer.
So its size is usually garbage, and it returns before PrepReadData. Our port
builds a proper local `msg`, which made the path reachable. That is why only
enabled-detour runs crashed.

The capture script now also saves the first 16 live bytes of every constant
in `src/offsets.rs` (`offset_prologues.json`). Any other constant that points
into a function body can be found the same way.

### Hosting fails: our info-response parser rejects the game's own format (run 15)

Upstream's `CheckPendingInfoRequests` never parses an info response, because of
the garbage size (see above). Ours does, and drops the message when
`msg_info_response_safe` fails. While hosting, the local client sends itself
an info response, and run 15 dropped it with code 2 (`valid` unreadable).

The game's own reader, `MSG_InfoResponse` (Feb `0x1ED5B40`, live
`0x1ED5480`), disassembled live:

```
PackageUInt("nonce"); PackageInt("uiscreen"); PackageUChar("nattype")
ArrayStart("lobbies")
i = 0; more = PackageElement(lm, true)
while more && i < 2:
    if ok: ok = read_lobby(&info->lobby[i], lm)   // live 0x1ECE5B0
    i += 1
    more = PackageElement(lm, i < 2)
return ok
```

So the array is flat, with zero, one or two elements and no second
`ArrayStart`. Upstream's nested loop does not model it. Our `read_lobby_pair`
differs as well: it requires exactly two elements, rejects a third, and
passes `true` on the final `PackageElement` call where the game passes
`false`. The per-lobby fields come from upstream, starting with a `valid`
bool, and code 2 shows that they do not match the helper at live
`0x1ECE5B0`. Its body is captured on the next run.

### The execute fault is not caused by our patching (run 10)

In run 10 the loader thread mapped `t7patch.dll` at 83191.746, then made no
call into it for exactly 2.0 s (the same 2.0 s gap as run 9), until `prepare`
at 83193.747. Our `DllMain` only calls `DisableThreadLibraryCalls`. A game
thread created at 83192.002 took Arxan int3s at once. Arxan's VEH handlers,
inside the exe image, returned `EXCEPTION_CONTINUE_EXECUTION`. At 83192.027
the thread executed at the unmapped `0x70002250BDD0`. No patch of ours was
installed then. So the base + `0x428xxxxx` fault is not caused by anything the
DLL patches. It is inherent to the game under this Proton, induced by an
extra module being loaded, or a side effect of `+seh` tracing slowing
Arxan's int3/VEH flow (for example, tripping a timing check). A Codex review
agreed, and ranked tracing first and module presence last, since runs 7 and 8
loaded the same DLL without faulting.

## Next step

- Run 14 confirmed the fix: the same sender's messages now reach
  `HandleIM` through its entry, and the game survived past the old crash
  window. The prologue audit of all 92 constants in `src/offsets.rs` found
  no other call site. The 44 constants without a usual prologue are data,
  deliberate mid-function patch sites, or leaf functions whose first
  instructions handle their arguments.
- Next, run the full patch (`T7PATCH_ONLY` unset), which adds the VMT hook,
  ideally to a lobby.
- Superseded by the fix: repeat what was done in-game in the 38 to 54 s window of runs
  2, 9 and 11 with the C++ build, to see whether upstream also receives the
  NULL-buffer message. Then look for the outer detour that differs: candidates
  are the lobby/IM dispatch hooks (`dwInstantDispatchMessage`,
  `LobbyMsgRW_PrepReadMsg`, `Sys_VerifyPacketChecksum`). `F`'s caller can be
  found by hooking `F` (Feb `0x1EEA130`) for diagnosis and logging its return
  address and arguments.
- Execute fault: run the vanilla game three or four times with the same
  `+seh` logging, and the full patch three times without `+seh`.
- The `vmt` run is still to do.
