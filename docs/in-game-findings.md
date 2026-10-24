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

## Next step

Run a Rust build with the hooks disabled (`T7PATCH_ONLY` without `hooks`). If it
survives past the window in which it usually crashes, the hooking layer
(`min_hook_rs` creating or enabling hooks) is implicated, and the next step is
to compare its live hook state with C MinHook's.
