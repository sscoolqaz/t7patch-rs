# Testing under Proton

How to run T7Patch-rs in Black Ops III on Linux under Proton, switch parts of
it off, and read what it logs. The results of the runs so far are in
[`in-game-run-log.md`](in-game-run-log.md).

## Game build

The runs used the September 2026 retail `BlackOps3.exe` (PE timestamp
`0x6A7B6355`, image size `0x1D75BC00`, Steam app 311210) under GE-Proton
(`GE-Proton11-9`, wine-staging 11.0). `src/build.rs` detects the build; the
February 2026 build is supported too but was not run.

## Loading the DLL

Build the DLL (`cargo build --release --target x86_64-pc-windows-gnu`) and
copy `target/x86_64-pc-windows-gnu/release/t7patch.dll` into the game folder.
The runs loaded it the way upstream's loader does: a `dsound.dll` proxy loads
`t7patchloader.dll`, which loads `t7patch.dll`, calls
`EnableInjectorlessInstall`, then `zbr_run_gamemode_lui("serious_anticrash_2023")`.
Proton must prefer the native proxy, so the launch options set a DLL override.

## Launch options

Steam launch options for a diagnostic run:

```
PROTON_LOG=1 WINEDEBUG=+timestamp,+pid,+tid,+debugstr,+loaddll,+seh WINEDLLOVERRIDES="dsound=n,b" %command%
```

- `WINEDLLOVERRIDES="dsound=n,b"` loads the proxy. Add any overrides the
  setup already needs (for example `dxgi=n,b;d3dcompiler_47=n`).
- `PROTON_LOG=1` writes the log to `$HOME/steam-<appid>.log`, so
  `$HOME/steam-311210.log` here (`PROTON_LOG_DIR` changes the directory).
- `+debugstr` shows the patch's own messages (`OutputDebugStringA`), all of
  which start with `T7 Patch`. `+loaddll` shows when `t7patch.dll` is mapped,
  `+seh` every exception, and `+timestamp,+pid,+tid` lets you line them up.
- `+seh` is heavy: Arxan raises hundreds of `int3` (`0x80000003`) exceptions
  per run, which is normal. Tracing slows that path, and it may be what
  triggers the intermittent execute fault described in the run log. For a
  plain play test, leave `WINEDEBUG` and `PROTON_LOG` out.

## Choosing components: `T7PATCH_ONLY`

Unset, the full patch is installed, as upstream does. Set `T7PATCH_ONLY` to a
comma-separated list (case-insensitive; unknown names are ignored) to install
only part of it. Proton passes launch-option variables through to the game, so
no rebuild is needed:

| Name | Installs |
|---|---|
| `arxan` | the Arxan integrity-check bypass |
| `dispatcher` | the exception dispatcher hook |
| `protection` | the protection patches |
| `create` | creates the `MinHook` detours without enabling them |
| `detours` | creates and enables the detours |
| `vmt` | the lobby VMT hook alone, independent of the detours |
| `hooks` | every hook stage: `create`, `detours` and `vmt` |
| `trace` | the diagnostic hook in `src/diag.rs`, plus trace lines from other modules |

`trace` is never part of the default set. It enables every hook that was
created. When the set differs from the default, the log shows
`T7 Patch: diagnostic components ...` with the parsed flags, so check that
line first. Typical sets used in the runs:

- `arxan,dispatcher,protection`: no hooks at all;
- `arxan,dispatcher,protection,create`: hooks built but not enabled;
- `arxan,dispatcher,protection,detours,trace`: detours with tracing, no VMT hook.

## Reading the output

### `crashes.log`

A fault the patch's handler treats as fatal is written to `crashes.log` in the
game folder (`steamapps/common/Black Ops III/`); a fatal script error also
shows a message box naming that file. Each entry has:

- `Game:`, the image base of `BlackOps3.exe` in that run;
- `Module:` and `Exception at (...)`, the faulting module's path and the
  fault's offset inside it, plus RIP and RSP;
- `Code:`, the exception code, and for an access violation `Access:` (0 read,
  1 write, 8 execute) and `Target:`;
- the code bytes around RIP, the registers, and a 0x2000-byte stack dump
  (upstream dumps 0x400), in absolute addresses.

To place a stack word, subtract the game's image base or `t7patch.dll`'s base
(from the Proton log or a memory map). An offset such as `t7patch+C71B` is only
meaningful for that exact DLL build, so keep the DLL that produced a log. Game
offsets are live RVAs. On the September build, a live RVA inside
`0x1D29C20 - 0x6C0 .. 0x2EFF000 - 0x6C0` is the February RVA minus `0x6C0`, so
add `0x6C0` to get the February RVA used in `src/offsets.rs`.

The handler runs in the `Wow64PrepareForException` slot, before Wine traces
the exception. A fault the patch handles therefore does not appear as a
`c0000005` line in the Proton log, only in `crashes.log`.

### Trace lines

With `trace` on, lines starting `T7 Patch trace` appear in the Proton log
under `+debugstr`:

- `T7 Patch trace 0x1EEA130 call N: rcx=... rdx=... r8=... r9=... rsp=... stack ...`
  logs a call to `LobbyMsg_HandleIM` (February `0x1EEA130`): the first few
  calls, and every call with NULL data. The stack words start with the return
  address.
- `T7 Patch trace info-check: xuid=<sender> keep|DROP reason=<r> detail=<d>`
  logs each verdict of `protection::check_pending_info_requests`. Reasons:
  `size`, `not-installed`, `overflowed`, `prep-read-failed`,
  `info-response-rejected` (detail is the parser code below),
  `info-response-handled`, `local`, `not-friends-only`,
  `server-or-splitscreen`, `friend` and `not-a-friend`. While hosting, a
  healthy lobby shows the local player's own `keep reason=local` and
  `DROP reason=info-response-handled` pair every few seconds. `DROP` here means
  the message is consumed by the patch, not discarded.

Parser codes from `msg_info_response_safe`: 1, a header field (`nonce`,
`uiscreen`, `nattype`) was unreadable; 2, a lobby's `valid` bool was
unreadable; 3, a lobby field was unreadable; 4, a third outer element or an
overflowed message; 5, a third inner element.

### Counting faults in the Proton log

```bash
grep -c 'code=c0000005' "$HOME/steam-311210.log"
grep -c 'code=80000003' "$HOME/steam-311210.log"
grep 'T7 Patch' "$HOME/steam-311210.log"
```

A healthy run has no `c0000005` and several hundred `80000003` (Arxan). The
exact `+seh` line format varies between Wine versions; adjust the pattern if
these find nothing.

## Capturing live game memory

The on-disk `BlackOps3.exe` is Arxan-encrypted, so a disassembler shows
ciphertext at most addresses. The decrypted image can be read from the live
process through `/proc/<pid>/maps` and `/proc/<pid>/mem`.

Reading another process's memory needs ptrace access. With Yama's default
`kernel.yama.ptrace_scope=1`, only an ancestor of the game may read it, which
a separate shell is not. Either run the capture as root, or lower the scope
for the session (`sysctl kernel.yama.ptrace_scope=0`, as root) and restore it
afterwards. Lowering it lets any of your processes read any other; do it only
while capturing.

Two helpers live in [`tools/`](../tools):

- [`tools/gamepid.sh`](../tools/gamepid.sh) prints the pid of the real game
  process. `pgrep -f BlackOps3.exe` also matches Proton's launcher wrapper, so
  the script picks the pid whose maps contain the exe. `GAME_EXE` overrides
  the exe name.
- [`tools/capture_hooks.py`](../tools/capture_hooks.py) waits for a new game
  process with `t7patch.dll` mapped, sleeps, checks it is still the same
  process, then saves the memory map and the live bytes of the hooked lobby
  functions, the hook relay and trampoline, and the first 16 bytes of every
  constant in `src/offsets.rs` (`offset_prologues.json`). That last file shows
  whether each constant is a function start or a site inside a function; it is
  how the PrepReadData bug was found. It needs `llvm-nm` to find the
  trampoline slot in the DLL, and the DLL given must be the exact file in the
  game folder.

```bash
tools/capture_hooks.py --dll "<game dir>/t7patch.dll" --offsets src/offsets.rs --out capture --delay 25
```

Start it before launching the game. Pass `--current` to capture a game that is
already running. The addresses it reads are live September RVAs.
