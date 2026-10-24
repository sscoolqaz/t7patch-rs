# In-game run log

The runs of this port inside Black Ops III so far, all on 2026-10-23, under
GE-Proton (`GE-Proton11-9`, wine-staging 11.0) on Linux with the September 2026
build. How the runs were set up and how to read their output is in
[`testing-under-proton.md`](testing-under-proton.md). The bugs they found are
explained in [`upstream-differences.md`](upstream-differences.md).

Result in short: the full patch hosts a lobby and plays rounds (run 19). It is
untested on Windows.

## Runs

"Components" is the `T7PATCH_ONLY` value; "full" means it was unset. The
reference runs used an older DLL from an earlier Rust port with no surviving
source ("old DLL"), and upstream's C++ build ("C++").

| Run | Build | Components | Result |
|---|---|---|---|
| 1 | `083656f` | full | Install failed: `cannot write the IsProcessorFeaturePresent import` (the 4-byte-aligned IAT slot). After rollback, about 23 s later, an execute fault at `0x700004541BB0`, then the game's own fail-fast `c0000409`. |
| 2 | `2aba7a2` | full | Installed. About 42 s later, a fault at live RVA `0x20FC9CF` in the original `LobbyMsgRW_PackageUInt`, called through our detour. Logged by our handler. |
| 3 | `2aba7a2` | full | About 3 s after load, an access violation in Wine's `dispatch_exception` (see "Wine's handler-list walk"). |
| 4 | `d3ec07b`, no thread freezing | full | As run 3: one execute fault at `0x7000228F5B70` and 1437 recursive faults in `dispatch_exception`. |
| ref | old DLL | n/a | Reached a lobby. No `c0000005`, 631 Arxan `int3`, which is normal. |
| 5 | `2aba7a2` | full | Execute fault at `0x7000224CA8A0` (unmapped) on the main thread. |
| 6 | `2aba7a2` | full | Execute fault at `0x7000225BDEF0`. A memory map of the live process shows nothing mapped within 256 MB. |
| ref 2 | old DLL | n/a | **The same execute fault**, at `0x7000224F3980`. The first reference run only survived because the game was quit at the lobby. |
| C++ | upstream | n/a | Reached a lobby; quit after 64 s. No `c0000005`, 651 Arxan `int3`. |
| 7 | `6f44075` | `arxan,dispatcher,protection` | No hooks. Ran 148 s, then quit. No `c0000005` or `c0000409`, nothing in `crashes.log`. |
| 8 | `eabdd62` | `...,create` | Hooks created, not enabled. Ran 211 s and exited cleanly. No faults. |
| 9 | `eabdd62` | `...,detours` | 38 s after load, the run-2 fault, with identical registers and stack. Our handler logged it and terminated the process. |
| 10 | `d2ac9e4` | `...,detours` | Execute fault at `0x70002250BDD0`, 1.7 s **before** `prepare` ran (see "The execute fault"). |
| 11 | `d2ac9e4` | `...,detours` | 54 s after load, the run-2 fault again: a read of address 0. Live hook bytes captured about 25 s in. |
| 12 | `9bf9835` | `...,detours,trace` | 40 s after load, the same fault. The trace hook on `LobbyMsg_HandleIM` logged **no** calls, although its body was on the crash stack. |
| 13 | `8715fa0` | `...,detours,trace` | 32 s after load, the same fault. The 0x2000-byte stack dump shows the return point of `check_pending_info_requests` above the zeroed buffer. Root cause: the PrepReadData constant was a call site inside `HandleIM`. |
| 14 | `7cc3f5a`, PrepReadData fixed | `...,detours,trace` | Ran 93 s and shut down cleanly. No `c0000005`, no `crashes.log` entry, 659 Arxan `int3`. The trace shows two `HandleIM` calls from our IM detour with a valid buffer, from the sender that used to crash. |
| 15 | `cee873f`, verdict trace | `...,detours,trace` | Clicked into a lobby, but hosting failed. The local player's own info response was dropped: `reason=info-response-rejected detail=2` (`valid` unreadable). No `c0000005`. |
| 16 | capture only | hooks off | Captured the live `MSG_InfoResponse` helper at live `0x1ECE5B0`, which showed the nested `lobbies` layout. |
| 17 | `8abb861`, nested parser | `...,detours,trace` | The local player's info response parses: `reason=info-response-handled detail=0`. Hosting still failed, because the handler was given the raw payload. Exited after 64 s, no faults. |
| 18 | `d068a9f`, `msg_t` handoff | `...,detours,trace` | **Hosting works.** The trace shows the local player's `keep reason=local` and `info-response-handled` pair every 5 to 8 s. A round was played. Exited after 229 s, no `c0000005`, no crash log. |
| 19 | `d068a9f` | **full** (VMT hook on, no `trace`) | Hosted and played a couple of rounds. Exited after 263 s with no crash-log entry. No Proton log, so no fault counts. |

## The execute fault

Several early runs, with new builds, pre-freeze builds **and the old DLL**,
had one thread jump to an unmapped address at the game's image base plus about
`0x428xxxxx`:

| Run | Fault address | Minus image base |
|---|---|---|
| 1 | `0x700004541BB0` | `+0x427C1BB0` |
| 4 | `0x7000228F5B70` | `+0x42C05B70` |
| 5 | `0x7000224CA8A0` | `+0x4280A8A0` |
| 6 | `0x7000225BDEF0` | `+0x428FDEF0` |
| ref 2 (old DLL) | `0x7000224F3980` | `+0x42803980` |

The image is `0x1D75BC00` bytes, so these targets lie far beyond it. In runs
4 and 6 the faulting thread had just been through Arxan's own vectored
handlers inside the exe, which return `EXCEPTION_CONTINUE_EXECUTION` and so
set RIP themselves. A target that is consistently "base plus a near-constant
offset" fits Arxan's checksum-keyed control flow.

Run 10 shows that the patch does not cause it. The loader mapped
`t7patch.dll`, then made no call into it for 2.0 s, until `prepare`. Our
`DllMain` only calls `DisableThreadLibraryCalls`. In that gap a game thread
took Arxan `int3`s, Arxan's handlers continued execution, and 25 ms later the
thread executed at the unmapped `0x70002250BDD0`. No patch of ours was
installed yet. The fault is inherent to the game under this Proton, induced by
an extra module being loaded, or a side effect of `+seh` tracing slowing
Arxan's `int3` path (for example, tripping a timing check). An independent
review ranked tracing first and module presence last, since runs 7 and 8
loaded the same DLL without faulting. The fault has not recurred since run 10,
but that is not proof it is gone.

An image diff of decrypted dumps (a crashing run with the new build, and the
old DLL at two times) found only scattered 2- to 4-byte differences that look
like Arxan runtime state. Because the old DLL crashes too, the diff cannot
isolate a cause.

### Wine's handler-list walk

In runs 3 and 4, a second thread faulted in Wine's `dispatch_exception` while
walking `vectored_exception_handlers`: the current entry was NULL. Dispatching
that fault walks the same list again, which gave a storm of 1437 faults. It
started in the same millisecond as the execute fault and only in crashing
runs, so it is most likely a consequence of the broken Arxan state, not an
independent bug.

## Still to do

- Run on Windows.
- Repeat the full patch without `+seh` tracing, and the vanilla game with it,
  to settle the execute fault.
- Run `T7PATCH_ONLY=vmt` alone.
- Exercise the campaign fixes and the Lua symbol resolver, which no run has
  covered.
