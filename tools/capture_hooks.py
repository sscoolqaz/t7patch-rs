#!/usr/bin/env python3
"""Capture live game memory around the patch's lobby hooks.

Waits for a NEW game process with t7patch.dll mapped, sleeps, checks that it is
still the same process (pid and start time), then reads from /proc/<pid>/mem:
- the fault site and the game addresses seen on the PackageUInt crash stack;
- the hooked LobbyMsgRW_PackageUInt entry, the relay its jump leads to, and the
  trampoline held in ORIG_PACKAGE_UINT (found in the DLL with llvm-nm);
- the lobby message readers used by the info-response parser;
- the first 16 bytes of every constant in src/offsets.rs, translated to the
  live build, to check that each is a function start (offset_prologues.json).
Every span records the requested length, the bytes read and any error.

Game addresses below are live September 2026 RVAs. Reading another process's
memory needs ptrace access; see docs/testing-under-proton.md.

Usage:
  capture_hooks.py --dll DLL [--offsets FILE] [--out DIR] [--delay SECONDS] [--current]
Environment defaults: T7PATCH_DLL, T7PATCH_OFFSETS, T7PATCH_CAPTURE_DIR,
GAME_EXE (passed to gamepid.sh).
DLL must be the exact t7patch.dll installed in the game folder.
"""
import argparse, hashlib, json, os, re, struct, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))

# September 2026 moved code by -0x6C0 in this February RVA range (src/build.rs).
SEPTEMBER_SHIFT_START, SEPTEMBER_SHIFT_END, SEPTEMBER_SHIFT = 0x1D29C20, 0x2EFF000, -0x6C0

parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
parser.add_argument("--dll", default=os.environ.get("T7PATCH_DLL"),
                    help="the t7patch.dll installed in the game folder (T7PATCH_DLL)")
parser.add_argument("--offsets", default=os.environ.get("T7PATCH_OFFSETS",
                    os.path.join(HERE, "..", "src", "offsets.rs")),
                    help="src/offsets.rs to audit (T7PATCH_OFFSETS; default: this repo's)")
parser.add_argument("--out", default=os.environ.get("T7PATCH_CAPTURE_DIR", "capture"),
                    help="output directory (T7PATCH_CAPTURE_DIR; default: ./capture)")
parser.add_argument("--delay", type=float, default=12, help="seconds to wait after load")
parser.add_argument("--current", action="store_true",
                    help="capture a game that is already running instead of waiting for a new one")
args = parser.parse_args()
if not args.dll:
    parser.error("--dll or T7PATCH_DLL is required")
os.makedirs(args.out, exist_ok=True)

def image_base(path):
    """The preferred image base from the PE optional header."""
    with open(path, "rb") as f:
        pe = f.read(0x400)
    header = struct.unpack_from("<I", pe, 0x3C)[0]
    return struct.unpack_from("<Q", pe, header + 24 + 24)[0]

nm = subprocess.run(["llvm-nm", args.dll], capture_output=True, text=True, check=True).stdout
orig_va = next(int(l.split()[0], 16) for l in nm.splitlines() if "ORIG_PACKAGE_UINT.0" in l)
orig_rva = orig_va - image_base(args.dll)
dll_sha = hashlib.sha256(open(args.dll, "rb").read()).hexdigest()

def game_pid():
    r = subprocess.run([os.path.join(HERE, "gamepid.sh")], capture_output=True, text=True)
    return r.stdout.strip() or None

def start_time(pid):
    try:
        return open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[19]
    except OSError:
        return None

stale = None if args.current else game_pid()
while True:
    pid = game_pid()
    if pid and pid != stale:
        try:
            if "t7patch.dll" in open(f"/proc/{pid}/maps").read():
                # The launcher hands off to the real process: wait until the pid holds.
                time.sleep(3)
                if game_pid() == pid:
                    break
        except OSError:
            pass
    time.sleep(0.5)
started = start_time(pid)
print(f"t7patch mapped in {pid}; waiting {args.delay} s", flush=True)
time.sleep(args.delay)
if game_pid() != pid or start_time(pid) != started:
    sys.exit(f"game process {pid} changed or exited during the delay")

maps = open(f"/proc/{pid}/maps").read()
open(os.path.join(args.out, "maps.txt"), "w").write(maps)
regions = []
for line in maps.splitlines():
    m = re.match(r"([0-9a-f]+)-([0-9a-f]+) (\S+) \S+ \S+ \S+\s*(.*)", line)
    if m:
        regions.append((int(m[1], 16), int(m[2], 16), m[3], m[4]))
exe = os.environ.get("GAME_EXE", "BlackOps3.exe")
base = min(s for s, e, p, path in regions if path.endswith(exe))
t7 = min(s for s, e, p, path in regions if path.endswith("t7patch.dll"))

def perms(addr):
    return next((f"{p} {path}".strip() for s, e, p, path in regions if s <= addr < e), "unmapped")

mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
meta = {"pid": pid, "start_time": started, "captured_at": time.time(), "base": hex(base),
        "t7patch": hex(t7), "dll_sha256": dll_sha, "orig_slot_rva": hex(orig_rva), "spans": {}}

def capture(name, addr, size):
    entry = {"addr": hex(addr), "requested": size, "perms": perms(addr)}
    data = b""
    try:
        mem.seek(addr)
        data = mem.read(size)
    except OSError as error:
        entry["error"] = str(error)
    entry["read"] = len(data)
    open(os.path.join(args.out, name + ".bin"), "wb").write(data)
    meta["spans"][name] = entry
    return data

# The PackageUInt fault site and every game address seen on its crash stack.
for rva in (0x20FC9CF, 0x1EEA9C5, 0x2BC3E11, 0x1EE214B, 0x1EE9E45, 0x1EE9B1B):
    capture(f"game_{rva:X}", base + rva - 0x100, 0x200)
entry = capture("packageuint_entry_1EE9DD0", base + 0x1EE9DD0, 0x100)
capture("handleim_entry_1EE9A70", base + 0x1EE9A70, 0x40)
capture("msg_info_response_1ED5480", base + 0x1ED5480, 0x600)
capture("dw_instant_handle_lobby_message_143A7A0", base + 0x143A7A0, 0x400)
capture("lobby_helper_1ECE5B0", base + 0x1ECE5B0, 0x500)
for name, rva in (("array_start", 0x1EE9BA0), ("package_bool", 0x1EE9C20), ("package_element", 0x1EE9C60)):
    capture(f"{name}_{rva:X}", base + rva, 0x100)

# The entry jump (E9 rel32) leads to the relay; the relay jumps to the detour.
if len(entry) >= 5 and entry[0] == 0xE9:
    relay = base + 0x1EE9DD0 + 5 + struct.unpack_from("<i", entry, 1)[0]
    meta["relay"] = hex(relay)
    capture("relay", relay & ~0xFFF, 0x1000)
else:
    meta["relay"] = f"entry does not start with E9: {entry[:8].hex()}"

slot = capture("orig_slot", t7 + orig_rva - 0x20, 0x40)
if len(slot) == 0x40:
    trampoline = struct.unpack_from("<Q", slot, 0x20)[0]
    meta["trampoline"] = hex(trampoline)
    capture("trampoline", trampoline & ~0xFFF, 0x1000)
    meta["trampoline_offset_in_page"] = hex(trampoline & 0xFFF)

json.dump(meta, open(os.path.join(args.out, "meta.json"), "w"), indent=1)
print(json.dumps(meta, indent=1), flush=True)

# Every February-RVA constant in src/offsets.rs, translated to September, so each
# can be checked to be a function start rather than an instruction inside one.
prologues = {}
for line in open(args.offsets):
    m = re.match(r"pub const (\w+): usize = (0x[0-9A-Fa-f]+);", line)
    if not m:
        continue
    feb = int(m[2], 16)
    live = feb + SEPTEMBER_SHIFT if SEPTEMBER_SHIFT_START <= feb < SEPTEMBER_SHIFT_END else feb
    try:
        mem.seek(base + live)
        prologues[m[1]] = {"feb": hex(feb), "live": hex(live), "bytes": mem.read(16).hex()}
    except OSError as error:
        prologues[m[1]] = {"feb": hex(feb), "live": hex(live), "error": str(error)}
json.dump(prologues, open(os.path.join(args.out, "offset_prologues.json"), "w"), indent=1)
print(f"{len(prologues)} offset prologues saved", flush=True)
