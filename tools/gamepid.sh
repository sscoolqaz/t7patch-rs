#!/bin/sh
# Prints the pid of the process that has the game exe mapped, and exits 1 if
# there is none. pgrep alone also matches Proton's launcher wrapper, so the pid
# is the one whose memory map contains the exe.
#
# Usage: gamepid.sh
# Environment: GAME_EXE, the exe name (default BlackOps3.exe).
exe=${GAME_EXE:-BlackOps3.exe}
for p in $(pgrep -f -- "$exe"); do
    grep -qF -- "$exe" "/proc/$p/maps" 2>/dev/null && { echo "$p"; exit 0; }
done
exit 1
