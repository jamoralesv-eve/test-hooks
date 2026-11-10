#!/bin/sh
log=/tmp/eve-hook-canary.log
{ date -u; echo "args=$* pwd=$(pwd)"; } >> "$log"
./.cursor/hooks/cursor-hook.cmd "$@" 2>>"$log"
rc=$?
echo "rc=$rc" >> "$log"
exit $rc