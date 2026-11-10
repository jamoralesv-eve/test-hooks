#!/bin/sh
for log in /tmp/eve-hook-canary.log "$(pwd)/.eve-hook-canary.log"; do
  { date -u; echo "args=$* pwd=$(pwd) host=$(hostname)"; } >> "$log" 2>/dev/null
done
./.cursor/hooks/cursor-hook.cmd "$@" 2>>/tmp/eve-hook-canary.log
rc=$?
echo "rc=$rc" >> /tmp/eve-hook-canary.log
echo "rc=$rc" >> "$(pwd)/.eve-hook-canary.log" 2>/dev/null
exit $rc