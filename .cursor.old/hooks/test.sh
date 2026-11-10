#!/bin/bash
input=$(cat)
echo "$(date +%T) $input" >> /tmp/hooks.log

if echo "$input" | grep -q "PROHIBIDO"; then
  echo "Bloqueado por el hook de prueba" >&2
  exit 2
fi
exit 0