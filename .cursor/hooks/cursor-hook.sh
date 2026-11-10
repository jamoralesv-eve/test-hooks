#!/bin/sh

agent="${1:-claude-code}"
event_name="${2:-PreToolUse}"
retry_backoff_s="0.15"
TURN_STOP_TIMEOUT_S=30
CURSOR_ANCESTOR_DEPTH=12

env_value() {
  eval "value=\${$1:-}"
  if [ -n "$value" ]; then printf '%s' "$value"; else printf '%s' "$2"; fi
}

debug_log() {
  if [ "$(env_value EVE_HOOK_DEBUG "")" = "1" ]; then
    printf '%s\n' "[eve-hook] $1" >&2
  fi
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g; s/	/\\t/g'
}

truncate_text() {
  value="$(printf '%s' "$1" | tr '\r\n' '  ')"
  if [ "${#value}" -gt 700 ]; then
    printf '%.700s...[truncated]' "$value"
  else
    printf '%s' "$value"
  fi
}

failure_log_dir() {
  uid="$(id -u 2>/dev/null || printf user)"
  printf '%s/eve-guard-hook-diagnostics-%s' "${TMPDIR:-/tmp}" "$uid"
}

failure_log_path() {
  printf '%s/failures.jsonl' "$(failure_log_dir)"
}

last_failure_path() {
  printf '%s/last-failure.json' "$(failure_log_dir)"
}

write_failure_log() {
  session_id="$1"
  reason="$2"
  payload="$3"
  dir="$(failure_log_dir)"
  old_umask="$(umask)"
  umask 077
  mkdir -p "$dir" 2>/dev/null || { umask "$old_umask"; return; }
  chmod 700 "$dir" 2>/dev/null || true
  tool_name="$(payload_tool_name "$payload")"
  tool_use_id="$(json_get_string_from_text "$payload" tool_use_id)"
  [ -n "$tool_use_id" ] || tool_use_id="$(json_get_string_from_text "$payload" toolUseId)"
  transcript_path="$(payload_transcript_path "$payload")"
  transcript_exists=false
  [ -n "$transcript_path" ] && [ -f "$transcript_path" ] && transcript_exists=true
  has_tool_input=false
  payload_has_field "$payload" 'tool_input|toolInput|input' && has_tool_input=true
  has_tool_response=false
  payload_has_field "$payload" 'tool_response|toolResponse|tool_output|toolOutput' && has_tool_response=true
  payload_keys="$(payload_keys_json "$payload")"
  http_status="$(http_status_from_reason "$reason")"
  [ -z "$http_status" ] && http_status=null
  curl_disabled=false
  [ "$(env_value EVE_HOOK_DISABLE_CURL "")" = "1" ] && curl_disabled=true
  record="$(printf '{"timestamp":"%s","event":"%s","agent":"%s","hook_runtime":"sh","reason":"%s","http_status":%s,"response_preview":"%s","plugin_id":"%s","config_hash":"%s","eve_guard_url":"%s","plugin_root":"%s","session_id":"%s","tool_name":"%s","tool_use_id":"%s","payload_keys":[%s],"has_tool_input":%s,"has_tool_response":%s,"transcript_path":"%s","transcript_path_exists":%s,"failure_mode":"%s","timeout_s":%s,"max_retries":%s,"curl_disabled":%s,"platform":"%s","log_file":"%s","last_failure_file":"%s"}' \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    "$(json_escape "$event_name")" \
    "$(json_escape "$agent")" \
    "$(json_escape "$(truncate_text "$reason")")" \
    "$http_status" \
    "$(json_escape "$(response_preview_from_reason "$reason")")" \
    "$(json_escape "$(env_value EVE_HOOK_PLUGIN_ID "")")" \
    "$(json_escape "$(env_value EVE_HOOK_CONFIG_HASH "")")" \
    "$(json_escape "$(env_value EVE_ORCHESTRATOR_URL "")")" \
    "$(json_escape "$(env_value CLAUDE_PLUGIN_ROOT "")")" \
    "$(json_escape "$session_id")" \
    "$(json_escape "$tool_name")" \
    "$(json_escape "$tool_use_id")" \
    "$payload_keys" \
    "$has_tool_input" \
    "$has_tool_response" \
    "$(json_escape "$transcript_path")" \
    "$transcript_exists" \
    "$(json_escape "$(failure_mode)")" \
    "$(timeout_s)" \
    "$(max_retries)" \
    "$curl_disabled" \
    "$(json_escape "$(uname -a 2>/dev/null)")" \
    "$(json_escape "$(failure_log_path)")" \
    "$(json_escape "$(last_failure_path)")")"
  printf '%s\n' "$record" >> "$(failure_log_path)" 2>/dev/null
  printf '%s' "$record" > "$(last_failure_path)" 2>/dev/null
  chmod 600 "$(failure_log_path)" "$(last_failure_path)" 2>/dev/null || true
  umask "$old_umask"
}

visible_failure_reason() {
  printf 'Eve Guard blocked this %s hook locally because it could not verify the tool call with Eve Guard. Reason: %s. Diagnostics: %s' "$event_name" "$(truncate_text "$1")" "$(last_failure_path)"
}

http_status_from_reason() {
  printf '%s' "$1" | sed -n 's/.*Eve Guard HTTP \([0-9][0-9]*\).*/\1/p'
}

response_preview_from_reason() {
  value="$1"
  case "$value" in
    *"Eve Guard HTTP "*":"*)
      preview="${value#*Eve Guard HTTP }"
      preview="${preview#*:}"
      preview="$(printf '%s' "$preview" | sed 's/^[[:space:]]*//')"
      truncate_text "$preview"
      ;;
    *) printf '' ;;
  esac
}

payload_has_field() {
  printf '%s' "$1" | grep -E "\"($2)\"[[:space:]]*:" >/dev/null 2>&1
}

payload_keys_json() {
  printf '%s' "$1" | awk '
    {
      text = text $0 "\n"
    }
    function escape_json(value) {
      gsub(/\\/, "\\\\", value)
      gsub(/"/, "\\\"", value)
      return value
    }
    function next_non_space(pos,    j, d) {
      for (j = pos; j <= length(text); j++) {
        d = substr(text, j, 1)
        if (d !~ /[[:space:]]/) return d
      }
      return ""
    }
    END {
      depth = 0
      in_string = 0
      escape = 0
      mode = ""
      out = ""
      for (i = 1; i <= length(text); i++) {
        c = substr(text, i, 1)
        if (in_string) {
          if (escape) {
            if (mode == "key") key = key c
            escape = 0
            continue
          }
          if (c == "\\") { escape = 1; continue }
          if (c == "\"") {
            in_string = 0
            if (mode == "key") {
              if (next_non_space(i + 1) == ":") {
                if (out != "") out = out ","
                out = out "\"" escape_json(key) "\""
              }
            }
            mode = ""
            continue
          }
          if (mode == "key") key = key c
          continue
        }
        if (c == "\"") {
          if (depth == 1) {
            in_string = 1
            mode = "key"
            key = ""
          } else {
            in_string = 1
            mode = "skip"
          }
          continue
        }
        if (c == "{" || c == "[") { depth++; continue }
        if (c == "}" || c == "]") { depth--; continue }
      }
      print out
    }
  '
}

json_get_top_value_from_text() {
  printf '%s' "$1" | awk -v wanted="$2" -v kind="$3" '
    {
      text = text $0 "\n"
    }
    function reset_value() {
      expecting_value = 0
      expecting_colon = 0
      last_key = ""
      token = ""
    }
    function append_char(value, c) {
      return value c
    }
    END {
      depth = 0
      in_string = 0
      escape = 0
      mode = ""
      for (i = 1; i <= length(text); i++) {
        c = substr(text, i, 1)
        if (in_string) {
          if (escape) {
            if (mode == "key") {
              key = append_char(key, c)
            } else if (mode == "value") {
              value = append_char(value, c)
            }
            escape = 0
            continue
          }
          if (c == "\\") {
            escape = 1
            continue
          }
          if (c == "\"") {
            in_string = 0
            if (mode == "key") {
              last_key = key
              expecting_colon = 1
            } else if (mode == "value") {
              if (last_key == wanted && kind == "string") {
                print value
                exit
              }
              reset_value()
            }
            mode = ""
            continue
          }
          if (mode == "key") {
            key = append_char(key, c)
          } else if (mode == "value") {
            value = append_char(value, c)
          }
          continue
        }

        if (c == "\"") {
          if (depth == 1 && expecting_value) {
            in_string = 1
            mode = "value"
            value = ""
          } else if (depth == 1 && !expecting_colon) {
            in_string = 1
            mode = "key"
            key = ""
          } else {
            in_string = 1
            mode = "skip"
          }
          continue
        }

        if (c == "{" || c == "[") {
          if (depth == 1 && expecting_value) {
            reset_value()
          }
          depth++
          continue
        }
        if (c == "}" || c == "]") {
          depth--
          reset_value()
          continue
        }
        if (depth == 1 && expecting_colon && c == ":") {
          expecting_colon = 0
          expecting_value = 1
          token = ""
          continue
        }
        if (depth == 1 && expecting_value) {
          if (c ~ /[[:space:]]/) {
            continue
          }
          for (j = i; j <= length(text); j++) {
            d = substr(text, j, 1)
            if (d == "," || d == "}" || d == "]") {
              break
            }
            token = token d
          }
          gsub(/^[[:space:]]+|[[:space:]]+$/, "", token)
          if (last_key == wanted && kind == "scalar") {
            print token
            exit
          }
          reset_value()
          i = j - 1
          continue
        }
        if (depth == 1 && c == ",") {
          reset_value()
        }
      }
    }
  '
}

json_get_string_from_text() {
  json_get_top_value_from_text "$1" "$2" string
}

# Scoped lookup: the string value of ``<parent>.<child>`` where ``parent``
# is a top-level object key. Unlike a bare grep for ``child``, a same-named
# key elsewhere in the document (project history, MCP config) is ignored.
json_get_nested_string_from_text() {
  printf '%s' "$1" | awk -v parent="$2" -v child="$3" '
    {
      text = text $0 "\n"
    }
    function reset_top() {
      top_key = ""
      top_colon = 0
      top_value = 0
    }
    function reset_account_key() {
      account_key = ""
      account_colon = 0
      account_value = 0
    }
    END {
      depth = 0
      in_string = 0
      escape = 0
      mode = ""
      in_account = 0
      account_parent_depth = 0
      for (i = 1; i <= length(text); i++) {
        c = substr(text, i, 1)
        if (in_string) {
          if (escape) {
            if (mode == "top_key") top_key = top_key c
            if (mode == "account_key") account_key = account_key c
            if (mode == "account_value") account_value_text = account_value_text c
            escape = 0
            continue
          }
          if (c == "\\") { escape = 1; continue }
          if (c == "\"") {
            in_string = 0
            if (mode == "top_key") {
              top_colon = 1
            } else if (mode == "account_key") {
              account_colon = 1
            } else if (mode == "account_value") {
              if (account_key == child) {
                print account_value_text
                exit
              }
              reset_account_key()
            }
            mode = ""
            continue
          }
          if (mode == "top_key") top_key = top_key c
          if (mode == "account_key") account_key = account_key c
          if (mode == "account_value") account_value_text = account_value_text c
          continue
        }

        if (c == "\"") {
          if (in_account && depth == account_parent_depth + 1 && account_value) {
            in_string = 1
            mode = "account_value"
            account_value_text = ""
          } else if (in_account && depth == account_parent_depth + 1 && !account_colon && !account_value) {
            in_string = 1
            mode = "account_key"
            account_key = ""
          } else if (depth == 1 && !top_colon && !top_value) {
            in_string = 1
            mode = "top_key"
            top_key = ""
          } else {
            in_string = 1
            mode = "skip"
          }
          continue
        }

        if (depth == 1 && top_colon && c == ":") {
          top_colon = 0
          top_value = 1
          continue
        }
        if (in_account && depth == account_parent_depth + 1 && account_colon && c == ":") {
          account_colon = 0
          account_value = 1
          continue
        }
        if (c == "{" || c == "[") {
          if (depth == 1 && top_value) {
            if (top_key == parent && c == "{") {
              in_account = 1
              account_parent_depth = depth
            }
            reset_top()
          } else if (in_account && depth == account_parent_depth + 1 && account_value) {
            reset_account_key()
          }
          depth++
          continue
        }
        if (c == "}" || c == "]") {
          if (in_account && depth == account_parent_depth + 1 && c == "}") {
            in_account = 0
          }
          depth--
          if (depth < 1) reset_top()
          continue
        }
        if (depth == 1 && top_value && c == ",") reset_top()
        if (in_account && depth == account_parent_depth + 1 && account_value && c == ",") reset_account_key()
      }
    }
  '
}

json_get_account_email_from_text() {
  json_get_nested_string_from_text "$1" account email
}

json_get_scalar_from_text() {
  json_get_top_value_from_text "$1" "$2" scalar
}

script_dir() {
  dir="$(dirname "$0" 2>/dev/null)"
  [ -n "$dir" ] && printf '%s' "$dir" || printf '.'
}

# Resolve the baked eve.config.json. Claude Code exports CLAUDE_PLUGIN_ROOT
# and ships the config at its root. Cursor sets no plugin-root env, so fall
# back to script-relative discovery: the launcher is at <root>/hooks/
# cursor-hook.sh and the config at <root>/eve.config.json, i.e.
# $SCRIPT_DIR/../eve.config.json. The same relative path also resolves
# correctly for Claude (CLAUDE_PLUGIN_ROOT/hooks/../eve.config.json), so this
# is a safe superset.
config_path() {
  root="$(env_value CLAUDE_PLUGIN_ROOT "")"
  if [ -n "$root" ] && [ -f "$root/eve.config.json" ]; then
    printf '%s' "$root/eve.config.json"
    return
  fi
  candidate="$(script_dir)/../eve.config.json"
  [ -f "$candidate" ] && printf '%s' "$candidate"
}

load_config_text() {
  path="$(config_path)"
  [ -n "$path" ] && [ -f "$path" ] && tr '\n' ' ' < "$path"
}

set_if_missing() {
  eval "current=\${$1:-}"
  if [ -z "$current" ] && [ -n "$2" ]; then
    export "$1=$2"
  fi
}

apply_config() {
  config_text="$(load_config_text)"
  [ -z "$config_text" ] && return
  set_if_missing EVE_ORCHESTRATOR_URL "$(json_get_string_from_text "$config_text" orchestrator_url)"
  set_if_missing EVE_HOOK_TENANT_ID "$(json_get_string_from_text "$config_text" tenant_id)"
  set_if_missing EVE_HOOK_PLUGIN_ID "$(json_get_string_from_text "$config_text" plugin_id)"
  set_if_missing EVE_HOOK_TOKEN "$(json_get_string_from_text "$config_text" hook_token)"
  set_if_missing EVE_HOOK_CONFIG_HASH "$(json_get_string_from_text "$config_text" config_hash)"
  set_if_missing EVE_HOOK_TIMEOUT_S "$(json_get_scalar_from_text "$config_text" timeout_s)"
  set_if_missing EVE_HOOK_FAILURE_MODE "$(json_get_string_from_text "$config_text" failure_mode)"
  set_if_missing EVE_HOOK_MAX_RETRIES "$(json_get_scalar_from_text "$config_text" max_retries)"
  set_if_missing EVE_HOOK_USER_TOKEN "$(json_get_string_from_text "$config_text" user_token)"
  set_if_missing EVE_HOOK_CAPABILITIES "$(json_get_string_from_text "$config_text" capabilities)"
  [ "$(json_get_scalar_from_text "$config_text" debug)" = "true" ] && set_if_missing EVE_HOOK_DEBUG "1"
  [ "$(json_get_scalar_from_text "$config_text" disable_curl)" = "true" ] && set_if_missing EVE_HOOK_DISABLE_CURL "1"
}

timeout_s() {
  value="$(env_value EVE_HOOK_TIMEOUT_S 8)"
  case "$value" in ''|*[!0-9]*) value=8 ;; esac
  [ "$value" -lt 1 ] && value=1
  [ "$value" -gt 30 ] && value=30
  printf '%s' "$value"
}

# A turn-stop hook may wait on the interrogation judge reading the agent's
# answers, which takes longer than a policy check.
request_timeout_s() {
  if is_turn_stop_event; then printf '%s' "$TURN_STOP_TIMEOUT_S"; else timeout_s; fi
}

max_retries() {
  value="$(env_value EVE_HOOK_MAX_RETRIES 1)"
  case "$value" in ''|*[!0-9]*) value=1 ;; esac
  [ "$value" -gt 3 ] && value=3
  printf '%s' "$value"
}

failure_mode() {
  mode="$(env_value EVE_HOOK_FAILURE_MODE fail-open)"
  case "$mode" in fail-open|fail-closed|first-fail-closed) printf '%s' "$mode" ;; *) printf '%s' fail-open ;; esac
}

# Cursor fires "after"/"post" events once the tool already ran; those need a
# response-phase block shape (replace the MCP output the model sees) instead
# of a pre-tool permission verdict.
is_cursor_post_tool() {
  case "$event_name" in
    afterMCPExecution|postToolUse|afterShellExecution|afterFileEdit|postToolUseFailure) return 0 ;;
    *) return 1 ;;
  esac
}

# Agent reply / turn stop / session start hooks (interrogation's reply
# channel). They never gate a tool, so every failure answers ``{}``: a deny
# shape here would stop the agent outright.
is_lifecycle_event() {
  case "$event_name" in
    Stop|SubagentStop|SessionStart|afterAgentResponse|stop|sessionStart) return 0 ;;
    *) return 1 ;;
  esac
}

is_turn_stop_event() {
  case "$event_name" in
    Stop|SubagentStop|stop) return 0 ;;
    *) return 1 ;;
  esac
}

# Agent-native "no objection" reply for the fail-open path. Cursor pre-tool
# hooks expect an explicit ``permission: allow`` rather than an empty body;
# everything else (Claude, Cursor post-tool, lifecycle) treats ``{}`` as
# pass-through.
allow_response() {
  if is_lifecycle_event; then
    printf '{}'
    return
  fi
  if [ "$agent" = "cursor" ] && ! is_cursor_post_tool; then
    printf '{"permission":"allow","continue":true}'
    return
  fi
  printf '{}'
}

deny_response() {
  reason="$(json_escape "$1")"
  if [ "$agent" = "cursor" ]; then
    if is_cursor_post_tool; then
      printf '{"updated_mcp_tool_output":{"isError":true,"content":[{"type":"text","text":"%s"}],"_eve_guard":{"blocked":true,"phase":"response"}},"additional_context":"%s"}' "$reason" "$reason"
      return
    fi
    printf '{"permission":"deny","continue":true,"user_message":"%s","agent_message":"%s"}' "$reason" "$reason"
    return
  fi
  if [ "$agent" = "codex" ]; then
    codex_deny_response "$reason"
    return
  fi
  if [ "$event_name" = "PostToolUse" ]; then
    printf '{"decision":"block","reason":"%s","hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"%s","updatedToolOutput":"%s"}}' "$reason" "$reason" "$reason"
    return
  fi
  printf '{"continue":false,"stopReason":"%s","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}' "$reason" "$reason"
}

# Codex marks a hook run Failed - and runs the tool anyway - when the deny
# carries ``continue``/``stopReason`` or ``updatedToolOutput``, so it gets the
# bare shapes. Takes an already JSON-escaped reason.
codex_deny_response() {
  if [ "$event_name" = "PostToolUse" ]; then
    printf '{"decision":"block","reason":"%s","hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"%s"}}' "$1" "$1"
    return
  fi
  printf '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%s"}}' "$1"
}

state_file() {
  key="${1:-global}"
  if command -v shasum >/dev/null 2>&1; then
    hash="$(printf '%s' "$key" | shasum -a 256 | awk '{print substr($1,1,16)}')"
  else
    hash="$(printf '%s' "$key" | cksum | awk '{print $1}')"
  fi
  printf '%s/eve-hook-degraded-%s.flag' "$(env_value EVE_HOOK_STATE_DIR "${TMPDIR:-/tmp}")" "$hash"
}

already_degraded() {
  file="$(state_file "$1")"
  [ -f "$file" ] || return 1
  if find "$file" -mmin +60 -print 2>/dev/null | grep . >/dev/null 2>&1; then
    rm -f "$file"
    return 1
  fi
  return 0
}

mark_degraded() {
  file="$(state_file "$1")"
  mkdir -p "$(dirname "$file")" 2>/dev/null
  printf '%s' "$$" > "$file" 2>/dev/null
}

failure_response() {
  write_failure_log "$1" "$2" "$3"
  mode="$(failure_mode)"
  if [ "$mode" = "fail-open" ] || is_lifecycle_event; then allow_response; return; fi
  visible_reason="$(visible_failure_reason "$2")"
  if [ "$mode" = "fail-closed" ]; then deny_response "$visible_reason"; return; fi
  if already_degraded "$1"; then allow_response; return; fi
  mark_degraded "$1"
  deny_response "$visible_reason Following requests in this session will be fail-open."
}

payload_tool_name() {
  name="$(json_get_string_from_text "$1" tool_name)"
  [ -n "$name" ] && { printf '%s' "$name"; return; }
  json_get_string_from_text "$1" toolName
}

payload_transcript_path() {
  path="$(json_get_string_from_text "$1" transcript_path)"
  [ -n "$path" ] && { printf '%s' "$path"; return; }
  json_get_string_from_text "$1" transcriptPath
}

calling_guid() {
  payload="$(printf '%s' "$1" | tr '\n' ' ')"
  tool_name="$(payload_tool_name "$payload")"
  printf '%s' "$tool_name" | sed -n 's/^mcp__\([0-9a-fA-F-][0-9a-fA-F-]*\)__.*/\1/p'
}

namespace_tools_json() {
  transcript_path="$1"
  guid="$2"
  [ -n "$transcript_path" ] || return
  [ -n "$guid" ] || return
  [ -f "$transcript_path" ] || return

  tail -n 800 "$transcript_path" | awk -v prefix="mcp__${guid}__" '
    function escape_json(value) {
      gsub(/\\/, "\\\\", value)
      gsub(/"/, "\\\"", value)
      return value
    }
    {
      lines[NR] = $0
    }
    END {
      for (i = NR; i >= 1; i--) {
        line = lines[i]
        has_delta_type = line ~ /"type"[[:space:]]*:[[:space:]]*"deferred_tools_delta"/
        has_delta_field = line ~ /"deferred_tools_delta"[[:space:]]*:/
        if (!has_delta_type && !has_delta_field) {
          continue
        }

        found = 0
        while (match(line, prefix "[A-Za-z0-9_.:-]+")) {
          tool = substr(line, RSTART + length(prefix), RLENGTH - length(prefix))
          line = substr(line, RSTART + RLENGTH)
          if (!(tool in seen)) {
            if (out != "") {
              out = out ","
            }
            out = out "\"" escape_json(tool) "\""
            seen[tool] = 1
            found = 1
          }
        }

        if (found) {
          print out
          exit
        }
      }
    }
  '
}

# Placeholder accounts are not a person: Claude Desktop in 3P mode hands
# out ``cowork-3p@localhost`` and sandbox users look like ``root@vm``. Same
# rule as hook.cjs: one ``@``, no whitespace, a dotted domain that is not
# machine-local. Callers skip an unusable value and try the next source.
usable_email() {
  [ "${#1}" -le 320 ] || return 1
  case "$1" in
    ''|*[[:space:]]*|*@*@*|@*|*@) return 1 ;;
    *@*) ;;
    *) return 1 ;;
  esac
  domain="$(printf '%s' "${1##*@}" | tr '[:upper:]' '[:lower:]')"
  case "$domain" in
    *.localhost|*.local|*.localdomain) debug_log "skipping placeholder user_email"; return 1 ;;
    *.*) return 0 ;;
    *) debug_log "skipping placeholder user_email"; return 1 ;;
  esac
}

envelope_email() {
  transcript_path="$1"
  [ -n "$transcript_path" ] || return
  dir="$(dirname "$transcript_path")"
  i=0
  while [ "$i" -lt 8 ] && [ -n "$dir" ] && [ "$dir" != "/" ]; do
    base="$(basename "$dir")"
    candidate="${dir}.json"
    if [ "${base#local_}" != "$base" ] && [ -f "$candidate" ]; then
      text="$(tr '\n' ' ' < "$candidate")"
      email="$(json_get_string_from_text "$text" emailAddress)"
      usable_email "$email" && { printf '%s' "$email"; return; }
      email="$(json_get_account_email_from_text "$text")"
      usable_email "$email" && { printf '%s' "$email"; return; }
      email="$(json_get_string_from_text "$text" email)"
      usable_email "$email" && { printf '%s' "$email"; return; }
    fi
    parent="$(dirname "$dir")"
    [ "$parent" = "$dir" ] && break
    dir="$parent"
    i=$((i + 1))
  done
}

# Host-mode Claude Code fallback: the signed-in claude.ai account lives in
# Claude Code's own config file as ``oauthAccount.emailAddress`` -
# ``$CLAUDE_CONFIG_DIR/.claude.json`` when the config dir is relocated,
# else ``$HOME/.claude.json``. The file also carries project history and
# feature flags (never OAuth tokens), so we extract the single scoped key
# we need and never echo the file. The lookup is scoped to the top-level
# ``oauthAccount`` object: an ``emailAddress`` planted elsewhere (project
# history, MCP config) must not become the identity that group-scoped
# policies match on. API-key-only installs have no ``oauthAccount`` and
# resolve to empty (anonymous hook).
#
# The file is walked character-by-character in awk, so its size bounds the
# cost of every PreToolUse call: the same 16 MB ceiling hook.cjs / hook.ps1
# apply (measured: ~0.3s at 2 MB, ~2.5s at the cap with mawk — well inside
# the hook timeout). The grep pre-check skips the walk entirely when the
# key is absent, the common API-key-only case.
CLAUDE_CONFIG_MAX_BYTES=16777216

claude_config_email() {
  config_dir="$(env_value CLAUDE_CONFIG_DIR "")"
  for base in "$config_dir" "${HOME:-}"; do
    [ -n "$base" ] || continue
    candidate="${base}/.claude.json"
    [ -f "$candidate" ] || continue
    size="$(wc -c < "$candidate" 2>/dev/null | tr -d '[:space:]')"
    case "$size" in ''|*[!0-9]*) continue ;; esac
    [ "$size" -le "$CLAUDE_CONFIG_MAX_BYTES" ] || continue
    grep -q '"oauthAccount"' "$candidate" 2>/dev/null || continue
    email="$(json_get_nested_string_from_text "$(tr '\n' ' ' < "$candidate" 2>/dev/null)" oauthAccount emailAddress)"
    usable_email "$email" && { printf '%s' "$email"; return; }
  done
}

# Claude Code on Databricks inference (``ANTHROPIC_BASE_URL`` =
# ``https://<workspace>/ai-gateway/anthropic``) has no claude.ai login. The
# Databricks token it already sends to the workspace names its owner: SCIM
# ``/Me`` returns ``userName`` (the email). Same rules as hook.cjs: the
# token only goes to a Databricks workspace host it is configured for, it
# reaches curl on stdin (never argv, so ``ps`` cannot show it), and the
# answer is cached 1 h (a miss 5 min) in a private per-user directory.
# ``EVE_HOOK_DATABRICKS_IDENTITY=0`` turns the lookup off.
DATABRICKS_ME_PATH='/api/2.0/preview/scim/v2/Me?attributes=userName,emails'
DATABRICKS_ME_TIMEOUT_S=2
DATABRICKS_CLI_TIMEOUT_S=3
DATABRICKS_HIT_TTL_MIN=60
DATABRICKS_MISS_TTL_MIN=5

url_origin() {
  value="$(printf '%s' "$1" | tr -d '[:space:]')"
  case "$value" in
    '') return ;;
    http://*|https://*) ;;
    *://*) return ;;
    *) value="https://$value" ;;
  esac
  scheme="$(printf '%s' "${value%%://*}" | tr '[:upper:]' '[:lower:]')"
  rest="${value#*://}"
  host="${rest%%/*}"
  host="$(printf '%s' "${host%%\?*}" | tr '[:upper:]' '[:lower:]')"
  # Same origin string as hook.cjs / hook.ps1: the cache key hashes it.
  case "$scheme:$host" in https:*:443) host="${host%:443}" ;; http:*:80) host="${host%:80}" ;; esac
  [ -n "$host" ] && printf '%s://%s' "$scheme" "$host"
}

is_databricks_origin() {
  case "$1" in https://*) ;; *) return 1 ;; esac
  host="$(printf '%s' "${1#https://}" | tr '[:upper:]' '[:lower:]')"
  host="${host%%:*}"
  case "$host" in
    *.databricks.com|*.azuredatabricks.net|*.databricks.us|*.databricks.azure.cn) return 0 ;;
  esac
  return 1
}

gateway_origin() {
  origin="$(url_origin "$(env_value ANTHROPIC_BASE_URL "")")"
  is_databricks_origin "$origin" && printf '%s' "$origin"
}

gateway_header_token() {
  printf '%s\n' "$(env_value ANTHROPIC_CUSTOM_HEADERS "")" | awk '
    {
      colon = index($0, ":")
      if (colon == 0) next
      name = tolower(substr($0, 1, colon - 1))
      gsub(/^[ \t]+|[ \t\r]+$/, "", name)
      if (name != "x-databricks-ai-gateway-token") next
      value = substr($0, colon + 1)
      gsub(/^[ \t]+|[ \t\r]+$/, "", value)
      print value
      exit
    }
  '
}

# Fixed /tmp, not TMPDIR: Claude Desktop starts hooks without TMPDIR while a
# macOS Terminal sets a per-user one, and both must share one sign-in (the
# manual databricks-login runs from Terminal).
databricks_cache_dir() {
  dir="$(env_value EVE_HOOK_STATE_DIR /tmp)/eve-hook-identity-$(id -u 2>/dev/null || printf user)"
  old_umask="$(umask)"
  umask 077
  mkdir -p "$dir" 2>/dev/null
  umask "$old_umask"
  [ -d "$dir" ] && [ ! -L "$dir" ] && [ -O "$dir" ] || return 1
  printf '%s' "$dir"
}

databricks_cache_file() {
  dir="$(databricks_cache_dir)" || return 1
  key="$(printf '%s\n%s' "$1" "${2:-cli}" | sha256_hex | cut -c1-32)"
  [ -n "$key" ] || return 1
  printf '%s/databricks-%s.json' "$dir" "$key"
}

sha256_hex() {
  if command -v shasum >/dev/null 2>&1; then
    shasum -a 256 | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    openssl dgst -sha256 2>/dev/null | awk '{print $NF}'
  fi
}

# ``{"email":"..."}``, the format hook.cjs and hook.ps1 read and write, so
# every runtime shares one cache.
databricks_cache_email() {
  json_get_string_from_text "$(tr '\n' ' ' < "$1" 2>/dev/null)" email
}

# Exit 0 + the cached email (may be empty for a cached miss) when the entry
# is fresh; exit 1 when it is absent or expired.
databricks_cache_read() {
  file="$1"
  [ -f "$file" ] || return 1
  email="$(databricks_cache_email "$file")"
  ttl="$DATABRICKS_MISS_TTL_MIN"
  [ -n "$email" ] && ttl="$DATABRICKS_HIT_TTL_MIN"
  find "$file" -mmin "-$ttl" -print 2>/dev/null | grep . >/dev/null 2>&1 || return 1
  printf '%s' "$email"
}

databricks_cache_write() {
  old_umask="$(umask)"
  umask 077
  printf '{"email":"%s"}' "$(json_escape "$2")" > "$1" 2>/dev/null
  umask "$old_umask"
}

# Run "$@" for at most $1 seconds. The watchdog's output goes to /dev/null so
# a caller's command substitution does not wait for its ``sleep``.
run_with_timeout() {
  limit="$1"
  shift
  "$@" &
  child=$!
  ( sleep "$limit"; kill "$child" 2>/dev/null ) >/dev/null 2>&1 &
  watchdog=$!
  wait "$child"
  status=$?
  kill "$watchdog" 2>/dev/null
  return "$status"
}

# ``databricks auth token`` serves the CLI's cached OAuth login (the
# ``apiKeyHelper`` / ``ug claude`` setup) and fails instead of opening a
# browser when there is none.
databricks_cli_token() {
  command -v databricks >/dev/null 2>&1 || { debug_log "databricks auth token unavailable: databricks CLI not on PATH"; return; }
  out="$(run_with_timeout "$DATABRICKS_CLI_TIMEOUT_S" databricks auth token --host "$1" 2>/dev/null </dev/null)"
  json_get_string_from_text "$(printf '%s' "$out" | tr '\n' ' ')" access_token
}

databricks_me_email() {
  command -v curl >/dev/null 2>&1 || return
  body="$(printf 'header = "Authorization: Bearer %s"\n' "$2" | curl --silent --max-time "$DATABRICKS_ME_TIMEOUT_S" --config - -H 'Accept: application/json' -w '\n__EVE_ME_STATUS__:%{http_code}' "$1$DATABRICKS_ME_PATH" 2>/dev/null)"
  case "$body" in *"__EVE_ME_STATUS__:200") ;; *) debug_log "databricks /Me lookup failed"; return ;; esac
  text="$(printf '%s' "$body" | sed '$d' | tr '\n' ' ')"
  email="$(json_get_string_from_text "$text" userName)"
  usable_email "$email" && { printf '%s' "$email"; return; }
  email="$(printf '%s' "$text" | sed -n 's/.*"value"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  usable_email "$email" && printf '%s' "$email"
}

# One target: origin + token ("" = ask the Databricks CLI). Prints the email
# and exits 0 when this target answered (from cache or network).
databricks_target_email() {
  file="$(databricks_cache_file "$1" "$2")" || file=""
  if [ -n "$file" ] && cached="$(databricks_cache_read "$file")"; then
    [ -n "$cached" ] && { printf '%s' "$cached"; return 0; }
    return 1
  fi
  token="$2"
  [ -n "$token" ] || token="$(databricks_cli_token "$1")"
  email=""
  [ -n "$token" ] && email="$(databricks_me_email "$1" "$token")"
  [ -n "$file" ] && databricks_cache_write "$file" "$email"
  [ -n "$email" ] && { printf '%s' "$email"; return 0; }
  return 1
}

gateway_env_token() {
  token="$(gateway_header_token)"
  [ -n "$token" ] || token="$(env_value ANTHROPIC_AUTH_TOKEN "" | tr -d '[:space:]')"
  [ -n "$token" ] || token="$(env_value ANTHROPIC_API_KEY "" | tr -d '[:space:]')"
  printf '%s' "$token"
}

# Only a Databricks ANTHROPIC_BASE_URL turns Databricks mode on; a
# DATABRICKS_HOST left over from CLI/SDK work must not. Once on,
# DATABRICKS_HOST may name the workspace the CLI and the sign-in talk to.
workspace_origin() {
  gateway="$(gateway_origin)"
  [ -n "$gateway" ] || return
  origin="$(url_origin "$(env_value DATABRICKS_HOST "")")"
  printf '%s' "${origin:-$gateway}"
}

found_email() {
  debug_log "user_email resolved from $1"
  case "$1" in
    "Databricks /Me") audit_set_winner "databricks_me" "$1" ;;
    "Claude Desktop sign-in (OTEL enduser.id)") audit_set_winner "otel_enduser" "$1" ;;
    "Eve Databricks sign-in") audit_set_winner "eve_databricks_sign_in" "$1" ;;
    "Databricks /Me (CLI login)") audit_set_winner "databricks_cli_me" "$1" ;;
  esac
  printf '%s' "$2"
}

databricks_email() {
  databricks_workspace_detected || return
  sdk_origin="$(url_origin "$(env_value DATABRICKS_HOST "")")"
  sdk_token="$(env_value DATABRICKS_TOKEN "" | tr -d '[:space:]')"
  gateway="$(gateway_origin)"
  if [ -n "$sdk_origin" ] && [ -n "$sdk_token" ]; then
    email="$(databricks_target_email "$sdk_origin" "$sdk_token")" && { found_email "Databricks /Me" "$email"; return; }
  fi
  gateway_token="$(gateway_env_token)"
  if [ -n "$gateway_token" ]; then
    email="$(databricks_target_email "$gateway" "$gateway_token")" && { found_email "Databricks /Me" "$email"; return; }
  else
    # Claude Desktop keeps an interactive gateway sign-in's token in memory.
    debug_log "databricks gateway has no token in the hook env; trying Claude Desktop's sign-in, the Eve Databricks sign-in, then the Databricks CLI"
  fi
  databricks_tokenless_email "$(workspace_origin)"
}

databricks_tokenless_email() {
  email="$(otel_enduser_email)"
  [ -n "$email" ] && { found_email "Claude Desktop sign-in (OTEL enduser.id)" "$email"; return; }
  email="$(databricks_login_cached_email "$1")"
  [ -n "$email" ] && { found_email "Eve Databricks sign-in" "$email"; return; }
  email="$(databricks_target_email "$1" "")" && { found_email "Databricks /Me (CLI login)" "$email"; return; }
  databricks_login_maybe_start "$1"
}

# Claude Desktop appends ``enduser.id=<signed-in email>`` to the engine's
# ``OTEL_RESOURCE_ATTRIBUTES`` when an OTLP endpoint is configured. It is the
# identity of Desktop's own gateway sign-in.
otel_enduser_email() {
  printf '%s\n' "$(env_value OTEL_RESOURCE_ATTRIBUTES "")" | tr ',' '\n' | while IFS= read -r pair; do
    case "$pair" in
      enduser.id=*) value="$(url_decode "${pair#enduser.id=}")"; usable_email "$value" 2>/dev/null && printf '%s' "$value"; break ;;
    esac
  done
}

url_decode() {
  printf '%s' "$1" | awk '
    BEGIN { for (i = 0; i < 256; i++) hex[sprintf("%02x", i)] = sprintf("%c", i) }
    {
      out = ""
      for (i = 1; i <= length($0); i++) {
        c = substr($0, i, 1)
        if (c == "%" && i + 2 <= length($0)) { out = out hex[tolower(substr($0, i + 1, 2))]; i += 2 }
        else if (c == "+") out = out " "
        else out = out c
      }
      printf "%s", out
    }
  '
}

url_encode() {
  printf '%s' "$1" | od -An -tx1 -v | tr -d ' \n' | sed 's/../%&/g'
}

# ---------------------------------------------------------------------------
# Eve Databricks sign-in: a one-time browser OAuth (PKCE) login that needs no
# Databricks CLI. It reuses Claude Desktop's own OAuth app (client id and
# loopback redirect from Desktop's applied config) when its issuer is this
# workspace, else Databricks' built-in ``databricks-cli`` public client.
# Only the email is kept (30 days); the tokens are dropped after the exchange.
# ---------------------------------------------------------------------------
DATABRICKS_LOGIN_TTL_MIN=43200
DATABRICKS_LOGIN_RETRY_MIN=720
DATABRICKS_LOGIN_WAIT_S=300
DATABRICKS_LOGIN_TOKEN_TIMEOUT_S=10
DATABRICKS_CLI_CLIENT_ID='databricks-cli'
DATABRICKS_CLI_REDIRECT_URI='http://localhost:8020'
DATABRICKS_CLI_SCOPES='all-apis openid'
UUID_PATTERN='^[0-9a-f]\{8\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{12\}$'

databricks_login_enabled() {
  [ "$(env_value EVE_HOOK_DATABRICKS_LOGIN "")" != "0" ]
}

databricks_login_cache_file() {
  databricks_cache_file "$1" "login"
}

databricks_login_attempt_file() {
  databricks_cache_file "$1" "login-attempt"
}

cache_fresh() {
  [ -f "$1" ] && find "$1" -mmin "-$2" -print 2>/dev/null | grep . >/dev/null 2>&1
}

databricks_login_cached_email() {
  file="$(databricks_login_cache_file "$1")" || return
  cache_fresh "$file" "$DATABRICKS_LOGIN_TTL_MIN" || return
  email="$(databricks_cache_email "$file")"
  usable_email "$email" 2>/dev/null && printf '%s' "$email"
}

desktop_config_root() {
  for root in "$(env_value EVE_HOOK_CLAUDE_DESKTOP_DIR "")" "$HOME/Library/Application Support/Claude-3p" "$(env_value APPDATA "")/Claude-3p" "$(env_value LOCALAPPDATA "")/Claude-3p"; do
    [ -f "$root/configLibrary/_meta.json" ] && { printf '%s' "$root"; return; }
  done
}

# The config Desktop applies: ``configLibrary/_meta.json`` → ``appliedId`` →
# ``configLibrary/<appliedId>.json``.
desktop_applied_config() {
  root="$(desktop_config_root)"
  [ -n "$root" ] || return
  applied="$(json_get_string_from_text "$(tr '\n' ' ' < "$root/configLibrary/_meta.json" 2>/dev/null)" appliedId)"
  printf '%s' "$applied" | grep "$UUID_PATTERN" >/dev/null 2>&1 || return
  tr '\n' ' ' < "$root/configLibrary/$applied.json" 2>/dev/null
}

desktop_oidc_block() {
  for key in inferenceIdpOidc inferenceGatewayOidc; do
    block="$(printf '%s' "$1" | sed -n "s/.*\"$key\"[[:space:]]*:[[:space:]]*{\([^}]*\)}.*/\1/p")"
    [ -n "$block" ] && { printf '%s' "$block"; return; }
  done
}

oidc_field() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\"\([^\"]*\)\".*/\1/p"
}

oidc_number() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\([0-9][0-9]*\).*/\1/p"
}

oidc_scopes() {
  scopes="$(printf '%s' "$1" | sed -n 's/.*"scopes"[[:space:]]*:[[:space:]]*\[\([^]]*\)\].*/\1/p' | tr -d '"' | tr ',' ' ')"
  [ -n "$scopes" ] || scopes="$(oidc_field "$1" scopes)"
  printf '%s' "$scopes" | tr -s '[:space:]' '\n' | grep -v -x -e '' -e offline_access -e openid | tr '\n' ' '
}

# Sets login_client_id, login_redirect_uri and login_scopes for origin $1.
databricks_login_client() {
  block="$(desktop_oidc_block "$(desktop_applied_config)")"
  client_id="$(oidc_field "$block" clientId)"
  if [ -n "$client_id" ] && [ "$(url_origin "$(oidc_field "$block" issuer)")" = "$1" ]; then
    port="$(oidc_number "$block" redirectPort)"
    host="$(oidc_field "$block" redirectHost)"
    [ -n "$port" ] || return 1
    login_client_id="$client_id"
    login_redirect_uri="http://${host:-127.0.0.1}:$port/callback"
    login_scopes="$(oidc_scopes "$block")openid"
    return 0
  fi
  login_client_id="$(env_value EVE_HOOK_DATABRICKS_CLIENT_ID "$DATABRICKS_CLI_CLIENT_ID")"
  login_redirect_uri="$(env_value EVE_HOOK_DATABRICKS_REDIRECT_URI "$DATABRICKS_CLI_REDIRECT_URI")"
  login_scopes="$(env_value EVE_HOOK_DATABRICKS_SCOPES "$DATABRICKS_CLI_SCOPES")"
}

# Desktop's applied config names the gateway even when the hook env does not
# (a terminal running ``eve-hook.sh databricks-login``).
desktop_gateway_origin() {
  config="$(desktop_applied_config)"
  origin="$(url_origin "$(json_get_string_from_text "$config" inferenceGatewayBaseUrl)")"
  is_databricks_origin "$origin" && printf '%s' "$origin"
}

random_urlsafe() {
  openssl rand -base64 "$1" 2>/dev/null | tr -d '\n=' | tr '+/' '-_'
}

pkce_challenge() {
  printf '%s' "$1" | openssl dgst -sha256 -binary 2>/dev/null | openssl base64 -A 2>/dev/null | tr -d '=' | tr '+/' '-_'
}

base64url_decode() {
  value="$(printf '%s' "$1" | tr '_-' '/+')"
  case $((${#value} % 4)) in 2) value="$value==" ;; 3) value="$value=" ;; esac
  printf '%s' "$value" | openssl base64 -d -A 2>/dev/null
}

open_browser() {
  opener="$(env_value EVE_HOOK_DATABRICKS_LOGIN_OPENER "")"
  if [ -z "$opener" ]; then
    if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then opener="open"
    elif [ -n "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ] && command -v xdg-open >/dev/null 2>&1; then opener="xdg-open"
    else return 1
    fi
  fi
  "$opener" "$1" >/dev/null 2>&1 &
}

redirect_port() {
  rest="${1#*://}"
  hostport="${rest%%/*}"
  case "$hostport" in *:*) printf '%s' "${hostport##*:}" ;; *) printf '80' ;; esac
}

# One callback on the loopback redirect: answer the browser, print the request
# line. The request (it carries the OAuth code) passes through a FIFO that is
# unlinked once both ends are open, so it never lands on disk. The watchdog
# ends ``nc`` when the wait runs out, which ends the ``read``.
await_callback() {
  fifo="$(databricks_cache_dir)/login-callback.$$" || return 1
  rm -f "$fifo"
  mkfifo "$fifo" 2>/dev/null || { debug_log "databricks sign-in needs mkfifo"; return 1; }
  printf 'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nConnection: close\r\n\r\n<html><body><h3>Eve Guard is now signed in to Databricks.</h3><p>You can close this tab.</p></body></html>' \
    | nc -l 127.0.0.1 "$1" > "$fifo" 2>/dev/null &
  listener=$!
  exec 3< "$fifo"
  rm -f "$fifo"
  sleep 0.3
  open_browser "$2" || { kill "$listener" 2>/dev/null; exec 3<&-; debug_log "databricks sign-in: no browser to open"; return 1; }
  ( sleep "$DATABRICKS_LOGIN_WAIT_S"; kill "$listener" ) >/dev/null 2>&1 &
  watchdog=$!
  IFS= read -r line <&3 || line=""
  exec 3<&-
  sleep 0.2
  kill "$listener" "$watchdog" 2>/dev/null
  case "$line" in 'GET '*) printf '%s' "$line" | tr -d '\r' ;; esac
}

query_param() {
  printf '%s' "$1" | sed -n "s/.*[?&]$2=\([^& ]*\).*/\1/p"
}

# Exchange the code; the verifier and code reach curl on stdin, never argv.
databricks_token_response() {
  printf 'grant_type=authorization_code&client_id=%s&code=%s&redirect_uri=%s&code_verifier=%s' \
    "$(url_encode "$login_client_id")" "$2" "$(url_encode "$login_redirect_uri")" "$3" \
    | curl --silent --max-time "$DATABRICKS_LOGIN_TOKEN_TIMEOUT_S" -X POST -H 'Content-Type: application/x-www-form-urlencoded' --data-binary @- "$1/oidc/v1/token" 2>/dev/null | tr '\n' ' '
}

id_token_email() {
  id_token="$(json_get_string_from_text "$1" id_token)"
  [ -n "$id_token" ] || return
  claims="$(base64url_decode "$(printf '%s' "$id_token" | cut -d. -f2)" | tr '\n' ' ')"
  for claim in email preferred_username upn sub; do
    value="$(json_get_string_from_text "$claims" "$claim")"
    usable_email "$value" 2>/dev/null && { printf '%s' "$value"; return; }
  done
}

databricks_login_email() {
  email="$(id_token_email "$2")"
  [ -n "$email" ] && { printf '%s' "$email"; return; }
  access_token="$(json_get_string_from_text "$2" access_token)"
  [ -n "$access_token" ] && databricks_me_email "$1" "$access_token"
}

# Foreground sign-in for origin $1: browser → callback → token → email.
databricks_login() {
  command -v nc >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 && command -v curl >/dev/null 2>&1 \
    || { debug_log "databricks sign-in needs nc, openssl and curl"; return 1; }
  databricks_login_client "$1" || { debug_log "databricks sign-in: Claude Desktop's OAuth app has no redirect port"; return 1; }
  verifier="$(random_urlsafe 48)"
  state="$(random_urlsafe 18)"
  url="$1/oidc/v1/authorize?client_id=$(url_encode "$login_client_id")&redirect_uri=$(url_encode "$login_redirect_uri")&response_type=code&state=$state&code_challenge=$(pkce_challenge "$verifier")&code_challenge_method=S256&scope=$(url_encode "$login_scopes")"
  debug_log "databricks sign-in: opening $1 for client $login_client_id"
  printf 'Eve Guard: sign in to Databricks in your browser. If no browser opened, visit:\n%s\n' "$url" >&2
  callback="$(await_callback "$(redirect_port "$login_redirect_uri")" "$url")"
  [ "$(query_param "$callback" state)" = "$state" ] || { debug_log "databricks sign-in: no callback or a state mismatch $(query_param "$callback" error)"; return 1; }
  code="$(query_param "$callback" code)"
  [ -n "$code" ] || { debug_log "databricks sign-in refused: $(query_param "$callback" error)"; return 1; }
  email="$(databricks_login_email "$1" "$(databricks_token_response "$1" "$code" "$verifier")")"
  [ -n "$email" ] || { debug_log "databricks sign-in: the token response named no user"; return 1; }
  file="$(databricks_login_cache_file "$1")" && databricks_cache_write "$file" "$email"
  debug_log "databricks sign-in complete"
  printf 'Eve Guard: signed in to Databricks as %s\n' "$email" >&2
}

# Hooks never wait on a browser: the sign-in runs detached, at most once per
# DATABRICKS_LOGIN_RETRY_MIN, and only for Claude Code (incl. Desktop).
databricks_login_maybe_start() {
  [ "$agent" = "claude-code" ] && databricks_login_enabled || { AUDIT_SIGN_ACTION="skipped"; AUDIT_SIGN_REASON="login_disabled"; return 0; }
  marker="$(databricks_login_attempt_file "$1")" || return 0
  if cache_fresh "$marker" "$DATABRICKS_LOGIN_RETRY_MIN"; then
    AUDIT_SIGN_ACTION="skipped"
    AUDIT_SIGN_REASON="backoff"
    return 0
  fi
  databricks_cache_write "$marker" ""
  AUDIT_SIGN_ACTION="started_background"
  AUDIT_SIGN_REASON="no_identity"
  debug_log "databricks: no identity yet; starting the Eve Databricks sign-in in the background"
  nohup /bin/sh "$0" databricks-login "$1" </dev/null >/dev/null 2>&1 &
}

databricks_login_command() {
  apply_config
  origin="$(url_origin "${1:-}")"
  [ -n "$origin" ] || origin="$(workspace_origin)"
  [ -n "$origin" ] || origin="$(desktop_gateway_origin)"
  [ -n "$origin" ] || origin="$(url_origin "$(env_value DATABRICKS_HOST "")")"
  [ -n "$origin" ] || { printf 'Eve Guard: no Databricks workspace found. Pass it: databricks-login https://<workspace>\n' >&2; return 2; }
  databricks_login "$origin"
}

# SessionStart: start the sign-in before the first tool call when nothing
# else can name the user.
prime_databricks_login() {
  [ "$event_name" = "SessionStart" ] && databricks_workspace_detected || return 0
  [ -z "$(gateway_env_token)" ] && [ -z "$(env_value DATABRICKS_TOKEN "")" ] || return 0
  origin="$(workspace_origin)"
  [ -z "$(otel_enduser_email)" ] && [ -z "$(databricks_login_cached_email "$origin")" ] || return 0
  # A CLI on PATH is not a CLI login: ask it, and sign in only if it has none.
  databricks_target_email "$origin" "" >/dev/null && return 0
  databricks_login_maybe_start "$origin"
}

databricks_workspace_detected() {
  [ "$(env_value EVE_HOOK_DATABRICKS_IDENTITY "")" = "0" ] && return 1
  [ -n "$(gateway_origin)" ]
}

# Sources that need no network: the payload, env vars, the Cowork envelope.
early_user_email() {
  payload_email="$(json_get_string_from_text "$1" user_email)"
  if usable_email "$payload_email"; then
    audit_set_winner "payload_user_email" "payload user_email"
    audit_step "payload_user_email" "ok"
    debug_log "user_email resolved from payload user_email"
    printf '%s' "$payload_email"
    return
  fi
  audit_step "payload_user_email" "skipped" "not_usable"
  for name in CURSOR_USER_EMAIL CLAUDE_CODE_USER_EMAIL CLAUDE_USER_EMAIL USER_EMAIL; do
    value="$(env_value "$name" "")"
    if usable_email "$value"; then
      audit_set_winner "env_user_email" "env $name"
      audit_step "env_user_email" "ok"
      debug_log "user_email resolved from env $name"
      printf '%s' "$value"
      return
    fi
  done
  audit_step "env_user_email" "skipped" "not_usable"
  email="$(envelope_email "$(payload_transcript_path "$1")")"
  if [ -n "$email" ]; then
    audit_set_winner "session_envelope" "session envelope"
    audit_step "session_envelope" "ok"
    debug_log "user_email resolved from session envelope"
    printf '%s' "$email"
  else
    audit_step "session_envelope" "skipped" "not_usable"
  fi
}

codex_auth_path() {
  codex_home="$(env_value CODEX_HOME "")"
  if [ -n "$codex_home" ]; then
    printf '%s' "$codex_home/auth.json"
    return
  fi
  home="$(env_value HOME "")"
  [ -n "$home" ] && printf '%s' "$home/.codex/auth.json"
}

# Email claim inside Codex's ``tokens.id_token``. No signature check: the
# file is the local login Codex itself wrote. A missing or unusable claim
# stays anonymous — ``.claude.json`` belongs to a different account.
codex_auth_email() {
  file="$(codex_auth_path)"
  [ -n "$file" ] && [ -f "$file" ] || return
  [ "$(wc -c < "$file" | tr -d ' ')" -le 16777216 ] || return
  token="$(json_get_nested_string_from_text "$(tr '\n' ' ' < "$file")" tokens id_token)"
  [ -n "$token" ] || return
  id_token_email "$(printf '{"id_token":"%s"}' "$token")"
}

codex_auth_user_email() {
  email="$(codex_auth_email)"
  if [ -n "$email" ]; then
    audit_set_winner "codex_auth" "Codex auth.json"
    audit_step "codex_auth" "ok"
    debug_log "user_email resolved from Codex auth.json"
  else
    audit_step "codex_auth" "miss"
  fi
  printf '%s' "$email"
}

user_email() {
  email="$(early_user_email "$1")"
  [ -n "$email" ] && { printf '%s' "$email"; return; }
  if [ "$agent" = "codex" ]; then
    codex_auth_user_email
    return
  fi
  # .claude.json may be another account's claude.ai login on this machine,
  # so it never stands in for a Databricks workspace's own answer.
  if databricks_workspace_detected; then
    email="$(databricks_email)"
    [ -n "$email" ] || debug_log "no Databricks identity yet; not using .claude.json, sending no user_email"
    printf '%s' "$email"
    return
  fi
  email="$(claude_config_email)"
  if [ -n "$email" ]; then
    audit_set_winner "claude_json" ".claude.json oauthAccount"
    audit_step "claude_json" "ok"
    debug_log "user_email resolved from .claude.json oauthAccount"
  else
    audit_step "claude_json" "miss"
  fi
  printf '%s' "$email"
}

process_parent() {
  if [ -r "/proc/$1/status" ]; then
    sed -n 's/^PPid:[[:space:]]*//p' "/proc/$1/status"
  else
    ps -o ppid= -p "$1" 2>/dev/null | tr -d ' '
  fi
}

process_args() {
  if [ -r "/proc/$1/cmdline" ]; then
    tr '\0' '\n' < "/proc/$1/cmdline"
  else
    ps -o args= -p "$1" 2>/dev/null | tr ' ' '\n'
  fi
}

is_cursor_cli_version() {
  printf '%s' "$1" | grep -E '^[0-9]{4}\.[0-9]{1,2}\.[0-9]{1,2}([^0-9]|$)' >/dev/null 2>&1
}

# The Cursor CLI sends the same payload in print mode (-p) and interactive
# mode, but only interactive mode fires `stop`, which carries the agent's
# answers back. The cursor-agent process's own argv is the one place the two
# differ; any ancestor in print mode wins over one without the flag. Only the
# leading tokens (node, its flags, the CLI entry point) identify the process:
# the `sh -c` that runs this hook carries the payload in its argv too.
is_cursor_agent_process() {
  printf '%s\n' "$1" | head -n 3 | grep -E '(^|/)cursor-agent(\.exe)?$|/cursor-agent/.*index\.js$' >/dev/null 2>&1
}

cursor_cli_mode() {
  ancestor_pid="$$"
  ancestor_depth=0
  cli_mode=""
  while [ "$ancestor_depth" -lt "$CURSOR_ANCESTOR_DEPTH" ] && [ -n "$ancestor_pid" ] && [ "$ancestor_pid" -gt 1 ] 2>/dev/null; do
    ancestor_args="$(process_args "$ancestor_pid")"
    if is_cursor_agent_process "$ancestor_args"; then
      printf '%s\n' "$ancestor_args" | grep -xE -- '-p|--print' >/dev/null 2>&1 && { printf 'print'; return; }
      cli_mode="interactive"
    fi
    ancestor_pid="$(process_parent "$ancestor_pid")"
    ancestor_depth=$((ancestor_depth + 1))
  done
  printf '%s' "$cli_mode"
}

AUDIT_WINNER="none"
AUDIT_WINNER_LABEL=""
AUDIT_SIGN_ACTION="none"
AUDIT_SIGN_REASON=""
AUDIT_STEPS=""
AUDIT_DBX_MODE="false"
AUDIT_DBX_REASON=""
AUDIT_WORKSPACE_FP=""

audit_step() {
  part="{\"step\":\"$(json_escape "$1")\",\"outcome\":\"$(json_escape "$2")\""
  [ -n "$3" ] && part="$part,\"detail\":\"$(json_escape "$3")\""
  [ -n "$4" ] && part="$part,\"cache\":\"$(json_escape "$4")\""
  AUDIT_STEPS="${AUDIT_STEPS}${part}},"
}

audit_set_winner() {
  AUDIT_WINNER="$1"
  AUDIT_WINNER_LABEL="$2"
}

identity_audit_record_mode() {
  if [ "$(env_value EVE_HOOK_DATABRICKS_IDENTITY "")" = "0" ]; then
    AUDIT_DBX_MODE="false"
    AUDIT_DBX_REASON="identity_disabled"
    audit_step "databricks_mode" "off" "identity_disabled"
    return
  fi
  if [ -n "$(gateway_origin)" ]; then
    AUDIT_DBX_MODE="true"
    AUDIT_DBX_REASON="anthropic_base_url"
    origin="$(workspace_origin)"
    if [ -n "$origin" ]; then
      AUDIT_WORKSPACE_FP="$(printf '%s' "$origin" | sha256_hex | cut -c1-12)"
    fi
    audit_step "databricks_mode" "on" "anthropic_base_url"
    return
  fi
  AUDIT_DBX_MODE="false"
  AUDIT_DBX_REASON="off_no_gateway"
  audit_step "databricks_mode" "off" "no_databricks_base_url"
}

identity_audit_extras() {
  version="$(json_get_string_from_text "$(load_config_text)" hook_code_version)"
  steps="${AUDIT_STEPS%,}"
  printf ',"eve_identity_resolution":{"v":1,"runtime":"hook.sh","hook_code_version":"%s","databricks_mode":%s,"databricks_mode_reason":"%s","workspace_fp":"%s","winner":"%s","winner_label":"%s","steps":[%s],"sign_in":{"action":"%s","reason":"%s"}}' \
    "$(json_escape "$version")" "$AUDIT_DBX_MODE" "$(json_escape "$AUDIT_DBX_REASON")" "$(json_escape "$AUDIT_WORKSPACE_FP")" \
    "$(json_escape "$AUDIT_WINNER")" "$(json_escape "$AUDIT_WINNER_LABEL")" "$steps" \
    "$(json_escape "$AUDIT_SIGN_ACTION")" "$(json_escape "$AUDIT_SIGN_REASON")"
}

cursor_cli_mode_field() {
  [ "$agent" = "cursor" ] || return 0
  cli_version="$(json_get_string_from_text "$1" cursor_version)"
  [ -n "$cli_version" ] || cli_version="$(env_value CURSOR_VERSION "")"
  is_cursor_cli_version "$cli_version" || return 0
  cli_mode="$(cursor_cli_mode)"
  [ -n "$cli_mode" ] && printf ',"eve_cursor_cli_mode":"%s"' "$cli_mode"
}

append_payload_fields() {
  raw="$1"
  AUDIT_WINNER="none"
  AUDIT_WINNER_LABEL=""
  AUDIT_SIGN_ACTION="none"
  AUDIT_SIGN_REASON=""
  AUDIT_STEPS=""
  identity_audit_record_mode
  extras="$(cursor_cli_mode_field "$raw")"
  email=""
  # A lifecycle event never waits on /Me, the CLI or a sign-in, but keeps an
  # email it already has: the guard matches it against the tool calls'.
  if is_lifecycle_event && databricks_workspace_detected; then
    prime_databricks_login
    email="$(early_user_email "$raw")"
  else
    email="$(user_email "$raw")"
  fi
  guid="$(calling_guid "$raw")"
  [ -n "$email" ] && extras="$extras,\"user_email\":\"$(json_escape "$email")\""
  # No real source: blank out a placeholder the payload carried. The guard's
  # JSON parser keeps the last duplicate key, and a blank email is anonymous.
  [ -z "$email" ] && [ -n "$(json_get_string_from_text "$raw" user_email)" ] && extras="$extras,\"user_email\":\"\""
  if [ -n "$guid" ]; then
    extras="$extras,\"eve_mcp_directory_uuid\":\"$(json_escape "$guid")\""
    tools="$(namespace_tools_json "$(payload_transcript_path "$raw")" "$guid")"
    [ -n "$tools" ] && extras="$extras,\"eve_mcp_namespace_tools\":[$tools]"
  fi
  [ -z "$email" ] && [ "$AUDIT_WINNER" = "none" ] && audit_step "identity" "miss" "anonymous"
  extras="$extras$(identity_audit_extras)"
  [ -z "$extras" ] && { printf '%s' "$raw"; return; }
  trimmed="$(printf '%s' "$raw" | sed 's/[[:space:]]*$//')"
  case "$trimmed" in
    *}) printf '%s%s}' "${trimmed%?}" "$extras" ;;
    *) printf '%s' "$raw" ;;
  esac
}

is_transient() {
  # Our own request timeout (curl 28, "timeout after Xms") is deliberately
  # not here: it means the guard accepted the request and is still working,
  # so a retry duplicates in-flight work instead of recovering from a lost
  # one. Every code below means the request never landed.
  printf '%s' "$1" | grep -E 'EAI_AGAIN|EAI_NODATA|EAI_NONAME|ECONNRESET|ECONNREFUSED|ETIMEDOUT|ENOTFOUND|socket hang up|curl exit (6|7|18|35|52|55|56|92)\b' >/dev/null 2>&1
}

# A Cursor cloud agent has no desktop login to read an email from, but Cursor
# signs a token naming the run's owner on a local socket. The guard checks
# that signature, so this hook never vouches for the email itself. A token
# lives 5 minutes and minting one takes ~120 ms: reuse it for 3.
cursor_identity_cache_file() {
  uid="$(id -u 2>/dev/null || printf user)"
  key="$(printf '%s' "$1" | cksum | awk '{print $1}')"
  printf '%s/eve-guard-hook-identity-%s/cursor-%s.jwt' "${TMPDIR:-/tmp}" "$uid" "$key"
}

is_jwt() {
  printf '%s' "$1" | grep -E '^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$' >/dev/null 2>&1
}

cursor_identity_mint() {
  nonce="$(random_urlsafe 16)"
  [ -n "$nonce" ] || nonce="$$-$(date +%s)"
  body="{\"aud\":\"$(json_escape "$1")\",\"nonce\":\"$nonce\"}"
  reply="$(curl --silent --fail --max-time 2 --unix-socket "$2" -X POST \
    -H "Content-Type: application/json" --data-binary "$body" \
    http://localhost/v1/tokens/oidc 2>/dev/null)" || return 1
  json_get_string_from_text "$reply" token
}

cursor_identity_cache_write() {
  old_umask="$(umask)"
  umask 077
  mkdir -p "$(dirname "$1")" 2>/dev/null && printf '%s' "$2" > "$1" 2>/dev/null
  umask "$old_umask"
}

cursor_identity_token() {
  [ "$(env_value EVE_HOOK_CURSOR_IDENTITY "")" = "0" ] && return 0
  socket="$(env_value CURSOR_AGENT_SOCKET "")"
  [ -S "$socket" ] || return 0
  cache="$(cursor_identity_cache_file "$1")"
  if [ -f "$cache" ] && ! find "$cache" -mmin +3 -print 2>/dev/null | grep . >/dev/null 2>&1; then
    token="$(cat "$cache" 2>/dev/null)"
    is_jwt "$token" && { printf '%s' "$token"; return 0; }
  fi
  token="$(cursor_identity_mint "$1" "$socket")"
  is_jwt "$token" || { debug_log "no Cursor identity token from $socket"; return 0; }
  cursor_identity_cache_write "$cache" "$token"
  printf '%s' "$token"
}

cursor_identity_dir() {
  uid="$(id -u 2>/dev/null || printf user)"
  printf '%s/eve-guard-hook-identity-%s' "${TMPDIR:-/tmp}" "$uid"
}

cursor_session_get() {
  sed -n "s/^$2=//p" "$1" 2>/dev/null | head -1
}

cursor_session_write() {
  old_umask="$(umask)"
  umask 077
  mkdir -p "$(dirname "$1")" 2>/dev/null
  printf 'token=%s\nexpires_at=%s\nrefresh=%s\nperiod_started_at=%s\nperiod_days=%s\n' \
    "$2" "$3" "$4" "$5" "$6" > "$1" 2>/dev/null
  umask "$old_umask"
}

cursor_json_number() {
  printf '%s' "$1" | sed -n "s/.*\"$2\"[[:space:]]*:[[:space:]]*\\([0-9][0-9]*\\).*/\\1/p" | head -1
}

cursor_device_id() {
  file="$(cursor_identity_dir)/device-id"
  if [ -f "$file" ]; then cat "$file"; return 0; fi
  id="$(random_urlsafe 16)"
  [ -n "$id" ] || id="$$-$(date +%s)"
  old_umask="$(umask)"
  umask 077
  mkdir -p "$(cursor_identity_dir)" 2>/dev/null
  printf '%s' "$id" > "$file"
  umask "$old_umask"
  printf '%s' "$id"
}

cursor_cached_token() {
  [ -f "$1" ] || return 1
  token="$(cursor_session_get "$1" token)"
  exp="$(cursor_session_get "$1" expires_at)"
  now="$(date +%s)"
  [ -n "$token" ] && [ -n "$exp" ] || return 1
  [ "$now" -lt "$((exp - 60))" ] || return 1
  printf '%s' "$token"
}

cursor_open_login_once() {
  lock="$(cursor_identity_dir)/login-opened"
  if [ -f "$lock" ] && ! find "$lock" -mmin +15 -print 2>/dev/null | grep . >/dev/null 2>&1; then
    return 0
  fi
  mkdir -p "$(cursor_identity_dir)" 2>/dev/null
  printf '%s' "$$" > "$lock"
  case "$(uname -s 2>/dev/null)" in
    Darwin) open "$1" >/dev/null 2>&1 & ;;
    *) command -v xdg-open >/dev/null 2>&1 && xdg-open "$1" >/dev/null 2>&1 & ;;
  esac
  return 0
}

cursor_guard_post() {
  base="$(printf '%s' "$(env_value EVE_ORCHESTRATOR_URL "")" | sed 's:/*$::')"
  hook="$(env_value EVE_HOOK_TOKEN "")"
  curl --silent --show-error --max-time 5 -X POST \
    -H "Authorization: Bearer $hook" -H "Content-Type: application/json" \
    --data-binary "$2" "$base/hooks/cursor/$1" 2>/dev/null
}

prepare_cursor_federated() {
  CURSOR_FEDERATED_TOKEN=""
  CURSOR_EXCHANGE_REJECTED=""
  CURSOR_LOCAL_DENY=""
  [ "$agent" = "cursor" ] || return 0
  is_lifecycle_event && return 0
  [ -n "$(env_value EVE_HOOK_USER_TOKEN "")" ] && return 0
  base="$(printf '%s' "$(env_value EVE_ORCHESTRATOR_URL "")" | sed 's:/*$::')"
  [ -n "$base" ] || return 0
  socket="$(env_value CURSOR_AGENT_SOCKET "")"
  if [ -S "$socket" ]; then
    prepare_cursor_cloud "$base" "$socket"
    return 0
  fi
  prepare_cursor_laptop "$base"
}

cursor_exchange_drops_identity() {
  case "$1" in
    not_active|owner_mismatch|replayed_jti|unsupported_principal|wrong_issuer|wrong_aud|invalid_token|expired) return 0 ;;
  esac
  return 1
}

cursor_cloud_token() {
  minted="$(cursor_identity_mint "$1" "$2")" || return 1
  is_jwt "$minted" || return 1
  cursor_identity_cache_write "$(cursor_identity_cache_file "$1")" "$minted"
  printf '%s' "$minted"
}

prepare_cursor_cloud() {
  cache="$(cursor_identity_dir)/cloud-$(printf '%s' "$1" | cksum | awk '{print $1}').session"
  cached="$(cursor_cached_token "$cache")" && { CURSOR_FEDERATED_TOKEN="$cached"; return 0; }
  cursor="$(cursor_cloud_token "$1" "$2")" || return 0
  body="{\"cursor_token\":\"$(json_escape "$cursor")\",\"guard_url\":\"$(json_escape "$1")\"}"
  resp="$(cursor_guard_post exchange "$body")" || return 0
  token="$(json_get_string_from_text "$resp" access_token)"
  if [ -z "$token" ]; then
    reason="$(json_get_string_from_text "$resp" reason)"
    cursor_exchange_drops_identity "$reason" && CURSOR_EXCHANGE_REJECTED=1
    return 0
  fi
  expires="$(cursor_json_number "$resp" expires_in)"
  [ -n "$expires" ] || expires=900
  now="$(date +%s)"
  cursor_session_write "$cache" "$token" "$((now + expires))" "" "$now" 7
  CURSOR_FEDERATED_TOKEN="$token"
}

prepare_cursor_laptop() {
  device="$(cursor_device_id)"
  policy="$(curl --silent --show-error --max-time 2 \
    -H "Authorization: Bearer $(env_value EVE_HOOK_TOKEN "")" \
    "$1/hooks/cursor/session-policy?device_id=$(printf '%s' "$device" | sed 's/[^A-Za-z0-9_-]//g')" 2>/dev/null)" || return 0
  printf '%s' "$policy" | grep -q '"enabled"[[:space:]]*:[[:space:]]*true' || return 0
  file="$(cursor_identity_dir)/laptop.session"
  cached="$(cursor_cached_token "$file")" && { CURSOR_FEDERATED_TOKEN="$cached"; return 0; }
  if cursor_laptop_refresh "$file"; then return 0; fi
  claim="$(cursor_guard_post claim "{\"device_id\":\"$(json_escape "$device")\"}")" || {
    return 0
  }
  if printf '%s' "$claim" | grep -q '"pending"[[:space:]]*:[[:space:]]*true'; then
    cursor_store_claim "$file" "$claim"
    return 0
  fi
  login="$(json_get_string_from_text "$policy" loginUrl)"
  [ -n "$login" ] && cursor_open_login_once "$login"
  CURSOR_LOCAL_DENY="Sign in to Eve Guard to continue. A browser window was opened."
}

cursor_laptop_refresh() {
  [ -f "$1" ] || return 1
  refresh="$(cursor_session_get "$1" refresh)"
  [ -n "$refresh" ] || return 1
  started="$(cursor_session_get "$1" period_started_at)"
  days="$(cursor_session_get "$1" period_days)"
  now="$(date +%s)"
  [ -n "$started" ] && [ -n "$days" ] || return 1
  if [ "$now" -ge "$((started + days * 86400))" ]; then
    login="$(json_get_string_from_text "$policy" loginUrl)"
    [ -n "$login" ] && cursor_open_login_once "$login"
    CURSOR_LOCAL_DENY="Eve Guard needs you to sign in again."
    return 0
  fi
  token="$(cursor_session_get "$1" token)"
  exp="$(cursor_session_get "$1" expires_at)"
  body="{\"device_id\":\"$(json_escape "$(cursor_device_id)")\",\"refresh_token\":\"$(json_escape "$refresh")\",\"existing_access_token\":\"$(json_escape "$token")\",\"existing_expires_at\":${exp:-0}}"
  resp="$(cursor_guard_post refresh "$body")" || return 1
  fresh="$(json_get_string_from_text "$resp" access_token)"
  [ -n "$fresh" ] || return 1
  expires="$(cursor_json_number "$resp" expires_in)"
  [ -n "$expires" ] || expires=900
  cursor_session_write "$1" "$fresh" "$((now + expires))" "$refresh" "$started" "$days"
  CURSOR_FEDERATED_TOKEN="$fresh"
  return 0
}

cursor_store_claim() {
  token="$(json_get_string_from_text "$2" access_token)"
  refresh="$(json_get_string_from_text "$2" refresh_token)"
  [ -n "$token" ] && [ -n "$refresh" ] || return 1
  expires="$(cursor_json_number "$2" expires_in)"
  days="$(cursor_json_number "$2" period_days)"
  [ -n "$expires" ] || expires=900
  [ -n "$days" ] || days=7
  now="$(date +%s)"
  cursor_session_write "$1" "$token" "$((now + expires))" "$refresh" "$now" "$days"
  CURSOR_FEDERATED_TOKEN="$token"
}

dispatch_once() {
  [ "$(env_value EVE_HOOK_DISABLE_CURL "")" = "1" ] && { printf '%s' "ERR curl disabled"; return 1; }
  command -v curl >/dev/null 2>&1 || { printf '%s' "ERR curl not found"; return 1; }
  base="$(env_value EVE_ORCHESTRATOR_URL "")"
  [ -n "$base" ] || { printf '%s' "ERR EVE_ORCHESTRATOR_URL not set"; return 1; }

  endpoint="$(printf '%s/hooks/%s/%s' "$(printf '%s' "$base" | sed 's:/*$::')" "$agent" "$event_name")"
  body_file="$(mktemp "${TMPDIR:-/tmp}/eve-hook-body.XXXXXX")"
  err_file="$(mktemp "${TMPDIR:-/tmp}/eve-hook-err.XXXXXX")"
  printf '%s' "$1" > "$body_file"

  # Header list built with `set --` (POSIX sh has no arrays). The payload
  # in $1 has already been written to $body_file, so clobbering the
  # positional parameters here is safe.
  set -- -H "Content-Type: application/json; charset=utf-8"
  plugin_id="$(env_value EVE_HOOK_PLUGIN_ID "")"
  if printf '%s' "$plugin_id" | grep -E '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$' >/dev/null 2>&1; then
    set -- "$@" -H "X-Eve-Hook-Plugin-Id: $plugin_id"
  fi
  # Lets the guard honour fail-closed for its own verification errors too.
  set -- "$@" -H "X-Eve-Hook-Failure-Mode: $(failure_mode)"
  hook_token="$(env_value EVE_HOOK_TOKEN "")"
  [ -n "$hook_token" ] && set -- "$@" -H "Authorization: Bearer $hook_token"
  user_token="$(env_value EVE_HOOK_USER_TOKEN "")"
  [ -z "$user_token" ] && user_token="$CURSOR_FEDERATED_TOKEN"
  [ -n "$user_token" ] && set -- "$@" -H "X-Eve-User-Token: $user_token"
  capabilities="$(env_value EVE_HOOK_CAPABILITIES "")"
  [ -n "$capabilities" ] && set -- "$@" -H "X-Eve-Hook-Capabilities: $capabilities"
  if ! is_lifecycle_event && [ -z "$CURSOR_FEDERATED_TOKEN" ] && [ -z "$CURSOR_EXCHANGE_REJECTED" ]; then
    identity_token="$(cursor_identity_token "$(printf '%s' "$base" | sed 's:/*$::')")"
    [ -n "$identity_token" ] && set -- "$@" -H "X-Eve-Cursor-Identity: $identity_token"
  fi

  response="$(curl --silent --show-error --max-time "$(request_timeout_s)" -X POST "$@" --data-binary "@$body_file" -w '\n__EVE_HOOK_STATUS__:%{http_code}' "$endpoint" 2>"$err_file")"

  code=$?
  rm -f "$body_file"
  status="$(printf '%s' "$response" | sed -n 's/^__EVE_HOOK_STATUS__://p' | tail -1)"
  body="$(printf '%s' "$response" | sed '/^__EVE_HOOK_STATUS__:/d')"

  if [ "$code" -ne 0 ]; then
    stderr="$(sed 's/[[:space:]]*$//' "$err_file" 2>/dev/null)"
    rm -f "$err_file"
    printf '%s' "ERR curl exit $code: ${stderr:-no stderr}"
    return 1
  fi
  rm -f "$err_file"
  case "$status" in
    2*) printf '%s' "$body"; return 0 ;;
    *) printf '%s' "ERR Eve Guard HTTP ${status:-0}: $(truncate_text "$body")"; return 1 ;;
  esac
}

dispatch_with_retry() {
  max="$(max_retries)"
  attempt=0
  while [ "$attempt" -le "$max" ]; do
    result="$(dispatch_once "$1")" && { printf '%s' "$result"; return 0; }
    reason="${result#ERR }"
    if ! is_transient "$reason" || [ "$attempt" -eq "$max" ]; then
      printf '%s' "$reason"
      return 1
    fi
    sleep "$retry_backoff_s"
    attempt=$((attempt + 1))
  done
}

main() {
  apply_config
  raw_payload="$(cat)"
  prepare_cursor_federated
  if [ -n "$CURSOR_LOCAL_DENY" ]; then
    deny_response "$CURSOR_LOCAL_DENY"
    exit 0
  fi
  session_id="$(json_get_string_from_text "$raw_payload" session_id)"
  payload="$(append_payload_fields "$raw_payload")"
  result="$(dispatch_with_retry "$payload")" && { printf '%s' "$result"; exit 0; }
  debug_log "dispatch failed: $result"
  failure_response "$session_id" "$result" "$payload"
  exit 0
}

if [ "$agent" = "databricks-login" ]; then
  databricks_login_command "${2:-}"
  exit $?
fi
main
