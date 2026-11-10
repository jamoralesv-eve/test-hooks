param(
  [string]$Agent = "claude-code",
  [string]$EventName = "PreToolUse"
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference = "SilentlyContinue"

$PostToolUseEvent = "PostToolUse"
$RetryBackoffMs = 150
# A turn-stop hook may wait on the interrogation judge reading the agent's
# answers, which takes longer than a policy check.
$TurnStopTimeoutSeconds = 30
# Agent reply / turn stop / session start hooks (interrogation's reply
# channel). They never gate a tool, so every failure answers "{}": a deny
# shape here would stop the agent outright.
$LifecycleEvents = @("Stop", "SubagentStop", "SessionStart", "afterAgentResponse", "stop", "sessionStart")
$TurnStopEvents = @("Stop", "SubagentStop", "stop")
$StateFileTtlSeconds = 3600
$CursorAncestorDepth = 12
$FailureLogDirName = "eve-guard-hook-diagnostics"
$FailureLogFileName = "failures.jsonl"
$LastFailureFileName = "last-failure.json"
# Our own request timeout (curl 28, "timeout after Xms") is deliberately
# absent: it means the guard accepted the request and is still working, so a
# retry duplicates in-flight work. Every pattern below means the request
# never reached the guard.
$TransientPatterns = @(
  "EAI_AGAIN", "EAI_NODATA", "EAI_NONAME", "ECONNRESET", "ECONNREFUSED",
  "ETIMEDOUT", "ENOTFOUND", "socket hang up",
  "curl exit (6|7|18|35|52|55|56|92)\b"
)

function Get-EnvValue([string]$Name, [string]$Default = "") {
  $value = [Environment]::GetEnvironmentVariable($Name)
  if ([string]::IsNullOrWhiteSpace($value)) { return $Default }
  return $value.Trim()
}

function Write-DebugLog([string]$Message) {
  if ((Get-EnvValue "EVE_HOOK_DEBUG") -eq "1") {
    [Console]::Error.WriteLine("[eve-hook] $Message")
  }
}

function Get-FailureLogDir {
  $dir = Join-Path ([IO.Path]::GetTempPath()) $FailureLogDirName
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  return $dir
}

function Get-FailureLogPath {
  return Join-Path (Get-FailureLogDir) $FailureLogFileName
}

function Get-LastFailurePath {
  return Join-Path (Get-FailureLogDir) $LastFailureFileName
}

function Truncate-Text([string]$Value, [int]$MaxLength = 700) {
  if ([string]::IsNullOrEmpty($Value)) { return "" }
  if ($Value.Length -le $MaxLength) { return $Value }
  return $Value.Substring(0, $MaxLength) + "...[truncated]"
}

function Read-JsonObject([string]$Text) {
  try { return $Text | ConvertFrom-Json } catch { return $null }
}

function Has-Property($Object, [string]$Name) {
  return $null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]
}

function Get-Property($Object, [string]$Name, $Default = $null) {
  if (Has-Property $Object $Name) { return $Object.PSObject.Properties[$Name].Value }
  return $Default
}

function Set-Property($Object, [string]$Name, $Value) {
  if (Has-Property $Object $Name) {
    $Object.PSObject.Properties[$Name].Value = $Value
    return
  }
  $Object | Add-Member -NotePropertyName $Name -NotePropertyValue $Value
}

function Get-PayloadKeys($Payload) {
  if ($null -eq $Payload) { return @() }
  return @($Payload.PSObject.Properties | ForEach-Object { $_.Name })
}

function Has-AnyProperty($Object, [string[]]$Names) {
  foreach ($name in $Names) {
    if (Has-Property $Object $name) { return $true }
  }
  return $false
}

function Extract-HttpStatus([string]$Reason) {
  $match = [regex]::Match($Reason, "Eve Guard HTTP (\d+)")
  if ($match.Success) { return [int]$match.Groups[1].Value }
  return $null
}

function Extract-ResponsePreview([string]$Reason) {
  $match = [regex]::Match($Reason, "Eve Guard HTTP \d+:\s*(.*)$")
  if ($match.Success) { return Truncate-Text $match.Groups[1].Value }
  return ""
}

function Get-ConfigPath {
  $root = Get-EnvValue "CLAUDE_PLUGIN_ROOT"
  if ($root) {
    $candidate = Join-Path $root "eve.config.json"
    if (Test-Path -LiteralPath $candidate) { return $candidate }
  }
  # Cursor sets no plugin-root env, so discover the config relative to the
  # script: the launcher is at <root>/hooks/cursor-hook.ps1 and the config
  # at <root>/eve.config.json, i.e. $PSScriptRoot/../eve.config.json. The
  # same path also resolves for Claude, so this is a safe superset.
  if ($PSScriptRoot) {
    $candidate = Join-Path (Split-Path -Parent $PSScriptRoot) "eve.config.json"
    if (Test-Path -LiteralPath $candidate) { return $candidate }
  }
  return $null
}

function Read-BakedConfig {
  $path = Get-ConfigPath
  if (-not $path) { return $null }
  return Read-JsonObject ([IO.File]::ReadAllText($path))
}

function Set-EnvIfMissing([string]$Name, $Value) {
  if ($null -eq $Value -or (Get-EnvValue $Name)) { return }
  Set-Item -Path "Env:$Name" -Value ([string]$Value)
}

function Apply-BakedConfig($Config) {
  if ($null -eq $Config) { return }
  Set-EnvIfMissing "EVE_ORCHESTRATOR_URL" (Get-Property $Config "orchestrator_url")
  Set-EnvIfMissing "EVE_HOOK_TENANT_ID" (Get-Property $Config "tenant_id")
  Set-EnvIfMissing "EVE_HOOK_PLUGIN_ID" (Get-Property $Config "plugin_id")
  Set-EnvIfMissing "EVE_HOOK_TOKEN" (Get-Property $Config "hook_token")
  Set-EnvIfMissing "EVE_HOOK_CONFIG_HASH" (Get-Property $Config "config_hash")
  Set-EnvIfMissing "EVE_HOOK_TIMEOUT_S" (Get-Property $Config "timeout_s")
  Set-EnvIfMissing "EVE_HOOK_FAILURE_MODE" (Get-Property $Config "failure_mode")
  Set-EnvIfMissing "EVE_HOOK_MAX_RETRIES" (Get-Property $Config "max_retries")
  Set-EnvIfMissing "EVE_HOOK_USER_TOKEN" (Get-Property $Config "user_token")
  Set-EnvIfMissing "EVE_HOOK_CAPABILITIES" (Get-Property $Config "capabilities")
  Set-EnvIfMissing "EVE_HOOK_DEBUG" $(if ((Get-Property $Config "debug") -eq $true) { "1" } else { "0" })
  Set-EnvIfMissing "EVE_HOOK_DISABLE_CURL" $(if ((Get-Property $Config "disable_curl") -eq $true) { "1" } else { "0" })
}

function Get-TimeoutSeconds {
  $raw = Get-EnvValue "EVE_HOOK_TIMEOUT_S" "8"
  $value = 8
  [void][int]::TryParse($raw, [ref]$value)
  return [Math]::Min(30, [Math]::Max(1, $value))
}

function Get-RequestTimeoutSeconds {
  if ($TurnStopEvents -ccontains $EventName) { return $TurnStopTimeoutSeconds }
  return Get-TimeoutSeconds
}

# What this bundle installed beyond tool hooks (e.g. "reply-text" when the
# stop hook is there to carry the agent's interrogation answers back).
function Get-HookCapabilities {
  return Get-EnvValue "EVE_HOOK_CAPABILITIES" ""
}

function Get-MaxRetries {
  $raw = Get-EnvValue "EVE_HOOK_MAX_RETRIES" "1"
  $value = 1
  [void][int]::TryParse($raw, [ref]$value)
  return [Math]::Min(3, [Math]::Max(0, $value))
}

# License-derived bearer baked as hook_token. A secret: never written to
# debug output; the guard alone validates its shape.
function Get-HookToken {
  return Get-EnvValue "EVE_HOOK_TOKEN" ""
}

function Get-UserToken {
  $fromEnv = Get-EnvValue "EVE_HOOK_USER_TOKEN" ""
  if ($fromEnv) { return $fromEnv }
  return [string]$script:CursorFederatedToken
}

function Get-FailureMode {
  $mode = Get-EnvValue "EVE_HOOK_FAILURE_MODE" "fail-open"
  if (@("fail-open", "fail-closed", "first-fail-closed") -contains $mode) { return $mode }
  return "fail-open"
}

# Cursor fires "after"/"post" events once the tool already ran; those take a
# response-phase block shape rather than a pre-tool permission verdict.
function Test-CursorPostTool([string]$Event) {
  return @("afterMCPExecution", "postToolUse", "afterShellExecution", "afterFileEdit", "postToolUseFailure") -contains $Event
}

function Test-LifecycleEvent([string]$Event) {
  return $LifecycleEvents -ccontains $Event
}

# Agent-native "no objection" reply for the fail-open path. Cursor pre-tool
# hooks want an explicit allow; everything else treats "{}" as pass-through.
function New-AllowResponse([string]$Event) {
  if (Test-LifecycleEvent $Event) { return "{}" }
  if ($Agent -eq "cursor" -and -not (Test-CursorPostTool $Event)) {
    return @{ permission = "allow"; continue = $true } | ConvertTo-Json -Compress
  }
  return "{}"
}

function New-DenyResponse([string]$Reason, [string]$Event) {
  if ($Agent -eq "cursor") {
    if (Test-CursorPostTool $Event) {
      return @{
        updated_mcp_tool_output = @{
          isError = $true
          content = @(@{ type = "text"; text = $Reason })
          _eve_guard = @{ blocked = $true; phase = "response" }
        }
        additional_context = $Reason
      } | ConvertTo-Json -Compress -Depth 10
    }
    return @{
      permission = "deny"
      continue = $true
      user_message = $Reason
      agent_message = $Reason
    } | ConvertTo-Json -Compress -Depth 10
  }
  if ($Agent -eq "codex") { return New-CodexDenyResponse $Reason $Event }
  if ($Event -eq $PostToolUseEvent) {
    return @{
      decision = "block"
      reason = $Reason
      hookSpecificOutput = @{
        hookEventName = $PostToolUseEvent
        additionalContext = $Reason
        updatedToolOutput = $Reason
      }
    } | ConvertTo-Json -Compress -Depth 10
  }
  return @{
    continue = $false
    stopReason = $Reason
    hookSpecificOutput = @{
      hookEventName = "PreToolUse"
      permissionDecision = "deny"
      permissionDecisionReason = $Reason
    }
  } | ConvertTo-Json -Compress -Depth 10
}

# Codex marks a hook run Failed - and runs the tool anyway - when the deny
# carries continue/stopReason or updatedToolOutput, so it gets the bare shapes.
function New-CodexDenyResponse([string]$Reason, [string]$Event) {
  if ($Event -eq $PostToolUseEvent) {
    return @{
      decision = "block"
      reason = $Reason
      hookSpecificOutput = @{ hookEventName = $PostToolUseEvent; additionalContext = $Reason }
    } | ConvertTo-Json -Compress -Depth 10
  }
  return @{
    hookSpecificOutput = @{
      hookEventName = "PreToolUse"
      permissionDecision = "deny"
      permissionDecisionReason = $Reason
    }
  } | ConvertTo-Json -Compress -Depth 10
}

function Write-FailureLog([string]$Reason, [string]$Event, $Payload = $null) {
  try {
    $transcriptPath = Get-Property $Payload "transcript_path" (Get-Property $Payload "transcriptPath" "")
    $record = @{
      timestamp = [DateTimeOffset]::UtcNow.ToString("o")
      event = $Event
      agent = $Agent
      hook_runtime = "powershell"
      reason = $Reason
      http_status = Extract-HttpStatus $Reason
      response_preview = Extract-ResponsePreview $Reason
      plugin_id = Get-EnvValue "EVE_HOOK_PLUGIN_ID"
      config_hash = Get-EnvValue "EVE_HOOK_CONFIG_HASH"
      eve_guard_url = Get-EnvValue "EVE_ORCHESTRATOR_URL"
      plugin_root = Get-EnvValue "CLAUDE_PLUGIN_ROOT"
      session_id = Get-Property $Payload "session_id" ""
      tool_name = Get-Property $Payload "tool_name" (Get-Property $Payload "toolName" "")
      tool_use_id = Get-Property $Payload "tool_use_id" (Get-Property $Payload "toolUseId" "")
      payload_keys = @(Get-PayloadKeys $Payload)
      has_tool_input = Has-AnyProperty $Payload @("tool_input", "toolInput", "input")
      has_tool_response = Has-AnyProperty $Payload @("tool_response", "toolResponse", "tool_output", "toolOutput")
      transcript_path = $transcriptPath
      transcript_path_exists = ($transcriptPath -and (Test-Path -LiteralPath $transcriptPath))
      failure_mode = Get-FailureMode
      timeout_s = Get-TimeoutSeconds
      max_retries = Get-MaxRetries
      curl_disabled = ((Get-EnvValue "EVE_HOOK_DISABLE_CURL") -eq "1")
      powershell_version = [string]$PSVersionTable.PSVersion
      powershell_edition = [string]$PSVersionTable.PSEdition
      log_file = Get-FailureLogPath
      last_failure_file = Get-LastFailurePath
    }
    $json = $record | ConvertTo-Json -Compress -Depth 12
    [IO.File]::AppendAllText((Get-FailureLogPath), $json + [Environment]::NewLine, [Text.UTF8Encoding]::new($false))
    [IO.File]::WriteAllText((Get-LastFailurePath), $json, [Text.UTF8Encoding]::new($false))
  } catch {}
}

function Format-FailureReason([string]$Reason, [string]$Event) {
  $logPath = Get-LastFailurePath
  return "Eve Guard blocked this $Event hook locally because it could not verify the tool call with Eve Guard. Reason: $(Truncate-Text $Reason). Diagnostics: $logPath"
}

function Get-StateFile([string]$SessionId) {
  $key = if ([string]::IsNullOrWhiteSpace($SessionId)) { "global" } else { $SessionId }
  $sha = [Security.Cryptography.SHA256]::Create()
  $bytes = [Text.Encoding]::UTF8.GetBytes($key)
  $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace("-", "").ToLowerInvariant().Substring(0, 16)
  return Join-Path (Get-EnvValue "EVE_HOOK_STATE_DIR" ([IO.Path]::GetTempPath())) "eve-hook-degraded-$hash.flag"
}

function Test-Degraded([string]$SessionId) {
  $file = Get-StateFile $SessionId
  if (-not (Test-Path -LiteralPath $file)) { return $false }
  if (((Get-Date) - (Get-Item -LiteralPath $file).LastWriteTime).TotalSeconds -gt $StateFileTtlSeconds) {
    Remove-Item -LiteralPath $file -Force
    return $false
  }
  return $true
}

function Set-Degraded([string]$SessionId) {
  $file = Get-StateFile $SessionId
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $file) | Out-Null
  [IO.File]::WriteAllText($file, [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds().ToString())
}

function Resolve-FailureResponse([string]$Mode, [string]$SessionId, [string]$Reason, [string]$Event, $Payload = $null) {
  Write-FailureLog $Reason $Event $Payload
  $visibleReason = Format-FailureReason $Reason $Event
  if ($Mode -eq "fail-open" -or (Test-LifecycleEvent $Event)) { return (New-AllowResponse $Event) }
  if ($Mode -eq "fail-closed") { return New-DenyResponse $visibleReason $Event }
  if (Test-Degraded $SessionId) { return (New-AllowResponse $Event) }
  Set-Degraded $SessionId
  return New-DenyResponse "$visibleReason Following requests in this session will be fail-open." $Event
}

# Placeholder accounts are not a person: Claude Desktop in 3P mode hands out
# ``cowork-3p@localhost`` and sandbox users look like ``root@vm``. Same rule
# as hook.cjs; an unusable value returns "" so the next source is tried.
function Get-UsableEmail($Value) {
  if ($Value -isnot [string]) { return "" }
  $email = $Value.Trim()
  if ($email.Length -gt 320 -or $email -notmatch '^[^\s@]+@[^\s@]+$') { return "" }
  $domain = $email.Substring($email.LastIndexOf("@") + 1)
  if ($domain -match '\.' -and $domain -notmatch '(^|\.)(localhost|local|localdomain)$') { return $email }
  Write-DebugLog "skipping placeholder user_email"
  return ""
}

# Sources that need no network: the payload, env vars, the Cowork envelope.
function Get-EarlyUserEmail($Payload) {
  $explicit = Get-UsableEmail (Get-Property $Payload "user_email" "")
  if ($explicit) {
    Set-AuditWinner "payload_user_email" "payload user_email"
    Add-AuditStep "payload_user_email" "ok"
    Write-DebugLog "user_email resolved from payload user_email"
    return $explicit
  }
  Add-AuditStep "payload_user_email" "skipped" "not_usable"
  foreach ($name in @("CURSOR_USER_EMAIL", "CLAUDE_CODE_USER_EMAIL", "CLAUDE_USER_EMAIL", "USER_EMAIL")) {
    $value = Get-UsableEmail (Get-EnvValue $name)
    if ($value) {
      Set-AuditWinner "env_user_email" "env $name"
      Add-AuditStep "env_user_email" "ok"
      Write-DebugLog "user_email resolved from env $name"
      return $value
    }
  }
  Add-AuditStep "env_user_email" "skipped" "not_usable"
  $envelope = Get-EnvelopeEmail (Get-Property $Payload "transcript_path" "")
  if ($envelope) {
    Set-AuditWinner "session_envelope" "session envelope"
    Add-AuditStep "session_envelope" "ok"
    Write-DebugLog "user_email resolved from session envelope"
  } else { Add-AuditStep "session_envelope" "skipped" "not_usable" }
  return $envelope
}

function Get-CodexAuthPath {
  $codexHome = Get-EnvValue "CODEX_HOME"
  if ($codexHome) { return (Join-Path $codexHome "auth.json") }
  # Not $home: PowerShell's automatic $HOME is read-only and names are case-insensitive.
  $userHome = Get-EnvValue "USERPROFILE"
  if (-not $userHome) { $userHome = Get-EnvValue "HOME" }
  if ($userHome) { return (Join-Path (Join-Path $userHome ".codex") "auth.json") }
  return ""
}

# Email claim inside Codex's tokens.id_token. A missing claim stays
# anonymous: .claude.json on this machine is a different account.
function Get-CodexAuthEmail {
  $path = Get-CodexAuthPath
  if (-not $path -or -not (Test-Path -LiteralPath $path -PathType Leaf)) { return "" }
  try {
    if ((Get-Item -LiteralPath $path).Length -gt 16MB) { return "" }
    $obj = Read-JsonObject ([IO.File]::ReadAllText($path))
    $token = [string](Get-Property (Get-Property $obj "tokens") "id_token" "")
    if ($token) { return (Get-IdTokenEmail $token) }
  } catch { return "" }
  return ""
}

function Get-UserEmail($Payload) {
  $early = Get-EarlyUserEmail $Payload
  if ($early) { return $early }
  if ($Agent -eq "codex") {
    $email = Get-CodexAuthEmail
    if ($email) {
      Set-AuditWinner "codex_auth" "Codex auth.json"
      Add-AuditStep "codex_auth" "ok"
      Write-DebugLog "user_email resolved from Codex auth.json"
    } else { Add-AuditStep "codex_auth" "miss" }
    return $email
  }
  # .claude.json may be another account's claude.ai login on this machine,
  # so it never stands in for a Databricks workspace's own answer.
  if (Test-DatabricksWorkspaceDetected) {
    $databricks = Get-DatabricksEmail
    if (-not $databricks) { Write-DebugLog "no Databricks identity yet; not using .claude.json, sending no user_email" }
    return $databricks
  }
  $config = Get-ClaudeConfigEmail
  if ($config) {
    Set-AuditWinner "claude_json" ".claude.json oauthAccount"
    Add-AuditStep "claude_json" "ok"
    Write-DebugLog "user_email resolved from .claude.json oauthAccount"
  } else { Add-AuditStep "claude_json" "miss" }
  return $config
}

# Claude Code on Databricks inference (``ANTHROPIC_BASE_URL`` =
# ``https://<workspace>/ai-gateway/anthropic``) has no claude.ai login. The
# Databricks token it already sends to the workspace names its owner: SCIM
# ``/Me`` returns ``userName`` (the email). Same rules as hook.cjs: the
# token only goes to a Databricks workspace host it is configured for, and
# the answer is cached 1 h (a miss 5 min) in a per-user directory.
# ``EVE_HOOK_DATABRICKS_IDENTITY=0`` turns the lookup off.
$DatabricksMePath = "/api/2.0/preview/scim/v2/Me?attributes=userName,emails"
$DatabricksHostPattern = '(\.databricks\.com|\.azuredatabricks\.net|\.databricks\.us|\.databricks\.azure\.cn)$'
$DatabricksMeTimeoutSeconds = 2
$DatabricksCliTimeoutMs = 3000
$DatabricksHitTtlSeconds = 3600
$DatabricksMissTtlSeconds = 300

function Get-UrlOrigin([string]$Value) {
  if ([string]::IsNullOrWhiteSpace($Value)) { return "" }
  $text = $Value.Trim()
  if ($text -notmatch '^[a-z]+://') { $text = "https://$text" }
  $uri = $null
  if (-not [Uri]::TryCreate($text, [UriKind]::Absolute, [ref]$uri)) { return "" }
  if ($uri.Scheme -ne "https" -and $uri.Scheme -ne "http") { return "" }
  return $uri.GetLeftPart([UriPartial]::Authority)
}

function Test-DatabricksOrigin([string]$Origin) {
  if (-not $Origin.StartsWith("https://")) { return $false }
  return ([Uri]$Origin).Host.ToLowerInvariant() -match $DatabricksHostPattern
}

function Get-GatewayOrigin {
  $origin = Get-UrlOrigin (Get-EnvValue "ANTHROPIC_BASE_URL")
  if ($origin -and (Test-DatabricksOrigin $origin)) { return $origin }
  return ""
}

function Get-GatewayHeaderToken {
  foreach ($line in ((Get-EnvValue "ANTHROPIC_CUSTOM_HEADERS") -split "\r?\n")) {
    $colon = $line.IndexOf(":")
    if ($colon -lt 0) { continue }
    if ($line.Substring(0, $colon).Trim().ToLowerInvariant() -ne "x-databricks-ai-gateway-token") { continue }
    return $line.Substring($colon + 1).Trim()
  }
  return ""
}

function Get-GatewayEnvToken {
  $token = Get-GatewayHeaderToken
  if (-not $token) { $token = Get-EnvValue "ANTHROPIC_AUTH_TOKEN" }
  if (-not $token) { $token = Get-EnvValue "ANTHROPIC_API_KEY" }
  return $token
}

# Only a Databricks ANTHROPIC_BASE_URL turns Databricks mode on; a
# DATABRICKS_HOST left over from CLI/SDK work must not. Once on,
# DATABRICKS_HOST may name the workspace the CLI and the sign-in talk to.
function Get-WorkspaceOrigin {
  $gateway = Get-GatewayOrigin
  if (-not $gateway) { return "" }
  $sdkOrigin = Get-UrlOrigin (Get-EnvValue "DATABRICKS_HOST")
  if ($sdkOrigin) { return $sdkOrigin }
  return $gateway
}

function Get-DatabricksTokenTargets {
  $targets = @()
  if (-not (Get-GatewayOrigin)) { return ,$targets }
  $sdkOrigin = Get-UrlOrigin (Get-EnvValue "DATABRICKS_HOST")
  $sdkToken = Get-EnvValue "DATABRICKS_TOKEN"
  if ($sdkOrigin -and $sdkToken) { $targets += ,@($sdkOrigin, $sdkToken) }
  $gateway = Get-GatewayOrigin
  $gatewayToken = Get-GatewayEnvToken
  if ($gateway -and $gatewayToken) { $targets += ,@($gateway, $gatewayToken) }
  # Claude Desktop keeps an interactive gateway sign-in's token in memory.
  if ($gateway -and -not $gatewayToken) { Write-DebugLog "databricks gateway has no token in the hook env; trying Claude Desktop's sign-in, the Eve Databricks sign-in, then the Databricks CLI" }
  return ,$targets
}

# The directory name hook.cjs and hook.sh use (uid off Windows, "user" on
# it), so every runtime shares one cache.
$script:IdentityOwner = $null
function Get-IdentityOwner {
  if ($null -ne $script:IdentityOwner) { return $script:IdentityOwner }
  $uid = ""
  if ([IO.Path]::DirectorySeparatorChar -ne '\') { try { $uid = (& id -u 2>$null | Out-String).Trim() } catch { $uid = "" } }
  $script:IdentityOwner = if ($uid) { $uid } else { "user" }
  return $script:IdentityOwner
}

function Get-DatabricksCacheFile([string]$Origin, [string]$Token) {
  $user = Get-IdentityOwner
  # Fixed /tmp off Windows, not TMPDIR: Claude Desktop starts hooks without
  # TMPDIR while a macOS Terminal sets a per-user one; both share one sign-in.
  $base = if ([IO.Path]::DirectorySeparatorChar -eq '\') { [IO.Path]::GetTempPath() } else { "/tmp" }
  $dir = Join-Path (Get-EnvValue "EVE_HOOK_STATE_DIR" $base) "eve-hook-identity-$user"
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $keySource = if ($Token) { $Token } else { "cli" }
  $sha = [Security.Cryptography.SHA256]::Create()
  $bytes = [Text.Encoding]::UTF8.GetBytes("$Origin`n$keySource")
  $hash = [BitConverter]::ToString($sha.ComputeHash($bytes)).Replace("-", "").ToLowerInvariant().Substring(0, 32)
  return Join-Path $dir "databricks-$hash.json"
}

# The cached email ("" for a cached miss) when fresh, else $null.
function Read-DatabricksCache([string]$File) {
  if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { return $null }
  $entry = Read-JsonObject ([IO.File]::ReadAllText($File))
  $email = Get-Property $entry "email" $null
  if ($email -isnot [string]) { return $null }
  $ttl = if ($email) { $DatabricksHitTtlSeconds } else { $DatabricksMissTtlSeconds }
  if (((Get-Date) - (Get-Item -LiteralPath $File).LastWriteTime).TotalSeconds -gt $ttl) { return $null }
  return $email
}

function Test-DatabricksWorkspaceDetected {
  if ((Get-EnvValue "EVE_HOOK_DATABRICKS_IDENTITY") -eq "0") { return $false }
  return [bool](Get-GatewayOrigin)
}

function Get-DatabricksCliToken([string]$Origin) {
  $cli = Get-Command "databricks" -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $cli) { Write-DebugLog "databricks auth token unavailable: databricks CLI not on PATH"; return "" }
  $info = New-Object System.Diagnostics.ProcessStartInfo
  $info.FileName = $cli.Source
  $info.Arguments = "auth token --host `"$Origin`""
  $info.UseShellExecute = $false
  $info.RedirectStandardOutput = $true
  $info.RedirectStandardInput = $true
  $info.CreateNoWindow = $true
  $process = [Diagnostics.Process]::Start($info)
  $process.StandardInput.Close()
  $read = $process.StandardOutput.ReadToEndAsync()
  if (-not $process.WaitForExit($DatabricksCliTimeoutMs)) {
    $process.Kill()
    return ""
  }
  if ($process.ExitCode -ne 0) { return "" }
  $token = Get-Property (Read-JsonObject $read.Result) "access_token" ""
  if ($token -is [string]) { return $token.Trim() }
  return ""
}

function Get-DatabricksMeEmail([string]$Origin, [string]$Token) {
  try {
    $user = Invoke-RestMethod -Method Get -Uri "$Origin$DatabricksMePath" -TimeoutSec $DatabricksMeTimeoutSeconds -UseBasicParsing `
      -Headers @{ Authorization = "Bearer $Token"; Accept = "application/json" }
  } catch {
    Write-DebugLog "databricks /Me lookup failed: $($_.Exception.Message)"
    return ""
  }
  $email = Get-UsableEmail (Get-Property $user "userName" "")
  if ($email) { return $email }
  $emails = @(Get-Property $user "emails" @())
  $primary = $emails | Where-Object { (Get-Property $_ "primary" $false) -eq $true } | Select-Object -First 1
  if (-not $primary) { $primary = $emails | Select-Object -First 1 }
  return Get-UsableEmail (Get-Property $primary "value" "")
}

function Get-DatabricksTargetEmail([string]$Origin, [string]$Token) {
  $file = Get-DatabricksCacheFile $Origin $Token
  $cached = Read-DatabricksCache $file
  if ($null -ne $cached) { return $cached }
  if (-not $Token) { $Token = Get-DatabricksCliToken $Origin }
  $email = if ($Token) { Get-DatabricksMeEmail $Origin $Token } else { "" }
  [IO.File]::WriteAllText($file, (@{ email = $email } | ConvertTo-Json -Compress))
  return $email
}

function Get-SafeTargetEmail([string]$Origin, [string]$Token) {
  try { return Get-DatabricksTargetEmail $Origin $Token } catch {
    Write-DebugLog "databricks identity lookup failed: $($_.Exception.Message)"
    return ""
  }
}

$script:AuditWinner = "none"
$script:AuditWinnerLabel = ""
$script:AuditSignAction = "none"
$script:AuditSignReason = ""
$script:AuditSteps = @()
$script:AuditDatabricksMode = $false
$script:AuditDatabricksReason = ""
$script:AuditWorkspaceFp = ""

function Add-AuditStep([string]$Step, [string]$Outcome, [string]$Detail = "", [string]$Cache = "") {
  $row = @{ step = $Step; outcome = $Outcome }
  if ($Detail) { $row.detail = $Detail }
  if ($Cache) { $row.cache = $Cache }
  $script:AuditSteps += ,$row
}

function Set-AuditWinner([string]$Code, [string]$Label) {
  $script:AuditWinner = $Code
  $script:AuditWinnerLabel = $Label
}

function Record-IdentityAuditMode {
  if ((Get-EnvValue "EVE_HOOK_DATABRICKS_IDENTITY") -eq "0") {
    $script:AuditDatabricksMode = $false
    $script:AuditDatabricksReason = "identity_disabled"
    Add-AuditStep "databricks_mode" "off" "identity_disabled"
    return
  }
  $gateway = Get-GatewayOrigin
  if ($gateway) {
    $script:AuditDatabricksMode = $true
    $script:AuditDatabricksReason = "anthropic_base_url"
    $origin = Get-WorkspaceOrigin
    if ($origin) {
      $sha = [Security.Cryptography.SHA256]::Create()
      $bytes = [Text.Encoding]::UTF8.GetBytes($origin)
      $script:AuditWorkspaceFp = ([BitConverter]::ToString($sha.ComputeHash($bytes)).Replace("-", "").ToLowerInvariant()).Substring(0, 12)
    }
    Add-AuditStep "databricks_mode" "on" "anthropic_base_url"
    return
  }
  $script:AuditDatabricksMode = $false
  $script:AuditDatabricksReason = "off_no_gateway"
  Add-AuditStep "databricks_mode" "off" "no_databricks_base_url"
}

function Attach-IdentityAudit($Payload) {
  $config = Read-BakedConfig
  $version = [string](Get-Property $config "hook_code_version" "")
  Set-Property $Payload "eve_identity_resolution" @{
    v = 1
    runtime = "hook.ps1"
    hook_code_version = $version
    databricks_mode = $script:AuditDatabricksMode
    databricks_mode_reason = $script:AuditDatabricksReason
    workspace_fp = $script:AuditWorkspaceFp
    winner = $script:AuditWinner
    winner_label = $script:AuditWinnerLabel
    steps = @($script:AuditSteps)
    sign_in = @{ action = $script:AuditSignAction; reason = $script:AuditSignReason }
  }
}

function Get-FoundEmail([string]$Label, [string]$Email) {
  Write-DebugLog "user_email resolved from $Label"
  switch ($Label) {
    "Databricks /Me" { Set-AuditWinner "databricks_me" $Label }
    "Claude Desktop sign-in (OTEL enduser.id)" { Set-AuditWinner "otel_enduser" $Label }
    "Eve Databricks sign-in" { Set-AuditWinner "eve_databricks_sign_in" $Label }
    "Databricks /Me (CLI login)" { Set-AuditWinner "databricks_cli_me" $Label }
  }
  return $Email
}

function Get-DatabricksEmail {
  if ((Get-EnvValue "EVE_HOOK_DATABRICKS_IDENTITY") -eq "0") { return "" }
  foreach ($target in (Get-DatabricksTokenTargets)) {
    $email = Get-SafeTargetEmail $target[0] $target[1]
    if ($email) { return (Get-FoundEmail "Databricks /Me" $email) }
  }
  $origin = Get-WorkspaceOrigin
  if (-not $origin) { return "" }
  return Get-DatabricksTokenlessEmail $origin
}

function Get-DatabricksTokenlessEmail([string]$Origin) {
  $email = Get-OtelEnduserEmail
  if ($email) { return (Get-FoundEmail "Claude Desktop sign-in (OTEL enduser.id)" $email) }
  $email = Read-DatabricksLoginEmail $Origin
  if ($email) { return (Get-FoundEmail "Eve Databricks sign-in" $email) }
  $email = Get-SafeTargetEmail $Origin ""
  if ($email) { return (Get-FoundEmail "Databricks /Me (CLI login)" $email) }
  Start-DatabricksLoginMaybe $Origin
  return ""
}

# Claude Desktop appends ``enduser.id=<signed-in email>`` to the engine's
# ``OTEL_RESOURCE_ATTRIBUTES`` when an OTLP endpoint is configured. It is the
# identity of Desktop's own gateway sign-in.
function Get-OtelEnduserEmail {
  foreach ($pair in ((Get-EnvValue "OTEL_RESOURCE_ATTRIBUTES") -split ",")) {
    $eq = $pair.IndexOf("=")
    if ($eq -lt 0 -or $pair.Substring(0, $eq).Trim() -ne "enduser.id") { continue }
    try { return Get-UsableEmail ([Uri]::UnescapeDataString($pair.Substring($eq + 1))) } catch { return "" }
  }
  return ""
}

# Eve Databricks sign-in: a one-time browser OAuth (PKCE) login that needs no
# Databricks CLI. It reuses Claude Desktop's own OAuth app (client id and
# loopback redirect from Desktop's applied config) when its issuer is this
# workspace, else Databricks' built-in ``databricks-cli`` public client.
# Only the email is kept (30 days); the tokens are dropped after the exchange.
$DatabricksLoginTtlSeconds = 30 * 24 * 3600
$DatabricksLoginRetrySeconds = 12 * 3600
$DatabricksLoginWaitSeconds = 300
$DatabricksLoginTokenTimeoutSeconds = 10
$DatabricksCliClientId = "databricks-cli"
$DatabricksCliRedirectUri = "http://localhost:8020"
$DatabricksCliScopes = "all-apis openid"
$IdTokenEmailClaims = @("email", "preferred_username", "upn", "sub")
$LoginDonePage = "<html><body><h3>Eve Guard is now signed in to Databricks.</h3><p>You can close this tab.</p></body></html>"

function Test-DatabricksLoginEnabled {
  return (Get-EnvValue "EVE_HOOK_DATABRICKS_LOGIN") -ne "0"
}

function Test-FreshFile([string]$File, [int]$TtlSeconds) {
  if (-not (Test-Path -LiteralPath $File -PathType Leaf)) { return $false }
  return ((Get-Date) - (Get-Item -LiteralPath $File).LastWriteTime).TotalSeconds -le $TtlSeconds
}

function Read-DatabricksLoginEmail([string]$Origin) {
  try {
    $file = Get-DatabricksCacheFile $Origin "login"
    if (-not (Test-FreshFile $file $DatabricksLoginTtlSeconds)) { return "" }
    return Get-UsableEmail (Get-Property (Read-JsonObject ([IO.File]::ReadAllText($file))) "email" "")
  } catch { return "" }
}

function Get-DesktopConfigRoots {
  $roots = @((Get-EnvValue "EVE_HOOK_CLAUDE_DESKTOP_DIR"))
  if ($env:HOME) { $roots += (Join-Path $env:HOME "Library/Application Support/Claude-3p") }
  foreach ($name in @("APPDATA", "LOCALAPPDATA")) {
    $base = Get-EnvValue $name
    if ($base) { $roots += (Join-Path $base "Claude-3p") }
  }
  return @($roots | Where-Object { $_ })
}

# The config Desktop applies: ``configLibrary/_meta.json`` -> ``appliedId`` ->
# ``configLibrary/<appliedId>.json``.
function Read-DesktopAppliedConfig {
  foreach ($root in (Get-DesktopConfigRoots)) {
    $library = Join-Path $root "configLibrary"
    $metaFile = Join-Path $library "_meta.json"
    if (-not (Test-Path -LiteralPath $metaFile -PathType Leaf)) { continue }
    $applied = [string](Get-Property (Read-JsonObject ([IO.File]::ReadAllText($metaFile))) "appliedId" "")
    if ($applied -cnotmatch '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$') { continue }
    $configFile = Join-Path $library "$applied.json"
    if (Test-Path -LiteralPath $configFile -PathType Leaf) { return Read-JsonObject ([IO.File]::ReadAllText($configFile)) }
  }
  return $null
}

function Get-DesktopOidcBlock($Config) {
  foreach ($key in @("inferenceIdpOidc", "inferenceGatewayOidc")) {
    $block = Get-Property $Config $key $null
    if ($null -ne $block -and (Get-Property $block "clientId" "")) { return $block }
  }
  return $null
}

function Get-OidcScopes($Block) {
  $raw = Get-Property $Block "scopes" ""
  $scopes = @((@($raw) -join " ") -split '\s+' | Where-Object { $_ -and $_ -ne "openid" -and $_ -ne "offline_access" })
  return (@($scopes) + "openid") -join " "
}

# @{ clientId; redirectUri; scopes } for the sign-in to $Origin.
function Get-DatabricksLoginClient([string]$Origin) {
  $block = Get-DesktopOidcBlock (Read-DesktopAppliedConfig)
  if ($null -ne $block -and (Get-UrlOrigin (Get-Property $block "issuer" "")) -eq $Origin) {
    $port = 0
    if (-not [int]::TryParse([string](Get-Property $block "redirectPort" ""), [ref]$port) -or $port -le 0) { throw "Claude Desktop's OAuth app has no redirect port" }
    $hostName = [string](Get-Property $block "redirectHost" "")
    if (-not $hostName) { $hostName = "127.0.0.1" }
    return @{ clientId = [string]$block.clientId; redirectUri = "http://${hostName}:$port/callback"; scopes = (Get-OidcScopes $block) }
  }
  return @{
    clientId = (Get-EnvValue "EVE_HOOK_DATABRICKS_CLIENT_ID" $DatabricksCliClientId)
    redirectUri = (Get-EnvValue "EVE_HOOK_DATABRICKS_REDIRECT_URI" $DatabricksCliRedirectUri)
    scopes = (Get-EnvValue "EVE_HOOK_DATABRICKS_SCOPES" $DatabricksCliScopes)
  }
}

# Desktop's applied config names the gateway even when the hook env does not
# (a terminal running ``hook.ps1 databricks-login``).
function Get-DesktopGatewayOrigin {
  $origin = Get-UrlOrigin ([string](Get-Property (Read-DesktopAppliedConfig) "inferenceGatewayBaseUrl" ""))
  if ($origin -and (Test-DatabricksOrigin $origin)) { return $origin }
  return ""
}

function ConvertTo-Base64Url([byte[]]$Bytes) {
  return [Convert]::ToBase64String($Bytes).TrimEnd("=").Replace("+", "-").Replace("/", "_")
}

function New-RandomUrlSafe([int]$Count) {
  $bytes = New-Object byte[] $Count
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  return ConvertTo-Base64Url $bytes
}

function Get-PkceChallenge([string]$Verifier) {
  $sha = [Security.Cryptography.SHA256]::Create()
  return ConvertTo-Base64Url ($sha.ComputeHash([Text.Encoding]::ASCII.GetBytes($Verifier)))
}

function Get-AuthorizeUrl([string]$Origin, $Client, [string]$State, [string]$Challenge) {
  $query = @(
    "client_id=$([Uri]::EscapeDataString($Client.clientId))",
    "redirect_uri=$([Uri]::EscapeDataString($Client.redirectUri))",
    "response_type=code", "state=$State", "code_challenge=$Challenge", "code_challenge_method=S256",
    "scope=$([Uri]::EscapeDataString($Client.scopes))"
  ) -join "&"
  return "$Origin/oidc/v1/authorize?$query"
}

function Open-Browser([string]$Url) {
  $opener = Get-EnvValue "EVE_HOOK_DATABRICKS_LOGIN_OPENER"
  if ($opener) { Start-Process -FilePath $opener -ArgumentList $Url | Out-Null; return $true }
  if ($IsMacOS) { Start-Process -FilePath "open" -ArgumentList $Url | Out-Null; return $true }
  if ($IsLinux) {
    if (-not ($env:DISPLAY -or $env:WAYLAND_DISPLAY)) { return $false }
    Start-Process -FilePath "xdg-open" -ArgumentList $Url | Out-Null
    return $true
  }
  Start-Process $Url | Out-Null
  return $true
}

function Get-QueryParam([string]$RequestLine, [string]$Name) {
  $match = [regex]::Match($RequestLine, "[?&]$([regex]::Escape($Name))=([^& ]*)")
  if (-not $match.Success) { return "" }
  return [Uri]::UnescapeDataString($match.Groups[1].Value)
}

# One callback on the loopback redirect: answer the browser, return the
# request line ("" on timeout). A TcpListener needs no HTTP URL ACL.
function Wait-LoginCallback([string]$RedirectUri, [string]$Url) {
  $redirect = [Uri]$RedirectUri
  $listeners = @(Start-LoopbackListeners $redirect)
  if ($listeners.Count -eq 0) { throw "cannot listen on $($redirect.Authority)" }
  try {
    if (-not (Open-Browser $Url)) { Write-DebugLog "databricks sign-in: no browser to open" }
    $deadline = (Get-Date).AddSeconds($DatabricksLoginWaitSeconds)
    while ((Get-Date) -lt $deadline) {
      $ready = $listeners | Where-Object { $_.Pending() } | Select-Object -First 1
      if (-not $ready) { Start-Sleep -Milliseconds 200; continue }
      $line = Read-CallbackRequest $ready.AcceptTcpClient()
      if ($line -match '^GET ') { return $line }
    }
    return ""
  } finally { $listeners | ForEach-Object { $_.Stop() } }
}

# ``localhost`` (the databricks-cli redirect) may resolve to ::1 first, as it
# does on Windows, so listen on both loopbacks; hook.cjs does the same.
function Start-LoopbackListeners([Uri]$Redirect) {
  $addresses = if ($Redirect.Host -eq "localhost") { @([Net.IPAddress]::Loopback, [Net.IPAddress]::IPv6Loopback) } else { @([Net.IPAddress]::Parse($Redirect.Host.Trim('[', ']'))) }
  foreach ($address in $addresses) {
    $listener = [Net.Sockets.TcpListener]::new($address, $Redirect.Port)
    try { $listener.Start(); $listener } catch { Write-DebugLog "databricks sign-in: cannot listen on ${address}: $($_.Exception.Message)" }
  }
}

function Read-CallbackRequest($Client) {
  try {
    $stream = $Client.GetStream()
    $line = [IO.StreamReader]::new($stream).ReadLine()
    $body = [Text.Encoding]::UTF8.GetBytes($LoginDonePage)
    $head = [Text.Encoding]::ASCII.GetBytes("HTTP/1.1 200 OK`r`nContent-Type: text/html; charset=utf-8`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n")
    $stream.Write($head, 0, $head.Length)
    $stream.Write($body, 0, $body.Length)
    return [string]$line
  } finally { $Client.Close() }
}

function Get-IdTokenEmail([string]$IdToken) {
  $parts = $IdToken -split "\."
  if ($parts.Count -lt 2) { return "" }
  $value = $parts[1].Replace("-", "+").Replace("_", "/")
  $value += "=" * ((4 - $value.Length % 4) % 4)
  $claims = Read-JsonObject ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($value)))
  foreach ($claim in $IdTokenEmailClaims) {
    $email = Get-UsableEmail (Get-Property $claims $claim "")
    if ($email) { return $email }
  }
  return ""
}

function Get-TokenResponseEmail([string]$Origin, $Response) {
  $idToken = [string](Get-Property $Response "id_token" "")
  $email = if ($idToken) { Get-IdTokenEmail $idToken } else { "" }
  if ($email) { return $email }
  $accessToken = [string](Get-Property $Response "access_token" "")
  if ($accessToken) { return Get-DatabricksMeEmail $Origin $accessToken }
  return ""
}

# Foreground sign-in for $Origin: browser -> callback -> token -> email.
function Invoke-DatabricksLogin([string]$Origin) {
  $client = Get-DatabricksLoginClient $Origin
  $verifier = New-RandomUrlSafe 48
  $state = New-RandomUrlSafe 18
  $url = Get-AuthorizeUrl $Origin $client $state (Get-PkceChallenge $verifier)
  Write-DebugLog "databricks sign-in: opening $Origin for client $($client.clientId)"
  [Console]::Error.WriteLine("Eve Guard: sign in to Databricks in your browser. If no browser opened, visit:`n$url")
  $callback = Wait-LoginCallback $client.redirectUri $url
  $code = Get-QueryParam $callback "code"
  if ((Get-QueryParam $callback "state") -ne $state -or -not $code) {
    Write-DebugLog "databricks sign-in: no code ($(Get-QueryParam $callback 'error'))"
    return ""
  }
  $form = @{ grant_type = "authorization_code"; client_id = $client.clientId; code = $code; redirect_uri = $client.redirectUri; code_verifier = $verifier }
  $response = Invoke-RestMethod -Method Post -Uri "$Origin/oidc/v1/token" -Body $form -ContentType "application/x-www-form-urlencoded" -TimeoutSec $DatabricksLoginTokenTimeoutSeconds -UseBasicParsing
  return Save-DatabricksLoginEmail $Origin (Get-TokenResponseEmail $Origin $response)
}

function Save-DatabricksLoginEmail([string]$Origin, [string]$Email) {
  if (-not $Email) { Write-DebugLog "databricks sign-in: the token response named no user"; return "" }
  [IO.File]::WriteAllText((Get-DatabricksCacheFile $Origin "login"), (@{ email = $Email } | ConvertTo-Json -Compress))
  Write-DebugLog "databricks sign-in complete"
  [Console]::Error.WriteLine("Eve Guard: signed in to Databricks as $Email")
  return $Email
}

# Hooks never wait on a browser: the sign-in runs detached, at most once per
# $DatabricksLoginRetrySeconds, and only for Claude Code (incl. Desktop). Its
# stdio goes to files so it never holds the hook's stdout open.
function Start-DatabricksLoginMaybe([string]$Origin) {
  if ($Agent -ne "claude-code" -or -not (Test-DatabricksLoginEnabled)) {
    $script:AuditSignAction = "skipped"
    $script:AuditSignReason = "login_disabled"
    return
  }
  try {
    $marker = Get-DatabricksCacheFile $Origin "login-attempt"
    if (Test-FreshFile $marker $DatabricksLoginRetrySeconds) {
      $script:AuditSignAction = "skipped"
      $script:AuditSignReason = "backoff"
      return
    }
    [IO.File]::WriteAllText($marker, "{}")
    $script:AuditSignAction = "started_background"
    $script:AuditSignReason = "no_identity"
    Write-DebugLog "databricks: no identity yet; starting the Eve Databricks sign-in in the background"
    $dir = Split-Path -Parent $marker
    $stdin = Join-Path $dir "login.in"
    [IO.File]::WriteAllText($stdin, "")
    $options = @{
      FilePath = (Get-Process -Id $PID).Path
      ArgumentList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "`"$PSCommandPath`"", "databricks-login", $Origin)
      RedirectStandardInput = $stdin
      RedirectStandardOutput = (Join-Path $dir "login.out")
      RedirectStandardError = (Join-Path $dir "login.err")
    }
    if ($IsWindows -or $env:OS -eq "Windows_NT") { $options.WindowStyle = "Hidden" }
    Start-Process @options | Out-Null
  } catch { Write-DebugLog "databricks sign-in start failed: $($_.Exception.Message)" }
}

# SessionStart: start the sign-in before the first tool call when nothing
# else can name the user.
function Invoke-DatabricksLoginPrime {
  if ($EventName -ne "SessionStart" -or -not (Test-DatabricksWorkspaceDetected)) { return }
  if ((Get-GatewayEnvToken) -or (Get-EnvValue "DATABRICKS_TOKEN") -or (Get-OtelEnduserEmail)) { return }
  $origin = Get-WorkspaceOrigin
  if (Read-DatabricksLoginEmail $origin) { return }
  # A CLI on PATH is not a CLI login: ask it, and sign in only if it has none.
  if (Get-SafeTargetEmail $origin "") { return }
  Start-DatabricksLoginMaybe $origin
}

function Invoke-DatabricksLoginCommand([string]$OriginArg) {
  Apply-BakedConfig (Read-BakedConfig)
  $origin = Get-UrlOrigin $OriginArg
  if (-not $origin) { $origin = Get-WorkspaceOrigin }
  if (-not $origin) { $origin = Get-DesktopGatewayOrigin }
  if (-not $origin) { $origin = Get-UrlOrigin (Get-EnvValue "DATABRICKS_HOST") }
  if (-not $origin) { [Console]::Error.WriteLine("Eve Guard: no Databricks workspace found. Pass it: databricks-login https://<workspace>"); return 2 }
  try {
    if (Invoke-DatabricksLogin $origin) { return 0 }
  } catch { Write-DebugLog "databricks sign-in failed: $($_.Exception.Message)" }
  return 1
}

# Host-mode Claude Code fallback: the signed-in claude.ai account lives in
# Claude Code's own config file as ``oauthAccount.emailAddress`` --
# ``$env:CLAUDE_CONFIG_DIR\.claude.json`` when the config dir is relocated,
# else ``%USERPROFILE%\.claude.json`` (``$HOME`` on pwsh/Unix). The file
# also carries project history and feature flags (never OAuth tokens), so
# we read the single property we need and never log the contents.
# API-key-only installs have no ``oauthAccount`` and resolve to "".
function Get-ClaudeConfigEmail {
  $candidates = @()
  $configDir = Get-EnvValue "CLAUDE_CONFIG_DIR"
  if ($configDir) { $candidates += (Join-Path $configDir ".claude.json") }
  if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) { $candidates += (Join-Path $env:USERPROFILE ".claude.json") }
  if (-not [string]::IsNullOrWhiteSpace($env:HOME)) { $candidates += (Join-Path $env:HOME ".claude.json") }
  foreach ($candidate in $candidates) {
    if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) { continue }
    try {
      if ((Get-Item -LiteralPath $candidate).Length -gt 16MB) { continue }
      $obj = Read-JsonObject ([IO.File]::ReadAllText($candidate))
      $email = Get-UsableEmail (Get-Property (Get-Property $obj "oauthAccount") "emailAddress" "")
      if ($email) { return $email }
    } catch {
      Write-DebugLog "claude config email lookup failed: $($_.Exception.Message)"
    }
  }
  return ""
}

function Get-EnvelopeEmail([string]$TranscriptPath) {
  if (-not $TranscriptPath) { return "" }
  $dir = Split-Path -Parent $TranscriptPath
  for ($i = 0; $i -lt 8 -and $dir; $i++) {
    $candidate = "$dir.json"
    if ((Split-Path -Leaf $dir).StartsWith("local_") -and (Test-Path -LiteralPath $candidate)) {
      $obj = Read-JsonObject ([IO.File]::ReadAllText($candidate))
      $email = Get-UsableEmail (Get-Property $obj "emailAddress" "")
      if ($email) { return $email }
      $accountEmail = Get-UsableEmail (Get-Property (Get-Property $obj "account") "email" "")
      if ($accountEmail) { return $accountEmail }
    }
    $parent = Split-Path -Parent $dir
    if ($parent -eq $dir) { break }
    $dir = $parent
  }
  return ""
}

function Get-CallingGuid($Payload) {
  $toolName = Get-Property $Payload "tool_name" (Get-Property $Payload "toolName" "")
  $match = [regex]::Match([string]$toolName, "^mcp__([0-9a-fA-F-]{36})__")
  if ($match.Success) { return $match.Groups[1].Value.ToLowerInvariant() }
  return ""
}

function Get-DeltaNames($EventObject) {
  $candidates = @()
  $attachment = Get-Property $EventObject "attachment"
  if ((Get-Property $attachment "type") -eq "deferred_tools_delta") { $candidates += $attachment }
  $nested = Get-Property (Get-Property $EventObject "message") "attachment"
  if ((Get-Property $nested "type") -eq "deferred_tools_delta") { $candidates += $nested }
  $direct = Get-Property $EventObject "deferred_tools_delta"
  if ($null -ne $direct) { $candidates += $direct }
  return Read-DeltaNames $candidates
}

function Read-DeltaNames($Deltas) {
  $names = @()
  foreach ($delta in $Deltas) {
    foreach ($field in @("addedNames", "tools")) {
      foreach ($entry in @(Get-Property $delta $field @())) {
        if ($entry -is [string]) { $names += $entry }
        else { $name = Get-Property $entry "name" ""; if ($name) { $names += $name } }
      }
    }
  }
  return $names
}

function Get-InitToolNames($EventObject) {
  if ((Get-Property $EventObject "type") -ne "system") { return @() }
  if ((Get-Property $EventObject "subtype") -ne "init") { return @() }
  $names = @()
  foreach ($entry in @(Get-Property $EventObject "tools" @())) {
    if ($entry -is [string]) { $names += $entry }
    else { $name = Get-Property $entry "name" ""; if ($name) { $names += $name } }
  }
  return $names
}

function Get-TranscriptToolNames($EventObject) {
  $names = @()
  $names += @(Get-DeltaNames $EventObject)
  $names += @(Get-InitToolNames $EventObject)
  return $names
}

function Get-NamespaceTools([string]$TranscriptPath, [string]$Guid) {
  if (-not $TranscriptPath -or -not $Guid -or -not (Test-Path -LiteralPath $TranscriptPath)) { return @() }
  $prefix = "mcp__$Guid`__"
  $lines = Get-Content -LiteralPath $TranscriptPath -Tail 800
  [array]::Reverse($lines)
  foreach ($line in $lines) {
    $obj = Read-JsonObject $line
    $found = @(Get-TranscriptToolNames $obj | Where-Object { $_.StartsWith($prefix) })
    if ($found.Count -gt 0) { return @($found | ForEach-Object { $_.Substring($prefix.Length) } | Select-Object -Unique) }
  }
  return @()
}

function Get-ClaudeAuditRoots {
  $roots = @()
  foreach ($base in @($env:APPDATA, $env:LOCALAPPDATA)) {
    if ([string]::IsNullOrWhiteSpace($base)) { continue }
    $roots += Join-Path $base "Claude\local-agent-mode-sessions"
    $packages = Join-Path $base "Packages"
    if (Test-Path -LiteralPath $packages) {
      foreach ($pkg in Get-ChildItem -LiteralPath $packages -Directory -Filter "Claude_*" -ErrorAction SilentlyContinue) {
        $roots += Join-Path $pkg.FullName "LocalCache\Roaming\Claude\local-agent-mode-sessions"
      }
    }
  }
  if (-not [string]::IsNullOrWhiteSpace($env:USERPROFILE)) {
    $roots += Join-Path $env:USERPROFILE ".claude"
  }
  if (Test-Path -LiteralPath "C:\Users") {
    foreach ($profile in Get-ChildItem -LiteralPath "C:\Users" -Directory -ErrorAction SilentlyContinue) {
      $roots += Join-Path $profile.FullName "AppData\Roaming\Claude\local-agent-mode-sessions"
      $packages = Join-Path $profile.FullName "AppData\Local\Packages"
      if (Test-Path -LiteralPath $packages) {
        foreach ($pkg in Get-ChildItem -LiteralPath $packages -Directory -Filter "Claude_*" -ErrorAction SilentlyContinue) {
          $roots += Join-Path $pkg.FullName "LocalCache\Roaming\Claude\local-agent-mode-sessions"
        }
      }
    }
  }
  return $roots | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -Unique
}

function Find-FallbackAuditPath([string]$SessionId) {
  if ([string]::IsNullOrWhiteSpace($SessionId)) { return "" }
  foreach ($root in Get-ClaudeAuditRoots) {
    $files = Get-ChildItem -LiteralPath $root -Recurse -Filter audit.jsonl -File -ErrorAction SilentlyContinue |
      Sort-Object LastWriteTime -Descending |
      Select-Object -First 80
    foreach ($file in $files) {
      try {
        if (Select-String -LiteralPath $file.FullName -Pattern $SessionId -SimpleMatch -Quiet) { return $file.FullName }
      } catch {}
    }
  }
  return ""
}

function Test-CursorCliVersion([string]$Version) {
  return $Version -match '^\d{4}\.\d{1,2}\.\d{1,2}(\D|$)'
}

# Only node / cursor-agent processes count: the shell that runs this hook can
# carry the payload, and with it any text, in its own command line.
function Test-CursorAgentProcess($Process) {
  if ([string]$Process.Name -notmatch '^(node|cursor-agent)(\.exe)?$') { return $false }
  return [string]$Process.CommandLine -match 'cursor-agent([\\/]|\.exe|"|\s|$)'
}

function Test-PrintFlag([string]$CommandLine) {
  $tokens = @($CommandLine -split '\s+')
  return ($tokens -ccontains "-p") -or ($tokens -ccontains "--print")
}

# The Cursor CLI sends the same payload in print mode (-p) and interactive
# mode, but only interactive mode fires `stop`, which carries the agent's
# answers back. The cursor-agent process's command line is the one place the
# two differ; any ancestor in print mode wins over one without the flag.
function Get-CursorCliMode {
  $processes = @{}
  foreach ($process in @(Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId, Name, CommandLine)) {
    $processes[[int]$process.ProcessId] = $process
  }
  $mode = ""
  $processId = $PID
  for ($depth = 0; $depth -lt $CursorAncestorDepth -and $processes.ContainsKey($processId); $depth++) {
    $process = $processes[$processId]
    if (Test-CursorAgentProcess $process) {
      if (Test-PrintFlag $process.CommandLine) { return "print" }
      $mode = "interactive"
    }
    $processId = [int]$process.ParentProcessId
  }
  return $mode
}

function Add-CursorCliMode($Payload) {
  if ($Agent -ne "cursor") { return }
  $version = [string](Get-Property $Payload "cursor_version" (Get-EnvValue "CURSOR_VERSION"))
  if (-not (Test-CursorCliVersion $version)) { return }
  try { $mode = Get-CursorCliMode } catch { return }
  if ($mode) { Set-Property $Payload "eve_cursor_cli_mode" $mode }
}

function Add-ResolutionSignals([string]$Raw) {
  $payload = Read-JsonObject $Raw
  if ($null -eq $payload) { return $Raw }
  $script:AuditWinner = "none"
  $script:AuditWinnerLabel = ""
  $script:AuditSignAction = "none"
  $script:AuditSignReason = ""
  $script:AuditSteps = @()
  Record-IdentityAuditMode
  Add-CursorCliMode $payload
  # A lifecycle event never waits on /Me, the CLI or a sign-in, but keeps an
  # email it already has: the guard matches it against the tool calls'.
  if ((Test-LifecycleEvent $EventName) -and (Test-DatabricksWorkspaceDetected)) {
    Invoke-DatabricksLoginPrime
    $email = Get-EarlyUserEmail $payload
  } else { $email = Get-UserEmail $payload }
  if ($email) { Set-Property $payload "user_email" $email }
  elseif ((Get-Property $payload "user_email" $null) -is [string]) { $payload.PSObject.Properties.Remove("user_email") }
  $guid = Get-CallingGuid $payload
  if ($guid) {
    Set-Property $payload "eve_mcp_directory_uuid" $guid
    $path = Get-Property $payload "transcript_path" (Get-Property $payload "transcriptPath" "")
    $tools = @(Get-NamespaceTools $path $guid)
    if ($tools.Count -eq 0) {
      $fallbackPath = Find-FallbackAuditPath (Get-Property $payload "session_id" "")
      $fallbackTools = @(Get-NamespaceTools $fallbackPath $guid)
      if ($fallbackTools.Count -gt 0) { $tools = $fallbackTools }
    }
    if ($tools.Count -gt 0) { Set-Property $payload "eve_mcp_namespace_tools" $tools }
  }
  if (-not $email -and $script:AuditWinner -eq "none") { Add-AuditStep "identity" "miss" "anonymous" }
  Attach-IdentityAudit $payload
  return ($payload | ConvertTo-Json -Compress -Depth 100)
}

function Test-Transient([string]$Reason) {
  foreach ($pattern in $TransientPatterns) {
    if ($Reason -match $pattern) { return $true }
  }
  return $false
}

function Get-Endpoint([string]$BaseUrl, [string]$HookAgent, [string]$HookEvent) {
  if (-not $BaseUrl) { throw "EVE_ORCHESTRATOR_URL not set" }
  $base = $BaseUrl.TrimEnd("/")
  return "$base/hooks/$([uri]::EscapeDataString($HookAgent))/$([uri]::EscapeDataString($HookEvent))"
}

function Invoke-CurlHookRequest([string]$Body) {
  if ((Get-EnvValue "EVE_HOOK_DISABLE_CURL") -eq "1") { throw "curl disabled" }
  $curl = Get-Command "curl.exe" -ErrorAction SilentlyContinue
  if ($null -eq $curl) { throw "curl.exe not found" }

  $endpoint = Get-Endpoint (Get-EnvValue "EVE_ORCHESTRATOR_URL") $Agent $EventName
  $bodyFile = [IO.Path]::GetTempFileName()
  $errFile = [IO.Path]::GetTempFileName()
  [IO.File]::WriteAllText($bodyFile, $Body, [Text.UTF8Encoding]::new($false))
  try {
    $args = @(
      "--silent", "--show-error",
      "--max-time", "$(Get-RequestTimeoutSeconds)",
      "-X", "POST",
      "-H", "Content-Type: application/json; charset=utf-8"
    )
    $pluginId = Get-EnvValue "EVE_HOOK_PLUGIN_ID"
    if ($pluginId -match "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$") {
      $args += @("-H", "X-Eve-Hook-Plugin-Id: $pluginId")
    }
    # Lets the guard honour fail-closed for its own verification errors too.
    $args += @("-H", "X-Eve-Hook-Failure-Mode: $(Get-FailureMode)")
    $hookToken = Get-HookToken
    if ($hookToken) { $args += @("-H", "Authorization: Bearer $hookToken") }
    $userToken = Get-UserToken
    if ($userToken) { $args += @("-H", "X-Eve-User-Token: $userToken") }
    $capabilities = Get-HookCapabilities
    if ($capabilities) { $args += @("-H", "X-Eve-Hook-Capabilities: $capabilities") }
    $args += @("--data-binary", "@$bodyFile", "-w", "`n__EVE_HOOK_STATUS__:%{http_code}", $endpoint)
    $response = & $curl.Source @args 2>$errFile
    $exitCode = $LASTEXITCODE
    $responseText = ($response -join "`n")
    if ($exitCode -ne 0) {
      $stderr = if (Test-Path -LiteralPath $errFile) { [IO.File]::ReadAllText($errFile).Trim() } else { "" }
      throw "curl exit ${exitCode}: $(if ($stderr) { $stderr } else { 'no stderr' })"
    }
    $statusMatch = [regex]::Match($responseText, "(?s)(?:^|\r?\n)__EVE_HOOK_STATUS__:(\d+)\s*$")
    if (-not $statusMatch.Success) { throw "curl missing HTTP status trailer" }
    $status = $statusMatch.Groups[1].Value
    $content = $responseText.Substring(0, $statusMatch.Index).TrimEnd()
    if (-not $status -or [int]$status -lt 200 -or [int]$status -ge 300) {
      throw "Eve Guard HTTP $(if ($status) { $status } else { '0' }): $(Truncate-Text $content)"
    }
    return $content
  } finally {
    Remove-Item -LiteralPath $bodyFile, $errFile -Force -ErrorAction SilentlyContinue
  }
}

function Invoke-HookRequest([string]$Body) {
  # Curl is the primary transport. Only fall back to Invoke-WebRequest when
  # curl cannot run at all — a curl timeout means the guard already has the
  # request, and sending it again via WebRequest duplicates in-flight work.
  if ((Get-EnvValue "EVE_HOOK_DISABLE_CURL") -ne "1") {
    $curl = Get-Command "curl.exe" -ErrorAction SilentlyContinue
    if ($null -ne $curl) { return Invoke-CurlHookRequest $Body }
  }
  return Invoke-WebHookRequest $Body
}

function Invoke-WebHookRequest([string]$Body) {
  $endpoint = Get-Endpoint (Get-EnvValue "EVE_ORCHESTRATOR_URL") $Agent $EventName
  $headers = @{ "Content-Type" = "application/json; charset=utf-8" }
  $pluginId = Get-EnvValue "EVE_HOOK_PLUGIN_ID"
  if ($pluginId -match "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$") {
    $headers["X-Eve-Hook-Plugin-Id"] = $pluginId
  }
  $headers["X-Eve-Hook-Failure-Mode"] = Get-FailureMode
  $hookToken = Get-HookToken
  if ($hookToken) { $headers["Authorization"] = "Bearer $hookToken" }
  $userToken = Get-UserToken
  if ($userToken) { $headers["X-Eve-User-Token"] = $userToken }
  $capabilities = Get-HookCapabilities
  if ($capabilities) { $headers["X-Eve-Hook-Capabilities"] = $capabilities }
  try {
    $bodyBytes = [Text.Encoding]::UTF8.GetBytes($Body)
    $response = Invoke-WebRequest -Uri $endpoint -Method Post -Headers $headers -Body $bodyBytes -TimeoutSec (Get-RequestTimeoutSeconds) -UseBasicParsing -ErrorAction Stop
  } catch {
    throw (Format-WebExceptionReason $_.Exception)
  }
  if ([int]$response.StatusCode -lt 200 -or [int]$response.StatusCode -ge 300) { throw "Eve Guard HTTP $($response.StatusCode)" }
  return [string]$response.Content
}

function Format-WebExceptionReason($Exception) {
  $response = $Exception.Response
  if ($null -eq $response) { return $Exception.Message }
  $statusCode = [int]$response.StatusCode
  $body = ""
  try {
    $stream = $response.GetResponseStream()
    if ($null -ne $stream) {
      $reader = [IO.StreamReader]::new($stream)
      $body = $reader.ReadToEnd()
    }
  } catch {}
  return "Eve Guard HTTP ${statusCode}: $(Truncate-Text $body)"
}

function Invoke-WithRetry([string]$Body) {
  $maxRetries = Get-MaxRetries
  for ($attempt = 0; $attempt -le $maxRetries; $attempt++) {
    try { return @{ ok = $true; body = (Invoke-HookRequest $Body); reason = "" } }
    catch {
      $reason = $_.Exception.Message
      if (-not (Test-Transient $reason) -or $attempt -eq $maxRetries) { return @{ ok = $false; body = ""; reason = $reason } }
      Start-Sleep -Milliseconds $RetryBackoffMs
    }
  }
}

function Get-CursorIdentityDir {
  $uid = [Environment]::UserName
  return Join-Path ([IO.Path]::GetTempPath()) "eve-guard-hook-identity-$uid"
}

function Get-CursorDeviceId {
  $dir = Get-CursorIdentityDir
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  $file = Join-Path $dir "device-id"
  if (Test-Path -LiteralPath $file) { return [IO.File]::ReadAllText($file).Trim() }
  $bytes = New-Object byte[] 24
  [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
  $id = [Convert]::ToBase64String($bytes).TrimEnd("=").Replace("+","-").Replace("/","_")
  [IO.File]::WriteAllText($file, $id)
  return $id
}

function Open-CursorLoginOnce([string]$Url) {
  if (-not $Url) { return }
  $lock = Join-Path (Get-CursorIdentityDir) "login-opened"
  if ((Test-Path -LiteralPath $lock) -and ((Get-Date) - (Get-Item -LiteralPath $lock).LastWriteTime).TotalMinutes -lt 15) { return }
  Set-Content -LiteralPath $lock -Value "1"
  Start-Process $Url
}

function Initialize-CursorFederated {
  $script:CursorFederatedToken = ""
  $script:CursorLocalDeny = ""
  if ($Agent -ne "cursor") { return }
  if (Get-EnvValue "EVE_HOOK_USER_TOKEN" "") { return }
  if (@("Stop","SubagentStop","stop","SessionStart","sessionStart","afterAgentResponse") -contains $EventName) { return }
  $base = (Get-EnvValue "EVE_ORCHESTRATOR_URL" "").TrimEnd("/")
  if (-not $base) { return }
  $device = Get-CursorDeviceId
  $hook = Get-HookToken
  try {
    $policy = Invoke-RestMethod -Headers @{ Authorization = "Bearer $hook" } -TimeoutSec 2 -Uri "$base/hooks/cursor/session-policy?device_id=$device"
  } catch { return }
  if (-not $policy.enabled) { return }
  $sessionFile = Join-Path (Get-CursorIdentityDir) "laptop.session"
  if (Test-Path -LiteralPath $sessionFile) {
    $saved = Get-Content -LiteralPath $sessionFile -Raw | ConvertFrom-Json
    $now = [int][double]::Parse((Get-Date -UFormat %s))
    if ($saved.token -and $saved.expires_at -and $now -lt ([int]$saved.expires_at - 60)) {
      $script:CursorFederatedToken = [string]$saved.token
      return
    }
    if ($saved.refresh) {
      try {
        $renewed = Invoke-RestMethod -Method Post -Headers @{ Authorization = "Bearer $hook"; "Content-Type" = "application/json" } -TimeoutSec 5 -Body (@{ device_id = $device; refresh_token = [string]$saved.refresh; existing_access_token = [string]$saved.token; existing_expires_at = [int]$saved.expires_at } | ConvertTo-Json) -Uri "$base/hooks/cursor/refresh"
        if ($renewed.access_token) {
          $script:CursorFederatedToken = [string]$renewed.access_token
          @{ token = [string]$renewed.access_token; refresh = [string]$saved.refresh; expires_at = $now + [int]$renewed.expires_in } | ConvertTo-Json | Set-Content -LiteralPath $sessionFile
          return
        }
      } catch {}
    }
  }
  try {
    $claim = Invoke-RestMethod -Method Post -Headers @{ Authorization = "Bearer $hook"; "Content-Type" = "application/json" } -TimeoutSec 5 -Body (@{ device_id = $device } | ConvertTo-Json) -Uri "$base/hooks/cursor/claim"
  } catch { return }
  if ($claim.pending -and $claim.access_token) {
    $script:CursorFederatedToken = [string]$claim.access_token
    $now = [int][double]::Parse((Get-Date -UFormat %s))
    @{ token = [string]$claim.access_token; refresh = [string]$claim.refresh_token; expires_at = $now + [int]$claim.expires_in } | ConvertTo-Json | Set-Content -LiteralPath $sessionFile
    return
  }
  Open-CursorLoginOnce ([string]$policy.loginUrl)
  $script:CursorLocalDeny = "Sign in to Eve Guard to continue. A browser window was opened."
}

function Main {
  Apply-BakedConfig (Read-BakedConfig)
  Initialize-CursorFederated
  $raw = [Console]::In.ReadToEnd()
  if ($script:CursorLocalDeny) {
    $reason = ($script:CursorLocalDeny -replace '\\','\\\\' -replace '"','\"')
    [Console]::Out.Write("{`"permission`":`"deny`",`"continue`":true,`"user_message`":`"$reason`",`"agent_message`":`"$reason`"}")
    exit 0
  }
  $parsed = Read-JsonObject $raw
  $sessionId = Get-Property $parsed "session_id" ""
  $payload = Add-ResolutionSignals $raw
  $enriched = Read-JsonObject $payload
  $result = Invoke-WithRetry $payload
  if ($result.ok) { [Console]::Out.Write($result.body); exit 0 }
  Write-DebugLog "dispatch failed: $($result.reason)"
  [Console]::Out.Write((Resolve-FailureResponse (Get-FailureMode) $sessionId $result.reason $EventName $enriched))
  exit 0
}

if ($Agent -eq "databricks-login") { exit (Invoke-DatabricksLoginCommand $(if ($PSBoundParameters.ContainsKey("EventName")) { $EventName } else { "" })) }

try { Main } catch {
  [Console]::Out.Write((Resolve-FailureResponse (Get-FailureMode) "" "fatal: $($_.Exception.Message)" $EventName))
  exit 0
}
