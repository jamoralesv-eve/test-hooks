:; exec /bin/sh "$(dirname "$0")/$(basename "$0" .cmd).sh" "$@" # sh/cmd polyglot launcher - see rem block below
@echo off
rem ==========================================================================
rem  Eve Agent Hook launcher - a sh/cmd POLYGLOT. This one file is the single
rem  entry point named in hooks.json ("<dir>/<name>.cmd <agent> <event>"), so
rem  the SAME command string stays silent on both platforms:
rem    * POSIX (/bin/sh -c ...): line 1 runs - ":" is a no-op, then "exec" of
rem      the sibling ".sh" (same basename) replaces this process, so none of the
rem      Windows lines below are ever read. No cross-platform probe -> no stderr.
rem    * Windows (cmd.exe /c ...): cmd treats the leading ":" on line 1 as a
rem      label and skips it, then runs this batch body, launching the sibling
rem      ".ps1" via PowerShell (pwsh as fallback, then a fail-closed deny).
rem  Cursor marks a hook failed the moment it writes to stderr, so probing the
rem  other OS's binary first (the old "/bin/sh || powershell.exe" chain) printed
rem  a "command not found"/"cannot find path" line on every call. This polyglot
rem  never probes a missing binary on either platform.
rem
rem  The trailing " #" on line 1 turns the CRLF into a POSIX comment so /bin/sh
rem  ignores the stray carriage return; the zip builder ships this file with
rem  CRLF endings, which cmd needs for its label/goto parsing.
rem
rem  %~dpn0 is this launcher's drive+path+name with no extension, so "%~dpn0.ps1"
rem  is the sibling PowerShell runtime regardless of the cursor-/eve- prefix.
rem ==========================================================================
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dpn0.ps1" %* && exit /b 0
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "%~dpn0.ps1" %* && exit /b 0
set "AGENT=%~1"
if "%AGENT%"=="" set "AGENT=claude-code"
set "EVENT_NAME=%~2"
if "%EVENT_NAME%"=="" set "EVENT_NAME=PreToolUse"
if "%TEMP%"=="" set "TEMP=%SystemRoot%\Temp"
set "DIAG_DIR=%TEMP%\eve-guard-hook-diagnostics"
set "LAST_FAILURE=%DIAG_DIR%\last-failure.json"
set "LAST_FAILURE_JSON=%LAST_FAILURE:\=/%"
set "REASON=Eve Guard could not start PowerShell on Windows, so this tool call was blocked. Install or enable Windows PowerShell or PowerShell 7, then retry. Diagnostics: %LAST_FAILURE_JSON%"
if not exist "%DIAG_DIR%" mkdir "%DIAG_DIR%" >nul 2>nul
> "%LAST_FAILURE%" echo {"timestamp":"cmd-fallback","event":"%EVENT_NAME%","agent":"%AGENT%","hook_runtime":"cmd","reason":"PowerShell and pwsh did not start","last_failure_file":"%LAST_FAILURE_JSON%"}
rem Lifecycle hooks (agent reply / turn stop / session start) never gate a
rem tool: answer "{}" so a missing PowerShell cannot stop the agent outright.
if /I "%EVENT_NAME%"=="Stop" goto lifecycle
if /I "%EVENT_NAME%"=="SubagentStop" goto lifecycle
if /I "%EVENT_NAME%"=="SessionStart" goto lifecycle
if /I "%EVENT_NAME%"=="afterAgentResponse" goto lifecycle
if /I "%AGENT%"=="cursor" goto cursor
if /I "%EVENT_NAME%"=="PostToolUse" (
  echo {"decision":"block","reason":"%REASON%","hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":"%REASON%","updatedToolOutput":"%REASON%"}}
  exit /b 0
)
echo {"continue":false,"stopReason":"%REASON%","hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"%REASON%"}}
exit /b 0

:cursor
if /I "%EVENT_NAME%"=="afterMCPExecution" goto cursorpost
if /I "%EVENT_NAME%"=="postToolUse" goto cursorpost
if /I "%EVENT_NAME%"=="afterShellExecution" goto cursorpost
if /I "%EVENT_NAME%"=="afterFileEdit" goto cursorpost
if /I "%EVENT_NAME%"=="postToolUseFailure" goto cursorpost
echo {"permission":"deny","continue":true,"user_message":"%REASON%","agent_message":"%REASON%"}
exit /b 0

:cursorpost
echo {"updated_mcp_tool_output":{"isError":true,"content":[{"type":"text","text":"%REASON%"}],"_eve_guard":{"blocked":true,"phase":"response"}},"additional_context":"%REASON%"}
exit /b 0

:lifecycle
echo {}
exit /b 0
