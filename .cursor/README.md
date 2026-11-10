Json format hooks:


Cursor Hooks:
```json
{
    "conversation_id": "be1519e4-3996-4c8d-a046-b4112ecacf64",
    "generation_id": "adb0f59c-bf1b-40ac-961a-502f5be6d896",
    "model": "grok-4.7",
    "tool_name": "Shell",
    "tool_input": {
        "command": "echo hola",
        "cwd": "",
        "timeout": 30000
    },
    "tool_use_id": "29f98747-8d55-4eee-a310-b3bd5db7f05a",
    "cwd": "",
    "session_id": "be1519e4-3996-4c8d-a046-b4112ecacf64",
    "hook_event_name": "preToolUse",
    "cursor_version": "3.27.22",
    "workspace_roots": [
        "/Users/alejandromoralesvasquez/ws/test-hooks"
    ],
    "user_email": "alejandro@eve.security",
    "transcript_path": null
}
{
    "conversation_id": "be1519e4-3996-4c8d-a046-b4112ecacf64",
    "generation_id": "adb0f59c-bf1b-40ac-961a-502f5be6d896",
    "model": "grok-4.7",
    "command": "echo hola",
    "cwd": "",
    "sandbox": true,
    "tool_use_id": "29f98747-8d55-4eee-a310-b3bd5db7f05a",
    "session_id": "be1519e4-3996-4c8d-a046-b4112ecacf64",
    "hook_event_name": "beforeShellExecution",
    "cursor_version": "3.27.22",
    "workspace_roots": [
        "/Users/alejandromoralesvasquez/ws/test-hooks"
    ],
    "user_email": "alejandro@eve.security",
    "transcript_path": null
}
```

Claude Hooks:
```json
{
    "session_id": "f69b2d5f-d527-4180-9eb8-133a4d8e303d",
    "transcript_path": "/Users/alejandromoralesvasquez/.claude/projects/-Users-alejandromoralesvasquez-ws-test-hooks/f69b2d5f-d527-4180-9eb8-133a4d8e303d.jsonl",
    "cwd": "/Users/alejandromoralesvasquez/ws/test-hooks",
    "scratchpad_dir": "/private/tmp/claude-501/-Users-alejandromoralesvasquez-ws-test-hooks/f69b2d5f-d527-4180-9eb8-133a4d8e303d/scratchpad",
    "prompt_id": "8b4d931c-b9e3-4eb3-8a6b-7161ee1633c2",
    "permission_mode": "auto",
    "effort": {
        "level": "medium"
    },
    "hook_event_name": "PreToolUse",
    "tool_name": "Bash",
    "tool_input": {
        "command": "echo PROHIBIDO",
        "description": "Print PROHIBIDO"
    },
    "tool_use_id": "toolu_01XERwk6conoLnT9S8XDk8Em"
}
```