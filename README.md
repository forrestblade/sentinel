# Sentinel

State-based tool gating and cryptographic receipt system for [Claude Code](https://docs.anthropic.com/en/docs/claude-code).

Sentinel enforces **deterministic tool access controls** outside the LLM's reasoning loop and produces **tamper-evident audit trails** of every tool execution. Unlike prompt-based guardrails, Sentinel cannot be bypassed by prompt injection, jailbreaks, or model misinterpretation — enforcement happens in code, not in context.

## How It Works

Sentinel intercepts every Claude Code tool call via [hooks](https://docs.anthropic.com/en/docs/claude-code/hooks) and enforces two security primitives:

### 1. State-Based Tool Gating

A finite state machine (FSM) controls which tools are available at each workflow phase. The orchestration layer intercepts tool calls via Claude Code's `PreToolUse` hook and blocks any tool not in the current state's allowlist.

```
Claude wants to call Write
    ↓
PreToolUse hook → HTTP POST localhost:9800/gate
    ↓
Sentinel checks: current state is "planning"
    planning allows: [Read, Glob, Grep, WebFetch, Agent, mcp__.*]
    Write is NOT in that list → BLOCKED (exit 2)
    ↓
Claude Code prevents the tool from executing
```

The model cannot talk its way past this. A prompt injection that says "ignore all rules" still hits the HTTP hook, which still checks the allowlist in deterministic Python code.

### 2. Cryptographic Receipts

Every tool execution produces an Ed25519-signed, SHA-256 hash-chained receipt proving the tool actually ran with specific inputs and outputs.

```json
{
  "id": "019d1238-481f-70fa-...",
  "seq": 42,
  "tool_name": "Edit",
  "tool_input_hash": "sha256:a3f2...",
  "tool_output_hash": "sha256:7b91...",
  "state": "developing",
  "prev_hash": "sha256:e4c1...",
  "event": "gate_allow",
  "signature": "ed25519:R2x5..."
}
```

- **Ed25519 signatures** — each receipt is signed with a private key that never enters the LLM's context
- **SHA-256 hash chain** — each receipt commits to the hash of the previous receipt; modifying any entry breaks the chain
- **LLMs cannot forge these** — tokenization makes hash computation impossible for language models

## Architecture

```
Claude tool call
    ↓
PreToolUse hook → HTTP POST localhost:9800/gate
    ↓
Sentinel: check FSM state → tool in allowlist? → guards pass?
    ↓ allow/deny
If allowed → tool executes → PostToolUse hook → HTTP POST /receipt
    ↓
Sentinel: hash(input) + hash(output) → chain to prev receipt → Ed25519 sign → append JSONL
```

Components:
- **HTTP server** (aiohttp) — maintains FSM state, handles gating decisions, generates receipts
- **CLI** — init, start/stop, status, verify chain, audit trail
- **MCP server** — lets Claude query its own state and receipts via [Model Context Protocol](https://modelcontextprotocol.io/)

## Installation

```bash
pip install -e .
sentinel init
sentinel start --daemon
```

## Configuration

Edit `~/.config/sentinel/sentinel.yaml`:

```yaml
fsm:
  initial_state: "idle"

  states:
    idle:
      description: "No active workflow"
      allowed_tools: [".*"]

    planning:
      description: "Read-only exploration"
      allowed_tools: ["Read", "Glob", "Grep", "WebFetch", "WebSearch", "Agent", "mcp__.*"]

    developing:
      description: "Full tool access"
      allowed_tools: [".*"]

    testing:
      description: "Test execution only"
      allowed_tools: ["Read", "Glob", "Grep", "Bash", "mcp__.*"]

    reviewing:
      description: "Read-only review"
      allowed_tools: ["Read", "Glob", "Grep", "WebFetch", "mcp__.*"]

  transitions:
    - { from: idle, to: planning, trigger: manual }
    - { from: idle, to: developing, trigger: manual }
    - { from: planning, to: developing, trigger: manual }
    - from: developing
      to: testing
      trigger: Bash
      guards:
        - field: command
          pattern: "^(pnpm|npm)\\s+test"
    - { from: testing, to: developing, trigger: manual }
    - { from: developing, to: reviewing, trigger: manual }
    - { from: "*", to: idle, trigger: manual }
```

Tool allowlists use regex patterns. Guards match tool input fields against regex patterns to trigger automatic state transitions.

## Pi Integration

Sentinel can run as a [pi](https://github.com/earendil-works/pi-coding-agent) extension using `pi-extension/index.ts`. The extension gates every pi tool call through `/gate`, records every tool result through `/receipt`, and adds a live status widget plus commands:

- `/sentinel-state` — show verbose server/FSM/receipt status
- `/sentinel-ui <on|off|toggle|verbose|compact|refresh>` — control the live widget
- `/sentinel-transition <state>` — manually transition FSM state

Install globally:

```bash
mkdir -p ~/.pi/agent/extensions/sentinel
cp pi-extension/index.ts ~/.pi/agent/extensions/sentinel/index.ts
pi /reload
```

Optional environment variables:

- `SENTINEL_URL` — default `http://127.0.0.1:9800`
- `SENTINEL_COMMAND` — command used to auto-start Sentinel, default `sentinel`
- `SENTINEL_CONFIG` — config path passed as `sentinel --config <path> start`

Pi tool names are lowercase (`read`, `bash`, `write`, `edit`). A minimal read-only planning state for pi looks like:

```yaml
planning:
  description: "Read-only exploration in pi"
  allowed_tools: ["read", "multi_tool_use\\.parallel"]
```

## Claude Code Integration

Add hooks to `~/.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": ".*",
        "hooks": [{ "type": "http", "url": "http://127.0.0.1:9800/gate", "timeout": 5 }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": ".*",
        "hooks": [{ "type": "http", "url": "http://127.0.0.1:9800/receipt", "timeout": 5 }]
      }
    ]
  }
}
```

Register the MCP server:

```bash
claude mcp add --scope user -t stdio sentinel -- python3 -m sentinel.mcp_server
```

## CLI

```
sentinel init                  # Generate keys, create config
sentinel start [--daemon]      # Start the HTTP server
sentinel stop                  # Stop the server
sentinel status                # Show server, FSM state, chain length
sentinel state                 # Detailed FSM state + available transitions
sentinel transition <state>    # Manually change state
sentinel verify                # Verify receipt chain integrity
sentinel audit [-n 20]         # View receipt audit trail
sentinel install-hooks         # Print hook config JSON
sentinel install-mcp           # Print MCP registration command
```

## MCP Tools

When registered as an MCP server, Claude can query its own enforcement state:

- `get_state` — current FSM state and transition count
- `get_allowed_tools` — tools available in current state
- `get_transitions` — available state transitions
- `get_recent_receipts` — recent audit trail entries
- `verify_chain` — verify receipt chain integrity
- `get_receipt` — look up a specific receipt by ID

## Failsafe Behavior

If the sentinel server is down, Claude Code treats HTTP hook connection errors as non-blocking — tools continue to work normally. Sentinel is a safety overlay, not a hard dependency. Missing receipts are detectable as gaps in the chain.

## Design Decisions

- **HTTP hooks over command hooks** — near-zero latency, server maintains state in memory
- **JSONL over SQLite** — append-only semantics match receipt chain model, trivially verifiable line by line
- **Ed25519 over HMAC** — externally verifiable (anyone with the public key can verify, no shared secret needed)
- **UUIDv7 over UUIDv4** — time-ordered IDs sort chronologically without a separate index
- **Atomic state writes** — `os.replace()` prevents corrupt state from partial writes

## Testing

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

69 tests covering crypto operations, FSM engine, receipt chain integrity, HTTP server endpoints, and tamper detection.

## License

MIT
