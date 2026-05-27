# Sentinel

State-based tool gating and cryptographic receipt system for [pi](https://pi.dev/).

Sentinel keeps tool policy enforcement outside the model's prompt/context. It gates pi tool calls with deterministic Python code, then records tamper-evident receipts for the calls that run.

## Why Sentinel?

Prompt-only guardrails can be ignored, misread, or overridden by prompt injection. Sentinel enforces policy in a local service:

- **Deterministic allow/deny decisions** from a finite state machine (FSM)
- **Regex-based tool allowlists** per workflow state
- **Optional guarded transitions** based on tool inputs
- **Ed25519-signed receipts** for auditability
- **SHA-256 hash chaining** so receipt edits, deletions, and reordering are detectable
- **Fail-open behavior** if the server is unavailable, so coding sessions are not bricked

## How It Works

```text
pi tool call requested
    ↓
pi extension → POST http://127.0.0.1:9800/gate
    ↓
Sentinel checks current FSM state, allowed tools, and transition guards
    ↓ allow/deny
If allowed, the tool runs
    ↓
pi extension → POST http://127.0.0.1:9800/receipt
    ↓
Sentinel hashes input/output, links to previous receipt, signs, appends session JSONL
```

When pi starts, creates, forks, or resumes a session, the extension calls `/session`; Sentinel switches to a dedicated log under `data/sessions/`, so receipt sequence numbers start at `0` for a new session. Resuming the same pi session reopens the same log. When pi closes or switches away from a session, the extension calls `/session/end` to mark that receipt session ended.

Example receipt:

```json
{
  "id": "019d1238-481f-70fa-...",
  "seq": 42,
  "tool_name": "edit",
  "tool_input_hash": "sha256:a3f2...",
  "tool_output_hash": "sha256:7b91...",
  "state": "developing",
  "prev_hash": "sha256:e4c1...",
  "event": "gate_allow",
  "signature": "ed25519:R2x5..."
}
```

## Installation

Requirements: Python 3.12+

```bash
git clone https://github.com/forrestblade/sentinel.git
cd sentinel
pip install -e .
sentinel init
sentinel start --daemon
sentinel status
```

For development:

```bash
pip install -e ".[dev]"
pytest tests/ -v
```

## Configuration

Sentinel writes its default config to `~/.config/sentinel/sentinel.yaml` during `sentinel init`.

```yaml
server:
  host: "127.0.0.1"
  port: 9800
  data_dir: "~/.config/sentinel/data"

fsm:
  initial_state: "idle"

  states:
    idle:
      description: "No active workflow"
      allowed_tools: [".*"]

    planning:
      description: "Read-only exploration"
      allowed_tools: ["read", "bash", "multi_tool_use\\.parallel"]

    developing:
      description: "Full tool access"
      allowed_tools: [".*"]

    testing:
      description: "Test execution only"
      allowed_tools: ["read", "bash", "multi_tool_use\\.parallel"]

    reviewing:
      description: "Read-only review"
      allowed_tools: ["read", "bash", "multi_tool_use\\.parallel"]

  transitions:
    - { from: idle, to: planning, trigger: manual }
    - { from: idle, to: developing, trigger: manual }
    - { from: planning, to: developing, trigger: manual }
    - from: developing
      to: testing
      trigger: bash
      guards:
        - field: command
          pattern: "^(pnpm|npm)\\s+test"
    - { from: testing, to: developing, trigger: manual }
    - { from: developing, to: reviewing, trigger: manual }
    - { from: reviewing, to: developing, trigger: manual }
    - { from: "*", to: idle, trigger: manual }
```

Tool names are matched as regular expressions. Guards match fields in the tool input and can trigger automatic state transitions.

## pi Integration

Sentinel runs as a pi extension. The extension:

- gates every pi tool call through `/gate`
- records every pi tool result through `/receipt`
- starts/resumes a separate receipt log for each pi session through `/session`
- auto-starts Sentinel on session start when possible
- auto-transitions FSM state from pi activity (`planning`, `developing`, `testing`, `idle`)
- shows a live status-line entry, with an optional widget
- adds commands for state, transitions, and widget controls

Install:

```bash
mkdir -p ~/.pi/agent/extensions/sentinel
cp pi-extension/index.ts ~/.pi/agent/extensions/sentinel/index.ts
```

Then start pi or run `/reload` inside an existing pi session.

Commands:

- `/sentinel-state` — show server, FSM, allowed tools, transitions, and receipt count
- `/sentinel-transition <state>` — manually transition FSM state
- `/sentinel-ui <on|off|toggle|verbose|compact|refresh>` — control the optional live widget

Optional environment variables:

- `SENTINEL_URL` — default `http://127.0.0.1:9800`
- `SENTINEL_COMMAND` — command used to auto-start Sentinel, default `sentinel`
- `SENTINEL_CONFIG` — config path passed as `sentinel --config <path> start`

pi tool names are lowercase (`read`, `bash`, `write`, `edit`). The default `planning` state allows read-only exploration with `read`, `bash`, and parallel read-only tool batches. The extension automatically moves to `developing` if `edit`, `write`, or a mutating shell command is requested.

## CLI

```text
sentinel --config <path> init       # Generate keys and config
sentinel start [--daemon]          # Start the HTTP server
sentinel stop                      # Stop the server
sentinel status                    # Show server, FSM state, chain length
sentinel state                     # Detailed FSM state and transitions
sentinel transition <state>        # Manually change state
sentinel verify                    # Verify receipt chain integrity
sentinel audit [-n 20]             # View receipt audit trail
sentinel audit --tool bash         # Filter by tool
sentinel audit --state developing  # Filter by state
sentinel audit --event gate_allow  # Filter by event
```

## HTTP API

- `GET /health` — server health, uptime, active session, receipt count
- `GET /state` — current FSM state, allowed tools, available transitions
- `POST /session` — start/resume a per-session receipt log; accepts `session_id` or `session_file`
- `POST /session/end` — end the active per-session receipt log
- `POST /gate` — gate a tool call
- `POST /receipt` — append a signed receipt for a tool result
- `POST /transition` — manually transition state

### `/gate` response

```json
{
  "decision": "allow",
  "reason": "Tool 'read' allowed in state 'planning'",
  "state": "planning",
  "receipt_id": "019d1238-481f-70fa-...",
  "context": "[Sentinel] state=planning | receipt=... | decision=allow"
}
```

## Failsafe Behavior

Sentinel is a safety overlay, not a hard runtime dependency. If the server is down, the pi extension allows tool calls to continue. Missing receipts or altered history are still detectable when verifying the chain.

## Design Notes

- **HTTP sidecar over prompt policy** — low latency and in-memory FSM state
- **JSONL over SQLite** — simple append-only receipt log
- **Ed25519 over HMAC** — externally verifiable signatures
- **UUIDv7 over UUIDv4** — chronological receipt IDs
- **Atomic state writes** — `os.replace()` prevents partial state files

## License

MIT
