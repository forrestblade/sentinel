"""aiohttp HTTP server for sentinel gating and receipt generation."""

import hashlib
import json
import os
import signal
import time
from pathlib import Path

from aiohttp import web

from sentinel.config import SentinelConfig, load_config
from sentinel.crypto import load_private_key, load_public_key
from sentinel.fsm import SentinelFSM
from sentinel.receipt import ReceiptChain


def create_app(config: SentinelConfig) -> web.Application:
    """Create the sentinel aiohttp application."""
    app = web.Application()
    app["config"] = config
    app["start_time"] = time.time()

    # Initialize FSM
    data_dir = config.server.data_dir
    data_dir.mkdir(parents=True, exist_ok=True)

    key_dir = data_dir / "keys"
    private_key = load_private_key(key_dir / "sentinel.key")
    public_key = load_public_key(key_dir / "sentinel.pub")

    app["fsm"] = SentinelFSM(config.fsm, data_dir / "state.json")
    app["private_key"] = private_key
    app["public_key"] = public_key
    app["current_session"] = None
    app["chain"] = ReceiptChain(data_dir / "receipts.jsonl", private_key, public_key)

    app.router.add_post("/session", handle_session)
    app.router.add_post("/session/end", handle_session_end)
    app.router.add_post("/gate", handle_gate)
    app.router.add_post("/receipt", handle_receipt)
    app.router.add_post("/transition", handle_transition)
    app.router.add_get("/state", handle_state)
    app.router.add_get("/health", handle_health)

    return app


def _session_slug(session_key: str) -> str:
    digest = hashlib.sha256(session_key.encode("utf-8")).hexdigest()[:16]
    name = Path(session_key).stem or "session"
    safe_name = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)[:48]
    return f"{safe_name}-{digest}"


def _switch_receipt_session(app: web.Application, session_key: str, metadata: dict) -> dict:
    data_dir: Path = app["config"].server.data_dir
    slug = _session_slug(session_key)
    session_dir = data_dir / "sessions" / slug
    session_dir.mkdir(parents=True, exist_ok=True)

    chain_path = session_dir / "receipts.jsonl"
    app["chain"] = ReceiptChain(chain_path, app["private_key"], app["public_key"])
    app["current_session"] = {
        "id": slug,
        "key": session_key,
        "path": str(chain_path),
        "started_at": time.time(),
        "metadata": metadata,
    }

    session_json = json.dumps(app["current_session"], separators=(",", ":"))
    index_path = data_dir / "sessions.jsonl"
    with open(index_path, "a") as f:
        f.write(session_json + "\n")
    (data_dir / "current_session.json").write_text(session_json)

    return app["current_session"]


async def handle_session(request: web.Request) -> web.Response:
    """Start or resume a receipt log for an agent session."""
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    session_key = body.get("session_id") or body.get("session_file")
    if not session_key:
        return web.json_response({"error": "Missing 'session_id' or 'session_file'"}, status=400)

    session = _switch_receipt_session(request.app, str(session_key), body)
    chain: ReceiptChain = request.app["chain"]
    return web.json_response({
        "session": session,
        "chain_length": chain.length,
    })


async def handle_session_end(request: web.Request) -> web.Response:
    """End the active receipt log for an agent session."""
    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    current = request.app.get("current_session")
    if current is None:
        return web.json_response({"ended": False, "reason": "No active session"})

    session_key = body.get("session_id") or body.get("session_file")
    if session_key and str(session_key) != current.get("key"):
        return web.json_response({"ended": False, "reason": "Session mismatch"}, status=409)

    ended = {
        **current,
        "ended_at": time.time(),
        "end_metadata": body,
    }
    data_dir: Path = request.app["config"].server.data_dir
    session_json = json.dumps(ended, separators=(",", ":"))
    with open(data_dir / "sessions.jsonl", "a") as f:
        f.write(session_json + "\n")
    (data_dir / "current_session.json").write_text(session_json)

    request.app["current_session"] = None
    request.app["chain"] = ReceiptChain(
        data_dir / "receipts.jsonl",
        request.app["private_key"],
        request.app["public_key"],
    )

    return web.json_response({"ended": True, "session": ended})


async def handle_gate(request: web.Request) -> web.Response:
    """PreToolUse hook endpoint: check FSM and allow/deny tool calls."""
    fsm: SentinelFSM = request.app["fsm"]
    chain: ReceiptChain = request.app["chain"]

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    tool_name = body.get("tool_name", "")
    tool_input = body.get("tool_input", {})

    allowed, reason = fsm.is_tool_allowed(tool_name)

    event = "gate_allow" if allowed else "gate_deny"
    receipt = chain.append(tool_name, tool_input, None, fsm.get_state().current, event)

    # Evaluate auto-transitions on allowed tools
    if allowed:
        target = fsm.evaluate_transition(tool_name, tool_input)
        if target:
            fsm.transition_to(target)

    decision = "allow" if allowed else "deny"

    return web.json_response({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason,
            "additionalContext": (
                f"[Sentinel] state={fsm.get_state().current} | "
                f"receipt={receipt.id} | decision={decision}"
            ),
        }
    })


async def handle_receipt(request: web.Request) -> web.Response:
    """PostToolUse hook endpoint: create a receipt with tool output hash."""
    fsm: SentinelFSM = request.app["fsm"]
    chain: ReceiptChain = request.app["chain"]

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    tool_name = body.get("tool_name", "")
    tool_input = body.get("tool_input", {})
    tool_response = body.get("tool_response", body.get("tool_result"))

    receipt = chain.append(
        tool_name, tool_input, tool_response,
        fsm.get_state().current, "post_receipt",
    )

    return web.json_response({
        "hookSpecificOutput": {
            "hookEventName": "PostToolUse",
            "additionalContext": (
                f"[Sentinel] receipt={receipt.id} | chain_length={chain.length}"
            ),
        }
    })


async def handle_transition(request: web.Request) -> web.Response:
    """Manual state transition endpoint."""
    fsm: SentinelFSM = request.app["fsm"]
    chain: ReceiptChain = request.app["chain"]

    try:
        body = await request.json()
    except json.JSONDecodeError:
        return web.json_response({"error": "Invalid JSON"}, status=400)

    to_state = body.get("to_state")
    if not to_state:
        return web.json_response({"error": "Missing 'to_state'"}, status=400)

    previous = fsm.get_state().current

    try:
        state = fsm.transition_to(to_state)
    except ValueError as e:
        return web.json_response({"error": str(e)}, status=400)

    chain.append(
        "manual_transition",
        {"from": previous, "to": to_state, "reason": body.get("reason", "")},
        None,
        state.current,
        "transition",
    )

    return web.json_response({
        "previous": previous,
        "current": state.current,
        "transition_count": state.transition_count,
    })


async def handle_state(request: web.Request) -> web.Response:
    """Return current FSM state."""
    fsm: SentinelFSM = request.app["fsm"]
    state = fsm.get_state()
    state_config = request.app["config"].fsm.states[state.current]
    return web.json_response({
        **state.to_dict(),
        "description": state_config.description,
        "allowed_tools": state_config.allowed_tools,
        "available_transitions": fsm.get_available_transitions(),
    })


async def handle_health(request: web.Request) -> web.Response:
    """Health check endpoint."""
    chain: ReceiptChain = request.app["chain"]
    return web.json_response({
        "status": "ok",
        "uptime": time.time() - request.app["start_time"],
        "chain_length": chain.length,
        "session": request.app.get("current_session"),
    })


def write_pid(data_dir: Path) -> None:
    pid_path = data_dir / "sentinel.pid"
    pid_path.write_text(str(os.getpid()))


def remove_pid(data_dir: Path) -> None:
    pid_path = data_dir / "sentinel.pid"
    if pid_path.exists():
        pid_path.unlink()


def run_server(config_path: Path, host: str | None = None, port: int | None = None) -> None:
    """Start the sentinel HTTP server."""
    config = load_config(config_path)
    app = create_app(config)

    h = host or config.server.host
    p = port or config.server.port

    write_pid(config.server.data_dir)

    try:
        web.run_app(app, host=h, port=p, print=lambda msg: print(f"[sentinel] {msg}"))
    finally:
        remove_pid(config.server.data_dir)
