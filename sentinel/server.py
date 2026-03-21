"""aiohttp HTTP server for sentinel gating and receipt generation."""

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
    app["chain"] = ReceiptChain(data_dir / "receipts.jsonl", private_key, public_key)

    app.router.add_post("/gate", handle_gate)
    app.router.add_post("/receipt", handle_receipt)
    app.router.add_post("/transition", handle_transition)
    app.router.add_get("/state", handle_state)
    app.router.add_get("/health", handle_health)

    return app


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
