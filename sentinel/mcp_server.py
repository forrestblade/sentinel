"""FastMCP server for Claude introspection of sentinel state and receipts."""

import json
from pathlib import Path

from mcp.server.fastmcp import FastMCP

from sentinel.config import load_config
from sentinel.crypto import load_private_key, load_public_key
from sentinel.receipt import ReceiptChain

DEFAULT_CONFIG_PATH = Path.home() / ".config" / "sentinel" / "sentinel.yaml"

mcp = FastMCP("sentinel")


def _get_data_dir() -> Path:
    config_path = DEFAULT_CONFIG_PATH
    if config_path.exists():
        config = load_config(config_path)
        return config.server.data_dir
    return Path.home() / ".config" / "sentinel" / "data"


def _read_state() -> dict | None:
    state_path = _get_data_dir() / "state.json"
    if state_path.exists():
        return json.loads(state_path.read_text())
    return None


def _get_chain() -> ReceiptChain | None:
    data_dir = _get_data_dir()
    chain_path = data_dir / "receipts.jsonl"
    key_dir = data_dir / "keys"
    priv_path = key_dir / "sentinel.key"
    pub_path = key_dir / "sentinel.pub"

    if not priv_path.exists() or not pub_path.exists():
        return None

    private_key = load_private_key(priv_path)
    public_key = load_public_key(pub_path)
    return ReceiptChain(chain_path, private_key, public_key)


@mcp.tool(description="Get the current Sentinel FSM state, previous state, and transition count")
def get_state() -> str:
    state = _read_state()
    if not state:
        return json.dumps({"error": "Sentinel not initialized"})

    config_path = DEFAULT_CONFIG_PATH
    if config_path.exists():
        config = load_config(config_path)
        state_config = config.fsm.states.get(state["current"])
        if state_config:
            state["description"] = state_config.description
    return json.dumps(state, indent=2)


@mcp.tool(description="List tools allowed in the current Sentinel FSM state")
def get_allowed_tools() -> str:
    state = _read_state()
    if not state:
        return json.dumps({"error": "Sentinel not initialized"})

    config_path = DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return json.dumps({"error": "Config not found"})

    config = load_config(config_path)
    state_config = config.fsm.states.get(state["current"])
    if not state_config:
        return json.dumps({"error": f"Unknown state: {state['current']}"})

    return json.dumps({
        "state": state["current"],
        "allowed_tools": state_config.allowed_tools,
    }, indent=2)


@mcp.tool(description="Get a specific receipt by its ID")
def get_receipt(receipt_id: str) -> str:
    chain = _get_chain()
    if not chain:
        return json.dumps({"error": "Chain not available"})

    receipts = chain.get_receipts()
    for r in receipts:
        if r.id == receipt_id:
            return json.dumps(r.to_dict(), indent=2)
    return json.dumps({"error": f"Receipt {receipt_id} not found"})


@mcp.tool(description="Get the N most recent receipts from the audit trail")
def get_recent_receipts(limit: int = 10) -> str:
    chain = _get_chain()
    if not chain:
        return json.dumps({"error": "Chain not available"})

    receipts = chain.get_receipts(limit=limit)
    return json.dumps([r.to_dict() for r in receipts], indent=2)


@mcp.tool(description="Verify the integrity of the entire receipt chain (signatures + hash links)")
def verify_chain() -> str:
    chain = _get_chain()
    if not chain:
        return json.dumps({"error": "Chain not available"})

    valid, last_seq, msg = chain.verify_chain()
    return json.dumps({
        "valid": valid,
        "chain_length": chain.length,
        "last_valid_seq": last_seq,
        "message": msg,
    }, indent=2)


@mcp.tool(description="List available state transitions from the current FSM state")
def get_transitions() -> str:
    state = _read_state()
    if not state:
        return json.dumps({"error": "Sentinel not initialized"})

    config_path = DEFAULT_CONFIG_PATH
    if not config_path.exists():
        return json.dumps({"error": "Config not found"})

    config = load_config(config_path)
    current = state["current"]
    available = []
    for t in config.fsm.transitions:
        if t.from_state == "*" or t.from_state == current:
            available.append({
                "to": t.to_state,
                "trigger": t.trigger,
                "guards": [{"field": g.field, "pattern": g.pattern} for g in t.guards],
            })

    return json.dumps({
        "current_state": current,
        "transitions": available,
    }, indent=2)


if __name__ == "__main__":
    mcp.run()
