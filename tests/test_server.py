"""Tests for the sentinel HTTP server."""

import json

import pytest
import yaml
from aiohttp import web
from aiohttp.test_utils import AioHTTPTestCase, unittest_run_loop

from sentinel.config import load_config
from sentinel.crypto import generate_keypair
from sentinel.server import create_app
from tests.conftest import SAMPLE_CONFIG


@pytest.fixture
def sentinel_app(tmp_path):
    """Create a sentinel app with test config."""
    # Write config
    config_path = tmp_path / "sentinel.yaml"
    cfg = {**SAMPLE_CONFIG}
    cfg["server"] = {**cfg["server"], "data_dir": str(tmp_path / "data")}
    config_path.write_text(yaml.dump(cfg))

    # Generate keys
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    generate_keypair(data_dir / "keys")

    config = load_config(config_path)
    return create_app(config)


async def test_health(aiohttp_client, sentinel_app):
    client = await aiohttp_client(sentinel_app)
    resp = await client.get("/health")
    assert resp.status == 200
    data = await resp.json()
    assert data["status"] == "ok"
    assert data["chain_length"] == 0


async def test_state(aiohttp_client, sentinel_app):
    client = await aiohttp_client(sentinel_app)
    resp = await client.get("/state")
    assert resp.status == 200
    data = await resp.json()
    assert data["current"] == "idle"
    assert "allowed_tools" in data
    assert "available_transitions" in data


async def test_gate_allows_tool_in_state(aiohttp_client, sentinel_app):
    client = await aiohttp_client(sentinel_app)
    resp = await client.post("/gate", json={
        "tool_name": "Read",
        "tool_input": {"file_path": "/test.py"},
    })
    assert resp.status == 200
    data = await resp.json()
    assert data["hookSpecificOutput"]["permissionDecision"] == "allow"
    assert "[Sentinel]" in data["hookSpecificOutput"]["additionalContext"]


async def test_gate_denies_tool_not_in_state(aiohttp_client, sentinel_app):
    client = await aiohttp_client(sentinel_app)
    # First transition to a restricted state
    await client.post("/transition", json={"to_state": "planning"})
    # Write is not allowed in planning
    resp = await client.post("/gate", json={
        "tool_name": "Write",
        "tool_input": {"file_path": "/test.py"},
    })
    assert resp.status == 200
    data = await resp.json()
    assert data["hookSpecificOutput"]["permissionDecision"] == "deny"


async def test_gate_creates_receipt(aiohttp_client, sentinel_app):
    client = await aiohttp_client(sentinel_app)
    await client.post("/gate", json={
        "tool_name": "Read",
        "tool_input": {"file_path": "/test.py"},
    })
    resp = await client.get("/health")
    data = await resp.json()
    assert data["chain_length"] == 1


async def test_gate_auto_transition(aiohttp_client, sentinel_app):
    client = await aiohttp_client(sentinel_app)
    # Move to developing first
    await client.post("/transition", json={"to_state": "developing"})
    # Bash with test command should auto-transition to testing
    await client.post("/gate", json={
        "tool_name": "Bash",
        "tool_input": {"command": "pnpm test"},
    })
    resp = await client.get("/state")
    data = await resp.json()
    assert data["current"] == "testing"


async def test_receipt_endpoint(aiohttp_client, sentinel_app):
    client = await aiohttp_client(sentinel_app)
    resp = await client.post("/receipt", json={
        "tool_name": "Read",
        "tool_input": {"file_path": "/test.py"},
        "tool_response": {"content": "hello world"},
    })
    assert resp.status == 200
    data = await resp.json()
    assert "receipt=" in data["hookSpecificOutput"]["additionalContext"]


async def test_transition_endpoint(aiohttp_client, sentinel_app):
    client = await aiohttp_client(sentinel_app)
    resp = await client.post("/transition", json={
        "to_state": "developing",
        "reason": "starting work",
    })
    assert resp.status == 200
    data = await resp.json()
    assert data["previous"] == "idle"
    assert data["current"] == "developing"


async def test_transition_to_invalid_state(aiohttp_client, sentinel_app):
    client = await aiohttp_client(sentinel_app)
    resp = await client.post("/transition", json={"to_state": "nonexistent"})
    assert resp.status == 400


async def test_transition_missing_to_state(aiohttp_client, sentinel_app):
    client = await aiohttp_client(sentinel_app)
    resp = await client.post("/transition", json={})
    assert resp.status == 400


async def test_gate_invalid_json(aiohttp_client, sentinel_app):
    client = await aiohttp_client(sentinel_app)
    resp = await client.post("/gate", data=b"not json", headers={"Content-Type": "application/json"})
    assert resp.status == 400


async def test_full_flow(aiohttp_client, sentinel_app):
    """Test a complete gate -> execute -> receipt flow."""
    client = await aiohttp_client(sentinel_app)

    # Gate check
    gate_resp = await client.post("/gate", json={
        "tool_name": "Read",
        "tool_input": {"file_path": "/src/main.py"},
    })
    assert (await gate_resp.json())["hookSpecificOutput"]["permissionDecision"] == "allow"

    # Post-execution receipt
    receipt_resp = await client.post("/receipt", json={
        "tool_name": "Read",
        "tool_input": {"file_path": "/src/main.py"},
        "tool_response": {"content": "import os\n"},
    })
    assert receipt_resp.status == 200

    # Verify chain grew
    health = await (await client.get("/health")).json()
    assert health["chain_length"] == 2  # gate + receipt
