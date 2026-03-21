"""Shared fixtures for sentinel tests."""

import pytest
import yaml

from sentinel.crypto import generate_keypair


SAMPLE_CONFIG = {
    "server": {
        "host": "127.0.0.1",
        "port": 9800,
    },
    "fsm": {
        "initial_state": "idle",
        "states": {
            "idle": {
                "description": "No active workflow",
                "allowed_tools": [".*"],
            },
            "planning": {
                "description": "Read-only exploration",
                "allowed_tools": ["Read", "Glob", "Grep", "WebFetch", "Agent", "mcp__.*"],
            },
            "developing": {
                "description": "Full tool access",
                "allowed_tools": [".*"],
            },
            "testing": {
                "description": "Test execution only",
                "allowed_tools": ["Read", "Glob", "Grep", "Bash", "mcp__.*"],
            },
        },
        "transitions": [
            {"from": "idle", "to": "planning", "trigger": "manual"},
            {"from": "idle", "to": "developing", "trigger": "manual"},
            {"from": "planning", "to": "developing", "trigger": "manual"},
            {
                "from": "developing",
                "to": "testing",
                "trigger": "Bash",
                "guards": [{"field": "command", "pattern": "^(pnpm|npm)\\s+test"}],
            },
            {"from": "testing", "to": "developing", "trigger": "manual"},
            {"from": "*", "to": "idle", "trigger": "manual"},
        ],
    },
}


@pytest.fixture
def sample_config_path(tmp_path):
    """Write sample config to a temp file and return the path."""
    config_file = tmp_path / "sentinel.yaml"
    config_file.write_text(yaml.dump(SAMPLE_CONFIG))
    return config_file


@pytest.fixture
def sample_config(sample_config_path):
    """Load and return the sample SentinelConfig."""
    from sentinel.config import load_config
    return load_config(sample_config_path)


@pytest.fixture
def key_pair(tmp_path):
    """Generate and return (private_key, public_key, key_dir)."""
    key_dir = tmp_path / "keys"
    priv, pub = generate_keypair(key_dir)
    return priv, pub, key_dir


@pytest.fixture
def data_dir(tmp_path):
    """Return a temp data directory."""
    d = tmp_path / "data"
    d.mkdir()
    return d
