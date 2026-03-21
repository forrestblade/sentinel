"""Tests for configuration loading and validation."""

import pytest
import yaml

from sentinel.config import ConfigError, load_config


def test_valid_config_loads(sample_config):
    assert sample_config.fsm.initial_state == "idle"
    assert "idle" in sample_config.fsm.states
    assert "planning" in sample_config.fsm.states
    assert len(sample_config.fsm.transitions) == 6


def test_state_has_allowed_tools(sample_config):
    planning = sample_config.fsm.states["planning"]
    assert "Read" in planning.allowed_tools
    assert "Glob" in planning.allowed_tools


def test_transition_with_guards(sample_config):
    guarded = [t for t in sample_config.fsm.transitions if t.guards]
    assert len(guarded) == 1
    assert guarded[0].from_state == "developing"
    assert guarded[0].to_state == "testing"
    assert guarded[0].guards[0].field == "command"


def test_server_defaults(tmp_path):
    config_file = tmp_path / "minimal.yaml"
    config_file.write_text(yaml.dump({
        "fsm": {
            "initial_state": "start",
            "states": {"start": {"description": "begin", "allowed_tools": [".*"]}},
        }
    }))
    cfg = load_config(config_file)
    assert cfg.server.host == "127.0.0.1"
    assert cfg.server.port == 9800


def test_missing_fsm_section(tmp_path):
    config_file = tmp_path / "bad.yaml"
    config_file.write_text(yaml.dump({"server": {}}))
    with pytest.raises(ConfigError, match="fsm"):
        load_config(config_file)


def test_missing_initial_state(tmp_path):
    config_file = tmp_path / "bad.yaml"
    config_file.write_text(yaml.dump({
        "fsm": {
            "states": {"a": {"description": "x", "allowed_tools": []}},
        }
    }))
    with pytest.raises(ConfigError, match="initial_state"):
        load_config(config_file)


def test_initial_state_not_defined(tmp_path):
    config_file = tmp_path / "bad.yaml"
    config_file.write_text(yaml.dump({
        "fsm": {
            "initial_state": "nonexistent",
            "states": {"a": {"description": "x", "allowed_tools": []}},
        }
    }))
    with pytest.raises(ConfigError, match="nonexistent"):
        load_config(config_file)


def test_transition_from_unknown_state(tmp_path):
    config_file = tmp_path / "bad.yaml"
    config_file.write_text(yaml.dump({
        "fsm": {
            "initial_state": "a",
            "states": {"a": {"description": "x", "allowed_tools": []}},
            "transitions": [{"from": "unknown", "to": "a", "trigger": "manual"}],
        }
    }))
    with pytest.raises(ConfigError, match="unknown"):
        load_config(config_file)


def test_transition_to_unknown_state(tmp_path):
    config_file = tmp_path / "bad.yaml"
    config_file.write_text(yaml.dump({
        "fsm": {
            "initial_state": "a",
            "states": {"a": {"description": "x", "allowed_tools": []}},
            "transitions": [{"from": "a", "to": "nowhere", "trigger": "manual"}],
        }
    }))
    with pytest.raises(ConfigError, match="nowhere"):
        load_config(config_file)


def test_wildcard_from_state_allowed(tmp_path):
    config_file = tmp_path / "ok.yaml"
    config_file.write_text(yaml.dump({
        "fsm": {
            "initial_state": "a",
            "states": {"a": {"description": "x", "allowed_tools": []}},
            "transitions": [{"from": "*", "to": "a", "trigger": "manual"}],
        }
    }))
    cfg = load_config(config_file)
    assert cfg.fsm.transitions[0].from_state == "*"


def test_invalid_regex_in_allowed_tools(tmp_path):
    config_file = tmp_path / "bad.yaml"
    config_file.write_text(yaml.dump({
        "fsm": {
            "initial_state": "a",
            "states": {"a": {"description": "x", "allowed_tools": ["[invalid"]}},
        }
    }))
    with pytest.raises(ConfigError, match="regex"):
        load_config(config_file)


def test_invalid_regex_in_guard(tmp_path):
    config_file = tmp_path / "bad.yaml"
    config_file.write_text(yaml.dump({
        "fsm": {
            "initial_state": "a",
            "states": {
                "a": {"description": "x", "allowed_tools": []},
                "b": {"description": "y", "allowed_tools": []},
            },
            "transitions": [{
                "from": "a", "to": "b", "trigger": "Bash",
                "guards": [{"field": "cmd", "pattern": "[bad"}],
            }],
        }
    }))
    with pytest.raises(ConfigError, match="regex"):
        load_config(config_file)
