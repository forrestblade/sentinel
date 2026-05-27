"""Tests for the FSM engine."""

import json

import pytest

from sentinel.fsm import FSMState, SentinelFSM


def test_initial_state(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    assert fsm.get_state().current == "idle"


def test_state_persists_to_disk(sample_config, data_dir):
    state_path = data_dir / "state.json"
    fsm = SentinelFSM(sample_config.fsm, state_path)
    assert state_path.exists()
    data = json.loads(state_path.read_text())
    assert data["current"] == "idle"


def test_state_reloads_from_disk(sample_config, data_dir):
    state_path = data_dir / "state.json"
    fsm1 = SentinelFSM(sample_config.fsm, state_path)
    fsm1.transition_to("developing")

    fsm2 = SentinelFSM(sample_config.fsm, state_path)
    assert fsm2.get_state().current == "developing"


def test_tool_allowed_wildcard(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    # idle allows ".*"
    allowed, _ = fsm.is_tool_allowed("bash")
    assert allowed
    allowed, _ = fsm.is_tool_allowed("write")
    assert allowed


def test_tool_denied_in_restricted_state(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    fsm.transition_to("planning")
    allowed, reason = fsm.is_tool_allowed("write")
    assert not allowed
    assert "write" in reason


def test_tool_allowed_in_restricted_state(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    fsm.transition_to("planning")
    allowed, _ = fsm.is_tool_allowed("read")
    assert allowed


def test_parallel_tool_pattern_matching(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    fsm.transition_to("planning")
    allowed, _ = fsm.is_tool_allowed("multi_tool_use.parallel")
    assert allowed


def test_transition_to_valid_state(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    state = fsm.transition_to("developing")
    assert state.current == "developing"
    assert state.previous == "idle"
    assert state.transition_count == 1


def test_transition_to_invalid_state(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    with pytest.raises(ValueError, match="nonexistent"):
        fsm.transition_to("nonexistent")


def test_auto_transition_with_guard(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    fsm.transition_to("developing")
    target = fsm.evaluate_transition("bash", {"command": "pnpm test"})
    assert target == "testing"


def test_auto_transition_guard_no_match(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    fsm.transition_to("developing")
    target = fsm.evaluate_transition("bash", {"command": "ls -la"})
    assert target is None


def test_auto_transition_wrong_tool(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    fsm.transition_to("developing")
    target = fsm.evaluate_transition("read", {"file_path": "/test"})
    assert target is None


def test_manual_transitions_not_auto_triggered(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    # idle->planning is manual, should not auto-trigger
    target = fsm.evaluate_transition("read", {})
    assert target is None


def test_get_available_transitions(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    transitions = fsm.get_available_transitions()
    targets = {t["to"] for t in transitions}
    assert "planning" in targets
    assert "developing" in targets
    assert "idle" in targets  # wildcard transition


def test_reset(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    fsm.transition_to("developing")
    state = fsm.reset()
    assert state.current == "idle"
    assert state.transition_count == 0


def test_transition_count_increments(sample_config, data_dir):
    fsm = SentinelFSM(sample_config.fsm, data_dir / "state.json")
    fsm.transition_to("developing")
    fsm.transition_to("testing")
    assert fsm.get_state().transition_count == 2


def test_fsm_state_serialization():
    state = FSMState(current="testing", previous="developing", entered_at=1000.0, transition_count=5)
    d = state.to_dict()
    restored = FSMState.from_dict(d)
    assert restored.current == state.current
    assert restored.previous == state.previous
    assert restored.transition_count == state.transition_count
