"""Finite State Machine engine for tool gating."""

import json
import os
import re
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from sentinel.config import FSMConfig, Transition


@dataclass
class FSMState:
    current: str
    previous: str | None = None
    entered_at: float = 0.0
    transition_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "FSMState":
        return cls(**d)


class SentinelFSM:
    def __init__(self, config: FSMConfig, state_path: Path) -> None:
        self._config = config
        self._state_path = state_path
        self._state = self._load_or_init()

    def _load_or_init(self) -> FSMState:
        if self._state_path.exists():
            data = json.loads(self._state_path.read_text())
            state = FSMState.from_dict(data)
            if state.current in self._config.states:
                return state
        return self._init_state()

    def _init_state(self) -> FSMState:
        state = FSMState(
            current=self._config.initial_state,
            entered_at=time.time(),
        )
        self._persist(state)
        return state

    def _persist(self, state: FSMState) -> None:
        self._state_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self._state_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(state.to_dict(), indent=2))
        os.replace(str(tmp_path), str(self._state_path))

    def get_state(self) -> FSMState:
        return self._state

    def is_tool_allowed(self, tool_name: str) -> tuple[bool, str]:
        """Check if a tool is allowed in the current state.

        Returns (allowed, reason).
        """
        state_config = self._config.states[self._state.current]
        for pattern in state_config.allowed_tools:
            if re.fullmatch(pattern, tool_name):
                return True, f"Tool '{tool_name}' allowed in state '{self._state.current}'"

        return False, (
            f"Tool '{tool_name}' not allowed in state '{self._state.current}'. "
            f"Allowed: {state_config.allowed_tools}"
        )

    def evaluate_transition(self, tool_name: str, tool_input: dict) -> str | None:
        """Check if a tool call should trigger a state transition.

        Returns the target state name if a transition should fire, None otherwise.
        """
        for t in self._config.transitions:
            if not self._transition_matches_source(t):
                continue
            if t.trigger == "manual":
                continue
            if t.trigger != tool_name:
                continue
            if self._guards_pass(t, tool_input):
                return t.to_state
        return None

    def transition_to(self, state_name: str) -> FSMState:
        """Execute a state transition."""
        if state_name not in self._config.states:
            raise ValueError(f"Unknown state: '{state_name}'")

        self._state = FSMState(
            current=state_name,
            previous=self._state.current,
            entered_at=time.time(),
            transition_count=self._state.transition_count + 1,
        )
        self._persist(self._state)
        return self._state

    def get_available_transitions(self) -> list[dict]:
        """List transitions available from the current state."""
        result = []
        for t in self._config.transitions:
            if self._transition_matches_source(t):
                result.append({
                    "to": t.to_state,
                    "trigger": t.trigger,
                    "guards": [{"field": g.field, "pattern": g.pattern} for g in t.guards],
                })
        return result

    def reset(self) -> FSMState:
        """Reset to the initial state."""
        self._state = self._init_state()
        return self._state

    def _transition_matches_source(self, t: Transition) -> bool:
        return t.from_state == "*" or t.from_state == self._state.current

    def _guards_pass(self, t: Transition, tool_input: dict) -> bool:
        for guard in t.guards:
            value = tool_input.get(guard.field, "")
            if not isinstance(value, str):
                value = str(value)
            if not re.search(guard.pattern, value):
                return False
        return True
