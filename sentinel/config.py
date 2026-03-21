"""Configuration loading and validation."""

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass(frozen=True)
class GuardCondition:
    field: str
    pattern: str

    def __post_init__(self) -> None:
        re.compile(self.pattern)


@dataclass(frozen=True)
class Transition:
    from_state: str
    to_state: str
    trigger: str
    guards: list[GuardCondition] = field(default_factory=list)


@dataclass(frozen=True)
class StateConfig:
    name: str
    description: str
    allowed_tools: list[str]

    def __post_init__(self) -> None:
        for pattern in self.allowed_tools:
            re.compile(pattern)


@dataclass(frozen=True)
class FSMConfig:
    initial_state: str
    states: dict[str, StateConfig]
    transitions: list[Transition]


@dataclass(frozen=True)
class ServerConfig:
    host: str = "127.0.0.1"
    port: int = 9800
    data_dir: Path = field(default_factory=lambda: Path.home() / ".config" / "sentinel" / "data")


@dataclass(frozen=True)
class SentinelConfig:
    fsm: FSMConfig
    server: ServerConfig


class ConfigError(Exception):
    pass


def load_config(config_path: Path) -> SentinelConfig:
    """Load and validate a sentinel YAML config file."""
    raw = yaml.safe_load(config_path.read_text())
    if not isinstance(raw, dict):
        raise ConfigError("Config must be a YAML mapping")

    server_raw = raw.get("server", {})
    server = ServerConfig(
        host=server_raw.get("host", "127.0.0.1"),
        port=server_raw.get("port", 9800),
        data_dir=Path(server_raw.get("data_dir", "~/.config/sentinel/data")).expanduser(),
    )

    fsm_raw = raw.get("fsm")
    if not fsm_raw:
        raise ConfigError("Config must have an 'fsm' section")

    initial_state = fsm_raw.get("initial_state")
    if not initial_state:
        raise ConfigError("FSM must have an 'initial_state'")

    states_raw = fsm_raw.get("states", {})
    if not states_raw:
        raise ConfigError("FSM must have at least one state")

    states: dict[str, StateConfig] = {}
    for name, state_data in states_raw.items():
        try:
            states[name] = StateConfig(
                name=name,
                description=state_data.get("description", ""),
                allowed_tools=state_data.get("allowed_tools", []),
            )
        except re.error as e:
            raise ConfigError(f"Invalid regex in state '{name}' allowed_tools: {e}") from e

    if initial_state not in states:
        raise ConfigError(f"initial_state '{initial_state}' is not a defined state")

    transitions_raw = fsm_raw.get("transitions", [])
    transitions: list[Transition] = []
    for t in transitions_raw:
        from_state = t.get("from")
        to_state = t.get("to")
        trigger = t.get("trigger", "manual")

        if not from_state or not to_state:
            raise ConfigError(f"Transition must have 'from' and 'to': {t}")

        if from_state != "*" and from_state not in states:
            raise ConfigError(f"Transition from unknown state '{from_state}'")
        if to_state not in states:
            raise ConfigError(f"Transition to unknown state '{to_state}'")

        guards = []
        for g in t.get("guards", []):
            try:
                guards.append(GuardCondition(field=g["field"], pattern=g["pattern"]))
            except KeyError as e:
                raise ConfigError(f"Guard must have 'field' and 'pattern': {g}") from e
            except re.error as e:
                raise ConfigError(f"Invalid regex in guard pattern: {e}") from e

        transitions.append(Transition(
            from_state=from_state,
            to_state=to_state,
            trigger=trigger,
            guards=guards,
        ))

    return SentinelConfig(
        fsm=FSMConfig(initial_state=initial_state, states=states, transitions=transitions),
        server=server,
    )
