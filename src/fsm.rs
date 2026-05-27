use crate::config::{FsmConfig, GuardCondition, Transition};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{error::Error, fmt, fs, path::PathBuf, time::SystemTime};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FsmState {
    pub current: String,
    pub previous: Option<String>,
    pub entered_at: f64,
    pub transition_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableGuard {
    pub field: String,
    pub pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AvailableTransition {
    pub to: String,
    pub trigger: String,
    pub guards: Vec<AvailableGuard>,
}

#[derive(Debug)]
pub struct FsmError(String);

impl FsmError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for FsmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for FsmError {}

pub struct SentinelFsm {
    config: FsmConfig,
    state_path: PathBuf,
    state: FsmState,
}

impl SentinelFsm {
    pub fn new(config: FsmConfig, state_path: PathBuf) -> Result<Self, FsmError> {
        let state = load_or_init(&config, &state_path)?;
        Ok(Self {
            config,
            state_path,
            state,
        })
    }

    pub fn get_state(&self) -> &FsmState {
        &self.state
    }

    pub fn is_tool_allowed(&self, tool_name: &str) -> (bool, String) {
        let Some(state_config) = self.config.states.get(&self.state.current) else {
            return (
                false,
                format!("Current state '{}' is not configured", self.state.current),
            );
        };

        for pattern in &state_config.allowed_tools {
            if regex_full_match(pattern, tool_name) {
                return (
                    true,
                    format!(
                        "Tool '{tool_name}' allowed in state '{}'",
                        self.state.current
                    ),
                );
            }
        }

        (
            false,
            format!(
                "Tool '{tool_name}' not allowed in state '{}'. Allowed: {:?}",
                self.state.current, state_config.allowed_tools
            ),
        )
    }

    pub fn evaluate_transition(&self, tool_name: &str, tool_input: &Value) -> Option<String> {
        self.config
            .transitions
            .iter()
            .find(|transition| {
                self.transition_matches_source(transition)
                    && transition.trigger != "manual"
                    && transition.trigger == tool_name
                    && guards_pass(transition, tool_input)
            })
            .map(|transition| transition.to_state.clone())
    }

    pub fn transition_to(&mut self, state_name: &str) -> Result<FsmState, FsmError> {
        if !self.config.states.contains_key(state_name) {
            return Err(FsmError::new(format!("Unknown state: '{state_name}'")));
        }

        self.state = FsmState {
            current: state_name.to_string(),
            previous: Some(self.state.current.clone()),
            entered_at: now_seconds(),
            transition_count: self.state.transition_count + 1,
        };
        persist(&self.state, &self.state_path)?;
        Ok(self.state.clone())
    }

    pub fn get_available_transitions(&self) -> Vec<AvailableTransition> {
        self.config
            .transitions
            .iter()
            .filter(|transition| self.transition_matches_source(transition))
            .map(|transition| AvailableTransition {
                to: transition.to_state.clone(),
                trigger: transition.trigger.clone(),
                guards: transition
                    .guards
                    .iter()
                    .map(|guard| AvailableGuard {
                        field: guard.field.clone(),
                        pattern: guard.pattern.clone(),
                    })
                    .collect(),
            })
            .collect()
    }

    pub fn reset(&mut self) -> Result<FsmState, FsmError> {
        self.state = init_state(&self.config, &self.state_path)?;
        Ok(self.state.clone())
    }

    fn transition_matches_source(&self, transition: &Transition) -> bool {
        transition.from_state == "*" || transition.from_state == self.state.current
    }
}

fn load_or_init(config: &FsmConfig, state_path: &PathBuf) -> Result<FsmState, FsmError> {
    if state_path.exists() {
        let text = fs::read_to_string(state_path)
            .map_err(|error| FsmError::new(format!("Failed to read state: {error}")))?;
        if let Ok(state) = serde_json::from_str::<FsmState>(&text)
            && config.states.contains_key(&state.current)
        {
            return Ok(state);
        }
    }

    init_state(config, state_path)
}

fn init_state(config: &FsmConfig, state_path: &PathBuf) -> Result<FsmState, FsmError> {
    let state = FsmState {
        current: config.initial_state.clone(),
        previous: None,
        entered_at: now_seconds(),
        transition_count: 0,
    };
    persist(&state, state_path)?;
    Ok(state)
}

fn persist(state: &FsmState, state_path: &PathBuf) -> Result<(), FsmError> {
    if let Some(parent) = state_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| FsmError::new(format!("Failed to create state dir: {error}")))?;
    }

    let tmp_path = state_path.with_extension("tmp");
    let rendered = serde_json::to_string_pretty(state)
        .map_err(|error| FsmError::new(format!("Failed to serialize state: {error}")))?;
    fs::write(&tmp_path, rendered)
        .map_err(|error| FsmError::new(format!("Failed to write state: {error}")))?;
    fs::rename(&tmp_path, state_path)
        .map_err(|error| FsmError::new(format!("Failed to replace state: {error}")))?;
    Ok(())
}

fn regex_full_match(pattern: &str, value: &str) -> bool {
    Regex::new(pattern)
        .ok()
        .and_then(|regex| regex.find(value))
        .is_some_and(|matched| matched.start() == 0 && matched.end() == value.len())
}

fn guards_pass(transition: &Transition, tool_input: &Value) -> bool {
    transition
        .guards
        .iter()
        .all(|guard| guard_matches(guard, tool_input))
}

fn guard_matches(guard: &GuardCondition, tool_input: &Value) -> bool {
    let value = tool_input
        .get(&guard.field)
        .map(value_to_string)
        .unwrap_or_default();

    Regex::new(&guard.pattern)
        .map(|regex| regex.is_match(&value))
        .unwrap_or(false)
}

fn value_to_string(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}
