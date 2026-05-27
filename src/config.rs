use regex::Regex;
use serde::Deserialize;
use std::{collections::HashMap, error::Error, fmt, fs, path::Path};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardCondition {
    pub field: String,
    pub pattern: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    pub from_state: String,
    pub to_state: String,
    pub trigger: String,
    pub guards: Vec<GuardCondition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateConfig {
    pub name: String,
    pub description: String,
    pub allowed_tools: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FsmConfig {
    pub initial_state: String,
    pub states: HashMap<String, StateConfig>,
    pub transitions: Vec<Transition>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub data_dir: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentinelConfig {
    pub fsm: FsmConfig,
    pub server: ServerConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(String);

impl ConfigError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ConfigError {}

#[derive(Debug, Deserialize)]
struct RawConfig {
    server: Option<RawServerConfig>,
    fsm: Option<RawFsmConfig>,
}

#[derive(Debug, Deserialize)]
struct RawServerConfig {
    host: Option<String>,
    port: Option<u16>,
    data_dir: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RawFsmConfig {
    initial_state: Option<String>,
    states: Option<HashMap<String, RawStateConfig>>,
    transitions: Option<Vec<RawTransition>>,
}

#[derive(Debug, Deserialize)]
struct RawStateConfig {
    description: Option<String>,
    allowed_tools: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct RawTransition {
    #[serde(rename = "from")]
    from_state: Option<String>,
    #[serde(rename = "to")]
    to_state: Option<String>,
    trigger: Option<String>,
    guards: Option<Vec<RawGuardCondition>>,
}

#[derive(Debug, Deserialize)]
struct RawGuardCondition {
    field: Option<String>,
    pattern: Option<String>,
}

pub fn load_config(config_path: &Path) -> Result<SentinelConfig, ConfigError> {
    let text = fs::read_to_string(config_path)
        .map_err(|error| ConfigError::new(format!("Failed to read config: {error}")))?;
    let raw: RawConfig = serde_yaml::from_str(&text)
        .map_err(|error| ConfigError::new(format!("Config must be a YAML mapping: {error}")))?;

    let server_raw = raw.server.unwrap_or(RawServerConfig {
        host: None,
        port: None,
        data_dir: None,
    });
    let server = ServerConfig {
        host: server_raw.host.unwrap_or_else(|| "127.0.0.1".to_string()),
        port: server_raw.port.unwrap_or(9800),
        data_dir: expand_home(
            &server_raw
                .data_dir
                .unwrap_or_else(|| "~/.config/sentinel/data".to_string()),
        ),
    };

    let fsm_raw = raw
        .fsm
        .ok_or_else(|| ConfigError::new("Config must have an 'fsm' section"))?;

    let initial_state = fsm_raw
        .initial_state
        .filter(|state| !state.is_empty())
        .ok_or_else(|| ConfigError::new("FSM must have an 'initial_state'"))?;

    let states_raw = fsm_raw
        .states
        .filter(|states| !states.is_empty())
        .ok_or_else(|| ConfigError::new("FSM must have at least one state"))?;

    let mut states = HashMap::new();
    for (name, state_raw) in states_raw {
        let allowed_tools = state_raw.allowed_tools.unwrap_or_default();
        for pattern in &allowed_tools {
            Regex::new(pattern).map_err(|error| {
                ConfigError::new(format!(
                    "Invalid regex in state '{name}' allowed_tools: {error}"
                ))
            })?;
        }

        states.insert(
            name.clone(),
            StateConfig {
                name,
                description: state_raw.description.unwrap_or_default(),
                allowed_tools,
            },
        );
    }

    if !states.contains_key(&initial_state) {
        return Err(ConfigError::new(format!(
            "initial_state '{initial_state}' is not a defined state"
        )));
    }

    let mut transitions = Vec::new();
    for transition_raw in fsm_raw.transitions.unwrap_or_default() {
        let from_state = transition_raw
            .from_state
            .filter(|state| !state.is_empty())
            .ok_or_else(|| ConfigError::new("Transition must have 'from' and 'to'"))?;
        let to_state = transition_raw
            .to_state
            .filter(|state| !state.is_empty())
            .ok_or_else(|| ConfigError::new("Transition must have 'from' and 'to'"))?;
        let trigger = transition_raw
            .trigger
            .unwrap_or_else(|| "manual".to_string());

        if from_state != "*" && !states.contains_key(&from_state) {
            return Err(ConfigError::new(format!(
                "Transition from unknown state '{from_state}'"
            )));
        }
        if !states.contains_key(&to_state) {
            return Err(ConfigError::new(format!(
                "Transition to unknown state '{to_state}'"
            )));
        }

        let mut guards = Vec::new();
        for guard_raw in transition_raw.guards.unwrap_or_default() {
            let field = guard_raw
                .field
                .ok_or_else(|| ConfigError::new("Guard must have 'field' and 'pattern'"))?;
            let pattern = guard_raw
                .pattern
                .ok_or_else(|| ConfigError::new("Guard must have 'field' and 'pattern'"))?;
            Regex::new(&pattern).map_err(|error| {
                ConfigError::new(format!("Invalid regex in guard pattern: {error}"))
            })?;
            guards.push(GuardCondition { field, pattern });
        }

        transitions.push(Transition {
            from_state,
            to_state,
            trigger,
            guards,
        });
    }

    Ok(SentinelConfig {
        fsm: FsmConfig {
            initial_state,
            states,
            transitions,
        },
        server,
    })
}

fn expand_home(path: &str) -> String {
    if path == "~" || path.starts_with("~/") {
        if let Some(home) = std::env::var_os("USERPROFILE").or_else(|| std::env::var_os("HOME")) {
            let home = home.to_string_lossy().replace('\\', "/");
            if path == "~" {
                home
            } else {
                format!("{home}/{}", &path[2..])
            }
        } else {
            path.to_string()
        }
    } else {
        path.to_string()
    }
}
