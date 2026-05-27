use sentinel::config::{ConfigError, load_config};
use std::{fs, path::PathBuf};
use tempfile::TempDir;

fn write_config(yaml: &str) -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("sentinel.yaml");
    fs::write(&path, yaml).unwrap();
    (dir, path)
}

fn sample_config_yaml() -> &'static str {
    r#"
server:
  host: "127.0.0.1"
  port: 9800
fsm:
  initial_state: "idle"
  states:
    idle:
      description: "No active workflow"
      allowed_tools: [".*"]
    planning:
      description: "Read-only exploration"
      allowed_tools: ["read", "bash", "multi_tool_use\\.parallel"]
    developing:
      description: "Full tool access"
      allowed_tools: [".*"]
    testing:
      description: "Test execution only"
      allowed_tools: ["read", "bash", "multi_tool_use\\.parallel"]
  transitions:
    - { from: "idle", to: "planning", trigger: "manual" }
    - { from: "idle", to: "developing", trigger: "manual" }
    - { from: "planning", to: "developing", trigger: "manual" }
    - from: "developing"
      to: "testing"
      trigger: "bash"
      guards:
        - { field: "command", pattern: "^(pnpm|npm)\\s+test" }
    - { from: "testing", to: "developing", trigger: "manual" }
    - { from: "*", to: "idle", trigger: "manual" }
"#
}

fn assert_config_error_contains(yaml: &str, needle: &str) {
    let (_dir, path) = write_config(yaml);
    let err = load_config(&path).expect_err("config should fail validation");
    assert!(
        err.to_string().contains(needle),
        "expected error {err:?} to contain {needle:?}"
    );
}

#[test]
fn valid_config_loads() {
    let (_dir, path) = write_config(sample_config_yaml());
    let config = load_config(&path).unwrap();

    assert_eq!(config.fsm.initial_state, "idle");
    assert!(config.fsm.states.contains_key("idle"));
    assert!(config.fsm.states.contains_key("planning"));
    assert_eq!(config.fsm.transitions.len(), 6);
}

#[test]
fn state_has_allowed_tools() {
    let (_dir, path) = write_config(sample_config_yaml());
    let config = load_config(&path).unwrap();
    let planning = config.fsm.states.get("planning").unwrap();

    assert!(planning.allowed_tools.contains(&"read".to_string()));
    assert!(planning.allowed_tools.contains(&"bash".to_string()));
}

#[test]
fn transition_with_guards() {
    let (_dir, path) = write_config(sample_config_yaml());
    let config = load_config(&path).unwrap();
    let guarded = config
        .fsm
        .transitions
        .iter()
        .filter(|transition| !transition.guards.is_empty())
        .collect::<Vec<_>>();

    assert_eq!(guarded.len(), 1);
    assert_eq!(guarded[0].from_state, "developing");
    assert_eq!(guarded[0].to_state, "testing");
    assert_eq!(guarded[0].guards[0].field, "command");
}

#[test]
fn server_defaults() {
    let (_dir, path) = write_config(
        r#"
fsm:
  initial_state: "start"
  states:
    start:
      description: "begin"
      allowed_tools: [".*"]
"#,
    );
    let config = load_config(&path).unwrap();

    assert_eq!(config.server.host, "127.0.0.1");
    assert_eq!(config.server.port, 9800);
}

#[test]
fn missing_fsm_section() {
    assert_config_error_contains("server: {}\n", "fsm");
}

#[test]
fn missing_initial_state() {
    assert_config_error_contains(
        r#"
fsm:
  states:
    a:
      description: "x"
      allowed_tools: []
"#,
        "initial_state",
    );
}

#[test]
fn initial_state_not_defined() {
    assert_config_error_contains(
        r#"
fsm:
  initial_state: "nonexistent"
  states:
    a:
      description: "x"
      allowed_tools: []
"#,
        "nonexistent",
    );
}

#[test]
fn transition_from_unknown_state() {
    assert_config_error_contains(
        r#"
fsm:
  initial_state: "a"
  states:
    a:
      description: "x"
      allowed_tools: []
  transitions:
    - { from: "unknown", to: "a", trigger: "manual" }
"#,
        "unknown",
    );
}

#[test]
fn transition_to_unknown_state() {
    assert_config_error_contains(
        r#"
fsm:
  initial_state: "a"
  states:
    a:
      description: "x"
      allowed_tools: []
  transitions:
    - { from: "a", to: "nowhere", trigger: "manual" }
"#,
        "nowhere",
    );
}

#[test]
fn wildcard_from_state_allowed() {
    let (_dir, path) = write_config(
        r#"
fsm:
  initial_state: "a"
  states:
    a:
      description: "x"
      allowed_tools: []
  transitions:
    - { from: "*", to: "a", trigger: "manual" }
"#,
    );
    let config = load_config(&path).unwrap();

    assert_eq!(config.fsm.transitions[0].from_state, "*");
}

#[test]
fn invalid_regex_in_allowed_tools() {
    assert_config_error_contains(
        r#"
fsm:
  initial_state: "a"
  states:
    a:
      description: "x"
      allowed_tools: ["[invalid"]
"#,
        "regex",
    );
}

#[test]
fn invalid_regex_in_guard() {
    assert_config_error_contains(
        r#"
fsm:
  initial_state: "a"
  states:
    a:
      description: "x"
      allowed_tools: []
    b:
      description: "y"
      allowed_tools: []
  transitions:
    - from: "a"
      to: "b"
      trigger: "bash"
      guards:
        - { field: "cmd", pattern: "[bad" }
"#,
        "regex",
    );
}

#[test]
fn config_error_is_public_error_type() {
    fn takes_config_error(_: ConfigError) {}

    let (_dir, path) = write_config("server: {}\n");
    takes_config_error(load_config(&path).unwrap_err());
}
