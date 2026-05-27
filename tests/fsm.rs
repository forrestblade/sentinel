use sentinel::{
    config::{FsmConfig, load_config},
    fsm::{FsmState, SentinelFsm},
};
use serde_json::json;
use std::{fs, path::PathBuf};
use tempfile::TempDir;

fn write_sample_config() -> (TempDir, PathBuf) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("sentinel.yaml");
    fs::write(
        &path,
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
"#,
    )
    .unwrap();
    (dir, path)
}

fn sample_fsm_config() -> (TempDir, FsmConfig) {
    let (dir, path) = write_sample_config();
    let config = load_config(&path).unwrap();
    (dir, config.fsm)
}

fn state_path(dir: &TempDir) -> PathBuf {
    dir.path().join("data").join("state.json")
}

#[test]
fn initial_state() {
    let (dir, config) = sample_fsm_config();
    let fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();

    assert_eq!(fsm.get_state().current, "idle");
}

#[test]
fn state_persists_to_disk() {
    let (dir, config) = sample_fsm_config();
    let path = state_path(&dir);
    let _fsm = SentinelFsm::new(config, path.clone()).unwrap();

    assert!(path.exists());
    let data: serde_json::Value = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    assert_eq!(data["current"], "idle");
}

#[test]
fn state_reloads_from_disk() {
    let (dir, config) = sample_fsm_config();
    let path = state_path(&dir);
    let mut fsm1 = SentinelFsm::new(config.clone(), path.clone()).unwrap();
    fsm1.transition_to("developing").unwrap();

    let fsm2 = SentinelFsm::new(config, path).unwrap();
    assert_eq!(fsm2.get_state().current, "developing");
}

#[test]
fn tool_allowed_wildcard() {
    let (dir, config) = sample_fsm_config();
    let fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();

    assert!(fsm.is_tool_allowed("bash").0);
    assert!(fsm.is_tool_allowed("write").0);
}

#[test]
fn tool_denied_in_restricted_state() {
    let (dir, config) = sample_fsm_config();
    let mut fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();
    fsm.transition_to("planning").unwrap();

    let (allowed, reason) = fsm.is_tool_allowed("write");
    assert!(!allowed);
    assert!(reason.contains("write"));
}

#[test]
fn tool_allowed_in_restricted_state() {
    let (dir, config) = sample_fsm_config();
    let mut fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();
    fsm.transition_to("planning").unwrap();

    assert!(fsm.is_tool_allowed("read").0);
}

#[test]
fn parallel_tool_pattern_matching() {
    let (dir, config) = sample_fsm_config();
    let mut fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();
    fsm.transition_to("planning").unwrap();

    assert!(fsm.is_tool_allowed("multi_tool_use.parallel").0);
}

#[test]
fn transition_to_valid_state() {
    let (dir, config) = sample_fsm_config();
    let mut fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();

    let state = fsm.transition_to("developing").unwrap();
    assert_eq!(state.current, "developing");
    assert_eq!(state.previous.as_deref(), Some("idle"));
    assert_eq!(state.transition_count, 1);
}

#[test]
fn transition_to_invalid_state() {
    let (dir, config) = sample_fsm_config();
    let mut fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();

    let err = fsm.transition_to("nonexistent").unwrap_err();
    assert!(err.to_string().contains("nonexistent"));
}

#[test]
fn auto_transition_with_guard() {
    let (dir, config) = sample_fsm_config();
    let mut fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();
    fsm.transition_to("developing").unwrap();

    assert_eq!(
        fsm.evaluate_transition("bash", &json!({ "command": "pnpm test" })),
        Some("testing".to_string())
    );
}

#[test]
fn auto_transition_guard_no_match() {
    let (dir, config) = sample_fsm_config();
    let mut fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();
    fsm.transition_to("developing").unwrap();

    assert_eq!(
        fsm.evaluate_transition("bash", &json!({ "command": "ls -la" })),
        None
    );
}

#[test]
fn auto_transition_wrong_tool() {
    let (dir, config) = sample_fsm_config();
    let mut fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();
    fsm.transition_to("developing").unwrap();

    assert_eq!(
        fsm.evaluate_transition("read", &json!({ "file_path": "/test" })),
        None
    );
}

#[test]
fn manual_transitions_not_auto_triggered() {
    let (dir, config) = sample_fsm_config();
    let fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();

    assert_eq!(fsm.evaluate_transition("read", &json!({})), None);
}

#[test]
fn get_available_transitions() {
    let (dir, config) = sample_fsm_config();
    let fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();
    let transitions = fsm.get_available_transitions();
    let targets = transitions
        .iter()
        .map(|transition| transition.to.as_str())
        .collect::<std::collections::HashSet<_>>();

    assert!(targets.contains("planning"));
    assert!(targets.contains("developing"));
    assert!(targets.contains("idle"));
}

#[test]
fn reset() {
    let (dir, config) = sample_fsm_config();
    let mut fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();
    fsm.transition_to("developing").unwrap();

    let state = fsm.reset().unwrap();
    assert_eq!(state.current, "idle");
    assert_eq!(state.transition_count, 0);
}

#[test]
fn transition_count_increments() {
    let (dir, config) = sample_fsm_config();
    let mut fsm = SentinelFsm::new(config, state_path(&dir)).unwrap();
    fsm.transition_to("developing").unwrap();
    fsm.transition_to("testing").unwrap();

    assert_eq!(fsm.get_state().transition_count, 2);
}

#[test]
fn fsm_state_serialization() {
    let state = FsmState {
        current: "testing".to_string(),
        previous: Some("developing".to_string()),
        entered_at: 1000.0,
        transition_count: 5,
    };

    let rendered = serde_json::to_string(&state).unwrap();
    let restored: FsmState = serde_json::from_str(&rendered).unwrap();

    assert_eq!(restored.current, state.current);
    assert_eq!(restored.previous, state.previous);
    assert_eq!(restored.transition_count, state.transition_count);
}
