use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sentinel::{config::load_config, crypto::generate_keypair, server::create_app};
use serde_json::{Value, json};
use std::{fs, path::PathBuf};
use tempfile::TempDir;
use tower::ServiceExt;

fn write_config(dir: &TempDir) -> PathBuf {
    let data_dir = dir.path().join("data").to_string_lossy().replace('\\', "/");
    let path = dir.path().join("sentinel.yaml");
    fs::write(
        &path,
        format!(
            r#"
server:
  host: "127.0.0.1"
  port: 9800
  data_dir: "{data_dir}"
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
    - {{ from: "idle", to: "planning", trigger: "manual" }}
    - {{ from: "idle", to: "developing", trigger: "manual" }}
    - {{ from: "planning", to: "developing", trigger: "manual" }}
    - from: "developing"
      to: "testing"
      trigger: "bash"
      guards:
        - {{ field: "command", pattern: "^(pnpm|npm)\\s+test" }}
    - {{ from: "testing", to: "developing", trigger: "manual" }}
    - {{ from: "*", to: "idle", trigger: "manual" }}
"#
        ),
    )
    .unwrap();
    path
}

fn app() -> (TempDir, axum::Router) {
    let dir = TempDir::new().unwrap();
    let config_path = write_config(&dir);
    let data_dir = dir.path().join("data");
    fs::create_dir_all(&data_dir).unwrap();
    generate_keypair(&data_dir.join("keys")).unwrap();
    let config = load_config(&config_path).unwrap();
    let app = create_app(config).unwrap();
    (dir, app)
}

async fn get_json(app: axum::Router, path: &str) -> (StatusCode, Value) {
    let response = app
        .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

async fn post_json(app: axum::Router, path: &str, body: Value) -> (StatusCode, Value) {
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, serde_json::from_slice(&bytes).unwrap())
}

#[tokio::test]
async fn health() {
    let (_dir, app) = app();
    let (status, data) = get_json(app, "/health").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(data["status"], "ok");
    assert_eq!(data["chain_length"], 0);
    assert!(data["session"].is_null());
}

#[tokio::test]
async fn state() {
    let (_dir, app) = app();
    let (status, data) = get_json(app, "/state").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(data["current"], "idle");
    assert!(data.get("allowed_tools").is_some());
    assert!(data.get("available_transitions").is_some());
}

#[tokio::test]
async fn gate_allows_tool_and_creates_receipt() {
    let (_dir, app) = app();
    let (status, data) = post_json(
        app.clone(),
        "/gate",
        json!({ "tool_name": "read", "tool_input": { "file_path": "/test.py" } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(data["decision"], "allow");
    assert!(data["context"].as_str().unwrap().contains("[Sentinel]"));

    let (_, health) = get_json(app, "/health").await;
    assert_eq!(health["chain_length"], 1);
}

#[tokio::test]
async fn gate_denies_tool_not_in_state() {
    let (_dir, app) = app();
    post_json(
        app.clone(),
        "/transition",
        json!({ "to_state": "planning" }),
    )
    .await;

    let (status, data) = post_json(
        app,
        "/gate",
        json!({ "tool_name": "write", "tool_input": { "file_path": "/test.py" } }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(data["decision"], "deny");
}

#[tokio::test]
async fn gate_auto_transition() {
    let (_dir, app) = app();
    post_json(
        app.clone(),
        "/transition",
        json!({ "to_state": "developing" }),
    )
    .await;
    post_json(
        app.clone(),
        "/gate",
        json!({ "tool_name": "bash", "tool_input": { "command": "pnpm test" } }),
    )
    .await;

    let (_, state) = get_json(app, "/state").await;
    assert_eq!(state["current"], "testing");
}

#[tokio::test]
async fn receipt_endpoint() {
    let (_dir, app) = app();
    let (status, data) = post_json(
        app,
        "/receipt",
        json!({
            "tool_name": "read",
            "tool_input": { "file_path": "/test.py" },
            "tool_response": { "content": "hello world" }
        }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(data["context"].as_str().unwrap().contains("receipt="));
}

#[tokio::test]
async fn transition_endpoint() {
    let (_dir, app) = app();
    let (status, data) = post_json(
        app,
        "/transition",
        json!({ "to_state": "developing", "reason": "starting work" }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(data["previous"], "idle");
    assert_eq!(data["current"], "developing");
}

#[tokio::test]
async fn transition_to_invalid_state() {
    let (_dir, app) = app();
    let (status, _) = post_json(app, "/transition", json!({ "to_state": "nonexistent" })).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn session_starts_separate_receipt_log() {
    let (_dir, app) = app();
    let (status, first) = post_json(
        app.clone(),
        "/session",
        json!({ "session_file": "/tmp/one.jsonl" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(first["chain_length"], 0);

    post_json(
        app.clone(),
        "/gate",
        json!({ "tool_name": "read", "tool_input": { "file_path": "/test.py" }}),
    )
    .await;
    let (_, health) = get_json(app.clone(), "/health").await;
    assert_eq!(health["chain_length"], 1);

    let (status, second) = post_json(
        app.clone(),
        "/session",
        json!({ "session_file": "/tmp/two.jsonl" }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(second["chain_length"], 0);
    assert_ne!(second["session"]["id"], first["session"]["id"]);

    let (_, health) = get_json(app, "/health").await;
    assert_eq!(health["chain_length"], 0);
}

#[tokio::test]
async fn session_resume_existing_receipt_log() {
    let (_dir, app) = app();
    post_json(
        app.clone(),
        "/session",
        json!({ "session_file": "/tmp/one.jsonl" }),
    )
    .await;
    post_json(
        app.clone(),
        "/gate",
        json!({ "tool_name": "read", "tool_input": { "file_path": "/test.py" }}),
    )
    .await;

    let (status, data) =
        post_json(app, "/session", json!({ "session_file": "/tmp/one.jsonl" })).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(data["chain_length"], 1);
}

#[tokio::test]
async fn session_end_clears_active_session() {
    let (_dir, app) = app();
    post_json(
        app.clone(),
        "/session",
        json!({ "session_file": "/tmp/one.jsonl" }),
    )
    .await;
    let (status, data) = post_json(
        app.clone(),
        "/session/end",
        json!({ "session_file": "/tmp/one.jsonl", "reason": "quit" }),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(data["ended"], true);
    assert!(
        data["session"]["ended_at"].as_f64().unwrap()
            >= data["session"]["started_at"].as_f64().unwrap()
    );

    let (_, health) = get_json(app, "/health").await;
    assert!(health["session"].is_null());
    assert_eq!(health["chain_length"], 0);
}

#[tokio::test]
async fn session_end_mismatch() {
    let (_dir, app) = app();
    post_json(
        app.clone(),
        "/session",
        json!({ "session_file": "/tmp/one.jsonl" }),
    )
    .await;

    let (status, _) = post_json(
        app,
        "/session/end",
        json!({ "session_file": "/tmp/two.jsonl" }),
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn session_missing_key() {
    let (_dir, app) = app();
    let (status, _) = post_json(app, "/session", json!({})).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn transition_missing_to_state() {
    let (_dir, app) = app();
    let (status, _) = post_json(app, "/transition", json!({})).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn gate_invalid_json() {
    let (_dir, app) = app();
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/gate")
                .header("content-type", "application/json")
                .body(Body::from("not json"))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn full_flow() {
    let (_dir, app) = app();

    let (_, gate) = post_json(
        app.clone(),
        "/gate",
        json!({ "tool_name": "read", "tool_input": { "file_path": "/src/main.py" } }),
    )
    .await;
    assert_eq!(gate["decision"], "allow");

    let (status, _) = post_json(
        app.clone(),
        "/receipt",
        json!({
            "tool_name": "read",
            "tool_input": { "file_path": "/src/main.py" },
            "tool_response": { "content": "import os\n" }
        }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (_, health) = get_json(app, "/health").await;
    assert_eq!(health["chain_length"], 2);
}
