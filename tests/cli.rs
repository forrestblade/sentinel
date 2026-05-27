use assert_cmd::Command;
use predicates::prelude::*;
use sentinel::{
    config::load_config, crypto::generate_keypair, fsm::SentinelFsm, receipt::ReceiptChain,
};
use serde_json::json;
use std::{
    fs,
    io::{Read, Write},
};
use tempfile::TempDir;

fn bin() -> Command {
    Command::cargo_bin("sentinel").unwrap()
}

fn write_config(dir: &TempDir) -> std::path::PathBuf {
    write_config_with_port(dir, 9800)
}

fn write_config_with_port(dir: &TempDir, port: u16) -> std::path::PathBuf {
    let data_dir = dir.path().join("data").to_string_lossy().replace('\\', "/");
    let path = dir.path().join("sentinel.yaml");
    fs::write(
        &path,
        format!(
            r#"
server:
  host: "127.0.0.1"
  port: {port}
  data_dir: "{data_dir}"
fsm:
  initial_state: "idle"
  states:
    idle:
      description: "No active workflow"
      allowed_tools: [".*"]
    developing:
      description: "Full tool access"
      allowed_tools: [".*"]
  transitions:
    - {{ from: "idle", to: "developing", trigger: "manual" }}
    - {{ from: "*", to: "idle", trigger: "manual" }}
"#
        ),
    )
    .unwrap();
    path
}

#[test]
fn init_creates_config_keys_and_data_dir() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("sentinel.yaml");
    let data_dir = dir.path().join("data");

    bin()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "init",
            "--data-dir",
            data_dir.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Sentinel initialized"));

    assert!(config_path.exists());
    assert!(data_dir.join("keys/sentinel.key").exists());
    assert!(data_dir.join("keys/sentinel.pub").exists());
}

#[test]
fn status_not_initialized_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("missing.yaml");

    bin()
        .args(["--config", config_path.to_str().unwrap(), "status"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Not initialized"));
}

#[test]
fn status_reports_state_and_chain_length() {
    let dir = TempDir::new().unwrap();
    let config_path = write_config(&dir);
    let config = load_config(&config_path).unwrap();
    let data_dir = std::path::PathBuf::from(&config.server.data_dir);
    fs::create_dir_all(data_dir.join("keys")).unwrap();
    let (private_key, public_key) = generate_keypair(&data_dir.join("keys")).unwrap();
    SentinelFsm::new(config.fsm, data_dir.join("state.json")).unwrap();
    let mut chain =
        ReceiptChain::new(data_dir.join("receipts.jsonl"), private_key, public_key).unwrap();
    chain
        .append("read", &json!({"a": 1}), None, "idle", "gate_allow")
        .unwrap();

    bin()
        .args(["--config", config_path.to_str().unwrap(), "status"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Server: not running"))
        .stdout(predicate::str::contains("State:  idle"))
        .stdout(predicate::str::contains("Chain:  1 receipts"));
}

#[test]
fn verify_reports_valid_chain() {
    let dir = TempDir::new().unwrap();
    let config_path = write_config(&dir);
    let config = load_config(&config_path).unwrap();
    let data_dir = std::path::PathBuf::from(&config.server.data_dir);
    fs::create_dir_all(data_dir.join("keys")).unwrap();
    let (private_key, public_key) = generate_keypair(&data_dir.join("keys")).unwrap();
    let mut chain =
        ReceiptChain::new(data_dir.join("receipts.jsonl"), private_key, public_key).unwrap();
    chain
        .append("read", &json!({"a": 1}), None, "idle", "gate_allow")
        .unwrap();

    bin()
        .args(["--config", config_path.to_str().unwrap(), "verify"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Chain valid: 1 receipts verified"));
}

#[test]
fn state_reports_current_state_details() {
    let dir = TempDir::new().unwrap();
    let config_path = write_config(&dir);
    let config = load_config(&config_path).unwrap();
    let data_dir = std::path::PathBuf::from(&config.server.data_dir);
    SentinelFsm::new(config.fsm, data_dir.join("state.json")).unwrap();

    bin()
        .args(["--config", config_path.to_str().unwrap(), "state"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Current state: idle"))
        .stdout(predicate::str::contains("Available transitions"));
}

#[test]
fn audit_reports_receipts_most_recent_first() {
    let dir = TempDir::new().unwrap();
    let config_path = write_config(&dir);
    let config = load_config(&config_path).unwrap();
    let data_dir = std::path::PathBuf::from(&config.server.data_dir);
    fs::create_dir_all(data_dir.join("keys")).unwrap();
    let (private_key, public_key) = generate_keypair(&data_dir.join("keys")).unwrap();
    let mut chain =
        ReceiptChain::new(data_dir.join("receipts.jsonl"), private_key, public_key).unwrap();
    chain
        .append("read", &json!({"a": 1}), None, "idle", "gate_allow")
        .unwrap();
    chain
        .append("write", &json!({"b": 2}), None, "developing", "gate_deny")
        .unwrap();

    bin()
        .args(["--config", config_path.to_str().unwrap(), "audit"])
        .assert()
        .success()
        .stdout(predicate::str::contains("[0001]"))
        .stdout(predicate::str::contains("gate_deny"))
        .stdout(predicate::str::contains("write"));
}

#[test]
fn audit_filters_by_tool_and_limit() {
    let dir = TempDir::new().unwrap();
    let config_path = write_config(&dir);
    let config = load_config(&config_path).unwrap();
    let data_dir = std::path::PathBuf::from(&config.server.data_dir);
    fs::create_dir_all(data_dir.join("keys")).unwrap();
    let (private_key, public_key) = generate_keypair(&data_dir.join("keys")).unwrap();
    let mut chain =
        ReceiptChain::new(data_dir.join("receipts.jsonl"), private_key, public_key).unwrap();
    chain
        .append("read", &json!({"a": 1}), None, "idle", "gate_allow")
        .unwrap();
    chain
        .append("write", &json!({"b": 2}), None, "developing", "gate_deny")
        .unwrap();
    chain
        .append("read", &json!({"c": 3}), None, "idle", "gate_allow")
        .unwrap();

    bin()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "audit",
            "--tool",
            "read",
            "--limit",
            "1",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("[0002]"))
        .stdout(predicate::str::contains("read"))
        .stdout(predicate::str::contains("write").not());
}

#[test]
fn audit_no_receipts_message() {
    let dir = TempDir::new().unwrap();
    let config_path = write_config(&dir);

    bin()
        .args(["--config", config_path.to_str().unwrap(), "audit"])
        .assert()
        .success()
        .stdout(predicate::str::contains("No receipts."));
}

#[test]
fn start_missing_config_exits_nonzero() {
    let dir = TempDir::new().unwrap();
    let config_path = dir.path().join("missing.yaml");

    bin()
        .args(["--config", config_path.to_str().unwrap(), "start"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Config not found"));
}

#[test]
fn start_serves_health_endpoint() {
    let dir = TempDir::new().unwrap();
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = std_listener.local_addr().unwrap().port();
    drop(std_listener);

    let config_path = write_config_with_port(&dir, port);
    let config = load_config(&config_path).unwrap();
    let data_dir = std::path::PathBuf::from(&config.server.data_dir);
    fs::create_dir_all(&data_dir).unwrap();
    generate_keypair(&data_dir.join("keys")).unwrap();

    let exe = assert_cmd::cargo::cargo_bin("sentinel");
    let mut child = std::process::Command::new(exe)
        .args(["--config", config_path.to_str().unwrap(), "start"])
        .spawn()
        .unwrap();

    let mut response = String::new();
    for _ in 0..50 {
        if let Ok(mut stream) = std::net::TcpStream::connect(("127.0.0.1", port)) {
            stream
                .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            stream
                .write_all(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .unwrap();
            let _ = stream.read_to_string(&mut response);
            if response.contains("\"status\":\"ok\"") {
                break;
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }

    let _ = child.kill();
    let _ = child.wait();
    assert!(response.contains("\"status\":\"ok\""), "{response}");
}

#[test]
fn stop_without_pid_reports_not_running() {
    let dir = TempDir::new().unwrap();
    let config_path = write_config(&dir);

    bin()
        .args(["--config", config_path.to_str().unwrap(), "stop"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Sentinel is not running"));
}

#[test]
fn transition_posts_to_running_server() {
    let dir = TempDir::new().unwrap();
    let std_listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = std_listener.local_addr().unwrap().port();
    std_listener.set_nonblocking(true).unwrap();

    let config_path = write_config_with_port(&dir, port);
    let config = load_config(&config_path).unwrap();
    let data_dir = std::path::PathBuf::from(&config.server.data_dir);
    fs::create_dir_all(&data_dir).unwrap();
    generate_keypair(&data_dir.join("keys")).unwrap();
    let app = sentinel::server::create_app(config).unwrap();

    std::thread::spawn(move || {
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async move {
            let listener = tokio::net::TcpListener::from_std(std_listener).unwrap();
            axum::serve(listener, app).await.unwrap();
        });
    });
    std::thread::sleep(std::time::Duration::from_millis(100));

    bin()
        .args([
            "--config",
            config_path.to_str().unwrap(),
            "transition",
            "developing",
            "--reason",
            "starting work",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("idle -> developing"));
}
