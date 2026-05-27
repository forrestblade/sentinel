use crate::{
    config::load_config,
    crypto::{generate_keypair, load_private_key, load_public_key},
    receipt::ReceiptChain,
};
use clap::{Parser, Subcommand};
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    net::TcpStream,
    path::PathBuf,
};

const EXAMPLE_CONFIG: &str = r#"server:
  host: "127.0.0.1"
  port: 9800
  data_dir: "~/.config/sentinel/data"

fsm:
  initial_state: "idle"

  states:
    idle:
      description: "No active workflow"
      allowed_tools: [".*"]

    thinking:
      description: "Agent is thinking through the task"
      allowed_tools: ["read", "bash", "multi_tool_use\\.parallel"]

    planning:
      description: "Read-only planning and exploration"
      allowed_tools: ["read", "bash", "multi_tool_use\\.parallel"]

    reading:
      description: "Inspecting files or project state"
      allowed_tools: ["read", "bash", "multi_tool_use\\.parallel"]

    writing:
      description: "Editing files or making local changes"
      allowed_tools: [".*"]

    testing:
      description: "Running tests or test-like checks"
      allowed_tools: ["read", "bash", "multi_tool_use\\.parallel"]

    committing:
      description: "Creating commits"
      allowed_tools: ["read", "bash", "multi_tool_use\\.parallel"]

    pushing:
      description: "Pushing commits to a remote"
      allowed_tools: ["read", "bash", "multi_tool_use\\.parallel"]

    developing:
      description: "General full-access development"
      allowed_tools: [".*"]

    reviewing:
      description: "Read-only review"
      allowed_tools: ["read", "bash", "multi_tool_use\\.parallel"]

  transitions:
    - { from: "*", to: thinking, trigger: manual }
    - { from: "*", to: planning, trigger: manual }
    - { from: "*", to: reading, trigger: manual }
    - { from: "*", to: writing, trigger: manual }
    - { from: "*", to: testing, trigger: manual }
    - { from: "*", to: committing, trigger: manual }
    - { from: "*", to: pushing, trigger: manual }
    - { from: "*", to: developing, trigger: manual }
    - { from: "*", to: reviewing, trigger: manual }
    - { from: "*", to: idle, trigger: manual }
"#;

#[derive(Debug, Parser)]
#[command(
    name = "sentinel",
    about = "Sentinel: State-based tool gating & cryptographic receipts for pi."
)]
pub struct Args {
    #[arg(long, default_value_os_t = default_config_path())]
    config: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Init {
        #[arg(long, default_value_os_t = default_data_dir())]
        data_dir: PathBuf,
    },
    Start {
        #[arg(long)]
        host: Option<String>,
        #[arg(long)]
        port: Option<u16>,
    },
    Stop,
    Status,
    State,
    Verify,
    Transition {
        state_name: String,
        #[arg(long, default_value = "")]
        reason: String,
    },
    Audit {
        #[arg(long = "tool")]
        tool_name: Option<String>,
        #[arg(long = "state")]
        state_filter: Option<String>,
        #[arg(long)]
        event: Option<String>,
        #[arg(long, short = 'n', default_value_t = 20)]
        limit: usize,
    },
}

pub fn run() -> i32 {
    match run_result(Args::parse()) {
        Ok(()) => 0,
        Err(error) => {
            eprintln!("{error}");
            1
        }
    }
}

fn run_result(args: Args) -> Result<(), String> {
    match args.command {
        Command::Init { data_dir } => init(args.config, data_dir),
        Command::Start { host, port } => start(args.config, host, port),
        Command::Stop => stop(args.config),
        Command::Status => status(args.config),
        Command::State => state(args.config),
        Command::Verify => verify(args.config),
        Command::Transition { state_name, reason } => transition(args.config, state_name, reason),
        Command::Audit {
            tool_name,
            state_filter,
            event,
            limit,
        } => audit(args.config, tool_name, state_filter, event, limit),
    }
}

fn init(config_path: PathBuf, data_dir: PathBuf) -> Result<(), String> {
    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)
            .map_err(|error| format!("Failed to create config dir: {error}"))?;
    }

    if config_path.exists() {
        println!("Config already exists: {}", config_path.display());
    } else {
        fs::write(&config_path, EXAMPLE_CONFIG)
            .map_err(|error| format!("Failed to write config: {error}"))?;
        println!("Created config: {}", config_path.display());
    }

    let key_dir = data_dir.join("keys");
    if key_dir.join("sentinel.key").exists() {
        println!("Keys already exist: {}", key_dir.display());
    } else {
        generate_keypair(&key_dir)
            .map_err(|error| format!("Failed to generate keypair: {error}"))?;
        println!("Generated Ed25519 keypair: {}", key_dir.display());
    }

    fs::create_dir_all(&data_dir).map_err(|error| format!("Failed to create data dir: {error}"))?;
    println!("Data directory: {}", data_dir.display());
    println!("\nSentinel initialized. Run 'sentinel start' to begin.");
    Ok(())
}

fn start(config_path: PathBuf, host: Option<String>, port: Option<u16>) -> Result<(), String> {
    if !config_path.exists() {
        return Err(format!(
            "Config not found: {}\nRun 'sentinel init' first.",
            config_path.display()
        ));
    }

    let config = load_config(&config_path).map_err(|error| error.to_string())?;
    let bind_host = host.unwrap_or_else(|| config.server.host.clone());
    let bind_port = port.unwrap_or(config.server.port);
    let data_dir = PathBuf::from(&config.server.data_dir);
    fs::create_dir_all(&data_dir).map_err(|error| error.to_string())?;
    fs::write(
        data_dir.join("sentinel.pid"),
        std::process::id().to_string(),
    )
    .map_err(|error| error.to_string())?;

    let app = crate::server::create_app(config).map_err(|error| error.to_string())?;
    let runtime = tokio::runtime::Runtime::new().map_err(|error| error.to_string())?;
    let result = runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind((bind_host.as_str(), bind_port))
            .await
            .map_err(|error| error.to_string())?;
        axum::serve(listener, app)
            .await
            .map_err(|error| error.to_string())
    });

    let _ = fs::remove_file(data_dir.join("sentinel.pid"));
    result
}

fn stop(config_path: PathBuf) -> Result<(), String> {
    if !config_path.exists() {
        return Err("Config not found.".to_string());
    }

    let config = load_config(&config_path).map_err(|error| error.to_string())?;
    let data_dir = PathBuf::from(&config.server.data_dir);
    let pid_path = data_dir.join("sentinel.pid");
    if !pid_path.exists() {
        println!("Sentinel is not running (no PID file).");
        return Ok(());
    }

    fs::remove_file(&pid_path).map_err(|error| error.to_string())?;
    println!("Sentinel stopped.");
    Ok(())
}

fn status(config_path: PathBuf) -> Result<(), String> {
    if !config_path.exists() {
        return Err("Not initialized. Run 'sentinel init'.".to_string());
    }

    let config = load_config(&config_path).map_err(|error| error.to_string())?;
    let data_dir = PathBuf::from(&config.server.data_dir);

    let pid_path = data_dir.join("sentinel.pid");
    if pid_path.exists() {
        let pid = fs::read_to_string(&pid_path).unwrap_or_default();
        println!(
            "Server: running/stale PID ({}) on {}:{}",
            pid.trim(),
            config.server.host,
            config.server.port
        );
    } else {
        println!("Server: not running");
    }

    let state_path = data_dir.join("state.json");
    if state_path.exists() {
        let state: Value = serde_json::from_str(
            &fs::read_to_string(&state_path).map_err(|error| error.to_string())?,
        )
        .map_err(|error| error.to_string())?;
        println!("State:  {}", state["current"].as_str().unwrap_or("unknown"));
        if let Some(previous) = state["previous"].as_str() {
            println!("  Previous: {previous}");
        }
        println!(
            "  Transitions: {}",
            state["transition_count"].as_u64().unwrap_or(0)
        );
    } else {
        println!("State:  not initialized");
    }

    let chain_path = data_dir.join("receipts.jsonl");
    if chain_path.exists() {
        let count = fs::read_to_string(chain_path)
            .map_err(|error| error.to_string())?
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count();
        println!("Chain:  {count} receipts");
    } else {
        println!("Chain:  empty");
    }
    Ok(())
}

fn state(config_path: PathBuf) -> Result<(), String> {
    let config = load_config(&config_path).map_err(|error| error.to_string())?;
    let data_dir = PathBuf::from(&config.server.data_dir);
    let state_path = data_dir.join("state.json");
    if !state_path.exists() {
        println!("FSM not initialized.");
        return Ok(());
    }

    let fsm_state: Value =
        serde_json::from_str(&fs::read_to_string(&state_path).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    let current = fsm_state["current"].as_str().unwrap_or("unknown");
    println!("Current state: {current}");
    if let Some(state_config) = config.fsm.states.get(current) {
        println!("Description:   {}", state_config.description);
        println!("Allowed tools: {}", state_config.allowed_tools.join(", "));
    }
    println!(
        "Previous:      {}",
        fsm_state["previous"].as_str().unwrap_or("None")
    );
    println!(
        "Transitions:   {}",
        fsm_state["transition_count"].as_u64().unwrap_or(0)
    );

    let available = config
        .fsm
        .transitions
        .iter()
        .filter(|transition| transition.from_state == "*" || transition.from_state == current)
        .collect::<Vec<_>>();
    if !available.is_empty() {
        println!("\nAvailable transitions:");
        for transition in available {
            let guard_info = if transition.guards.is_empty() {
                String::new()
            } else {
                let guards = transition
                    .guards
                    .iter()
                    .map(|guard| format!("{}~{}", guard.field, guard.pattern))
                    .collect::<Vec<_>>()
                    .join(", ");
                format!(" (guards: {guards})")
            };
            println!(
                "  -> {} [trigger: {}]{}",
                transition.to_state, transition.trigger, guard_info
            );
        }
    }
    Ok(())
}

fn verify(config_path: PathBuf) -> Result<(), String> {
    let config = load_config(&config_path).map_err(|error| error.to_string())?;
    let data_dir = PathBuf::from(&config.server.data_dir);
    let chain_path = data_dir.join("receipts.jsonl");
    if !chain_path.exists() {
        println!("No receipt chain found.");
        return Ok(());
    }

    let key_dir = data_dir.join("keys");
    let private_key =
        load_private_key(&key_dir.join("sentinel.key")).map_err(|error| error.to_string())?;
    let public_key =
        load_public_key(&key_dir.join("sentinel.pub")).map_err(|error| error.to_string())?;
    let chain = ReceiptChain::new(chain_path, private_key, public_key)
        .map_err(|error| error.to_string())?;
    let (valid, last_seq, message) = chain.verify_chain();
    if valid {
        println!("Chain valid: {} receipts verified", chain.length());
        Ok(())
    } else {
        Err(format!("CHAIN BROKEN at seq {}: {message}", last_seq + 1))
    }
}

fn transition(config_path: PathBuf, state_name: String, reason: String) -> Result<(), String> {
    let config = load_config(&config_path).map_err(|error| error.to_string())?;
    let body = serde_json::json!({ "to_state": state_name, "reason": reason });
    let response = post_json_to_server(
        &config.server.host,
        config.server.port,
        "/transition",
        &body,
    )?;

    if !response.status_ok {
        return Err(format!(
            "Failed to transition (server returned {}): {}",
            response.status_code, response.body
        ));
    }

    let data: Value = serde_json::from_str(&response.body).map_err(|error| error.to_string())?;
    println!(
        "{} -> {}",
        data["previous"].as_str().unwrap_or("unknown"),
        data["current"].as_str().unwrap_or("unknown")
    );
    Ok(())
}

struct HttpResponse {
    status_code: u16,
    status_ok: bool,
    body: String,
}

fn post_json_to_server(
    host: &str,
    port: u16,
    path: &str,
    body: &Value,
) -> Result<HttpResponse, String> {
    let body = serde_json::to_string(body).map_err(|error| error.to_string())?;
    let mut stream = TcpStream::connect((host, port))
        .map_err(|error| format!("Failed to transition (is server running?): {error}"))?;
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|error| error.to_string())?;

    let mut response = String::new();
    stream
        .read_to_string(&mut response)
        .map_err(|error| error.to_string())?;
    let status_line = response.lines().next().unwrap_or_default();
    let status_code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse::<u16>().ok())
        .unwrap_or(0);
    let body = response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_string())
        .unwrap_or_default();

    Ok(HttpResponse {
        status_code,
        status_ok: (200..300).contains(&status_code),
        body,
    })
}

fn audit(
    config_path: PathBuf,
    tool_name: Option<String>,
    state_filter: Option<String>,
    event: Option<String>,
    limit: usize,
) -> Result<(), String> {
    let config = load_config(&config_path).map_err(|error| error.to_string())?;
    let data_dir = PathBuf::from(&config.server.data_dir);
    let chain_path = data_dir.join("receipts.jsonl");
    if !chain_path.exists() {
        println!("No receipts.");
        return Ok(());
    }

    let key_dir = data_dir.join("keys");
    let private_key =
        load_private_key(&key_dir.join("sentinel.key")).map_err(|error| error.to_string())?;
    let public_key =
        load_public_key(&key_dir.join("sentinel.pub")).map_err(|error| error.to_string())?;
    let chain = ReceiptChain::new(chain_path, private_key, public_key)
        .map_err(|error| error.to_string())?;
    let receipts = chain.get_receipts(
        tool_name.as_deref(),
        state_filter.as_deref(),
        event.as_deref(),
        Some(limit),
    );

    if receipts.is_empty() {
        println!("No matching receipts.");
        return Ok(());
    }

    for receipt in receipts {
        let sig_short = format!(
            "{}...",
            receipt.signature.chars().take(12).collect::<String>()
        );
        println!(
            "[{seq:04}] {id}  {event:<14} {tool:<20} state={state:<12} sig={sig}",
            seq = receipt.seq,
            id = receipt.id,
            event = receipt.event,
            tool = receipt.tool_name,
            state = receipt.state,
            sig = sig_short,
        );
    }
    Ok(())
}

fn default_config_path() -> PathBuf {
    default_config_dir().join("sentinel.yaml")
}

fn default_data_dir() -> PathBuf {
    default_config_dir().join("data")
}

fn default_config_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".config")
        .join("sentinel")
}
