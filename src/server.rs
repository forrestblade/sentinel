use crate::{
    config::SentinelConfig,
    crypto::{PrivateKey, PublicKey, load_private_key, load_public_key},
    fsm::SentinelFsm,
    receipt::ReceiptChain,
};
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    io::Write,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::SystemTime,
};

#[derive(Clone)]
struct AppState {
    inner: Arc<Mutex<InnerState>>,
}

struct InnerState {
    config: SentinelConfig,
    start_time: f64,
    fsm: SentinelFsm,
    private_key: PrivateKey,
    public_key: PublicKey,
    chain: ReceiptChain,
    current_session: Option<Value>,
}

pub fn create_app(config: SentinelConfig) -> Result<Router, Box<dyn std::error::Error>> {
    let data_dir = PathBuf::from(&config.server.data_dir);
    std::fs::create_dir_all(&data_dir)?;

    let key_dir = data_dir.join("keys");
    let private_key = load_private_key(&key_dir.join("sentinel.key"))?;
    let public_key = load_public_key(&key_dir.join("sentinel.pub"))?;
    let fsm = SentinelFsm::new(config.fsm.clone(), data_dir.join("state.json"))?;
    let chain = ReceiptChain::new(
        data_dir.join("receipts.jsonl"),
        private_key.clone(),
        public_key,
    )?;

    let state = AppState {
        inner: Arc::new(Mutex::new(InnerState {
            config,
            start_time: now_seconds(),
            fsm,
            private_key,
            public_key,
            chain,
            current_session: None,
        })),
    };

    Ok(Router::new()
        .route("/session", post(handle_session))
        .route("/session/end", post(handle_session_end))
        .route("/gate", post(handle_gate))
        .route("/receipt", post(handle_receipt))
        .route("/transition", post(handle_transition))
        .route("/state", get(handle_state))
        .route("/health", get(handle_health))
        .with_state(state))
}

async fn handle_health(State(state): State<AppState>) -> Json<Value> {
    let inner = state.inner.lock().expect("state mutex poisoned");
    Json(json!({
        "status": "ok",
        "uptime": now_seconds() - inner.start_time,
        "chain_length": inner.chain.length(),
        "session": inner.current_session,
    }))
}

async fn handle_state(State(state): State<AppState>) -> Response {
    let inner = state.inner.lock().expect("state mutex poisoned");
    let current = inner.fsm.get_state().current.clone();
    let Some(state_config) = inner.config.fsm.states.get(&current) else {
        return json_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": "current state is not configured" }),
        );
    };

    Json(json!({
        "current": inner.fsm.get_state().current,
        "previous": inner.fsm.get_state().previous,
        "entered_at": inner.fsm.get_state().entered_at,
        "transition_count": inner.fsm.get_state().transition_count,
        "description": state_config.description,
        "allowed_tools": state_config.allowed_tools,
        "available_transitions": inner.fsm.get_available_transitions().into_iter().map(|transition| json!({
            "to": transition.to,
            "trigger": transition.trigger,
            "guards": transition.guards.into_iter().map(|guard| json!({"field": guard.field, "pattern": guard.pattern})).collect::<Vec<_>>()
        })).collect::<Vec<_>>()
    })).into_response()
}

async fn handle_gate(
    State(state): State<AppState>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return json_status(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON" })),
    };

    let mut inner = state.inner.lock().expect("state mutex poisoned");
    let tool_name = body.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let tool_input = body.get("tool_input").cloned().unwrap_or_else(|| json!({}));

    let (allowed, reason) = inner.fsm.is_tool_allowed(tool_name);
    let event = if allowed { "gate_allow" } else { "gate_deny" };
    let current = inner.fsm.get_state().current.clone();
    let receipt = match inner
        .chain
        .append(tool_name, &tool_input, None, &current, event)
    {
        Ok(receipt) => receipt,
        Err(error) => {
            return json_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": error.to_string() }),
            );
        }
    };

    if allowed
        && let Some(target) = inner.fsm.evaluate_transition(tool_name, &tool_input)
        && let Err(error) = inner.fsm.transition_to(&target)
    {
        return json_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": error.to_string() }),
        );
    }

    let decision = if allowed { "allow" } else { "deny" };
    let state_name = inner.fsm.get_state().current.clone();
    Json(json!({
        "decision": decision,
        "reason": reason,
        "state": state_name,
        "receipt_id": receipt.id,
        "context": format!("[Sentinel] state={} | receipt={} | decision={}", inner.fsm.get_state().current, receipt.id, decision),
    })).into_response()
}

async fn handle_receipt(
    State(state): State<AppState>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return json_status(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON" })),
    };

    let mut inner = state.inner.lock().expect("state mutex poisoned");
    let tool_name = body.get("tool_name").and_then(Value::as_str).unwrap_or("");
    let tool_input = body.get("tool_input").cloned().unwrap_or_else(|| json!({}));
    let tool_response = body
        .get("tool_response")
        .or_else(|| body.get("tool_result"))
        .cloned();
    let current = inner.fsm.get_state().current.clone();
    let receipt = match inner.chain.append(
        tool_name,
        &tool_input,
        tool_response.as_ref(),
        &current,
        "post_receipt",
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            return json_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": error.to_string() }),
            );
        }
    };

    Json(json!({
        "receipt_id": receipt.id,
        "chain_length": inner.chain.length(),
        "context": format!("[Sentinel] receipt={} | chain_length={}", receipt.id, inner.chain.length()),
    })).into_response()
}

async fn handle_transition(
    State(state): State<AppState>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return json_status(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON" })),
    };

    let Some(to_state) = body.get("to_state").and_then(Value::as_str) else {
        return json_status(
            StatusCode::BAD_REQUEST,
            json!({ "error": "Missing 'to_state'" }),
        );
    };

    let mut inner = state.inner.lock().expect("state mutex poisoned");
    let previous = inner.fsm.get_state().current.clone();
    let state_after = match inner.fsm.transition_to(to_state) {
        Ok(state_after) => state_after,
        Err(error) => {
            return json_status(
                StatusCode::BAD_REQUEST,
                json!({ "error": error.to_string() }),
            );
        }
    };

    let transition_input = json!({
        "from": previous,
        "to": to_state,
        "reason": body.get("reason").and_then(Value::as_str).unwrap_or(""),
    });
    let _ = inner.chain.append(
        "manual_transition",
        &transition_input,
        None,
        &state_after.current,
        "transition",
    );

    Json(json!({
        "previous": previous,
        "current": state_after.current,
        "transition_count": state_after.transition_count,
    }))
    .into_response()
}

async fn handle_session(
    State(state): State<AppState>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return json_status(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON" })),
    };

    let Some(session_key) = body
        .get("session_id")
        .or_else(|| body.get("session_file"))
        .and_then(Value::as_str)
    else {
        return json_status(
            StatusCode::BAD_REQUEST,
            json!({ "error": "Missing 'session_id' or 'session_file'" }),
        );
    };

    let mut inner = state.inner.lock().expect("state mutex poisoned");
    let session = match switch_receipt_session(&mut inner, session_key, body.clone()) {
        Ok(session) => session,
        Err(error) => {
            return json_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": error.to_string() }),
            );
        }
    };
    Json(json!({ "session": session, "chain_length": inner.chain.length() })).into_response()
}

async fn handle_session_end(
    State(state): State<AppState>,
    body: Result<Json<Value>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let Json(body) = match body {
        Ok(body) => body,
        Err(_) => return json_status(StatusCode::BAD_REQUEST, json!({ "error": "Invalid JSON" })),
    };

    let mut inner = state.inner.lock().expect("state mutex poisoned");
    let Some(current) = inner.current_session.clone() else {
        return Json(json!({ "ended": false, "reason": "No active session" })).into_response();
    };

    let session_key = body
        .get("session_id")
        .or_else(|| body.get("session_file"))
        .and_then(Value::as_str);
    if let Some(session_key) = session_key
        && current.get("key").and_then(Value::as_str) != Some(session_key)
    {
        return json_status(
            StatusCode::CONFLICT,
            json!({ "ended": false, "reason": "Session mismatch" }),
        );
    }

    let mut ended = current.as_object().cloned().unwrap_or_default();
    ended.insert("ended_at".to_string(), json!(now_seconds()));
    ended.insert("end_metadata".to_string(), body.clone());
    let ended = Value::Object(ended);

    let data_dir = PathBuf::from(&inner.config.server.data_dir);
    if let Err(error) = append_session_index(&data_dir, &ended) {
        return json_status(
            StatusCode::INTERNAL_SERVER_ERROR,
            json!({ "error": error.to_string() }),
        );
    }
    inner.current_session = None;
    inner.chain = match ReceiptChain::new(
        data_dir.join("receipts.jsonl"),
        inner.private_key.clone(),
        inner.public_key,
    ) {
        Ok(chain) => chain,
        Err(error) => {
            return json_status(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": error.to_string() }),
            );
        }
    };

    Json(json!({ "ended": true, "session": ended })).into_response()
}

fn switch_receipt_session(
    inner: &mut InnerState,
    session_key: &str,
    metadata: Value,
) -> Result<Value, Box<dyn std::error::Error>> {
    let data_dir = PathBuf::from(&inner.config.server.data_dir);
    let slug = session_slug(session_key);
    let session_dir = data_dir.join("sessions").join(&slug);
    std::fs::create_dir_all(&session_dir)?;
    let chain_path = session_dir.join("receipts.jsonl");

    inner.chain = ReceiptChain::new(
        chain_path.clone(),
        inner.private_key.clone(),
        inner.public_key,
    )?;
    let session = json!({
        "id": slug,
        "key": session_key,
        "path": chain_path.to_string_lossy(),
        "started_at": now_seconds(),
        "metadata": metadata,
    });
    append_session_index(&data_dir, &session)?;
    inner.current_session = Some(session.clone());
    Ok(session)
}

fn append_session_index(
    data_dir: &Path,
    session: &Value,
) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(data_dir)?;
    let line = serde_json::to_string(session)? + "\n";
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(data_dir.join("sessions.jsonl"))?
        .write_all(line.as_bytes())?;
    std::fs::write(
        data_dir.join("current_session.json"),
        serde_json::to_string(session)?,
    )?;
    Ok(())
}

fn session_slug(session_key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(session_key.as_bytes());
    let digest = format!("{:x}", hasher.finalize());
    let digest = &digest[..16];
    let stem = Path::new(session_key)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("session");
    let safe = stem
        .chars()
        .map(|ch| {
            if ch.is_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .take(48)
        .collect::<String>();
    format!("{safe}-{digest}")
}

fn json_status(status: StatusCode, value: Value) -> Response {
    (status, Json(value)).into_response()
}

fn now_seconds() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0)
}
