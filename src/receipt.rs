use crate::{
    crypto::{PrivateKey, PublicKey, sha256_hex, sign, verify},
    uuid7::uuid7,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, error::Error, fmt, fs, path::PathBuf, time::SystemTime};

const GENESIS_SEED: &str = "sentinel:genesis";

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Receipt {
    pub id: String,
    pub seq: i64,
    pub timestamp: f64,
    pub tool_name: String,
    pub tool_input_hash: String,
    pub tool_output_hash: Option<String>,
    pub state: String,
    pub prev_hash: String,
    pub event: String,
    pub signature: String,
}

impl Receipt {
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut fields = BTreeMap::new();
        fields.insert("event", serde_json::json!(self.event));
        fields.insert("id", serde_json::json!(self.id));
        fields.insert("prev_hash", serde_json::json!(self.prev_hash));
        fields.insert("seq", serde_json::json!(self.seq));
        fields.insert("state", serde_json::json!(self.state));
        fields.insert("timestamp", serde_json::json!(self.timestamp));
        fields.insert("tool_input_hash", serde_json::json!(self.tool_input_hash));
        fields.insert("tool_name", serde_json::json!(self.tool_name));
        fields.insert("tool_output_hash", serde_json::json!(self.tool_output_hash));
        serde_json::to_vec(&fields).expect("receipt canonical JSON serialization cannot fail")
    }
}

#[derive(Debug)]
pub struct ReceiptError(String);

impl ReceiptError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for ReceiptError {}

pub struct ReceiptChain {
    chain_path: PathBuf,
    private_key: PrivateKey,
    public_key: PublicKey,
    seq: i64,
    prev_hash: String,
}

impl ReceiptChain {
    pub fn new(
        chain_path: PathBuf,
        private_key: PrivateKey,
        public_key: PublicKey,
    ) -> Result<Self, ReceiptError> {
        if let Some(parent) = chain_path.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                ReceiptError::new(format!("Failed to create receipt dir: {error}"))
            })?;
        }

        let mut chain = Self {
            chain_path,
            private_key,
            public_key,
            seq: 0,
            prev_hash: sha256_hex(GENESIS_SEED.as_bytes()),
        };

        if chain.chain_path.exists() {
            chain.load_tail()?;
        }

        Ok(chain)
    }

    pub fn append(
        &mut self,
        tool_name: &str,
        tool_input: &Value,
        tool_output: Option<&Value>,
        state: &str,
        event: &str,
    ) -> Result<Receipt, ReceiptError> {
        let input_hash = sha256_hex(&canonical_json(tool_input)?);
        let output_hash = tool_output
            .map(canonical_json)
            .transpose()?
            .map(|bytes| sha256_hex(&bytes));

        let mut receipt = Receipt {
            id: uuid7().to_string(),
            seq: self.seq,
            timestamp: now_seconds(),
            tool_name: tool_name.to_string(),
            tool_input_hash: input_hash,
            tool_output_hash: output_hash,
            state: state.to_string(),
            prev_hash: self.prev_hash.clone(),
            event: event.to_string(),
            signature: String::new(),
        };

        receipt.signature = sign(&self.private_key, &receipt.canonical_bytes());
        let line = serde_json::to_string(&receipt)
            .map_err(|error| ReceiptError::new(format!("Failed to serialize receipt: {error}")))?
            + "\n";

        fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.chain_path)
            .and_then(|mut file| std::io::Write::write_all(&mut file, line.as_bytes()))
            .map_err(|error| ReceiptError::new(format!("Failed to append receipt: {error}")))?;

        self.prev_hash = sha256_hex(&receipt.canonical_bytes());
        self.seq += 1;

        Ok(receipt)
    }

    pub fn verify_chain(&self) -> (bool, i64, String) {
        if !self.chain_path.exists() {
            return (true, -1, "Empty chain".to_string());
        }

        let text = match fs::read_to_string(&self.chain_path) {
            Ok(text) => text,
            Err(error) => return (false, -1, format!("Failed to read chain: {error}")),
        };

        let mut expected_prev = sha256_hex(GENESIS_SEED.as_bytes());
        let mut last_valid = -1;

        for (line_num, line) in text.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }

            let receipt = match serde_json::from_str::<Receipt>(line) {
                Ok(receipt) => receipt,
                Err(error) => {
                    return (
                        false,
                        last_valid,
                        format!("Line {line_num}: invalid JSON: {error}"),
                    );
                }
            };

            if receipt.prev_hash != expected_prev {
                return (
                    false,
                    last_valid,
                    format!(
                        "Seq {}: hash chain broken. Expected prev_hash={}..., got {}...",
                        receipt.seq,
                        &expected_prev[..expected_prev.len().min(16)],
                        &receipt.prev_hash[..receipt.prev_hash.len().min(16)]
                    ),
                );
            }

            let canonical = receipt.canonical_bytes();
            if !verify(&self.public_key, &canonical, &receipt.signature) {
                return (
                    false,
                    last_valid,
                    format!("Seq {}: invalid signature", receipt.seq),
                );
            }

            expected_prev = sha256_hex(&canonical);
            last_valid = receipt.seq;
        }

        (true, last_valid, "Chain valid".to_string())
    }

    pub fn get_receipts(
        &self,
        tool_name: Option<&str>,
        state: Option<&str>,
        event: Option<&str>,
        limit: Option<usize>,
    ) -> Vec<Receipt> {
        let Ok(text) = fs::read_to_string(&self.chain_path) else {
            return Vec::new();
        };

        let mut receipts = text
            .lines()
            .filter_map(|line| serde_json::from_str::<Receipt>(line.trim()).ok())
            .filter(|receipt| tool_name.is_none_or(|tool_name| receipt.tool_name == tool_name))
            .filter(|receipt| state.is_none_or(|state| receipt.state == state))
            .filter(|receipt| event.is_none_or(|event| receipt.event == event))
            .collect::<Vec<_>>();

        receipts.reverse();
        if let Some(limit) = limit {
            receipts.truncate(limit);
        }
        receipts
    }

    pub fn length(&self) -> i64 {
        self.seq
    }

    fn load_tail(&mut self) -> Result<(), ReceiptError> {
        let text = fs::read_to_string(&self.chain_path)
            .map_err(|error| ReceiptError::new(format!("Failed to read chain: {error}")))?;
        let Some(last_line) = text.lines().rev().find(|line| !line.trim().is_empty()) else {
            return Ok(());
        };
        let last = serde_json::from_str::<Receipt>(last_line)
            .map_err(|error| ReceiptError::new(format!("Failed to parse receipt tail: {error}")))?;

        self.seq = last.seq + 1;
        self.prev_hash = sha256_hex(&last.canonical_bytes());
        Ok(())
    }
}

fn canonical_json(value: &Value) -> Result<Vec<u8>, ReceiptError> {
    serde_json::to_vec(value).map_err(|error| {
        ReceiptError::new(format!("Failed to serialize JSON canonically: {error}"))
    })
}

fn now_seconds() -> f64 {
    let seconds = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs_f64())
        .unwrap_or(0.0);
    (seconds * 1000.0).round() / 1000.0
}
