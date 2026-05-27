use sentinel::{
    crypto::generate_keypair,
    receipt::{Receipt, ReceiptChain},
};
use serde_json::json;
use tempfile::TempDir;

fn key_pair() -> (
    TempDir,
    sentinel::crypto::PrivateKey,
    sentinel::crypto::PublicKey,
) {
    let dir = TempDir::new().unwrap();
    let (private_key, public_key) = generate_keypair(&dir.path().join("keys")).unwrap();
    (dir, private_key, public_key)
}

#[test]
fn append_creates_receipt() {
    let (dir, private_key, public_key) = key_pair();
    let mut chain =
        ReceiptChain::new(dir.path().join("receipts.jsonl"), private_key, public_key).unwrap();

    let receipt = chain
        .append(
            "read",
            &json!({ "file_path": "/test" }),
            Some(&json!({ "content": "hello" })),
            "idle",
            "gate_allow",
        )
        .unwrap();

    assert_eq!(receipt.tool_name, "read");
    assert_eq!(receipt.seq, 0);
    assert_eq!(receipt.event, "gate_allow");
    assert!(!receipt.signature.is_empty());
}

#[test]
fn chain_links_receipts() {
    let (dir, private_key, public_key) = key_pair();
    let mut chain =
        ReceiptChain::new(dir.path().join("receipts.jsonl"), private_key, public_key).unwrap();
    let r1 = chain
        .append("read", &json!({ "path": "a" }), None, "idle", "gate_allow")
        .unwrap();
    let r2 = chain
        .append(
            "write",
            &json!({ "path": "b" }),
            Some(&json!({ "ok": true })),
            "developing",
            "gate_allow",
        )
        .unwrap();

    assert_eq!(r2.seq, 1);
    assert_ne!(r2.prev_hash, r1.prev_hash);
}

#[test]
fn verify_valid_chain() {
    let (dir, private_key, public_key) = key_pair();
    let mut chain =
        ReceiptChain::new(dir.path().join("receipts.jsonl"), private_key, public_key).unwrap();
    chain
        .append("read", &json!({ "a": 1 }), None, "idle", "gate_allow")
        .unwrap();
    chain
        .append(
            "write",
            &json!({ "b": 2 }),
            Some(&json!({ "ok": true })),
            "idle",
            "post_receipt",
        )
        .unwrap();
    chain
        .append(
            "bash",
            &json!({ "cmd": "ls" }),
            Some(&json!({ "out": "file" })),
            "developing",
            "gate_allow",
        )
        .unwrap();

    let (valid, last_seq, message) = chain.verify_chain();
    assert!(valid, "{message}");
    assert_eq!(last_seq, 2);
    assert!(message.to_lowercase().contains("valid"));
}

#[test]
fn verify_detects_tampered_field() {
    let (dir, private_key, public_key) = key_pair();
    let chain_path = dir.path().join("receipts.jsonl");
    let mut chain = ReceiptChain::new(chain_path.clone(), private_key, public_key).unwrap();
    chain
        .append("read", &json!({ "a": 1 }), None, "idle", "gate_allow")
        .unwrap();
    chain
        .append("write", &json!({ "b": 2 }), None, "idle", "gate_allow")
        .unwrap();

    let mut lines = std::fs::read_to_string(&chain_path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    let mut data: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
    data["tool_name"] = json!("TAMPERED");
    lines[0] = serde_json::to_string(&data).unwrap();
    std::fs::write(&chain_path, format!("{}\n", lines.join("\n"))).unwrap();

    let (valid, _, message) = chain.verify_chain();
    assert!(!valid);
    let message = message.to_lowercase();
    assert!(message.contains("signature") || message.contains("hash"));
}

#[test]
fn verify_detects_deleted_entry() {
    let (dir, private_key, public_key) = key_pair();
    let chain_path = dir.path().join("receipts.jsonl");
    let mut chain = ReceiptChain::new(chain_path.clone(), private_key, public_key).unwrap();
    chain
        .append("read", &json!({ "a": 1 }), None, "idle", "gate_allow")
        .unwrap();
    chain
        .append("write", &json!({ "b": 2 }), None, "idle", "gate_allow")
        .unwrap();
    chain
        .append("bash", &json!({ "c": 3 }), None, "idle", "gate_allow")
        .unwrap();

    let lines = std::fs::read_to_string(&chain_path)
        .unwrap()
        .lines()
        .map(str::to_string)
        .collect::<Vec<_>>();
    std::fs::write(&chain_path, format!("{}\n{}\n", lines[0], lines[2])).unwrap();

    let (valid, _, message) = chain.verify_chain();
    assert!(!valid);
    assert!(message.to_lowercase().contains("hash chain broken"));
}

#[test]
fn verify_empty_chain() {
    let (dir, private_key, public_key) = key_pair();
    let chain =
        ReceiptChain::new(dir.path().join("receipts.jsonl"), private_key, public_key).unwrap();

    let (valid, last_seq, _) = chain.verify_chain();
    assert!(valid);
    assert_eq!(last_seq, -1);
}

#[test]
fn chain_reloads_from_disk() {
    let (dir, private_key, public_key) = key_pair();
    let chain_path = dir.path().join("receipts.jsonl");
    let mut chain1 =
        ReceiptChain::new(chain_path.clone(), private_key.clone(), public_key).unwrap();
    chain1
        .append("read", &json!({ "a": 1 }), None, "idle", "gate_allow")
        .unwrap();
    chain1
        .append("write", &json!({ "b": 2 }), None, "idle", "gate_allow")
        .unwrap();

    let public_key = private_key.verifying_key();
    let mut chain2 = ReceiptChain::new(chain_path, private_key, public_key).unwrap();
    assert_eq!(chain2.length(), 2);
    let r3 = chain2
        .append("bash", &json!({ "c": 3 }), None, "idle", "gate_allow")
        .unwrap();
    assert_eq!(r3.seq, 2);

    let (valid, last_seq, message) = chain2.verify_chain();
    assert!(valid, "{message}");
    assert_eq!(last_seq, 2);
}

#[test]
fn query_by_tool_name() {
    let (dir, private_key, public_key) = key_pair();
    let mut chain =
        ReceiptChain::new(dir.path().join("receipts.jsonl"), private_key, public_key).unwrap();
    chain
        .append("read", &json!({ "a": 1 }), None, "idle", "gate_allow")
        .unwrap();
    chain
        .append("write", &json!({ "b": 2 }), None, "idle", "gate_allow")
        .unwrap();
    chain
        .append("read", &json!({ "c": 3 }), None, "idle", "gate_allow")
        .unwrap();

    let results = chain.get_receipts(Some("read"), None, None, None);
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|receipt| receipt.tool_name == "read"));
}

#[test]
fn query_by_state() {
    let (dir, private_key, public_key) = key_pair();
    let mut chain =
        ReceiptChain::new(dir.path().join("receipts.jsonl"), private_key, public_key).unwrap();
    chain
        .append("read", &json!({ "a": 1 }), None, "idle", "gate_allow")
        .unwrap();
    chain
        .append(
            "write",
            &json!({ "b": 2 }),
            None,
            "developing",
            "gate_allow",
        )
        .unwrap();

    let results = chain.get_receipts(None, Some("developing"), None, None);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].tool_name, "write");
}

#[test]
fn query_with_limit() {
    let (dir, private_key, public_key) = key_pair();
    let mut chain =
        ReceiptChain::new(dir.path().join("receipts.jsonl"), private_key, public_key).unwrap();
    for i in 0..10 {
        chain
            .append("read", &json!({ "i": i }), None, "idle", "gate_allow")
            .unwrap();
    }

    let results = chain.get_receipts(None, None, None, Some(3));
    assert_eq!(results.len(), 3);
    assert_eq!(results[0].seq, 9);
}

#[test]
fn receipt_canonical_bytes_excludes_signature() {
    let receipt = Receipt {
        id: "test-id".to_string(),
        seq: 0,
        timestamp: 1000.0,
        tool_name: "read".to_string(),
        tool_input_hash: "abc".to_string(),
        tool_output_hash: None,
        state: "idle".to_string(),
        prev_hash: "def".to_string(),
        event: "gate_allow".to_string(),
        signature: "should-be-excluded".to_string(),
    };

    let canonical = receipt.canonical_bytes();
    assert!(
        !canonical
            .windows(b"signature".len())
            .any(|w| w == b"signature")
    );
    assert!(
        !canonical
            .windows(b"should-be-excluded".len())
            .any(|w| w == b"should-be-excluded")
    );
}

#[test]
fn receipt_canonical_bytes_deterministic() {
    let receipt = Receipt {
        id: "test-id".to_string(),
        seq: 0,
        timestamp: 1000.0,
        tool_name: "read".to_string(),
        tool_input_hash: "abc".to_string(),
        tool_output_hash: None,
        state: "idle".to_string(),
        prev_hash: "def".to_string(),
        event: "gate_allow".to_string(),
        signature: "sig".to_string(),
    };

    assert_eq!(receipt.canonical_bytes(), receipt.canonical_bytes());
}

#[test]
fn output_hash_none_for_gate_events() {
    let (dir, private_key, public_key) = key_pair();
    let mut chain =
        ReceiptChain::new(dir.path().join("receipts.jsonl"), private_key, public_key).unwrap();
    let receipt = chain
        .append(
            "read",
            &json!({ "path": "/test" }),
            None,
            "idle",
            "gate_allow",
        )
        .unwrap();

    assert!(receipt.tool_output_hash.is_none());
}
