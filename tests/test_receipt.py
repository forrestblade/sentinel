"""Tests for the cryptographic receipt chain."""

import json

from sentinel.receipt import Receipt, ReceiptChain


def test_append_creates_receipt(key_pair, data_dir):
    priv, pub, _ = key_pair
    chain = ReceiptChain(data_dir / "receipts.jsonl", priv, pub)
    receipt = chain.append("Read", {"file_path": "/test"}, {"content": "hello"}, "idle", "gate_allow")
    assert receipt.tool_name == "Read"
    assert receipt.seq == 0
    assert receipt.event == "gate_allow"
    assert receipt.signature != ""


def test_chain_links_receipts(key_pair, data_dir):
    priv, pub, _ = key_pair
    chain = ReceiptChain(data_dir / "receipts.jsonl", priv, pub)
    r1 = chain.append("Read", {"path": "a"}, None, "idle", "gate_allow")
    r2 = chain.append("Write", {"path": "b"}, {"ok": True}, "developing", "gate_allow")
    assert r2.seq == 1
    assert r2.prev_hash != r1.prev_hash  # prev_hash of r2 = hash of r1's canonical form


def test_verify_valid_chain(key_pair, data_dir):
    priv, pub, _ = key_pair
    chain = ReceiptChain(data_dir / "receipts.jsonl", priv, pub)
    chain.append("Read", {"a": 1}, None, "idle", "gate_allow")
    chain.append("Write", {"b": 2}, {"ok": True}, "idle", "post_receipt")
    chain.append("Bash", {"cmd": "ls"}, {"out": "file"}, "developing", "gate_allow")

    valid, last_seq, msg = chain.verify_chain()
    assert valid
    assert last_seq == 2
    assert "valid" in msg.lower()


def test_verify_detects_tampered_field(key_pair, data_dir):
    priv, pub, _ = key_pair
    chain_path = data_dir / "receipts.jsonl"
    chain = ReceiptChain(chain_path, priv, pub)
    chain.append("Read", {"a": 1}, None, "idle", "gate_allow")
    chain.append("Write", {"b": 2}, None, "idle", "gate_allow")

    # Tamper with the first receipt's tool_name
    lines = chain_path.read_text().splitlines()
    data = json.loads(lines[0])
    data["tool_name"] = "TAMPERED"
    lines[0] = json.dumps(data, separators=(",", ":"))
    chain_path.write_text("\n".join(lines) + "\n")

    chain2 = ReceiptChain(chain_path, priv, pub)
    valid, last_seq, msg = chain2.verify_chain()
    assert not valid
    assert "signature" in msg.lower() or "hash" in msg.lower()


def test_verify_detects_deleted_entry(key_pair, data_dir):
    priv, pub, _ = key_pair
    chain_path = data_dir / "receipts.jsonl"
    chain = ReceiptChain(chain_path, priv, pub)
    chain.append("Read", {"a": 1}, None, "idle", "gate_allow")
    chain.append("Write", {"b": 2}, None, "idle", "gate_allow")
    chain.append("Bash", {"c": 3}, None, "idle", "gate_allow")

    # Delete the middle entry
    lines = chain_path.read_text().splitlines()
    chain_path.write_text(lines[0] + "\n" + lines[2] + "\n")

    chain2 = ReceiptChain(chain_path, priv, pub)
    valid, _, msg = chain2.verify_chain()
    assert not valid
    assert "hash chain broken" in msg.lower()


def test_verify_empty_chain(key_pair, data_dir):
    priv, pub, _ = key_pair
    chain = ReceiptChain(data_dir / "receipts.jsonl", priv, pub)
    valid, last_seq, _ = chain.verify_chain()
    assert valid
    assert last_seq == -1


def test_chain_reloads_from_disk(key_pair, data_dir):
    priv, pub, _ = key_pair
    chain_path = data_dir / "receipts.jsonl"

    chain1 = ReceiptChain(chain_path, priv, pub)
    chain1.append("Read", {"a": 1}, None, "idle", "gate_allow")
    chain1.append("Write", {"b": 2}, None, "idle", "gate_allow")

    # Create new chain instance from same file
    chain2 = ReceiptChain(chain_path, priv, pub)
    assert chain2.length == 2
    r3 = chain2.append("Bash", {"c": 3}, None, "idle", "gate_allow")
    assert r3.seq == 2

    # Verify the whole chain still works
    valid, last_seq, _ = chain2.verify_chain()
    assert valid
    assert last_seq == 2


def test_query_by_tool_name(key_pair, data_dir):
    priv, pub, _ = key_pair
    chain = ReceiptChain(data_dir / "receipts.jsonl", priv, pub)
    chain.append("Read", {"a": 1}, None, "idle", "gate_allow")
    chain.append("Write", {"b": 2}, None, "idle", "gate_allow")
    chain.append("Read", {"c": 3}, None, "idle", "gate_allow")

    results = chain.get_receipts(tool_name="Read")
    assert len(results) == 2
    assert all(r.tool_name == "Read" for r in results)


def test_query_by_state(key_pair, data_dir):
    priv, pub, _ = key_pair
    chain = ReceiptChain(data_dir / "receipts.jsonl", priv, pub)
    chain.append("Read", {"a": 1}, None, "idle", "gate_allow")
    chain.append("Write", {"b": 2}, None, "developing", "gate_allow")

    results = chain.get_receipts(state="developing")
    assert len(results) == 1
    assert results[0].tool_name == "Write"


def test_query_with_limit(key_pair, data_dir):
    priv, pub, _ = key_pair
    chain = ReceiptChain(data_dir / "receipts.jsonl", priv, pub)
    for i in range(10):
        chain.append("Read", {"i": i}, None, "idle", "gate_allow")

    results = chain.get_receipts(limit=3)
    assert len(results) == 3
    # Most recent first
    assert results[0].seq == 9


def test_receipt_canonical_bytes_excludes_signature():
    receipt = Receipt(
        id="test-id", seq=0, timestamp=1000.0, tool_name="Read",
        tool_input_hash="abc", tool_output_hash=None, state="idle",
        prev_hash="def", event="gate_allow", signature="should-be-excluded",
    )
    canonical = receipt.canonical_bytes()
    assert b"signature" not in canonical
    assert b"should-be-excluded" not in canonical


def test_receipt_canonical_bytes_deterministic():
    receipt = Receipt(
        id="test-id", seq=0, timestamp=1000.0, tool_name="Read",
        tool_input_hash="abc", tool_output_hash=None, state="idle",
        prev_hash="def", event="gate_allow", signature="sig",
    )
    assert receipt.canonical_bytes() == receipt.canonical_bytes()


def test_output_hash_none_for_gate_events(key_pair, data_dir):
    priv, pub, _ = key_pair
    chain = ReceiptChain(data_dir / "receipts.jsonl", priv, pub)
    receipt = chain.append("Read", {"path": "/test"}, None, "idle", "gate_allow")
    assert receipt.tool_output_hash is None
