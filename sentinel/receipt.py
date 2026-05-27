"""Cryptographic receipt chain with Ed25519 signing and SHA-256 hash linking."""

import json
import os
import time

if os.name == "posix":
    import fcntl
else:
    fcntl = None
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from sentinel.crypto import sha256_hex, sign, verify
from sentinel.uuid7 import uuid7

GENESIS_SEED = "sentinel:genesis"


@dataclass(frozen=True)
class Receipt:
    id: str
    seq: int
    timestamp: float
    tool_name: str
    tool_input_hash: str
    tool_output_hash: str | None
    state: str
    prev_hash: str
    event: str
    signature: str

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "seq": self.seq,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "tool_input_hash": self.tool_input_hash,
            "tool_output_hash": self.tool_output_hash,
            "state": self.state,
            "prev_hash": self.prev_hash,
            "event": self.event,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Receipt":
        return cls(**d)

    def canonical_bytes(self) -> bytes:
        """Canonical form for hashing/signing: sorted keys, no whitespace, no signature field."""
        d = self.to_dict()
        d.pop("signature")
        return json.dumps(d, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _canonical_json(obj: object) -> bytes:
    """Canonical JSON encoding for hashing tool inputs/outputs."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


class ReceiptChain:
    def __init__(
        self,
        chain_path: Path,
        private_key: Ed25519PrivateKey,
        public_key: Ed25519PublicKey,
    ) -> None:
        self._chain_path = chain_path
        self._private_key = private_key
        self._public_key = public_key
        self._seq = 0
        self._prev_hash = sha256_hex(GENESIS_SEED.encode("utf-8"))

        chain_path.parent.mkdir(parents=True, exist_ok=True)
        if chain_path.exists():
            self._load_tail()

    def _load_tail(self) -> None:
        """Load the last receipt to get seq and prev_hash."""
        last_line = None
        with open(self._chain_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    last_line = line
        if last_line:
            last = json.loads(last_line)
            self._seq = last["seq"] + 1
            self._prev_hash = sha256_hex(
                Receipt.from_dict(last).canonical_bytes()
            )

    def append(
        self,
        tool_name: str,
        tool_input: object,
        tool_output: object | None,
        state: str,
        event: str,
    ) -> Receipt:
        """Create a signed receipt and append it to the chain."""
        input_hash = sha256_hex(_canonical_json(tool_input))
        output_hash = sha256_hex(_canonical_json(tool_output)) if tool_output is not None else None

        receipt = Receipt(
            id=str(uuid7()),
            seq=self._seq,
            timestamp=time.time(),
            tool_name=tool_name,
            tool_input_hash=input_hash,
            tool_output_hash=output_hash,
            state=state,
            prev_hash=self._prev_hash,
            event=event,
            signature="",  # placeholder, will be replaced
        )

        canonical = receipt.canonical_bytes()
        sig = sign(self._private_key, canonical)
        receipt = Receipt(**{**receipt.to_dict(), "signature": sig})

        line = json.dumps(receipt.to_dict(), separators=(",", ":")) + "\n"

        with open(self._chain_path, "a") as f:
            if fcntl is None:
                f.write(line)
            else:
                fcntl.flock(f, fcntl.LOCK_EX)
                try:
                    f.write(line)
                finally:
                    fcntl.flock(f, fcntl.LOCK_UN)

        self._prev_hash = sha256_hex(receipt.canonical_bytes())
        self._seq += 1

        return receipt

    def verify_chain(self) -> tuple[bool, int, str]:
        """Verify the entire receipt chain.

        Returns (valid, last_valid_seq, error_message).
        """
        if not self._chain_path.exists():
            return True, -1, "Empty chain"

        expected_prev = sha256_hex(GENESIS_SEED.encode("utf-8"))
        last_valid = -1

        with open(self._chain_path, "r") as f:
            for line_num, line in enumerate(f):
                line = line.strip()
                if not line:
                    continue

                try:
                    data = json.loads(line)
                except json.JSONDecodeError as e:
                    return False, last_valid, f"Line {line_num}: invalid JSON: {e}"

                receipt = Receipt.from_dict(data)

                # Verify hash chain
                if receipt.prev_hash != expected_prev:
                    return False, last_valid, (
                        f"Seq {receipt.seq}: hash chain broken. "
                        f"Expected prev_hash={expected_prev[:16]}..., "
                        f"got {receipt.prev_hash[:16]}..."
                    )

                # Verify signature
                canonical = receipt.canonical_bytes()
                if not verify(self._public_key, canonical, receipt.signature):
                    return False, last_valid, f"Seq {receipt.seq}: invalid signature"

                expected_prev = sha256_hex(canonical)
                last_valid = receipt.seq

        return True, last_valid, "Chain valid"

    def get_receipts(
        self,
        tool_name: str | None = None,
        state: str | None = None,
        event: str | None = None,
        limit: int | None = None,
    ) -> list[Receipt]:
        """Query receipts with optional filters. Returns most recent first."""
        if not self._chain_path.exists():
            return []

        all_receipts: list[Receipt] = []
        with open(self._chain_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                r = Receipt.from_dict(json.loads(line))
                if tool_name and r.tool_name != tool_name:
                    continue
                if state and r.state != state:
                    continue
                if event and r.event != event:
                    continue
                all_receipts.append(r)

        all_receipts.reverse()
        if limit:
            all_receipts = all_receipts[:limit]
        return all_receipts

    @property
    def length(self) -> int:
        return self._seq
