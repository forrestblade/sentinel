"""Ed25519 key management, signing, verification, and SHA-256 hashing."""

import base64
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
    load_pem_private_key,
    load_pem_public_key,
)


def generate_keypair(key_dir: Path) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    """Generate an Ed25519 keypair and save to PEM files."""
    key_dir.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_path = key_dir / "sentinel.key"
    public_path = key_dir / "sentinel.pub"

    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )

    # Write private key with restrictive permissions
    fd = os.open(str(private_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, private_pem)
    finally:
        os.close(fd)

    public_path.write_bytes(public_pem)

    return private_key, public_key


def load_private_key(path: Path) -> Ed25519PrivateKey:
    """Load an Ed25519 private key from a PEM file."""
    key = load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"Expected Ed25519 private key, got {type(key).__name__}")
    return key


def load_public_key(path: Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from a PEM file."""
    key = load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"Expected Ed25519 public key, got {type(key).__name__}")
    return key


def sign(private_key: Ed25519PrivateKey, data: bytes) -> str:
    """Sign data with Ed25519, return base64-encoded signature."""
    signature = private_key.sign(data)
    return base64.b64encode(signature).decode("ascii")


def verify(public_key: Ed25519PublicKey, data: bytes, signature_b64: str) -> bool:
    """Verify an Ed25519 signature. Returns True if valid, False otherwise."""
    try:
        raw_sig = base64.b64decode(signature_b64)
        public_key.verify(raw_sig, data)
        return True
    except Exception:
        return False


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of data."""
    return hashlib.sha256(data).hexdigest()
