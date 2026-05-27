"""Tests for Ed25519 crypto operations."""

import os

import pytest

from sentinel.crypto import (
    generate_keypair,
    load_private_key,
    load_public_key,
    sha256_hex,
    sign,
    verify,
)


def test_generate_keypair_creates_files(tmp_path):
    key_dir = tmp_path / "keys"
    generate_keypair(key_dir)
    assert (key_dir / "sentinel.key").exists()
    assert (key_dir / "sentinel.pub").exists()


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes are not represented faithfully on Windows")
def test_private_key_permissions(tmp_path):
    key_dir = tmp_path / "keys"
    generate_keypair(key_dir)
    mode = os.stat(key_dir / "sentinel.key").st_mode & 0o777
    assert mode == 0o600


def test_roundtrip_sign_verify(key_pair):
    priv, pub, _ = key_pair
    data = b"hello sentinel"
    sig = sign(priv, data)
    assert verify(pub, data, sig)


def test_bad_signature_rejected(key_pair):
    priv, pub, _ = key_pair
    data = b"hello sentinel"
    sig = sign(priv, data)
    assert not verify(pub, b"tampered data", sig)


def test_wrong_key_rejected(tmp_path):
    key_dir1 = tmp_path / "keys1"
    key_dir2 = tmp_path / "keys2"
    priv1, _ = generate_keypair(key_dir1)
    _, pub2 = generate_keypair(key_dir2)
    sig = sign(priv1, b"data")
    assert not verify(pub2, b"data", sig)


def test_key_persistence(key_pair):
    _, _, key_dir = key_pair
    priv = load_private_key(key_dir / "sentinel.key")
    pub = load_public_key(key_dir / "sentinel.pub")
    data = b"persistence test"
    sig = sign(priv, data)
    assert verify(pub, data, sig)


def test_sha256_hex():
    result = sha256_hex(b"hello")
    assert len(result) == 64
    assert result == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_sha256_deterministic():
    assert sha256_hex(b"test") == sha256_hex(b"test")


def test_sha256_different_inputs():
    assert sha256_hex(b"a") != sha256_hex(b"b")
