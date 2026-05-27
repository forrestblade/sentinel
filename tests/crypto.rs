use sentinel::crypto::{
    generate_keypair, load_private_key, load_public_key, sha256_hex, sign, verify,
};
use tempfile::TempDir;

#[test]
fn generate_keypair_creates_files() {
    let dir = TempDir::new().unwrap();
    let key_dir = dir.path().join("keys");

    generate_keypair(&key_dir).unwrap();

    assert!(key_dir.join("sentinel.key").exists());
    assert!(key_dir.join("sentinel.pub").exists());
}

#[test]
fn roundtrip_sign_verify() {
    let dir = TempDir::new().unwrap();
    let (private_key, public_key) = generate_keypair(&dir.path().join("keys")).unwrap();
    let data = b"hello sentinel";

    let signature = sign(&private_key, data);

    assert!(verify(&public_key, data, &signature));
}

#[test]
fn bad_signature_rejected() {
    let dir = TempDir::new().unwrap();
    let (private_key, public_key) = generate_keypair(&dir.path().join("keys")).unwrap();
    let signature = sign(&private_key, b"hello sentinel");

    assert!(!verify(&public_key, b"tampered data", &signature));
}

#[test]
fn wrong_key_rejected() {
    let dir = TempDir::new().unwrap();
    let key_dir1 = dir.path().join("keys1");
    let key_dir2 = dir.path().join("keys2");
    let (private_key, _) = generate_keypair(&key_dir1).unwrap();
    let (_, public_key2) = generate_keypair(&key_dir2).unwrap();
    let signature = sign(&private_key, b"data");

    assert!(!verify(&public_key2, b"data", &signature));
}

#[test]
fn key_persistence() {
    let dir = TempDir::new().unwrap();
    let key_dir = dir.path().join("keys");
    generate_keypair(&key_dir).unwrap();

    let private_key = load_private_key(&key_dir.join("sentinel.key")).unwrap();
    let public_key = load_public_key(&key_dir.join("sentinel.pub")).unwrap();
    let data = b"persistence test";
    let signature = sign(&private_key, data);

    assert!(verify(&public_key, data, &signature));
}

#[test]
fn generated_private_key_is_pkcs8_pem() {
    let dir = TempDir::new().unwrap();
    let key_dir = dir.path().join("keys");
    generate_keypair(&key_dir).unwrap();

    let pem = std::fs::read_to_string(key_dir.join("sentinel.key")).unwrap();
    assert!(pem.contains("-----BEGIN PRIVATE KEY-----"));
    assert!(pem.contains("-----END PRIVATE KEY-----"));
}

#[test]
fn generated_public_key_is_spki_pem() {
    let dir = TempDir::new().unwrap();
    let key_dir = dir.path().join("keys");
    generate_keypair(&key_dir).unwrap();

    let pem = std::fs::read_to_string(key_dir.join("sentinel.pub")).unwrap();
    assert!(pem.contains("-----BEGIN PUBLIC KEY-----"));
    assert!(pem.contains("-----END PUBLIC KEY-----"));
}

#[test]
fn sha256_hex_known_value() {
    let result = sha256_hex(b"hello");

    assert_eq!(result.len(), 64);
    assert_eq!(
        result,
        "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
    );
}

#[test]
fn sha256_deterministic() {
    assert_eq!(sha256_hex(b"test"), sha256_hex(b"test"));
}

#[test]
fn sha256_different_inputs() {
    assert_ne!(sha256_hex(b"a"), sha256_hex(b"b"));
}
