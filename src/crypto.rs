use base64::{Engine as _, engine::general_purpose::STANDARD};
use ed25519_dalek::{
    Signature, Signer, SigningKey, Verifier, VerifyingKey,
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
};
use pkcs8::LineEnding;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use std::{error::Error, fmt, fs, path::Path};

pub type PrivateKey = SigningKey;
pub type PublicKey = VerifyingKey;

#[derive(Debug)]
pub struct CryptoError(String);

impl CryptoError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for CryptoError {}

pub fn generate_keypair(key_dir: &Path) -> Result<(PrivateKey, PublicKey), CryptoError> {
    fs::create_dir_all(key_dir)
        .map_err(|error| CryptoError::new(format!("Failed to create key dir: {error}")))?;

    let private_key = SigningKey::generate(&mut OsRng);
    let public_key = private_key.verifying_key();

    let private_pem = private_key
        .to_pkcs8_pem(LineEnding::LF)
        .map_err(|error| CryptoError::new(format!("Failed to encode private key: {error}")))?;
    let public_pem = public_key
        .to_public_key_pem(LineEnding::LF)
        .map_err(|error| CryptoError::new(format!("Failed to encode public key: {error}")))?;

    fs::write(key_dir.join("sentinel.key"), private_pem.as_bytes())
        .map_err(|error| CryptoError::new(format!("Failed to write private key: {error}")))?;
    fs::write(key_dir.join("sentinel.pub"), public_pem.as_bytes())
        .map_err(|error| CryptoError::new(format!("Failed to write public key: {error}")))?;

    Ok((private_key, public_key))
}

pub fn load_private_key(path: &Path) -> Result<PrivateKey, CryptoError> {
    let pem = fs::read_to_string(path)
        .map_err(|error| CryptoError::new(format!("Failed to read private key: {error}")))?;
    SigningKey::from_pkcs8_pem(&pem)
        .map_err(|error| CryptoError::new(format!("Expected Ed25519 private key: {error}")))
}

pub fn load_public_key(path: &Path) -> Result<PublicKey, CryptoError> {
    let pem = fs::read_to_string(path)
        .map_err(|error| CryptoError::new(format!("Failed to read public key: {error}")))?;
    VerifyingKey::from_public_key_pem(&pem)
        .map_err(|error| CryptoError::new(format!("Expected Ed25519 public key: {error}")))
}

pub fn sign(private_key: &PrivateKey, data: &[u8]) -> String {
    let signature = private_key.sign(data);
    STANDARD.encode(signature.to_bytes())
}

pub fn verify(public_key: &PublicKey, data: &[u8], signature_b64: &str) -> bool {
    let Ok(raw_signature) = STANDARD.decode(signature_b64) else {
        return false;
    };
    let Ok(signature_bytes) = <[u8; 64]>::try_from(raw_signature.as_slice()) else {
        return false;
    };
    let signature = Signature::from_bytes(&signature_bytes);

    public_key.verify(data, &signature).is_ok()
}

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}
