//! Ed25519 Digital Signature Module
//!
//! Provides signature generation and verification for authenticating
//! third-party file uploads. Each authorized sender has an Ed25519
//! keypair; the server stores the public keys to verify signatures.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use std::path::Path;
use zeroize::Zeroize;

/// Ed25519 signature size in bytes
pub const SIGNATURE_SIZE: usize = 64;
/// Ed25519 public key size in bytes
pub const PUBLIC_KEY_SIZE: usize = 32;
/// Ed25519 secret key size in bytes
pub const SECRET_KEY_SIZE: usize = 32;

/// Error types for signing operations
#[derive(Debug)]
pub enum SigningError {
    /// Signature verification failed
    InvalidSignature,
    /// Public key format is invalid
    InvalidPublicKey,
    /// Secret key format is invalid
    InvalidSecretKey,
    /// Signing operation failed
    SigningFailed,
    /// Sender not found in authorized list
    SenderNotFound(String),
    /// I/O error during key operations
    IoError(std::io::Error),
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SigningError::InvalidSignature => write!(f, "Signature verification failed"),
            SigningError::InvalidPublicKey => write!(f, "Invalid public key format"),
            SigningError::InvalidSecretKey => write!(f, "Invalid secret key format"),
            SigningError::SigningFailed => write!(f, "Signing operation failed"),
            SigningError::SenderNotFound(id) => write!(f, "Sender '{}' not found", id),
            SigningError::IoError(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for SigningError {}

impl From<std::io::Error> for SigningError {
    fn from(e: std::io::Error) -> Self {
        SigningError::IoError(e)
    }
}

/// Generate a new Ed25519 signing keypair
///
/// # Returns
/// Tuple of (signing_key, verifying_key)
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();

    tracing::info!("Generated new Ed25519 signing keypair");
    (signing_key, verifying_key)
}

/// Sign data with a secret key
///
/// # Arguments
/// * `signing_key` - Ed25519 signing key
/// * `data` - Data to sign
///
/// # Returns
/// 64-byte signature
pub fn sign(signing_key: &SigningKey, data: &[u8]) -> [u8; SIGNATURE_SIZE] {
    let signature = signing_key.sign(data);
    signature.to_bytes()
}

/// Verify a signature over data
///
/// # Arguments
/// * `verifying_key` - Ed25519 verifying (public) key
/// * `data` - Original data that was signed
/// * `signature` - 64-byte signature to verify
///
/// # Returns
/// `Ok(())` if signature is valid, `Err(InvalidSignature)` otherwise
pub fn verify(
    verifying_key: &VerifyingKey,
    data: &[u8],
    signature: &[u8; SIGNATURE_SIZE],
) -> Result<(), SigningError> {
    let sig = Signature::from_bytes(signature);

    verifying_key
        .verify(data, &sig)
        .map_err(|_| SigningError::InvalidSignature)
}

/// Parse a verifying key from bytes
pub fn verifying_key_from_bytes(bytes: &[u8]) -> Result<VerifyingKey, SigningError> {
    if bytes.len() != PUBLIC_KEY_SIZE {
        return Err(SigningError::InvalidPublicKey);
    }

    let key_bytes: [u8; PUBLIC_KEY_SIZE] = bytes
        .try_into()
        .map_err(|_| SigningError::InvalidPublicKey)?;

    VerifyingKey::from_bytes(&key_bytes).map_err(|_| SigningError::InvalidPublicKey)
}

/// Parse a verifying key from hex string
pub fn verifying_key_from_hex(hex: &str) -> Result<VerifyingKey, SigningError> {
    let bytes = hex::decode(hex).map_err(|_| SigningError::InvalidPublicKey)?;
    verifying_key_from_bytes(&bytes)
}

/// Parse a signing key from bytes
pub fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey, SigningError> {
    if bytes.len() != SECRET_KEY_SIZE {
        return Err(SigningError::InvalidSecretKey);
    }

    let key_bytes: [u8; SECRET_KEY_SIZE] = bytes
        .try_into()
        .map_err(|_| SigningError::InvalidSecretKey)?;

    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Save signing keypair to files
///
/// # Arguments
/// * `sk_path` - Path for secret (signing) key
/// * `pk_path` - Path for public (verifying) key
/// * `signing_key` - The signing key to save
///
/// # Security
/// Secret key file is created with restricted permissions (0600)
pub fn save_keypair(
    sk_path: &Path,
    pk_path: &Path,
    signing_key: &SigningKey,
) -> Result<(), SigningError> {
    use std::fs::{self, File};
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    // Create parent directories
    if let Some(parent) = sk_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = pk_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Save secret key with restricted permissions
    let mut sk_file = File::create(sk_path)?;
    sk_file.write_all(signing_key.as_bytes())?;

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(sk_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(sk_path, perms)?;
    }

    // Save public key
    let verifying_key = signing_key.verifying_key();
    let mut pk_file = File::create(pk_path)?;
    pk_file.write_all(verifying_key.as_bytes())?;

    tracing::info!(
        sk_path = %sk_path.display(),
        pk_path = %pk_path.display(),
        "Saved Ed25519 keypair to files"
    );
    Ok(())
}

/// Load signing key from file
pub fn load_signing_key(path: &Path) -> Result<SigningKey, SigningError> {
    let mut bytes = std::fs::read(path)?;
    let result = signing_key_from_bytes(&bytes);
    bytes.zeroize();
    tracing::debug!(path = %path.display(), "Loaded Ed25519 signing key");
    result
}

/// Load verifying key from file
pub fn load_verifying_key(path: &Path) -> Result<VerifyingKey, SigningError> {
    let bytes = std::fs::read(path)?;
    let key = verifying_key_from_bytes(&bytes)?;
    tracing::debug!(path = %path.display(), "Loaded Ed25519 verifying key");
    Ok(key)
}

/// Compute fingerprint of a verifying key (for identification)
///
/// # Returns
/// BLAKE3 hash of the public key bytes (hex-encoded, first 16 chars)
pub fn fingerprint(verifying_key: &VerifyingKey) -> String {
    let hash = blake3::hash(verifying_key.as_bytes());
    hash.to_hex()[..16].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (sk, vk) = generate_keypair();
        assert_eq!(sk.as_bytes().len(), SECRET_KEY_SIZE);
        assert_eq!(vk.as_bytes().len(), PUBLIC_KEY_SIZE);
    }

    #[test]
    fn test_sign_verify_roundtrip() {
        let (sk, vk) = generate_keypair();
        let message = b"Test message to sign";

        let signature = sign(&sk, message);
        let result = verify(&vk, message, &signature);

        assert!(result.is_ok());
    }

    #[test]
    fn test_wrong_message_rejected() {
        let (sk, vk) = generate_keypair();
        let message = b"Original message";
        let wrong_message = b"Different message";

        let signature = sign(&sk, message);
        let result = verify(&vk, wrong_message, &signature);

        assert!(matches!(result, Err(SigningError::InvalidSignature)));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let (sk1, _vk1) = generate_keypair();
        let (_sk2, vk2) = generate_keypair();
        let message = b"Test message";

        let signature = sign(&sk1, message);
        let result = verify(&vk2, message, &signature);

        assert!(matches!(result, Err(SigningError::InvalidSignature)));
    }

    #[test]
    fn test_tampered_signature_rejected() {
        let (sk, vk) = generate_keypair();
        let message = b"Test message";

        let mut signature = sign(&sk, message);
        signature[0] ^= 0xFF; // Tamper with signature

        let result = verify(&vk, message, &signature);
        assert!(matches!(result, Err(SigningError::InvalidSignature)));
    }

    #[test]
    fn test_verifying_key_serialization() {
        let (_sk, vk) = generate_keypair();

        // Bytes roundtrip
        let bytes = vk.as_bytes();
        let vk2 = verifying_key_from_bytes(bytes).unwrap();
        assert_eq!(vk, vk2);

        // Hex roundtrip
        let hex = hex::encode(vk.as_bytes());
        let vk3 = verifying_key_from_hex(&hex).unwrap();
        assert_eq!(vk, vk3);
    }

    #[test]
    fn test_signing_key_serialization() {
        let (sk, _vk) = generate_keypair();

        let bytes = sk.as_bytes();
        let sk2 = signing_key_from_bytes(bytes).unwrap();
        assert_eq!(sk.as_bytes(), sk2.as_bytes());
    }

    #[test]
    fn test_invalid_key_sizes_rejected() {
        let short_bytes = vec![0u8; 16];
        let long_bytes = vec![0u8; 64];

        assert!(matches!(
            verifying_key_from_bytes(&short_bytes),
            Err(SigningError::InvalidPublicKey)
        ));
        assert!(matches!(
            verifying_key_from_bytes(&long_bytes),
            Err(SigningError::InvalidPublicKey)
        ));
        assert!(matches!(
            signing_key_from_bytes(&short_bytes),
            Err(SigningError::InvalidSecretKey)
        ));
    }

    #[test]
    fn test_fingerprint_consistency() {
        let (_sk, vk) = generate_keypair();
        let fp1 = fingerprint(&vk);
        let fp2 = fingerprint(&vk);

        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 16);
    }

    #[test]
    fn test_different_keys_different_fingerprints() {
        let (_sk1, vk1) = generate_keypair();
        let (_sk2, vk2) = generate_keypair();

        let fp1 = fingerprint(&vk1);
        let fp2 = fingerprint(&vk2);

        assert_ne!(fp1, fp2);
    }
}
