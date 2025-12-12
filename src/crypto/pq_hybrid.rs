//! Hybrid Post-Quantum Key Exchange Module
//!
//! Implements a hybrid Key Encapsulation Mechanism (KEM) combining:
//! - X25519 (classical elliptic curve Diffie-Hellman)
//! - Kyber-768 (NIST FIPS 203 ML-KEM, post-quantum secure)
//!
//! This provides defense against "Harvest Now, Decrypt Later" attacks
//! where adversaries store encrypted data to decrypt once quantum
//! computers become available.

use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext, PublicKey as KyberPubKeyTrait, SecretKey as KyberSecKeyTrait, SharedSecret};
use sha2::Sha256;
use std::path::Path;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, Zeroizing};

/// Kyber-768 public key size in bytes
const KYBER_PK_SIZE: usize = 1184;
/// Kyber-768 secret key size in bytes
const KYBER_SK_SIZE: usize = 2400;
/// Kyber-768 ciphertext size in bytes
const KYBER_CT_SIZE: usize = 1088;
/// X25519 key size in bytes
const X25519_KEY_SIZE: usize = 32;

/// Error types for hybrid KEM operations
#[derive(Debug)]
pub enum HybridError {
    /// Key generation failed
    KeyGenerationFailed,
    /// Encapsulation failed
    EncapsulationFailed,
    /// Decapsulation failed
    DecapsulationFailed,
    /// Invalid key format or size
    InvalidKeyFormat,
    /// I/O error during key operations
    IoError(std::io::Error),
    /// Serialization/deserialization error
    SerializationError,
}

impl std::fmt::Display for HybridError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HybridError::KeyGenerationFailed => write!(f, "Hybrid key generation failed"),
            HybridError::EncapsulationFailed => write!(f, "Hybrid encapsulation failed"),
            HybridError::DecapsulationFailed => write!(f, "Hybrid decapsulation failed"),
            HybridError::InvalidKeyFormat => write!(f, "Invalid key format or size"),
            HybridError::IoError(e) => write!(f, "I/O error: {}", e),
            HybridError::SerializationError => write!(f, "Key serialization/deserialization error"),
        }
    }
}

impl std::error::Error for HybridError {}

impl From<std::io::Error> for HybridError {
    fn from(e: std::io::Error) -> Self {
        HybridError::IoError(e)
    }
}

/// Server's static hybrid public key (safe to distribute)
#[derive(Clone)]
pub struct HybridPublicKey {
    /// X25519 public key (32 bytes)
    pub x25519: [u8; X25519_KEY_SIZE],
    /// Kyber-768 public key (1184 bytes)
    pub kyber: Vec<u8>,
}

impl HybridPublicKey {
    /// Serialize public key to bytes
    /// Format: [32 bytes X25519][1184 bytes Kyber]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(X25519_KEY_SIZE + KYBER_PK_SIZE);
        bytes.extend_from_slice(&self.x25519);
        bytes.extend_from_slice(&self.kyber);
        bytes
    }

    /// Deserialize public key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
        if bytes.len() != X25519_KEY_SIZE + KYBER_PK_SIZE {
            tracing::error!(
                "Invalid hybrid public key size: expected {}, got {}",
                X25519_KEY_SIZE + KYBER_PK_SIZE,
                bytes.len()
            );
            return Err(HybridError::InvalidKeyFormat);
        }

        let x25519: [u8; X25519_KEY_SIZE] = bytes[..X25519_KEY_SIZE]
            .try_into()
            .map_err(|_| HybridError::InvalidKeyFormat)?;

        let kyber = bytes[X25519_KEY_SIZE..].to_vec();

        Ok(Self { x25519, kyber })
    }
}

/// Server's static hybrid secret key (MUST BE PROTECTED)
pub struct HybridSecretKey {
    /// X25519 secret key
    x25519: X25519StaticSecret,
    /// Kyber-768 secret key (2400 bytes)
    kyber: Vec<u8>,
}

impl HybridSecretKey {
    /// Serialize secret key to bytes
    /// Format: [32 bytes X25519][2400 bytes Kyber]
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::with_capacity(X25519_KEY_SIZE + KYBER_SK_SIZE));
        bytes.extend_from_slice(self.x25519.as_bytes());
        bytes.extend_from_slice(&self.kyber);
        bytes
    }

    /// Deserialize secret key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
        if bytes.len() != X25519_KEY_SIZE + KYBER_SK_SIZE {
            tracing::error!(
                "Invalid hybrid secret key size: expected {}, got {}",
                X25519_KEY_SIZE + KYBER_SK_SIZE,
                bytes.len()
            );
            return Err(HybridError::InvalidKeyFormat);
        }

        let x25519_bytes: [u8; X25519_KEY_SIZE] = bytes[..X25519_KEY_SIZE]
            .try_into()
            .map_err(|_| HybridError::InvalidKeyFormat)?;

        let x25519 = X25519StaticSecret::from(x25519_bytes);
        let kyber = bytes[X25519_KEY_SIZE..].to_vec();

        Ok(Self { x25519, kyber })
    }
}

impl Drop for HybridSecretKey {
    fn drop(&mut self) {
        // Zeroize secret key material on drop
        self.kyber.zeroize();
    }
}

/// Client's encapsulation result (sent with encrypted upload)
#[derive(Clone)]
pub struct HybridEncapsulation {
    /// Client's ephemeral X25519 public key (32 bytes)
    pub x25519_ephemeral_pk: [u8; X25519_KEY_SIZE],
    /// Kyber ciphertext (1088 bytes)
    pub kyber_ciphertext: Vec<u8>,
}

impl HybridEncapsulation {
    /// Serialize encapsulation to bytes
    /// Format: [32 bytes X25519 ephemeral PK][1088 bytes Kyber CT]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(X25519_KEY_SIZE + KYBER_CT_SIZE);
        bytes.extend_from_slice(&self.x25519_ephemeral_pk);
        bytes.extend_from_slice(&self.kyber_ciphertext);
        bytes
    }

    /// Deserialize encapsulation from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, HybridError> {
        if bytes.len() != X25519_KEY_SIZE + KYBER_CT_SIZE {
            tracing::error!(
                "Invalid encapsulation size: expected {}, got {}",
                X25519_KEY_SIZE + KYBER_CT_SIZE,
                bytes.len()
            );
            return Err(HybridError::InvalidKeyFormat);
        }

        let x25519_ephemeral_pk: [u8; X25519_KEY_SIZE] = bytes[..X25519_KEY_SIZE]
            .try_into()
            .map_err(|_| HybridError::InvalidKeyFormat)?;

        let kyber_ciphertext = bytes[X25519_KEY_SIZE..].to_vec();

        Ok(Self {
            x25519_ephemeral_pk,
            kyber_ciphertext,
        })
    }
}

/// Generate a new hybrid keypair for the server
///
/// # Returns
/// Tuple of (secret_key, public_key)
///
/// # Security
/// - X25519 key generated from OS random source
/// - Kyber-768 key generated from secure RNG
pub fn generate_keypair() -> (HybridSecretKey, HybridPublicKey) {
    // Generate X25519 keypair
    let x25519_secret = X25519StaticSecret::random_from_rng(rand_core::OsRng);
    let x25519_public = X25519PublicKey::from(&x25519_secret);

    // Generate Kyber-768 keypair
    let (kyber_pk, kyber_sk) = kyber768::keypair();

    let secret_key = HybridSecretKey {
        x25519: x25519_secret,
        kyber: kyber_sk.as_bytes().to_vec(),
    };

    let public_key = HybridPublicKey {
        x25519: x25519_public.to_bytes(),
        kyber: kyber_pk.as_bytes().to_vec(),
    };

    tracing::info!("Generated new hybrid X25519+Kyber-768 keypair");
    (secret_key, public_key)
}

/// Save keypair to files
///
/// # Arguments
/// * `sk_path` - Path for secret key file
/// * `pk_path` - Path for public key file
/// * `sk` - Secret key to save
/// * `pk` - Public key to save
///
/// # Security
/// Secret key file is created with restricted permissions (0600)
pub fn save_keypair(
    sk_path: &Path,
    pk_path: &Path,
    sk: &HybridSecretKey,
    pk: &HybridPublicKey,
) -> Result<(), HybridError> {
    use std::fs::{self, File};
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    // Create parent directories if needed
    if let Some(parent) = sk_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if let Some(parent) = pk_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Save secret key with restricted permissions
    let sk_bytes = sk.to_bytes();
    let mut sk_file = File::create(sk_path)?;
    sk_file.write_all(&sk_bytes)?;

    #[cfg(unix)]
    {
        let mut perms = fs::metadata(sk_path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(sk_path, perms)?;
    }

    // Save public key
    let pk_bytes = pk.to_bytes();
    let mut pk_file = File::create(pk_path)?;
    pk_file.write_all(&pk_bytes)?;

    tracing::info!(
        sk_path = %sk_path.display(),
        pk_path = %pk_path.display(),
        "Saved hybrid keypair to files"
    );
    Ok(())
}

/// Load secret key from file
pub fn load_secret_key(path: &Path) -> Result<HybridSecretKey, HybridError> {
    let bytes = std::fs::read(path)?;
    let sk = HybridSecretKey::from_bytes(&bytes)?;
    tracing::debug!(path = %path.display(), "Loaded hybrid secret key");
    Ok(sk)
}

/// Load public key from file
pub fn load_public_key(path: &Path) -> Result<HybridPublicKey, HybridError> {
    let bytes = std::fs::read(path)?;
    let pk = HybridPublicKey::from_bytes(&bytes)?;
    tracing::debug!(path = %path.display(), "Loaded hybrid public key");
    Ok(pk)
}

/// Client-side: Encapsulate against server's public key
///
/// # Arguments
/// * `server_pk` - Server's hybrid public key
///
/// # Returns
/// Tuple of (shared_secret, encapsulation)
///
/// # Security
/// - Generates ephemeral X25519 keypair per encapsulation
/// - Shared secret is derived using HKDF-SHA256 with domain separation
pub fn encapsulate(server_pk: &HybridPublicKey) -> Result<([u8; 32], HybridEncapsulation), HybridError> {
    // Generate ephemeral X25519 keypair
    let ephemeral_secret = X25519StaticSecret::random_from_rng(rand_core::OsRng);
    let ephemeral_public = X25519PublicKey::from(&ephemeral_secret);

    // X25519 key exchange
    let server_x25519_pk = X25519PublicKey::from(server_pk.x25519);
    let x25519_shared = ephemeral_secret.diffie_hellman(&server_x25519_pk);

    // Kyber encapsulation
    let kyber_pk = kyber768::PublicKey::from_bytes(&server_pk.kyber)
        .map_err(|_| HybridError::EncapsulationFailed)?;
    let (kyber_shared, kyber_ct) = kyber768::encapsulate(&kyber_pk);

    // Derive final shared secret using HKDF
    let shared_secret = derive_shared_secret(x25519_shared.as_bytes(), kyber_shared.as_bytes());

    let encapsulation = HybridEncapsulation {
        x25519_ephemeral_pk: ephemeral_public.to_bytes(),
        kyber_ciphertext: kyber_ct.as_bytes().to_vec(),
    };

    tracing::debug!("Completed hybrid encapsulation");
    Ok((shared_secret, encapsulation))
}

/// Server-side: Decapsulate to recover shared secret
///
/// # Arguments
/// * `server_sk` - Server's hybrid secret key
/// * `encap` - Client's encapsulation
///
/// # Returns
/// 32-byte shared secret
pub fn decapsulate(
    server_sk: &HybridSecretKey,
    encap: &HybridEncapsulation,
) -> Result<[u8; 32], HybridError> {
    // X25519 key exchange
    let client_x25519_pk = X25519PublicKey::from(encap.x25519_ephemeral_pk);
    let x25519_shared = server_sk.x25519.diffie_hellman(&client_x25519_pk);

    // Kyber decapsulation
    let kyber_sk = kyber768::SecretKey::from_bytes(&server_sk.kyber)
        .map_err(|_| HybridError::DecapsulationFailed)?;
    let kyber_ct = kyber768::Ciphertext::from_bytes(&encap.kyber_ciphertext)
        .map_err(|_| HybridError::DecapsulationFailed)?;
    let kyber_shared = kyber768::decapsulate(&kyber_ct, &kyber_sk);

    // Derive final shared secret using HKDF
    let shared_secret = derive_shared_secret(x25519_shared.as_bytes(), kyber_shared.as_bytes());

    tracing::debug!("Completed hybrid decapsulation");
    Ok(shared_secret)
}

/// Derive shared secret from X25519 and Kyber shared secrets
///
/// Uses HKDF-SHA256 with domain separation to combine both secrets
fn derive_shared_secret(x25519_shared: &[u8], kyber_shared: &[u8]) -> [u8; 32] {
    // Concatenate both shared secrets
    let mut ikm = Zeroizing::new(Vec::with_capacity(32 + kyber_shared.len()));
    ikm.extend_from_slice(x25519_shared);
    ikm.extend_from_slice(kyber_shared);

    // HKDF-SHA256 with domain separation
    let hk = Hkdf::<Sha256>::new(Some(b"pq-hybrid-v1"), &ikm);
    let mut output = [0u8; 32];
    hk.expand(b"xchacha20poly1305-key", &mut output)
        .expect("32 bytes is valid HKDF output length");

    output
}

/// Compute fingerprint of a public key (for TOFU verification)
///
/// # Returns
/// BLAKE3 hash of the public key bytes (hex-encoded)
pub fn fingerprint(pk: &HybridPublicKey) -> String {
    let bytes = pk.to_bytes();
    blake3::hash(&bytes).to_hex().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keypair_generation() {
        let (sk, pk) = generate_keypair();
        assert_eq!(pk.x25519.len(), X25519_KEY_SIZE);
        assert_eq!(pk.kyber.len(), KYBER_PK_SIZE);
        assert_eq!(sk.kyber.len(), KYBER_SK_SIZE);
    }

    #[test]
    fn test_public_key_serialization() {
        let (_sk, pk) = generate_keypair();
        let bytes = pk.to_bytes();
        let pk2 = HybridPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.x25519, pk2.x25519);
        assert_eq!(pk.kyber, pk2.kyber);
    }

    #[test]
    fn test_secret_key_serialization() {
        let (sk, _pk) = generate_keypair();
        let bytes = sk.to_bytes();
        let sk2 = HybridSecretKey::from_bytes(&bytes).unwrap();
        assert_eq!(sk.x25519.as_bytes(), sk2.x25519.as_bytes());
        assert_eq!(sk.kyber, sk2.kyber);
    }

    #[test]
    fn test_encapsulation_serialization() {
        let (_sk, pk) = generate_keypair();
        let (_shared, encap) = encapsulate(&pk).unwrap();
        let bytes = encap.to_bytes();
        let encap2 = HybridEncapsulation::from_bytes(&bytes).unwrap();
        assert_eq!(encap.x25519_ephemeral_pk, encap2.x25519_ephemeral_pk);
        assert_eq!(encap.kyber_ciphertext, encap2.kyber_ciphertext);
    }

    #[test]
    fn test_encapsulate_decapsulate_roundtrip() {
        let (sk, pk) = generate_keypair();
        let (shared1, encap) = encapsulate(&pk).unwrap();
        let shared2 = decapsulate(&sk, &encap).unwrap();
        assert_eq!(shared1, shared2, "Shared secrets must match");
    }

    #[test]
    fn test_different_encapsulations_produce_different_secrets() {
        let (sk, pk) = generate_keypair();
        let (shared1, encap1) = encapsulate(&pk).unwrap();
        let (shared2, encap2) = encapsulate(&pk).unwrap();

        // Different encapsulations should produce different shared secrets
        assert_ne!(shared1, shared2);
        assert_ne!(encap1.x25519_ephemeral_pk, encap2.x25519_ephemeral_pk);

        // But both should decapsulate correctly
        let dec1 = decapsulate(&sk, &encap1).unwrap();
        let dec2 = decapsulate(&sk, &encap2).unwrap();
        assert_eq!(shared1, dec1);
        assert_eq!(shared2, dec2);
    }

    #[test]
    fn test_fingerprint_consistency() {
        let (_sk, pk) = generate_keypair();
        let fp1 = fingerprint(&pk);
        let fp2 = fingerprint(&pk);
        assert_eq!(fp1, fp2);
        assert_eq!(fp1.len(), 64); // BLAKE3 hex output
    }

    #[test]
    fn test_invalid_key_size_rejected() {
        let invalid_bytes = vec![0u8; 100];
        assert!(HybridPublicKey::from_bytes(&invalid_bytes).is_err());
        assert!(HybridSecretKey::from_bytes(&invalid_bytes).is_err());
        assert!(HybridEncapsulation::from_bytes(&invalid_bytes).is_err());
    }
}
