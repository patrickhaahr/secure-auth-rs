//! Streaming XChaCha20-Poly1305 Encryption Module
//!
//! Implements chunk-based authenticated encryption using XChaCha20-Poly1305.
//! Each chunk is independently authenticated, allowing streaming decryption
//! without loading the entire file into memory.
//!
//! Wire Format:
//! [24-byte nonce][chunk1][chunk2]...[chunkN]
//!
//! Each chunk:
//! [4-byte ciphertext length (BE)][ciphertext with 16-byte auth tag]

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

/// Chunk size for streaming encryption (64KB)
pub const CHUNK_SIZE: usize = 64 * 1024;
/// XChaCha20 nonce size (24 bytes / 192 bits)
const NONCE_SIZE: usize = 24;
/// Poly1305 authentication tag size
const TAG_SIZE: usize = 16;

/// Error types for stream cipher operations
#[derive(Debug)]
pub enum StreamCipherError {
    /// Encryption operation failed
    EncryptionFailed,
    /// Decryption operation failed
    DecryptionFailed,
    /// Authentication tag verification failed (data tampered)
    AuthenticationFailed,
    /// Invalid chunk format
    InvalidChunkFormat,
    /// Missing nonce in stream
    NonceMissing,
    /// Invalid key size
    InvalidKeySize,
}

impl std::fmt::Display for StreamCipherError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamCipherError::EncryptionFailed => write!(f, "Encryption operation failed"),
            StreamCipherError::DecryptionFailed => write!(f, "Decryption operation failed"),
            StreamCipherError::AuthenticationFailed => {
                write!(f, "Authentication failed - data may be tampered")
            }
            StreamCipherError::InvalidChunkFormat => write!(f, "Invalid chunk format"),
            StreamCipherError::NonceMissing => write!(f, "Nonce missing from stream"),
            StreamCipherError::InvalidKeySize => write!(f, "Invalid key size - expected 32 bytes"),
        }
    }
}

impl std::error::Error for StreamCipherError {}

/// Streaming encryptor for client-side use
///
/// Encrypts data in chunks while simultaneously computing BLAKE3 hash
/// of the plaintext for integrity verification.
pub struct StreamEncryptor {
    cipher: XChaCha20Poly1305,
    nonce_base: [u8; NONCE_SIZE],
    chunk_counter: u64,
    hasher: blake3::Hasher,
}

impl StreamEncryptor {
    /// Create a new stream encryptor with the shared secret
    ///
    /// # Arguments
    /// * `shared_secret` - 32-byte key derived from hybrid KEM
    pub fn new(shared_secret: &[u8; 32]) -> Self {
        let cipher = XChaCha20Poly1305::new(shared_secret.into());

        // Generate random base nonce
        let mut nonce_base = [0u8; NONCE_SIZE];
        OsRng.fill_bytes(&mut nonce_base);

        Self {
            cipher,
            nonce_base,
            chunk_counter: 0,
            hasher: blake3::Hasher::new(),
        }
    }

    /// Get the nonce (call once, at the start of encryption)
    ///
    /// This nonce must be transmitted to the receiver before
    /// the encrypted chunks.
    pub fn nonce(&self) -> [u8; NONCE_SIZE] {
        self.nonce_base
    }

    /// Encrypt a chunk of plaintext
    ///
    /// # Arguments
    /// * `plaintext` - Chunk of plaintext data (typically up to CHUNK_SIZE bytes)
    ///
    /// # Returns
    /// Encrypted chunk: [4-byte length][ciphertext + tag]
    pub fn encrypt_chunk(&mut self, plaintext: &[u8]) -> Vec<u8> {
        // Update hash with plaintext
        self.hasher.update(plaintext);

        // Derive per-chunk nonce
        let nonce = self.derive_chunk_nonce();
        self.chunk_counter += 1;

        // Encrypt (includes 16-byte auth tag)
        let ciphertext = self
            .cipher
            .encrypt(&nonce, plaintext)
            .expect("Encryption should not fail with valid key");

        // Format: [4-byte length][ciphertext + tag]
        let len = ciphertext.len() as u32;
        let mut output = Vec::with_capacity(4 + ciphertext.len());
        output.extend_from_slice(&len.to_be_bytes());
        output.extend_from_slice(&ciphertext);

        output
    }

    /// Finalize encryption and return BLAKE3 hash of all plaintext
    ///
    /// # Returns
    /// Hex-encoded BLAKE3 hash of the original plaintext
    pub fn finalize(self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }

    /// Derive per-chunk nonce by XORing counter into base nonce
    fn derive_chunk_nonce(&self) -> XNonce {
        let mut nonce = self.nonce_base;
        // XOR counter into last 8 bytes (big-endian)
        let counter_bytes = self.chunk_counter.to_be_bytes();
        for i in 0..8 {
            nonce[16 + i] ^= counter_bytes[i];
        }
        XNonce::from(nonce)
    }
}

/// Streaming decryptor for server-side use
///
/// Decrypts data in chunks while verifying authentication tags
/// and computing BLAKE3 hash of the decrypted plaintext.
pub struct StreamDecryptor {
    cipher: XChaCha20Poly1305,
    nonce_base: [u8; NONCE_SIZE],
    chunk_counter: u64,
    hasher: blake3::Hasher,
}

impl StreamDecryptor {
    /// Create a new stream decryptor
    ///
    /// # Arguments
    /// * `shared_secret` - 32-byte key derived from hybrid KEM
    /// * `nonce` - 24-byte nonce from encryptor
    pub fn new(shared_secret: &[u8; 32], nonce: [u8; NONCE_SIZE]) -> Self {
        let cipher = XChaCha20Poly1305::new(shared_secret.into());

        Self {
            cipher,
            nonce_base: nonce,
            chunk_counter: 0,
            hasher: blake3::Hasher::new(),
        }
    }

    /// Decrypt a chunk of ciphertext
    ///
    /// # Arguments
    /// * `ciphertext` - Encrypted chunk (ciphertext + 16-byte auth tag, without length prefix)
    ///
    /// # Returns
    /// Decrypted plaintext or authentication error
    ///
    /// # Security
    /// Returns `AuthenticationFailed` if the data has been tampered with
    pub fn decrypt_chunk(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, StreamCipherError> {
        if ciphertext.len() < TAG_SIZE {
            return Err(StreamCipherError::InvalidChunkFormat);
        }

        // Derive per-chunk nonce
        let nonce = self.derive_chunk_nonce();
        self.chunk_counter += 1;

        // Decrypt and verify auth tag
        let plaintext = self
            .cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| StreamCipherError::AuthenticationFailed)?;

        // Update hash with decrypted plaintext
        self.hasher.update(&plaintext);

        Ok(plaintext)
    }

    /// Finalize decryption and return BLAKE3 hash of all decrypted data
    ///
    /// # Returns
    /// Hex-encoded BLAKE3 hash of the decrypted plaintext
    pub fn finalize(self) -> String {
        self.hasher.finalize().to_hex().to_string()
    }

    /// Derive per-chunk nonce by XORing counter into base nonce
    fn derive_chunk_nonce(&self) -> XNonce {
        let mut nonce = self.nonce_base;
        let counter_bytes = self.chunk_counter.to_be_bytes();
        for i in 0..8 {
            nonce[16 + i] ^= counter_bytes[i];
        }
        XNonce::from(nonce)
    }
}

impl Drop for StreamEncryptor {
    fn drop(&mut self) {
        // Zeroize sensitive state
        self.nonce_base.zeroize();
    }
}

impl Drop for StreamDecryptor {
    fn drop(&mut self) {
        self.nonce_base.zeroize();
    }
}

/// Parse encrypted stream data into chunks for decryption
///
/// # Arguments
/// * `data` - Raw encrypted data (after nonce extraction)
///
/// # Returns
/// Iterator over individual encrypted chunks
pub struct ChunkIterator<'a> {
    data: &'a [u8],
    offset: usize,
}

impl<'a> ChunkIterator<'a> {
    /// Create a new chunk iterator
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, offset: 0 }
    }
}

impl<'a> Iterator for ChunkIterator<'a> {
    type Item = Result<&'a [u8], StreamCipherError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.offset >= self.data.len() {
            return None;
        }

        // Read 4-byte length prefix
        if self.offset + 4 > self.data.len() {
            return Some(Err(StreamCipherError::InvalidChunkFormat));
        }

        let len_bytes: [u8; 4] = self.data[self.offset..self.offset + 4]
            .try_into()
            .unwrap();
        let chunk_len = u32::from_be_bytes(len_bytes) as usize;
        self.offset += 4;

        // Read chunk data
        if self.offset + chunk_len > self.data.len() {
            return Some(Err(StreamCipherError::InvalidChunkFormat));
        }

        let chunk = &self.data[self.offset..self.offset + chunk_len];
        self.offset += chunk_len;

        Some(Ok(chunk))
    }
}

/// Extract nonce from the beginning of encrypted stream
///
/// # Arguments
/// * `data` - Raw encrypted stream starting with 24-byte nonce
///
/// # Returns
/// Tuple of (nonce, remaining data)
pub fn extract_nonce(data: &[u8]) -> Result<([u8; NONCE_SIZE], &[u8]), StreamCipherError> {
    if data.len() < NONCE_SIZE {
        return Err(StreamCipherError::NonceMissing);
    }

    let nonce: [u8; NONCE_SIZE] = data[..NONCE_SIZE]
        .try_into()
        .map_err(|_| StreamCipherError::NonceMissing)?;

    Ok((nonce, &data[NONCE_SIZE..]))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }

    #[test]
    fn test_encrypt_decrypt_single_chunk() {
        let key = test_key();
        let plaintext = b"Hello, World!";

        let mut encryptor = StreamEncryptor::new(&key);
        let nonce = encryptor.nonce();
        let encrypted = encryptor.encrypt_chunk(plaintext);
        let enc_hash = encryptor.finalize();

        // Parse chunk (skip 4-byte length prefix)
        let chunk_len = u32::from_be_bytes(encrypted[..4].try_into().unwrap()) as usize;
        let ciphertext = &encrypted[4..4 + chunk_len];

        let mut decryptor = StreamDecryptor::new(&key, nonce);
        let decrypted = decryptor.decrypt_chunk(ciphertext).unwrap();
        let dec_hash = decryptor.finalize();

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
        assert_eq!(enc_hash, dec_hash);
    }

    #[test]
    fn test_encrypt_decrypt_multiple_chunks() {
        let key = test_key();
        let data1 = b"First chunk of data";
        let data2 = b"Second chunk of data";
        let data3 = b"Third chunk of data";

        let mut encryptor = StreamEncryptor::new(&key);
        let nonce = encryptor.nonce();

        let enc1 = encryptor.encrypt_chunk(data1);
        let enc2 = encryptor.encrypt_chunk(data2);
        let enc3 = encryptor.encrypt_chunk(data3);
        let enc_hash = encryptor.finalize();

        let mut decryptor = StreamDecryptor::new(&key, nonce);

        // Parse and decrypt each chunk
        for (encrypted, expected) in [(enc1, data1), (enc2, data2), (enc3, data3)] {
            let chunk_len = u32::from_be_bytes(encrypted[..4].try_into().unwrap()) as usize;
            let ciphertext = &encrypted[4..4 + chunk_len];
            let decrypted = decryptor.decrypt_chunk(ciphertext).unwrap();
            assert_eq!(expected.as_slice(), decrypted.as_slice());
        }

        let dec_hash = decryptor.finalize();
        assert_eq!(enc_hash, dec_hash);
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let key = test_key();
        let plaintext = b"Sensitive data";

        let mut encryptor = StreamEncryptor::new(&key);
        let nonce = encryptor.nonce();
        let mut encrypted = encryptor.encrypt_chunk(plaintext);
        let _ = encryptor.finalize();

        // Tamper with ciphertext
        if let Some(byte) = encrypted.get_mut(10) {
            *byte ^= 0xFF;
        }

        let chunk_len = u32::from_be_bytes(encrypted[..4].try_into().unwrap()) as usize;
        let ciphertext = &encrypted[4..4 + chunk_len];

        let mut decryptor = StreamDecryptor::new(&key, nonce);
        let result = decryptor.decrypt_chunk(ciphertext);

        assert!(matches!(result, Err(StreamCipherError::AuthenticationFailed)));
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key1 = test_key();
        let key2 = test_key();
        let plaintext = b"Secret message";

        let mut encryptor = StreamEncryptor::new(&key1);
        let nonce = encryptor.nonce();
        let encrypted = encryptor.encrypt_chunk(plaintext);
        let _ = encryptor.finalize();

        let chunk_len = u32::from_be_bytes(encrypted[..4].try_into().unwrap()) as usize;
        let ciphertext = &encrypted[4..4 + chunk_len];

        let mut decryptor = StreamDecryptor::new(&key2, nonce);
        let result = decryptor.decrypt_chunk(ciphertext);

        assert!(matches!(result, Err(StreamCipherError::AuthenticationFailed)));
    }

    #[test]
    fn test_chunk_iterator() {
        let key = test_key();
        let chunks = [b"chunk1".as_slice(), b"chunk2".as_slice(), b"chunk3".as_slice()];

        let mut encryptor = StreamEncryptor::new(&key);
        let mut encrypted_data = Vec::new();

        for chunk in &chunks {
            encrypted_data.extend(encryptor.encrypt_chunk(chunk));
        }
        let _ = encryptor.finalize();

        let iter = ChunkIterator::new(&encrypted_data);
        let parsed_chunks: Vec<_> = iter.collect();

        assert_eq!(parsed_chunks.len(), 3);
        for chunk in parsed_chunks {
            assert!(chunk.is_ok());
        }
    }

    #[test]
    fn test_extract_nonce() {
        let key = test_key();
        let encryptor = StreamEncryptor::new(&key);
        let nonce = encryptor.nonce();

        // Simulate wire format
        let mut wire_data = Vec::new();
        wire_data.extend_from_slice(&nonce);
        wire_data.extend_from_slice(b"rest of encrypted data");

        let (extracted_nonce, rest) = extract_nonce(&wire_data).unwrap();

        assert_eq!(nonce, extracted_nonce);
        assert_eq!(rest, b"rest of encrypted data");
    }

    #[test]
    fn test_large_chunk() {
        let key = test_key();
        let large_data = vec![0xABu8; CHUNK_SIZE];

        let mut encryptor = StreamEncryptor::new(&key);
        let nonce = encryptor.nonce();
        let encrypted = encryptor.encrypt_chunk(&large_data);
        let enc_hash = encryptor.finalize();

        let chunk_len = u32::from_be_bytes(encrypted[..4].try_into().unwrap()) as usize;
        let ciphertext = &encrypted[4..4 + chunk_len];

        let mut decryptor = StreamDecryptor::new(&key, nonce);
        let decrypted = decryptor.decrypt_chunk(ciphertext).unwrap();
        let dec_hash = decryptor.finalize();

        assert_eq!(large_data, decrypted);
        assert_eq!(enc_hash, dec_hash);
    }
}
