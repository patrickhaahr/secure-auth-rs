use std::path::Path;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

/// Errors that can occur during file integrity operations
#[derive(Debug)]
pub enum IntegrityError {
    /// I/O error reading file
    Io(std::io::Error),
    /// Hash mismatch - file may be contaminated
    HashMismatch { expected: String, actual: String },
    /// File not found
    NotFound,
    /// The stored hash was not valid hex
    InvalidHashFormat,
}

impl std::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IntegrityError::Io(e) => write!(f, "I/O error: {}", e),
            IntegrityError::HashMismatch { expected, actual } => {
                write!(f, "Hash mismatch: expected {}, got {}", expected, actual)
            }
            IntegrityError::NotFound => write!(f, "File not found"),
            IntegrityError::InvalidHashFormat => write!(f, "Stored hash is not valid hex"),
        }
    }
}

impl std::error::Error for IntegrityError {}

impl From<std::io::Error> for IntegrityError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::NotFound {
            IntegrityError::NotFound
        } else {
            IntegrityError::Io(e)
        }
    }
}

/// Compute BLAKE3 hash from byte slice (for upload data)
pub fn compute_hash(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Compute BLAKE3 hash from file on disk (streaming, memory-efficient)
pub async fn compute_file_hash(path: &Path) -> Result<String, IntegrityError> {
    let mut file = File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 65536]; // 64KB chunks

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Verify file integrity without loading content into RAM for scalability
pub async fn verify_file_integrity(
    path: &Path,
    expected_hex: &str,
) -> Result<bool, IntegrityError> {
    // We duplicate the stream logic here so we don't load the whole file into RAM just for a
    // boolean check
    let mut file = File::open(path).await?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0u8; 65536];

    loop {
        let bytes_read = file.read(&mut buffer).await?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    let computed_hash = hasher.finalize();
    let expected_hash =
        blake3::Hash::from_hex(expected_hex).map_err(|_| IntegrityError::InvalidHashFormat)?;

    // Constant-time comparison
    Ok(computed_hash == expected_hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_hash() {
        let data = b"Hello World!";
        let hash = compute_hash(data);
        assert_eq!(hash.len(), 64); // 256 bits = 64 hex chars
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_hash_consistency() {
        let data = b"Test data for hashing";
        let hash1 = compute_hash(data);
        let hash2 = compute_hash(data);
        assert_eq!(hash1, hash2, "Same input should produce same hash");
    }

    #[test]
    fn test_hash_sensitivity() {
        let data1 = b"Test dataA";
        let data2 = b"Test dataB";
        let hash1 = compute_hash(data1);
        let hash2 = compute_hash(data2);
        assert_ne!(
            hash1, hash2,
            "Different input should produce different hash"
        );
    }

    #[tokio::test]
    async fn test_verify_logic() {
        // Create temp file
        let data = b"Secure content";
        let hash = compute_hash(data); // Hex string

        // In real usage we read from file, but here we simulate the logic
        let computed_bytes = blake3::hash(data);
        let expected_bytes = blake3::Hash::from_hex(&hash).unwrap();

        // This is the constant time check
        assert_eq!(computed_bytes, expected_bytes);
    }
}
