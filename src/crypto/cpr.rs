use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand_core::OsRng;
use zeroize::Zeroizing;

/// Error type for CPR hashing operations
#[derive(Debug)]
pub enum CprHashError {
    InvalidParams,
    HashingFailed,
    VerificationFailed,
    InvalidHash,
    InvalidFormat,
}

impl std::fmt::Display for CprHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CprHashError::InvalidParams => write!(f, "Invalid parameters for CPR hashing"),
            CprHashError::HashingFailed => write!(f, "CPR hashing failed"),
            CprHashError::VerificationFailed => write!(f, "CPR verification failed"),
            CprHashError::InvalidHash => write!(f, "Invalid hash"),
            CprHashError::InvalidFormat => write!(f, "Invalid CPR format"),
        }
    }
}

impl std::error::Error for CprHashError {}

/// Validates Danish CPR number format
///
/// # Format
/// CPR format: DDMMYY-XXXX
/// - DD: Day (01-31)
/// - MM: Month (01-12)
/// - YY: Year (00-99)
/// - XXXX: 4-digit sequence number
///
/// # Arguments
/// * `cpr` - The CPR number string to validate
///
/// # Returns
/// * `Ok(())` - CPR format is valid
/// * `Err(CprHashError::InvalidFormat)` - CPR format is invalid
fn validate_cpr_format(cpr: &str) -> Result<(), CprHashError> {
    // Check length and hyphen position
    if cpr.len() != 11 {
        return Err(CprHashError::InvalidFormat);
    }

    if cpr.chars().nth(6) != Some('-') {
        return Err(CprHashError::InvalidFormat);
    }

    // Extract parts
    let date_part = &cpr[..6];
    let sequence_part = &cpr[7..];

    // Validate all digits in date part
    if !date_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(CprHashError::InvalidFormat);
    }

    // Validate all digits in sequence part
    if !sequence_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(CprHashError::InvalidFormat);
    }

    // Parse day, month, year
    let day: u32 = date_part[..2].parse().map_err(|_| CprHashError::InvalidFormat)?;
    let month: u32 = date_part[2..4].parse().map_err(|_| CprHashError::InvalidFormat)?;
    let _year: u32 = date_part[4..6].parse().map_err(|_| CprHashError::InvalidFormat)?;

    // Validate day range
    if day < 1 || day > 31 {
        return Err(CprHashError::InvalidFormat);
    }

    // Validate month range
    if month < 1 || month > 12 {
        return Err(CprHashError::InvalidFormat);
    }

    Ok(())
}

/// Creates an Argon2id instance with recommended parameters for CPR hashing
///
/// Parameters:
/// - Memory cost: 19456 KiB (19 MiB)
/// - Time cost: 2 iterations
/// - Parallelism: 1 thread - suitable for SQLite
fn get_argon2_hasher() -> Result<Argon2<'static>, CprHashError> {
    let params = Params::new(
        19456, 2, 1, None, // default output length (32 bytes)
    )
    .map_err(|_| CprHashError::InvalidParams)?;

    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// Hashes a CPR number using Argon2id
///
/// # Arguments
/// * `cpr` - format: "DDMMYY-XXXX"
///
/// # Returns
/// * `Ok(String)` - PHC string format containing algorithm, version, params, salt, and hash
/// * `Err(CprHashError)` - if hashing fails
///
/// # Security
/// - Uses cryptographically secure random salt
/// - Returns PHC format: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
/// - Safe to store in database
/// # Example
/// ```
/// let hash = hash_cpr("010190-1234")?;
/// // Returns: "$argon2id$v=19$m=19456,t=2,p=1$..."
/// ```
pub fn hash_cpr(cpr: &str) -> Result<String, CprHashError> {
    validate_cpr_format(cpr)?;

    let argon2 = get_argon2_hasher()?;
    let salt = SaltString::generate(&mut OsRng);

    // Use Zeroizing to ensure CPR bytes are cleared from memory
    let cpr_bytes = Zeroizing::new(cpr.as_bytes().to_vec());
    let cpr_hash = argon2
        .hash_password(&cpr_bytes, &salt)
        .map_err(|_| CprHashError::HashingFailed)?;

    Ok(cpr_hash.to_string())
}

/// Verifies a CPR number against a stored Argon2id hash
///
/// # Arguments
/// * cpr - The CPR number to verify
/// * hash - The stored PHC format hash string
///
/// # Returns
/// * Ok(true) - CPR matches the hash
/// * Ok(false) - CPR does not match the hash
/// * Err(CprHashError) - if the hash is invalid or verification fails
///
/// # Security
/// - Constant-time comparison (handled by Argon2)
/// - Extracts and uses salt from stored hash
/// - Validates algorithm, version and params
///
/// # Example
/// ```
/// let is_valid = verify_cpr("010190-1234", &stored_hash)?;
/// if is_valid {
///     println!("CPR verified successfully");
/// }
/// ```
pub fn verify_cpr(cpr: &str, hash: &str) -> Result<bool, CprHashError> {
    validate_cpr_format(cpr)?;

    let argon2 = get_argon2_hasher()?;

    let parsed_hash = PasswordHash::new(hash).map_err(|_| CprHashError::InvalidHash)?;

    // Use Zeroizing to ensure CPR bytes are cleared from memory
    let cpr_bytes = Zeroizing::new(cpr.as_bytes().to_vec());

    match argon2.verify_password(&cpr_bytes, &parsed_hash) {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::PasswordHash;

    #[test]
    fn test_hash_cpr_produces_valid_phc_format() {
        let cpr = "010190-1234";
        let hash_str = hash_cpr(cpr).expect("Failed to hash CPR");

        // Parse the PHC string - this validates the entire structure
        let parsed = PasswordHash::new(&hash_str).expect("Hash should be valid PHC format");

        assert_eq!(
            parsed.algorithm.as_str(),
            "argon2id",
            "Hash must use argon2id algorithm"
        );
        assert_eq!(
            parsed.version.unwrap(),
            19,
            "Hash must use Argon2 version 19"
        );

        // Validate security parameters
        let params = parsed.params;
        assert_eq!(
            params.get("m").unwrap().decimal().unwrap(),
            19456,
            "Memory cost must be 19456 KiB"
        );
        assert_eq!(
            params.get("t").unwrap().decimal().unwrap(),
            2,
            "Time cost must be 2 iterations"
        );
        assert_eq!(
            params.get("p").unwrap().decimal().unwrap(),
            1,
            "Parallelism must be 1 thread"
        );

        // Ensure salt and hash are present
        assert!(
            !parsed.salt.unwrap().as_str().is_empty(),
            "Salt must be present"
        );
        assert!(
            parsed.hash.is_some(),
            "Hash must be present"
        );
    }

    #[test]
    fn test_verify_cpr_success() {
        let cpr = "010190-1234";
        let hash = hash_cpr(cpr).expect("Failed to hash CPR");

        let is_valid = verify_cpr(cpr, &hash).expect("Verification should not fail");

        assert!(
            is_valid,
            "Valid CPR should verify successfully against its hash"
        );
    }

    #[test]
    fn test_salt_is_random_salt() {
        let cpr = "010190-1234";
        let hash1 = hash_cpr(cpr).expect("First hash failed");
        let hash2 = hash_cpr(cpr).expect("Second hash failed");

        // Different salts must produce different hashes
        assert_ne!(hash1, hash2, "Hashes must be unique due to random salt");

        // Both hashes must be valid
        assert!(
            verify_cpr(cpr, &hash1).expect("First verification failed"),
            "First hash should verify"
        );
        assert!(
            verify_cpr(cpr, &hash2).expect("Second verification failed"),
            "Second hash should verify"
        );
    }

    #[test]
    fn test_verify_cpr_with_wrong_cpr() {
        let cpr = "010190-1234";
        let wrong_cpr = "020190-5678";
        let hash = hash_cpr(cpr).expect("Failed to hash CPR");

        let is_valid = verify_cpr(wrong_cpr, &hash).expect("Verification should not fail");

        assert!(
            !is_valid,
            "Wrong CPR should not verify successfully"
        );
    }

    #[test]
    fn test_verify_cpr_with_invalid_hash_format() {
        let cpr = "010190-1234";
        let invalid_hash = "not-a-valid-phc-hash";

        let result = verify_cpr(cpr, invalid_hash);

        assert!(
            result.is_err(),
            "Invalid hash format should return an error"
        );
        assert!(
            matches!(result.unwrap_err(), CprHashError::InvalidHash),
            "Should return InvalidHash error"
        );
    }

    #[test]
    fn test_hash_cpr_with_invalid_format_no_hyphen() {
        let invalid_cpr = "0101901234"; // Missing hyphen
        let result = hash_cpr(invalid_cpr);

        assert!(
            result.is_err(),
            "Invalid CPR format should return an error"
        );
        assert!(
            matches!(result.unwrap_err(), CprHashError::InvalidFormat),
            "Should return InvalidFormat error"
        );
    }

    #[test]
    fn test_hash_cpr_with_invalid_format_wrong_hyphen_position() {
        let invalid_cpr = "010190-12-34"; // Extra hyphen
        let result = hash_cpr(invalid_cpr);

        assert!(result.is_err(), "CPR with wrong format should be invalid");
    }

    #[test]
    fn test_hash_cpr_with_invalid_day() {
        let invalid_cpr = "000190-1234"; // Day 00
        let result = hash_cpr(invalid_cpr);

        assert!(result.is_err(), "Day 00 should be invalid");
        
        let invalid_cpr = "320190-1234"; // Day 32
        let result = hash_cpr(invalid_cpr);

        assert!(result.is_err(), "Day 32 should be invalid");
    }

    #[test]
    fn test_hash_cpr_with_invalid_month() {
        let invalid_cpr = "010090-1234"; // Month 00
        let result = hash_cpr(invalid_cpr);

        assert!(result.is_err(), "Month 00 should be invalid");
        
        let invalid_cpr = "011390-1234"; // Month 13
        let result = hash_cpr(invalid_cpr);

        assert!(result.is_err(), "Month 13 should be invalid");
    }

    #[test]
    fn test_hash_cpr_with_non_numeric_characters() {
        let invalid_cpr = "01019A-1234"; // Letter in date
        let result = hash_cpr(invalid_cpr);

        assert!(result.is_err(), "Non-numeric characters should be invalid");
        
        let invalid_cpr = "010190-12X4"; // Letter in sequence
        let result = hash_cpr(invalid_cpr);

        assert!(result.is_err(), "Non-numeric characters should be invalid");
    }

    #[test]
    fn test_verify_cpr_with_empty_string() {
        let empty_cpr = "";
        let valid_cpr = "010190-1234";
        let hash = hash_cpr(valid_cpr).expect("Failed to hash CPR");

        let result = verify_cpr(empty_cpr, &hash);

        assert!(
            result.is_err(),
            "Empty CPR should return an error"
        );
        assert!(
            matches!(result.unwrap_err(), CprHashError::InvalidFormat),
            "Should return InvalidFormat error"
        );
    }

    #[test]
    fn test_validate_cpr_format_edge_cases() {
        // Valid edge cases
        assert!(hash_cpr("311299-9999").is_ok(), "Max valid day and month");
        assert!(hash_cpr("010100-0000").is_ok(), "Min valid values");
        
        // Test various valid dates
        assert!(hash_cpr("150685-1234").is_ok(), "Valid mid-range date");
        assert!(hash_cpr("291095-5678").is_ok(), "Valid October date");
    }
}
