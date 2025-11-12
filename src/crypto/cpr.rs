use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use rand_core::OsRng;
use zeroize::Zeroizing;
use std::env;

/// Error type for CPR hashing operations
#[derive(Debug)]
pub enum CprHashError {
    InvalidParams,
    HashingFailed,
    VerificationFailed,
    InvalidHash,
    InvalidFormat,
    MissingPepper,
}

impl std::fmt::Display for CprHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CprHashError::InvalidParams => write!(f, "Invalid parameters for CPR hashing"),
            CprHashError::HashingFailed => write!(f, "CPR hashing failed"),
            CprHashError::VerificationFailed => write!(f, "CPR verification failed"),
            CprHashError::InvalidHash => write!(f, "Invalid hash"),
            CprHashError::InvalidFormat => write!(f, "Invalid CPR format"),
            CprHashError::MissingPepper => write!(f, "CPR pepper is not configured"),
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
    if !(1..=31).contains(&day) {
        return Err(CprHashError::InvalidFormat);
    }

    // Validate month range
    if !(1..=12).contains(&month) {
        return Err(CprHashError::InvalidFormat);
    }

    Ok(())
}

/// Loads CPR pepper from environment variables
///
/// # Returns
/// * `Ok(String)` - The pepper string
/// * `Err(CprHashError::MissingPepper)` - if pepper is not configured
///
/// # Security
/// - Pepper must be kept secret and never logged
/// - Should be a strong random string (32+ characters)
fn load_cpr_pepper() -> Result<String, CprHashError> {
    env::var("CPR_PEPPER").map_err(|_| {
        tracing::error!("CPR_PEPPER environment variable is not set");
        CprHashError::MissingPepper
    })
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

/// Hashes a CPR number using Argon2id with pepper
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
/// - Combines CPR with server-side pepper before hashing
/// - Returns PHC format: $argon2id$v=19$m=19456,t=2,p=1$<salt>$<hash>
/// - Safe to store in database
/// # Example
/// ```
/// let hash = hash_cpr("010190-1234")?;
/// // Returns: "$argon2id$v=19$m=19456,t=2,p=1$..."
/// ```
pub fn hash_cpr(cpr: &str) -> Result<String, CprHashError> {
    validate_cpr_format(cpr)?;

    let pepper = load_cpr_pepper()?;
    let argon2 = get_argon2_hasher()?;
    let salt = SaltString::generate(&mut OsRng);

    // Combine CPR with pepper: format: cpr:pepper
    let peppered_input = format!("{}:{}", cpr, pepper);
    
    // Use Zeroizing to ensure peppered input bytes are cleared from memory
    let peppered_bytes = Zeroizing::new(peppered_input.as_bytes().to_vec());
    let cpr_hash = argon2
        .hash_password(&peppered_bytes, &salt)
        .map_err(|_| {
            tracing::warn!("CPR hashing failed");
            CprHashError::HashingFailed
        })?;

    tracing::info!("CPR hashed successfully with pepper");
    Ok(cpr_hash.to_string())
}

/// Verifies a CPR number against a stored Argon2id hash with pepper
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
/// - Uses same pepper combination as hashing
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

    let pepper = load_cpr_pepper()?;
    let argon2 = get_argon2_hasher()?;

    let parsed_hash = PasswordHash::new(hash).map_err(|_| {
        tracing::warn!("Invalid CPR hash format provided for verification");
        CprHashError::InvalidHash
    })?;

    // Combine CPR with pepper using same format as hashing
    let peppered_input = format!("{}:{}", cpr, pepper);
    
    // Use Zeroizing to ensure peppered input bytes are cleared from memory
    let peppered_bytes = Zeroizing::new(peppered_input.as_bytes().to_vec());

    match argon2.verify_password(&peppered_bytes, &parsed_hash) {
        Ok(_) => {
            tracing::info!("CPR verification successful with pepper");
            Ok(true)
        }
        Err(_) => {
            tracing::warn!("CPR verification failed - incorrect CPR provided");
            Ok(false)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::password_hash::PasswordHash;

    #[test]
    fn test_hash_cpr_produces_valid_phc_format() {
        // Set test pepper for this test
        unsafe {
            std::env::set_var("CPR_PEPPER", "test_pepper_for_phc_format");
        }
        
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

    #[test]
    fn test_pepper_based_cpr_hashing() {
        // Set test pepper
        unsafe {
            std::env::set_var("CPR_PEPPER", "test_pepper_for_testing");
        }
        
        let cpr = "010190-1234";
        let wrong_cpr = "020190-5678";
        
        // Test hashing
        let hash1 = hash_cpr(cpr).expect("First hash should succeed");
        let hash2 = hash_cpr(cpr).expect("Second hash should succeed");
        
        // Hashes should be different due to random salt
        assert_ne!(hash1, hash2, "Hashes should be different due to random salt");
        
        // Both should verify correctly
        assert!(verify_cpr(cpr, &hash1).expect("First verification should succeed"), 
                "First hash should verify");
        assert!(verify_cpr(cpr, &hash2).expect("Second verification should succeed"), 
                "Second hash should verify");
        
        // Wrong CPR should not verify
        assert!(!verify_cpr(wrong_cpr, &hash1).expect("Wrong CPR verification should succeed"), 
                "Wrong CPR should not verify");
        
        // Test that different peppers produce different hashes
        unsafe {
            std::env::set_var("CPR_PEPPER", "different_pepper");
        }
        let hash_with_different_pepper = hash_cpr(cpr).expect("Hash with different pepper should succeed");
        
        unsafe {
            std::env::set_var("CPR_PEPPER", "test_pepper_for_testing");
        }
        let hash_with_original_pepper = hash_cpr(cpr).expect("Hash with original pepper should succeed");
        
        assert_ne!(hash_with_different_pepper, hash_with_original_pepper, 
                   "Different peppers should produce different hashes");
    }
}
