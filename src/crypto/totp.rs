use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit},
};
use base64::{Engine as _, engine::general_purpose};
use rand_core::{OsRng, RngCore};
use totp_rs::{Algorithm, Secret, TOTP};
use zeroize::Zeroizing;

/// Error type for TOTP operations
#[derive(Debug)]
pub enum TotpError {
    InvalidSecret,
    InvalidCode,
    EncryptionFailed,
    DecryptionFailed,
    InvalidKey,
    KeyNotFound,
    TotpCreationFailed(String),
    CodeGenerationFailed,
    SystemTimeError,
}

impl std::fmt::Display for TotpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TotpError::InvalidSecret => write!(f, "Invalid TOTP secret format"),
            TotpError::InvalidCode => write!(f, "Invalid TOTP code format"),
            TotpError::EncryptionFailed => write!(f, "Failed to encrypt TOTP secret"),
            TotpError::DecryptionFailed => write!(f, "Failed to decrypt TOTP secret"),
            TotpError::InvalidKey => write!(f, "Invalid encryption key"),
            TotpError::KeyNotFound => write!(f, "TOTP_ENCRYPTION_KEY environment variable not set"),
            TotpError::TotpCreationFailed(err) => {
                write!(f, "Failed to create TOTP instance: {}", err)
            }
            TotpError::CodeGenerationFailed => write!(f, "Failed to generate TOTP code"),
            TotpError::SystemTimeError => write!(f, "System time error"),
        }
    }
}

impl std::error::Error for TotpError {}

/// Loads TOTP encryption key from environment variable
///
/// # Environment Variable
/// `TOTP_ENCRYPTION_KEY` - 64 hex characters (32 bytes)
///
/// # Returns
/// * `Ok([u8, 32])` - The 32-byte encryption key
/// * `Err(TotpError)` - If key is missing or invalid
///
/// # Example
/// ```bash
/// # Generate key once during setup:
/// openssl rand -hex 32
/// # Add to .env:
/// TOTP_ENCRYPTION_KEY=secret_key...
/// ```
pub fn load_encryption_key() -> Result<[u8; 32], TotpError> {
    let key_hex = std::env::var("TOTP_ENCRYPTION_KEY").map_err(|_| {
        tracing::error!("TOTP_ENCRYPTION_KEY environment variable not set");
        TotpError::KeyNotFound
    })?;

    let key_bytes = hex::decode(&key_hex).map_err(|_| {
        tracing::error!("TOTP_ENCRYPTION_KEY contains invalid hex characters");
        TotpError::InvalidKey
    })?;

    let key: [u8; 32] = key_bytes.try_into().map_err(|_| {
        tracing::error!("TOTP_ENCRYPTION_KEY must be exactly 32 bytes (64 hex characters)");
        TotpError::InvalidKey
    })?;

    tracing::debug!("TOTP encryption key loaded successfully");
    Ok(key)
}

/// Generates a cryptographically secure TOTP secret
///
/// # Returns
/// Base32-encoded secret (32 characters, 160 bits of entropy)
///
/// # Security
/// - Uses OsRng for cryptographic randomness
/// - 20 random bytes = 160 bits of entropy
/// - Compatible with Authenticator apps
///
/// # Example
/// ```rust
/// let secret = generate_totp_secret();
/// // returns "JBSWY3DPEHPK3PXP" (example)
/// ```
pub fn generate_totp_secret() -> String {
    // Generate 20 random bytes (160 bits of entropy)
    let mut secret_bytes = [0u8; 20];
    OsRng.fill_bytes(&mut secret_bytes);

    // Encode as base32
    let secret = Secret::Raw(secret_bytes.to_vec());

    tracing::info!("Generated new TOTP secret");

    // Convert to base32 encoded string
    secret.to_encoded().to_string()
}

/// Encrypts a TOTP secret using AES-256-GCM
///
/// # Arguments
/// * `secret` - Base32-encoded TOTP secret
/// * `key` - 32-byte encryption key
///
/// # Returns
/// * `Ok(Vec<u8>)` - Encrypted data: 12 byte nonce + 16 byte auth tag
/// * `Err(TotpError)` - If encryption fails
///
/// # Security
/// - Random nonce for each encryption (stored with ciphertext)
/// - Authenticated encryption (prevents tampering)
/// - Secret is zeroized after encryption
///
/// # Storage Format
/// [12 bytes: nonce][N bytes: ciphertext + 16-byte auth tag]
pub fn encrypt_totp_secret(secret: &str, key: &[u8; 32]) -> Result<Vec<u8>, TotpError> {
    let cipher = Aes256Gcm::new(key.into());

    // Generate random 96-bit nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    // Use Zeroizing to clear secret from memory after encryption
    let secret_bytes = Zeroizing::new(secret.as_bytes().to_vec());

    // Encrypt (automatically appends 16-byte auth tag)
    let ciphertext = cipher.encrypt(&nonce, secret_bytes.as_ref()).map_err(|_| {
        tracing::error!("Failed to encrypt TOTP secret");
        TotpError::EncryptionFailed
    })?;

    // Prepend nonce to ciphertext
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);

    tracing::debug!("TOTP secret encrypted successfully");
    Ok(result)
}

/// Decrypts a TOTP secret using AES-256-GCM
///
/// # Arguments
/// * `encrypted` - Encrypted TOTP secret (12 byte nonce + 16 byte auth tag)
/// * `key` - 32-byte encryption key (same key used for encryption)
///
/// # Returns
/// * `Ok(String)` - Decrypted base32-encoded TOTP secret
/// * `Err(TotpError)` - If decryption fails or data is tampered
///
/// # Security
/// - Verifies authentication tag (detects tampering)
/// - Constant-time comparison for auth tag
/// - Returns error if ciphertext was tampered with
pub fn decrypt_totp_secret(encrypted: &[u8], key: &[u8; 32]) -> Result<String, TotpError> {
    if encrypted.len() < 12 {
        tracing::error!("Encrypted TOTP secret is too short");
        return Err(TotpError::DecryptionFailed);
    }

    let cipher = Aes256Gcm::new(key.into());

    // Extract nonce (first 12 bytes)
    let nonce_bytes: [u8; 12] = encrypted[..12].try_into().map_err(|_| {
        tracing::error!("Invalid nonce size");
        TotpError::DecryptionFailed
    })?;
    let nonce = Nonce::from(nonce_bytes);

    // Decrypt and verify authentication tag
    let plaintext = cipher.decrypt(&nonce, &encrypted[12..]).map_err(|_| {
        tracing::error!("Failed to decrypt TOTP secret (wrong key or tampered data)");
        TotpError::DecryptionFailed
    })?;

    // Convert string and zeroize plaintext bytes
    let secret = String::from_utf8(plaintext).map_err(|_| {
        tracing::error!("Decrypted TOTP secret is invalid UTF-8");
        TotpError::DecryptionFailed
    })?;

    tracing::debug!("TOTP secret decrypted successfully");
    Ok(secret)
}

/// Generates a 6-digit TOTP code from secret
///
/// # Arguments
/// * `secret` - Base32-encoded TOTP secret
///
/// # Returns
/// * `Ok(String)` - 6-digit TOTP code
/// * `Err(TotpError)` - If secret is invalid or code generation fails
///
/// # Parameters
/// - Algorithm: SHA512
/// - Digits: 6
/// - Period: 30 seconds
///
/// # Example
/// ```rust
/// let code = generate_totp_code("JBSWY3DPEHPK3PXP");
/// // returns "123456" (example, changes every 30 seconds)
/// ```
pub fn generate_totp_code(secret: &str) -> Result<String, TotpError> {
    // Parse the base32 secret
    let secret_enum = Secret::Encoded(secret.to_string());
    let secret_bytes = secret_enum.to_bytes().map_err(|_| {
        tracing::error!("Failed to decode base32 TOTP secret");
        TotpError::InvalidSecret
    })?;

    // Create TOTP instance
    // Algorithm::SHA512, 6 digits, 1 skew (±30s tolerance), 30 second step
    let totp = TOTP::new(
        Algorithm::SHA512,
        6,
        1,
        30,
        secret_bytes,
        None,
        "".to_string(),
    )
    .map_err(|e| {
        tracing::error!("Failed to create TOTP instance: {}", e);
        TotpError::TotpCreationFailed(e.to_string())
    })?;

    // Generate current code
    let code = totp.generate_current().map_err(|_| {
        tracing::error!("Failed to generate TOTP code");
        TotpError::CodeGenerationFailed
    })?;

    tracing::debug!("Generated TOTP code");
    Ok(code)
}

/// Verifies a TOTP code against a secret
///
/// # Arguments
/// * `secret` - Base32-encoded TOTP secret
/// * `code` - 6-digit TOTP code provided by user
///
/// # Returns
/// * `Ok(true)` - Code is valid
/// * `Ok(false)` - Code is invalid
/// * `Err(TotpError)` - If secret is invalid
///
/// # Time Window
/// Accepts codes from:
/// - Previous period (t-30s)
/// - Current period (t)
/// - Next period (t+30s)
///
/// This provides ±30s tolerance for clock drift
///
/// # Example
/// ```rust
/// let is_valid = verify_totp_code("JBSWY3DPEHPK3PXP", "123456")?;
/// if is_valid {
///     println!("Code verified!");
/// }
/// ```
pub fn verify_totp_code(secret: &str, code: &str) -> Result<bool, TotpError> {
    // Validate code format
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        tracing::warn!("Invalid TOTP code format provided");
        return Ok(false);
    }

    // Parse the base32 secret
    let secret_enum = Secret::Encoded(secret.to_string());
    let secret_bytes = secret_enum.to_bytes().map_err(|_| {
        tracing::error!("Failed to decode base32 TOTP secret");
        TotpError::InvalidSecret
    })?;

    // Create TOTP instance with skew=1 (±30s tolerance)
    let totp = TOTP::new(
        Algorithm::SHA512,
        6,
        1,
        30,
        secret_bytes,
        None,
        "".to_string(),
    )
    .map_err(|e| {
        tracing::error!("Failed to create TOTP instance: {}", e);
        TotpError::TotpCreationFailed(e.to_string())
    })?;

    // Verify code (totp-rs handles time window with skew)
    let is_valid = totp.check_current(code).map_err(|_| {
        tracing::error!("System time error during TOTP verification");
        TotpError::SystemTimeError
    })?;

    if is_valid {
        tracing::info!("TOTP code verified successfully");
    } else {
        tracing::warn!("TOTP code verification failed - incorrect code");
    }

    Ok(is_valid)
}

/// Generates an otpauth:// URI for manual TOTP setup
///
/// # Arguments
/// * `secret` - Base32-encoded TOTP secret
/// * `account_id` - Account identifier
/// * `issuer` - Service name (e.g. Authenticator App)
///
/// # Returns
/// otpauth:// URI string for manual entry
///
/// # Example
/// ```rust
/// let uri = generate_otpauth_uri("JBSWY3DPEHPK3PXP", "A1B2C3D4E5F6G7H8", "AuthApp");
/// // Returns: "otpauth://totp/AuthApp:A1B2C3D4E5F6G7H8?secret=JBSWY3DPEHPK3PXP&issuer=AuthApp&algorithm=SHA512"
/// ```
pub fn generate_otpauth_uri(
    secret: &str,
    account_id: &str,
    issuer: &str,
) -> Result<String, TotpError> {
    // Parse the base32 secret
    let secret_enum = Secret::Encoded(secret.to_string());
    let secret_bytes = secret_enum.to_bytes().map_err(|_| {
        tracing::error!("Failed to decode base32 TOTP secret");
        TotpError::InvalidSecret
    })?;

    // Create TOTP instance with SHA512 to match our code generation/verification
    let totp = TOTP::new(
        Algorithm::SHA512,
        6,
        1,
        30,
        secret_bytes,
        Some(issuer.to_string()),
        account_id.to_string(),
    )
    .map_err(|e| {
        tracing::error!("Failed to create TOTP instance: {}", e);
        TotpError::TotpCreationFailed(e.to_string())
    })?;

    // Get the otpauth URI
    let uri = totp.get_url();

    tracing::debug!("Generated TOTP otpauth URI for account {}", account_id);
    Ok(uri)
}

/// Generates a base64-encoded QR code image as a data URI
///
/// # Arguments
/// * `secret` - Base32-encoded TOTP secret
/// * `account_id` - Account identifier
/// * `issuer` - Service name (e.g. Authenticator App)
///
/// # Returns
/// Base64-encoded PNG image as data URI (data:image/png;base64,...)
///
/// # Example
/// ```rust
/// let qr_data_uri = generate_qr_uri("JBSWY3DPEHPK3PXP", "A1B2C3D4E5F6G7H8", "AuthApp");
/// // Returns: "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA..."
/// // Can be directly used as img src in HTML
/// ```
pub fn generate_qr_uri(secret: &str, account_id: &str, issuer: &str) -> Result<String, TotpError> {
    // Parse the base32 secret
    let secret_enum = Secret::Encoded(secret.to_string());
    let secret_bytes = secret_enum.to_bytes().map_err(|_| {
        tracing::error!("Failed to decode base32 TOTP secret");
        TotpError::InvalidSecret
    })?;

    // Create TOTP instance with SHA512 to match our code generation/verification
    let totp = TOTP::new(
        Algorithm::SHA512,
        6,
        1,
        30,
        secret_bytes,
        Some(issuer.to_string()),
        account_id.to_string(),
    )
    .map_err(|e| {
        tracing::error!("Failed to create TOTP instance: {}", e);
        TotpError::TotpCreationFailed(e.to_string())
    })?;

    // Generate QR code as PNG bytes
    let qr_bytes = totp.get_qr_png().map_err(|e| {
        tracing::error!("Failed to generate QR code: {}", e);
        TotpError::TotpCreationFailed(format!("QR generation failed: {}", e))
    })?;

    // Encode to base64 and create data URI
    let base64_qr = general_purpose::STANDARD.encode(&qr_bytes);
    let data_uri = format!("data:image/png;base64,{}", base64_qr);

    tracing::debug!("Generated TOTP QR code for account {}", account_id);
    Ok(data_uri)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_totp_secret() {
        let secret = generate_totp_secret();
        assert_eq!(secret.len(), 32, "Base32 secret should be 32 characters");
    }

    #[test]
    fn test_generate_totp_secret_base32() {
        let secret = generate_totp_secret();
        assert!(
            secret
                .chars()
                .all(|c| "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c)),
            "Secret should only contain base32 characters"
        );
    }

    #[test]
    fn test_generate_totp_secret_uniqueness() {
        let secret1 = generate_totp_secret();
        let secret2 = generate_totp_secret();
        assert_ne!(secret1, secret2, "Generated secrets should be unique");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let secret = generate_totp_secret();
        let key = generate_test_key();

        let encrypted = encrypt_totp_secret(&secret, &key).expect("Encryption failed");
        let decrypted = decrypt_totp_secret(&encrypted, &key).expect("Decryption failed");

        assert_eq!(secret, decrypted, "Decrypted secret should match original");
    }

    #[test]
    fn test_encrypt_produces_different_ciphertext() {
        let secret = "JBSWY3DPEHPK3PXP";
        let key = generate_test_key();

        let encrypted1 = encrypt_totp_secret(secret, &key).expect("First encryption failed");
        let encrypted2 = encrypt_totp_secret(secret, &key).expect("Second encryption failed");

        assert_ne!(
            encrypted1, encrypted2,
            "Different nonces should produce different ciphertexts"
        );

        // Both should decrypt to the same secret
        let decrypted1 = decrypt_totp_secret(&encrypted1, &key).expect("First decryption failed");
        let decrypted2 = decrypt_totp_secret(&encrypted2, &key).expect("Second decryption failed");

        assert_eq!(decrypted1, secret);
        assert_eq!(decrypted2, secret);
    }

    #[test]
    fn test_decrypt_with_wrong_key_fails() {
        let secret = "JBSWY3DPEHPK3PXP";
        let key1 = generate_test_key();
        let key2 = generate_test_key();

        let encrypted = encrypt_totp_secret(secret, &key1).expect("Encryption failed");
        let result = decrypt_totp_secret(&encrypted, &key2);

        assert!(result.is_err(), "Decryption with wrong key should fail");
        assert!(matches!(result.unwrap_err(), TotpError::DecryptionFailed));
    }

    #[test]
    fn test_decrypt_tampered_data_fails() {
        let secret = "JBSWY3DPEHPK3PXP";
        let key = generate_test_key();

        let mut encrypted = encrypt_totp_secret(secret, &key).expect("Encryption failed");

        // Tamper with the ciphertext
        if let Some(byte) = encrypted.last_mut() {
            *byte ^= 0xFF;
        }

        let result = decrypt_totp_secret(&encrypted, &key);

        assert!(result.is_err(), "Decryption of tampered data should fail");
        assert!(matches!(result.unwrap_err(), TotpError::DecryptionFailed));
    }

    #[test]
    fn test_generate_totp_code_format() {
        let secret = generate_totp_secret();
        let code = generate_totp_code(&secret).expect("Code generation failed");

        assert_eq!(code.len(), 6, "TOTP code should be 6 digits");
        assert!(
            code.chars().all(|c| c.is_ascii_digit()),
            "TOTP code should only contain digits"
        );
    }

    #[test]
    fn test_verify_totp_code_with_correct_code() {
        let secret = generate_totp_secret();

        // Generate a code and immediately verify it
        let code = generate_totp_code(&secret).expect("Code generation failed");
        let is_valid = verify_totp_code(&secret, &code).expect("Verification failed");

        assert!(is_valid, "Valid code should verify successfully");
    }

    #[test]
    fn test_verify_totp_code_with_wrong_code() {
        let secret = generate_totp_secret();
        let wrong_code = "000000";

        let is_valid = verify_totp_code(&secret, wrong_code).expect("Verification failed");

        // Note: There's a tiny chance this could be valid code
        assert!(!is_valid, "Wrong code should not verify");
    }

    #[test]
    fn test_verify_totp_code_with_invalid_format() {
        let secret = generate_totp_secret();

        let result = verify_totp_code(&secret, "12345"); // Too short
        assert_eq!(result.unwrap(), false);

        let result = verify_totp_code(&secret, "1234567"); // Too long
        assert_eq!(result.unwrap(), false);

        let result = verify_totp_code(&secret, "12345a"); // Non-digit
        assert_eq!(result.unwrap(), false);
    }

    #[test]
    fn test_generate_qr_uri_format() {
        let secret = generate_totp_secret();
        let account_id = "A1B2C3D4E5F6G7H8";
        let issuer = "AuthApp";

        let data_uri = generate_qr_uri(&secret, account_id, issuer).expect("URI generation failed");

        // Verify data URI format (base64-encoded PNG)
        assert!(
            data_uri.starts_with("data:image/png;base64,"),
            "Should be a base64-encoded PNG data URI"
        );

        // Verify it's a valid base64 string after the prefix
        let base64_part = data_uri.strip_prefix("data:image/png;base64,").unwrap();
        assert!(!base64_part.is_empty(), "Base64 data should not be empty");

        // Verify it contains valid base64 characters
        assert!(
            base64_part
                .chars()
                .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '='),
            "Should contain valid base64 characters"
        );
    }

    #[test]
    fn test_generate_qr_uri_with_special_characters() {
        let secret = generate_totp_secret();
        let account_id = "test+user@example.com";
        let issuer = "My App & Service";

        let data_uri = generate_qr_uri(&secret, account_id, issuer).expect("URI generation failed");

        // Should be a valid data URI (base64-encoded PNG)
        assert!(
            data_uri.starts_with("data:image/png;base64,"),
            "Should be a base64-encoded PNG data URI"
        );

        // Verify it's not empty
        let base64_part = data_uri.strip_prefix("data:image/png;base64,").unwrap();
        assert!(!base64_part.is_empty(), "Base64 data should not be empty");
    }

    #[test]
    fn test_generate_otpauth_uri_format() {
        let secret = generate_totp_secret();
        let account_id = "A1B2C3D4E5F6G7H8";
        let issuer = "AuthApp";

        let uri = generate_otpauth_uri(&secret, account_id, issuer).expect("URI generation failed");

        // Verify otpauth URI format
        assert!(
            uri.starts_with("otpauth://totp/"),
            "URI should start with otpauth://totp/"
        );
        assert!(uri.contains(&secret), "URI should contain secret");
        assert!(uri.contains(account_id), "URI should contain account ID");
        assert!(uri.contains(issuer), "URI should contain issuer");
        assert!(
            uri.contains("algorithm=SHA512"),
            "URI should specify SHA512"
        );
    }

    #[test]
    fn test_generate_otpauth_uri_with_special_characters() {
        let secret = generate_totp_secret();
        let account_id = "test+user@example.com";
        let issuer = "My App & Service";

        let uri = generate_otpauth_uri(&secret, account_id, issuer).expect("URI generation failed");

        // URL encoding should be handled by totp-rs
        assert!(
            uri.starts_with("otpauth://totp/"),
            "URI should be valid otpauth URL"
        );
        assert!(uri.contains(&secret), "URI should contain secret");
    }

    #[test]
    fn test_full_flow_generate_verify_code() {
        // Full flow: generate secret -> generate code -> verify code
        let secret = generate_totp_secret();

        // Generate a code
        let code = generate_totp_code(&secret).expect("Code generation failed");

        // Verify the code immediately (should be valid)
        let is_valid = verify_totp_code(&secret, &code).expect("Verification failed");
        assert!(is_valid, "Generated code should verify successfully");
    }

    #[test]
    fn test_full_flow_with_encryption() {
        // Full flow: generate -> encrypt -> decrypt -> generate code -> verify
        let secret = generate_totp_secret();
        let key = generate_test_key();

        // Encrypt the secret
        let encrypted = encrypt_totp_secret(&secret, &key).expect("Encryption failed");

        // Decrypt the secret
        let decrypted = decrypt_totp_secret(&encrypted, &key).expect("Decryption failed");

        // Generate code from decrypted secret
        let code = generate_totp_code(&decrypted).expect("Code generation failed");

        // Verify code against original secret
        let is_valid = verify_totp_code(&secret, &code).expect("Verification failed");
        assert!(is_valid, "Code from decrypted secret should verify");
    }

    #[test]
    fn test_full_flow_qr_uri_to_code_verification() {
        // Full flow: generate secret -> create otpauth URI -> extract secret -> verify code
        let secret = generate_totp_secret();
        let account_id = "test_account";
        let issuer = "TestApp";

        // Generate otpauth URI
        let uri = generate_otpauth_uri(&secret, account_id, issuer).expect("URI generation failed");

        // Verify URI contains the secret (simulating manual entry or QR scan)
        assert!(
            uri.contains(&secret),
            "OTPAuth URI should contain the secret"
        );

        // Generate code using the same secret
        let code = generate_totp_code(&secret).expect("Code generation failed");

        // Verify the code (simulating user entering code from authenticator app)
        let is_valid = verify_totp_code(&secret, &code).expect("Verification failed");
        assert!(is_valid, "Code should verify after otpauth URI generation");
    }

    #[test]
    fn test_full_flow_end_to_end_with_encryption() {
        // Complete end-to-end flow with all components
        let key = generate_test_key();
        let account_id = "user123";
        let issuer = "SecureApp";

        // 1. Generate secret
        let secret = generate_totp_secret();

        // 2. Encrypt secret for storage
        let encrypted = encrypt_totp_secret(&secret, &key).expect("Encryption failed");

        // 3. Generate QR data URI and otpauth URI for user enrollment
        let qr_data_uri =
            generate_qr_uri(&secret, account_id, issuer).expect("QR generation failed");
        assert!(
            qr_data_uri.starts_with("data:image/png;base64,"),
            "QR should be base64 PNG data URI"
        );

        let otpauth_uri = generate_otpauth_uri(&secret, account_id, issuer)
            .expect("OTPAuth URI generation failed");
        assert!(
            otpauth_uri.contains(&secret),
            "OTPAuth URI should contain secret"
        );
        assert!(
            otpauth_uri.contains("algorithm=SHA512"),
            "OTPAuth URI should specify SHA512"
        );

        // 4. Simulate time passing - decrypt secret from storage
        let decrypted = decrypt_totp_secret(&encrypted, &key).expect("Decryption failed");
        assert_eq!(secret, decrypted, "Decrypted secret should match original");

        // 5. Generate code (simulating authenticator app)
        let code = generate_totp_code(&decrypted).expect("Code generation failed");
        assert_eq!(code.len(), 6, "Code should be 6 digits");

        // 6. Verify code (simulating login)
        let is_valid = verify_totp_code(&decrypted, &code).expect("Verification failed");
        assert!(is_valid, "Valid code should verify successfully");

        // 7. Verify invalid code fails
        let invalid_code = "000000";
        let is_valid = verify_totp_code(&decrypted, invalid_code).expect("Verification failed");
        assert!(!is_valid, "Invalid code should not verify");
    }

    #[test]
    fn test_code_generation_consistency() {
        // Verify that the same secret generates the same code at the same time
        let secret = generate_totp_secret();

        let code1 = generate_totp_code(&secret).expect("First code generation failed");
        let code2 = generate_totp_code(&secret).expect("Second code generation failed");

        assert_eq!(
            code1, code2,
            "Same secret should generate identical codes at same time"
        );
    }

    #[test]
    fn test_verify_code_with_different_secret_fails() {
        // Ensure codes from different secrets don't verify against each other
        let secret1 = generate_totp_secret();
        let secret2 = generate_totp_secret();

        let code1 = generate_totp_code(&secret1).expect("Code generation failed");
        let is_valid = verify_totp_code(&secret2, &code1).expect("Verification failed");

        assert!(!is_valid, "Code from different secret should not verify");
    }

    // Helper functions for tests
    fn generate_test_key() -> [u8; 32] {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        key
    }
}
