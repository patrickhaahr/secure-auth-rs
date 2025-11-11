use rand::Rng;
use rand::distr::Alphanumeric;

/// Generates a cryptographically secure 16-character alphanumeric account ID
///
/// # Security Properties
/// - Uses OsRng
/// - 16 characters from [A-Za-z0-9] (62 possible characters)
/// - 95 bits of entropy
pub fn generate_account_id() -> String {
    use rand::rng;

    rng()
        .sample_iter(&Alphanumeric)
        .take(16)
        .map(char::from)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn test_generate_account_id_length() {
        let id = generate_account_id();
        assert_eq!(id.len(), 16, "Account ID must be exactly 16 characters");
    }

    #[test]
    fn test_generate_account_id_alphanumeric() {
        let id = generate_account_id();
        assert!(
            id.chars().all(|c| c.is_ascii_alphanumeric()),
            "Account ID must only contain alphanumeric characters"
        );
    }

    #[test]
    fn test_generate_account_id_uniqueness() {
        let mut ids = HashSet::new();
        for _ in 0..1000 {
            let id = generate_account_id();
            assert!(ids.insert(id), "Generated duplicate account ID");
        }
    }
}
