use super::models::{Account, CprData, Passkey, TotpSecret};
use sqlx::{Pool, Sqlite};

// Account
pub async fn create_account(
    pool: &Pool<Sqlite>,
    id: &str,
) -> Result<Account, sqlx::Error> {
    let result = sqlx::query_as::<_, Account>(
        r#"
        INSERT INTO accounts (id, created_at)
        VALUES (?, datetime('now'))
        RETURNING id, created_at
        "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await;

    match &result {
        Ok(account) => tracing::info!(account_id = %account.id, "Account created"),
        Err(e) => tracing::error!(account_id = %id, error = %e, "Failed to create account"),
    }

    result
}

pub async fn account_exists(pool: &Pool<Sqlite>, id: &str) -> Result<bool, sqlx::Error> {
    let result: (i64,) = sqlx::query_as(
        r#"
            SELECT COUNT(*) FROM accounts WHERE id = ?
            "#,
    )
    .bind(id)
    .fetch_one(pool)
    .await?;

    Ok(result.0 > 0)
}

pub async fn delete_account(pool: &Pool<Sqlite>, id: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
            DELETE FROM accounts WHERE id = ?
            "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    let rows_affected = result.rows_affected();
    if rows_affected > 0 {
        tracing::info!(account_id = %id, "Account deleted");
    } else {
        tracing::warn!(account_id = %id, "Attempted to delete non-existent account");
    }

    Ok(rows_affected)
}

// Account Role
pub async fn is_admin(pool: &Pool<Sqlite>, account_id: &str) -> Result<bool, sqlx::Error> {
    let result: Option<(bool,)> = sqlx::query_as(
        r#"
            SELECT is_admin FROM account_roles WHERE account_id = ?
            "#,
    )
    .bind(account_id)
    .fetch_optional(pool)
    .await?;

    let is_admin = result.map(|r| r.0).unwrap_or(false);
    tracing::debug!(account_id = %account_id, is_admin = %is_admin, "Admin privilege check");

    Ok(is_admin)
}

// CPR data
pub async fn insert_cpr_data(
    pool: &Pool<Sqlite>,
    account_id: &str,
    cpr_hash: &str,
) -> Result<CprData, sqlx::Error> {
    let result = sqlx::query_as::<_, CprData>(
        r#"
        INSERT INTO cpr_data (account_id, cpr_hash, verified_at)
        VALUES (?, ?, datetime('now'))
        RETURNING account_id, cpr_hash, verified_at
        "#,
    )
    .bind(account_id)
    .bind(cpr_hash)
    .fetch_one(pool)
    .await;

    match &result {
        Ok(_) => tracing::info!("CPR data inserted and verified"),
        Err(e) => tracing::error!(error = %e, "Failed to insert CPR data"),
    }

    result
}

pub async fn cpr_hash_exists(pool: &Pool<Sqlite>, cpr_hash: &str) -> Result<bool, sqlx::Error> {
    use tokio::time::{sleep, Duration, Instant};

    let start = Instant::now();
    
    let result: (i64,) = sqlx::query_as(
        r#"
            SELECT COUNT(*) FROM cpr_data WHERE cpr_hash = ?
            "#,
    )
    .bind(cpr_hash)
    .fetch_one(pool)
    .await?;

    // Ensure minimum 50ms response time to prevent timing attacks
    let elapsed = start.elapsed();
    if elapsed < Duration::from_millis(50) {
        sleep(Duration::from_millis(50) - elapsed).await;
    }

    Ok(result.0 > 0)
}

// Passkey
pub async fn insert_passkey(
    pool: &Pool<Sqlite>,
    id: &str,
    account_id: &str,
    credential_id: &[u8],
    public_key: &[u8],
    aaguid: &[u8],
    attestation_type: &str,
    nickname: Option<&str>,
) -> Result<Passkey, sqlx::Error> {
    let result = sqlx::query_as::<_, Passkey>(
        r#"
        INSERT INTO passkeys (
            id, account_id, credential_id, public_key, sign_count,
            aaguid, attestation_type, nickname, created_at, last_used_at 
        )
        VALUES (?, ?, ?, ?, 0, ?, ?, ?, datetime('now'), NULL)
        RETURNING id, account_id, credential_id, public_key,
            sign_count, aaguid, attestation_type, nickname, created_at, last_used_at
        "#,
    )
    .bind(id)
    .bind(account_id)
    .bind(credential_id)
    .bind(public_key)
    .bind(aaguid)
    .bind(attestation_type)
    .bind(nickname)
    .fetch_one(pool)
    .await;

    match &result {
        Ok(passkey) => tracing::info!(
            passkey_id = %passkey.id,
            account_id = %account_id,
            nickname = ?nickname,
            "Passkey registered"
        ),
        Err(e) => tracing::error!(
            account_id = %account_id,
            error = %e,
            "Failed to register passkey"
        ),
    }

    result
}

pub async fn find_passkeys_by_account(
    pool: &Pool<Sqlite>,
    account_id: &str,
) -> Result<Vec<Passkey>, sqlx::Error> {
    sqlx::query_as::<_, Passkey>(
        r#"
        SELECT id, account_id, credential_id, public_key, 
               sign_count, aaguid, attestation_type, nickname,
               created_at, last_used_at
        FROM passkeys
        WHERE account_id = ?
        ORDER BY created_at DESC
        "#,
    )
    .bind(account_id)
    .fetch_all(pool)
    .await
}

pub async fn update_passkey_usage(
    pool: &Pool<Sqlite>,
    credential_id: &[u8],
    new_sign_count: u32,
) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE passkeys
        SET sign_count = ?, last_used_at = datetime('now')
        WHERE credential_id = ?
        "#,
    )
    .bind(new_sign_count)
    .bind(credential_id)
    .execute(pool)
    .await?;

    let rows_affected = result.rows_affected();
    if rows_affected > 0 {
        tracing::info!(
            sign_count = %new_sign_count,
            "Passkey used successfully"
        );
    } else {
        tracing::warn!("Attempted to update non-existent passkey");
    }

    Ok(rows_affected)
}

pub async fn delete_passkey(pool: &Pool<Sqlite>, id: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM passkeys WHERE id = ?
        "#,
    )
    .bind(id)
    .execute(pool)
    .await?;

    let rows_affected = result.rows_affected();
    if rows_affected > 0 {
        tracing::info!(passkey_id = %id, "Passkey deleted");
    } else {
        tracing::warn!(passkey_id = %id, "Attempted to delete non-existent passkey");
    }

    Ok(rows_affected)
}

// TOTP Secret
pub async fn insert_totp_secret(
    pool: &Pool<Sqlite>,
    account_id: &str,
    secret_encrypted: &[u8],
) -> Result<TotpSecret, sqlx::Error> {
    let result = sqlx::query_as::<_, TotpSecret>(
        r#"
        INSERT INTO totp_secrets (
            account_id, secret_encrypted, algorithm, 
            digits, period, is_verified, created_at
        )
        VALUES (?, ?, 'SHA1', 6, 30, 0, datetime('now'))
        RETURNING account_id, secret_encrypted, algorithm, 
                  digits, period, is_verified, created_at
        "#,
    )
    .bind(account_id)
    .bind(secret_encrypted)
    .fetch_one(pool)
    .await;

    match &result {
        Ok(_) => tracing::info!(account_id = %account_id, "TOTP secret created (unverified)"),
        Err(e) => tracing::error!(account_id = %account_id, error = %e, "Failed to create TOTP secret"),
    }

    result
}

pub async fn verify_totp(pool: &Pool<Sqlite>, account_id: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        UPDATE totp_secrets
        SET is_verified = 1
        WHERE account_id = ?
        "#,
    )
    .bind(account_id)
    .execute(pool)
    .await?;

    let rows_affected = result.rows_affected();
    if rows_affected > 0 {
        tracing::info!(account_id = %account_id, "TOTP verified with valid code");
    } else {
        tracing::warn!(account_id = %account_id, "Attempted to verify non-existent TOTP");
    }

    Ok(rows_affected)
}

pub async fn delete_totp_secret(pool: &Pool<Sqlite>, account_id: &str) -> Result<u64, sqlx::Error> {
    let result = sqlx::query(
        r#"
        DELETE FROM totp_secrets WHERE account_id = ?
        "#,
    )
    .bind(account_id)
    .execute(pool)
    .await?;

    let rows_affected = result.rows_affected();
    if rows_affected > 0 {
        tracing::info!(account_id = %account_id, "TOTP secret deleted");
    } else {
        tracing::warn!(account_id = %account_id, "Attempted to delete non-existent TOTP secret");
    }

    Ok(rows_affected)
}
