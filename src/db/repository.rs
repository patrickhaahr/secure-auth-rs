use super::models::{Account, AccountRole, CprData, Passkey, TotpSecret};
use sqlx::{Pool, Sqlite};

// Account
pub async fn create_account(
    pool: &Pool<Sqlite>,
    id: &str,
    account_id: &str,
) -> Result<Account, sqlx::Error> {
    sqlx::query_as::<_, Account>(
        r#"
        INSERT INTO accounts (id, account_id, created_at)
        VALUES (?, ?, datetime('now'))
        RETURNING id, account_id, created_at
        "#,
    )
    .bind(id)
    .bind(account_id)
    .fetch_one(pool)
    .await
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

    Ok(result.rows_affected())
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

    Ok(result.map(|r| r.0).unwrap_or(false))
}

// CPR data
pub async fn insert_cpr_data(
    pool: &Pool<Sqlite>,
    account_id: &str,
    cpr_encrypted: &[u8],
    cpr_hash: &str,
) -> Result<CprData, sqlx::Error> {
    sqlx::query_as::<_, CprData>(
        r#"
        INSERT INTO cpr_data (account_id, cpr_encrypted, cpr_hash, verified_at)
        VALUES (?, ?, ?, datetime('now'))
        RETURNING id, account_id, cpr_encrypted, cpr_hash, verified_at
        "#,
    )
    .bind(account_id)
    .bind(cpr_encrypted)
    .bind(cpr_hash)
    .fetch_one(pool)
    .await
}

pub async fn cpr_hash_exists(pool: &Pool<Sqlite>, cpr_hash: &str) -> Result<bool, sqlx::Error> {
    let result: (i64,) = sqlx::query_as(
        r#"
            SELECT COUNT(*) FROM cpr_data WHERE cpr_hash = ?
            "#,
    )
    .bind(cpr_hash)
    .fetch_one(pool)
    .await?;

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
) -> Result<Passkey, sqlx::Error> {
    sqlx::query_as::<_, Passkey>(
        r#"
        INSERT INTO passkeys (
            id, account_id, credential_id, public_key, sign_count,
            aaguid, attestation_type, created_at, last_used_at 
        )
        VALUES (?, ?, ?, ?, 0, ?, ?, datetime('now'), NULL)
        RETURNING id, account_id, credential_id, public_key,
            sign_count, aaguid, attestation_type, created_at, last_used_at
        "#,
    )
    .bind(id)
    .bind(account_id)
    .bind(credential_id)
    .bind(public_key)
    .bind(aaguid)
    .bind(attestation_type)
    .fetch_one(pool)
    .await
}

pub async fn find_passkeys_by_account(
    pool: &Pool<Sqlite>,
    account_id: &str,
) -> Result<Vec<Passkey>, sqlx::Error> {
    sqlx::query_as::<_, Passkey>(
        r#"
        SELECT id, account_id, credential_id, public_key, 
               sign_count, aaguid, attestation_type, 
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
    new_sign_count: i32,
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
    Ok(result.rows_affected())
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
    Ok(result.rows_affected())
}

// TOTP Secret
pub async fn insert_totp_secret(
    pool: &Pool<Sqlite>,
    account_id: &str,
    secret_encrypted: &[u8],
) -> Result<TotpSecret, sqlx::Error> {
    sqlx::query_as::<_, TotpSecret>(
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
    .await
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
    Ok(result.rows_affected())
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
    Ok(result.rows_affected())
}
