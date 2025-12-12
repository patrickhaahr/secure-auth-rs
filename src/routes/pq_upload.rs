//! Post-Quantum Cryptography File Upload Routes
//!
//! Endpoints for third-party servers to upload encrypted files
//! using hybrid X25519+Kyber-768 key exchange and XChaCha20-Poly1305 encryption.

use crate::{
    crypto::{
        pq_hybrid::{self, HybridEncapsulation},
        signing,
        stream_cipher::{self, ChunkIterator, StreamDecryptor},
    },
    db::{files_models::AuditAction, files_repository},
    AppState,
};
use axum::{
    Json,
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::BytesMut;
use futures::StreamExt;
use serde::Serialize;
use std::path::PathBuf;
use tokio::io::AsyncWriteExt;

/// Storage directory for third-party uploads
const UPLOAD_DIR: &str = "files/uploads";

// ============================================================================
// Request/Response Types
// ============================================================================

#[derive(Debug, Serialize)]
pub struct PublicKeyResponse {
    /// Base64-encoded hybrid public key
    pub public_key: String,
    /// BLAKE3 fingerprint for TOFU verification
    pub fingerprint: String,
    /// Algorithm description
    pub algorithm: String,
}

#[derive(Debug, Serialize)]
pub struct UploadResponse {
    pub file_id: String,
    pub filename: String,
    pub blake3_hash: String,
    pub file_size: i64,
    pub status: String,
}

#[derive(Debug, Serialize)]
pub struct ErrorResponse {
    pub error: String,
    pub code: String,
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Ensure upload directory exists
async fn ensure_upload_dir() -> Result<(), std::io::Error> {
    tokio::fs::create_dir_all(UPLOAD_DIR).await
}

/// Get storage path for uploaded file
fn get_upload_path(blake3_hash: &str) -> PathBuf {
    PathBuf::from(UPLOAD_DIR).join(format!("{}.bin", blake3_hash))
}

/// Sanitize filename to prevent path traversal
fn sanitize_filename(filename: &str) -> String {
    filename
        .chars()
        .filter(|c| !matches!(c, '/' | '\\' | '\0' | ':' | '*' | '?' | '"' | '<' | '>' | '|'))
        .take(255)
        .collect()
}

/// Extract and validate required header
fn get_required_header(headers: &HeaderMap, name: &str) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Missing required header: {}", name),
                    code: "MISSING_HEADER".to_string(),
                }),
            )
        })
}

// ============================================================================
// Route Handlers
// ============================================================================

/// GET /api/pqc/public-key
///
/// Returns the server's hybrid public key for third-party servers
/// to use when encrypting file uploads.
///
/// # Response
/// - `public_key`: Base64-encoded X25519+Kyber-768 public key
/// - `fingerprint`: BLAKE3 hash for TOFU (Trust On First Use) verification
/// - `algorithm`: "X25519+Kyber768"
pub async fn get_public_key(
    State(state): State<AppState>,
) -> Result<Json<PublicKeyResponse>, (StatusCode, Json<ErrorResponse>)> {
    let pk_bytes = state.pq_public_key.to_bytes();
    let fingerprint = pq_hybrid::fingerprint(&state.pq_public_key);

    tracing::info!(
        fingerprint = %fingerprint,
        "Public key requested by third-party"
    );

    Ok(Json(PublicKeyResponse {
        public_key: BASE64.encode(&pk_bytes),
        fingerprint,
        algorithm: "X25519+Kyber768".to_string(),
    }))
}

/// POST /api/pqc/upload
///
/// Receives encrypted file uploads from authorized third-party servers.
///
/// # Headers
/// - `X-Sender-Key-Id`: Sender's registered ID
/// - `X-Sender-Signature`: Base64 Ed25519 signature of BLAKE3 hash
/// - `X-PQC-Encapsulation`: Base64 hybrid encapsulation data
/// - `X-Blake3-Hash`: Expected BLAKE3 hash of plaintext (hex)
/// - `X-Filename`: Original filename
///
/// # Body
/// Encrypted stream: [24-byte nonce][encrypted chunks...]
///
/// # Security
/// 1. Verifies sender is authorized and active
/// 2. Verifies Ed25519 signature over claimed hash
/// 3. Decapsulates hybrid KEM to recover shared secret
/// 4. Stream decrypts and verifies each chunk's auth tag
/// 5. Verifies BLAKE3 hash matches claimed hash
/// 6. Stores file in quarantine for admin approval
pub async fn upload(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: Body,
) -> Result<Json<UploadResponse>, (StatusCode, Json<ErrorResponse>)> {
    // =========================================================================
    // 1. Parse and validate headers
    // =========================================================================
    let sender_id = get_required_header(&headers, "X-Sender-Key-Id")?;
    let signature_b64 = get_required_header(&headers, "X-Sender-Signature")?;
    let encapsulation_b64 = get_required_header(&headers, "X-PQC-Encapsulation")?;
    let claimed_hash = get_required_header(&headers, "X-Blake3-Hash")?;
    let filename = get_required_header(&headers, "X-Filename")?;

    let sanitized_filename = sanitize_filename(&filename);

    tracing::info!(
        sender_id = %sender_id,
        filename = %sanitized_filename,
        "Processing third-party upload"
    );

    // =========================================================================
    // 2. Verify sender is authorized and active
    // =========================================================================
    let sender = files_repository::get_sender(&state.files_db, &sender_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error fetching sender");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    code: "DB_ERROR".to_string(),
                }),
            )
        })?
        .ok_or_else(|| {
            tracing::warn!(sender_id = %sender_id, "Unknown sender attempted upload");
            (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Unknown sender".to_string(),
                    code: "UNKNOWN_SENDER".to_string(),
                }),
            )
        })?;

    if !sender.is_active {
        tracing::warn!(sender_id = %sender_id, "Disabled sender attempted upload");
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Sender is disabled".to_string(),
                code: "SENDER_DISABLED".to_string(),
            }),
        ));
    }

    // =========================================================================
    // 3. Verify Ed25519 signature over the claimed hash
    // =========================================================================
    let signature_bytes = BASE64.decode(&signature_b64).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signature encoding".to_string(),
                code: "INVALID_SIGNATURE".to_string(),
            }),
        )
    })?;

    let signature: [u8; 64] = signature_bytes.try_into().map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid signature length".to_string(),
                code: "INVALID_SIGNATURE".to_string(),
            }),
        )
    })?;

    let sender_pk = signing::verifying_key_from_hex(&sender.ed25519_public_key).map_err(|_| {
        tracing::error!(sender_id = %sender_id, "Invalid stored public key");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Invalid sender configuration".to_string(),
                code: "CONFIG_ERROR".to_string(),
            }),
        )
    })?;

    signing::verify(&sender_pk, claimed_hash.as_bytes(), &signature).map_err(|_| {
        tracing::warn!(sender_id = %sender_id, "Signature verification failed");
        (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Signature verification failed".to_string(),
                code: "INVALID_SIGNATURE".to_string(),
            }),
        )
    })?;

    tracing::debug!(sender_id = %sender_id, "Signature verified");

    // =========================================================================
    // 4. Decapsulate hybrid KEM to recover shared secret
    // =========================================================================
    let encap_bytes = BASE64.decode(&encapsulation_b64).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid encapsulation encoding".to_string(),
                code: "INVALID_ENCAPSULATION".to_string(),
            }),
        )
    })?;

    let encapsulation = HybridEncapsulation::from_bytes(&encap_bytes).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Invalid encapsulation format".to_string(),
                code: "INVALID_ENCAPSULATION".to_string(),
            }),
        )
    })?;

    let shared_secret = pq_hybrid::decapsulate(&state.pq_secret_key, &encapsulation).map_err(|e| {
        tracing::error!(error = ?e, "Decapsulation failed");
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Decapsulation failed".to_string(),
                code: "DECAPSULATION_FAILED".to_string(),
            }),
        )
    })?;

    tracing::debug!("Hybrid decapsulation successful");

    // =========================================================================
    // 5. Stream decrypt body to temp file
    // =========================================================================
    ensure_upload_dir().await.map_err(|e| {
        tracing::error!(error = %e, "Failed to create upload directory");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Storage error".to_string(),
                code: "STORAGE_ERROR".to_string(),
            }),
        )
    })?;

    let temp_id = uuid::Uuid::new_v4();
    let temp_path = PathBuf::from(UPLOAD_DIR).join(format!("{}.tmp", temp_id));

    let mut temp_file = tokio::fs::File::create(&temp_path).await.map_err(|e| {
        tracing::error!(error = %e, "Failed to create temp file");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Storage error".to_string(),
                code: "STORAGE_ERROR".to_string(),
            }),
        )
    })?;

    // Collect body into buffer (for streaming we'd use a more sophisticated approach)
    let mut stream = body.into_data_stream();
    let mut body_buffer = BytesMut::new();

    while let Some(chunk_result) = stream.next().await {
        let chunk = chunk_result.map_err(|e| {
            tracing::error!(error = %e, "Stream read error");
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Upload stream error".to_string(),
                    code: "STREAM_ERROR".to_string(),
                }),
            )
        })?;
        body_buffer.extend_from_slice(&chunk);
    }

    // Extract nonce from beginning of stream
    let (nonce, encrypted_data) = stream_cipher::extract_nonce(&body_buffer).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Missing nonce in encrypted stream".to_string(),
                code: "MISSING_NONCE".to_string(),
            }),
        )
    })?;

    // Create decryptor
    let mut decryptor = StreamDecryptor::new(&shared_secret, nonce);
    let mut file_size: u64 = 0;

    // Decrypt chunks
    let chunk_iter = ChunkIterator::new(encrypted_data);
    for chunk_result in chunk_iter {
        let ciphertext = chunk_result.map_err(|_| {
            // Cleanup temp file
            let _ = std::fs::remove_file(&temp_path);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Invalid chunk format".to_string(),
                    code: "INVALID_CHUNK".to_string(),
                }),
            )
        })?;

        let plaintext = decryptor.decrypt_chunk(ciphertext).map_err(|e| {
            tracing::error!(error = ?e, "Chunk decryption failed - possible tampering");
            // Cleanup temp file
            let _ = std::fs::remove_file(&temp_path);
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: "Decryption failed - data may be tampered".to_string(),
                    code: "DECRYPTION_FAILED".to_string(),
                }),
            )
        })?;

        file_size += plaintext.len() as u64;
        temp_file.write_all(&plaintext).await.map_err(|e| {
            tracing::error!(error = %e, "Write error");
            let _ = std::fs::remove_file(&temp_path);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Storage write error".to_string(),
                    code: "STORAGE_ERROR".to_string(),
                }),
            )
        })?;
    }

    temp_file.flush().await.map_err(|e| {
        tracing::error!(error = %e, "Flush error");
        let _ = std::fs::remove_file(&temp_path);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Storage error".to_string(),
                code: "STORAGE_ERROR".to_string(),
            }),
        )
    })?;

    // =========================================================================
    // 6. Verify BLAKE3 hash
    // =========================================================================
    let computed_hash = decryptor.finalize();

    if computed_hash != claimed_hash {
        tracing::error!(
            expected = %claimed_hash,
            computed = %computed_hash,
            sender_id = %sender_id,
            "Hash mismatch - rejecting upload"
        );
        let _ = tokio::fs::remove_file(&temp_path).await;
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Hash verification failed".to_string(),
                code: "HASH_MISMATCH".to_string(),
            }),
        ));
    }

    tracing::debug!(hash = %computed_hash, "Hash verified");

    // =========================================================================
    // 7. Move to final location and record in database
    // =========================================================================
    let final_path = get_upload_path(&computed_hash);

    // Check if physical file already exists (deduplication)
    let existing = files_repository::get_physical_file(&state.files_db, &computed_hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Database error");
            let _ = std::fs::remove_file(&temp_path);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    code: "DB_ERROR".to_string(),
                }),
            )
        })?;

    if existing.is_some() {
        // File already exists - deduplicate
        let _ = tokio::fs::remove_file(&temp_path).await;
        files_repository::increment_ref_count(&state.files_db, &computed_hash)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "Failed to increment ref_count");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: "Database error".to_string(),
                        code: "DB_ERROR".to_string(),
                    }),
                )
            })?;
        tracing::info!(hash = %computed_hash, "File deduplicated");
    } else {
        // New file - move to final location
        tokio::fs::rename(&temp_path, &final_path).await.map_err(|e| {
            tracing::error!(error = %e, "Failed to move file");
            let _ = std::fs::remove_file(&temp_path);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Storage error".to_string(),
                    code: "STORAGE_ERROR".to_string(),
                }),
            )
        })?;

        // Insert physical file record
        files_repository::insert_physical_file(
            &state.files_db,
            &computed_hash,
            file_size as i64,
            final_path.to_string_lossy().as_ref(),
        )
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Failed to insert physical file");
            let _ = std::fs::remove_file(&final_path);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: "Database error".to_string(),
                    code: "DB_ERROR".to_string(),
                }),
            )
        })?;
    }

    // Insert logical file record (quarantined)
    let file_id = uuid::Uuid::now_v7().to_string();
    let file_type = mime_guess::from_path(&sanitized_filename)
        .first_or_octet_stream()
        .to_string();

    files_repository::insert_third_party_file(
        &state.files_db,
        &file_id,
        &sanitized_filename,
        &file_type,
        &computed_hash,
        &sender_id,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "Failed to insert file metadata");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: "Database error".to_string(),
                code: "DB_ERROR".to_string(),
            }),
        )
    })?;

    // Update sender's last upload timestamp
    let _ = files_repository::update_sender_last_upload(&state.files_db, &sender_id).await;

    // Audit log
    let _ = files_repository::log_audit(
        &state.files_db,
        &file_id,
        &sanitized_filename,
        &computed_hash,
        AuditAction::ThirdPartyUpload,
        &sender_id,
        None,
        Some(&format!(
            r#"{{"sender_id": "{}", "file_size": {}, "origin": "third_party"}}"#,
            sender_id, file_size
        )),
    )
    .await;

    tracing::info!(
        file_id = %file_id,
        filename = %sanitized_filename,
        hash = %computed_hash,
        size = %file_size,
        sender_id = %sender_id,
        "Third-party file uploaded successfully (quarantined)"
    );

    Ok(Json(UploadResponse {
        file_id,
        filename: sanitized_filename,
        blake3_hash: computed_hash,
        file_size: file_size as i64,
        status: "quarantine".to_string(),
    }))
}
