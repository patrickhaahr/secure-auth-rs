//! Third-Party File Sender CLI
//!
//! Uploads files to the Secure Auth Server using:
//! - Hybrid Post-Quantum Encryption (X25519 + Kyber-768)
//! - Streaming Authenticated Encryption (XChaCha20-Poly1305)
//! - Ed25519 Signatures for authentication

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use clap::Parser;
use secure_auth_rs::crypto::{
    pq_hybrid::{self, HybridPublicKey},
    signing,
    stream_cipher::StreamEncryptor,
};
use serde_json::Value;
use std::path::PathBuf;
use tokio::io::AsyncReadExt;

#[derive(Parser)]
#[command(name = "sender")]
#[command(about = "Securely upload files to the Secure Auth Server")]
struct Args {
    /// File to upload
    #[arg(short, long)]
    file: PathBuf,

    /// Server Base URL (e.g. https://localhost:3443)
    #[arg(short, long)]
    server_url: String,

    /// Sender ID (registered on server)
    #[arg(short = 'i', long)]
    sender_id: String,

    /// Path to Sender's Ed25519 Secret Key
    #[arg(short = 'k', long)]
    signing_key: PathBuf,

    /// Path to Server's Hybrid Public Key (optional)
    /// If not provided, it will be fetched from the server (TOFU)
    #[arg(short = 'p', long)]
    server_pk: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // 1. Load or fetch server public key
    let server_pk = match args.server_pk {
        Some(path) => {
            println!("Loading server public key from {:?}", path);
            pq_hybrid::load_public_key(&path)?
        }
        None => {
            println!("Fetching server public key from {}...", args.server_url);
            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true) // For development/testing
                .build()?;
            
            let resp = client.get(format!("{}/api/pqc/public-key", args.server_url)).send().await?;
            let json: Value = resp.json().await?;
            
            let pk_b64 = json["public_key"].as_str().ok_or("Missing public_key")?;
            let pk_bytes = BASE64.decode(pk_b64)?;
            
            let fingerprint = json["fingerprint"].as_str().unwrap_or("unknown");
            println!("⚠️  TOFU: Server key fingerprint: {}", fingerprint);
            println!("    Verify this matches the expected value on first use!");
            
            HybridPublicKey::from_bytes(&pk_bytes)?
        }
    };

    // 2. Load sender signing key
    let signing_key = signing::load_signing_key(&args.signing_key)?;

    // 3. Open file
    println!("Reading file: {:?}", args.file);
    let mut file = tokio::fs::File::open(&args.file).await?;
    let filename = args.file.file_name().unwrap().to_str().unwrap();

    // 4. Encapsulate (Hybrid Key Exchange)
    let (shared_secret, encapsulation) = pq_hybrid::encapsulate(&server_pk)?;

    // 5. Stream encrypt and upload
    let mut encryptor = StreamEncryptor::new(&shared_secret);
    let mut encrypted_body = Vec::new();

    // Add nonce to beginning of stream
    encrypted_body.extend_from_slice(&encryptor.nonce());

    // Stream read and encrypt chunks
    let mut buffer = vec![0u8; 64 * 1024]; // 64KB chunks
    loop {
        let n = file.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        let encrypted_chunk = encryptor.encrypt_chunk(&buffer[..n]);
        encrypted_body.extend(encrypted_chunk);
    }

    let plaintext_hash = encryptor.finalize();
    println!("File hash (BLAKE3): {}", plaintext_hash);

    // 6. Sign the hash
    let signature = signing::sign(&signing_key, plaintext_hash.as_bytes());

    // 7. Upload
    println!("Uploading to {}...", args.server_url);
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true) // For development
        .build()?;

    let response = client
        .post(format!("{}/api/pqc/upload", args.server_url))
        .header("X-Sender-Key-Id", &args.sender_id)
        .header("X-Sender-Signature", BASE64.encode(&signature))
        .header("X-PQC-Encapsulation", BASE64.encode(encapsulation.to_bytes()))
        .header("X-Blake3-Hash", &plaintext_hash)
        .header("X-Filename", filename)
        .header("Content-Type", "application/octet-stream")
        .body(encrypted_body)
        .send()
        .await?;

    if response.status().is_success() {
        let json: Value = response.json().await?;
        println!("✓ Upload successful!");
        println!("  File ID: {}", json["file_id"]);
        println!("  Status: {}", json["status"]);
    } else {
        let status = response.status();
        let text = response.text().await?;
        println!("✗ Upload failed: {} - {}", status, text);
    }

    Ok(())
}
