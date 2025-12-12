//! Key Generation Tool for Secure File Transfer
//!
//! Generates:
//! 1. Hybrid X25519+Kyber-768 keys for the Server (FIPS 203 compliant)
//! 2. Ed25519 Signing keys for Third-Party Senders

use clap::{Parser, Subcommand};
use secure_auth_rs::crypto::{pq_hybrid, signing};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "keygen")]
#[command(about = "Generate cryptographic keys for secure file transfer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate Server Hybrid Keypair (X25519 + Kyber-768)
    Server {
        /// Output directory for keys
        #[arg(short, long, default_value = "keys")]
        output_dir: PathBuf,
    },
    /// Generate Sender Signing Keypair (Ed25519)
    Sender {
        /// Sender ID (e.g., "server2")
        #[arg(short, long)]
        id: String,
        
        /// Output directory for keys
        #[arg(short, long, default_value = "keys/senders")]
        output_dir: PathBuf,
    },
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Server { output_dir } => {
            println!("Generating Server Hybrid Keypair...");
            
            let (sk, pk) = pq_hybrid::generate_keypair();
            
            let sk_path = output_dir.join("server_hybrid.sk");
            let pk_path = output_dir.join("server_hybrid.pk");
            
            pq_hybrid::save_keypair(&sk_path, &pk_path, &sk, &pk)?;
            
            println!("✓ Keys generated successfully:");
            println!("  Secret Key: {} (PROTECT THIS FILE, 0600 permissions set)", sk_path.display());
            println!("  Public Key: {}", pk_path.display());
            
            let fingerprint = pq_hybrid::fingerprint(&pk);
            println!("  Fingerprint: {}", fingerprint);
        }
        Commands::Sender { id, output_dir } => {
            println!("Generating Sender Signing Keypair for '{}'...", id);
            
            let (signing_key, verifying_key) = signing::generate_keypair();
            
            let sk_path = output_dir.join(format!("{}.sk", id));
            let pk_path = output_dir.join(format!("{}.pk", id));
            
            signing::save_keypair(&sk_path, &pk_path, &signing_key)?;
            
            println!("✓ Keys generated successfully:");
            println!("  Secret Key: {} (PROTECT THIS FILE, 0600 permissions set)", sk_path.display());
            println!("  Public Key: {}", pk_path.display());
            println!("  Public Key (Hex): {}", hex::encode(verifying_key.as_bytes()));
            println!("\nTo register this sender, add the hex public key to the 'third_party_senders' table.");
        }
    }

    Ok(())
}
