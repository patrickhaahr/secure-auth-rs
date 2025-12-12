#!/bin/bash
# Setup script for PQ File Transfer System
# Generates keys and registers sender in database

set -e  # Exit on any error

echo "🔐 PQ File Transfer System Setup"
echo "================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SENDER_ID="server2"
SENDER_NAME="External Server 2"
KEYS_DIR="keys"
SENDERS_DIR="$KEYS_DIR/senders"
TEST_FILE="test-file.txt"

echo -e "${BLUE}Step 1: Generate Server Hybrid Keypair${NC}"
echo "----------------------------------------"

if [ ! -d "$KEYS_DIR" ]; then
    mkdir -p "$KEYS_DIR"
fi

# Generate server keys
cargo run --bin keygen -- server --output-dir "$KEYS_DIR"
echo -e "${GREEN}✓ Server keys generated in $KEYS_DIR${NC}"

echo
echo -e "${BLUE}Step 2: Generate Sender Signing Keypair${NC}"
echo "------------------------------------------"

if [ ! -d "$SENDERS_DIR" ]; then
    mkdir -p "$SENDERS_DIR"
fi

# Generate sender keys
cargo run --bin keygen -- sender --id "$SENDER_ID" --output-dir "$SENDERS_DIR"
echo -e "${GREEN}✓ Sender keys generated for $SENDER_ID${NC}"

echo
echo -e "${BLUE}Step 3: Register Sender in Database${NC}"
echo "-------------------------------------"

# Check if files.db exists
if [ ! -f "files.db" ]; then
    echo -e "${RED}✗ files.db not found. Please run migrations first.${NC}"
    exit 1
fi

# Extract the public key
PUBLIC_KEY=$(cat "$SENDERS_DIR/$SENDER_ID.pk")

# Insert into database (SQLite)
sqlite3 files.db <<EOF
INSERT OR REPLACE INTO third_party_senders (id, name, ed25519_public_key, is_active, created_at)
VALUES ('$SENDER_ID', '$SENDER_NAME', '$PUBLIC_KEY', 1, datetime('now'));
EOF

echo -e "${GREEN}✓ Sender $SENDER_ID registered in database${NC}"

# Verify insertion
echo "Sender details:"
sqlite3 files.db "SELECT id, name, is_active, created_at FROM third_party_senders WHERE id = '$SENDER_ID';"

echo
echo -e "${BLUE}Step 4: Create Test File${NC}"
echo "--------------------"

# Create test file
cat > "$TEST_FILE" <<EOF
This is a top secret document from $SENDER_ID.

Content for testing:
- Timestamp: $(date)
- Server fingerprint: $(cargo run --bin keygen -- server --output-dir "$KEYS_DIR" 2>&1 | grep fingerprint | cut -d' ' -f3)
- Security level: Maximum (Post-Quantum)
- Encryption: Hybrid X25519 + Kyber-768
- Auth: Ed25519 signatures
- Storage: XChaCha20-Poly1305

This file should be encrypted, quarantined, and approved before access.
EOF

echo -e "${GREEN}✓ Test file created: $TEST_FILE${NC}"

echo
echo -e "${BLUE}Step 5: Update .env Configuration${NC}"
echo "-----------------------------------"

# Check if .env exists and add PQ key paths if not present
if [ -f ".env" ]; then
    if ! grep -q "PQ_SECRET_KEY_PATH" .env; then
        echo "" >> .env
        echo "# Post-Quantum Cryptography Keys" >> .env
        echo "PQ_SECRET_KEY_PATH=$KEYS_DIR/server_hybrid.sk" >> .env
        echo "PQ_PUBLIC_KEY_PATH=$KEYS_DIR/server_hybrid.pk" >> .env
        echo -e "${GREEN}✓ Added PQ key paths to .env${NC}"
    else
        echo -e "${YELLOW}⚠ PQ key paths already exist in .env${NC}"
    fi
else
    echo "# Post-Quantum Cryptography Keys" > .env
    echo "PQ_SECRET_KEY_PATH=$KEYS_DIR/server_hybrid.sk" >> .env
    echo "PQ_PUBLIC_KEY_PATH=$KEYS_DIR/server_hybrid.pk" >> .env
    echo -e "${GREEN}✓ Created .env with PQ key paths${NC}"
fi

echo
echo -e "${BLUE}Step 6: Verification${NC}"
echo "----------------"

# Verify all files exist
echo "Checking generated files:"
echo -e "  ${GREEN}✓${NC} Server secret key: $KEYS_DIR/server_hybrid.sk"
echo -e "  ${GREEN}✓${NC} Server public key: $KEYS_DIR/server_hybrid.pk"
echo -e "  ${GREEN}✓${NC} Sender secret key: $SENDERS_DIR/$SENDER_ID.sk"
echo -e "  ${GREEN}✓${NC} Sender public key: $SENDERS_DIR/$SENDER_ID.pk"
echo -e "  ${GREEN}✓${NC} Test file: $TEST_FILE"

# Show server fingerprint
echo
echo "Server Public Key Fingerprint:"
cargo run --bin keygen -- server --output-dir "$KEYS_DIR" 2>&1 | grep fingerprint | cut -d' ' -f3

echo
echo -e "${GREEN}🎉 Setup Complete!${NC}"
echo
echo "Next steps:"
echo "1. Start the server: ./cargo-rs server"
echo "2. In another terminal: ./send-file.sh"
echo "3. Check quarantined files via admin interface"
echo
echo "Important:"
echo "- The server secret key is PROTECTED - keep it safe"
echo "- Verify TOFU fingerprint on first connection"
echo "- Admin approval is required before file access"