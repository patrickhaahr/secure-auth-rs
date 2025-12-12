#!/bin/bash
# Script to send files using the PQ File Transfer System

set -e  # Exit on any error

# Configuration
SENDER_ID="server2"
SENDERS_DIR="../keys/senders"
SERVER_URL="https://127.0.0.1:3443"
TEST_FILE="test-file.txt"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo "🚀 PQ Secure File Sender"
echo "========================="

# Check prerequisites
echo -e "${BLUE}Checking prerequisites...${NC}"

# Check if test file exists, create if not
if [ ! -f "$TEST_FILE" ]; then
    echo -e "${YELLOW}⚠️  Test file '$TEST_FILE' not found, creating...${NC}"
    cat > "$TEST_FILE" << 'EOF'
This is a test file for the PQ Secure File Transfer System.

Created: $(date)
Purpose: Testing secure file upload and download functionality
Content: Sample text for verification

This file contains no sensitive information and is intended for testing
the post-quantum cryptographic file transfer system.

EOF
    echo -e "${GREEN}✓ Test file created: $TEST_FILE${NC}"
else
    echo -e "${GREEN}✓ Test file found: $TEST_FILE${NC}"
fi

# Check if sender keys exist
if [ ! -f "$SENDERS_DIR/$SENDER_ID.sk" ]; then
    echo -e "${RED}✗ Sender secret key not found${NC}"
    echo "Run './setup-pq.sh' first to generate keys"
    exit 1
fi
echo -e "${GREEN}✓ Sender secret key found${NC}"

# Check if server is running
echo -e "${BLUE}Checking server status...${NC}"
if ! curl -k -s --connect-timeout 5 "$SERVER_URL/health" > /dev/null; then
    echo -e "${RED}✗ Server is not running at $SERVER_URL${NC}"
    echo "Start the server with: ./cargo-rs server"
    exit 1
fi
echo -e "${GREEN}✓ Server is running${NC}"

# Get server public key with TOFU verification
echo
echo -e "${BLUE}Fetching server public key (TOFU)...${NC}"
echo "--------------------------------------------"

PK_RESPONSE=$(curl -k -s "$SERVER_URL/api/pqc/public-key")
PUBLIC_KEY=$(echo "$PK_RESPONSE" | jq -r '.public_key')
FINGERPRINT=$(echo "$PK_RESPONSE" | jq -r '.fingerprint')

echo "Server Public Key Fingerprint: $FINGERPRINT"
echo -e "${YELLOW}⚠️  Verify this fingerprint on first use (Trust On First Use)${NC}"

# Get local server fingerprint for comparison
if [ -f "../keys/server_hybrid.pk" ]; then
    LOCAL_FINGERPRINT=$(cargo run --bin keygen -- inspect --key-path ../keys/server_hybrid.pk 2>&1 | grep "Fingerprint:" | cut -d' ' -f2)
    if [ "$FINGERPRINT" = "$LOCAL_FINGERPRINT" ]; then
        echo -e "${GREEN}✓ Fingerprint matches local key${NC}"
    else
        echo -e "${RED}✗ FINGERPRINT MISMATCH!${NC}"
        echo "Local:  $LOCAL_FINGERPRINT"
        echo "Remote: $FINGERPRINT"
        echo -e "${YELLOW}⚠️  This could indicate a Man-in-the-Middle attack!${NC}"
        echo "Do not proceed unless you understand this mismatch."
        read -p "Continue anyway? (y/N): " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            echo "Upload aborted for security reasons."
            exit 1
        fi
    fi
fi

echo
echo -e "${BLUE}Uploading file...${NC}"
echo "--------------------"

# Get file info
FILE_SIZE=$(stat -f%z "$TEST_FILE" 2>/dev/null || stat -c%s "$TEST_FILE" 2>/dev/null)
# FILE_HASH variable removed as it was unused and caused confusion/side-effects

echo "File: $TEST_FILE"
echo "Size: $FILE_SIZE bytes"
echo "Sender: $SENDER_ID"

# Run the sender CLI
echo "Executing secure upload..."
echo

cargo run --bin sender -- \
    --file "$TEST_FILE" \
    --server-url "$SERVER_URL" \
    --sender-id "$SENDER_ID" \
    --signing-key "$SENDERS_DIR/$SENDER_ID.sk"

UPLOAD_RESULT=$?

echo
if [ $UPLOAD_RESULT -eq 0 ]; then
    echo -e "${GREEN}✅ Upload completed successfully!${NC}"
    echo
    echo "Next steps:"
    echo "1. Login as admin: https://localhost:3443/login.html"
    echo "2. Check quarantined files: https://localhost:3443/admin.html"
    echo "3. Approve the uploaded file"
    echo "4. Grant permissions to users"
    echo "5. Users can then download and verify the file"
else
    echo -e "${RED}❌ Upload failed${NC}"
    exit 1
fi

echo
echo -e "${BLUE}File upload summary${NC}"
echo "===================="
echo "Filename: $TEST_FILE"
echo "Sender: $SENDER_ID"
echo "Server: $SERVER_URL"
echo "Status: Uploaded (quarantined)"
echo
echo -e "${YELLOW}Note: The file is currently in quarantine.${NC}"
echo -e "${YELLOW}      Admin approval is required before access.${NC}"
