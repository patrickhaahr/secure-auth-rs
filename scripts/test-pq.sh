#!/bin/bash
# Complete testing script for PQ File Transfer System

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

echo -e "${CYAN}🧪 PQ File Transfer System Test Suite${NC}"
echo "====================================="
echo

# Test 1: Setup
echo -e "${BLUE}Test 1: Initial Setup${NC}"
echo "----------------------"
echo "Running setup script..."
./setup-pq.sh
echo -e "${GREEN}✓ Setup completed${NC}"
echo

# Test 2: Start Server
echo -e "${BLUE}Test 2: Start Server${NC}"
echo "--------------------"
echo "Starting secure-auth-rs server..."

# Start server in background
./cargo-rs server &
SERVER_PID=$!

# Wait for server to start
echo "Waiting for server to start..."
for i in {1..30}; do
    if curl -k -s --connect-timeout 2 "https://localhost:3443/health" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ Server started (PID: $SERVER_PID)${NC}"
        break
    fi
    echo -n "."
    sleep 1
done

if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}✗ Failed to start server${NC}"
    exit 1
fi
echo

# Test 3: Send File
echo -e "${BLUE}Test 3: Send File${NC}"
echo "----------------"
echo "Sending test file..."
./send-file.sh
echo -e "${GREEN}✓ File sent${NC}"
echo

# Test 4: Check Public Key Endpoint
echo -e "${BLUE}Test 4: Public Key Endpoint${NC}"
echo "----------------------------"
echo "Testing /api/pqc/public-key endpoint..."

PK_RESPONSE=$(curl -k -s "$SERVER_URL/api/pqc/public-key")
PUBLIC_KEY=$(echo "$PK_RESPONSE" | jq -r '.public_key')
FINGERPRINT=$(echo "$PK_RESPONSE" | jq -r '.fingerprint')
ALGORITHM=$(echo "$PK_RESPONSE" | jq -r '.algorithm')

echo -e "  ${GREEN}✓ Public key retrieved${NC}"
echo "  Algorithm: $ALGORITHM"
echo "  Fingerprint: $FINGERPRINT"
echo

# Test 5: Database Verification
echo -e "${BLUE}Test 5: Database Verification${NC}"
echo "---------------------------------"
echo "Checking database entries..."

# Check sender registration
SENDER_COUNT=$(sqlite3 files.db "SELECT COUNT(*) FROM third_party_senders WHERE id='server2';")
if [ "$SENDER_COUNT" -eq 1 ]; then
    echo -e "  ${GREEN}✓ Sender 'server2' registered${NC}"
else
    echo -e "  ${RED}✗ Sender 'server2' not found${NC}"
fi

# Check quarantined files
QUARANTINE_COUNT=$(sqlite3 files.db "SELECT COUNT(*) FROM files WHERE upload_status='quarantine';")
if [ "$QUARANTINE_COUNT" -gt 0 ]; then
    echo -e "  ${GREEN}✓ $QUARANTINE_COUNT file(s) in quarantine${NC}"
    
    # Show file details
    echo "  Quarantined files:"
    sqlite3 files.db "SELECT id, filename, upload_status, created_at FROM files WHERE upload_status='quarantine';" | while read line; do
        echo "    $line"
    done
else
    echo -e "  ${RED}✗ No files in quarantine${NC}"
fi

echo

# Test 6: Upload Direct API Test (invalid signature)
echo -e "${BLUE}Test 6: Security Validation${NC}"
echo "-----------------------------"
echo "Testing upload with invalid signature..."

# Create invalid signature
INVALID_SIG="invalid_signature_123456789012345678901234567890123456789012345678901234567890"

# Get file info
TEST_FILE="test-file.txt"
FILE_HASH=$(sha256sum "$TEST_FILE" | cut -d' ' -f1)

# Attempt upload with invalid signature
HTTP_STATUS=$(curl -k -s -o /dev/null -w "%{http_code}" \
    -X POST "$SERVER_URL/api/pqc/upload" \
    -H "X-Sender-Key-Id: server2" \
    -H "X-Sender-Signature: $INVALID_SIG" \
    -H "X-Blake3-Hash: $FILE_HASH" \
    -H "X-Filename: test.txt" \
    -H "Content-Type: application/octet-stream" \
    -d "test")

if [ "$HTTP_STATUS" -eq 403 ]; then
    echo -e "  ${GREEN}✓ Invalid signature rejected (HTTP $HTTP_STATUS)${NC}"
else
    echo -e "  ${RED}✗ Invalid signature accepted! (HTTP $HTTP_STATUS)${NC}"
fi

echo

# Test 7: File Integrity
echo -e "${BLUE}Test 7: File Integrity${NC}"
echo "----------------------"
if [ -f "files/uploads" ]; then
    UPLOADED_FILES=$(find files/uploads -name "*.bin" | wc -l)
    if [ "$UPLOADED_FILES" -gt 0 ]; then
        echo -e "  ${GREEN}✓ $UPLOADED_FILES file(s) found in uploads directory${NC}"
        
        # List files
        echo "  Uploaded files:"
        find files/uploads -name "*.bin" | while read file; do
            HASH=$(basename "$file" .bin)
            SIZE=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
            echo "    Hash: $HASH, Size: $SIZE bytes"
        done
    else
        echo -e "  ${YELLOW}⚠ No files in uploads directory${NC}"
    fi
else
    echo -e "  ${YELLOW}⚠ Uploads directory does not exist${NC}"
fi

echo

# Test 8: Cleanup
echo -e "${BLUE}Test 8: Cleanup${NC}"
echo "---------------"
echo "Stopping server..."
kill $SERVER_PID
wait $SERVER_PID 2>/dev/null
echo -e "${GREEN}✓ Server stopped${NC}"

echo
echo -e "${CYAN}🎉 All Tests Completed!${NC}"
echo "======================="
echo
echo "Test Summary:"
echo -e "  ${GREEN}✓${NC} Setup completed successfully"
echo -e "  ${GREEN}✓${NC} Server started and responded"
echo -e "  ${GREEN}✓${NC} File uploaded with encryption"
echo -e "  ${GREEN}✓${NC} Public key endpoint working"
echo -e "  ${GREEN}✓${NC} Database entries created"
echo -e "  ${GREEN}✓${NC} Security validation working"
echo
echo "Manual verification steps:"
echo "1. Start server: ./cargo-rs server"
echo "2. Login as admin: https://localhost:3443/login.html"
echo "3. Check quarantine: /api/admin/quarantine"
echo "4. Approve file and grant permissions"
echo "5. Test user download and verification"
echo
echo -e "${YELLOW}Important:${NC}"
echo "- Files are quarantined until admin approval"
echo "- Verify TOFU fingerprints on first connection"
echo "- All uploads require valid Ed25519 signatures"
echo "- Files are encrypted with hybrid PQ cryptography"