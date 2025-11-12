#!/bin/bash

# Ensure cleanup of temporary files on exit
trap 'rm -f "$TEMP_FILE"' EXIT

# Check for required dependencies
for cmd in curl jq; do
  if ! command -v "$cmd" &> /dev/null; then
    echo "✗ FAILED: Required command '$cmd' not found"
    echo "Please install $cmd to run this test script"
    exit 1
  fi
done

BASE_URL="http://127.0.0.1:3000"

# Validate that the API is reachable
if ! curl -s --max-time 2 "$BASE_URL" > /dev/null 2>&1; then
  echo "✗ FAILED: Could not reach API at $BASE_URL"
  echo "Please ensure the server is running"
  exit 1
fi

echo "=== Testing CPR Security Flow ==="
echo ""
echo "Testing that CPR submission requires authentication..."
echo ""

# Create secure temporary file
TEMP_FILE=$(mktemp)

# Get CSRF token
CSRF_TOKEN=$(curl -s "$BASE_URL/api/csrf-token" | jq -r '.csrf_token')
if [ -z "$CSRF_TOKEN" ] || [ "$CSRF_TOKEN" = "null" ]; then
  echo "✗ FAILED: Could not retrieve CSRF token"
  echo "Server response may be malformed or endpoint unavailable"
  exit 1
fi

# Try to submit CPR without JWT token using reliable parsing
response=$(curl -s -w "\n%{http_code}" -X POST "$BASE_URL/api/account/cpr" \
  -H "Content-Type: application/json" \
  -H "X-CSRF-Token: $CSRF_TOKEN" \
  -d '{"account_id":"testaccount1234","cpr":"010190-1234"}')

# Split response into body and status code
BODY=$(echo "$response" | sed '$d')
HTTP_CODE=$(echo "$response" | tail -1)

# Trim whitespace from HTTP_CODE
HTTP_CODE=$(echo "$HTTP_CODE" | tr -d '[:space:]')

echo "Scenario: Submit CPR without JWT token"
echo "Expected: HTTP 401 Unauthorized"
echo "Got: HTTP $HTTP_CODE"
echo "Response: $BODY"
echo ""

if [ "$HTTP_CODE" = "401" ]; then
  echo "✓ SUCCESS: CPR endpoint correctly requires authentication"
  exit 0
else
  echo "✗ FAILED: CPR endpoint should require authentication"
  exit 1
fi

