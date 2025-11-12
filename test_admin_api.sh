#!/bin/bash

# Admin API Test Script
# Tests admin endpoints with different authorization scenarios

set -e

BASE_URL="http://127.0.0.1:3000"
CSRF_TOKEN=""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

# Helper functions
print_success() {
    echo -e "${GREEN}PASS${NC}"
}

print_error() {
    echo -e "${RED}FAIL${NC}"
}

# Get CSRF token
get_csrf_token() {
    CSRF_TOKEN=$(curl -s -X GET "${BASE_URL}/api/csrf-token" | jq -r '.csrf_token' 2>/dev/null)
    if [ "$CSRF_TOKEN" = "null" ] || [ -z "$CSRF_TOKEN" ]; then
        return 1
    fi
    return 0
}

# Test unauthenticated access
test_unauthenticated() {
    echo -n "GET /api/admin/users (unauth): "
    response=$(curl -s -w "%{http_code}" -X GET "${BASE_URL}/api/admin/users" \
        -H "Content-Type: application/json")
    http_code="${response: -3}"
    
    if [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
        print_success
    else
        print_error
    fi
    
    echo -n "DELETE /api/admin/users/test-id (unauth): "
    response=$(curl -s -w "%{http_code}" -X DELETE "${BASE_URL}/api/admin/users/test-id" \
        -H "Content-Type: application/json")
    http_code="${response: -3}"
    
    if [ "$http_code" = "401" ] || [ "$http_code" = "403" ]; then
        print_success
    else
        print_error
    fi
}

# Test with invalid token
test_invalid_token() {
    echo -n "GET /api/admin/users (invalid token): "
    if ! get_csrf_token; then
        print_error
        return
    fi
    response=$(curl -s -w "%{http_code}" -X GET "${BASE_URL}/api/admin/users" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer invalid_token_12345" \
        -H "X-CSRF-Token: $CSRF_TOKEN")
    http_code="${response: -3}"
    
    if [ "$http_code" = "401" ]; then
        print_success
    else
        print_error
    fi
    
    echo -n "DELETE /api/admin/users/test-id (invalid token): "
    if ! get_csrf_token; then
        print_error
        return
    fi
    response=$(curl -s -w "%{http_code}" -X DELETE "${BASE_URL}/api/admin/users/test-id" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer invalid_token_12345" \
        -H "X-CSRF-Token: $CSRF_TOKEN")
    http_code="${response: -3}"
    
    if [ "$http_code" = "401" ]; then
        print_success
    else
        print_error
    fi
}

# Test CSRF protection
test_csrf_protection() {
    echo -n "GET /api/admin/users (no CSRF): "
    response=$(curl -s -w "%{http_code}" -X GET "${BASE_URL}/api/admin/users" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer dummy_token")
    http_code="${response: -3}"
    
    if [ "$http_code" = "401" ] || [ "$http_code" = "403" ] || [ "$http_code" = "400" ]; then
        print_success
    else
        print_error
    fi
}

# Test admin check endpoint
test_admin_check() {
    echo -n "GET /api/admin/check (unauth): "
    response=$(curl -s -w "%{http_code}" -X GET "${BASE_URL}/api/admin/check" \
        -H "Content-Type: application/json")
    http_code="${response: -3}"
    
    if [ "$http_code" = "401" ]; then
        print_success
    else
        print_error
    fi
    
    echo -n "GET /api/admin/check (invalid token): "
    response=$(curl -s -w "%{http_code}" -X GET "${BASE_URL}/api/admin/check" \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer invalid_token")
    http_code="${response: -3}"
    
    if [ "$http_code" = "401" ]; then
        print_success
    else
        print_error
    fi
}

# Main execution
main() {
    # Check if server is running
    if ! curl -s "${BASE_URL}/health" > /dev/null; then
        echo "FAIL: Server not running at $BASE_URL"
        exit 1
    fi
    
    # Run tests
    test_unauthenticated
    test_invalid_token
    test_csrf_protection
    test_admin_check
}

# Run main function
main "$@"