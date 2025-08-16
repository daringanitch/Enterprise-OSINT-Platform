#!/bin/bash

# Simple Authentication Endpoint Test Script
# Tests auth endpoints using curl

BASE_URL="http://localhost:5002"
echo "=== Enterprise OSINT Platform - Authentication Tests ==="
echo "Base URL: $BASE_URL"
echo "Timestamp: $(date)"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}=== $1 ===${NC}"
}

print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ $1${NC}"
}

# Check if server is running
print_header "SERVER CONNECTIVITY TEST"
print_info "Testing server connectivity..."

response=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/health" 2>/dev/null)
if [ "$response" = "200" ]; then
    print_success "Server is running and accessible"
elif [ "$response" = "403" ]; then
    print_error "Server returned 403 - may be running on different port"
    echo "Trying to find Flask process..."
    ps aux | grep -i python | grep -v grep
    exit 1
else
    print_error "Server is not accessible at $BASE_URL (HTTP $response)"
    echo "Make sure the Flask server is running on port 5000"
    exit 1
fi

# Test 1: Login with valid credentials
print_header "LOGIN ENDPOINT TESTS"
print_info "Testing login with valid credentials..."

login_response=$(curl -s -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username": "admin", "password": "admin123"}')

echo "Login Response:"
echo "$login_response" | python3 -m json.tool 2>/dev/null || echo "$login_response"

# Extract token if login successful
token=$(echo "$login_response" | python3 -c "import sys, json; data=json.load(sys.stdin); print(data.get('access_token', ''))" 2>/dev/null)

if [ ! -z "$token" ]; then
    print_success "Login successful - Token received"
    echo "Token: ${token:0:20}..."
else
    print_error "Login failed - No token received"
fi

echo

# Test 2: Login with invalid credentials
print_info "Testing login with invalid credentials..."

invalid_response=$(curl -s -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username": "invalid_user", "password": "wrong_password"}')

echo "Invalid Login Response:"
echo "$invalid_response" | python3 -m json.tool 2>/dev/null || echo "$invalid_response"

if echo "$invalid_response" | grep -q "Invalid credentials" || echo "$invalid_response" | grep -q "error"; then
    print_success "Invalid credentials correctly rejected"
else
    print_error "Invalid credentials not properly handled"
fi

echo

# Test 3: Login with missing fields
print_info "Testing login with missing fields..."

missing_response=$(curl -s -X POST "$BASE_URL/api/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username": "admin"}')

echo "Missing Password Response:"
echo "$missing_response" | python3 -m json.tool 2>/dev/null || echo "$missing_response"

echo

# Test 4: Protected endpoint without token
print_header "PROTECTED ENDPOINT TESTS"
print_info "Testing protected endpoint without token..."

no_token_response=$(curl -s -X GET "$BASE_URL/api/auth/me")

echo "No Token Response:"
echo "$no_token_response" | python3 -m json.tool 2>/dev/null || echo "$no_token_response"

if echo "$no_token_response" | grep -q "error" || echo "$no_token_response" | grep -q "Unauthorized"; then
    print_success "Protected endpoint correctly requires authentication"
else
    print_error "Protected endpoint should require authentication"
fi

echo

# Test 5: Protected endpoint with invalid token
print_info "Testing protected endpoint with invalid token..."

invalid_token_response=$(curl -s -X GET "$BASE_URL/api/auth/me" \
    -H "Authorization: Bearer invalid_token_here")

echo "Invalid Token Response:"
echo "$invalid_token_response" | python3 -m json.tool 2>/dev/null || echo "$invalid_token_response"

if echo "$invalid_token_response" | grep -q "error" || echo "$invalid_token_response" | grep -q "Invalid"; then
    print_success "Invalid token correctly rejected"
else
    print_error "Invalid token should be rejected"
fi

echo

# Test 6: Protected endpoint with valid token
if [ ! -z "$token" ]; then
    print_info "Testing protected endpoint with valid token..."
    
    valid_token_response=$(curl -s -X GET "$BASE_URL/api/auth/me" \
        -H "Authorization: Bearer $token")
    
    echo "Valid Token Response:"
    echo "$valid_token_response" | python3 -m json.tool 2>/dev/null || echo "$valid_token_response"
    
    if echo "$valid_token_response" | grep -q "user" && ! echo "$valid_token_response" | grep -q "error"; then
        print_success "Protected endpoint accessible with valid token"
    else
        print_error "Protected endpoint should be accessible with valid token"
    fi
    
    echo
    
    # Test 7: Logout
    print_header "LOGOUT ENDPOINT TEST"
    print_info "Testing logout endpoint..."
    
    logout_response=$(curl -s -X POST "$BASE_URL/api/auth/logout" \
        -H "Authorization: Bearer $token")
    
    echo "Logout Response:"
    echo "$logout_response" | python3 -m json.tool 2>/dev/null || echo "$logout_response"
    
    if echo "$logout_response" | grep -q "successful" || echo "$logout_response" | grep -q "Logout"; then
        print_success "Logout successful"
    else
        print_error "Logout failed"
    fi
else
    print_error "Cannot test protected endpoints - no valid token"
fi

echo
print_header "TEST SUMMARY"
print_success "All authentication endpoint tests completed!"
print_info "Review the output above for any failed tests."