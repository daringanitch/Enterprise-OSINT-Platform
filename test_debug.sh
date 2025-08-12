#!/bin/bash

# Test script to check investigation status
echo "Testing investigation debug endpoint..."

# First login to get token
echo "1. Logging in..."
TOKEN_RESPONSE=$(curl -s -X POST "http://localhost:8080/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email": "test@example.com", "password": "TestPassword123"}')

echo "Login response: $TOKEN_RESPONSE"

# Extract token
TOKEN=$(echo $TOKEN_RESPONSE | grep -o '"access_token":"[^"]*"' | cut -d'"' -f4)

if [ -z "$TOKEN" ]; then
  echo "Failed to get token"
  exit 1
fi

echo "2. Got token: ${TOKEN:0:20}..."

# Test debug endpoint
echo "3. Checking investigations status..."
DEBUG_RESPONSE=$(curl -s -X GET "http://localhost:8080/api/v1/investigations/debug/status" \
  -H "Authorization: Bearer $TOKEN")

echo "Debug response:"
echo $DEBUG_RESPONSE | python3 -m json.tool

echo "4. Checking regular investigations list..."
LIST_RESPONSE=$(curl -s -X GET "http://localhost:8080/api/v1/investigations/" \
  -H "Authorization: Bearer $TOKEN")

echo "List response:"
echo $LIST_RESPONSE | python3 -m json.tool