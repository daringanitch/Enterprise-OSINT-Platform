#!/usr/bin/env python3
"""
Comprehensive Authentication Endpoints Test Script
Tests all authentication endpoints for the Enterprise OSINT Platform
"""

import requests
import json
import sys
from datetime import datetime

# Configuration
BASE_URL = "http://localhost:5001"
AUTH_ENDPOINTS = {
    "login": f"{BASE_URL}/api/auth/login",
    "logout": f"{BASE_URL}/api/auth/logout",
    "me": f"{BASE_URL}/api/auth/me"
}

# Test credentials (these should exist in your database)
TEST_USER = {
    "username": "admin",
    "password": "admin123"
}

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    END = '\033[0m'
    BOLD = '\033[1m'

def print_header(title):
    """Print formatted test section header"""
    print(f"\n{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{title.center(60)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.BLUE}{'='*60}{Colors.END}")

def print_success(message):
    """Print success message"""
    print(f"{Colors.GREEN}✓ {message}{Colors.END}")

def print_error(message):
    """Print error message"""
    print(f"{Colors.RED}✗ {message}{Colors.END}")

def print_warning(message):
    """Print warning message"""
    print(f"{Colors.YELLOW}⚠ {message}{Colors.END}")

def print_info(message):
    """Print info message"""
    print(f"{Colors.BLUE}ℹ {message}{Colors.END}")

def test_login_valid_credentials():
    """Test login with valid credentials"""
    print_info("Testing login with valid credentials...")
    
    try:
        response = requests.post(
            AUTH_ENDPOINTS["login"],
            json=TEST_USER,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            data = response.json()
            if 'access_token' in data and 'user' in data:
                print_success("Login successful - Token received")
                return data['access_token']
            else:
                print_error("Login response missing required fields")
                return None
        else:
            print_error(f"Login failed with status {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return None

def test_login_invalid_credentials():
    """Test login with invalid credentials"""
    print_info("Testing login with invalid credentials...")
    
    try:
        invalid_user = {
            "username": "invalid_user",
            "password": "wrong_password"
        }
        
        response = requests.post(
            AUTH_ENDPOINTS["login"],
            json=invalid_user,
            headers={"Content-Type": "application/json"}
        )
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 401:
            print_success("Invalid credentials correctly rejected")
        else:
            print_error(f"Expected 401, got {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")

def test_login_missing_fields():
    """Test login with missing required fields"""
    print_info("Testing login with missing fields...")
    
    test_cases = [
        {"username": "admin"},  # Missing password
        {"password": "admin123"},  # Missing username
        {},  # Missing both
    ]
    
    for i, case in enumerate(test_cases, 1):
        print(f"\n  Test case {i}: {case}")
        try:
            response = requests.post(
                AUTH_ENDPOINTS["login"],
                json=case,
                headers={"Content-Type": "application/json"}
            )
            
            print(f"  Status Code: {response.status_code}")
            print(f"  Response: {json.dumps(response.json(), indent=2)}")
            
            if response.status_code == 400:
                print_success(f"  Case {i}: Missing fields correctly rejected")
            else:
                print_error(f"  Case {i}: Expected 400, got {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            print_error(f"  Case {i}: Request failed: {e}")

def test_protected_endpoint_without_token():
    """Test accessing protected endpoint without token"""
    print_info("Testing protected endpoint without token...")
    
    try:
        response = requests.get(AUTH_ENDPOINTS["me"])
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 401:
            print_success("Protected endpoint correctly requires authentication")
        else:
            print_error(f"Expected 401, got {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")

def test_protected_endpoint_with_invalid_token():
    """Test accessing protected endpoint with invalid token"""
    print_info("Testing protected endpoint with invalid token...")
    
    try:
        headers = {"Authorization": "Bearer invalid_token_here"}
        response = requests.get(AUTH_ENDPOINTS["me"], headers=headers)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 401:
            print_success("Invalid token correctly rejected")
        else:
            print_error(f"Expected 401, got {response.status_code}")
            
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")

def test_protected_endpoint_with_valid_token(token):
    """Test accessing protected endpoint with valid token"""
    print_info("Testing protected endpoint with valid token...")
    
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.get(AUTH_ENDPOINTS["me"], headers=headers)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            data = response.json()
            if 'user' in data:
                print_success("Protected endpoint accessible with valid token")
                return True
            else:
                print_error("Valid token response missing user data")
                return False
        else:
            print_error(f"Expected 200, got {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return False

def test_logout(token):
    """Test logout endpoint"""
    print_info("Testing logout endpoint...")
    
    try:
        headers = {"Authorization": f"Bearer {token}"}
        response = requests.post(AUTH_ENDPOINTS["logout"], headers=headers)
        
        print(f"Status Code: {response.status_code}")
        print(f"Response: {json.dumps(response.json(), indent=2)}")
        
        if response.status_code == 200:
            print_success("Logout successful")
            return True
        else:
            print_error(f"Expected 200, got {response.status_code}")
            return False
            
    except requests.exceptions.RequestException as e:
        print_error(f"Request failed: {e}")
        return False

def test_server_connectivity():
    """Test if the server is running"""
    print_info("Testing server connectivity...")
    
    try:
        response = requests.get(f"{BASE_URL}/api/health", timeout=5)
        if response.status_code == 200:
            print_success("Server is running and accessible")
            return True
        else:
            print_error(f"Server returned status {response.status_code}")
            return False
    except requests.exceptions.RequestException as e:
        print_error(f"Cannot connect to server at {BASE_URL}: {e}")
        return False

def main():
    """Run all authentication endpoint tests"""
    print(f"{Colors.BOLD}{Colors.BLUE}Enterprise OSINT Platform - Authentication Endpoint Tests{Colors.END}")
    print(f"Base URL: {BASE_URL}")
    print(f"Test User: {TEST_USER['username']}")
    print(f"Timestamp: {datetime.now().isoformat()}")
    
    # Test server connectivity first
    print_header("SERVER CONNECTIVITY TEST")
    if not test_server_connectivity():
        print_error("Server is not accessible. Please ensure the backend is running on port 5000.")
        sys.exit(1)
    
    # Test login scenarios
    print_header("LOGIN ENDPOINT TESTS")
    
    # Valid credentials
    token = test_login_valid_credentials()
    if not token:
        print_error("Failed to get valid token. Cannot proceed with protected endpoint tests.")
        return
    
    print()
    # Invalid credentials
    test_login_invalid_credentials()
    
    print()
    # Missing fields
    test_login_missing_fields()
    
    # Test protected endpoints
    print_header("PROTECTED ENDPOINT TESTS")
    
    # Without token
    test_protected_endpoint_without_token()
    
    print()
    # With invalid token
    test_protected_endpoint_with_invalid_token()
    
    print()
    # With valid token
    if test_protected_endpoint_with_valid_token(token):
        print_success("All protected endpoint tests passed")
    
    # Test logout
    print_header("LOGOUT ENDPOINT TEST")
    test_logout(token)
    
    print_header("TEST SUMMARY")
    print_success("All authentication endpoint tests completed!")
    print_info("Review the output above for any failed tests.")

if __name__ == "__main__":
    main()