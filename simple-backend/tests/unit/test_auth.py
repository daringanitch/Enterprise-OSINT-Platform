"""
Unit tests for authentication functionality
"""
import pytest
import json
import jwt
from datetime import datetime, timedelta


class TestAuthentication:
    """Test authentication endpoints and JWT handling"""
    
    def test_login_missing_credentials(self, client):
        """Test login with missing credentials"""
        response = client.post('/api/auth/login',
                              data=json.dumps({}),
                              content_type='application/json')
        
        assert response.status_code == 400
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_login_invalid_credentials(self, client):
        """Test login with invalid credentials"""
        response = client.post('/api/auth/login',
                              data=json.dumps({
                                  'username': 'invalid',
                                  'password': 'wrong'
                              }),
                              content_type='application/json')
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_login_success_structure(self, client, monkeypatch):
        """Test successful login returns proper structure"""
        # Mock the authenticate_user function
        def mock_auth(username, password):
            if username == 'testuser' and password == 'testpass':
                return {
                    'user_id': 'test123',
                    'username': 'testuser',
                    'full_name': 'Test User',
                    'role': 'analyst',
                    'clearance_level': 'confidential'
                }
            return None
        
        monkeypatch.setattr('app.authenticate_user', mock_auth)
        
        response = client.post('/api/auth/login',
                              data=json.dumps({
                                  'username': 'testuser',
                                  'password': 'testpass'
                              }),
                              content_type='application/json')
        
        assert response.status_code == 200
        data = json.loads(response.data)
        
        # Verify response structure
        assert 'access_token' in data
        assert 'message' in data
        assert 'user' in data
        
        # Verify user data
        user = data['user']
        assert user['username'] == 'testuser'
        assert user['role'] == 'analyst'
        assert user['clearance_level'] == 'confidential'
        
        # Verify JWT token
        token = data['access_token']
        decoded = jwt.decode(token, 'test-secret-key', algorithms=['HS256'])
        assert decoded['username'] == 'testuser'
        assert decoded['role'] == 'analyst'
    
    def test_protected_endpoint_without_token(self, client):
        """Test accessing protected endpoint without token"""
        response = client.get('/api/investigations')
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data
        assert 'Authentication required' in data['error']
    
    def test_protected_endpoint_with_invalid_token(self, client):
        """Test accessing protected endpoint with invalid token"""
        headers = {'Authorization': 'Bearer invalid-token'}
        response = client.get('/api/investigations', headers=headers)
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_protected_endpoint_with_expired_token(self, client):
        """Test accessing protected endpoint with expired token"""
        # Create an expired token
        payload = {
            'user_id': 'test123',
            'username': 'testuser',
            'exp': datetime.utcnow() - timedelta(hours=1),  # Expired
            'iat': datetime.utcnow() - timedelta(hours=2)
        }
        
        expired_token = jwt.encode(payload, 'test-secret-key', algorithm='HS256')
        headers = {'Authorization': f'Bearer {expired_token}'}
        
        response = client.get('/api/investigations', headers=headers)
        
        assert response.status_code == 401
        data = json.loads(response.data)
        assert 'error' in data
    
    def test_logout_endpoint(self, client, auth_headers):
        """Test logout endpoint"""
        response = client.post('/api/auth/logout', headers=auth_headers)
        
        assert response.status_code == 200
        data = json.loads(response.data)
        assert 'message' in data
        assert 'success' in data['message'].lower() or 'logged out' in data['message'].lower()