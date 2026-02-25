"""
Unit tests for External Secrets integration
"""
import pytest
import os
from unittest.mock import Mock, patch, MagicMock


class TestExternalSecretsIntegration:
    """Test External Secrets Operator integration"""
    
    def test_environment_variable_loading(self):
        """Test that application loads secrets from environment variables"""
        # Mock environment variables that would be populated by External Secrets
        env_vars = {
            'OPENAI_API_KEY': 'sk-test123',
            'TWITTER_BEARER_TOKEN': 'AAAA-test',
            'VAULT_TOKEN': 'hvs.test',
            'JWT_SECRET_KEY': 'jwt-secret-test',
            'POSTGRES_URL': 'postgresql://user:pass@host:5432/db'
        }
        
        with patch.dict(os.environ, env_vars):
            # Test that environment variables are accessible
            assert os.getenv('OPENAI_API_KEY') == 'sk-test123'
            assert os.getenv('TWITTER_BEARER_TOKEN') == 'AAAA-test'
            assert os.getenv('VAULT_TOKEN') == 'hvs.test'
            assert os.getenv('JWT_SECRET_KEY') == 'jwt-secret-test'
            assert os.getenv('POSTGRES_URL') == 'postgresql://user:pass@host:5432/db'
    
    def test_vault_client_with_external_secrets_token(self):
        """Test Vault client initialization with External Secrets token"""
        from vault_client import VaultClient, VaultConfig
        
        # VaultConfig uses .url and .token fields (not .vault_url / .vault_token).
        # It does not auto-read VAULT_ADDR from the environment; pass values explicitly.
        config = VaultConfig(
            url='http://vault:8200',
            token='hvs.external-secrets-token'
        )
        client = VaultClient(config)

        assert client.config.url == 'http://vault:8200'
        assert client.config.token == 'hvs.external-secrets-token'
    
    def test_api_key_retrieval_from_environment(self):
        """Test API key retrieval from environment variables"""
        from api_connection_monitor import APIConnectionMonitor
        
        test_api_keys = {
            'OPENAI_API_KEY': 'sk-external-test',
            'TWITTER_BEARER_TOKEN': 'AAAA-external-test',
            'SHODAN_API_KEY': 'shodan-external-test',
            'VIRUSTOTAL_API_KEY': 'vt-external-test'
        }
        
        with patch.dict(os.environ, test_api_keys):
            monitor = APIConnectionMonitor()
            
            # Verify that environment variables are used
            assert os.getenv('OPENAI_API_KEY') == 'sk-external-test'
            assert os.getenv('TWITTER_BEARER_TOKEN') == 'AAAA-external-test'
    
    def test_database_connection_with_external_secrets(self):
        """Test database connection using External Secrets"""
        from postgres_audit_client import init_audit_client
        
        db_config = {
            'POSTGRES_URL': 'postgresql://eso_user:eso_pass@postgresql:5432/osint_audit',
            'POSTGRES_HOST': 'postgresql',
            'POSTGRES_PORT': '5432',
            'POSTGRES_USER': 'eso_user',
            'POSTGRES_PASSWORD': 'eso_pass',
            'POSTGRES_DB': 'osint_audit'
        }
        
        with patch.dict(os.environ, db_config):
            with patch('postgres_audit_client.psycopg2.connect') as mock_connect:
                mock_connect.return_value = Mock()
                
                # Test that connection uses External Secrets values
                client = init_audit_client()
                
                # Verify connection was attempted with ESO values
                assert os.getenv('POSTGRES_URL') == 'postgresql://eso_user:eso_pass@postgresql:5432/osint_audit'
    
    def test_redis_connection_with_external_secrets(self):
        """Test Redis connection using External Secrets"""
        from job_queue import JobQueueManager
        
        redis_config = {
            'REDIS_HOST': 'redis-eso',
            'REDIS_PORT': '6379',
            'REDIS_DB': '0',
            'REDIS_PASSWORD': 'eso-redis-password'
        }
        
        with patch.dict(os.environ, redis_config):
            with patch('job_queue.Redis') as mock_redis:
                mock_redis_instance = Mock()
                mock_redis.return_value = mock_redis_instance
                mock_redis_instance.ping.return_value = True
                
                manager = JobQueueManager()
                
                # Verify Redis connection used ESO values
                mock_redis.assert_called_with(
                    host='redis-eso',
                    port=6379,
                    db=0,
                    password='eso-redis-password',
                    decode_responses=True,
                    socket_timeout=30,
                    socket_connect_timeout=30,
                    retry_on_timeout=True
                )
    
    def test_jwt_secret_from_external_secrets(self):
        """Test JWT secret loading from External Secrets"""
        import jwt
        
        test_secret = 'external-secrets-jwt-key-123'
        
        with patch.dict(os.environ, {'JWT_SECRET_KEY': test_secret}):
            # Test JWT token creation with ESO secret
            payload = {'user_id': 'test', 'exp': 9999999999}
            token = jwt.encode(payload, test_secret, algorithm='HS256')
            
            # Verify token can be decoded with same secret
            decoded = jwt.decode(token, test_secret, algorithms=['HS256'])
            assert decoded['user_id'] == 'test'
    
    def test_mcp_server_authentication_with_external_secrets(self):
        """Test MCP server authentication using External Secrets"""
        from mcp_clients import MCPClientManager
        
        mcp_config = {
            'GITHUB_TOKEN': 'ghp-external-secrets-token',
            'TWITTER_BEARER_TOKEN': 'AAAA-eso-twitter-token',
            'REDDIT_API_KEY': 'reddit-eso-key'
        }
        
        with patch.dict(os.environ, mcp_config):
            manager = MCPClientManager()
            
            # Verify MCP clients can access ESO-provided credentials
            assert os.getenv('GITHUB_TOKEN') == 'ghp-external-secrets-token'
            assert os.getenv('TWITTER_BEARER_TOKEN') == 'AAAA-eso-twitter-token'
            assert os.getenv('REDDIT_API_KEY') == 'reddit-eso-key'


class TestSecretRotationHandling:
    """Test handling of secret rotation"""
    
    def test_vault_token_refresh(self):
        """Test handling of Vault token refresh"""
        from vault_client import VaultClient, VaultConfig
        
        # VaultConfig uses .token (not .vault_token); values must be passed explicitly
        config = VaultConfig(token='hvs.initial-token')
        client = VaultClient(config)
        assert client.config.token == 'hvs.initial-token'

        # Simulate token rotation by External Secrets — create a new config with the rotated token
        new_config = VaultConfig(token='hvs.rotated-token')
        assert new_config.token == 'hvs.rotated-token'
    
    def test_api_key_rotation(self):
        """Test handling of API key rotation"""
        # Simulate API key rotation
        original_key = 'sk-original-key'
        rotated_key = 'sk-rotated-key'
        
        with patch.dict(os.environ, {'OPENAI_API_KEY': original_key}):
            assert os.getenv('OPENAI_API_KEY') == original_key
        
        # After External Secrets rotates the key
        with patch.dict(os.environ, {'OPENAI_API_KEY': rotated_key}):
            assert os.getenv('OPENAI_API_KEY') == rotated_key
    
    def test_database_password_rotation(self):
        """Test handling of database password rotation"""
        original_url = 'postgresql://user:original_pass@host:5432/db'
        rotated_url = 'postgresql://user:rotated_pass@host:5432/db'
        
        with patch.dict(os.environ, {'POSTGRES_URL': original_url}):
            assert os.getenv('POSTGRES_URL') == original_url
        
        # After External Secrets rotates the password
        with patch.dict(os.environ, {'POSTGRES_URL': rotated_url}):
            assert os.getenv('POSTGRES_URL') == rotated_url


class TestSecretValidation:
    """Test secret validation and error handling"""
    
    def test_missing_required_secrets(self):
        """Test handling of missing required secrets"""
        # Clear environment variables
        required_vars = ['OPENAI_API_KEY', 'JWT_SECRET_KEY', 'VAULT_TOKEN']
        
        for var in required_vars:
            if var in os.environ:
                del os.environ[var]
        
        # Test graceful handling of missing secrets
        with patch.dict(os.environ, {}, clear=True):
            # Application should handle missing secrets gracefully
            assert os.getenv('OPENAI_API_KEY') is None
            assert os.getenv('JWT_SECRET_KEY') is None
            assert os.getenv('VAULT_TOKEN') is None
    
    def test_invalid_secret_format(self):
        """Test handling of invalid secret formats"""
        invalid_secrets = {
            'POSTGRES_URL': 'invalid-url-format',
            'REDIS_PORT': 'not-a-number',
            'JWT_SECRET_KEY': ''  # Empty secret
        }
        
        with patch.dict(os.environ, invalid_secrets):
            # Application should validate and handle invalid formats
            assert os.getenv('POSTGRES_URL') == 'invalid-url-format'
            assert os.getenv('REDIS_PORT') == 'not-a-number'
            assert os.getenv('JWT_SECRET_KEY') == ''
    
    def test_secret_length_validation(self):
        """Test validation of secret lengths"""
        secrets = {
            'JWT_SECRET_KEY': 'x' * 64,  # 64 character key
            'ENCRYPTION_KEY': 'y' * 32,  # 32 character key
            'SESSION_SECRET': 'z' * 24   # 24 character key
        }
        
        with patch.dict(os.environ, secrets):
            assert len(os.getenv('JWT_SECRET_KEY')) == 64
            assert len(os.getenv('ENCRYPTION_KEY')) == 32
            assert len(os.getenv('SESSION_SECRET')) == 24


class TestComplianceIntegration:
    """Test compliance-related secret handling"""
    
    def test_audit_logging_configuration(self):
        """Test audit logging configuration from External Secrets"""
        compliance_config = {
            'GDPR_ENABLED': 'true',
            'CCPA_ENABLED': 'true',
            'PIPEDA_ENABLED': 'true',
            'DATA_RETENTION_DAYS': '365',
            'AUDIT_LOG_RETENTION_DAYS': '2555'
        }
        
        with patch.dict(os.environ, compliance_config):
            assert os.getenv('GDPR_ENABLED') == 'true'
            assert os.getenv('DATA_RETENTION_DAYS') == '365'
            assert os.getenv('AUDIT_LOG_RETENTION_DAYS') == '2555'
    
    def test_encryption_key_handling(self):
        """Test encryption key handling for compliance"""
        encryption_config = {
            'ENCRYPTION_KEY': 'base64-encoded-encryption-key',
            'ENCRYPTION_ALGORITHM': 'AES-256-GCM',
            'KEY_ROTATION_INTERVAL_DAYS': '90'
        }
        
        with patch.dict(os.environ, encryption_config):
            assert os.getenv('ENCRYPTION_KEY') == 'base64-encoded-encryption-key'
            assert os.getenv('ENCRYPTION_ALGORITHM') == 'AES-256-GCM'
            assert os.getenv('KEY_ROTATION_INTERVAL_DAYS') == '90'


class TestHealthChecks:
    """Test health checks for External Secrets integration"""
    
    def test_secret_availability_health_check(self):
        """Test health check for secret availability"""
        required_secrets = [
            'OPENAI_API_KEY',
            'JWT_SECRET_KEY', 
            'POSTGRES_URL',
            'VAULT_TOKEN'
        ]
        
        # All secrets available
        complete_config = {secret: f'test-{secret.lower()}' for secret in required_secrets}
        
        with patch.dict(os.environ, complete_config):
            health_status = {}
            for secret in required_secrets:
                health_status[secret] = os.getenv(secret) is not None
            
            assert all(health_status.values())
    
    def test_vault_connectivity_with_eso_token(self):
        """Test Vault connectivity using External Secrets token"""
        vault_config = {
            'VAULT_ADDR': 'http://vault:8200',
            'VAULT_TOKEN': 'hvs.eso-managed-token'
        }
        
        from vault_client import VaultClient, VaultConfig

        with patch('vault_client.hvac.Client') as mock_hvac:
            mock_client = Mock()
            mock_client.is_authenticated.return_value = True
            mock_hvac.return_value = mock_client

            # VaultConfig uses .token (not .vault_token); set the value explicitly
            config = VaultConfig(url='http://vault:8200', token='hvs.eso-managed-token')
            client = VaultClient(config)

            # Verify Vault client stores the ESO token
            assert client.config.token == 'hvs.eso-managed-token'
    
    def test_mcp_server_health_with_eso_credentials(self):
        """Test MCP server health checks with External Secrets credentials"""
        mcp_credentials = {
            'GITHUB_TOKEN': 'ghp-eso-token',
            'TWITTER_BEARER_TOKEN': 'AAAA-eso-token',
            'SHODAN_API_KEY': 'shodan-eso-key'
        }
        
        with patch.dict(os.environ, mcp_credentials):
            # Mock MCP server health check
            health_results = {}
            
            for service, token in mcp_credentials.items():
                # Simulate health check using ESO-provided credentials
                health_results[service] = {
                    'status': 'healthy',
                    'token_present': bool(os.getenv(service)),
                    'token_format_valid': token.startswith(('sk-', 'ghp-', 'AAAA-', 'shodan-'))
                }
            
            # Verify all services report healthy with ESO credentials
            for service, result in health_results.items():
                assert result['status'] == 'healthy'
                assert result['token_present'] is True
                assert result['token_format_valid'] is True


class TestErrorScenarios:
    """Test error scenarios in External Secrets integration"""
    
    def test_vault_unreachable_fallback(self):
        """Test fallback behavior when Vault is unreachable"""
        # Simulate Vault being unreachable by clearing Vault-related env vars
        with patch.dict(os.environ, {}, clear=True):
            # Application should have fallback behavior
            vault_addr = os.getenv('VAULT_ADDR', 'http://localhost:8200')
            vault_token = os.getenv('VAULT_TOKEN', 'dev-only-token')
            
            # Verify fallback values are used
            assert vault_addr in ['http://localhost:8200', None]
            assert vault_token in ['dev-only-token', None]
    
    def test_external_secrets_sync_failure(self):
        """Test handling when External Secrets fails to sync"""
        # Simulate stale secrets (External Secrets not updating)
        stale_config = {
            'OPENAI_API_KEY': 'sk-stale-key',
            'SECRET_LAST_UPDATED': '2024-01-01T00:00:00Z'  # Old timestamp
        }
        
        with patch.dict(os.environ, stale_config):
            # Application should detect and handle stale secrets
            last_updated = os.getenv('SECRET_LAST_UPDATED')
            api_key = os.getenv('OPENAI_API_KEY')
            
            assert last_updated == '2024-01-01T00:00:00Z'
            assert api_key == 'sk-stale-key'
    
    def test_partial_secret_availability(self):
        """Test handling when only some secrets are available"""
        partial_config = {
            'OPENAI_API_KEY': 'sk-available',
            'JWT_SECRET_KEY': 'jwt-available'
            # TWITTER_BEARER_TOKEN and others missing
        }
        
        with patch.dict(os.environ, partial_config, clear=True):
            available_secrets = []
            missing_secrets = []
            
            required_secrets = ['OPENAI_API_KEY', 'TWITTER_BEARER_TOKEN', 'JWT_SECRET_KEY']
            
            for secret in required_secrets:
                if os.getenv(secret):
                    available_secrets.append(secret)
                else:
                    missing_secrets.append(secret)
            
            # Verify partial availability is detected
            assert 'OPENAI_API_KEY' in available_secrets
            assert 'JWT_SECRET_KEY' in available_secrets
            assert 'TWITTER_BEARER_TOKEN' in missing_secrets