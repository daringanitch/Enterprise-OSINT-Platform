#!/usr/bin/env python3
"""
HashiCorp Vault Integration for Secure API Key Management
Provides secure storage and retrieval of API keys and sensitive configuration
"""

import logging
import os
import json
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
import hashlib
import base64

# HashiCorp Vault client
try:
    import hvac
    HVAC_AVAILABLE = True
except ImportError:
    HVAC_AVAILABLE = False

logger = logging.getLogger(__name__)


@dataclass
class VaultConfig:
    """HashiCorp Vault configuration"""
    url: str = "http://localhost:8200"
    token: Optional[str] = None
    role_id: Optional[str] = None
    secret_id: Optional[str] = None
    mount_point: str = "secret"
    namespace: Optional[str] = None
    ca_cert_path: Optional[str] = None
    verify_tls: bool = True
    timeout: int = 30
    
    # Authentication method
    auth_method: str = "token"  # token, approle, userpass, kubernetes
    
    # Auto-renewal settings
    auto_renew: bool = True
    renewal_threshold: int = 300  # Renew if less than 5 minutes left


@dataclass
class SecretMetadata:
    """Metadata for stored secrets"""
    path: str
    version: int
    created_time: datetime
    deletion_time: Optional[datetime]
    destroyed: bool
    custom_metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class APIKeyConfig:
    """Configuration for API keys"""
    service_name: str
    api_key: str
    endpoint_url: Optional[str] = None
    rate_limit: Optional[int] = None
    quota_limit: Optional[int] = None
    expiry_date: Optional[datetime] = None
    environment: str = "production"
    created_by: str = "system"
    tags: List[str] = field(default_factory=list)
    
    # Usage tracking
    last_used: Optional[datetime] = None
    usage_count: int = 0
    
    # Security settings
    ip_restrictions: List[str] = field(default_factory=list)
    allowed_operations: List[str] = field(default_factory=list)


class VaultClient:
    """HashiCorp Vault client for secure API key management"""
    
    def __init__(self, config: Optional[VaultConfig] = None):
        if not HVAC_AVAILABLE:
            logger.warning("hvac library not available. Install with: pip install hvac")
            self.vault_client = None
            self.mock_storage = {}  # Fallback to in-memory storage for development
            self.config = config or VaultConfig()
            return
        
        self.config = config or VaultConfig()
        self.vault_client = None
        self.authenticated = False
        self._initialize_client()
    
    def _initialize_client(self):
        """Initialize Vault client with configuration"""
        if not HVAC_AVAILABLE:
            logger.warning("Using mock storage - HashiCorp Vault not available")
            return
        
        try:
            # Create Vault client
            self.vault_client = hvac.Client(
                url=self.config.url,
                token=self.config.token,
                verify=self.config.verify_tls,
                timeout=self.config.timeout,
                namespace=self.config.namespace,
                cert=self.config.ca_cert_path
            )
            
            # Authenticate based on method
            self._authenticate()
            
            logger.info(f"Vault client initialized successfully: {self.config.url}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Vault client: {str(e)}")
            self.vault_client = None
    
    def _authenticate(self):
        """Authenticate with HashiCorp Vault"""
        if not self.vault_client:
            return False
        
        try:
            if self.config.auth_method == "token":
                # Token authentication
                if self.config.token:
                    self.vault_client.token = self.config.token
                else:
                    # Try to get token from environment or file
                    token = os.getenv('VAULT_TOKEN')
                    if not token and os.path.exists(os.path.expanduser('~/.vault-token')):
                        with open(os.path.expanduser('~/.vault-token'), 'r') as f:
                            token = f.read().strip()
                    
                    if token:
                        self.vault_client.token = token
                    else:
                        raise ValueError("No Vault token available")
            
            elif self.config.auth_method == "approle":
                # AppRole authentication
                if not self.config.role_id or not self.config.secret_id:
                    raise ValueError("AppRole authentication requires role_id and secret_id")
                
                auth_response = self.vault_client.auth.approle.login(
                    role_id=self.config.role_id,
                    secret_id=self.config.secret_id
                )
                
                self.vault_client.token = auth_response['auth']['client_token']
            
            else:
                raise ValueError(f"Unsupported authentication method: {self.config.auth_method}")
            
            # Verify authentication
            if self.vault_client.is_authenticated():
                self.authenticated = True
                logger.info("Successfully authenticated with Vault")
                return True
            else:
                raise Exception("Authentication failed")
        
        except Exception as e:
            logger.error(f"Vault authentication failed: {str(e)}")
            self.authenticated = False
            return False
    
    def store_api_key(self, service_name: str, api_key_config: APIKeyConfig) -> bool:
        """Store API key configuration securely"""
        
        path = f"api-keys/{service_name}"
        
        # Prepare secret data
        secret_data = {
            'api_key': api_key_config.api_key,
            'endpoint_url': api_key_config.endpoint_url,
            'rate_limit': api_key_config.rate_limit,
            'quota_limit': api_key_config.quota_limit,
            'expiry_date': api_key_config.expiry_date.isoformat() if api_key_config.expiry_date else None,
            'environment': api_key_config.environment,
            'created_by': api_key_config.created_by,
            'created_at': datetime.utcnow().isoformat(),
            'tags': api_key_config.tags,
            'last_used': api_key_config.last_used.isoformat() if api_key_config.last_used else None,
            'usage_count': api_key_config.usage_count,
            'ip_restrictions': api_key_config.ip_restrictions,
            'allowed_operations': api_key_config.allowed_operations
        }
        
        # Add metadata
        metadata = {
            'service_name': service_name,
            'environment': api_key_config.environment,
            'created_by': api_key_config.created_by,
            'last_updated': datetime.utcnow().isoformat()
        }
        
        return self._write_secret(path, secret_data, metadata)
    
    def get_api_key(self, service_name: str, environment: str = "production") -> Optional[APIKeyConfig]:
        """Retrieve API key configuration"""
        
        path = f"api-keys/{service_name}"
        secret_data = self._read_secret(path)
        
        if not secret_data:
            return None
        
        # Check environment match
        if secret_data.get('environment') != environment:
            logger.warning(f"Environment mismatch for {service_name}: expected {environment}, got {secret_data.get('environment')}")
            return None
        
        # Convert back to APIKeyConfig
        try:
            config = APIKeyConfig(
                service_name=service_name,
                api_key=secret_data.get('api_key'),
                endpoint_url=secret_data.get('endpoint_url'),
                rate_limit=secret_data.get('rate_limit'),
                quota_limit=secret_data.get('quota_limit'),
                expiry_date=datetime.fromisoformat(secret_data['expiry_date']) if secret_data.get('expiry_date') else None,
                environment=secret_data.get('environment', 'production'),
                created_by=secret_data.get('created_by', 'unknown'),
                tags=secret_data.get('tags', []),
                last_used=datetime.fromisoformat(secret_data['last_used']) if secret_data.get('last_used') else None,
                usage_count=secret_data.get('usage_count', 0),
                ip_restrictions=secret_data.get('ip_restrictions', []),
                allowed_operations=secret_data.get('allowed_operations', [])
            )
            
            # Update last used timestamp
            self._update_usage_tracking(service_name, config)
            
            return config
            
        except Exception as e:
            logger.error(f"Failed to parse API key config for {service_name}: {str(e)}")
            return None
    
    def list_api_keys(self, environment: Optional[str] = None) -> List[str]:
        """List all stored API keys"""
        
        base_path = "api-keys"
        
        if not self.vault_client or not self.authenticated:
            # Mock storage fallback
            keys = list(self.mock_storage.keys())
            if environment:
                filtered_keys = []
                for key in keys:
                    if key.startswith(f"{base_path}/"):
                        service_name = key.replace(f"{base_path}/", "")
                        config = self.get_api_key(service_name, environment)
                        if config:
                            filtered_keys.append(service_name)
                return filtered_keys
            return [key.replace(f"{base_path}/", "") for key in keys if key.startswith(f"{base_path}/")]
        
        try:
            # List secrets from Vault
            response = self.vault_client.secrets.kv.v2.list_secrets(
                path=base_path,
                mount_point=self.config.mount_point
            )
            
            keys = response['data']['keys'] if response.get('data', {}).get('keys') else []
            
            # Filter by environment if specified
            if environment:
                filtered_keys = []
                for key in keys:
                    config = self.get_api_key(key, environment)
                    if config:
                        filtered_keys.append(key)
                return filtered_keys
            
            return keys
            
        except Exception as e:
            logger.error(f"Failed to list API keys: {str(e)}")
            return []
    
    def update_api_key(self, service_name: str, updates: Dict[str, Any]) -> bool:
        """Update API key configuration"""
        
        # Get existing config
        existing_config = self.get_api_key(service_name)
        if not existing_config:
            logger.error(f"API key for {service_name} not found")
            return False
        
        # Apply updates
        for key, value in updates.items():
            if hasattr(existing_config, key):
                setattr(existing_config, key, value)
            else:
                logger.warning(f"Unknown configuration key: {key}")
        
        # Store updated config
        return self.store_api_key(service_name, existing_config)
    
    def delete_api_key(self, service_name: str) -> bool:
        """Delete API key configuration"""
        
        path = f"api-keys/{service_name}"
        return self._delete_secret(path)
    
    def rotate_api_key(self, service_name: str, new_api_key: str) -> bool:
        """Rotate API key while preserving other configuration"""
        
        config = self.get_api_key(service_name)
        if not config:
            return False
        
        # Update key and reset usage tracking
        config.api_key = new_api_key
        config.last_used = None
        config.usage_count = 0
        
        return self.store_api_key(service_name, config)
    
    def _write_secret(self, path: str, data: Dict[str, Any], metadata: Optional[Dict[str, str]] = None) -> bool:
        """Write secret to Vault"""
        
        if not self.vault_client or not self.authenticated:
            # Mock storage fallback
            full_path = f"{self.config.mount_point}/{path}"
            self.mock_storage[full_path] = {
                'data': data,
                'metadata': metadata or {},
                'created_time': datetime.utcnow().isoformat()
            }
            logger.info(f"Stored secret in mock storage: {path}")
            return True
        
        try:
            # Write secret using KV v2
            response = self.vault_client.secrets.kv.v2.create_or_update_secret(
                path=path,
                secret=data,
                custom_metadata=metadata,
                mount_point=self.config.mount_point
            )
            
            logger.info(f"Successfully stored secret: {path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to write secret {path}: {str(e)}")
            return False
    
    def _read_secret(self, path: str) -> Optional[Dict[str, Any]]:
        """Read secret from Vault"""
        
        if not self.vault_client or not self.authenticated:
            # Mock storage fallback
            full_path = f"{self.config.mount_point}/{path}"
            if full_path in self.mock_storage:
                return self.mock_storage[full_path]['data']
            return None
        
        try:
            # Read secret using KV v2
            response = self.vault_client.secrets.kv.v2.read_secret_version(
                path=path,
                mount_point=self.config.mount_point
            )
            
            return response['data']['data'] if response.get('data', {}).get('data') else None
            
        except Exception as e:
            logger.error(f"Failed to read secret {path}: {str(e)}")
            return None
    
    def _delete_secret(self, path: str) -> bool:
        """Delete secret from Vault"""
        
        if not self.vault_client or not self.authenticated:
            # Mock storage fallback
            full_path = f"{self.config.mount_point}/{path}"
            if full_path in self.mock_storage:
                del self.mock_storage[full_path]
                logger.info(f"Deleted secret from mock storage: {path}")
                return True
            return False
        
        try:
            # Delete secret using KV v2
            self.vault_client.secrets.kv.v2.delete_metadata_and_all_versions(
                path=path,
                mount_point=self.config.mount_point
            )
            
            logger.info(f"Successfully deleted secret: {path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete secret {path}: {str(e)}")
            return False
    
    def _update_usage_tracking(self, service_name: str, config: APIKeyConfig):
        """Update usage tracking for API key"""
        
        config.last_used = datetime.utcnow()
        config.usage_count += 1
        
        # Store updated config (fire and forget for performance)
        try:
            self.store_api_key(service_name, config)
        except Exception as e:
            logger.warning(f"Failed to update usage tracking for {service_name}: {str(e)}")
    
    def get_vault_status(self) -> Dict[str, Any]:
        """Get Vault cluster status"""
        
        if not self.vault_client:
            return {
                'available': False,
                'sealed': False,
                'authenticated': False,
                'mode': 'mock',
                'version': 'N/A'
            }
        
        try:
            health = self.vault_client.sys.read_health_status()
            seal_status = self.vault_client.sys.read_seal_status()
            
            return {
                'available': True,
                'sealed': seal_status.get('sealed', True),
                'authenticated': self.authenticated,
                'mode': 'vault',
                'version': seal_status.get('version', 'unknown'),
                'cluster_name': seal_status.get('cluster_name', 'unknown'),
                'cluster_id': seal_status.get('cluster_id', 'unknown'),
                'ha_enabled': seal_status.get('ha_enabled', False)
            }
            
        except Exception as e:
            logger.error(f"Failed to get Vault status: {str(e)}")
            return {
                'available': False,
                'sealed': True,
                'authenticated': False,
                'mode': 'error',
                'error': str(e)
            }
    
    def create_policy(self, policy_name: str, policy_rules: str) -> bool:
        """Create or update Vault policy"""
        
        if not self.vault_client or not self.authenticated:
            logger.warning("Cannot create policy without Vault connection")
            return False
        
        try:
            self.vault_client.sys.create_or_update_policy(
                name=policy_name,
                policy=policy_rules
            )
            
            logger.info(f"Successfully created/updated policy: {policy_name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create policy {policy_name}: {str(e)}")
            return False


class ConfigurationManager:
    """Centralized configuration management using Vault"""
    
    def __init__(self, vault_client: VaultClient):
        self.vault_client = vault_client
        self.service_configs = {}
        self._load_default_services()
    
    def _load_default_services(self):
        """Load default service configurations"""
        self.service_configs = {
            'openai': {
                'name': 'OpenAI API',
                'endpoint': 'https://api.openai.com/v1',
                'required_scopes': ['chat', 'completions'],
                'rate_limit': 3500,  # requests per minute
                'quota_limit': 1000000,  # tokens per month
                'env_var': 'OPENAI_API_KEY'
            },
            'shodan': {
                'name': 'Shodan API',
                'endpoint': 'https://api.shodan.io',
                'required_scopes': ['search', 'info'],
                'rate_limit': 1,  # requests per second
                'quota_limit': 10000,  # queries per month
                'env_var': 'SHODAN_API_KEY'
            },
            'virustotal': {
                'name': 'VirusTotal API',
                'endpoint': 'https://www.virustotal.com/vtapi/v2',
                'required_scopes': ['file', 'url', 'domain', 'ip'],
                'rate_limit': 4,  # requests per minute
                'quota_limit': 1000,  # requests per day
                'env_var': 'VIRUSTOTAL_API_KEY'
            },
            'twitter': {
                'name': 'Twitter API v2',
                'endpoint': 'https://api.twitter.com/2',
                'required_scopes': ['tweet.read', 'users.read'],
                'rate_limit': 300,  # requests per 15 minutes
                'quota_limit': 2000000,  # tweets per month
                'env_var': 'TWITTER_BEARER_TOKEN'
            },
            'reddit': {
                'name': 'Reddit API',
                'endpoint': 'https://oauth.reddit.com',
                'required_scopes': ['read'],
                'rate_limit': 60,  # requests per minute
                'quota_limit': 100000,  # requests per day
                'env_var': 'REDDIT_API_KEY'
            },
            'alienvault_otx': {
                'name': 'AlienVault OTX API',
                'endpoint': 'https://otx.alienvault.com/api/v1',
                'required_scopes': ['read'],
                'rate_limit': 10,  # requests per second
                'quota_limit': 10000,  # requests per day
                'env_var': 'ALIENVAULT_OTX_API_KEY'
            }
        }
    
    def register_api_key(self, service_name: str, api_key: str, 
                        environment: str = "production") -> bool:
        """Register an API key for a service"""
        
        if service_name not in self.service_configs:
            logger.error(f"Unknown service: {service_name}")
            return False
        
        service_info = self.service_configs[service_name]
        
        # Create API key configuration
        config = APIKeyConfig(
            service_name=service_name,
            api_key=api_key,
            endpoint_url=service_info['endpoint'],
            rate_limit=service_info.get('rate_limit'),
            quota_limit=service_info.get('quota_limit'),
            environment=environment,
            created_by="admin",
            tags=[service_name, environment],
            allowed_operations=service_info.get('required_scopes', [])
        )
        
        return self.vault_client.store_api_key(service_name, config)
    
    def get_service_api_key(self, service_name: str, 
                           environment: str = "production") -> Optional[str]:
        """Get API key for a service"""
        
        config = self.vault_client.get_api_key(service_name, environment)
        return config.api_key if config else None
    
    def get_all_service_configs(self) -> Dict[str, Dict[str, Any]]:
        """Get all service configurations"""
        
        result = {}
        
        for service_name, service_info in self.service_configs.items():
            # Check if API key is configured
            has_key = self.vault_client.get_api_key(service_name) is not None
            
            result[service_name] = {
                'name': service_info['name'],
                'endpoint': service_info['endpoint'],
                'configured': has_key,
                'rate_limit': service_info.get('rate_limit'),
                'quota_limit': service_info.get('quota_limit'),
                'required_scopes': service_info.get('required_scopes', [])
            }
        
        return result
    
    def validate_api_key(self, service_name: str, api_key: str) -> bool:
        """Validate an API key format (basic validation)"""
        
        if not api_key or len(api_key.strip()) < 10:
            return False
        
        # Service-specific validation
        if service_name == 'openai' and not api_key.startswith('sk-'):
            return False
        
        if service_name == 'shodan' and len(api_key) != 32:
            return False
        
        if service_name == 'virustotal' and len(api_key) != 64:
            return False
        
        return True
    
    def import_from_environment(self) -> Dict[str, bool]:
        """Import API keys from environment variables"""
        
        results = {}
        
        for service_name, service_info in self.service_configs.items():
            env_var = service_info.get('env_var')
            if env_var:
                api_key = os.getenv(env_var)
                if api_key:
                    if self.validate_api_key(service_name, api_key):
                        success = self.register_api_key(service_name, api_key)
                        results[service_name] = success
                        if success:
                            logger.info(f"Imported API key for {service_name} from environment")
                    else:
                        logger.warning(f"Invalid API key format for {service_name}")
                        results[service_name] = False
                else:
                    results[service_name] = False
        
        return results


# Default Vault policies for OSINT application
OSINT_VAULT_POLICIES = {
    'osint-admin': '''
    # Full access to API keys and configuration
    path "secret/data/api-keys/*" {
        capabilities = ["create", "read", "update", "delete", "list"]
    }
    
    path "secret/metadata/api-keys/*" {
        capabilities = ["list", "read", "delete"]
    }
    
    path "secret/data/config/*" {
        capabilities = ["create", "read", "update", "delete", "list"]
    }
    ''',
    
    'osint-operator': '''
    # Read-only access to API keys for application use
    path "secret/data/api-keys/*" {
        capabilities = ["read"]
    }
    
    path "secret/data/config/*" {
        capabilities = ["read"]
    }
    ''',
    
    'osint-readonly': '''
    # Very limited read access for monitoring
    path "secret/metadata/api-keys/*" {
        capabilities = ["list"]
    }
    '''
}