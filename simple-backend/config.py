"""
Configuration management for Enterprise OSINT Platform
"""

import os
from typing import List, Dict


class Config:
    """Base configuration class"""
    
    # Security
    SECRET_KEY = os.environ.get('JWT_SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("JWT_SECRET_KEY environment variable is required")
    
    # Database
    POSTGRES_URL = os.environ.get('POSTGRES_URL')
    if not POSTGRES_URL:
        raise ValueError("POSTGRES_URL environment variable is required")
    
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://redis-cluster:6379/0')
    
    # MCP Server URLs
    MCP_INFRASTRUCTURE_URL = os.environ.get('MCP_INFRASTRUCTURE_URL', 'http://mcp-infrastructure-enhanced:8021')
    MCP_SOCIAL_URL = os.environ.get('MCP_SOCIAL_URL', 'http://mcp-social-enhanced:8010')
    MCP_THREAT_URL = os.environ.get('MCP_THREAT_URL', 'http://mcp-threat-enhanced:8020')
    MCP_FINANCIAL_URL = os.environ.get('MCP_FINANCIAL_URL', 'http://mcp-financial-enhanced:8040')
    MCP_TECHNICAL_URL = os.environ.get('MCP_TECHNICAL_URL', 'http://mcp-technical-enhanced:8050')
    
    @property
    def MCP_SERVERS(self) -> List[tuple]:
        """Get all MCP server configurations"""
        return [
            ('infrastructure', self.MCP_INFRASTRUCTURE_URL),
            ('social', self.MCP_SOCIAL_URL),
            ('threat', self.MCP_THREAT_URL),
            ('financial', self.MCP_FINANCIAL_URL),
            ('technical', self.MCP_TECHNICAL_URL)
        ]
    
    # API Keys (optional)
    OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')
    VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY')
    SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY')
    ABUSEIPDB_API_KEY = os.environ.get('ABUSEIPDB_API_KEY')
    GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN')
    
    # Network Configuration
    CORS_ORIGINS = os.environ.get('CORS_ORIGINS', 'http://localhost:8080').split(',')
    BACKEND_BASE_URL = os.environ.get('BACKEND_BASE_URL', 'http://osint-backend:5000')
    FRONTEND_BASE_URL = os.environ.get('FRONTEND_BASE_URL', 'http://osint-frontend:80')
    
    # Timeouts (in seconds)
    HTTP_TIMEOUT = int(os.environ.get('HTTP_TIMEOUT_SECONDS', '30'))
    INVESTIGATION_TIMEOUT = int(os.environ.get('INVESTIGATION_TIMEOUT_SECONDS', '1800'))
    MCP_TIMEOUT = int(os.environ.get('MCP_TIMEOUT_SECONDS', '120'))
    DEFAULT_TIMEOUT = int(os.environ.get('DEFAULT_TIMEOUT_SECONDS', '600'))
    
    # Compliance
    ADMIN_CONTACT_EMAIL = os.environ.get('ADMIN_CONTACT_EMAIL', 'admin@your-organization.com')
    SEC_COMPLIANCE_EMAIL = os.environ.get('SEC_COMPLIANCE_EMAIL', 'compliance@your-organization.com')
    DATA_RETENTION_DAYS = int(os.environ.get('DATA_RETENTION_DAYS', '30'))
    
    # Application Settings
    DEBUG = os.environ.get('DEBUG_MODE', 'false').lower() == 'true'
    INCLUDE_EXAMPLE_DATA = os.environ.get('INCLUDE_EXAMPLE_DATA', 'false').lower() == 'true'
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    
    # Vault Configuration
    VAULT_URL = os.environ.get('VAULT_URL', 'http://vault:8200')
    VAULT_TOKEN = os.environ.get('VAULT_TOKEN')


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    CORS_ORIGINS = ['http://localhost:8080', 'http://localhost:3000', 'http://127.0.0.1:8080']


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False
    
    def __init__(self):
        super().__init__()
        # Validate critical production settings
        if not self.SECRET_KEY or len(self.SECRET_KEY) < 32:
            raise ValueError("Production requires a secure JWT_SECRET_KEY (32+ characters)")
        
        if 'localhost' in str(self.POSTGRES_URL):
            raise ValueError("Production should not use localhost database URLs")


# Configuration factory
def get_config():
    """Get configuration based on FLASK_ENV"""
    env = os.environ.get('FLASK_ENV', 'production')
    
    if env == 'development':
        return DevelopmentConfig()
    else:
        return ProductionConfig()
