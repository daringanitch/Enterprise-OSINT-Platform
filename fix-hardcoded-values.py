#!/usr/bin/env python3
"""
Fix Hardcoded Values Script for Enterprise OSINT Platform

This script identifies and helps fix hardcoded values that should be environment variables.
"""

import os
import re
from pathlib import Path
from typing import Dict, List, Tuple


class HardcodedValueFixer:
    """Finds and helps fix hardcoded values in the codebase"""
    
    def __init__(self):
        self.issues: List[Dict] = []
        self.fixes_applied: List[str] = []
        
    def scan_backend_config(self) -> List[Dict]:
        """Scan backend configuration for hardcoded values"""
        issues = []
        backend_file = Path('simple-backend/app.py')
        
        if backend_file.exists():
            content = backend_file.read_text()
            
            # Check for hardcoded MCP URLs
            mcp_url_pattern = r"'http://mcp-[^']+'"
            matches = re.findall(mcp_url_pattern, content)
            if matches:
                issues.append({
                    'file': str(backend_file),
                    'issue': 'Hardcoded MCP server URLs',
                    'examples': matches[:3],
                    'fix': 'Use MCP_*_URL environment variables'
                })
            
            # Check for hardcoded CORS origins
            if 'localhost:8080' in content or 'localhost:*' in content:
                issues.append({
                    'file': str(backend_file),
                    'issue': 'Hardcoded CORS origins',
                    'fix': 'Use CORS_ORIGINS environment variable'
                })
            
            # Check for dev secret key
            if 'dev-secret-key' in content:
                issues.append({
                    'file': str(backend_file),
                    'issue': 'Development secret key in production code',
                    'fix': 'Remove fallback or use secure default'
                })
        
        return issues
    
    def scan_k8s_configs(self) -> List[Dict]:
        """Scan Kubernetes configurations for hardcoded values"""
        issues = []
        k8s_files = Path('k8s').glob('*.yaml')
        
        for k8s_file in k8s_files:
            try:
                content = k8s_file.read_text()
                
                # Check for hardcoded passwords
                if 'admin123' in content:
                    issues.append({
                        'file': str(k8s_file),
                        'issue': 'Hardcoded admin password',
                        'fix': 'Use Kubernetes secrets'
                    })
                
                # Check for hardcoded service URLs
                mcp_urls = re.findall(r'http://mcp-[^"]+', content)
                if mcp_urls:
                    issues.append({
                        'file': str(k8s_file),
                        'issue': 'Hardcoded MCP service URLs',
                        'examples': mcp_urls[:2],
                        'fix': 'Use ConfigMap or environment variables'
                    })
                
            except Exception as e:
                print(f"Warning: Could not read {k8s_file}: {e}")
        
        return issues
    
    def generate_env_template(self) -> str:
        """Generate environment variable template"""
        template = """# Enterprise OSINT Platform Environment Variables
# Copy this file to .env and customize for your deployment

# === SECURITY CONFIGURATION ===
JWT_SECRET_KEY=your-secure-jwt-secret-key-at-least-32-characters-long
VAULT_TOKEN=your-vault-token-here
FLASK_ENV=production

# === DATABASE CONFIGURATION ===
POSTGRES_URL=postgresql://osint_user:secure_password@osint-platform-postgresql:5432/osint_audit
REDIS_URL=redis://redis-cluster:6379/0

# === MCP SERVER URLS ===
MCP_INFRASTRUCTURE_URL=http://mcp-infrastructure-enhanced:8021
MCP_SOCIAL_URL=http://mcp-social-enhanced:8010
MCP_THREAT_URL=http://mcp-threat-enhanced:8020
MCP_FINANCIAL_URL=http://mcp-financial-enhanced:8040
MCP_TECHNICAL_URL=http://mcp-technical-enhanced:8050

# === API KEYS (Optional) ===
OPENAI_API_KEY=your-openai-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
SHODAN_API_KEY=your-shodan-api-key
ABUSEIPDB_API_KEY=your-abuseipdb-api-key
GITHUB_TOKEN=your-github-token

# === NETWORK CONFIGURATION ===
CORS_ORIGINS=http://localhost:8080,http://your-domain.com:8080
BACKEND_BASE_URL=http://osint-backend:5000
FRONTEND_BASE_URL=http://osint-frontend:80

# === TIMEOUT CONFIGURATION ===
HTTP_TIMEOUT_SECONDS=30
INVESTIGATION_TIMEOUT_SECONDS=1800
MCP_TIMEOUT_SECONDS=120
DEFAULT_TIMEOUT_SECONDS=600

# === COMPLIANCE CONFIGURATION ===
ADMIN_CONTACT_EMAIL=admin@your-organization.com
SEC_COMPLIANCE_EMAIL=compliance@your-organization.com
DATA_RETENTION_DAYS=30

# === MONITORING CONFIGURATION ===
PROMETHEUS_RETENTION_DAYS=15
GRAFANA_ADMIN_PASSWORD=secure-grafana-password
HEALTH_CHECK_INTERVAL_MINUTES=5

# === DEVELOPMENT FLAGS ===
DEBUG_MODE=false
INCLUDE_EXAMPLE_DATA=false
LOG_LEVEL=INFO
"""
        return template
    
    def generate_configmap_template(self) -> str:
        """Generate Kubernetes ConfigMap template"""
        template = """apiVersion: v1
kind: ConfigMap
metadata:
  name: osint-platform-config
  namespace: osint-platform
data:
  # MCP Server Configuration
  MCP_INFRASTRUCTURE_URL: "http://mcp-infrastructure-enhanced:8021"
  MCP_SOCIAL_URL: "http://mcp-social-enhanced:8010"
  MCP_THREAT_URL: "http://mcp-threat-enhanced:8020"
  MCP_FINANCIAL_URL: "http://mcp-financial-enhanced:8040"
  MCP_TECHNICAL_URL: "http://mcp-technical-enhanced:8050"
  
  # Service Configuration
  BACKEND_BASE_URL: "http://osint-backend:5000"
  FRONTEND_BASE_URL: "http://osint-frontend:80"
  
  # Timeout Configuration
  HTTP_TIMEOUT_SECONDS: "30"
  INVESTIGATION_TIMEOUT_SECONDS: "1800"
  MCP_TIMEOUT_SECONDS: "120"
  DEFAULT_TIMEOUT_SECONDS: "600"
  
  # Compliance Configuration
  DATA_RETENTION_DAYS: "30"
  
  # Monitoring Configuration
  PROMETHEUS_RETENTION_DAYS: "15"
  HEALTH_CHECK_INTERVAL_MINUTES: "5"
  
  # Application Configuration
  DEBUG_MODE: "false"
  INCLUDE_EXAMPLE_DATA: "false"
  LOG_LEVEL: "INFO"
  FLASK_ENV: "production"

---
apiVersion: v1
kind: Secret
metadata:
  name: osint-platform-secrets
  namespace: osint-platform
type: Opaque
stringData:
  JWT_SECRET_KEY: "your-secure-jwt-secret-key-change-this"
  VAULT_TOKEN: "your-vault-token-here"
  POSTGRES_PASSWORD: "secure-postgres-password"
  REDIS_PASSWORD: "secure-redis-password"
  GRAFANA_ADMIN_PASSWORD: "secure-grafana-password"
  
  # Optional API Keys
  OPENAI_API_KEY: "your-openai-api-key"
  VIRUSTOTAL_API_KEY: "your-virustotal-api-key"
  SHODAN_API_KEY: "your-shodan-api-key"
  ABUSEIPDB_API_KEY: "your-abuseipdb-api-key"
  GITHUB_TOKEN: "your-github-token"
"""
        return template
    
    def create_config_class(self) -> str:
        """Generate a configuration class for the backend"""
        config_class = """\"\"\"
Configuration management for Enterprise OSINT Platform
\"\"\"

import os
from typing import List, Dict


class Config:
    \"\"\"Base configuration class\"\"\"
    
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
        \"\"\"Get all MCP server configurations\"\"\"
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
    \"\"\"Development configuration\"\"\"
    DEBUG = True
    CORS_ORIGINS = ['http://localhost:8080', 'http://localhost:3000', 'http://127.0.0.1:8080']


class ProductionConfig(Config):
    \"\"\"Production configuration\"\"\"
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
    \"\"\"Get configuration based on FLASK_ENV\"\"\"
    env = os.environ.get('FLASK_ENV', 'production')
    
    if env == 'development':
        return DevelopmentConfig()
    else:
        return ProductionConfig()
"""
        return config_class
    
    def run_analysis(self) -> None:
        """Run complete analysis and generate recommendations"""
        print("🔍 Analyzing hardcoded values in Enterprise OSINT Platform")
        print("=" * 60)
        
        # Scan for issues
        backend_issues = self.scan_backend_config()
        k8s_issues = self.scan_k8s_configs()
        
        all_issues = backend_issues + k8s_issues
        
        if all_issues:
            print(f"❌ Found {len(all_issues)} configuration issues:")
            print()
            
            for i, issue in enumerate(all_issues, 1):
                print(f"{i}. {issue['file']}")
                print(f"   Issue: {issue['issue']}")
                print(f"   Fix: {issue['fix']}")
                if 'examples' in issue:
                    print(f"   Examples: {', '.join(issue['examples'])}")
                print()
        else:
            print("✅ No hardcoded values found!")
        
        # Generate configuration files
        print("📁 Generating configuration templates...")
        
        # Environment template
        env_template = self.generate_env_template()
        with open('.env.template', 'w') as f:
            f.write(env_template)
        print("✅ Created .env.template")
        
        # ConfigMap template
        configmap_template = self.generate_configmap_template()
        with open('k8s/configmap-template.yaml', 'w') as f:
            f.write(configmap_template)
        print("✅ Created k8s/configmap-template.yaml")
        
        # Configuration class
        config_class = self.create_config_class()
        os.makedirs('simple-backend', exist_ok=True)
        with open('simple-backend/config.py', 'w') as f:
            f.write(config_class)
        print("✅ Created simple-backend/config.py")
        
        # Summary
        print("\n" + "=" * 60)
        print("📋 RECOMMENDATIONS")
        print("=" * 60)
        print("1. Review and customize .env.template for your environment")
        print("2. Apply k8s/configmap-template.yaml to your cluster")
        print("3. Update simple-backend/app.py to use the new Config class")
        print("4. Replace hardcoded values with config.VARIABLE_NAME")
        print("5. Test thoroughly before deploying to production")
        print("\n🔒 Security Note: Never commit .env files or real secrets to git!")


def main():
    """Main function"""
    fixer = HardcodedValueFixer()
    fixer.run_analysis()


if __name__ == "__main__":
    main()