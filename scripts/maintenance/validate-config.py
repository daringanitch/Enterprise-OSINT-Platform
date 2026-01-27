#!/usr/bin/env python3
"""
Configuration Validation Script for Enterprise OSINT Platform

This script validates that all required environment variables and configuration
settings are properly configured before deployment.
"""

import os
import sys
import re
import subprocess
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse
import requests


class ConfigValidator:
    """Validates Enterprise OSINT Platform configuration"""
    
    def __init__(self):
        self.errors: List[str] = []
        self.warnings: List[str] = []
        
    def load_env_file(self) -> None:
        """Load .env file if it exists"""
        if os.path.exists('.env'):
            print("📂 Loading .env file...")
            with open('.env', 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        os.environ[key] = value
    
    def validate_environment_variables(self) -> bool:
        """Validate required environment variables"""
        # Load .env file first
        self.load_env_file()
        print("🔍 Validating environment variables...")
        
        # Required environment variables
        required_vars = {
            'POSTGRES_URL': 'PostgreSQL database connection string',
            'JWT_SECRET_KEY': 'JWT token signing secret',
            'FLASK_ENV': 'Flask environment (development/production)'
        }
        
        # Optional but recommended variables
        optional_vars = {
            'OPENAI_API_KEY': 'OpenAI API for AI-powered analysis',
            'VIRUSTOTAL_API_KEY': 'VirusTotal API for threat intelligence',
            'SHODAN_API_KEY': 'Shodan API for network intelligence',
            'ABUSEIPDB_API_KEY': 'AbuseIPDB API for IP reputation',
            'GITHUB_TOKEN': 'GitHub API token for repository analysis'
        }
        
        # MCP Server URLs
        mcp_urls = {
            'MCP_INFRASTRUCTURE_URL': 'http://mcp-infrastructure-enhanced:8021',
            'MCP_THREAT_URL': 'http://mcp-threat-enhanced:8020',
            'MCP_AI_URL': 'http://mcp-technical-enhanced:8050',
            'MCP_SOCIAL_URL': 'http://mcp-social-enhanced:8010',
            'MCP_FINANCIAL_URL': 'http://mcp-financial-enhanced:8040'
        }
        
        all_valid = True
        
        # Check required variables
        for var, description in required_vars.items():
            value = os.getenv(var)
            if not value:
                self.errors.append(f"❌ Missing required variable {var}: {description}")
                all_valid = False
            elif var == 'JWT_SECRET_KEY' and len(value) < 32:
                self.warnings.append(f"⚠️  JWT_SECRET_KEY should be at least 32 characters long")
            elif var == 'POSTGRES_URL' and not self._validate_postgres_url(value):
                self.errors.append(f"❌ Invalid POSTGRES_URL format: {value}")
                all_valid = False
            else:
                print(f"✅ {var}: OK")
        
        # Check optional variables
        for var, description in optional_vars.items():
            value = os.getenv(var)
            if value:
                print(f"✅ {var}: Configured")
            else:
                self.warnings.append(f"⚠️  Optional {var} not set: {description}")
        
        # Check MCP URLs
        for var, default_url in mcp_urls.items():
            value = os.getenv(var, default_url)
            if not self._validate_url(value):
                self.errors.append(f"❌ Invalid URL format for {var}: {value}")
                all_valid = False
            else:
                print(f"✅ {var}: {value}")
        
        return all_valid
    
    def validate_kubernetes_config(self) -> bool:
        """Validate Kubernetes configuration"""
        print("\n🔍 Validating Kubernetes configuration...")
        
        try:
            # Check kubectl is available
            result = subprocess.run(['kubectl', 'version', '--client'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                self.errors.append("❌ kubectl not found or not configured")
                return False
            print("✅ kubectl: Available")
            
            # Check if connected to a cluster
            result = subprocess.run(['kubectl', 'cluster-info'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                self.warnings.append("⚠️  Not connected to Kubernetes cluster")
            else:
                print("✅ Kubernetes cluster: Connected")
                
            # Check namespace exists
            result = subprocess.run(['kubectl', 'get', 'namespace', 'osint-platform'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                self.warnings.append("⚠️  osint-platform namespace doesn't exist")
            else:
                print("✅ osint-platform namespace: Exists")
            
            return True
            
        except FileNotFoundError:
            self.errors.append("❌ kubectl not found in PATH")
            return False
    
    def validate_required_files(self) -> bool:
        """Validate required configuration files exist"""
        print("\n🔍 Validating required files...")
        
        required_files = [
            'k8s/postgresql-deployment.yaml',
            'k8s/simple-backend-deployment.yaml',
            'k8s/simple-frontend-deployment.yaml',
            'k8s/monitoring-stack.yaml',
            'k8s/health-monitoring.yaml',
            'simple-backend/app.py',
            'simple-backend/requirements.txt',
            'simple-frontend/index.html'
        ]
        
        all_exist = True
        for file_path in required_files:
            if os.path.exists(file_path):
                print(f"✅ {file_path}: Exists")
            else:
                self.errors.append(f"❌ Missing required file: {file_path}")
                all_exist = False
        
        return all_exist
    
    def validate_docker_images(self) -> bool:
        """Validate Docker images are available"""
        print("\n🔍 Validating Docker images...")
        
        try:
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True)
            if result.returncode != 0:
                self.warnings.append("⚠️  Docker not available - cannot validate images")
                return True
            
            # Extract image names from deployment files
            images_to_check = [
                'postgres:15',
                'redis:7',
                'prom/prometheus:latest',
                'grafana/grafana:latest',
                'vault:latest'
            ]
            
            for image in images_to_check:
                result = subprocess.run(['docker', 'images', '--format', '{{.Repository}}:{{.Tag}}'], 
                                      capture_output=True, text=True)
                if image in result.stdout:
                    print(f"✅ {image}: Available locally")
                else:
                    self.warnings.append(f"⚠️  Docker image {image} not found locally")
            
            return True
            
        except FileNotFoundError:
            self.warnings.append("⚠️  Docker not found - skipping image validation")
            return True
    
    def validate_network_connectivity(self) -> bool:
        """Validate network connectivity to external services"""
        print("\n🔍 Validating network connectivity...")
        
        services_to_check = [
            ('OpenAI API', 'https://api.openai.com'),
            ('VirusTotal API', 'https://www.virustotal.com/api/v3/'),
            ('GitHub API', 'https://api.github.com'),
            ('Docker Hub', 'https://registry-1.docker.io')
        ]
        
        all_reachable = True
        for service_name, url in services_to_check:
            try:
                response = requests.get(url, timeout=5)
                if response.status_code < 500:  # Accept 4xx as "reachable"
                    print(f"✅ {service_name}: Reachable")
                else:
                    self.warnings.append(f"⚠️  {service_name}: HTTP {response.status_code}")
            except requests.RequestException as e:
                self.warnings.append(f"⚠️  {service_name}: Not reachable ({e})")
                all_reachable = False
        
        return all_reachable
    
    def _validate_postgres_url(self, url: str) -> bool:
        """Validate PostgreSQL URL format"""
        try:
            parsed = urlparse(url)
            return (parsed.scheme == 'postgresql' and 
                   parsed.hostname and 
                   parsed.username and 
                   parsed.password)
        except Exception:
            return False
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL format"""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def run_validation(self) -> bool:
        """Run all validation checks"""
        print("🚀 Enterprise OSINT Platform Configuration Validator")
        print("=" * 60)
        
        checks = [
            self.validate_environment_variables,
            self.validate_kubernetes_config,
            self.validate_required_files,
            self.validate_docker_images,
            self.validate_network_connectivity
        ]
        
        all_passed = True
        for check in checks:
            try:
                if not check():
                    all_passed = False
            except Exception as e:
                self.errors.append(f"❌ Validation error: {e}")
                all_passed = False
        
        # Print summary
        print("\n" + "=" * 60)
        print("📋 VALIDATION SUMMARY")
        print("=" * 60)
        
        if self.errors:
            print(f"❌ ERRORS ({len(self.errors)}):")
            for error in self.errors:
                print(f"   {error}")
        
        if self.warnings:
            print(f"\n⚠️  WARNINGS ({len(self.warnings)}):")
            for warning in self.warnings:
                print(f"   {warning}")
        
        if not self.errors and not self.warnings:
            print("🎉 All checks passed! Configuration is valid.")
        elif not self.errors:
            print("✅ Configuration is valid with warnings.")
        else:
            print("❌ Configuration validation failed. Please fix errors before deploying.")
        
        return all_passed and len(self.errors) == 0


def main():
    """Main validation function"""
    validator = ConfigValidator()
    success = validator.run_validation()
    
    if success:
        print("\n🚀 Ready for deployment!")
        sys.exit(0)
    else:
        print("\n❌ Configuration issues found. Please fix before deploying.")
        sys.exit(1)


if __name__ == "__main__":
    main()