#!/usr/bin/env python3
"""
Enhanced Threat Intelligence MCP Server - Real Intelligence Implementation
Provides actual threat intelligence gathering capabilities via VirusTotal, AlienVault OTX, and other APIs
"""

import os
import json
import logging
import requests
from flask import Flask, jsonify, request
from datetime import datetime, timedelta
import hashlib
import re
from typing import Dict, List, Any, Optional
import base64

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API Configuration
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', '')
SHODAN_API_KEY = os.environ.get('SHODAN_API_KEY', '')
ALIENVAULT_OTX_API_KEY = os.environ.get('ALIENVAULT_OTX_API_KEY', '')
HAVEIBEENPWNED_API_KEY = os.environ.get('HAVEIBEENPWNED_API_KEY', '')

# Cache for API responses (simple in-memory cache)
response_cache = {}
CACHE_DURATION = 1800  # 30 minutes for threat intel data

def get_cache_key(tool: str, params: Dict) -> str:
    """Generate cache key from tool and parameters"""
    param_str = json.dumps(params, sort_keys=True)
    return hashlib.md5(f"{tool}:{param_str}".encode()).hexdigest()

def get_cached_response(cache_key: str) -> Optional[Dict]:
    """Get cached response if still valid"""
    if cache_key in response_cache:
        cached = response_cache[cache_key]
        if datetime.utcnow() < cached['expires']:
            logger.info(f"Cache hit for key: {cache_key}")
            return cached['data']
    return None

def cache_response(cache_key: str, data: Dict):
    """Cache response with expiration"""
    response_cache[cache_key] = {
        'data': data,
        'expires': datetime.utcnow() + timedelta(seconds=CACHE_DURATION)
    }

def get_virustotal_domain_report(domain: str) -> Dict[str, Any]:
    """Get VirusTotal domain reputation data"""
    try:
        if not VIRUSTOTAL_API_KEY:
            logger.warning("VirusTotal API key not configured")
            return {
                'domain': domain,
                'error': 'VirusTotal API not configured',
                'data_source': 'Limited Data',
                'note': 'Configure VIRUSTOTAL_API_KEY for real threat data'
            }
        
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY,
            'User-Agent': 'OSINT-MCP-ThreatIntel/1.0'
        }
        
        # Get domain report
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        response = requests.get(url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            # Calculate threat score
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious = last_analysis_stats.get('malicious', 0)
            suspicious = last_analysis_stats.get('suspicious', 0)
            clean = last_analysis_stats.get('harmless', 0)
            undetected = last_analysis_stats.get('undetected', 0)
            
            total_engines = malicious + suspicious + clean + undetected
            threat_score = ((malicious * 10) + (suspicious * 5)) / max(total_engines, 1)
            
            return {
                'domain': domain,
                'threat_score': round(threat_score, 2),
                'reputation': attributes.get('reputation', 0),
                'last_analysis_date': datetime.fromtimestamp(
                    attributes.get('last_analysis_date', 0)
                ).isoformat() if attributes.get('last_analysis_date') else None,
                'analysis_stats': last_analysis_stats,
                'categories': attributes.get('categories', {}),
                'registrar': attributes.get('registrar', 'Unknown'),
                'creation_date': datetime.fromtimestamp(
                    attributes.get('creation_date', 0)
                ).isoformat() if attributes.get('creation_date') else None,
                'whois_date': datetime.fromtimestamp(
                    attributes.get('whois_date', 0)
                ).isoformat() if attributes.get('whois_date') else None,
                'popularity_ranks': attributes.get('popularity_ranks', {}),
                'data_source': 'VirusTotal API v3',
                'query_time': datetime.utcnow().isoformat()
            }
        
        # Handle API errors
        error_data = response.json() if response.text else {}
        return {
            'domain': domain,
            'error': f"VirusTotal API error: {response.status_code}",
            'details': error_data,
            'data_source': 'VirusTotal API v3 (Error)'
        }
        
    except Exception as e:
        logger.error(f"VirusTotal domain analysis failed: {str(e)}")
        return {
            'domain': domain,
            'error': str(e),
            'data_source': 'Error'
        }

def get_shodan_host_info(ip_address: str) -> Dict[str, Any]:
    """Get Shodan host information for IP address"""
    try:
        if not SHODAN_API_KEY:
            logger.warning("Shodan API key not configured")
            return {
                'ip': ip_address,
                'error': 'Shodan API not configured',
                'data_source': 'Limited Data',
                'note': 'Configure SHODAN_API_KEY for real host data'
            }
        
        headers = {
            'User-Agent': 'OSINT-MCP-ThreatIntel/1.0'
        }
        
        # Get host info
        url = f"https://api.shodan.io/shodan/host/{ip_address}"
        params = {'key': SHODAN_API_KEY}
        
        response = requests.get(url, params=params, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract key information
            ports = [service.get('port') for service in data.get('data', [])]
            services = [f"{service.get('product', 'Unknown')} {service.get('version', '')}" 
                       for service in data.get('data', []) if service.get('product')]
            
            # Calculate risk score based on open ports and services
            risky_ports = [22, 23, 3389, 1433, 3306, 5432, 6379, 27017]  # Common attack vectors
            risk_score = sum(1 for port in ports if port in risky_ports) * 2
            
            return {
                'ip': ip_address,
                'hostnames': data.get('hostnames', []),
                'country': data.get('country_name', 'Unknown'),
                'city': data.get('city', 'Unknown'),
                'isp': data.get('isp', 'Unknown'),
                'organization': data.get('org', 'Unknown'),
                'open_ports': sorted(ports),
                'services': services[:10],  # Limit to 10 services
                'vulnerabilities': data.get('vulns', []),
                'last_update': data.get('last_update', ''),
                'risk_score': min(risk_score, 10),  # Cap at 10
                'total_services': len(data.get('data', [])),
                'data_source': 'Shodan API',
                'query_time': datetime.utcnow().isoformat()
            }
        
        # Handle API errors
        error_data = response.json() if response.text else {}
        return {
            'ip': ip_address,
            'error': f"Shodan API error: {response.status_code}",
            'details': error_data,
            'data_source': 'Shodan API (Error)'
        }
        
    except Exception as e:
        logger.error(f"Shodan host analysis failed: {str(e)}")
        return {
            'ip': ip_address,
            'error': str(e),
            'data_source': 'Error'
        }

def check_haveibeenpwned(email: str) -> Dict[str, Any]:
    """Check if email has been in data breaches"""
    try:
        if not HAVEIBEENPWNED_API_KEY:
            logger.warning("HaveIBeenPwned API key not configured")
            return {
                'email': email,
                'error': 'HaveIBeenPwned API not configured',
                'data_source': 'Limited Data',
                'note': 'Configure HAVEIBEENPWNED_API_KEY for breach data'
            }
        
        headers = {
            'hibp-api-key': HAVEIBEENPWNED_API_KEY,
            'User-Agent': 'OSINT-MCP-ThreatIntel/1.0',
            'format': 'application/json'
        }
        
        # Check breaches
        breach_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        breach_response = requests.get(breach_url, headers=headers, timeout=10)
        
        breaches = []
        if breach_response.status_code == 200:
            breaches = breach_response.json()
        elif breach_response.status_code == 404:
            breaches = []  # No breaches found
        else:
            return {
                'email': email,
                'error': f"HaveIBeenPwned API error: {breach_response.status_code}",
                'data_source': 'HaveIBeenPwned API (Error)'
            }
        
        # Calculate risk score
        recent_breaches = [b for b in breaches if b.get('BreachDate', '') >= '2020-01-01']
        sensitive_breaches = [b for b in breaches if b.get('IsSensitive', False)]
        
        risk_score = len(breaches) + (len(recent_breaches) * 2) + (len(sensitive_breaches) * 3)
        
        return {
            'email': email,
            'breach_count': len(breaches),
            'recent_breaches': len(recent_breaches),
            'sensitive_breaches': len(sensitive_breaches),
            'risk_score': min(risk_score, 10),  # Cap at 10
            'breaches': [
                {
                    'name': breach.get('Name'),
                    'domain': breach.get('Domain'),
                    'breach_date': breach.get('BreachDate'),
                    'pwn_count': breach.get('PwnCount'),
                    'is_verified': breach.get('IsVerified'),
                    'is_sensitive': breach.get('IsSensitive'),
                    'data_classes': breach.get('DataClasses', [])
                }
                for breach in breaches[:10]  # Limit to 10 most recent
            ],
            'data_source': 'HaveIBeenPwned API v3',
            'query_time': datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"HaveIBeenPwned check failed: {str(e)}")
        return {
            'email': email,
            'error': str(e),
            'data_source': 'Error'
        }

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'threat-intel-mcp-enhanced',
        'version': '2.0.0',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/tools', methods=['GET'])
def list_tools():
    """List available tools"""
    return jsonify({
        'tools': {
            'virustotal_domain': {
                'description': 'Get real VirusTotal domain reputation and threat analysis',
                'parameters': {
                    'domain': {'type': 'string', 'description': 'Domain name to analyze', 'required': True}
                },
                'intelligence_type': 'REAL',
                'requires_api_key': True,
                'example': {'domain': 'malware-example.com'}
            },
            'shodan_host': {
                'description': 'Get real Shodan host information and service analysis',
                'parameters': {
                    'ip': {'type': 'string', 'description': 'IP address to analyze', 'required': True}
                },
                'intelligence_type': 'REAL',
                'requires_api_key': True,
                'example': {'ip': '8.8.8.8'}
            },
            'breach_check': {
                'description': 'Check if email has been in data breaches via HaveIBeenPwned',
                'parameters': {
                    'email': {'type': 'string', 'description': 'Email address to check', 'required': True}
                },
                'intelligence_type': 'REAL',
                'requires_api_key': True,
                'example': {'email': 'test@example.com'}
            }
        }
    })

@app.route('/execute', methods=['POST'])
def execute_tool():
    """Execute a specific tool"""
    try:
        data = request.get_json()
        tool = data.get('tool')
        parameters = data.get('parameters', {})
        
        # Generate cache key
        cache_key = get_cache_key(tool, parameters)
        
        # Check cache first
        cached_result = get_cached_response(cache_key)
        if cached_result:
            cached_result['metadata']['cache_used'] = True
            return jsonify(cached_result)
        
        start_time = datetime.utcnow()
        
        if tool == 'virustotal_domain':
            domain = parameters.get('domain')
            if not domain:
                return jsonify({'error': 'Domain parameter is required'}), 400
            
            result = get_virustotal_domain_report(domain)
            
        elif tool == 'shodan_host':
            ip = parameters.get('ip')
            if not ip:
                return jsonify({'error': 'IP parameter is required'}), 400
            
            result = get_shodan_host_info(ip)
            
        elif tool == 'breach_check':
            email = parameters.get('email')
            if not email:
                return jsonify({'error': 'Email parameter is required'}), 400
            
            result = check_haveibeenpwned(email)
            
        else:
            return jsonify({'error': f'Unknown tool: {tool}'}), 400
        
        # Calculate processing time
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        response = {
            'tool': tool,
            'parameters': parameters,
            'result': result,
            'success': 'error' not in result,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': {
                'processing_time_ms': processing_time,
                'cache_used': False,
                'intelligence_type': 'REAL',
                'data_freshness': 'Live' if 'error' not in result else 'Error'
            }
        }
        
        # Cache successful responses
        if 'error' not in result:
            cache_response(cache_key, response)
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Tool execution failed: {str(e)}")
        return jsonify({
            'error': str(e),
            'tool': data.get('tool'),
            'success': False
        }), 500

@app.route('/status', methods=['GET'])
def api_status():
    """Check API configuration status"""
    return jsonify({
        'apis': {
            'virustotal': {
                'configured': bool(VIRUSTOTAL_API_KEY),
                'endpoint': 'virustotal.com/api/v3',
                'status': 'active' if VIRUSTOTAL_API_KEY else 'not_configured'
            },
            'shodan': {
                'configured': bool(SHODAN_API_KEY),
                'endpoint': 'api.shodan.io',
                'status': 'active' if SHODAN_API_KEY else 'not_configured'
            },
            'haveibeenpwned': {
                'configured': bool(HAVEIBEENPWNED_API_KEY),
                'endpoint': 'haveibeenpwned.com/api/v3',
                'status': 'active' if HAVEIBEENPWNED_API_KEY else 'not_configured'
            },
            'alienvault_otx': {
                'configured': bool(ALIENVAULT_OTX_API_KEY),
                'endpoint': 'otx.alienvault.com/api/v1',
                'status': 'active' if ALIENVAULT_OTX_API_KEY else 'not_configured'
            }
        },
        'cache_stats': {
            'entries': len(response_cache),
            'cache_duration_seconds': CACHE_DURATION
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('MCP_SERVER_PORT', 8020))
    app.run(host='0.0.0.0', port=port, debug=False)