#!/usr/bin/env python3
"""
Threat Intelligence Aggregator MCP Server
Combines multiple threat feeds for comprehensive threat analysis
"""

import os
import json
import asyncio
import aiohttp
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import hashlib
import base64
from urllib.parse import urlparse

class ThreatIntelligenceAggregator:
    """Aggregates threat intelligence from multiple sources"""
    
    def __init__(self):
        self.session = None
        
        # API Keys
        self.virustotal_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.abuseipdb_key = os.getenv('ABUSEIPDB_API_KEY')
        self.shodan_key = os.getenv('SHODAN_API_KEY')
        self.otx_key = os.getenv('ALIENVAULT_OTX_API_KEY')
        self.urlscan_key = os.getenv('URLSCAN_API_KEY')
        self.hybrid_key = os.getenv('HYBRID_ANALYSIS_API_KEY')
        
        # Caching for rate limiting
        self.cache = {}
        self.cache_ttl = 3600  # 1 hour
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    def _cache_key(self, source: str, indicator: str) -> str:
        """Generate cache key"""
        return f"{source}:{indicator}"

    def _is_cached(self, key: str) -> bool:
        """Check if result is cached and valid"""
        if key in self.cache:
            timestamp, _ = self.cache[key]
            if datetime.now() - timestamp < timedelta(seconds=self.cache_ttl):
                return True
        return False

    def _get_cached(self, key: str) -> Any:
        """Get cached result"""
        _, data = self.cache[key]
        return data

    def _set_cache(self, key: str, data: Any):
        """Cache result"""
        self.cache[key] = (datetime.now(), data)

    async def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Aggregate IP reputation from multiple sources"""
        results = {
            'ip': ip,
            'timestamp': datetime.utcnow().isoformat(),
            'reputation_scores': {},
            'threat_categories': [],
            'confidence': 0
        }
        
        # Check multiple sources in parallel
        tasks = []
        
        if self.abuseipdb_key:
            tasks.append(self._check_abuseipdb(ip))
        
        if self.virustotal_key:
            tasks.append(self._check_virustotal_ip(ip))
            
        if self.shodan_key:
            tasks.append(self._check_shodan_ip(ip))
            
        if self.otx_key:
            tasks.append(self._check_otx_ip(ip))
        
        # Gather all results
        if tasks:
            threat_data = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            total_score = 0
            source_count = 0
            
            for data in threat_data:
                if isinstance(data, dict) and not data.get('error'):
                    source = data.get('source')
                    score = data.get('malicious_score', 0)
                    
                    results['reputation_scores'][source] = score
                    total_score += score
                    source_count += 1
                    
                    # Aggregate threat categories
                    if 'categories' in data:
                        results['threat_categories'].extend(data['categories'])
            
            # Calculate overall confidence
            if source_count > 0:
                results['confidence'] = total_score / source_count
                results['risk_level'] = self._calculate_risk_level(results['confidence'])
        
        # Remove duplicates from categories
        results['threat_categories'] = list(set(results['threat_categories']))
        
        return results

    async def _check_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation on AbuseIPDB"""
        cache_key = self._cache_key('abuseipdb', ip)
        if self._is_cached(cache_key):
            return self._get_cached(cache_key)
            
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Key': self.abuseipdb_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    result = {
                        'source': 'AbuseIPDB',
                        'malicious_score': data['data']['abuseConfidenceScore'],
                        'total_reports': data['data']['totalReports'],
                        'categories': [cat['category'] for cat in data['data']['reports'][:5]] if 'reports' in data['data'] else [],
                        'country': data['data']['countryCode'],
                        'usage_type': data['data']['usageType']
                    }
                    self._set_cache(cache_key, result)
                    return result
                    
        except Exception as e:
            return {'error': str(e), 'source': 'AbuseIPDB'}

    async def _check_virustotal_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP on VirusTotal"""
        cache_key = self._cache_key('virustotal', ip)
        if self._is_cached(cache_key):
            return self._get_cached(cache_key)
            
        try:
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
            headers = {'x-apikey': self.virustotal_key}
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Calculate malicious score
                    stats = data['data']['attributes']['last_analysis_stats']
                    total = sum(stats.values())
                    malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
                    
                    score = (malicious / total * 100) if total > 0 else 0
                    
                    result = {
                        'source': 'VirusTotal',
                        'malicious_score': score,
                        'malicious_count': malicious,
                        'total_engines': total,
                        'categories': [],
                        'network': data['data']['attributes'].get('network', ''),
                        'asn': data['data']['attributes'].get('asn', '')
                    }
                    self._set_cache(cache_key, result)
                    return result
                    
        except Exception as e:
            return {'error': str(e), 'source': 'VirusTotal'}

    async def _check_shodan_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP on Shodan"""
        cache_key = self._cache_key('shodan', ip)
        if self._is_cached(cache_key):
            return self._get_cached(cache_key)
            
        try:
            url = f'https://api.shodan.io/shodan/host/{ip}'
            params = {'key': self.shodan_key}
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Calculate risk based on exposed services
                    risky_ports = [22, 23, 445, 3389, 5900]  # SSH, Telnet, SMB, RDP, VNC
                    exposed_risky = sum(1 for item in data.get('data', []) if item['port'] in risky_ports)
                    
                    score = min(exposed_risky * 20, 100)  # Each risky port adds 20 to score
                    
                    result = {
                        'source': 'Shodan',
                        'malicious_score': score,
                        'open_ports': [item['port'] for item in data.get('data', [])],
                        'vulnerabilities': data.get('vulns', []),
                        'categories': ['exposed_services'] if score > 0 else [],
                        'organization': data.get('org', ''),
                        'operating_system': data.get('os', '')
                    }
                    self._set_cache(cache_key, result)
                    return result
                    
        except Exception as e:
            return {'error': str(e), 'source': 'Shodan'}

    async def _check_otx_ip(self, ip: str) -> Dict[str, Any]:
        """Check IP on AlienVault OTX"""
        cache_key = self._cache_key('otx', ip)
        if self._is_cached(cache_key):
            return self._get_cached(cache_key)
            
        try:
            headers = {'X-OTX-API-KEY': self.otx_key}
            url = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general'
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Calculate score based on pulse count
                    pulse_count = data.get('pulse_info', {}).get('count', 0)
                    score = min(pulse_count * 10, 100)  # Each pulse adds 10 to score
                    
                    result = {
                        'source': 'AlienVault OTX',
                        'malicious_score': score,
                        'pulse_count': pulse_count,
                        'categories': ['threat_intelligence'] if pulse_count > 0 else [],
                        'reputation': data.get('reputation', 0)
                    }
                    self._set_cache(cache_key, result)
                    return result
                    
        except Exception as e:
            return {'error': str(e), 'source': 'AlienVault OTX'}

    async def check_domain_reputation(self, domain: str) -> Dict[str, Any]:
        """Check domain reputation across multiple sources"""
        results = {
            'domain': domain,
            'timestamp': datetime.utcnow().isoformat(),
            'reputation_scores': {},
            'categories': [],
            'dns_records': {},
            'ssl_info': {}
        }
        
        # Check multiple sources
        tasks = []
        
        if self.virustotal_key:
            tasks.append(self._check_virustotal_domain(domain))
            
        if self.urlscan_key:
            tasks.append(self._check_urlscan(domain))
            
        if self.otx_key:
            tasks.append(self._check_otx_domain(domain))
        
        # Gather results
        if tasks:
            threat_data = await asyncio.gather(*tasks, return_exceptions=True)
            
            for data in threat_data:
                if isinstance(data, dict) and not data.get('error'):
                    source = data.get('source')
                    results['reputation_scores'][source] = data.get('malicious_score', 0)
                    
                    if 'categories' in data:
                        results['categories'].extend(data['categories'])
        
        results['categories'] = list(set(results['categories']))
        results['risk_level'] = self._calculate_risk_level(
            sum(results['reputation_scores'].values()) / len(results['reputation_scores']) 
            if results['reputation_scores'] else 0
        )
        
        return results

    async def _check_virustotal_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain on VirusTotal"""
        cache_key = self._cache_key('virustotal_domain', domain)
        if self._is_cached(cache_key):
            return self._get_cached(cache_key)
            
        try:
            url = f'https://www.virustotal.com/api/v3/domains/{domain}'
            headers = {'x-apikey': self.virustotal_key}
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    stats = data['data']['attributes']['last_analysis_stats']
                    total = sum(stats.values())
                    malicious = stats.get('malicious', 0) + stats.get('suspicious', 0)
                    
                    score = (malicious / total * 100) if total > 0 else 0
                    
                    result = {
                        'source': 'VirusTotal',
                        'malicious_score': score,
                        'categories': data['data']['attributes'].get('categories', []),
                        'popularity_rank': data['data']['attributes'].get('popularity_ranks', {})
                    }
                    self._set_cache(cache_key, result)
                    return result
                    
        except Exception as e:
            return {'error': str(e), 'source': 'VirusTotal'}

    async def _check_urlscan(self, domain: str) -> Dict[str, Any]:
        """Submit and check domain on URLScan.io"""
        cache_key = self._cache_key('urlscan', domain)
        if self._is_cached(cache_key):
            return self._get_cached(cache_key)
            
        try:
            # Search for existing scans
            search_url = 'https://urlscan.io/api/v1/search/'
            params = {'q': f'domain:{domain}', 'size': 1}
            
            async with self.session.get(search_url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data['results']:
                        scan = data['results'][0]
                        score = 0
                        categories = []
                        
                        if scan['verdicts']['malicious']:
                            score = 100
                            categories.append('malicious')
                        elif scan['verdicts']['score'] > 50:
                            score = scan['verdicts']['score']
                            categories.append('suspicious')
                        
                        result = {
                            'source': 'URLScan.io',
                            'malicious_score': score,
                            'categories': categories,
                            'screenshot': scan.get('screenshot'),
                            'verdict': scan['verdicts']
                        }
                        self._set_cache(cache_key, result)
                        return result
                        
        except Exception as e:
            return {'error': str(e), 'source': 'URLScan.io'}

    async def _check_otx_domain(self, domain: str) -> Dict[str, Any]:
        """Check domain on AlienVault OTX"""
        cache_key = self._cache_key('otx_domain', domain)
        if self._is_cached(cache_key):
            return self._get_cached(cache_key)
            
        try:
            headers = {'X-OTX-API-KEY': self.otx_key}
            url = f'https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general'
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    pulse_count = data.get('pulse_info', {}).get('count', 0)
                    score = min(pulse_count * 10, 100)
                    
                    result = {
                        'source': 'AlienVault OTX',
                        'malicious_score': score,
                        'pulse_count': pulse_count,
                        'categories': ['threat_intelligence'] if pulse_count > 0 else []
                    }
                    self._set_cache(cache_key, result)
                    return result
                    
        except Exception as e:
            return {'error': str(e), 'source': 'AlienVault OTX'}

    async def check_file_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash reputation"""
        results = {
            'hash': file_hash,
            'hash_type': self._identify_hash_type(file_hash),
            'timestamp': datetime.utcnow().isoformat(),
            'detections': {},
            'threat_names': [],
            'first_seen': None,
            'last_seen': None
        }
        
        # Check VirusTotal
        if self.virustotal_key:
            vt_result = await self._check_virustotal_hash(file_hash)
            if not vt_result.get('error'):
                results['detections']['virustotal'] = vt_result
                results['threat_names'].extend(vt_result.get('threat_names', []))
        
        # Check Hybrid Analysis
        if self.hybrid_key:
            hybrid_result = await self._check_hybrid_analysis(file_hash)
            if not hybrid_result.get('error'):
                results['detections']['hybrid_analysis'] = hybrid_result
        
        # Calculate overall threat level
        total_score = sum(d.get('malicious_score', 0) for d in results['detections'].values())
        results['threat_level'] = self._calculate_risk_level(
            total_score / len(results['detections']) if results['detections'] else 0
        )
        
        return results

    def _identify_hash_type(self, hash_string: str) -> str:
        """Identify hash type by length"""
        hash_lengths = {
            32: 'MD5',
            40: 'SHA1',
            64: 'SHA256',
            128: 'SHA512'
        }
        return hash_lengths.get(len(hash_string), 'Unknown')

    async def _check_virustotal_hash(self, file_hash: str) -> Dict[str, Any]:
        """Check file hash on VirusTotal"""
        try:
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            headers = {'x-apikey': self.virustotal_key}
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    attributes = data['data']['attributes']
                    
                    stats = attributes['last_analysis_stats']
                    total = sum(stats.values())
                    malicious = stats.get('malicious', 0)
                    
                    # Get threat names
                    threat_names = []
                    for engine, result in attributes['last_analysis_results'].items():
                        if result['category'] == 'malicious' and result.get('result'):
                            threat_names.append(result['result'])
                    
                    return {
                        'malicious_score': (malicious / total * 100) if total > 0 else 0,
                        'detection_ratio': f"{malicious}/{total}",
                        'threat_names': list(set(threat_names))[:5],
                        'file_type': attributes.get('type_description', ''),
                        'file_size': attributes.get('size', 0),
                        'first_submission': attributes.get('first_submission_date'),
                        'last_analysis': attributes.get('last_analysis_date')
                    }
                    
        except Exception as e:
            return {'error': str(e)}

    async def _check_hybrid_analysis(self, file_hash: str) -> Dict[str, Any]:
        """Check file on Hybrid Analysis"""
        try:
            url = 'https://www.hybrid-analysis.com/api/v2/search/hash'
            headers = {
                'api-key': self.hybrid_key,
                'user-agent': 'OSINT Bot'
            }
            data = {'hash': file_hash}
            
            async with self.session.post(url, headers=headers, data=data) as response:
                if response.status == 200:
                    results = await response.json()
                    
                    if results:
                        report = results[0]
                        threat_score = report.get('threat_score', 0)
                        
                        return {
                            'malicious_score': threat_score,
                            'verdict': report.get('verdict', ''),
                            'malware_family': report.get('vx_family', ''),
                            'environment': report.get('environment_description', ''),
                            'submit_time': report.get('analysis_start_time')
                        }
                        
        except Exception as e:
            return {'error': str(e)}

    def _calculate_risk_level(self, score: float) -> str:
        """Calculate risk level from score"""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'CLEAN'

    async def threat_hunt(self, indicators: List[str]) -> Dict[str, Any]:
        """Perform threat hunting on multiple indicators"""
        results = {
            'timestamp': datetime.utcnow().isoformat(),
            'total_indicators': len(indicators),
            'threats_found': 0,
            'results': []
        }
        
        for indicator in indicators:
            indicator_type = self._identify_indicator_type(indicator)
            
            if indicator_type == 'ip':
                result = await self.check_ip_reputation(indicator)
            elif indicator_type == 'domain':
                result = await self.check_domain_reputation(indicator)
            elif indicator_type == 'hash':
                result = await self.check_file_hash(indicator)
            else:
                result = {'error': f'Unknown indicator type for: {indicator}'}
            
            result['indicator'] = indicator
            result['type'] = indicator_type
            
            if result.get('risk_level') in ['HIGH', 'CRITICAL']:
                results['threats_found'] += 1
            
            results['results'].append(result)
        
        return results

    def _identify_indicator_type(self, indicator: str) -> str:
        """Identify type of indicator"""
        # Simple heuristics
        if '.' in indicator and len(indicator.split('.')) == 4:
            try:
                # Check if valid IP
                parts = indicator.split('.')
                if all(0 <= int(part) <= 255 for part in parts):
                    return 'ip'
            except:
                pass
        
        if len(indicator) in [32, 40, 64, 128] and all(c in '0123456789abcdef' for c in indicator.lower()):
            return 'hash'
        
        return 'domain'


# MCP Server Implementation
class ThreatAggregatorMCPServer:
    def __init__(self):
        self.aggregator = None
        
    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP protocol requests"""
        method = request.get('method')
        params = request.get('params', {})
        
        # Initialize aggregator if needed
        if not self.aggregator:
            self.aggregator = ThreatIntelligenceAggregator()
            await self.aggregator.__aenter__()
        
        # Route to appropriate handler
        handlers = {
            'threat/check_ip': self.aggregator.check_ip_reputation,
            'threat/check_domain': self.aggregator.check_domain_reputation,
            'threat/check_hash': self.aggregator.check_file_hash,
            'threat/hunt': self.aggregator.threat_hunt
        }
        
        handler = handlers.get(method)
        if handler:
            try:
                result = await handler(**params)
                return {
                    'success': True,
                    'data': result
                }
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e)
                }
        
        return {
            'success': False,
            'error': f'Unknown method: {method}'
        }

    async def get_capabilities(self) -> Dict[str, Any]:
        """Return server capabilities"""
        return {
            'name': 'Threat Intelligence Aggregator',
            'version': '1.0.0',
            'methods': [
                {
                    'name': 'threat/check_ip',
                    'description': 'Check IP reputation across multiple sources',
                    'params': ['ip']
                },
                {
                    'name': 'threat/check_domain',
                    'description': 'Check domain reputation',
                    'params': ['domain']
                },
                {
                    'name': 'threat/check_hash',
                    'description': 'Check file hash reputation',
                    'params': ['file_hash']
                },
                {
                    'name': 'threat/hunt',
                    'description': 'Hunt for threats in multiple indicators',
                    'params': ['indicators']
                }
            ],
            'required_api_keys': [
                'VIRUSTOTAL_API_KEY',
                'ABUSEIPDB_API_KEY',
                'SHODAN_API_KEY',
                'ALIENVAULT_OTX_API_KEY',
                'URLSCAN_API_KEY',
                'HYBRID_ANALYSIS_API_KEY'
            ]
        }


if __name__ == '__main__':
    import uvicorn
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    import asyncio
    
    # Create FastAPI app
    app = FastAPI(
        title="Threat Intelligence Aggregator MCP Server",
        description="Multi-source threat intelligence aggregation",
        version="1.0.0"
    )
    
    # Initialize MCP server
    mcp_server = ThreatAggregatorMCPServer()
    
    @app.get("/")
    async def root():
        return {"message": "Threat Intelligence Aggregator MCP Server", "version": "1.0.0", "status": "running"}
    
    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "threat-aggregator-mcp"}
    
    @app.get("/capabilities")
    async def get_capabilities():
        return await mcp_server.get_capabilities()
    
    @app.post("/mcp")
    async def handle_mcp_request(request: dict):
        try:
            result = await mcp_server.handle_request(request)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    # Add individual endpoint routes for direct access
    @app.post("/threat/check_ip")
    async def check_ip_reputation(request: dict):
        ip = request.get('ip')
        if not ip:
            raise HTTPException(status_code=400, detail="IP address required")
        
        async with ThreatIntelligenceAggregator() as aggregator:
            result = await aggregator.check_ip_reputation(ip)
            return {"success": True, "data": result}
    
    @app.post("/threat/check_domain")
    async def check_domain_reputation(request: dict):
        domain = request.get('domain')
        if not domain:
            raise HTTPException(status_code=400, detail="Domain required")
        
        async with ThreatIntelligenceAggregator() as aggregator:
            result = await aggregator.check_domain_reputation(domain)
            return {"success": True, "data": result}
    
    @app.post("/threat/check_hash")
    async def check_file_hash(request: dict):
        file_hash = request.get('file_hash')
        if not file_hash:
            raise HTTPException(status_code=400, detail="File hash required")
        
        async with ThreatIntelligenceAggregator() as aggregator:
            result = await aggregator.check_file_hash(file_hash)
            return {"success": True, "data": result}
    
    @app.post("/threat/hunt")
    async def threat_hunt(request: dict):
        indicators = request.get('indicators', [])
        if not indicators:
            raise HTTPException(status_code=400, detail="Indicators list required")
        
        async with ThreatIntelligenceAggregator() as aggregator:
            result = await aggregator.threat_hunt(indicators)
            return {"success": True, "data": result}
    
    print("Starting Threat Intelligence Aggregator MCP Server on port 8020...")
    uvicorn.run(app, host="0.0.0.0", port=8020)