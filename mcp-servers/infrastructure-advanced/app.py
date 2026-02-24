#!/usr/bin/env python3
"""
Advanced Infrastructure Intelligence MCP Server
Enhanced capabilities for comprehensive infrastructure reconnaissance
"""

import os
import ssl
import socket
import json
import asyncio
import aiohttp
from datetime import datetime
from typing import Dict, List, Any, Optional
import dns.resolver
import dns.reversename
import whois
import ipaddress
import certifi
from functools import lru_cache

from passive_dns_circl import CIRCLPassiveDNS
from cert_chain import CertificateChainAnalyzer

class AdvancedInfrastructureIntel:
    """Advanced infrastructure intelligence gathering"""
    
    def __init__(self):
        self.session = None
        self.securitytrails_api_key = os.getenv('SECURITYTRAILS_API_KEY')
        self.censys_api_id = os.getenv('CENSYS_API_ID')
        self.censys_api_secret = os.getenv('CENSYS_API_SECRET')
        
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.session.close()

    async def certificate_transparency(self, domain: str) -> Dict[str, Any]:
        """Query certificate transparency logs via crt.sh"""
        try:
            url = f"https://crt.sh/?q={domain}&output=json"
            async with self.session.get(url, ssl=False) as response:
                if response.status == 200:
                    certs = await response.json()
                    
                    # Extract unique subdomains
                    subdomains = set()
                    for cert in certs:
                        names = cert.get('name_value', '').split('\n')
                        for name in names:
                            if name and '*' not in name:
                                subdomains.add(name.lower())
                    
                    return {
                        'certificate_count': len(certs),
                        'subdomains': sorted(list(subdomains)),
                        'certificates': certs[:10],  # Latest 10 certificates
                        'first_seen': min([cert['entry_timestamp'] for cert in certs]) if certs else None,
                        'last_seen': max([cert['entry_timestamp'] for cert in certs]) if certs else None
                    }
                    
        except Exception as e:
            return {'error': str(e)}

    async def passive_dns(self, domain: str) -> Dict[str, Any]:
        """Query passive DNS data"""
        if not self.securitytrails_api_key:
            return {'error': 'SecurityTrails API key not configured'}
            
        try:
            headers = {'APIKEY': self.securitytrails_api_key}
            
            # Get historical DNS records
            url = f"https://api.securitytrails.com/v1/history/{domain}/dns"
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        'historical_records': data,
                        'record_types': list(data.keys()),
                        'total_changes': sum(len(records) for records in data.values())
                    }
                    
        except Exception as e:
            return {'error': str(e)}

    async def passive_dns_multi(self, domain: str) -> Dict[str, Any]:
        """Multi-source passive DNS: CIRCL pDNS (free, always) + SecurityTrails (if key set).

        Returns a merged view with per-source results and a deduplicated list of
        all unique IPs seen across sources.
        """
        sources: Dict[str, Any] = {}

        # Source 1: CIRCL pDNS — free, no API key required
        try:
            async with CIRCLPassiveDNS() as circl:
                circl_result = await circl.query(domain)
            sources['circl_pdns'] = circl_result
        except Exception as exc:
            sources['circl_pdns'] = {'error': str(exc), 'source': 'circl_pdns'}

        # Source 2: SecurityTrails — only if API key is present
        if self.securitytrails_api_key:
            st_result = await self.passive_dns(domain)
            if 'error' not in st_result:
                sources['securitytrails'] = st_result
            else:
                sources['securitytrails'] = st_result  # include the error for transparency

        # Merge unique IPs across all sources
        all_ips: set = set()
        for src_name, src_data in sources.items():
            for ip in src_data.get('unique_ips', []):
                all_ips.add(ip)

        return {
            'domain': domain,
            'sources': sources,
            'unique_ips': sorted(all_ips),
            'source_count': len(sources),
        }

    async def certificate_deep_analysis(self, domain: str) -> Dict[str, Any]:
        """Deep certificate analysis: CT log history + live cert chain (SANs, expiry, fingerprint).

        Combines:
        * crt.sh certificate transparency query (historical certs + discovered subdomains)
        * Live TLS handshake parsed by CertificateChainAnalyzer (SANs, expiry alert, fingerprint)
        """
        result: Dict[str, Any] = {
            'domain': domain,
            'ct_history': {},
            'live_cert': {},
            'all_sans': [],
            'expiry_alert': None,
        }

        # --- CT log history (crt.sh) ---
        try:
            ct_data = await self.certificate_transparency(domain)
            result['ct_history'] = ct_data
            ct_sans = ct_data.get('subdomains', [])
        except Exception as exc:
            result['ct_history'] = {'error': str(exc)}
            ct_sans = []

        # --- Live TLS certificate ---
        try:
            live = await CertificateChainAnalyzer.fetch_live_cert(domain)
            result['live_cert'] = live
            live_sans = live.get('subject_alt_names', [])
            result['expiry_alert'] = live.get('expiry_alert')
        except Exception as exc:
            result['live_cert'] = {'error': str(exc)}
            live_sans = []

        # Merge and deduplicate SANs from both sources
        result['all_sans'] = CertificateChainAnalyzer.merge_san_lists(ct_sans, live_sans)

        return result

    async def asn_lookup(self, ip: str) -> Dict[str, Any]:
        """Get ASN information for an IP address"""
        try:
            # Team Cymru whois service
            resolver = dns.resolver.Resolver()
            
            # Reverse the IP for DNS query
            reversed_ip = '.'.join(reversed(ip.split('.')))
            query = f"{reversed_ip}.origin.asn.cymru.com"
            
            try:
                answers = resolver.resolve(query, 'TXT')
                for rdata in answers:
                    # Parse ASN response
                    parts = str(rdata).strip('"').split(' | ')
                    if len(parts) >= 3:
                        return {
                            'asn': f"AS{parts[0]}",
                            'ip_range': parts[1],
                            'country': parts[2],
                            'registry': parts[3] if len(parts) > 3 else None,
                            'allocated': parts[4] if len(parts) > 4 else None
                        }
            except:
                pass
                
            # Fallback to basic GeoIP
            return await self.geoip_lookup(ip)
            
        except Exception as e:
            return {'error': str(e)}

    async def geoip_lookup(self, ip: str) -> Dict[str, Any]:
        """Get geographic information for an IP"""
        try:
            url = f"http://ip-api.com/json/{ip}"
            async with self.session.get(url) as response:
                if response.status == 200:
                    return await response.json()
        except:
            return {'error': 'GeoIP lookup failed'}

    async def reverse_ip_lookup(self, ip: str) -> Dict[str, Any]:
        """Find other domains hosted on the same IP"""
        try:
            # Use Bing search for reverse IP (no API key needed)
            query = f"ip:{ip}"
            url = f"https://www.bing.com/search?q={query}"
            
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    # Note: In production, parse HTML response properly
                    return {
                        'ip': ip,
                        'note': 'Reverse IP lookup requires HTML parsing',
                        'alternative': 'Use SecurityTrails or Censys API for better results'
                    }
                    
        except Exception as e:
            return {'error': str(e)}

    async def port_scan(self, host: str, common_ports: bool = True) -> Dict[str, Any]:
        """Basic port scanning for common services"""
        if common_ports:
            ports = [21, 22, 23, 25, 53, 80, 110, 443, 445, 3306, 3389, 8080, 8443]
        else:
            ports = range(1, 1001)  # Top 1000 ports
            
        open_ports = []
        
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            
            result = sock.connect_ex((host, port))
            if result == 0:
                service = self._identify_service(port)
                open_ports.append({
                    'port': port,
                    'state': 'open',
                    'service': service
                })
            
            sock.close()
            
        return {
            'host': host,
            'scan_type': 'common_ports' if common_ports else 'top_1000',
            'open_ports': open_ports,
            'total_ports_scanned': len(ports),
            'total_open': len(open_ports)
        }

    def _identify_service(self, port: int) -> str:
        """Identify common services by port number"""
        services = {
            21: 'ftp',
            22: 'ssh',
            23: 'telnet',
            25: 'smtp',
            53: 'dns',
            80: 'http',
            110: 'pop3',
            443: 'https',
            445: 'smb',
            3306: 'mysql',
            3389: 'rdp',
            8080: 'http-alt',
            8443: 'https-alt'
        }
        return services.get(port, 'unknown')

    async def web_technologies(self, url: str) -> Dict[str, Any]:
        """Detect web technologies used by a website"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (compatible; OSINT-Bot/1.0)'
            }
            
            async with self.session.get(url, headers=headers, allow_redirects=True) as response:
                if response.status == 200:
                    # Analyze headers
                    tech_stack = []
                    
                    # Server header
                    if 'Server' in response.headers:
                        tech_stack.append({
                            'category': 'Web Server',
                            'name': response.headers['Server']
                        })
                    
                    # X-Powered-By
                    if 'X-Powered-By' in response.headers:
                        tech_stack.append({
                            'category': 'Framework',
                            'name': response.headers['X-Powered-By']
                        })
                    
                    # Content Management Systems
                    content = await response.text()
                    
                    if 'wp-content' in content or 'wordpress' in content.lower():
                        tech_stack.append({
                            'category': 'CMS',
                            'name': 'WordPress'
                        })
                    elif 'joomla' in content.lower():
                        tech_stack.append({
                            'category': 'CMS',
                            'name': 'Joomla'
                        })
                    elif 'drupal' in content.lower():
                        tech_stack.append({
                            'category': 'CMS',
                            'name': 'Drupal'
                        })
                    
                    return {
                        'url': str(response.url),
                        'status_code': response.status,
                        'technologies': tech_stack,
                        'headers': dict(response.headers),
                        'cookies': [{'name': c.key, 'secure': c.get('secure', False)} 
                                   for c in response.cookies.values()]
                    }
                    
        except Exception as e:
            return {'error': str(e)}

    async def subdomain_takeover_check(self, subdomain: str) -> Dict[str, Any]:
        """Check if subdomain is vulnerable to takeover"""
        try:
            # Resolve CNAME
            resolver = dns.resolver.Resolver()
            
            try:
                answers = resolver.resolve(subdomain, 'CNAME')
                cname = str(answers[0].target)
                
                # Check against known vulnerable services
                vulnerable_services = {
                    'amazonaws.com': 'AWS S3',
                    'azurewebsites.net': 'Azure',
                    'cloudapp.net': 'Azure',
                    'github.io': 'GitHub Pages',
                    'herokuapp.com': 'Heroku',
                    'surge.sh': 'Surge.sh',
                    'netlify.com': 'Netlify'
                }
                
                for service, name in vulnerable_services.items():
                    if service in cname:
                        # Check if actually vulnerable
                        try:
                            socket.gethostbyname(subdomain)
                        except socket.gaierror:
                            return {
                                'vulnerable': True,
                                'subdomain': subdomain,
                                'cname': cname,
                                'service': name,
                                'risk': 'HIGH'
                            }
                
                return {
                    'vulnerable': False,
                    'subdomain': subdomain,
                    'cname': cname
                }
                
            except dns.resolver.NXDOMAIN:
                return {
                    'vulnerable': False,
                    'subdomain': subdomain,
                    'error': 'Subdomain does not exist'
                }
                
        except Exception as e:
            return {'error': str(e)}

    async def comprehensive_recon(self, target: str) -> Dict[str, Any]:
        """Perform comprehensive reconnaissance on a target"""
        results = {
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'intelligence': {}
        }
        
        # Determine if target is IP or domain
        try:
            ipaddress.ip_address(target)
            is_ip = True
        except ValueError:
            is_ip = False
        
        if is_ip:
            # IP-based recon
            results['intelligence']['asn'] = await self.asn_lookup(target)
            results['intelligence']['reverse_dns'] = await self._reverse_dns_lookup(target)
            results['intelligence']['geolocation'] = await self.geoip_lookup(target)
            results['intelligence']['reverse_ip'] = await self.reverse_ip_lookup(target)
        else:
            # Domain-based recon
            results['intelligence']['whois'] = await self._whois_lookup(target)
            results['intelligence']['dns'] = await self._comprehensive_dns_lookup(target)
            # Enhanced: multi-source passive DNS (CIRCL always; SecurityTrails if key present)
            results['intelligence']['passive_dns_multi'] = await self.passive_dns_multi(target)
            # Enhanced: deep certificate analysis (CT history + live cert chain)
            results['intelligence']['certificate_deep_analysis'] = await self.certificate_deep_analysis(target)
            results['intelligence']['web_technologies'] = await self.web_technologies(f"https://{target}")

            # Get IP for port scan
            try:
                ip = socket.gethostbyname(target)
                results['intelligence']['port_scan'] = await self.port_scan(ip)
                results['intelligence']['asn'] = await self.asn_lookup(ip)
            except:
                pass
        
        return results

    async def _reverse_dns_lookup(self, ip: str) -> Dict[str, Any]:
        """Perform reverse DNS lookup"""
        try:
            addr = dns.reversename.from_address(ip)
            resolver = dns.resolver.Resolver()
            answers = resolver.resolve(addr, 'PTR')
            
            return {
                'ip': ip,
                'hostnames': [str(rdata) for rdata in answers]
            }
        except Exception as e:
            return {'error': str(e)}

    async def _whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Enhanced WHOIS lookup"""
        try:
            w = whois.whois(domain)
            return {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'name_servers': w.name_servers if isinstance(w.name_servers, list) else [w.name_servers],
                'status': w.status,
                'emails': w.emails if hasattr(w, 'emails') else None,
                'dnssec': w.dnssec if hasattr(w, 'dnssec') else None
            }
        except Exception as e:
            return {'error': str(e)}

    async def _comprehensive_dns_lookup(self, domain: str) -> Dict[str, Any]:
        """Comprehensive DNS record lookup"""
        records = {}
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA']
        
        resolver = dns.resolver.Resolver()
        
        for record_type in record_types:
            try:
                answers = resolver.resolve(domain, record_type)
                records[record_type] = [str(rdata) for rdata in answers]
            except:
                records[record_type] = []
        
        # Check DNSSEC
        try:
            resolver.resolve(domain, 'DNSKEY')
            records['dnssec'] = True
        except:
            records['dnssec'] = False
            
        return records


# MCP Server Implementation
class InfrastructureAdvancedMCPServer:
    def __init__(self):
        self.intel = None
        
    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP protocol requests"""
        method = request.get('method')
        params = request.get('params', {})
        
        # Initialize intel client if needed
        if not self.intel:
            self.intel = AdvancedInfrastructureIntel()
            await self.intel.__aenter__()
        
        # Route to appropriate handler
        handlers = {
            'infrastructure/certificate_transparency': self.intel.certificate_transparency,
            'infrastructure/passive_dns': self.intel.passive_dns,
            'infrastructure/passive_dns_multi': self.intel.passive_dns_multi,
            'infrastructure/certificate_deep_analysis': self.intel.certificate_deep_analysis,
            'infrastructure/asn_lookup': self.intel.asn_lookup,
            'infrastructure/reverse_ip': self.intel.reverse_ip_lookup,
            'infrastructure/port_scan': self.intel.port_scan,
            'infrastructure/web_technologies': self.intel.web_technologies,
            'infrastructure/subdomain_takeover': self.intel.subdomain_takeover_check,
            'infrastructure/comprehensive_recon': self.intel.comprehensive_recon
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
            'name': 'Infrastructure Advanced Intelligence',
            'version': '2.0.0',
            'methods': [
                {
                    'name': 'infrastructure/certificate_transparency',
                    'description': 'Query certificate transparency logs',
                    'params': ['domain']
                },
                {
                    'name': 'infrastructure/passive_dns',
                    'description': 'Get historical DNS records via SecurityTrails (requires API key)',
                    'params': ['domain']
                },
                {
                    'name': 'infrastructure/passive_dns_multi',
                    'description': 'Multi-source passive DNS: CIRCL pDNS (free, always on) + SecurityTrails (if key set)',
                    'params': ['domain']
                },
                {
                    'name': 'infrastructure/certificate_deep_analysis',
                    'description': 'Deep cert analysis: CT log history (crt.sh) + live TLS cert chain (SANs, expiry, fingerprint)',
                    'params': ['domain']
                },
                {
                    'name': 'infrastructure/asn_lookup',
                    'description': 'Get ASN information for IP',
                    'params': ['ip']
                },
                {
                    'name': 'infrastructure/reverse_ip',
                    'description': 'Find domains on same IP',
                    'params': ['ip']
                },
                {
                    'name': 'infrastructure/port_scan',
                    'description': 'Scan common ports',
                    'params': ['host', 'common_ports']
                },
                {
                    'name': 'infrastructure/web_technologies',
                    'description': 'Detect web technologies',
                    'params': ['url']
                },
                {
                    'name': 'infrastructure/subdomain_takeover',
                    'description': 'Check subdomain takeover vulnerability',
                    'params': ['subdomain']
                },
                {
                    'name': 'infrastructure/comprehensive_recon',
                    'description': 'Full infrastructure reconnaissance',
                    'params': ['target']
                }
            ]
        }


if __name__ == '__main__':
    import uvicorn
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    import asyncio
    
    # Create FastAPI app
    app = FastAPI(
        title="Infrastructure Advanced MCP Server",
        description="Enhanced infrastructure intelligence gathering",
        version="2.0.0"
    )
    
    # Initialize MCP server
    mcp_server = InfrastructureAdvancedMCPServer()
    
    @app.get("/")
    async def root():
        return {"message": "Infrastructure Advanced MCP Server", "version": "2.0.0", "status": "running"}
    
    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "infrastructure-advanced-mcp"}
    
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
    @app.post("/infrastructure/certificate_transparency")
    async def certificate_transparency(request: dict):
        domain = request.get('domain')
        if not domain:
            raise HTTPException(status_code=400, detail="Domain required")
        
        async with AdvancedInfrastructureIntel() as intel:
            result = await intel.certificate_transparency(domain)
            return {"success": True, "data": result}
    
    @app.post("/infrastructure/comprehensive_recon") 
    async def comprehensive_recon(request: dict):
        target = request.get('target')
        if not target:
            raise HTTPException(status_code=400, detail="Target required")
        
        async with AdvancedInfrastructureIntel() as intel:
            result = await intel.comprehensive_recon(target)
            return {"success": True, "data": result}
    
    @app.post("/infrastructure/asn_lookup")
    async def asn_lookup(request: dict):
        ip = request.get('ip')
        if not ip:
            raise HTTPException(status_code=400, detail="IP address required")
            
        async with AdvancedInfrastructureIntel() as intel:
            result = await intel.asn_lookup(ip)
            return {"success": True, "data": result}
    
    @app.post("/infrastructure/port_scan")
    async def port_scan(request: dict):
        host = request.get('host')
        if not host:
            raise HTTPException(status_code=400, detail="Host required")
        
        common_ports = request.get('common_ports', True)
        
        async with AdvancedInfrastructureIntel() as intel:
            result = await intel.port_scan(host, common_ports)
            return {"success": True, "data": result}
    
    @app.post("/infrastructure/web_technologies")
    async def web_technologies(request: dict):
        url = request.get('url')
        if not url:
            raise HTTPException(status_code=400, detail="URL required")

        async with AdvancedInfrastructureIntel() as intel:
            result = await intel.web_technologies(url)
            return {"success": True, "data": result}

    @app.post("/infrastructure/passive_dns_multi")
    async def passive_dns_multi(request: dict):
        domain = request.get('domain')
        if not domain:
            raise HTTPException(status_code=400, detail="Domain required")

        async with AdvancedInfrastructureIntel() as intel:
            result = await intel.passive_dns_multi(domain)
            return {"success": True, "data": result}

    @app.post("/infrastructure/certificate_deep_analysis")
    async def certificate_deep_analysis(request: dict):
        domain = request.get('domain')
        if not domain:
            raise HTTPException(status_code=400, detail="Domain required")

        async with AdvancedInfrastructureIntel() as intel:
            result = await intel.certificate_deep_analysis(domain)
            return {"success": True, "data": result}

    print("Starting Advanced Infrastructure Intelligence MCP Server on port 8021...")
    uvicorn.run(app, host="0.0.0.0", port=8021)