"""
MCP (Model Context Protocol) Client for OSINT tools
"""
import asyncio
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import aiohttp
from flask import current_app
import logging

logger = logging.getLogger(__name__)


@dataclass
class MCPTool:
    """MCP Tool definition"""
    name: str
    description: str
    parameters: Dict[str, Any]
    

@dataclass
class MCPServer:
    """MCP Server configuration"""
    name: str
    url: str
    description: str
    tools: List[MCPTool]
    status: str = "unknown"
    

class MCPClient:
    """Client for interacting with MCP servers"""
    
    def __init__(self):
        self.servers = {}
        self._session = None
        self._initialize_servers()
    
    def _initialize_servers(self):
        """Initialize MCP server configurations"""
        self.servers = {
            'social_media': MCPServer(
                name='social_media',
                url=current_app.config.get('MCP_SERVERS', {}).get('social_media', 'http://localhost:8010'),
                description='Social Media Intelligence MCP Server',
                tools=[
                    MCPTool(
                        name='analyze_twitter_profile',
                        description='Analyze Twitter/X profile and activity',
                        parameters={'username': 'string', 'include_tweets': 'boolean'}
                    ),
                    MCPTool(
                        name='analyze_linkedin_company',
                        description='Get LinkedIn company information',
                        parameters={'company_name': 'string', 'include_employees': 'boolean'}
                    ),
                    MCPTool(
                        name='search_reddit',
                        description='Search Reddit for mentions and discussions',
                        parameters={'query': 'string', 'subreddits': 'array', 'time_range': 'string'}
                    ),
                    MCPTool(
                        name='analyze_instagram',
                        description='Analyze Instagram presence',
                        parameters={'handle': 'string'}
                    ),
                    MCPTool(
                        name='analyze_facebook',
                        description='Analyze Facebook page data',
                        parameters={'page_id': 'string'}
                    )
                ]
            ),
            'infrastructure': MCPServer(
                name='infrastructure',
                url=current_app.config.get('MCP_SERVERS', {}).get('infrastructure', 'http://localhost:8020'),
                description='Infrastructure Assessment MCP Server',
                tools=[
                    MCPTool(
                        name='whois_lookup',
                        description='Perform WHOIS domain lookup',
                        parameters={'domain': 'string'}
                    ),
                    MCPTool(
                        name='dns_records',
                        description='Get DNS records for a domain',
                        parameters={'domain': 'string', 'record_types': 'array'}
                    ),
                    MCPTool(
                        name='ssl_certificate_info',
                        description='Analyze SSL certificate information',
                        parameters={'domain': 'string', 'port': 'integer'}
                    ),
                    MCPTool(
                        name='subdomain_enumeration',
                        description='Enumerate subdomains',
                        parameters={'domain': 'string', 'deep_scan': 'boolean'}
                    ),
                    MCPTool(
                        name='technology_detection',
                        description='Detect technology stack',
                        parameters={'url': 'string'}
                    ),
                    MCPTool(
                        name='port_scan',
                        description='Scan for open ports',
                        parameters={'target': 'string', 'port_range': 'string'}
                    )
                ]
            ),
            'threat_intel': MCPServer(
                name='threat_intel',
                url=current_app.config.get('MCP_SERVERS', {}).get('threat_intel', 'http://localhost:8030'),
                description='Threat Intelligence MCP Server',
                tools=[
                    MCPTool(
                        name='threat_assessment',
                        description='Assess threat level for target',
                        parameters={'target': 'string', 'threat_types': 'array'}
                    ),
                    MCPTool(
                        name='breach_check',
                        description='Check for data breaches',
                        parameters={'email': 'string', 'domain': 'string'}
                    ),
                    MCPTool(
                        name='reputation_check',
                        description='Check IP/domain reputation',
                        parameters={'target': 'string', 'target_type': 'string'}
                    ),
                    MCPTool(
                        name='malware_check',
                        description='Check for malware associations',
                        parameters={'domain': 'string', 'file_hash': 'string'}
                    ),
                    MCPTool(
                        name='vulnerability_scan',
                        description='Scan for known vulnerabilities',
                        parameters={'target': 'string', 'scan_type': 'string'}
                    ),
                    MCPTool(
                        name='dark_web_monitoring',
                        description='Monitor dark web mentions',
                        parameters={'keywords': 'array', 'domains': 'array'}
                    )
                ]
            )
        }
    
    async def __aenter__(self):
        """Async context manager entry"""
        self._session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self._session:
            await self._session.close()
    
    async def check_server_status(self, server_name: str) -> Dict[str, Any]:
        """Check MCP server status"""
        server = self.servers.get(server_name)
        if not server:
            return {'status': 'error', 'message': 'Server not found'}
        
        try:
            async with self._session.get(
                f"{server.url}/status",
                timeout=aiohttp.ClientTimeout(total=5)
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    server.status = 'online'
                    return {
                        'status': 'online',
                        'server': server_name,
                        'tools_available': len(server.tools),
                        'details': data
                    }
                else:
                    server.status = 'error'
                    return {
                        'status': 'error',
                        'server': server_name,
                        'message': f'HTTP {response.status}'
                    }
        except asyncio.TimeoutError:
            server.status = 'timeout'
            return {
                'status': 'timeout',
                'server': server_name,
                'message': 'Server timeout'
            }
        except Exception as e:
            server.status = 'error'
            logger.error(f"Error checking MCP server {server_name}: {str(e)}")
            return {
                'status': 'error',
                'server': server_name,
                'message': str(e)
            }
    
    async def execute_tool(self, server_name: str, tool_name: str, 
                          parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a tool on an MCP server"""
        server = self.servers.get(server_name)
        if not server:
            raise ValueError(f"Server {server_name} not found")
        
        # Validate tool exists
        tool = next((t for t in server.tools if t.name == tool_name), None)
        if not tool:
            raise ValueError(f"Tool {tool_name} not found on server {server_name}")
        
        try:
            async with self._session.post(
                f"{server.url}/execute",
                json={
                    'tool': tool_name,
                    'parameters': parameters
                },
                timeout=aiohttp.ClientTimeout(total=30)
            ) as response:
                if response.status == 200:
                    result = await response.json()
                    return {
                        'success': True,
                        'server': server_name,
                        'tool': tool_name,
                        'result': result
                    }
                else:
                    error_data = await response.text()
                    return {
                        'success': False,
                        'server': server_name,
                        'tool': tool_name,
                        'error': f'HTTP {response.status}: {error_data}'
                    }
        except asyncio.TimeoutError:
            return {
                'success': False,
                'server': server_name,
                'tool': tool_name,
                'error': 'Tool execution timeout'
            }
        except Exception as e:
            logger.error(f"Error executing tool {tool_name} on {server_name}: {str(e)}")
            return {
                'success': False,
                'server': server_name,
                'tool': tool_name,
                'error': str(e)
            }
    
    async def execute_investigation_tools(self, target: str, 
                                        investigation_type: str) -> Dict[str, Any]:
        """Execute all relevant tools for an investigation"""
        results = {
            'social_media': {},
            'infrastructure': {},
            'threat_intel': {}
        }
        
        # Social Media Intelligence
        if investigation_type in ['comprehensive', 'social_media']:
            # Twitter analysis
            twitter_result = await self.execute_tool(
                'social_media', 
                'analyze_twitter_profile',
                {'username': target.replace('.com', ''), 'include_tweets': True}
            )
            results['social_media']['twitter'] = twitter_result.get('result', {})
            
            # LinkedIn analysis
            linkedin_result = await self.execute_tool(
                'social_media',
                'analyze_linkedin_company', 
                {'company_name': target, 'include_employees': True}
            )
            results['social_media']['linkedin'] = linkedin_result.get('result', {})
            
            # Reddit search
            reddit_result = await self.execute_tool(
                'social_media',
                'search_reddit',
                {'query': target, 'subreddits': [], 'time_range': 'year'}
            )
            results['social_media']['reddit'] = reddit_result.get('result', {})
        
        # Infrastructure Assessment
        if investigation_type in ['comprehensive', 'infrastructure']:
            # WHOIS lookup
            whois_result = await self.execute_tool(
                'infrastructure',
                'whois_lookup',
                {'domain': target}
            )
            results['infrastructure']['whois'] = whois_result.get('result', {})
            
            # DNS records
            dns_result = await self.execute_tool(
                'infrastructure',
                'dns_records',
                {'domain': target, 'record_types': ['A', 'AAAA', 'MX', 'TXT', 'NS']}
            )
            results['infrastructure']['dns'] = dns_result.get('result', {})
            
            # SSL certificate
            ssl_result = await self.execute_tool(
                'infrastructure',
                'ssl_certificate_info',
                {'domain': target, 'port': 443}
            )
            results['infrastructure']['ssl'] = ssl_result.get('result', {})
            
            # Subdomain enumeration
            subdomain_result = await self.execute_tool(
                'infrastructure',
                'subdomain_enumeration',
                {'domain': target, 'deep_scan': False}
            )
            results['infrastructure']['subdomains'] = subdomain_result.get('result', {})
        
        # Threat Intelligence
        if investigation_type in ['comprehensive', 'threat_assessment']:
            # Threat assessment
            threat_result = await self.execute_tool(
                'threat_intel',
                'threat_assessment',
                {'target': target, 'threat_types': ['malware', 'phishing', 'reputation']}
            )
            results['threat_intel']['assessment'] = threat_result.get('result', {})
            
            # Breach check
            breach_result = await self.execute_tool(
                'threat_intel',
                'breach_check',
                {'domain': target, 'email': ''}
            )
            results['threat_intel']['breaches'] = breach_result.get('result', {})
            
            # Reputation check
            reputation_result = await self.execute_tool(
                'threat_intel',
                'reputation_check',
                {'target': target, 'target_type': 'domain'}
            )
            results['threat_intel']['reputation'] = reputation_result.get('result', {})
        
        return results
    
    def get_all_servers(self) -> List[Dict[str, Any]]:
        """Get all MCP server configurations"""
        return [
            {
                'name': server.name,
                'url': server.url,
                'description': server.description,
                'status': server.status,
                'tools_count': len(server.tools)
            }
            for server in self.servers.values()
        ]
    
    def get_server_tools(self, server_name: str) -> List[Dict[str, Any]]:
        """Get tools for a specific server"""
        server = self.servers.get(server_name)
        if not server:
            return []
        
        return [
            {
                'name': tool.name,
                'description': tool.description,
                'parameters': tool.parameters
            }
            for tool in server.tools
        ]