"""
MCP (Model Context Protocol) client for OSINT servers
"""
import os
from typing import Dict, Any, Optional, List
import httpx
import logging
from datetime import datetime
import asyncio

logger = logging.getLogger(__name__)


class MCPClient:
    """Client for communicating with MCP OSINT servers"""
    
    # MCP server configuration
    MCP_SERVERS = {
        "social_media": {
            "url": os.getenv("MCP_SOCIAL_MEDIA_URL", "http://mcp-social-media:8010"),
            "tools": ["analyze_twitter_profile", "analyze_linkedin_company", "search_reddit"]
        },
        "infrastructure": {
            "url": os.getenv("MCP_INFRASTRUCTURE_URL", "http://mcp-infrastructure:8020"),
            "tools": ["whois_lookup", "dns_records", "ssl_certificate_info", "subdomain_enumeration"]
        },
        "threat_intel": {
            "url": os.getenv("MCP_THREAT_INTEL_URL", "http://mcp-threat-intel:8030"),
            "tools": ["threat_assessment", "breach_check", "reputation_check"]
        }
    }
    
    def __init__(self, client: Optional[httpx.AsyncClient] = None):
        self.client = client or httpx.AsyncClient(timeout=30.0)
        self._health_cache: Dict[str, bool] = {}
        self._last_health_check: Dict[str, float] = {}
    
    async def __aenter__(self):
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.client:
            await self.client.aclose()
    
    async def check_server_health(self, server_name: str) -> bool:
        """Check if an MCP server is healthy"""
        try:
            # Cache health checks for 60 seconds
            now = datetime.now().timestamp()
            last_check = self._last_health_check.get(server_name, 0)
            
            if now - last_check < 60 and server_name in self._health_cache:
                return self._health_cache[server_name]
            
            server_config = self.MCP_SERVERS.get(server_name)
            if not server_config:
                logger.error(f"Unknown MCP server: {server_name}")
                return False
            
            response = await self.client.get(f"{server_config['url']}/health")
            is_healthy = response.status_code == 200
            
            # Update cache
            self._health_cache[server_name] = is_healthy
            self._last_health_check[server_name] = now
            
            return is_healthy
            
        except Exception as e:
            logger.error(f"Health check failed for {server_name}: {e}")
            self._health_cache[server_name] = False
            return False
    
    async def get_server_status(self, server_name: str) -> Dict[str, Any]:
        """Get detailed status of an MCP server"""
        try:
            server_config = self.MCP_SERVERS.get(server_name)
            if not server_config:
                return {"status": "error", "message": f"Unknown server: {server_name}"}
            
            response = await self.client.get(f"{server_config['url']}/status")
            if response.status_code == 200:
                return response.json()
            else:
                return {"status": "error", "message": f"Status check failed: {response.status_code}"}
                
        except Exception as e:
            logger.error(f"Status check failed for {server_name}: {e}")
            return {"status": "error", "message": str(e)}
    
    async def call_tool(self, server_name: str, tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Call a specific tool on an MCP server"""
        try:
            server_config = self.MCP_SERVERS.get(server_name)
            if not server_config:
                return {
                    "success": False,
                    "error": f"Unknown MCP server: {server_name}"
                }
            
            # Validate tool exists for this server
            if tool_name not in server_config["tools"]:
                return {
                    "success": False,
                    "error": f"Tool '{tool_name}' not available on server '{server_name}'"
                }
            
            # Check server health first
            if not await self.check_server_health(server_name):
                return {
                    "success": False,
                    "error": f"MCP server '{server_name}' is not healthy"
                }
            
            # Make the request
            payload = {
                "tool": tool_name,
                "parameters": parameters
            }
            
            logger.info(f"Calling {server_name}.{tool_name} with parameters: {parameters}")
            
            response = await self.client.post(
                f"{server_config['url']}/execute",
                json=payload
            )
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Tool {tool_name} completed successfully")
                return result
            else:
                error_msg = f"Tool execution failed: {response.status_code}"
                logger.error(f"{error_msg} - {response.text}")
                return {
                    "success": False,
                    "error": error_msg,
                    "details": response.text
                }
                
        except httpx.TimeoutException:
            error_msg = f"Timeout calling {server_name}.{tool_name}"
            logger.error(error_msg)
            return {"success": False, "error": error_msg}
            
        except Exception as e:
            error_msg = f"Error calling {server_name}.{tool_name}: {str(e)}"
            logger.error(error_msg)
            return {"success": False, "error": error_msg}
    
    async def get_all_servers_status(self) -> Dict[str, Any]:
        """Get status of all MCP servers"""
        results = {}
        
        tasks = []
        for server_name in self.MCP_SERVERS:
            tasks.append(self._get_server_info(server_name))
        
        server_infos = await asyncio.gather(*tasks, return_exceptions=True)
        
        for server_name, info in zip(self.MCP_SERVERS.keys(), server_infos):
            if isinstance(info, Exception):
                results[server_name] = {
                    "healthy": False,
                    "status": "error",
                    "error": str(info)
                }
            else:
                results[server_name] = info
        
        return results
    
    async def _get_server_info(self, server_name: str) -> Dict[str, Any]:
        """Get info for a single server"""
        is_healthy = await self.check_server_health(server_name)
        status = await self.get_server_status(server_name) if is_healthy else {"status": "unreachable"}
        
        return {
            "healthy": is_healthy,
            "url": self.MCP_SERVERS[server_name]["url"],
            "tools": self.MCP_SERVERS[server_name]["tools"],
            "status": status
        }
    
    # Convenience methods for specific tools
    
    async def whois_lookup(self, domain: str) -> Dict[str, Any]:
        """Perform WHOIS lookup on a domain"""
        return await self.call_tool("infrastructure", "whois_lookup", {"domain": domain})
    
    async def analyze_twitter_profile(self, username: str) -> Dict[str, Any]:
        """Analyze a Twitter/X profile"""
        return await self.call_tool("social_media", "analyze_twitter_profile", {"username": username})
    
    async def threat_assessment(self, target: str, target_type: str = "domain") -> Dict[str, Any]:
        """Perform threat assessment on a target"""
        return await self.call_tool("threat_intel", "threat_assessment", {
            "target": target,
            "target_type": target_type
        })
    
    async def dns_records(self, domain: str) -> Dict[str, Any]:
        """Get DNS records for a domain"""
        return await self.call_tool("infrastructure", "dns_records", {"domain": domain})
    
    async def search_reddit(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """Search Reddit for mentions"""
        return await self.call_tool("social_media", "search_reddit", {
            "query": query,
            "limit": limit
        })