"""
API Connection Monitor for Enterprise OSINT Platform

This module provides real-time monitoring and fallback mechanisms for all external API connections.
Ensures the platform remains operational even when external services are unavailable.
"""

import asyncio
import aiohttp
import time
import logging
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
import json
import os
from contextlib import asynccontextmanager

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class APIStatus(Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"
    RATE_LIMITED = "rate_limited"
    QUOTA_EXCEEDED = "quota_exceeded"
    UNKNOWN = "unknown"

class APIType(Enum):
    SOCIAL_MEDIA = "social_media"
    INFRASTRUCTURE = "infrastructure"
    THREAT_INTELLIGENCE = "threat_intelligence"
    AI_ML = "ai_ml"
    CORPORATE = "corporate"

@dataclass
class APIEndpoint:
    """Configuration for external API endpoint"""
    name: str
    api_type: APIType
    base_url: str
    health_check_endpoint: str
    api_key_env_var: str
    required: bool = False
    timeout_seconds: int = 10
    retry_attempts: int = 3
    rate_limit_per_minute: int = 60
    cost_per_request: float = 0.0
    description: str = ""

@dataclass
class APIStatusInfo:
    """Status information for an API endpoint"""
    name: str
    api_type: APIType
    status: APIStatus
    last_check: datetime
    response_time_ms: Optional[int]
    error_message: Optional[str]
    success_rate: float
    total_requests: int
    failed_requests: int
    last_successful_request: Optional[datetime]
    rate_limit_reset: Optional[datetime]
    quota_remaining: Optional[int]
    estimated_cost_today: float
    availability_percentage: float

class APIConnectionMonitor:
    """Monitor and manage external API connections with fallback mechanisms"""
    
    def __init__(self):
        """Initialize the API connection monitor"""
        self.api_endpoints: Dict[str, APIEndpoint] = {}
        self.api_status: Dict[str, APIStatusInfo] = {}
        self.request_history: Dict[str, List[Dict[str, Any]]] = {}
        self.fallback_enabled = True
        self.monitoring_enabled = True
        self.check_interval_seconds = 60
        
        # Initialize default API endpoints
        self._initialize_default_endpoints()
        
        # Start background monitoring
        self._monitoring_task = None
        
    def _initialize_default_endpoints(self):
        """Initialize default external API endpoints"""
        
        # Social Media APIs
        self.add_endpoint(APIEndpoint(
            name="twitter",
            api_type=APIType.SOCIAL_MEDIA,
            base_url="https://api.twitter.com/2",
            health_check_endpoint="/users/by/username/twitter",
            api_key_env_var="TWITTER_BEARER_TOKEN",
            required=False,
            rate_limit_per_minute=300,
            cost_per_request=0.01,
            description="Twitter/X API for social media intelligence"
        ))
        
        self.add_endpoint(APIEndpoint(
            name="reddit",
            api_type=APIType.SOCIAL_MEDIA,
            base_url="https://www.reddit.com/api/v1",
            health_check_endpoint="/me",
            api_key_env_var="REDDIT_CLIENT_ID",
            required=False,
            rate_limit_per_minute=100,
            cost_per_request=0.0,
            description="Reddit API for community discussions and sentiment"
        ))
        
        self.add_endpoint(APIEndpoint(
            name="linkedin",
            api_type=APIType.SOCIAL_MEDIA,
            base_url="https://api.linkedin.com/v2",
            health_check_endpoint="/people/(id={person-id})",
            api_key_env_var="LINKEDIN_ACCESS_TOKEN",
            required=False,
            rate_limit_per_minute=500,
            cost_per_request=0.005,
            description="LinkedIn API for professional network analysis"
        ))
        
        # Infrastructure APIs
        self.add_endpoint(APIEndpoint(
            name="shodan",
            api_type=APIType.INFRASTRUCTURE,
            base_url="https://api.shodan.io",
            health_check_endpoint="/api-info",
            api_key_env_var="SHODAN_API_KEY",
            required=False,
            rate_limit_per_minute=100,
            cost_per_request=0.10,
            description="Shodan API for internet-connected device discovery"
        ))
        
        self.add_endpoint(APIEndpoint(
            name="virustotal",
            api_type=APIType.INFRASTRUCTURE,
            base_url="https://www.virustotal.com/api/v3",
            health_check_endpoint="/users/current",
            api_key_env_var="VIRUSTOTAL_API_KEY",
            required=False,
            rate_limit_per_minute=1000,
            cost_per_request=0.02,
            description="VirusTotal API for malware analysis and reputation"
        ))
        
        self.add_endpoint(APIEndpoint(
            name="whoisxml",
            api_type=APIType.INFRASTRUCTURE,
            base_url="https://www.whoisxmlapi.com/whoisserver/WhoisService",
            health_check_endpoint="?domainName=example.com&username=demo",
            api_key_env_var="WHOISXML_API_KEY",
            required=False,
            rate_limit_per_minute=1000,
            cost_per_request=0.01,
            description="WhoisXML API for domain registration information"
        ))
        
        # Threat Intelligence APIs
        self.add_endpoint(APIEndpoint(
            name="alienvault_otx",
            api_type=APIType.THREAT_INTELLIGENCE,
            base_url="https://otx.alienvault.com/api/v1",
            health_check_endpoint="/user/me",
            api_key_env_var="ALIENVAULT_API_KEY",
            required=False,
            rate_limit_per_minute=1000,
            cost_per_request=0.0,
            description="AlienVault OTX for threat intelligence feeds"
        ))
        
        self.add_endpoint(APIEndpoint(
            name="abuseipdb",
            api_type=APIType.THREAT_INTELLIGENCE,
            base_url="https://api.abuseipdb.com/api/v2",
            health_check_endpoint="/check",
            api_key_env_var="ABUSEIPDB_API_KEY",
            required=False,
            rate_limit_per_minute=1000,
            cost_per_request=0.0,
            description="AbuseIPDB for IP reputation and abuse reporting"
        ))
        
        self.add_endpoint(APIEndpoint(
            name="greynoise",
            api_type=APIType.THREAT_INTELLIGENCE,
            base_url="https://api.greynoise.io/v3",
            health_check_endpoint="/account",
            api_key_env_var="GREYNOISE_API_KEY",
            required=False,
            rate_limit_per_minute=1000,
            cost_per_request=0.001,
            description="GreyNoise for internet background noise analysis"
        ))
        
        # AI/ML APIs
        self.add_endpoint(APIEndpoint(
            name="openai",
            api_type=APIType.AI_ML,
            base_url="https://api.openai.com/v1",
            health_check_endpoint="/models",
            api_key_env_var="OPENAI_API_KEY",
            required=True,  # Critical for analysis
            rate_limit_per_minute=3000,
            cost_per_request=0.05,
            description="OpenAI API for intelligence analysis and report generation"
        ))
        
        # Corporate Intelligence APIs
        self.add_endpoint(APIEndpoint(
            name="clearbit",
            api_type=APIType.CORPORATE,
            base_url="https://person.clearbit.com/v2",
            health_check_endpoint="/combined/find",
            api_key_env_var="CLEARBIT_API_KEY",
            required=False,
            rate_limit_per_minute=600,
            cost_per_request=0.50,
            description="Clearbit API for corporate and person enrichment"
        ))
        
    def add_endpoint(self, endpoint: APIEndpoint):
        """Add an API endpoint to monitor"""
        self.api_endpoints[endpoint.name] = endpoint
        
        # Initialize status tracking
        self.api_status[endpoint.name] = APIStatusInfo(
            name=endpoint.name,
            api_type=endpoint.api_type,
            status=APIStatus.UNKNOWN,
            last_check=datetime.now(timezone.utc),
            response_time_ms=None,
            error_message=None,
            success_rate=0.0,
            total_requests=0,
            failed_requests=0,
            last_successful_request=None,
            rate_limit_reset=None,
            quota_remaining=None,
            estimated_cost_today=0.0,
            availability_percentage=0.0
        )
        
        # Initialize request history
        self.request_history[endpoint.name] = []
        
    async def check_api_health(self, api_name: str) -> APIStatusInfo:
        """Check the health of a specific API endpoint"""
        if api_name not in self.api_endpoints:
            raise ValueError(f"Unknown API endpoint: {api_name}")
            
        endpoint = self.api_endpoints[api_name]
        status_info = self.api_status[api_name]
        
        start_time = time.time()
        
        try:
            # Get API key from environment
            api_key = os.getenv(endpoint.api_key_env_var)
            if not api_key and endpoint.required:
                status_info.status = APIStatus.OFFLINE
                status_info.error_message = f"Missing required API key: {endpoint.api_key_env_var}"
                status_info.last_check = datetime.now(timezone.utc)
                return status_info
            elif not api_key:
                status_info.status = APIStatus.OFFLINE
                status_info.error_message = f"API key not configured: {endpoint.api_key_env_var}"
                status_info.last_check = datetime.now(timezone.utc)
                return status_info
            
            # Prepare headers
            headers = self._get_api_headers(api_name, api_key)
            
            # Make health check request
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=endpoint.timeout_seconds)) as session:
                url = f"{endpoint.base_url}{endpoint.health_check_endpoint}"
                
                async with session.get(url, headers=headers) as response:
                    response_time_ms = int((time.time() - start_time) * 1000)
                    
                    if response.status == 200:
                        status_info.status = APIStatus.ONLINE
                        status_info.error_message = None
                        status_info.last_successful_request = datetime.now(timezone.utc)
                    elif response.status == 429:
                        status_info.status = APIStatus.RATE_LIMITED
                        status_info.error_message = "Rate limit exceeded"
                        # Try to parse rate limit reset time
                        reset_time = response.headers.get('X-RateLimit-Reset')
                        if reset_time:
                            status_info.rate_limit_reset = datetime.fromtimestamp(int(reset_time), timezone.utc)
                    elif response.status == 402 or response.status == 403:
                        status_info.status = APIStatus.QUOTA_EXCEEDED
                        status_info.error_message = "Quota exceeded or payment required"
                    else:
                        status_info.status = APIStatus.DEGRADED
                        status_info.error_message = f"HTTP {response.status}: {response.reason}"
                    
                    status_info.response_time_ms = response_time_ms
                    
                    # Parse quota information if available
                    quota_remaining = response.headers.get('X-RateLimit-Remaining')
                    if quota_remaining:
                        status_info.quota_remaining = int(quota_remaining)
                        
        except asyncio.TimeoutError:
            status_info.status = APIStatus.OFFLINE
            status_info.error_message = f"Request timeout after {endpoint.timeout_seconds}s"
            status_info.response_time_ms = None
            
        except aiohttp.ClientError as e:
            status_info.status = APIStatus.OFFLINE
            status_info.error_message = f"Connection error: {str(e)}"
            status_info.response_time_ms = None
            
        except Exception as e:
            status_info.status = APIStatus.OFFLINE
            status_info.error_message = f"Unexpected error: {str(e)}"
            status_info.response_time_ms = None
            
        # Update status tracking
        status_info.last_check = datetime.now(timezone.utc)
        status_info.total_requests += 1
        
        if status_info.status != APIStatus.ONLINE:
            status_info.failed_requests += 1
            
        # Calculate success rate
        if status_info.total_requests > 0:
            status_info.success_rate = ((status_info.total_requests - status_info.failed_requests) / 
                                      status_info.total_requests) * 100
        
        # Log status change
        logger.info(f"API {api_name} health check: {status_info.status.value} "
                   f"({response_time_ms if 'response_time_ms' in locals() else 'N/A'}ms)")
        
        return status_info
    
    def _get_api_headers(self, api_name: str, api_key: str) -> Dict[str, str]:
        """Get appropriate headers for each API"""
        headers = {
            "User-Agent": "Enterprise-OSINT-Platform/1.0"
        }
        
        # API-specific header formats
        if api_name == "twitter":
            headers["Authorization"] = f"Bearer {api_key}"
        elif api_name == "openai":
            headers["Authorization"] = f"Bearer {api_key}"
            headers["Content-Type"] = "application/json"
        elif api_name == "shodan":
            # Shodan uses API key as query parameter, not header
            pass
        elif api_name in ["virustotal", "abuseipdb", "greynoise"]:
            headers["x-apikey"] = api_key
        elif api_name == "alienvault_otx":
            headers["X-OTX-API-KEY"] = api_key
        elif api_name == "clearbit":
            headers["Authorization"] = f"Bearer {api_key}"
        elif api_name == "whoisxml":
            # WhoisXML uses username/password, not API key
            pass
        else:
            # Generic API key header
            headers["X-API-Key"] = api_key
            
        return headers
    
    async def check_all_apis(self) -> Dict[str, APIStatusInfo]:
        """Check the health of all configured API endpoints"""
        tasks = []
        
        for api_name in self.api_endpoints.keys():
            task = asyncio.create_task(self.check_api_health(api_name))
            tasks.append((api_name, task))
        
        # Wait for all health checks to complete
        results = {}
        for api_name, task in tasks:
            try:
                results[api_name] = await task
            except Exception as e:
                logger.error(f"Failed to check {api_name}: {str(e)}")
                # Create error status
                results[api_name] = APIStatusInfo(
                    name=api_name,
                    api_type=self.api_endpoints[api_name].api_type,
                    status=APIStatus.OFFLINE,
                    last_check=datetime.now(timezone.utc),
                    response_time_ms=None,
                    error_message=str(e),
                    success_rate=0.0,
                    total_requests=0,
                    failed_requests=0,
                    last_successful_request=None,
                    rate_limit_reset=None,
                    quota_remaining=None,
                    estimated_cost_today=0.0,
                    availability_percentage=0.0
                )
        
        return results
    
    def get_apis_by_type(self, api_type: APIType) -> Dict[str, APIStatusInfo]:
        """Get API status information filtered by type"""
        return {
            name: status for name, status in self.api_status.items()
            if self.api_endpoints[name].api_type == api_type
        }
    
    def get_available_apis(self, api_type: Optional[APIType] = None) -> List[str]:
        """Get list of currently available API endpoints"""
        available = []
        
        for name, status in self.api_status.items():
            if status.status == APIStatus.ONLINE:
                if api_type is None or self.api_endpoints[name].api_type == api_type:
                    available.append(name)
        
        return available
    
    def get_fallback_apis(self, api_type: APIType) -> List[str]:
        """Get list of fallback APIs for a specific type"""
        fallbacks = []
        
        # Get all APIs of the requested type, prioritize by availability
        type_apis = [(name, status) for name, status in self.api_status.items()
                    if self.api_endpoints[name].api_type == api_type]
        
        # Sort by status priority (online first, then degraded, then offline)
        status_priority = {
            APIStatus.ONLINE: 1,
            APIStatus.DEGRADED: 2,
            APIStatus.RATE_LIMITED: 3,
            APIStatus.QUOTA_EXCEEDED: 4,
            APIStatus.OFFLINE: 5,
            APIStatus.UNKNOWN: 6
        }
        
        type_apis.sort(key=lambda x: (status_priority.get(x[1].status, 6), x[1].response_time_ms or 9999))
        
        return [name for name, status in type_apis]
    
    def is_api_available(self, api_name: str) -> bool:
        """Check if a specific API is currently available"""
        if api_name not in self.api_status:
            return False
            
        status = self.api_status[api_name].status
        return status in [APIStatus.ONLINE, APIStatus.DEGRADED]
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get overall system status including all APIs"""
        total_apis = len(self.api_endpoints)
        online_apis = len([s for s in self.api_status.values() if s.status == APIStatus.ONLINE])
        degraded_apis = len([s for s in self.api_status.values() if s.status == APIStatus.DEGRADED])
        offline_apis = len([s for s in self.api_status.values() if s.status == APIStatus.OFFLINE])
        
        # Calculate overall system health
        if online_apis == total_apis:
            system_status = "healthy"
        elif online_apis + degraded_apis >= total_apis * 0.8:
            system_status = "degraded"
        elif online_apis + degraded_apis >= total_apis * 0.5:
            system_status = "limited"
        else:
            system_status = "critical"
        
        # Check critical APIs
        critical_apis_available = all(
            self.is_api_available(name) for name, endpoint in self.api_endpoints.items()
            if endpoint.required
        )
        
        return {
            "system_status": system_status,
            "critical_apis_available": critical_apis_available,
            "total_apis": total_apis,
            "online_apis": online_apis,
            "degraded_apis": degraded_apis,
            "offline_apis": offline_apis,
            "fallback_mode": not critical_apis_available,
            "last_check": max([s.last_check for s in self.api_status.values()]) if self.api_status else None,
            "api_breakdown": {
                api_type.value: {
                    "total": len([e for e in self.api_endpoints.values() if e.api_type == api_type]),
                    "available": len(self.get_available_apis(api_type))
                } for api_type in APIType
            }
        }
    
    def get_api_costs_today(self) -> Dict[str, float]:
        """Calculate estimated API costs for today"""
        costs = {}
        today = datetime.now(timezone.utc).date()
        
        for api_name, endpoint in self.api_endpoints.items():
            # Count requests made today (simplified - would need actual request tracking)
            daily_requests = len([
                req for req in self.request_history.get(api_name, [])
                if datetime.fromisoformat(req['timestamp']).date() == today
            ])
            
            costs[api_name] = daily_requests * endpoint.cost_per_request
            
        return costs
    
    async def start_monitoring(self):
        """Start background monitoring of API endpoints"""
        if self._monitoring_task is not None:
            return
            
        self.monitoring_enabled = True
        self._monitoring_task = asyncio.create_task(self._monitoring_loop())
        logger.info("API monitoring started")
    
    async def stop_monitoring(self):
        """Stop background monitoring"""
        self.monitoring_enabled = False
        if self._monitoring_task:
            self._monitoring_task.cancel()
            try:
                await self._monitoring_task
            except asyncio.CancelledError:
                pass
            self._monitoring_task = None
        logger.info("API monitoring stopped")
    
    async def _monitoring_loop(self):
        """Background monitoring loop"""
        while self.monitoring_enabled:
            try:
                await self.check_all_apis()
                await asyncio.sleep(self.check_interval_seconds)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in monitoring loop: {str(e)}")
                await asyncio.sleep(min(self.check_interval_seconds, 30))
    
    def log_api_request(self, api_name: str, success: bool, response_time_ms: int, 
                       error_message: Optional[str] = None):
        """Log an API request for tracking and cost calculation"""
        if api_name not in self.request_history:
            self.request_history[api_name] = []
        
        request_log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "success": success,
            "response_time_ms": response_time_ms,
            "error_message": error_message
        }
        
        self.request_history[api_name].append(request_log)
        
        # Keep only last 1000 requests per API for memory management
        if len(self.request_history[api_name]) > 1000:
            self.request_history[api_name] = self.request_history[api_name][-1000:]
        
        # Update estimated cost
        if success and api_name in self.api_endpoints:
            endpoint = self.api_endpoints[api_name]
            self.api_status[api_name].estimated_cost_today += endpoint.cost_per_request

# Global instance
api_monitor = APIConnectionMonitor()

async def get_api_monitor() -> APIConnectionMonitor:
    """Get the global API monitor instance"""
    return api_monitor

async def check_api_availability(api_name: str) -> bool:
    """Quick check if an API is available"""
    monitor = await get_api_monitor()
    return monitor.is_api_available(api_name)

async def get_fallback_for_type(api_type: APIType) -> Optional[str]:
    """Get the best available fallback API for a given type"""
    monitor = await get_api_monitor()
    available = monitor.get_available_apis(api_type)
    return available[0] if available else None

if __name__ == "__main__":
    # Test the API monitor
    async def test_monitor():
        monitor = APIConnectionMonitor()
        
        # Start monitoring
        await monitor.start_monitoring()
        
        # Wait a bit for initial checks
        await asyncio.sleep(5)
        
        # Check system status
        status = monitor.get_system_status()
        print(f"System Status: {status}")
        
        # Check individual APIs
        for api_name in monitor.api_endpoints.keys():
            api_status = monitor.api_status[api_name]
            print(f"{api_name}: {api_status.status.value} "
                  f"({api_status.response_time_ms}ms) - {api_status.error_message or 'OK'}")
        
        # Stop monitoring
        await monitor.stop_monitoring()
    
    asyncio.run(test_monitor())