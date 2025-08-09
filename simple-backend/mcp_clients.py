#!/usr/bin/env python3
"""
MCP Client Services for External Intelligence API Integrations
Implements connections to Social Media, Infrastructure, and Threat Intelligence APIs
"""

import os
import asyncio
import logging
import aiohttp
import json
import time
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class APICredentials:
    """API credentials configuration"""
    api_key: Optional[str] = None
    api_secret: Optional[str] = None
    bearer_token: Optional[str] = None
    base_url: Optional[str] = None
    rate_limit_per_minute: int = 60


@dataclass
class IntelligenceResult:
    """Standardized intelligence data result"""
    source: str
    data_type: str
    target: str
    raw_data: Dict[str, Any]
    processed_data: Dict[str, Any]
    confidence_score: float
    timestamp: datetime
    metadata: Dict[str, Any]


class MCPClientBase(ABC):
    """Base class for MCP intelligence gathering clients"""
    
    def __init__(self, credentials: APICredentials):
        self.credentials = credentials
        self.session: Optional[aiohttp.ClientSession] = None
        self.last_request_time = 0
        self.request_count = 0
        self.rate_limit_window_start = time.time()
    
    async def __aenter__(self):
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self.session:
            await self.session.close()
    
    async def _rate_limit_check(self):
        """Check and enforce rate limits"""
        current_time = time.time()
        
        # Reset counter if window has passed
        if current_time - self.rate_limit_window_start > 60:
            self.request_count = 0
            self.rate_limit_window_start = current_time
        
        # Check rate limit
        if self.request_count >= self.credentials.rate_limit_per_minute:
            wait_time = 60 - (current_time - self.rate_limit_window_start)
            if wait_time > 0:
                logger.warning(f"Rate limit reached for {self.__class__.__name__}, waiting {wait_time:.1f}s")
                await asyncio.sleep(wait_time)
                self.request_count = 0
                self.rate_limit_window_start = time.time()
        
        # Minimum delay between requests
        time_since_last = current_time - self.last_request_time
        min_delay = 1.0  # 1 second minimum between requests
        if time_since_last < min_delay:
            await asyncio.sleep(min_delay - time_since_last)
        
        self.request_count += 1
        self.last_request_time = time.time()
    
    @abstractmethod
    async def gather_intelligence(self, target: str, **kwargs) -> List[IntelligenceResult]:
        """Gather intelligence for the specified target"""
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check API health and connectivity"""
        pass


class SocialMediaMCPClient(MCPClientBase):
    """Social Media Intelligence MCP Client"""
    
    def __init__(self, credentials: Dict[str, APICredentials]):
        # Store multiple API credentials for different platforms
        self.twitter_creds = credentials.get('twitter')
        self.reddit_creds = credentials.get('reddit')
        self.linkedin_creds = credentials.get('linkedin')
        super().__init__(credentials.get('twitter', APICredentials()))
    
    async def gather_intelligence(self, target: str, **kwargs) -> List[IntelligenceResult]:
        """Gather social media intelligence"""
        results = []
        
        try:
            # Twitter/X Intelligence
            if self.twitter_creds and self.twitter_creds.bearer_token:
                twitter_data = await self._gather_twitter_intelligence(target)
                if twitter_data:
                    results.append(twitter_data)
            
            # Reddit Intelligence
            if self.reddit_creds:
                reddit_data = await self._gather_reddit_intelligence(target)
                if reddit_data:
                    results.append(reddit_data)
            
            # LinkedIn Intelligence
            if self.linkedin_creds:
                linkedin_data = await self._gather_linkedin_intelligence(target)
                if linkedin_data:
                    results.append(linkedin_data)
        
        except Exception as e:
            logger.error(f"Social media intelligence gathering failed: {str(e)}")
        
        return results
    
    async def _gather_twitter_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather Twitter/X intelligence"""
        await self._rate_limit_check()
        
        try:
            headers = {
                'Authorization': f'Bearer {self.twitter_creds.bearer_token}',
                'Content-Type': 'application/json'
            }
            
            # Search for mentions of the target
            search_url = 'https://api.twitter.com/2/tweets/search/recent'
            params = {
                'query': f'"{target}" -is:retweet',
                'max_results': 100,
                'tweet.fields': 'author_id,created_at,public_metrics,context_annotations'
            }
            
            async with self.session.get(search_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    # Process Twitter data
                    processed_data = {
                        'platform': 'twitter',
                        'mentions_count': len(data.get('data', [])),
                        'tweets': data.get('data', [])[:10],  # Limit for processing
                        'sentiment': self._analyze_twitter_sentiment(data.get('data', [])),
                        'engagement_metrics': self._calculate_twitter_engagement(data.get('data', [])),
                        'hashtags': self._extract_twitter_hashtags(data.get('data', [])),
                        'user_types': self._analyze_twitter_users(data.get('data', []))
                    }
                    
                    return IntelligenceResult(
                        source='twitter',
                        data_type='social_media',
                        target=target,
                        raw_data=data,
                        processed_data=processed_data,
                        confidence_score=0.8,
                        timestamp=datetime.utcnow(),
                        metadata={'api_version': 'v2', 'query_type': 'recent_search'}
                    )
                else:
                    logger.warning(f"Twitter API error: {response.status}")
                    
        except Exception as e:
            logger.error(f"Twitter intelligence gathering failed: {str(e)}")
        
        return None
    
    async def _gather_reddit_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather Reddit intelligence"""
        await self._rate_limit_check()
        
        try:
            # Use Reddit's public API (no auth required for basic search)
            search_url = f'https://www.reddit.com/search.json'
            params = {
                'q': target,
                'sort': 'relevance',
                'limit': 25,
                't': 'month'  # Last month
            }
            
            headers = {
                'User-Agent': 'OSINT-Platform/1.0'
            }
            
            async with self.session.get(search_url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    processed_data = {
                        'platform': 'reddit',
                        'posts_found': len(data.get('data', {}).get('children', [])),
                        'subreddits': self._extract_reddit_subreddits(data),
                        'sentiment': self._analyze_reddit_sentiment(data),
                        'top_posts': self._extract_reddit_top_posts(data)
                    }
                    
                    return IntelligenceResult(
                        source='reddit',
                        data_type='social_media',
                        target=target,
                        raw_data=data,
                        processed_data=processed_data,
                        confidence_score=0.7,
                        timestamp=datetime.utcnow(),
                        metadata={'query_type': 'search', 'timeframe': 'month'}
                    )
                    
        except Exception as e:
            logger.error(f"Reddit intelligence gathering failed: {str(e)}")
        
        return None
    
    async def _gather_linkedin_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather LinkedIn intelligence (limited due to API restrictions)"""
        # LinkedIn API has severe restrictions, so this would be placeholder
        # In practice, would use web scraping with proper rate limiting and respect for robots.txt
        
        processed_data = {
            'platform': 'linkedin',
            'note': 'LinkedIn intelligence requires specialized API access',
            'company_profile': f'Would search for: {target}',
            'employees': 'API access required',
            'company_updates': 'API access required'
        }
        
        return IntelligenceResult(
            source='linkedin',
            data_type='social_media',
            target=target,
            raw_data={'note': 'API access limited'},
            processed_data=processed_data,
            confidence_score=0.3,
            timestamp=datetime.utcnow(),
            metadata={'status': 'limited_access'}
        )
    
    def _analyze_twitter_sentiment(self, tweets: List[Dict]) -> Dict[str, Any]:
        """Basic Twitter sentiment analysis"""
        if not tweets:
            return {'overall': 0.0, 'positive': 0, 'negative': 0, 'neutral': 0}
        
        # Simple keyword-based sentiment (would use proper NLP in production)
        positive_keywords = ['good', 'great', 'excellent', 'love', 'amazing', 'awesome']
        negative_keywords = ['bad', 'terrible', 'hate', 'awful', 'worse', 'sucks']
        
        sentiment_scores = []
        for tweet in tweets:
            text = tweet.get('text', '').lower()
            pos_count = sum(1 for word in positive_keywords if word in text)
            neg_count = sum(1 for word in negative_keywords if word in text)
            
            if pos_count > neg_count:
                sentiment_scores.append(1)
            elif neg_count > pos_count:
                sentiment_scores.append(-1)
            else:
                sentiment_scores.append(0)
        
        avg_sentiment = sum(sentiment_scores) / len(sentiment_scores) if sentiment_scores else 0
        
        return {
            'overall': round(avg_sentiment, 2),
            'positive': sentiment_scores.count(1),
            'negative': sentiment_scores.count(-1),
            'neutral': sentiment_scores.count(0)
        }
    
    def _calculate_twitter_engagement(self, tweets: List[Dict]) -> Dict[str, int]:
        """Calculate Twitter engagement metrics"""
        total_likes = 0
        total_retweets = 0
        total_replies = 0
        
        for tweet in tweets:
            metrics = tweet.get('public_metrics', {})
            total_likes += metrics.get('like_count', 0)
            total_retweets += metrics.get('retweet_count', 0)
            total_replies += metrics.get('reply_count', 0)
        
        return {
            'total_likes': total_likes,
            'total_retweets': total_retweets,
            'total_replies': total_replies,
            'avg_engagement': round((total_likes + total_retweets + total_replies) / max(len(tweets), 1), 2)
        }
    
    def _extract_twitter_hashtags(self, tweets: List[Dict]) -> List[str]:
        """Extract hashtags from tweets"""
        hashtags = []
        for tweet in tweets:
            text = tweet.get('text', '')
            tweet_hashtags = [word[1:] for word in text.split() if word.startswith('#')]
            hashtags.extend(tweet_hashtags)
        
        # Return top 10 most common hashtags
        from collections import Counter
        return [tag for tag, count in Counter(hashtags).most_common(10)]
    
    def _analyze_twitter_users(self, tweets: List[Dict]) -> Dict[str, int]:
        """Analyze Twitter user types"""
        # Placeholder for user analysis
        return {
            'verified_users': 0,
            'regular_users': len(tweets),
            'bot_suspected': 0
        }
    
    def _extract_reddit_subreddits(self, data: Dict) -> List[str]:
        """Extract subreddits from Reddit data"""
        subreddits = []
        for post in data.get('data', {}).get('children', []):
            subreddit = post.get('data', {}).get('subreddit', '')
            if subreddit:
                subreddits.append(subreddit)
        
        from collections import Counter
        return [sub for sub, count in Counter(subreddits).most_common(10)]
    
    def _analyze_reddit_sentiment(self, data: Dict) -> Dict[str, Any]:
        """Basic Reddit sentiment analysis"""
        posts = data.get('data', {}).get('children', [])
        if not posts:
            return {'overall': 0.0, 'positive': 0, 'negative': 0, 'neutral': 0}
        
        # Simple upvote ratio analysis
        sentiment_scores = []
        for post in posts:
            post_data = post.get('data', {})
            upvote_ratio = post_data.get('upvote_ratio', 0.5)
            
            if upvote_ratio > 0.7:
                sentiment_scores.append(1)
            elif upvote_ratio < 0.3:
                sentiment_scores.append(-1)
            else:
                sentiment_scores.append(0)
        
        avg_sentiment = sum(sentiment_scores) / len(sentiment_scores) if sentiment_scores else 0
        
        return {
            'overall': round(avg_sentiment, 2),
            'positive': sentiment_scores.count(1),
            'negative': sentiment_scores.count(-1),
            'neutral': sentiment_scores.count(0)
        }
    
    def _extract_reddit_top_posts(self, data: Dict) -> List[Dict]:
        """Extract top Reddit posts"""
        posts = []
        for post in data.get('data', {}).get('children', [])[:5]:  # Top 5
            post_data = post.get('data', {})
            posts.append({
                'title': post_data.get('title', ''),
                'subreddit': post_data.get('subreddit', ''),
                'score': post_data.get('score', 0),
                'num_comments': post_data.get('num_comments', 0),
                'url': post_data.get('url', '')
            })
        
        return posts
    
    async def health_check(self) -> Dict[str, Any]:
        """Check social media APIs health"""
        status = {
            'service': 'social_media_mcp',
            'status': 'healthy',
            'apis': {}
        }
        
        # Twitter health check
        if self.twitter_creds and self.twitter_creds.bearer_token:
            try:
                headers = {'Authorization': f'Bearer {self.twitter_creds.bearer_token}'}
                async with self.session.get('https://api.twitter.com/2/users/me', headers=headers) as response:
                    status['apis']['twitter'] = 'online' if response.status == 200 else 'error'
            except:
                status['apis']['twitter'] = 'offline'
        else:
            status['apis']['twitter'] = 'not_configured'
        
        # Reddit health check (public API)
        try:
            async with self.session.get('https://www.reddit.com/.json', 
                                      headers={'User-Agent': 'OSINT-Platform/1.0'}) as response:
                status['apis']['reddit'] = 'online' if response.status == 200 else 'error'
        except:
            status['apis']['reddit'] = 'offline'
        
        status['apis']['linkedin'] = 'limited_access'
        
        return status


class InfrastructureMCPClient(MCPClientBase):
    """Infrastructure Intelligence MCP Client"""
    
    def __init__(self, credentials: Dict[str, APICredentials]):
        self.shodan_creds = credentials.get('shodan')
        self.virustotal_creds = credentials.get('virustotal')
        super().__init__(credentials.get('shodan', APICredentials()))
    
    async def gather_intelligence(self, target: str, **kwargs) -> List[IntelligenceResult]:
        """Gather infrastructure intelligence"""
        results = []
        
        try:
            # WHOIS Intelligence
            whois_data = await self._gather_whois_intelligence(target)
            if whois_data:
                results.append(whois_data)
            
            # DNS Intelligence
            dns_data = await self._gather_dns_intelligence(target)
            if dns_data:
                results.append(dns_data)
            
            # Shodan Intelligence
            if self.shodan_creds and self.shodan_creds.api_key:
                shodan_data = await self._gather_shodan_intelligence(target)
                if shodan_data:
                    results.append(shodan_data)
            
            # SSL/TLS Certificate Intelligence
            cert_data = await self._gather_certificate_intelligence(target)
            if cert_data:
                results.append(cert_data)
        
        except Exception as e:
            logger.error(f"Infrastructure intelligence gathering failed: {str(e)}")
        
        return results
    
    async def _gather_whois_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather WHOIS intelligence"""
        try:
            import subprocess
            
            # Use system whois command (would use python-whois library in production)
            result = subprocess.run(['whois', target], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                whois_text = result.stdout
                
                # Parse basic WHOIS information
                processed_data = {
                    'domain': target,
                    'registrar': self._extract_whois_field(whois_text, 'Registrar'),
                    'creation_date': self._extract_whois_field(whois_text, 'Creation Date'),
                    'expiration_date': self._extract_whois_field(whois_text, 'Registry Expiry Date'),
                    'name_servers': self._extract_whois_nameservers(whois_text),
                    'status': self._extract_whois_status(whois_text)
                }
                
                return IntelligenceResult(
                    source='whois',
                    data_type='infrastructure',
                    target=target,
                    raw_data={'whois_output': whois_text},
                    processed_data=processed_data,
                    confidence_score=0.9,
                    timestamp=datetime.utcnow(),
                    metadata={'query_type': 'domain_whois'}
                )
                
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {str(e)}")
        
        return None
    
    async def _gather_dns_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather DNS intelligence"""
        try:
            import socket
            
            # Basic DNS resolution
            try:
                ip_address = socket.gethostbyname(target)
            except socket.gaierror:
                ip_address = None
            
            # Get additional DNS records (would use dnspython library in production)
            processed_data = {
                'domain': target,
                'a_record': ip_address,
                'dns_resolution': 'success' if ip_address else 'failed',
                'reverse_dns': self._reverse_dns_lookup(ip_address) if ip_address else None
            }
            
            return IntelligenceResult(
                source='dns',
                data_type='infrastructure',
                target=target,
                raw_data={'ip_address': ip_address},
                processed_data=processed_data,
                confidence_score=0.8,
                timestamp=datetime.utcnow(),
                metadata={'query_type': 'dns_resolution'}
            )
            
        except Exception as e:
            logger.error(f"DNS lookup failed: {str(e)}")
        
        return None
    
    async def _gather_shodan_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather Shodan intelligence"""
        await self._rate_limit_check()
        
        try:
            headers = {'Content-Type': 'application/json'}
            params = {'key': self.shodan_creds.api_key}
            
            # Shodan host search
            url = f'https://api.shodan.io/shodan/host/{target}'
            
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    processed_data = {
                        'ip': target,
                        'ports': data.get('ports', []),
                        'services': [service.get('product', 'Unknown') for service in data.get('data', [])],
                        'organization': data.get('org', 'Unknown'),
                        'country': data.get('country_name', 'Unknown'),
                        'last_update': data.get('last_update', ''),
                        'vulnerabilities': data.get('vulns', [])
                    }
                    
                    return IntelligenceResult(
                        source='shodan',
                        data_type='infrastructure',
                        target=target,
                        raw_data=data,
                        processed_data=processed_data,
                        confidence_score=0.9,
                        timestamp=datetime.utcnow(),
                        metadata={'api': 'shodan_host'}
                    )
                    
        except Exception as e:
            logger.error(f"Shodan lookup failed: {str(e)}")
        
        return None
    
    async def _gather_certificate_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather SSL certificate intelligence"""
        try:
            import ssl
            import socket
            
            # Get SSL certificate info
            context = ssl.create_default_context()
            
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    processed_data = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
                        'signature_algorithm': cert.get('signatureAlgorithm')
                    }
                    
                    return IntelligenceResult(
                        source='ssl_certificate',
                        data_type='infrastructure',
                        target=target,
                        raw_data=cert,
                        processed_data=processed_data,
                        confidence_score=0.8,
                        timestamp=datetime.utcnow(),
                        metadata={'port': 443, 'protocol': 'https'}
                    )
                    
        except Exception as e:
            logger.error(f"SSL certificate lookup failed: {str(e)}")
        
        return None
    
    def _extract_whois_field(self, whois_text: str, field: str) -> Optional[str]:
        """Extract field from WHOIS output"""
        for line in whois_text.split('\n'):
            if field.lower() in line.lower() and ':' in line:
                return line.split(':', 1)[1].strip()
        return None
    
    def _extract_whois_nameservers(self, whois_text: str) -> List[str]:
        """Extract name servers from WHOIS output"""
        nameservers = []
        for line in whois_text.split('\n'):
            if 'name server' in line.lower() and ':' in line:
                ns = line.split(':', 1)[1].strip()
                if ns:
                    nameservers.append(ns)
        return nameservers[:4]  # Limit to first 4
    
    def _extract_whois_status(self, whois_text: str) -> List[str]:
        """Extract domain status from WHOIS output"""
        statuses = []
        for line in whois_text.split('\n'):
            if 'status' in line.lower() and ':' in line:
                status = line.split(':', 1)[1].strip()
                if status:
                    statuses.append(status)
        return statuses
    
    def _reverse_dns_lookup(self, ip: str) -> Optional[str]:
        """Perform reverse DNS lookup"""
        try:
            import socket
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
    
    async def health_check(self) -> Dict[str, Any]:
        """Check infrastructure APIs health"""
        status = {
            'service': 'infrastructure_mcp',
            'status': 'healthy',
            'tools': {}
        }
        
        # Test basic DNS resolution
        try:
            import socket
            socket.gethostbyname('google.com')
            status['tools']['dns'] = 'online'
        except:
            status['tools']['dns'] = 'offline'
        
        # Test WHOIS availability
        try:
            import subprocess
            result = subprocess.run(['which', 'whois'], capture_output=True)
            status['tools']['whois'] = 'available' if result.returncode == 0 else 'unavailable'
        except:
            status['tools']['whois'] = 'unavailable'
        
        # Test Shodan API
        if self.shodan_creds and self.shodan_creds.api_key:
            try:
                params = {'key': self.shodan_creds.api_key}
                async with self.session.get('https://api.shodan.io/api-info', params=params) as response:
                    status['tools']['shodan'] = 'online' if response.status == 200 else 'error'
            except:
                status['tools']['shodan'] = 'offline'
        else:
            status['tools']['shodan'] = 'not_configured'
        
        return status


class ThreatIntelligenceMCPClient(MCPClientBase):
    """Threat Intelligence MCP Client"""
    
    def __init__(self, credentials: Dict[str, APICredentials]):
        self.virustotal_creds = credentials.get('virustotal')
        self.misp_creds = credentials.get('misp')
        self.otx_creds = credentials.get('otx')
        super().__init__(credentials.get('virustotal', APICredentials()))
    
    async def gather_intelligence(self, target: str, **kwargs) -> List[IntelligenceResult]:
        """Gather threat intelligence"""
        results = []
        
        try:
            # VirusTotal Intelligence
            if self.virustotal_creds and self.virustotal_creds.api_key:
                vt_data = await self._gather_virustotal_intelligence(target)
                if vt_data:
                    results.append(vt_data)
            
            # AlienVault OTX Intelligence
            if self.otx_creds and self.otx_creds.api_key:
                otx_data = await self._gather_otx_intelligence(target)
                if otx_data:
                    results.append(otx_data)
            
            # Basic threat reputation check
            reputation_data = await self._basic_reputation_check(target)
            if reputation_data:
                results.append(reputation_data)
        
        except Exception as e:
            logger.error(f"Threat intelligence gathering failed: {str(e)}")
        
        return results
    
    async def _gather_virustotal_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather VirusTotal intelligence"""
        await self._rate_limit_check()
        
        try:
            headers = {
                'x-apikey': self.virustotal_creds.api_key,
                'Content-Type': 'application/json'
            }
            
            # Determine if target is URL, domain, or IP
            if target.startswith('http'):
                # URL scan
                import base64
                url_id = base64.urlsafe_b64encode(target.encode()).decode().strip('=')
                endpoint = f'https://www.virustotal.com/api/v3/urls/{url_id}'
            else:
                # Domain/IP scan
                endpoint = f'https://www.virustotal.com/api/v3/domains/{target}'
            
            async with self.session.get(endpoint, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    attributes = data.get('data', {}).get('attributes', {})
                    
                    processed_data = {
                        'target': target,
                        'reputation': attributes.get('reputation', 0),
                        'harmless': attributes.get('last_analysis_stats', {}).get('harmless', 0),
                        'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                        'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                        'undetected': attributes.get('last_analysis_stats', {}).get('undetected', 0),
                        'categories': attributes.get('categories', {}),
                        'last_analysis_date': attributes.get('last_analysis_date'),
                        'whois_date': attributes.get('whois_date')
                    }
                    
                    # Calculate risk score
                    total_scans = sum([
                        processed_data['harmless'],
                        processed_data['malicious'], 
                        processed_data['suspicious'],
                        processed_data['undetected']
                    ])
                    
                    risk_score = 0
                    if total_scans > 0:
                        risk_score = (processed_data['malicious'] + processed_data['suspicious'] * 0.5) / total_scans * 100
                    
                    processed_data['risk_score'] = round(risk_score, 2)
                    
                    return IntelligenceResult(
                        source='virustotal',
                        data_type='threat_intelligence',
                        target=target,
                        raw_data=data,
                        processed_data=processed_data,
                        confidence_score=0.9,
                        timestamp=datetime.utcnow(),
                        metadata={'api_version': 'v3', 'scan_engines': total_scans}
                    )
                    
        except Exception as e:
            logger.error(f"VirusTotal lookup failed: {str(e)}")
        
        return None
    
    async def _gather_otx_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather AlienVault OTX intelligence"""
        await self._rate_limit_check()
        
        try:
            headers = {
                'X-OTX-API-KEY': self.otx_creds.api_key,
                'Content-Type': 'application/json'
            }
            
            # OTX domain indicators
            endpoint = f'https://otx.alienvault.com/api/v1/indicators/domain/{target}/general'
            
            async with self.session.get(endpoint, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    processed_data = {
                        'target': target,
                        'pulse_info': data.get('pulse_info', {}),
                        'alexa': data.get('alexa', ''),
                        'whois': data.get('whois', ''),
                        'base_indicator': data.get('base_indicator', {}),
                        'reputation': data.get('reputation', 0)
                    }
                    
                    return IntelligenceResult(
                        source='alienvault_otx',
                        data_type='threat_intelligence',
                        target=target,
                        raw_data=data,
                        processed_data=processed_data,
                        confidence_score=0.8,
                        timestamp=datetime.utcnow(),
                        metadata={'api': 'otx', 'indicator_type': 'domain'}
                    )
                    
        except Exception as e:
            logger.error(f"OTX lookup failed: {str(e)}")
        
        return None
    
    async def _basic_reputation_check(self, target: str) -> Optional[IntelligenceResult]:
        """Basic reputation check using multiple sources"""
        try:
            # Simple reputation aggregation
            reputation_score = 50  # Neutral baseline
            risk_indicators = []
            
            # Check against basic blacklists (placeholder)
            # In production, would check against multiple threat feeds
            
            processed_data = {
                'target': target,
                'reputation_score': reputation_score,
                'risk_indicators': risk_indicators,
                'data_sources': ['basic_checks'],
                'threat_level': 'low' if reputation_score > 70 else 'medium' if reputation_score > 30 else 'high'
            }
            
            return IntelligenceResult(
                source='basic_reputation',
                data_type='threat_intelligence',
                target=target,
                raw_data={'reputation_score': reputation_score},
                processed_data=processed_data,
                confidence_score=0.5,
                timestamp=datetime.utcnow(),
                metadata={'method': 'basic_aggregation'}
            )
            
        except Exception as e:
            logger.error(f"Basic reputation check failed: {str(e)}")
        
        return None
    
    async def health_check(self) -> Dict[str, Any]:
        """Check threat intelligence APIs health"""
        status = {
            'service': 'threat_intelligence_mcp',
            'status': 'healthy',
            'apis': {}
        }
        
        # VirusTotal health check
        if self.virustotal_creds and self.virustotal_creds.api_key:
            try:
                headers = {'x-apikey': self.virustotal_creds.api_key}
                async with self.session.get('https://www.virustotal.com/api/v3/domains/google.com', 
                                          headers=headers) as response:
                    status['apis']['virustotal'] = 'online' if response.status == 200 else 'error'
            except:
                status['apis']['virustotal'] = 'offline'
        else:
            status['apis']['virustotal'] = 'not_configured'
        
        # OTX health check
        if self.otx_creds and self.otx_creds.api_key:
            try:
                headers = {'X-OTX-API-KEY': self.otx_creds.api_key}
                async with self.session.get('https://otx.alienvault.com/api/v1/user/me', 
                                          headers=headers) as response:
                    status['apis']['otx'] = 'online' if response.status == 200 else 'error'
            except:
                status['apis']['otx'] = 'offline'
        else:
            status['apis']['otx'] = 'not_configured'
        
        status['apis']['basic_reputation'] = 'online'
        
        return status


class MCPClientManager:
    """Manager for all MCP intelligence gathering clients"""
    
    def __init__(self):
        self.clients: Dict[str, MCPClientBase] = {}
        self._setup_credentials()
    
    def _setup_credentials(self):
        """Setup API credentials from environment variables"""
        
        # Social Media Credentials
        social_creds = {
            'twitter': APICredentials(
                bearer_token=os.getenv('TWITTER_BEARER_TOKEN'),
                rate_limit_per_minute=300  # Twitter API v2 limit
            ),
            'reddit': APICredentials(
                api_key=os.getenv('REDDIT_CLIENT_ID'),
                api_secret=os.getenv('REDDIT_CLIENT_SECRET'),
                rate_limit_per_minute=60
            ),
            'linkedin': APICredentials(
                api_key=os.getenv('LINKEDIN_API_KEY'),
                rate_limit_per_minute=30
            )
        }
        
        # Infrastructure Credentials
        infra_creds = {
            'shodan': APICredentials(
                api_key=os.getenv('SHODAN_API_KEY'),
                rate_limit_per_minute=100
            ),
            'virustotal': APICredentials(
                api_key=os.getenv('VIRUSTOTAL_API_KEY'),
                rate_limit_per_minute=4  # Free tier limit
            )
        }
        
        # Threat Intelligence Credentials
        threat_creds = {
            'virustotal': APICredentials(
                api_key=os.getenv('VIRUSTOTAL_API_KEY'),
                rate_limit_per_minute=4
            ),
            'misp': APICredentials(
                api_key=os.getenv('MISP_API_KEY'),
                base_url=os.getenv('MISP_URL'),
                rate_limit_per_minute=60
            ),
            'otx': APICredentials(
                api_key=os.getenv('OTX_API_KEY'),
                rate_limit_per_minute=60
            )
        }
        
        # Initialize clients
        self.clients['social_media'] = SocialMediaMCPClient(social_creds)
        self.clients['infrastructure'] = InfrastructureMCPClient(infra_creds)
        self.clients['threat_intelligence'] = ThreatIntelligenceMCPClient(threat_creds)
    
    async def gather_all_intelligence(self, target: str, investigation_type: str = 'comprehensive') -> Dict[str, List[IntelligenceResult]]:
        """Gather intelligence from all applicable sources"""
        results = {}
        
        try:
            tasks = []
            
            # Determine which clients to use based on investigation type
            if investigation_type in ['comprehensive', 'social_media']:
                async with self.clients['social_media'] as client:
                    tasks.append(('social_media', client.gather_intelligence(target)))
            
            if investigation_type in ['comprehensive', 'infrastructure']:
                async with self.clients['infrastructure'] as client:
                    tasks.append(('infrastructure', client.gather_intelligence(target)))
            
            if investigation_type in ['comprehensive', 'threat_assessment']:
                async with self.clients['threat_intelligence'] as client:
                    tasks.append(('threat_intelligence', client.gather_intelligence(target)))
            
            # Execute all intelligence gathering tasks concurrently
            for client_name, task in tasks:
                try:
                    intelligence_results = await task
                    results[client_name] = intelligence_results
                except Exception as e:
                    logger.error(f"Intelligence gathering failed for {client_name}: {str(e)}")
                    results[client_name] = []
        
        except Exception as e:
            logger.error(f"Intelligence gathering manager failed: {str(e)}")
        
        return results
    
    async def health_check_all(self) -> Dict[str, Dict[str, Any]]:
        """Perform health check on all MCP clients"""
        health_results = {}
        
        for client_name, client in self.clients.items():
            try:
                async with client as active_client:
                    health_results[client_name] = await active_client.health_check()
            except Exception as e:
                health_results[client_name] = {
                    'service': client_name,
                    'status': 'error',
                    'error': str(e)
                }
        
        return health_results