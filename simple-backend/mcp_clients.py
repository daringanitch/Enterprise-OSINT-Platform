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

try:
    from observability import trace_mcp_operation, add_trace_attributes, record_error
except ImportError:
    # Fallback if observability module not available
    def trace_mcp_operation(server, operation):
        def decorator(func):
            return func
        return decorator
    def add_trace_attributes(**kwargs):
        pass
    def record_error(error, error_type="unknown"):
        pass

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
    
    @trace_mcp_operation("social_media", "gather_intelligence")
    async def gather_intelligence(self, target: str, **kwargs) -> List[IntelligenceResult]:
        """Gather social media intelligence"""
        
        # Add trace attributes
        add_trace_attributes(
            mcp_client="social_media",
            target=target,
            platforms_enabled=["twitter" if self.twitter_creds else None, 
                              "reddit" if self.reddit_creds else None,
                              "linkedin" if self.linkedin_creds else None]
        )
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
            record_error(e, "social_media_intelligence_error")
            add_trace_attributes(social_media_error=str(e))
        
        return results
    
    @trace_mcp_operation("social_media", "twitter_api")
    async def _gather_twitter_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather Twitter/X intelligence via enhanced social media MCP server"""
        
        try:
            # Use enhanced social media MCP server
            mcp_url = 'http://mcp-social-enhanced:8010/execute'
            payload = {
                'tool': 'twitter_profile',
                'parameters': {'username': target}
            }
            
            async with self.session.post(mcp_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('success', False):
                        result_data = data.get('result', {})
                        
                        return IntelligenceResult(
                            source='twitter_enhanced',
                            data_type='social_media_profile',
                            target=target,
                            raw_data=result_data,
                            processed_data={
                                'username': result_data.get('username'),
                                'name': result_data.get('name'),
                                'followers': result_data.get('metrics', {}).get('followers_count', 0),
                                'verified': result_data.get('verified', False),
                                'location': result_data.get('location'),
                                'created_at': result_data.get('created_at'),
                                'description': result_data.get('description')
                            },
                            confidence_score=0.9 if 'error' not in result_data else 0.3,
                            timestamp=datetime.utcnow(),
                            metadata={
                                'api_source': result_data.get('data_source', 'Enhanced MCP'),
                                'intelligence_type': 'REAL',
                                'processing_time': data.get('metadata', {}).get('processing_time_ms', 0)
                            }
                        )
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
    
    @trace_mcp_operation("social_media", "reddit_api")
    async def _gather_reddit_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather Reddit intelligence via enhanced social media MCP server"""
        
        try:
            # Use enhanced social media MCP server for Reddit profile
            mcp_url = 'http://mcp-social-enhanced:8010/execute'
            payload = {
                'tool': 'reddit_profile',
                'parameters': {'username': target}
            }
            
            async with self.session.post(mcp_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('success', False):
                        result_data = data.get('result', {})
                        
                        processed_data = {
                            'platform': 'reddit',
                            'username': result_data.get('username'),
                            'link_karma': result_data.get('link_karma', 0),
                            'comment_karma': result_data.get('comment_karma', 0),
                            'total_karma': result_data.get('total_karma', 0),
                            'account_age_days': result_data.get('account_age_days', 0),
                            'verified': result_data.get('verified', False),
                            'is_mod': result_data.get('is_mod', False),
                            'created_date': result_data.get('created_date')
                        }
                        
                        return IntelligenceResult(
                            source='reddit_enhanced',
                            data_type='social_media_profile',
                            target=target,
                            raw_data=result_data,
                            processed_data=processed_data,
                            confidence_score=0.9 if 'error' not in result_data else 0.3,
                            timestamp=datetime.utcnow(),
                            metadata={
                                'api_source': result_data.get('data_source', 'Enhanced MCP'),
                                'intelligence_type': 'REAL',
                                'processing_time': data.get('metadata', {}).get('processing_time_ms', 0)
                            }
                        )
                    
        except Exception as e:
            logger.error(f"Reddit intelligence gathering failed: {str(e)}")
        
        return None
    
    @trace_mcp_operation("social_media", "linkedin_api")
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
    
    @trace_mcp_operation("infrastructure", "gather_intelligence")
    async def gather_intelligence(self, target: str, **kwargs) -> List[IntelligenceResult]:
        """Gather infrastructure intelligence"""
        
        # Add trace attributes
        add_trace_attributes(
            mcp_client="infrastructure",
            target=target,
            shodan_enabled=bool(self.shodan_creds and self.shodan_creds.api_key),
            virustotal_enabled=bool(self.virustotal_creds and self.virustotal_creds.api_key)
        )
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
    
    @trace_mcp_operation("infrastructure", "whois_lookup")
    async def _gather_whois_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather WHOIS intelligence via enhanced infrastructure MCP server"""
        try:
            # Call enhanced infrastructure MCP server for real WHOIS data
            mcp_url = 'http://mcp-infrastructure-enhanced:8021/execute'
            payload = {
                'tool': 'whois_lookup',
                'parameters': {'domain': target}
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(mcp_url, json=payload, timeout=30) as response:
                    if response.status == 200:
                        mcp_result = await response.json()
                        
                        if mcp_result.get('success') and 'result' in mcp_result:
                            whois_data = mcp_result['result']
                            
                            # Transform MCP result to our format
                            processed_data = {
                                'domain': whois_data.get('domain', target),
                                'registrar': whois_data.get('registrar', 'Unknown'),
                                'creation_date': whois_data.get('created', 'Unknown'),
                                'expiration_date': whois_data.get('expires', 'Unknown'),
                                'name_servers': whois_data.get('nameservers', []),
                                'status': whois_data.get('status', 'Unknown'),
                                'organization': whois_data.get('org', 'Unknown'),
                                'country': whois_data.get('country', 'Unknown'),
                                'data_source': whois_data.get('data_source', 'Live WHOIS Query')
                            }
                            
                            return IntelligenceResult(
                                source='whois_enhanced',
                                data_type='infrastructure',
                                target=target,
                                raw_data={'whois_response': mcp_result, 'raw_whois': whois_data.get('raw_data', '')},
                                processed_data=processed_data,
                                confidence_score=0.95,  # Higher confidence for real data
                                timestamp=datetime.utcnow(),
                                metadata={
                                    'query_type': 'domain_whois', 
                                    'intelligence_type': 'REAL',
                                    'processing_time_ms': mcp_result.get('metadata', {}).get('processing_time_ms', 0)
                                }
                            )
                
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {str(e)}")
        
        return None
    
    @trace_mcp_operation("infrastructure", "dns_lookup")
    async def _gather_dns_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather DNS intelligence via enhanced infrastructure MCP server"""
        try:
            # Call enhanced infrastructure MCP server for real DNS data
            mcp_url = 'http://mcp-infrastructure-enhanced:8021/execute'
            payload = {
                'tool': 'dns_records',
                'parameters': {'domain': target}
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(mcp_url, json=payload, timeout=30) as response:
                    if response.status == 200:
                        mcp_result = await response.json()
                        
                        if mcp_result.get('success') and 'result' in mcp_result:
                            dns_data = mcp_result['result']
                            
                            # Transform MCP result to our format
                            processed_data = {
                                'domain': dns_data.get('domain', target),
                                'a_records': dns_data.get('a_records', []),
                                'mx_records': dns_data.get('mx_records', []),
                                'ns_records': dns_data.get('ns_records', []),
                                'txt_records': dns_data.get('txt_records', []),
                                'cname_records': dns_data.get('cname_records', []),
                                'dns_resolution': 'success' if dns_data.get('a_records') else 'failed',
                                'data_source': dns_data.get('data_source', 'Live DNS Query')
                            }
                            
                            return IntelligenceResult(
                                source='dns_enhanced',
                                data_type='infrastructure',
                                target=target,
                                raw_data={'dns_response': mcp_result},
                                processed_data=processed_data,
                                confidence_score=0.95,  # Higher confidence for real data
                                timestamp=datetime.utcnow(),
                                metadata={
                                    'query_type': 'dns_resolution',
                                    'intelligence_type': 'REAL',
                                    'processing_time_ms': mcp_result.get('metadata', {}).get('processing_time_ms', 0)
                                }
                            )
            
        except Exception as e:
            logger.error(f"DNS lookup failed: {str(e)}")
        
        return None
    
    @trace_mcp_operation("infrastructure", "shodan_lookup")
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
    
    @trace_mcp_operation("infrastructure", "certificate_analysis")
    async def _gather_certificate_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather SSL certificate intelligence via enhanced infrastructure MCP server"""
        try:
            # Call enhanced infrastructure MCP server for real SSL certificate data
            mcp_url = 'http://mcp-infrastructure-enhanced:8021/execute'
            payload = {
                'tool': 'ssl_certificate_info',
                'parameters': {'domain': target, 'port': 443}
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(mcp_url, json=payload, timeout=30) as response:
                    if response.status == 200:
                        mcp_result = await response.json()
                        
                        if mcp_result.get('success') and 'result' in mcp_result:
                            ssl_data = mcp_result['result']
                            
                            # Transform MCP result to our format
                            processed_data = {
                                'domain': ssl_data.get('domain', target),
                                'subject': ssl_data.get('subject', {}),
                                'issuer': ssl_data.get('issuer', {}),
                                'version': ssl_data.get('version', 'Unknown'),
                                'serial_number': ssl_data.get('serial_number', 'Unknown'),
                                'not_before': ssl_data.get('not_before', 'Unknown'),
                                'not_after': ssl_data.get('not_after', 'Unknown'),
                                'signature_algorithm': ssl_data.get('signature_algorithm', 'Unknown'),
                                'is_valid': ssl_data.get('is_valid', False),
                                'days_until_expiry': ssl_data.get('days_until_expiry', 0),
                                'data_source': ssl_data.get('data_source', 'Live SSL Query')
                            }
                            
                            return IntelligenceResult(
                                source='ssl_certificate_enhanced',
                                data_type='infrastructure',
                                target=target,
                                raw_data={'ssl_response': mcp_result},
                                processed_data=processed_data,
                                confidence_score=0.95,  # Higher confidence for real data
                                timestamp=datetime.utcnow(),
                                metadata={
                                    'query_type': 'ssl_certificate',
                                    'intelligence_type': 'REAL',
                                    'processing_time_ms': mcp_result.get('metadata', {}).get('processing_time_ms', 0)
                                }
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
    
    @trace_mcp_operation("threat_intelligence", "gather_intelligence")
    async def gather_intelligence(self, target: str, **kwargs) -> List[IntelligenceResult]:
        """Gather threat intelligence"""
        
        # Add trace attributes
        add_trace_attributes(
            mcp_client="threat_intelligence",
            target=target,
            virustotal_enabled=bool(self.virustotal_creds and self.virustotal_creds.api_key),
            misp_enabled=bool(self.misp_creds),
            otx_enabled=bool(self.otx_creds)
        )
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
    
    @trace_mcp_operation("threat_intelligence", "virustotal_lookup")
    async def _gather_virustotal_intelligence(self, target: str) -> Optional[IntelligenceResult]:
        """Gather VirusTotal intelligence via enhanced threat intel MCP server"""
        
        try:
            # Use enhanced threat intel MCP server
            mcp_url = 'http://mcp-threat-enhanced:8020/execute'
            payload = {
                'tool': 'virustotal_domain',
                'parameters': {'domain': target}
            }
            
            async with self.session.post(mcp_url, json=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    
                    if data.get('success', False):
                        result_data = data.get('result', {})
                        
                        return IntelligenceResult(
                            source='virustotal_enhanced',
                            data_type='threat_intelligence',
                            target=target,
                            raw_data=result_data,
                            processed_data={
                                'domain': result_data.get('domain'),
                                'threat_score': result_data.get('threat_score', 0),
                                'reputation': result_data.get('reputation', 0),
                                'malicious_detections': result_data.get('analysis_stats', {}).get('malicious', 0),
                                'suspicious_detections': result_data.get('analysis_stats', {}).get('suspicious', 0),
                                'clean_detections': result_data.get('analysis_stats', {}).get('harmless', 0),
                                'categories': result_data.get('categories', {}),
                                'registrar': result_data.get('registrar'),
                                'last_analysis': result_data.get('last_analysis_date')
                            },
                            confidence_score=0.9 if 'error' not in result_data else 0.3,
                            timestamp=datetime.utcnow(),
                            metadata={
                                'api_source': result_data.get('data_source', 'Enhanced MCP'),
                                'intelligence_type': 'REAL',
                                'processing_time': data.get('metadata', {}).get('processing_time_ms', 0)
                            }
                        )
        
        except Exception as e:
            logger.error(f"VirusTotal intelligence gathering failed: {str(e)}")
        
        return None
    
    @trace_mcp_operation("threat_intelligence", "otx_lookup")
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


class EnhancedMCPClient:
    """Client for enhanced MCP servers via HTTP"""
    
    def __init__(self, server_name: str, config: Dict[str, Any]):
        self.server_name = server_name
        self.host = config['host']
        self.port = config['port']
        self.timeout = config.get('timeout', 30)
        self.base_url = f"http://{self.host}:{self.port}"
        
    async def call_method(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Call an MCP method via HTTP"""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout)) as session:
                payload = {
                    'method': method,
                    'params': params
                }
                
                async with session.post(f"{self.base_url}/mcp", json=payload) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {
                            'success': False,
                            'error': f'HTTP {response.status}: {await response.text()}'
                        }
                        
        except Exception as e:
            logger.error(f"Error calling {self.server_name} method {method}: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_capabilities(self) -> Dict[str, Any]:
        """Get server capabilities"""
        try:
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=10)) as session:
                async with session.get(f"{self.base_url}/capabilities") as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {'error': f'HTTP {response.status}'}
        except Exception as e:
            return {'error': str(e)}


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
        # Enhanced MCP Server configurations
        enhanced_servers = {
            'infrastructure_advanced': {
                'host': 'mcp-infrastructure-advanced.osint-platform.svc.cluster.local',
                'port': 5015,
                'timeout': 30
            },
            'threat_aggregator': {
                'host': 'mcp-threat-aggregator.osint-platform.svc.cluster.local', 
                'port': 5016,
                'timeout': 60
            },
            'ai_analyzer': {
                'host': 'mcp-ai-analyzer.osint-platform.svc.cluster.local',
                'port': 5017,
                'timeout': 120
            }
        }
        
        # Initialize legacy clients
        self.clients['social_media'] = SocialMediaMCPClient(social_creds)
        self.clients['infrastructure'] = InfrastructureMCPClient(infra_creds)
        self.clients['threat_intelligence'] = ThreatIntelligenceMCPClient(threat_creds)
        
        # Initialize enhanced MCP clients
        self.clients['infrastructure_advanced'] = EnhancedMCPClient('infrastructure_advanced', enhanced_servers['infrastructure_advanced'])
        self.clients['threat_aggregator'] = EnhancedMCPClient('threat_aggregator', enhanced_servers['threat_aggregator'])
        self.clients['ai_analyzer'] = EnhancedMCPClient('ai_analyzer', enhanced_servers['ai_analyzer'])
    
    async def gather_all_intelligence(self, target: str, investigation_type: str = 'comprehensive') -> Dict[str, List[IntelligenceResult]]:
        """Gather intelligence from enhanced MCP servers via HTTP"""
        results = {}
        
        try:
            # Use direct HTTP calls to enhanced MCP servers
            import aiohttp
            
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session:
                
                # Infrastructure Intelligence
                if investigation_type in ['comprehensive', 'infrastructure']:
                    try:
                        results['infrastructure'] = await self._call_enhanced_mcp(
                            session, 'http://mcp-infrastructure-enhanced:8021/execute',
                            [
                                {'tool': 'whois_lookup', 'parameters': {'domain': target}},
                                {'tool': 'dns_records', 'parameters': {'domain': target, 'record_type': 'A'}},
                                {'tool': 'ssl_certificate_info', 'parameters': {'domain': target}}
                            ],
                            'infrastructure'
                        )
                    except Exception as e:
                        logger.error(f"Infrastructure intelligence failed: {str(e)}")
                        results['infrastructure'] = []
                
                # Social Media Intelligence
                if investigation_type in ['comprehensive', 'social_media']:
                    try:
                        results['social_media'] = await self._call_enhanced_mcp(
                            session, 'http://mcp-social-enhanced:8010/execute',
                            [
                                {'tool': 'reddit_profile', 'parameters': {'username': target}},
                                {'tool': 'social_media_search', 'parameters': {'query': target}}
                            ],
                            'social_media'
                        )
                    except Exception as e:
                        logger.error(f"Social media intelligence failed: {str(e)}")
                        results['social_media'] = []
                
                # Threat Intelligence
                if investigation_type in ['comprehensive', 'threat_assessment']:
                    try:
                        results['threat_intelligence'] = await self._call_enhanced_mcp(
                            session, 'http://mcp-threat-enhanced:8020/execute',
                            [
                                {'tool': 'virustotal_domain', 'parameters': {'domain': target}}
                            ],
                            'threat_intelligence'
                        )
                    except Exception as e:
                        logger.error(f"Threat intelligence failed: {str(e)}")
                        results['threat_intelligence'] = []
        
        except Exception as e:
            logger.error(f"Intelligence gathering manager failed: {str(e)}")
        
        return results
    
    async def _call_enhanced_mcp(self, session, mcp_url: str, tools: List[Dict], source_type: str) -> List[IntelligenceResult]:
        """Call enhanced MCP server and convert to IntelligenceResult"""
        results = []
        
        for tool_call in tools:
            try:
                async with session.post(mcp_url, json=tool_call, headers={'Content-Type': 'application/json'}) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if data.get('success', False):
                            result_data = data.get('result', {})
                            
                            # Convert to IntelligenceResult format
                            intelligence_result = IntelligenceResult(
                                source=tool_call['tool'] + '_enhanced',
                                data_type=source_type,
                                target=tool_call['parameters'].get('domain', tool_call['parameters'].get('username', tool_call['parameters'].get('query', 'unknown'))),
                                raw_data=result_data,
                                processed_data=result_data,
                                confidence_score=0.9 if 'error' not in result_data else 0.3,
                                timestamp=datetime.utcnow(),
                                metadata={
                                    'api_source': result_data.get('data_source', 'Enhanced MCP'),
                                    'intelligence_type': 'REAL',
                                    'mcp_server': mcp_url,
                                    'processing_time': data.get('metadata', {}).get('processing_time_ms', 0)
                                }
                            )
                            results.append(intelligence_result)
                        else:
                            logger.warning(f"MCP call failed: {data}")
                    else:
                        logger.error(f"MCP server error: {response.status}")
                        
            except Exception as e:
                logger.error(f"MCP call exception for {tool_call}: {str(e)}")
        
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
    
    async def gather_enhanced_intelligence(self, target: str, investigation_type: str = 'comprehensive') -> Dict[str, Any]:
        """Gather intelligence using enhanced MCP servers"""
        enhanced_results = {
            'target': target,
            'investigation_type': investigation_type,
            'timestamp': datetime.utcnow().isoformat(),
            'infrastructure_advanced': {},
            'threat_aggregator': {},
            'ai_analysis': {}
        }
        
        try:
            # Infrastructure Advanced Analysis
            if 'infrastructure_advanced' in self.clients:
                infra_client = self.clients['infrastructure_advanced']
                
                # Comprehensive reconnaissance
                recon_result = await infra_client.call_method(
                    'infrastructure/comprehensive_recon',
                    {'target': target}
                )
                enhanced_results['infrastructure_advanced']['reconnaissance'] = recon_result
                
                # Certificate transparency
                ct_result = await infra_client.call_method(
                    'infrastructure/certificate_transparency',
                    {'domain': target}
                )
                enhanced_results['infrastructure_advanced']['certificate_transparency'] = ct_result
                
            # Threat Intelligence Aggregation
            if 'threat_aggregator' in self.clients:
                threat_client = self.clients['threat_aggregator']
                
                # Check if target is IP or domain
                if self._is_ip(target):
                    threat_result = await threat_client.call_method(
                        'threat/check_ip',
                        {'ip': target}
                    )
                else:
                    threat_result = await threat_client.call_method(
                        'threat/check_domain',
                        {'domain': target}
                    )
                enhanced_results['threat_aggregator']['reputation'] = threat_result
                
            # AI Analysis (if we have enough data)
            if 'ai_analyzer' in self.clients and enhanced_results['infrastructure_advanced']:
                ai_client = self.clients['ai_analyzer']
                
                # Generate executive summary
                summary_result = await ai_client.call_method(
                    'ai/generate_executive_summary',
                    {'investigation_data': enhanced_results}
                )
                enhanced_results['ai_analysis']['executive_summary'] = summary_result
                
                # Predict attack vectors
                if enhanced_results['infrastructure_advanced'].get('reconnaissance'):
                    attack_vectors = await ai_client.call_method(
                        'ai/predict_attack_vectors',
                        {'target_profile': enhanced_results['infrastructure_advanced']['reconnaissance']}
                    )
                    enhanced_results['ai_analysis']['attack_vectors'] = attack_vectors
                    
        except Exception as e:
            logger.error(f"Enhanced intelligence gathering failed: {e}")
            enhanced_results['error'] = str(e)
        
        return enhanced_results
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address"""
        import ipaddress
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    async def get_enhanced_capabilities(self) -> Dict[str, Any]:
        """Get capabilities of all enhanced MCP servers"""
        capabilities = {}
        
        for name, client in self.clients.items():
            if isinstance(client, EnhancedMCPClient):
                capabilities[name] = await client.get_capabilities()
                
        return capabilities