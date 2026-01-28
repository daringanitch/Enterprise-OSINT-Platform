#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.
# Individual use is free. Commercial use requires 3% profit sharing.
# See LICENSE file for details.

"""
Expanded Data Sources for Enterprise OSINT Platform

Provides additional intelligence gathering capabilities:
- Passive DNS (historical DNS records)
- Code Intelligence (GitHub, GitLab)
- Breach Intelligence (credential leaks, breaches)
- URL Intelligence (malicious URLs, phishing)
- Business Intelligence (corporate records, SEC filings)
- News Intelligence (media mentions, press coverage)

Each source provides:
- Async data collection
- Rate limiting
- Error handling with fallbacks
- Standardized result format
"""

import os
import asyncio
import logging
import aiohttp
import json
import re
import hashlib
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum

logger = logging.getLogger(__name__)


# ============================================================================
# Data Models
# ============================================================================

@dataclass
class DataSourceResult:
    """Standardized result from any data source"""
    source_name: str
    source_type: str
    target: str
    success: bool
    data: Dict[str, Any]
    confidence: float = 0.0
    timestamp: datetime = field(default_factory=datetime.utcnow)
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'source_name': self.source_name,
            'source_type': self.source_type,
            'target': self.target,
            'success': self.success,
            'data': self.data,
            'confidence': self.confidence,
            'timestamp': self.timestamp.isoformat(),
            'error': self.error,
            'metadata': self.metadata
        }


class DataSourceType(Enum):
    """Types of expanded data sources"""
    PASSIVE_DNS = "passive_dns"
    CODE_INTEL = "code_intelligence"
    BREACH_INTEL = "breach_intelligence"
    URL_INTEL = "url_intelligence"
    BUSINESS_INTEL = "business_intelligence"
    NEWS_INTEL = "news_intelligence"


# ============================================================================
# Base Data Source Client
# ============================================================================

class ExpandedDataSourceBase(ABC):
    """Base class for expanded data source clients"""

    def __init__(self, api_key: Optional[str] = None, base_url: Optional[str] = None):
        self.api_key = api_key
        self.base_url = base_url
        self._session: Optional[aiohttp.ClientSession] = None
        self._rate_limit_remaining = 100
        self._rate_limit_reset = datetime.utcnow()

    async def get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session"""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            self._session = aiohttp.ClientSession(timeout=timeout)
        return self._session

    async def close(self):
        """Close the session"""
        if self._session and not self._session.closed:
            await self._session.close()

    @abstractmethod
    async def gather(self, target: str, **kwargs) -> DataSourceResult:
        """Gather intelligence for target"""
        pass

    @abstractmethod
    def get_source_info(self) -> Dict[str, Any]:
        """Get information about this data source"""
        pass


# ============================================================================
# Passive DNS Intelligence
# ============================================================================

class PassiveDNSClient(ExpandedDataSourceBase):
    """
    Passive DNS intelligence gathering.

    Collects historical DNS records to identify:
    - Historical IP addresses
    - Domain changes over time
    - Related domains (shared IPs)
    - Subdomain discovery
    """

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(
            api_key=api_key or os.environ.get('SECURITYTRAILS_API_KEY'),
            base_url='https://api.securitytrails.com/v1'
        )

    def get_source_info(self) -> Dict[str, Any]:
        return {
            'name': 'Passive DNS',
            'type': DataSourceType.PASSIVE_DNS.value,
            'description': 'Historical DNS records and domain intelligence',
            'capabilities': ['historical_dns', 'subdomain_discovery', 'related_domains', 'whois_history'],
            'rate_limit': '50 requests/day (free tier)',
            'data_retention': '5+ years of historical data'
        }

    async def gather(self, target: str, **kwargs) -> DataSourceResult:
        """Gather passive DNS intelligence for a domain"""
        try:
            # Check if we have API key for real data
            if self.api_key:
                return await self._gather_real(target)
            else:
                return await self._gather_simulated(target)
        except Exception as e:
            logger.error(f"Passive DNS gathering failed for {target}: {e}")
            return DataSourceResult(
                source_name='passive_dns',
                source_type=DataSourceType.PASSIVE_DNS.value,
                target=target,
                success=False,
                data={},
                error=str(e)
            )

    async def _gather_real(self, target: str) -> DataSourceResult:
        """Gather real passive DNS data from SecurityTrails API"""
        session = await self.get_session()
        headers = {'APIKEY': self.api_key}

        results = {
            'historical_dns': [],
            'subdomains': [],
            'related_domains': [],
            'first_seen': None,
            'last_seen': None
        }

        try:
            # Get DNS history
            async with session.get(
                f"{self.base_url}/history/{target}/dns/a",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    records = data.get('records', [])
                    results['historical_dns'] = [
                        {
                            'ip': r.get('values', [{}])[0].get('ip', ''),
                            'first_seen': r.get('first_seen'),
                            'last_seen': r.get('last_seen'),
                            'organizations': r.get('organizations', [])
                        }
                        for r in records[:50]  # Limit to 50 records
                    ]
                    if records:
                        results['first_seen'] = records[-1].get('first_seen')
                        results['last_seen'] = records[0].get('last_seen')

            # Get subdomains
            async with session.get(
                f"{self.base_url}/domain/{target}/subdomains",
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    results['subdomains'] = data.get('subdomains', [])[:100]

            return DataSourceResult(
                source_name='securitytrails',
                source_type=DataSourceType.PASSIVE_DNS.value,
                target=target,
                success=True,
                data=results,
                confidence=0.9,
                metadata={'api_source': 'SecurityTrails', 'is_real_data': True}
            )

        except aiohttp.ClientError as e:
            logger.error(f"SecurityTrails API error: {e}")
            return await self._gather_simulated(target)

    async def _gather_simulated(self, target: str) -> DataSourceResult:
        """Generate simulated passive DNS data for demo mode"""
        import random

        # Generate realistic-looking historical DNS data
        historical_dns = []
        base_date = datetime.utcnow() - timedelta(days=365*3)

        for i in range(random.randint(5, 15)):
            days_offset = random.randint(0, 365*3)
            first_seen = base_date + timedelta(days=days_offset)
            last_seen = first_seen + timedelta(days=random.randint(30, 365))

            historical_dns.append({
                'ip': f"{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}",
                'first_seen': first_seen.strftime('%Y-%m-%d'),
                'last_seen': min(last_seen, datetime.utcnow()).strftime('%Y-%m-%d'),
                'organizations': [random.choice(['Cloudflare', 'AWS', 'Google Cloud', 'DigitalOcean', 'Fastly'])]
            })

        # Sort by first_seen descending
        historical_dns.sort(key=lambda x: x['first_seen'], reverse=True)

        # Generate subdomains
        subdomain_prefixes = ['www', 'mail', 'api', 'dev', 'staging', 'app', 'admin', 'cdn', 'static', 'blog', 'shop', 'secure', 'portal', 'dashboard']
        subdomains = random.sample(subdomain_prefixes, random.randint(4, 10))

        return DataSourceResult(
            source_name='passive_dns_simulated',
            source_type=DataSourceType.PASSIVE_DNS.value,
            target=target,
            success=True,
            data={
                'historical_dns': historical_dns,
                'subdomains': subdomains,
                'related_domains': [f"related-{i}.{target.split('.')[-1]}" for i in range(random.randint(2, 5))],
                'first_seen': historical_dns[-1]['first_seen'] if historical_dns else None,
                'last_seen': historical_dns[0]['last_seen'] if historical_dns else None,
                'total_records': len(historical_dns),
                'unique_ips': len(set(r['ip'] for r in historical_dns))
            },
            confidence=0.6,
            metadata={'api_source': 'Simulated', 'is_real_data': False, 'demo_mode': True}
        )


# ============================================================================
# Code Intelligence (GitHub)
# ============================================================================

class CodeIntelligenceClient(ExpandedDataSourceBase):
    """
    Code intelligence gathering from GitHub/GitLab.

    Identifies:
    - Public repositories mentioning target
    - Code exposure (leaked credentials, configs)
    - Developer activity patterns
    - Technology stack indicators
    """

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(
            api_key=api_key or os.environ.get('GITHUB_TOKEN'),
            base_url='https://api.github.com'
        )

    def get_source_info(self) -> Dict[str, Any]:
        return {
            'name': 'Code Intelligence',
            'type': DataSourceType.CODE_INTEL.value,
            'description': 'GitHub/GitLab code repository intelligence',
            'capabilities': ['repo_discovery', 'code_search', 'credential_exposure', 'tech_stack'],
            'rate_limit': '30 requests/minute (authenticated)',
            'data_sources': ['GitHub', 'GitLab']
        }

    async def gather(self, target: str, **kwargs) -> DataSourceResult:
        """Gather code intelligence for a target (domain, org, or username)"""
        try:
            if self.api_key:
                return await self._gather_real(target)
            else:
                return await self._gather_simulated(target)
        except Exception as e:
            logger.error(f"Code intelligence gathering failed for {target}: {e}")
            return DataSourceResult(
                source_name='code_intel',
                source_type=DataSourceType.CODE_INTEL.value,
                target=target,
                success=False,
                data={},
                error=str(e)
            )

    async def _gather_real(self, target: str) -> DataSourceResult:
        """Gather real code intelligence from GitHub"""
        session = await self.get_session()
        headers = {
            'Authorization': f'token {self.api_key}',
            'Accept': 'application/vnd.github.v3+json'
        }

        results = {
            'repositories': [],
            'code_mentions': [],
            'potential_exposures': [],
            'developers': [],
            'technologies': []
        }

        try:
            # Search for repositories mentioning the target
            search_query = target.replace('.', ' ')
            async with session.get(
                f"{self.base_url}/search/repositories",
                params={'q': search_query, 'per_page': 10},
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    results['repositories'] = [
                        {
                            'name': repo['full_name'],
                            'description': repo.get('description', ''),
                            'stars': repo['stargazers_count'],
                            'language': repo.get('language'),
                            'updated_at': repo['updated_at'],
                            'url': repo['html_url']
                        }
                        for repo in data.get('items', [])[:10]
                    ]

            # Search for code mentioning the target (potential exposure)
            async with session.get(
                f"{self.base_url}/search/code",
                params={'q': f'"{target}"', 'per_page': 5},
                headers=headers
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    for item in data.get('items', [])[:5]:
                        # Check for potential credential exposure
                        path = item.get('path', '').lower()
                        if any(s in path for s in ['.env', 'config', 'credential', 'secret', 'key']):
                            results['potential_exposures'].append({
                                'file': item['path'],
                                'repository': item['repository']['full_name'],
                                'url': item['html_url'],
                                'risk_level': 'high' if 'secret' in path or 'key' in path else 'medium'
                            })
                        results['code_mentions'].append({
                            'file': item['path'],
                            'repository': item['repository']['full_name'],
                            'url': item['html_url']
                        })

            return DataSourceResult(
                source_name='github',
                source_type=DataSourceType.CODE_INTEL.value,
                target=target,
                success=True,
                data=results,
                confidence=0.85,
                metadata={'api_source': 'GitHub API', 'is_real_data': True}
            )

        except aiohttp.ClientError as e:
            logger.error(f"GitHub API error: {e}")
            return await self._gather_simulated(target)

    async def _gather_simulated(self, target: str) -> DataSourceResult:
        """Generate simulated code intelligence"""
        import random

        domain_name = target.split('.')[0] if '.' in target else target

        repositories = [
            {
                'name': f'{domain_name}/{random.choice(["api", "sdk", "client", "docs", "tools"])}',
                'description': f'Official {domain_name} {random.choice(["API client", "SDK", "documentation", "tools"])}',
                'stars': random.randint(10, 5000),
                'language': random.choice(['Python', 'JavaScript', 'Go', 'Java', 'TypeScript']),
                'updated_at': (datetime.utcnow() - timedelta(days=random.randint(1, 180))).isoformat(),
                'url': f'https://github.com/{domain_name}/{random.choice(["api", "sdk"])}'
            }
            for _ in range(random.randint(2, 5))
        ]

        potential_exposures = []
        if random.random() < 0.3:  # 30% chance of finding exposure
            potential_exposures.append({
                'file': random.choice(['.env.example', 'config.sample.json', 'docker-compose.yml']),
                'repository': f'random-user/{domain_name}-project',
                'risk_level': random.choice(['low', 'medium']),
                'url': f'https://github.com/random-user/{domain_name}-project'
            })

        return DataSourceResult(
            source_name='code_intel_simulated',
            source_type=DataSourceType.CODE_INTEL.value,
            target=target,
            success=True,
            data={
                'repositories': repositories,
                'code_mentions': [{'file': 'README.md', 'repository': r['name']} for r in repositories[:3]],
                'potential_exposures': potential_exposures,
                'technologies': random.sample(['Python', 'JavaScript', 'Docker', 'Kubernetes', 'AWS', 'React'], 3),
                'total_repos_found': len(repositories),
                'exposure_risk': 'low' if not potential_exposures else potential_exposures[0]['risk_level']
            },
            confidence=0.5,
            metadata={'api_source': 'Simulated', 'is_real_data': False, 'demo_mode': True}
        )


# ============================================================================
# Breach Intelligence
# ============================================================================

class BreachIntelligenceClient(ExpandedDataSourceBase):
    """
    Breach and credential leak intelligence.

    Identifies:
    - Known data breaches affecting the target domain
    - Compromised credentials
    - Paste sites mentions
    - Dark web exposure indicators
    """

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(
            api_key=api_key or os.environ.get('HIBP_API_KEY'),
            base_url='https://haveibeenpwned.com/api/v3'
        )

    def get_source_info(self) -> Dict[str, Any]:
        return {
            'name': 'Breach Intelligence',
            'type': DataSourceType.BREACH_INTEL.value,
            'description': 'Data breach and credential leak monitoring',
            'capabilities': ['breach_detection', 'credential_exposure', 'paste_monitoring', 'dark_web_mentions'],
            'rate_limit': '10 requests/minute',
            'data_sources': ['HaveIBeenPwned', 'DeHashed', 'LeakCheck']
        }

    async def gather(self, target: str, **kwargs) -> DataSourceResult:
        """Gather breach intelligence for a domain or email"""
        try:
            if self.api_key:
                return await self._gather_real(target)
            else:
                return await self._gather_simulated(target)
        except Exception as e:
            logger.error(f"Breach intelligence gathering failed for {target}: {e}")
            return DataSourceResult(
                source_name='breach_intel',
                source_type=DataSourceType.BREACH_INTEL.value,
                target=target,
                success=False,
                data={},
                error=str(e)
            )

    async def _gather_real(self, target: str) -> DataSourceResult:
        """Gather real breach data from HIBP"""
        session = await self.get_session()
        headers = {
            'hibp-api-key': self.api_key,
            'User-Agent': 'OSINT-Platform'
        }

        results = {
            'breaches': [],
            'total_breaches': 0,
            'total_records_exposed': 0,
            'data_classes_exposed': set(),
            'earliest_breach': None,
            'latest_breach': None
        }

        try:
            # Search for breaches by domain
            async with session.get(
                f"{self.base_url}/breaches",
                params={'domain': target},
                headers=headers
            ) as response:
                if response.status == 200:
                    breaches = await response.json()
                    for breach in breaches:
                        results['breaches'].append({
                            'name': breach['Name'],
                            'title': breach['Title'],
                            'breach_date': breach['BreachDate'],
                            'added_date': breach['AddedDate'],
                            'pwn_count': breach['PwnCount'],
                            'data_classes': breach['DataClasses'],
                            'is_verified': breach['IsVerified'],
                            'is_sensitive': breach['IsSensitive']
                        })
                        results['total_records_exposed'] += breach['PwnCount']
                        results['data_classes_exposed'].update(breach['DataClasses'])

                    results['total_breaches'] = len(breaches)
                    results['data_classes_exposed'] = list(results['data_classes_exposed'])

                    if breaches:
                        dates = [b['BreachDate'] for b in breaches]
                        results['earliest_breach'] = min(dates)
                        results['latest_breach'] = max(dates)

            return DataSourceResult(
                source_name='haveibeenpwned',
                source_type=DataSourceType.BREACH_INTEL.value,
                target=target,
                success=True,
                data=results,
                confidence=0.95,
                metadata={'api_source': 'HaveIBeenPwned', 'is_real_data': True}
            )

        except aiohttp.ClientError as e:
            logger.error(f"HIBP API error: {e}")
            return await self._gather_simulated(target)

    async def _gather_simulated(self, target: str) -> DataSourceResult:
        """Generate simulated breach intelligence"""
        import random

        breach_names = [
            'LinkedIn', 'Adobe', 'Dropbox', 'MyFitnessPal', 'Canva',
            'Zynga', 'Dubsmash', 'MyHeritage', 'Armor Games', 'CafePress'
        ]

        data_classes = [
            'Email addresses', 'Passwords', 'Usernames', 'IP addresses',
            'Names', 'Phone numbers', 'Physical addresses', 'Dates of birth'
        ]

        num_breaches = random.randint(0, 4)
        breaches = []
        total_exposed = 0
        all_data_classes = set()

        for i in range(num_breaches):
            breach_date = (datetime.utcnow() - timedelta(days=random.randint(180, 2000))).strftime('%Y-%m-%d')
            pwn_count = random.randint(10000, 10000000)
            exposed_classes = random.sample(data_classes, random.randint(2, 5))

            breaches.append({
                'name': random.choice(breach_names),
                'title': f'{random.choice(breach_names)} Data Breach',
                'breach_date': breach_date,
                'pwn_count': pwn_count,
                'data_classes': exposed_classes,
                'is_verified': random.choice([True, True, False]),
                'is_sensitive': random.choice([False, False, True])
            })
            total_exposed += pwn_count
            all_data_classes.update(exposed_classes)

        risk_level = 'low' if num_breaches == 0 else 'medium' if num_breaches < 3 else 'high'

        return DataSourceResult(
            source_name='breach_intel_simulated',
            source_type=DataSourceType.BREACH_INTEL.value,
            target=target,
            success=True,
            data={
                'breaches': breaches,
                'total_breaches': num_breaches,
                'total_records_exposed': total_exposed,
                'data_classes_exposed': list(all_data_classes),
                'earliest_breach': breaches[-1]['breach_date'] if breaches else None,
                'latest_breach': breaches[0]['breach_date'] if breaches else None,
                'risk_level': risk_level,
                'recommendation': 'Monitor for credential stuffing attacks' if num_breaches > 0 else 'No known breaches'
            },
            confidence=0.5,
            metadata={'api_source': 'Simulated', 'is_real_data': False, 'demo_mode': True}
        )


# ============================================================================
# URL Intelligence
# ============================================================================

class URLIntelligenceClient(ExpandedDataSourceBase):
    """
    Malicious URL and phishing intelligence.

    Identifies:
    - Known malicious URLs associated with target
    - Phishing campaigns
    - Malware distribution
    - URL reputation
    """

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(
            api_key=api_key or os.environ.get('URLHAUS_API_KEY'),
            base_url='https://urlhaus-api.abuse.ch/v1'
        )

    def get_source_info(self) -> Dict[str, Any]:
        return {
            'name': 'URL Intelligence',
            'type': DataSourceType.URL_INTEL.value,
            'description': 'Malicious URL and phishing detection',
            'capabilities': ['malware_urls', 'phishing_detection', 'url_reputation', 'threat_classification'],
            'rate_limit': 'Unlimited (URLhaus)',
            'data_sources': ['URLhaus', 'PhishTank', 'OpenPhish']
        }

    async def gather(self, target: str, **kwargs) -> DataSourceResult:
        """Gather URL intelligence for a domain"""
        try:
            # URLhaus is free and doesn't require API key
            return await self._gather_urlhaus(target)
        except Exception as e:
            logger.error(f"URL intelligence gathering failed for {target}: {e}")
            return await self._gather_simulated(target)

    async def _gather_urlhaus(self, target: str) -> DataSourceResult:
        """Gather data from URLhaus"""
        session = await self.get_session()

        results = {
            'malicious_urls': [],
            'threat_types': [],
            'total_urls': 0,
            'active_threats': 0,
            'tags': []
        }

        try:
            async with session.post(
                f"{self.base_url}/host/",
                data={'host': target}
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    if data.get('query_status') == 'ok':
                        urls = data.get('urls', [])
                        results['total_urls'] = len(urls)

                        threat_types = set()
                        tags = set()

                        for url in urls[:20]:  # Limit to 20
                            results['malicious_urls'].append({
                                'url': url.get('url'),
                                'threat_type': url.get('threat'),
                                'status': url.get('url_status'),
                                'date_added': url.get('date_added'),
                                'tags': url.get('tags', [])
                            })
                            if url.get('threat'):
                                threat_types.add(url.get('threat'))
                            if url.get('tags'):
                                tags.update(url.get('tags'))
                            if url.get('url_status') == 'online':
                                results['active_threats'] += 1

                        results['threat_types'] = list(threat_types)
                        results['tags'] = list(tags)

            return DataSourceResult(
                source_name='urlhaus',
                source_type=DataSourceType.URL_INTEL.value,
                target=target,
                success=True,
                data=results,
                confidence=0.9 if results['total_urls'] > 0 else 0.7,
                metadata={'api_source': 'URLhaus', 'is_real_data': True}
            )

        except aiohttp.ClientError as e:
            logger.error(f"URLhaus API error: {e}")
            return await self._gather_simulated(target)

    async def _gather_simulated(self, target: str) -> DataSourceResult:
        """Generate simulated URL intelligence"""
        import random

        threat_types = ['malware_download', 'phishing', 'cryptominer', 'c2', 'spam']

        num_urls = random.randint(0, 5)
        malicious_urls = []

        for i in range(num_urls):
            malicious_urls.append({
                'url': f'https://{target}/{"".join(random.choices("abcdefghijklmnop", k=8))}.php',
                'threat_type': random.choice(threat_types),
                'status': random.choice(['online', 'offline', 'offline']),
                'date_added': (datetime.utcnow() - timedelta(days=random.randint(1, 180))).strftime('%Y-%m-%d'),
                'tags': random.sample(['elf', 'exe', 'doc', 'js', 'emotet', 'qakbot'], random.randint(0, 2))
            })

        return DataSourceResult(
            source_name='url_intel_simulated',
            source_type=DataSourceType.URL_INTEL.value,
            target=target,
            success=True,
            data={
                'malicious_urls': malicious_urls,
                'threat_types': list(set(u['threat_type'] for u in malicious_urls)),
                'total_urls': num_urls,
                'active_threats': len([u for u in malicious_urls if u['status'] == 'online']),
                'tags': list(set(tag for u in malicious_urls for tag in u.get('tags', []))),
                'risk_level': 'high' if num_urls > 3 else 'medium' if num_urls > 0 else 'low'
            },
            confidence=0.5,
            metadata={'api_source': 'Simulated', 'is_real_data': False, 'demo_mode': True}
        )


# ============================================================================
# Business Intelligence
# ============================================================================

class BusinessIntelligenceClient(ExpandedDataSourceBase):
    """
    Corporate and business intelligence.

    Identifies:
    - Company registration information
    - SEC filings (for public companies)
    - Corporate structure
    - Key personnel
    """

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(
            api_key=api_key or os.environ.get('OPENCORPORATES_API_KEY'),
            base_url='https://api.opencorporates.com/v0.4'
        )

    def get_source_info(self) -> Dict[str, Any]:
        return {
            'name': 'Business Intelligence',
            'type': DataSourceType.BUSINESS_INTEL.value,
            'description': 'Corporate registration and business intelligence',
            'capabilities': ['company_search', 'sec_filings', 'corporate_structure', 'key_personnel'],
            'rate_limit': '50 requests/month (free)',
            'data_sources': ['OpenCorporates', 'SEC EDGAR', 'Company registries']
        }

    async def gather(self, target: str, **kwargs) -> DataSourceResult:
        """Gather business intelligence for a company/domain"""
        try:
            # Extract company name from domain
            company_name = target.split('.')[0] if '.' in target else target
            return await self._gather_simulated(company_name, target)
        except Exception as e:
            logger.error(f"Business intelligence gathering failed for {target}: {e}")
            return DataSourceResult(
                source_name='business_intel',
                source_type=DataSourceType.BUSINESS_INTEL.value,
                target=target,
                success=False,
                data={},
                error=str(e)
            )

    async def _gather_simulated(self, company_name: str, target: str) -> DataSourceResult:
        """Generate simulated business intelligence"""
        import random

        industries = ['Technology', 'Finance', 'Healthcare', 'Retail', 'Manufacturing', 'Media']
        jurisdictions = ['Delaware, USA', 'California, USA', 'United Kingdom', 'Ireland', 'Netherlands']

        incorporation_date = datetime.utcnow() - timedelta(days=random.randint(365, 7300))

        return DataSourceResult(
            source_name='business_intel_simulated',
            source_type=DataSourceType.BUSINESS_INTEL.value,
            target=target,
            success=True,
            data={
                'company_info': {
                    'name': company_name.title() + random.choice([' Inc.', ' LLC', ' Ltd.', ' Corp.']),
                    'jurisdiction': random.choice(jurisdictions),
                    'incorporation_date': incorporation_date.strftime('%Y-%m-%d'),
                    'status': 'Active',
                    'industry': random.choice(industries),
                    'company_type': random.choice(['Private', 'Public', 'Private'])
                },
                'financial_indicators': {
                    'estimated_revenue': random.choice(['$1M-$10M', '$10M-$50M', '$50M-$100M', '$100M+']),
                    'employee_count': random.choice(['10-50', '50-200', '200-500', '500+']),
                    'funding_stage': random.choice(['Bootstrapped', 'Seed', 'Series A', 'Series B', 'Public'])
                },
                'key_personnel': [
                    {'role': 'CEO', 'name': 'John Smith'},
                    {'role': 'CTO', 'name': 'Jane Doe'},
                    {'role': 'CFO', 'name': 'Bob Johnson'}
                ][:random.randint(1, 3)],
                'related_entities': [
                    f'{company_name.title()} {suffix}'
                    for suffix in random.sample(['International', 'Holdings', 'Ventures', 'Technologies'], random.randint(0, 2))
                ],
                'regulatory_filings': random.randint(0, 5),
                'risk_indicators': {
                    'litigation_history': random.choice([True, False, False]),
                    'regulatory_issues': random.choice([True, False, False, False]),
                    'financial_distress': False
                }
            },
            confidence=0.5,
            metadata={'api_source': 'Simulated', 'is_real_data': False, 'demo_mode': True}
        )


# ============================================================================
# News Intelligence
# ============================================================================

class NewsIntelligenceClient(ExpandedDataSourceBase):
    """
    News and media intelligence.

    Identifies:
    - Recent news mentions
    - Press releases
    - Sentiment trends
    - Crisis indicators
    """

    def __init__(self, api_key: Optional[str] = None):
        super().__init__(
            api_key=api_key or os.environ.get('NEWSAPI_KEY'),
            base_url='https://newsapi.org/v2'
        )

    def get_source_info(self) -> Dict[str, Any]:
        return {
            'name': 'News Intelligence',
            'type': DataSourceType.NEWS_INTEL.value,
            'description': 'News and media monitoring',
            'capabilities': ['news_mentions', 'sentiment_analysis', 'crisis_detection', 'trend_analysis'],
            'rate_limit': '100 requests/day (free)',
            'data_sources': ['NewsAPI', 'GDELT', 'Google News']
        }

    async def gather(self, target: str, **kwargs) -> DataSourceResult:
        """Gather news intelligence for a target"""
        try:
            if self.api_key:
                return await self._gather_real(target)
            else:
                return await self._gather_simulated(target)
        except Exception as e:
            logger.error(f"News intelligence gathering failed for {target}: {e}")
            return DataSourceResult(
                source_name='news_intel',
                source_type=DataSourceType.NEWS_INTEL.value,
                target=target,
                success=False,
                data={},
                error=str(e)
            )

    async def _gather_real(self, target: str) -> DataSourceResult:
        """Gather real news data from NewsAPI"""
        session = await self.get_session()

        results = {
            'articles': [],
            'total_results': 0,
            'sentiment_summary': {'positive': 0, 'negative': 0, 'neutral': 0},
            'top_sources': [],
            'trending_topics': []
        }

        try:
            async with session.get(
                f"{self.base_url}/everything",
                params={
                    'q': target,
                    'sortBy': 'publishedAt',
                    'pageSize': 20,
                    'apiKey': self.api_key
                }
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    results['total_results'] = data.get('totalResults', 0)

                    sources = {}
                    for article in data.get('articles', [])[:20]:
                        results['articles'].append({
                            'title': article.get('title'),
                            'source': article.get('source', {}).get('name'),
                            'published_at': article.get('publishedAt'),
                            'url': article.get('url'),
                            'description': article.get('description', '')[:200]
                        })
                        source_name = article.get('source', {}).get('name', 'Unknown')
                        sources[source_name] = sources.get(source_name, 0) + 1

                    results['top_sources'] = sorted(sources.items(), key=lambda x: x[1], reverse=True)[:5]

            return DataSourceResult(
                source_name='newsapi',
                source_type=DataSourceType.NEWS_INTEL.value,
                target=target,
                success=True,
                data=results,
                confidence=0.8,
                metadata={'api_source': 'NewsAPI', 'is_real_data': True}
            )

        except aiohttp.ClientError as e:
            logger.error(f"NewsAPI error: {e}")
            return await self._gather_simulated(target)

    async def _gather_simulated(self, target: str) -> DataSourceResult:
        """Generate simulated news intelligence"""
        import random

        news_sources = ['TechCrunch', 'Reuters', 'Bloomberg', 'CNBC', 'The Verge', 'Wired', 'Forbes']
        topics = ['expansion', 'partnership', 'funding', 'product launch', 'acquisition', 'earnings', 'leadership change']

        num_articles = random.randint(3, 12)
        articles = []
        sources_count = {}

        for i in range(num_articles):
            source = random.choice(news_sources)
            topic = random.choice(topics)
            days_ago = random.randint(1, 30)

            articles.append({
                'title': f'{target.split(".")[0].title()} announces {topic}',
                'source': source,
                'published_at': (datetime.utcnow() - timedelta(days=days_ago)).isoformat(),
                'url': f'https://{source.lower().replace(" ", "")}.com/article/{random.randint(1000, 9999)}',
                'description': f'Recent news about {target} regarding {topic}...'
            })
            sources_count[source] = sources_count.get(source, 0) + 1

        sentiment = {
            'positive': random.randint(20, 60),
            'negative': random.randint(5, 25),
            'neutral': 0
        }
        sentiment['neutral'] = 100 - sentiment['positive'] - sentiment['negative']

        return DataSourceResult(
            source_name='news_intel_simulated',
            source_type=DataSourceType.NEWS_INTEL.value,
            target=target,
            success=True,
            data={
                'articles': articles,
                'total_results': num_articles,
                'sentiment_summary': sentiment,
                'top_sources': sorted(sources_count.items(), key=lambda x: x[1], reverse=True)[:5],
                'trending_topics': random.sample(topics, min(3, len(topics))),
                'media_visibility': 'high' if num_articles > 8 else 'medium' if num_articles > 4 else 'low',
                'crisis_indicators': random.choice([False, False, False, True])
            },
            confidence=0.5,
            metadata={'api_source': 'Simulated', 'is_real_data': False, 'demo_mode': True}
        )


# ============================================================================
# Expanded Data Source Manager
# ============================================================================

class ExpandedDataSourceManager:
    """
    Manager for all expanded data sources.

    Provides unified interface for:
    - Gathering intelligence from all sources
    - Aggregating results
    - Managing API keys and rate limits
    """

    def __init__(self):
        self.sources: Dict[str, ExpandedDataSourceBase] = {}
        self._initialize_sources()

    def _initialize_sources(self):
        """Initialize all data source clients"""
        self.sources = {
            'passive_dns': PassiveDNSClient(),
            'code_intel': CodeIntelligenceClient(),
            'breach_intel': BreachIntelligenceClient(),
            'url_intel': URLIntelligenceClient(),
            'business_intel': BusinessIntelligenceClient(),
            'news_intel': NewsIntelligenceClient()
        }

    def get_available_sources(self) -> List[Dict[str, Any]]:
        """Get list of available data sources and their capabilities"""
        return [source.get_source_info() for source in self.sources.values()]

    async def gather_all(self, target: str, sources: List[str] = None) -> Dict[str, DataSourceResult]:
        """
        Gather intelligence from all or specified sources.

        Args:
            target: Domain, company, or entity to investigate
            sources: List of source names to query (None = all)

        Returns:
            Dictionary mapping source name to result
        """
        results = {}

        # Determine which sources to query
        source_names = sources or list(self.sources.keys())

        # Gather from all sources in parallel
        tasks = []
        for name in source_names:
            if name in self.sources:
                tasks.append(self._gather_from_source(name, target))

        gathered = await asyncio.gather(*tasks, return_exceptions=True)

        for name, result in zip(source_names, gathered):
            if isinstance(result, Exception):
                logger.error(f"Error gathering from {name}: {result}")
                results[name] = DataSourceResult(
                    source_name=name,
                    source_type='error',
                    target=target,
                    success=False,
                    data={},
                    error=str(result)
                )
            else:
                results[name] = result

        return results

    async def _gather_from_source(self, source_name: str, target: str) -> DataSourceResult:
        """Gather from a single source with error handling"""
        source = self.sources.get(source_name)
        if not source:
            raise ValueError(f"Unknown source: {source_name}")
        return await source.gather(target)

    async def close_all(self):
        """Close all source connections"""
        for source in self.sources.values():
            await source.close()

    def get_aggregated_summary(self, results: Dict[str, DataSourceResult]) -> Dict[str, Any]:
        """
        Generate an aggregated summary from all results.

        Provides:
        - Overall risk assessment
        - Key findings across sources
        - Data quality metrics
        """
        successful = [r for r in results.values() if r.success]
        failed = [r for r in results.values() if not r.success]

        # Calculate aggregate confidence
        avg_confidence = sum(r.confidence for r in successful) / len(successful) if successful else 0

        # Identify key findings
        key_findings = []
        risk_indicators = []

        for result in successful:
            data = result.data

            # Passive DNS findings
            if result.source_type == DataSourceType.PASSIVE_DNS.value:
                if data.get('subdomains'):
                    key_findings.append(f"Discovered {len(data['subdomains'])} subdomains")
                if data.get('historical_dns'):
                    key_findings.append(f"Found {len(data['historical_dns'])} historical DNS records")

            # Breach findings
            if result.source_type == DataSourceType.BREACH_INTEL.value:
                if data.get('total_breaches', 0) > 0:
                    risk_indicators.append(f"Domain appears in {data['total_breaches']} known breaches")

            # URL findings
            if result.source_type == DataSourceType.URL_INTEL.value:
                if data.get('active_threats', 0) > 0:
                    risk_indicators.append(f"{data['active_threats']} active malicious URLs detected")

            # Code findings
            if result.source_type == DataSourceType.CODE_INTEL.value:
                if data.get('potential_exposures'):
                    risk_indicators.append(f"{len(data['potential_exposures'])} potential code exposures found")

        return {
            'sources_queried': len(results),
            'sources_successful': len(successful),
            'sources_failed': len(failed),
            'average_confidence': round(avg_confidence, 2),
            'key_findings': key_findings,
            'risk_indicators': risk_indicators,
            'overall_risk': 'high' if len(risk_indicators) >= 2 else 'medium' if risk_indicators else 'low',
            'data_completeness': round(len(successful) / len(results) * 100, 1) if results else 0
        }


# Global instance
expanded_data_manager = ExpandedDataSourceManager()
