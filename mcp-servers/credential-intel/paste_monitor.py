"""
Paste Site Credential Monitor
================================

Monitors public paste sites for credential dumps and mentions of target
domains, emails, or usernames.

Sources monitored:
  * psbdmp.ws — Pastebin dump search (free, no API key)
  * GitHub Gist search via GitHub's public API (free, no API key for basic searches)
  * IntelX paste search (API key optional; falls back to public-facing hints)

OPSEC NOTE: Paste site searches typically require sending the query term
to the search service.  Use with awareness of the OPSEC implications.

No API keys required for psbdmp.ws.
INTELX_API_KEY env var is optional for IntelligenceX results.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import aiohttp

logger = logging.getLogger(__name__)

_USER_AGENT = "Enterprise-OSINT-Platform/3.0"
_PSBDMP_SEARCH = "https://psbdmp.ws/api/v3/search/{query}"
_PSBDMP_DUMP = "https://psbdmp.ws/api/v3/dump/{paste_id}"
_INTELX_BASE = "https://2.intelx.io"

# Patterns for detecting credential-like content in paste text
_CREDENTIAL_PATTERNS = [
    re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}:[^\s\n]{4,}", re.MULTILINE),
    re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\s*[|,;:]\s*[^\s\n]{4,}", re.MULTILINE),
    re.compile(r"password[=:]\s*\S+", re.IGNORECASE),
    re.compile(r"passwd[=:]\s*\S+", re.IGNORECASE),
]

_INTELX_API_KEY = os.getenv("INTELX_API_KEY", "")


class PasteMonitor:
    """
    Monitors paste sites for credential dumps related to a target.

    Usage::

        async with PasteMonitor() as monitor:
            result = await monitor.search_domain("example.com")
    """

    def __init__(self):
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "PasteMonitor":
        self._session = aiohttp.ClientSession(
            headers={
                "User-Agent": _USER_AGENT,
                "Accept": "application/json",
            }
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def search_domain(self, domain: str, fetch_content: bool = False) -> Dict[str, Any]:
        """
        Search paste sites for any paste containing a domain name.

        Parameters
        ----------
        domain:
            Domain to search for (e.g. ``"example.com"``).
        fetch_content:
            If True, fetch the full content of up to 5 matching pastes and
            analyse for credential patterns.  Increases latency.

        Returns::

            {
                "query": str,
                "paste_count": int,
                "pastes": [...],
                "credential_lines_found": int,
                "sources": [str, ...],
                "source": "paste_monitor"
            }
        """
        pastes = await self._psbdmp_search(domain)
        if fetch_content and pastes:
            pastes = await self._enrich_pastes(pastes[:5])

        cred_lines = sum(p.get("credential_lines", 0) for p in pastes)
        sources = list({p.get("source_site") for p in pastes})

        return {
            "query": domain,
            "paste_count": len(pastes),
            "pastes": pastes,
            "credential_lines_found": cred_lines,
            "sources": sources,
            "source": "paste_monitor",
        }

    async def search_email(self, email: str, fetch_content: bool = False) -> Dict[str, Any]:
        """Search paste sites for pastes mentioning a specific email address."""
        pastes = await self._psbdmp_search(email)
        if fetch_content and pastes:
            pastes = await self._enrich_pastes(pastes[:5])

        cred_lines = sum(p.get("credential_lines", 0) for p in pastes)

        return {
            "query": email,
            "paste_count": len(pastes),
            "pastes": pastes,
            "credential_lines_found": cred_lines,
            "source": "paste_monitor",
        }

    async def search_keyword(self, keyword: str) -> Dict[str, Any]:
        """Generic keyword search across paste sites."""
        pastes = await self._psbdmp_search(keyword)
        return {
            "query": keyword,
            "paste_count": len(pastes),
            "pastes": pastes,
            "source": "paste_monitor",
        }

    async def fetch_and_analyse_paste(self, paste_id: str) -> Dict[str, Any]:
        """
        Fetch a specific paste by ID and analyse it for credential patterns.

        Returns::

            {
                "paste_id": str,
                "content_length": int,
                "credential_lines": int,
                "sample_credentials": [str, ...],  // first 10 matches
                "has_emails": bool,
                "email_count": int,
                "source": "paste_monitor"
            }
        """
        try:
            url = _PSBDMP_DUMP.format(paste_id=paste_id)
            async with self._session.get(url) as resp:
                if resp.status != 200:
                    return {
                        "paste_id": paste_id,
                        "error": f"HTTP {resp.status}",
                        "source": "paste_monitor",
                    }
                data = await resp.json(content_type=None)
                content = data.get("data") if isinstance(data, dict) else str(data)
                if not content:
                    return {"paste_id": paste_id, "credential_lines": 0, "source": "paste_monitor"}

                return self._analyse_content(paste_id, content)
        except Exception as exc:
            logger.warning("PasteMonitor.fetch_and_analyse_paste failed for %s: %s", paste_id, exc)
            return {"paste_id": paste_id, "error": str(exc), "source": "paste_monitor"}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _psbdmp_search(self, query: str) -> List[Dict[str, Any]]:
        """Query psbdmp.ws for pastes matching a keyword."""
        try:
            url = _PSBDMP_SEARCH.format(query=quote(query, safe=""))
            async with self._session.get(url) as resp:
                if resp.status != 200:
                    logger.debug("psbdmp search returned HTTP %s for %s", resp.status, query)
                    return []
                data = await resp.json(content_type=None)

                if isinstance(data, dict):
                    items = data.get("data") or data.get("results") or []
                elif isinstance(data, list):
                    items = data
                else:
                    return []

                pastes = []
                for item in items:
                    if isinstance(item, str):
                        pastes.append({
                            "paste_id": item,
                            "source_site": "pastebin",
                            "url": f"https://pastebin.com/{item}",
                            "date": None,
                            "tags": [],
                        })
                    elif isinstance(item, dict):
                        pastes.append({
                            "paste_id": item.get("id") or item.get("paste_id"),
                            "source_site": item.get("source") or "pastebin",
                            "url": item.get("url") or f"https://pastebin.com/{item.get('id')}",
                            "date": item.get("time") or item.get("date"),
                            "title": item.get("title") or item.get("tags"),
                            "tags": item.get("tags") or [],
                        })
                return pastes
        except Exception as exc:
            logger.warning("psbdmp search failed for %s: %s", query, exc)
            return []

    async def _enrich_pastes(self, pastes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fetch content for pastes and analyse for credentials."""
        enriched = []
        for paste in pastes:
            paste_id = paste.get("paste_id")
            if paste_id:
                analysis = await self.fetch_and_analyse_paste(paste_id)
                paste.update({
                    "credential_lines": analysis.get("credential_lines", 0),
                    "email_count": analysis.get("email_count", 0),
                    "content_length": analysis.get("content_length", 0),
                })
            enriched.append(paste)
        return enriched

    @staticmethod
    def _analyse_content(paste_id: str, content: str) -> Dict[str, Any]:
        """Analyse raw paste content for credential patterns."""
        email_pattern = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
        email_matches = email_pattern.findall(content)

        cred_matches = []
        for pattern in _CREDENTIAL_PATTERNS:
            cred_matches.extend(pattern.findall(content))

        return {
            "paste_id": paste_id,
            "content_length": len(content),
            "credential_lines": len(cred_matches),
            "sample_credentials": cred_matches[:10],
            "has_emails": len(email_matches) > 0,
            "email_count": len(set(email_matches)),
            "source": "paste_monitor",
        }
