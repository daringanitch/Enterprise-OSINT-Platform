"""
Dehashed API Client
====================

Wraps the Dehashed REST API for searching compiled credential databases
containing 15B+ records from thousands of data breaches.

Query field operators:
  email:, username:, ip_address:, password:, hashed_password:,
  name:, vin:, address:, phone:, domain:

API docs: https://www.dehashed.com/docs
Required env vars: DEHASHED_EMAIL, DEHASHED_API_KEY
Rate limit: Depends on subscription tier
"""

from __future__ import annotations

import base64
import logging
import os
import re
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)

_DEHASHED_BASE = "https://api.dehashed.com"
_USER_AGENT = "Enterprise-OSINT-Platform/3.0"


class DehashedClient:
    """
    Async Dehashed API client.

    Usage::

        async with DehashedClient() as client:
            result = await client.search_email("user@example.com")
    """

    def __init__(
        self,
        email: Optional[str] = None,
        api_key: Optional[str] = None,
    ):
        self.email = email or os.getenv("DEHASHED_EMAIL", "")
        self.api_key = api_key or os.getenv("DEHASHED_API_KEY", "")
        self._session: Optional[aiohttp.ClientSession] = None
        self._configured = bool(self.email and self.api_key)

    @property
    def configured(self) -> bool:
        return self._configured

    async def __aenter__(self) -> "DehashedClient":
        # Dehashed uses HTTP Basic auth
        creds = base64.b64encode(f"{self.email}:{self.api_key}".encode()).decode()
        self._session = aiohttp.ClientSession(
            headers={
                "Authorization": f"Basic {creds}",
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

    async def search(
        self,
        query: str,
        size: int = 10,
        page: int = 1,
    ) -> Dict[str, Any]:
        """
        Generic search across Dehashed database.

        Parameters
        ----------
        query:
            Field-qualified query string, e.g. ``"email:user@example.com"``
            or ``"domain:example.com"`` or ``"password:Dragon2019!"``
        size:
            Number of results per page (max 10000).
        page:
            Page number (1-indexed).

        Returns::

            {
                "query": str,
                "total": int,
                "entries": [
                    {
                        "id": str,
                        "email": str | None,
                        "ip_address": str | None,
                        "username": str | None,
                        "password": str | None,
                        "hashed_password": str | None,
                        "name": str | None,
                        "vin": str | None,
                        "address": str | None,
                        "phone": str | None,
                        "database_name": str
                    }, ...
                ],
                "source": "dehashed"
            }
        """
        if not self._configured:
            return {"error": "Dehashed credentials not configured", "query": query, "source": "dehashed"}

        try:
            params = {"query": query, "size": min(size, 10000), "page": page}
            async with self._session.get(f"{_DEHASHED_BASE}/search", params=params) as resp:
                if resp.status == 400:
                    body = await resp.text()
                    return {"error": f"Bad request: {body[:200]}", "query": query, "source": "dehashed"}
                if resp.status == 401:
                    return {"error": "Dehashed credentials invalid", "query": query, "source": "dehashed"}
                if resp.status == 302:
                    # Redirect usually means not subscribed
                    return {"error": "Dehashed subscription required or session expired",
                            "query": query, "source": "dehashed"}
                if resp.status != 200:
                    return {"error": f"HTTP {resp.status}", "query": query, "source": "dehashed"}

                data = await resp.json()
                entries = data.get("entries") or []
                normalised = [self._normalise_entry(e) for e in entries]

                return {
                    "query": query,
                    "total": data.get("total", len(normalised)),
                    "entries": normalised,
                    "balance": data.get("balance"),
                    "source": "dehashed",
                }
        except Exception as exc:
            logger.warning("DehashedClient.search failed for %s: %s", query, exc)
            return {"error": str(exc), "query": query, "source": "dehashed"}

    async def search_email(self, email: str, size: int = 10) -> Dict[str, Any]:
        """Search for all breach entries containing a specific email address."""
        result = await self.search(f"email:{email}", size=size)
        result["email"] = email
        return result

    async def search_domain(self, domain: str, size: int = 20) -> Dict[str, Any]:
        """
        Search for all breach entries from a specific domain.

        This is the most powerful corporate exposure check — returns all
        leaked credentials for any @domain.com address.
        """
        result = await self.search(f"domain:{domain}", size=size)
        result["domain"] = domain
        # Extract unique emails
        emails = list({e.get("email") for e in result.get("entries", []) if e.get("email")})
        result["unique_emails"] = sorted(emails)
        result["unique_email_count"] = len(emails)
        return result

    async def search_username(self, username: str, size: int = 10) -> Dict[str, Any]:
        """Search for all breach entries containing a specific username."""
        result = await self.search(f"username:{username}", size=size)
        result["username"] = username
        return result

    async def search_password(self, password: str, size: int = 5) -> Dict[str, Any]:
        """
        Search for breach entries where a specific plaintext password was used.

        OPSEC WARNING: Sends the full plaintext password to Dehashed servers.
        For known hashes, prefer search_hashed_password().
        """
        result = await self.search(f"password:{password}", size=size)
        result["searched_password"] = password
        return result

    async def search_ip(self, ip: str, size: int = 10) -> Dict[str, Any]:
        """Search for breach entries associated with an IP address."""
        result = await self.search(f"ip_address:{ip}", size=size)
        result["ip"] = ip
        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_entry(entry: Dict[str, Any]) -> Dict[str, Any]:
        """Normalise a raw Dehashed entry to a consistent schema."""
        return {
            "id": entry.get("id"),
            "email": entry.get("email") or None,
            "ip_address": entry.get("ip_address") or None,
            "username": entry.get("username") or None,
            "password": entry.get("password") or None,
            "hashed_password": entry.get("hashed_password") or None,
            "name": entry.get("name") or None,
            "vin": entry.get("vin") or None,
            "address": entry.get("address") or None,
            "phone": entry.get("phone") or None,
            "database_name": entry.get("database_name") or "unknown",
        }
