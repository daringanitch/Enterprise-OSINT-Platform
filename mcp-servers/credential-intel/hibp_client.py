"""
HaveIBeenPwned Enterprise API v3 Client
=========================================

Wraps the HIBP Enterprise REST API for:
  * Breached account checks (by email)
  * Domain exposure reports (all emails in breaches for a domain)
  * Paste monitoring (by email)
  * k-anonymity password hash lookup via HIBP Passwords API

OPSEC NOTE: Email-based queries are NOT k-anonymous — the full email is sent
to HIBP servers.  Only password checks use the k-anonymity model.
Plan your OPSEC accordingly.

API docs: https://haveibeenpwned.com/API/v3
Required env var: HIBP_API_KEY
Rate limit: 1 request / 1500 ms per key
"""

from __future__ import annotations

import hashlib
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)

_HIBP_BASE = "https://haveibeenpwned.com/api/v3"
_HIBP_PWNED_BASE = "https://api.pwnedpasswords.com"
_USER_AGENT = "Enterprise-OSINT-Platform/3.0"
_RATE_LIMIT_DELAY = 1.6  # seconds — HIBP enforces ≥1500 ms


class HIBPClient:
    """
    Async HaveIBeenPwned Enterprise API v3 client.

    Usage::

        async with HIBPClient() as client:
            result = await client.check_email("user@example.com")
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or os.getenv("HIBP_API_KEY", "")
        self._session: Optional[aiohttp.ClientSession] = None
        self._configured = bool(self.api_key)
        self._last_request_time: float = 0.0

    @property
    def configured(self) -> bool:
        return self._configured

    async def __aenter__(self) -> "HIBPClient":
        headers = {
            "hibp-api-key": self.api_key,
            "user-agent": _USER_AGENT,
            "Accept": "application/json",
        }
        self._session = aiohttp.ClientSession(headers=headers)
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()
            self._session = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def check_email(self, email: str) -> Dict[str, Any]:
        """
        Check if an email address appears in any known data breaches.

        Returns::

            {
                "email": str,
                "breach_count": int,
                "breaches": [
                    {
                        "name": str,
                        "title": str,
                        "domain": str,
                        "breach_date": str,
                        "pwn_count": int,
                        "data_classes": [str, ...],
                        "is_verified": bool,
                        "is_sensitive": bool,
                        "is_spam_list": bool
                    }, ...
                ],
                "data_classes_exposed": [str, ...],
                "has_password_exposure": bool,
                "source": "hibp"
            }
        """
        if not self._configured:
            return {"error": "HIBP API key not configured", "email": email, "source": "hibp"}

        await self._rate_limit()
        try:
            url = f"{_HIBP_BASE}/breachedaccount/{email}?truncateResponse=false"
            async with self._session.get(url) as resp:
                if resp.status == 404:
                    # 404 = no breaches found (not an error)
                    return {
                        "email": email,
                        "breach_count": 0,
                        "breaches": [],
                        "data_classes_exposed": [],
                        "has_password_exposure": False,
                        "source": "hibp",
                    }
                if resp.status == 429:
                    return {"error": "HIBP rate limit exceeded", "email": email, "source": "hibp"}
                if resp.status == 401:
                    return {"error": "HIBP API key invalid or expired", "email": email, "source": "hibp"}
                if resp.status != 200:
                    return {"error": f"HTTP {resp.status}", "email": email, "source": "hibp"}

                breaches = await resp.json()
                all_data_classes: set = set()
                normalised = []
                for b in breaches:
                    dcs = b.get("DataClasses", [])
                    all_data_classes.update(dcs)
                    normalised.append({
                        "name": b.get("Name"),
                        "title": b.get("Title"),
                        "domain": b.get("Domain"),
                        "breach_date": b.get("BreachDate"),
                        "pwn_count": b.get("PwnCount", 0),
                        "data_classes": dcs,
                        "is_verified": b.get("IsVerified", False),
                        "is_sensitive": b.get("IsSensitive", False),
                        "is_spam_list": b.get("IsSpamList", False),
                        "is_retired": b.get("IsRetired", False),
                    })

                return {
                    "email": email,
                    "breach_count": len(normalised),
                    "breaches": normalised,
                    "data_classes_exposed": sorted(all_data_classes),
                    "has_password_exposure": "Passwords" in all_data_classes,
                    "source": "hibp",
                }
        except Exception as exc:
            logger.warning("HIBPClient.check_email failed for %s: %s", email, exc)
            return {"error": str(exc), "email": email, "source": "hibp"}

    async def check_domain(self, domain: str) -> Dict[str, Any]:
        """
        Get all email addresses from a domain that appear in known breaches.

        This uses the HIBP Domain Search API which returns {email: [breach_names]}.

        Returns::

            {
                "domain": str,
                "email_count": int,
                "emails": { "user@domain.com": ["breach1", "breach2"], ... },
                "most_breached": { "email": str, "count": int },
                "source": "hibp"
            }
        """
        if not self._configured:
            return {"error": "HIBP API key not configured", "domain": domain, "source": "hibp"}

        await self._rate_limit()
        try:
            url = f"{_HIBP_BASE}/breacheddomain/{domain}"
            async with self._session.get(url) as resp:
                if resp.status == 404:
                    return {
                        "domain": domain,
                        "email_count": 0,
                        "emails": {},
                        "most_breached": None,
                        "source": "hibp",
                    }
                if resp.status == 401:
                    return {"error": "HIBP API key invalid — domain search requires Enterprise subscription",
                            "domain": domain, "source": "hibp"}
                if resp.status != 200:
                    return {"error": f"HTTP {resp.status}", "domain": domain, "source": "hibp"}

                data = await resp.json()
                most_breached = None
                if data:
                    most_email = max(data.keys(), key=lambda e: len(data[e]))
                    most_breached = {"email": most_email, "count": len(data[most_email])}

                return {
                    "domain": domain,
                    "email_count": len(data),
                    "emails": data,
                    "most_breached": most_breached,
                    "source": "hibp",
                }
        except Exception as exc:
            logger.warning("HIBPClient.check_domain failed for %s: %s", domain, exc)
            return {"error": str(exc), "domain": domain, "source": "hibp"}

    async def check_pastes(self, email: str) -> Dict[str, Any]:
        """
        Check if an email appears in any known paste sites.

        Returns::

            {
                "email": str,
                "paste_count": int,
                "pastes": [
                    {
                        "source": str,
                        "id": str,
                        "title": str | None,
                        "date": str | None,
                        "email_count": int | None
                    }, ...
                ],
                "source": "hibp"
            }
        """
        if not self._configured:
            return {"error": "HIBP API key not configured", "email": email, "source": "hibp"}

        await self._rate_limit()
        try:
            url = f"{_HIBP_BASE}/pasteaccount/{email}"
            async with self._session.get(url) as resp:
                if resp.status == 404:
                    return {
                        "email": email,
                        "paste_count": 0,
                        "pastes": [],
                        "source": "hibp",
                    }
                if resp.status != 200:
                    return {"error": f"HTTP {resp.status}", "email": email, "source": "hibp"}

                pastes = await resp.json()
                normalised = [
                    {
                        "source": p.get("Source"),
                        "id": p.get("Id"),
                        "title": p.get("Title"),
                        "date": p.get("Date"),
                        "email_count": p.get("EmailCount"),
                    }
                    for p in (pastes or [])
                ]
                return {
                    "email": email,
                    "paste_count": len(normalised),
                    "pastes": normalised,
                    "source": "hibp",
                }
        except Exception as exc:
            logger.warning("HIBPClient.check_pastes failed for %s: %s", email, exc)
            return {"error": str(exc), "email": email, "source": "hibp"}

    async def check_password_pwned(self, password: str) -> Dict[str, Any]:
        """
        Check if a password appears in breaches using k-anonymity (SHA-1 prefix).

        The full password is NEVER sent — only the first 5 chars of its SHA-1 hash.

        Returns::

            {
                "password_sha1_prefix": str,   // first 5 hex chars of SHA-1
                "pwned_count": int,             // 0 if not found
                "is_pwned": bool,
                "source": "hibp_passwords"
            }
        """
        sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        prefix = sha1[:5]
        suffix = sha1[5:]

        try:
            # Use a separate session without auth headers for Pwned Passwords API
            async with aiohttp.ClientSession(headers={"user-agent": _USER_AGENT}) as sess:
                url = f"{_HIBP_PWNED_BASE}/range/{prefix}"
                async with sess.get(url) as resp:
                    if resp.status != 200:
                        return {
                            "error": f"HIBP Passwords API returned HTTP {resp.status}",
                            "is_pwned": None,
                            "source": "hibp_passwords",
                        }
                    text = await resp.text()

            count = 0
            for line in text.splitlines():
                hash_suffix, n = line.split(":")
                if hash_suffix.upper() == suffix:
                    count = int(n)
                    break

            return {
                "password_sha1_prefix": prefix,
                "pwned_count": count,
                "is_pwned": count > 0,
                "source": "hibp_passwords",
            }
        except Exception as exc:
            logger.warning("HIBPClient.check_password_pwned failed: %s", exc)
            return {"error": str(exc), "is_pwned": None, "source": "hibp_passwords"}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _rate_limit(self) -> None:
        """Enforce HIBP's 1500ms minimum between requests."""
        import asyncio
        import time

        now = time.monotonic()
        elapsed = now - self._last_request_time
        if elapsed < _RATE_LIMIT_DELAY:
            await asyncio.sleep(_RATE_LIMIT_DELAY - elapsed)
        self._last_request_time = time.monotonic()
