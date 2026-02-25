"""
Hudson Rock Cavalier API Client (Free Tier)
============================================

Hudson Rock tracks credentials stolen by infostealer malware (Redline,
Raccoon, Vidar, Lumma, etc.).  This is qualitatively different from breach
databases — these are credentials that were actively exfiltrated from a
victim's machine, often including:
  * Saved browser credentials
  * Session cookies (can be used for session hijacking, not just password reuse)
  * System information (OS, hostname, IP, country)
  * List of installed software

The free Cavalier API tier allows limited queries with no API key.

API docs: https://cavalier.hudsonrock.com/docs
No API key required (free tier)
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)

_HUDSON_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"
_USER_AGENT = "Enterprise-OSINT-Platform/3.0"


class HudsonRockClient:
    """
    Async Hudson Rock Cavalier API client (free tier, no API key).

    Usage::

        async with HudsonRockClient() as client:
            result = await client.search_email("user@example.com")
    """

    def __init__(self):
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self) -> "HudsonRockClient":
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

    async def search_email(self, email: str) -> Dict[str, Any]:
        """
        Search for infostealer victims by email address.

        Returns victim machine details when the email was found in an
        infostealer log.

        Returns::

            {
                "email": str,
                "found": bool,
                "stealers": [
                    {
                        "computer_name": str,
                        "operating_system": str,
                        "malware_path": str,
                        "date_compromised": str,
                        "antiviruses": [str, ...],
                        "ip": str,
                        "top_passwords": [str, ...],
                        "top_logins": [str, ...],
                        "employee_count": int | None,
                        "url": str | None
                    }, ...
                ],
                "stealer_count": int,
                "source": "hudson_rock"
            }
        """
        try:
            url = f"{_HUDSON_BASE}/search-by-email"
            async with self._session.get(url, params={"email": email}) as resp:
                return self._parse_response(resp.status, await self._safe_json(resp),
                                            "email", email)
        except Exception as exc:
            logger.warning("HudsonRockClient.search_email failed for %s: %s", email, exc)
            return {"error": str(exc), "email": email, "found": False, "source": "hudson_rock"}

    async def search_domain(self, domain: str) -> Dict[str, Any]:
        """
        Search for infostealer victims associated with a domain.

        Returns summary of victim machines where credentials for the domain
        were found.

        Returns::

            {
                "domain": str,
                "found": bool,
                "employees": [
                    {
                        "username": str,
                        "email": str | None,
                        "computer_name": str,
                        "operating_system": str,
                        "date_compromised": str,
                        "url": str | None
                    }, ...
                ],
                "third_party_count": int,
                "employee_count": int,
                "source": "hudson_rock"
            }
        """
        try:
            url = f"{_HUDSON_BASE}/search-by-domain"
            async with self._session.get(url, params={"domain": domain}) as resp:
                return self._parse_domain_response(resp.status, await self._safe_json(resp), domain)
        except Exception as exc:
            logger.warning("HudsonRockClient.search_domain failed for %s: %s", domain, exc)
            return {"error": str(exc), "domain": domain, "found": False, "source": "hudson_rock"}

    async def search_username(self, username: str) -> Dict[str, Any]:
        """
        Search for infostealer victims by username.

        Returns::

            {
                "username": str,
                "found": bool,
                "stealers": [...],
                "stealer_count": int,
                "source": "hudson_rock"
            }
        """
        try:
            url = f"{_HUDSON_BASE}/search-by-username"
            async with self._session.get(url, params={"username": username}) as resp:
                return self._parse_response(resp.status, await self._safe_json(resp),
                                            "username", username)
        except Exception as exc:
            logger.warning("HudsonRockClient.search_username failed for %s: %s", username, exc)
            return {"error": str(exc), "username": username, "found": False, "source": "hudson_rock"}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    async def _safe_json(resp: aiohttp.ClientResponse) -> Any:
        """Parse JSON response, returning None on failure."""
        try:
            return await resp.json(content_type=None)
        except Exception:
            try:
                text = await resp.text()
                logger.debug("HudsonRock non-JSON response: %s", text[:200])
            except Exception:
                pass
            return None

    @staticmethod
    def _normalise_stealer(entry: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "computer_name": entry.get("computer_name") or entry.get("computerName"),
            "operating_system": entry.get("operating_system") or entry.get("operatingSystem"),
            "malware_path": entry.get("malware_path") or entry.get("malwarePath"),
            "date_compromised": entry.get("date_compromised") or entry.get("dateCompromised"),
            "antiviruses": entry.get("antiviruses") or [],
            "ip": entry.get("ip"),
            "top_passwords": entry.get("top_passwords") or entry.get("topPasswords") or [],
            "top_logins": entry.get("top_logins") or entry.get("topLogins") or [],
            "employee_count": entry.get("employee_count"),
            "url": entry.get("url"),
        }

    def _parse_response(
        self,
        status: int,
        data: Any,
        key: str,
        value: str,
    ) -> Dict[str, Any]:
        if status == 429:
            return {"error": "Hudson Rock rate limit exceeded", key: value,
                    "found": False, "source": "hudson_rock"}
        if status not in (200, 404):
            return {"error": f"HTTP {status}", key: value, "found": False, "source": "hudson_rock"}
        if not data or not isinstance(data, (dict, list)):
            return {key: value, "found": False, "stealers": [], "stealer_count": 0,
                    "source": "hudson_rock"}

        # API returns a list of stealer objects or {"message": "..."}
        if isinstance(data, list):
            stealers = [self._normalise_stealer(e) for e in data]
        elif isinstance(data, dict) and "stealers" in data:
            stealers = [self._normalise_stealer(e) for e in data["stealers"]]
        elif isinstance(data, dict) and data.get("message"):
            stealers = []
        else:
            stealers = []

        return {
            key: value,
            "found": len(stealers) > 0,
            "stealers": stealers,
            "stealer_count": len(stealers),
            "source": "hudson_rock",
        }

    def _parse_domain_response(self, status: int, data: Any, domain: str) -> Dict[str, Any]:
        if status == 429:
            return {"error": "Hudson Rock rate limit exceeded", "domain": domain,
                    "found": False, "source": "hudson_rock"}
        if status not in (200, 404):
            return {"error": f"HTTP {status}", "domain": domain, "found": False,
                    "source": "hudson_rock"}
        if not data or not isinstance(data, dict):
            return {"domain": domain, "found": False, "employees": [], "third_party_count": 0,
                    "employee_count": 0, "source": "hudson_rock"}

        employees = []
        raw_employees = data.get("employees") or data.get("stealers") or []
        for e in raw_employees:
            employees.append({
                "username": e.get("username") or e.get("user"),
                "email": e.get("email"),
                "computer_name": e.get("computer_name") or e.get("computerName"),
                "operating_system": e.get("operating_system") or e.get("operatingSystem"),
                "date_compromised": e.get("date_compromised") or e.get("dateCompromised"),
                "url": e.get("url"),
            })

        return {
            "domain": domain,
            "found": len(employees) > 0 or bool(data.get("employees_count")),
            "employees": employees,
            "employee_count": data.get("employees_count") or len(employees),
            "third_party_count": data.get("third_party_count") or 0,
            "source": "hudson_rock",
        }
