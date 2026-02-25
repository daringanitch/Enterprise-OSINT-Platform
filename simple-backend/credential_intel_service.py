"""
Credential Intelligence Service
=================================

Backend service that orchestrates credential intelligence queries across
the four source clients.  This service is used directly by the Flask
credentials blueprint — it does NOT require the credential-intel MCP server
to be running (it imports the client classes directly from the MCP server
module path).

If the MCP server clients are unavailable, the service degrades gracefully
with descriptive error responses.

Sources:
  * HaveIBeenPwned Enterprise (HIBP_API_KEY env var)
  * Dehashed (DEHASHED_EMAIL + DEHASHED_API_KEY env vars)
  * Hudson Rock Cavalier (free, no API key)
  * Paste site monitor (free, no API key)
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Import client classes from the MCP server directory.
# Fall back gracefully if not available (different deployment paths).
# ---------------------------------------------------------------------------

_MCP_SERVER_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "mcp-servers", "credential-intel")
)

_CLIENTS_AVAILABLE = False
HIBPClient = None
DehashedClient = None
HudsonRockClient = None
PasteMonitor = None

if os.path.isdir(_MCP_SERVER_DIR):
    if _MCP_SERVER_DIR not in sys.path:
        sys.path.insert(0, _MCP_SERVER_DIR)
    try:
        from hibp_client import HIBPClient  # type: ignore
        from dehashed_client import DehashedClient  # type: ignore
        from hudson_rock_client import HudsonRockClient  # type: ignore
        from paste_monitor import PasteMonitor  # type: ignore
        _CLIENTS_AVAILABLE = True
        logger.info("credential_intel_service: MCP clients loaded successfully")
    except ImportError as exc:
        logger.warning("credential_intel_service: Could not import MCP clients: %s", exc)
else:
    logger.info("credential_intel_service: MCP server dir not found at %s", _MCP_SERVER_DIR)


def _unavailable_response(source: str, target: str, reason: str = "Client not available") -> Dict[str, Any]:
    return {"error": reason, "target": target, "source": source}


def _run_async(coro) -> Any:
    """Run an async coroutine from a synchronous context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(asyncio.run, coro)
                return future.result(timeout=60)
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


# ---------------------------------------------------------------------------
# CredentialIntelService
# ---------------------------------------------------------------------------


class CredentialIntelService:
    """
    High-level service for credential intelligence queries.

    All public methods are synchronous wrappers around async operations.
    Designed for use in Flask route handlers.
    """

    # ------------------------------------------------------------------
    # HIBP methods
    # ------------------------------------------------------------------

    def check_email_breaches(self, email: str) -> Dict[str, Any]:
        """Check email address against HIBP breach database."""
        if not _CLIENTS_AVAILABLE or HIBPClient is None:
            return _unavailable_response("hibp", email, "HIBP client not available")

        async def _run():
            async with HIBPClient() as client:
                return await client.check_email(email)

        return _run_async(_run())

    def check_domain_exposure(self, domain: str) -> Dict[str, Any]:
        """Get all email addresses from a domain that appear in HIBP breaches."""
        if not _CLIENTS_AVAILABLE or HIBPClient is None:
            return _unavailable_response("hibp", domain, "HIBP client not available")

        async def _run():
            async with HIBPClient() as client:
                return await client.check_domain(domain)

        return _run_async(_run())

    def check_email_pastes(self, email: str) -> Dict[str, Any]:
        """Check if an email appears in known paste sites via HIBP."""
        if not _CLIENTS_AVAILABLE or HIBPClient is None:
            return _unavailable_response("hibp", email, "HIBP client not available")

        async def _run():
            async with HIBPClient() as client:
                return await client.check_pastes(email)

        return _run_async(_run())

    def check_password_pwned(self, password: str) -> Dict[str, Any]:
        """k-anonymity password check via HIBP Passwords API."""
        if not _CLIENTS_AVAILABLE or HIBPClient is None:
            return _unavailable_response("hibp_passwords", password[:3] + "***", "HIBP client not available")

        async def _run():
            async with HIBPClient() as client:
                return await client.check_password_pwned(password)

        return _run_async(_run())

    # ------------------------------------------------------------------
    # Dehashed methods
    # ------------------------------------------------------------------

    def dehashed_search(self, query: str, size: int = 10) -> Dict[str, Any]:
        """Generic Dehashed field-qualified search."""
        if not _CLIENTS_AVAILABLE or DehashedClient is None:
            return _unavailable_response("dehashed", query, "Dehashed client not available")

        async def _run():
            async with DehashedClient() as client:
                return await client.search(query, size=size)

        return _run_async(_run())

    def dehashed_domain(self, domain: str, size: int = 20) -> Dict[str, Any]:
        """Dehashed domain exposure — all leaked @domain.com credentials."""
        if not _CLIENTS_AVAILABLE or DehashedClient is None:
            return _unavailable_response("dehashed", domain, "Dehashed client not available")

        async def _run():
            async with DehashedClient() as client:
                return await client.search_domain(domain, size=size)

        return _run_async(_run())

    def dehashed_email(self, email: str, size: int = 10) -> Dict[str, Any]:
        """Dehashed search by email."""
        if not _CLIENTS_AVAILABLE or DehashedClient is None:
            return _unavailable_response("dehashed", email, "Dehashed client not available")

        async def _run():
            async with DehashedClient() as client:
                return await client.search_email(email, size=size)

        return _run_async(_run())

    # ------------------------------------------------------------------
    # Hudson Rock methods
    # ------------------------------------------------------------------

    def hudson_rock_email(self, email: str) -> Dict[str, Any]:
        """Hudson Rock infostealer lookup by email."""
        if not _CLIENTS_AVAILABLE or HudsonRockClient is None:
            return _unavailable_response("hudson_rock", email, "Hudson Rock client not available")

        async def _run():
            async with HudsonRockClient() as client:
                return await client.search_email(email)

        return _run_async(_run())

    def hudson_rock_domain(self, domain: str) -> Dict[str, Any]:
        """Hudson Rock infostealer lookup by domain."""
        if not _CLIENTS_AVAILABLE or HudsonRockClient is None:
            return _unavailable_response("hudson_rock", domain, "Hudson Rock client not available")

        async def _run():
            async with HudsonRockClient() as client:
                return await client.search_domain(domain)

        return _run_async(_run())

    # ------------------------------------------------------------------
    # Paste monitor methods
    # ------------------------------------------------------------------

    def paste_search_domain(self, domain: str, fetch_content: bool = False) -> Dict[str, Any]:
        """Paste site search for domain credential dumps."""
        if not _CLIENTS_AVAILABLE or PasteMonitor is None:
            return _unavailable_response("paste_monitor", domain, "Paste monitor not available")

        async def _run():
            async with PasteMonitor() as monitor:
                return await monitor.search_domain(domain, fetch_content=fetch_content)

        return _run_async(_run())

    def paste_search_email(self, email: str) -> Dict[str, Any]:
        """Paste site search for email mentions."""
        if not _CLIENTS_AVAILABLE or PasteMonitor is None:
            return _unavailable_response("paste_monitor", email, "Paste monitor not available")

        async def _run():
            async with PasteMonitor() as monitor:
                return await monitor.search_email(email)

        return _run_async(_run())

    # ------------------------------------------------------------------
    # Password analysis (sync, no external calls)
    # ------------------------------------------------------------------

    def analyze_passwords(self, passwords: List[str]) -> Dict[str, Any]:
        """Local password pattern and reuse analysis."""
        if not _CLIENTS_AVAILABLE:
            return {"error": "Credential intel clients not available", "passwords": passwords}

        # Import the analysis method from the MCP server module
        try:
            from app import CredentialIntelligence  # type: ignore
            ci = CredentialIntelligence()
            return ci.analyze_passwords(passwords)
        except ImportError:
            return {"error": "CredentialIntelligence not importable", "password_count": len(passwords)}

    # ------------------------------------------------------------------
    # Full exposure check (all sources concurrently)
    # ------------------------------------------------------------------

    def full_exposure_check(self, target: str, target_type: str = "email") -> Dict[str, Any]:
        """
        Comprehensive credential exposure check across all configured sources.

        target_type: "email" | "domain" | "username"
        """
        if not _CLIENTS_AVAILABLE:
            return {
                "error": "Credential intel clients not available",
                "target": target,
                "target_type": target_type,
            }

        try:
            from app import CredentialIntelligence  # type: ignore
        except ImportError:
            return {"error": "CredentialIntelligence module not importable", "target": target}

        async def _run():
            async with CredentialIntelligence() as intel:
                return await intel.full_exposure_check(target, target_type)

        return _run_async(_run())

    # ------------------------------------------------------------------
    # Service status
    # ------------------------------------------------------------------

    def get_source_status(self) -> Dict[str, Any]:
        """
        Return the availability status of each credential intelligence source.

        Returns::

            {
                "clients_available": bool,
                "sources": {
                    "hibp":        {"available": bool, "configured": bool, "api_key_set": bool},
                    "dehashed":    {"available": bool, "configured": bool},
                    "hudson_rock": {"available": bool, "configured": True, "note": "free"},
                    "paste":       {"available": bool, "configured": True, "note": "free"}
                }
            }
        """
        if not _CLIENTS_AVAILABLE:
            return {
                "clients_available": False,
                "sources": {
                    "hibp": {"available": False, "configured": False},
                    "dehashed": {"available": False, "configured": False},
                    "hudson_rock": {"available": False, "configured": False},
                    "paste": {"available": False, "configured": False},
                },
            }

        hibp_key = bool(os.getenv("HIBP_API_KEY"))
        dehashed_email = bool(os.getenv("DEHASHED_EMAIL"))
        dehashed_key = bool(os.getenv("DEHASHED_API_KEY"))

        return {
            "clients_available": True,
            "sources": {
                "hibp": {
                    "available": True,
                    "configured": hibp_key,
                    "api_key_set": hibp_key,
                    "note": "HIBP_API_KEY required for email/domain/paste checks; password check is free",
                },
                "dehashed": {
                    "available": True,
                    "configured": dehashed_email and dehashed_key,
                    "email_set": dehashed_email,
                    "key_set": dehashed_key,
                },
                "hudson_rock": {
                    "available": True,
                    "configured": True,
                    "note": "Free tier — no API key required",
                },
                "paste": {
                    "available": True,
                    "configured": True,
                    "note": "Free — psbdmp.ws, no API key required",
                },
            },
        }


# Module-level singleton
credential_intel_service = CredentialIntelService()
