"""
Credential Intelligence MCP Server
=====================================

Port: 8030

Multi-source credential and breach intelligence aggregator:

  Source 1 — HaveIBeenPwned Enterprise API (paid, HIBP_API_KEY)
    * Breached account check by email
    * Domain exposure report (all leaked emails for a domain)
    * Paste site monitoring via HIBP
    * k-anonymity password hash check (no API key needed)

  Source 2 — Dehashed (paid, DEHASHED_EMAIL + DEHASHED_API_KEY)
    * 15B+ record credential database
    * Search by email, domain, username, password, IP

  Source 3 — Hudson Rock Cavalier (free, no API key)
    * Infostealer malware victim database
    * Session cookie theft + password reuse detection

  Source 4 — Paste Site Monitor (free, no API key)
    * psbdmp.ws search for domain/email credential dumps
    * Pattern analysis to detect credential combo lists

MCP Methods
-----------
credentials/hibp_email           — HIBP breach check by email
credentials/hibp_domain          — HIBP domain exposure report
credentials/hibp_pastes          — HIBP paste check by email
credentials/hibp_password_pwned  — k-anonymity password check
credentials/dehashed_search      — Dehashed generic search
credentials/dehashed_email       — Dehashed email lookup
credentials/dehashed_domain      — Dehashed domain exposure
credentials/dehashed_username    — Dehashed username lookup
credentials/hudson_rock_email    — Hudson Rock email lookup
credentials/hudson_rock_domain   — Hudson Rock domain lookup
credentials/hudson_rock_username — Hudson Rock username lookup
credentials/paste_domain         — Paste site domain search
credentials/paste_email          — Paste site email search
credentials/analyze_passwords    — Password pattern + reuse analysis
credentials/full_exposure_check  — Comprehensive email/domain check across all sources
"""

from __future__ import annotations

import asyncio
import collections
import logging
import os
import re
from typing import Any, Dict, List, Optional

from hibp_client import HIBPClient
from dehashed_client import DehashedClient
from hudson_rock_client import HudsonRockClient
from paste_monitor import PasteMonitor

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# CredentialIntelligence — core class
# ---------------------------------------------------------------------------


class CredentialIntelligence:
    """
    Aggregate credential intelligence from multiple sources.

    This class manages all four source clients as async context managers.
    Call :meth:`open` and :meth:`close` (or use as an async context manager).
    """

    def __init__(self):
        self._hibp: Optional[HIBPClient] = None
        self._dehashed: Optional[DehashedClient] = None
        self._hudson: Optional[HudsonRockClient] = None
        self._paste: Optional[PasteMonitor] = None

    async def __aenter__(self) -> "CredentialIntelligence":
        self._hibp = HIBPClient()
        self._dehashed = DehashedClient()
        self._hudson = HudsonRockClient()
        self._paste = PasteMonitor()
        await self._hibp.__aenter__()
        await self._dehashed.__aenter__()
        await self._hudson.__aenter__()
        await self._paste.__aenter__()
        return self

    async def __aexit__(self, *args: Any) -> None:
        for client in (self._hibp, self._dehashed, self._hudson, self._paste):
            try:
                if client:
                    await client.__aexit__(None, None, None)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # HIBP methods
    # ------------------------------------------------------------------

    async def hibp_email(self, email: str) -> Dict[str, Any]:
        """HIBP breach check for an email address."""
        return await self._hibp.check_email(email)

    async def hibp_domain(self, domain: str) -> Dict[str, Any]:
        """HIBP domain exposure report."""
        return await self._hibp.check_domain(domain)

    async def hibp_pastes(self, email: str) -> Dict[str, Any]:
        """HIBP paste check for an email address."""
        return await self._hibp.check_pastes(email)

    async def hibp_password_pwned(self, password: str) -> Dict[str, Any]:
        """k-anonymity password check via HIBP Passwords API."""
        return await self._hibp.check_password_pwned(password)

    # ------------------------------------------------------------------
    # Dehashed methods
    # ------------------------------------------------------------------

    async def dehashed_search(self, query: str, size: int = 10) -> Dict[str, Any]:
        """Generic Dehashed search (field-qualified query string)."""
        return await self._dehashed.search(query, size=size)

    async def dehashed_email(self, email: str, size: int = 10) -> Dict[str, Any]:
        """Dehashed search by email."""
        return await self._dehashed.search_email(email, size=size)

    async def dehashed_domain(self, domain: str, size: int = 20) -> Dict[str, Any]:
        """Dehashed domain exposure — all leaked credentials for @domain emails."""
        return await self._dehashed.search_domain(domain, size=size)

    async def dehashed_username(self, username: str, size: int = 10) -> Dict[str, Any]:
        """Dehashed search by username."""
        return await self._dehashed.search_username(username, size=size)

    # ------------------------------------------------------------------
    # Hudson Rock methods
    # ------------------------------------------------------------------

    async def hudson_rock_email(self, email: str) -> Dict[str, Any]:
        """Hudson Rock infostealer lookup by email."""
        return await self._hudson.search_email(email)

    async def hudson_rock_domain(self, domain: str) -> Dict[str, Any]:
        """Hudson Rock infostealer lookup by domain."""
        return await self._hudson.search_domain(domain)

    async def hudson_rock_username(self, username: str) -> Dict[str, Any]:
        """Hudson Rock infostealer lookup by username."""
        return await self._hudson.search_username(username)

    # ------------------------------------------------------------------
    # Paste monitor methods
    # ------------------------------------------------------------------

    async def paste_domain(self, domain: str, fetch_content: bool = False) -> Dict[str, Any]:
        """Paste site search for domain-related credential dumps."""
        return await self._paste.search_domain(domain, fetch_content=fetch_content)

    async def paste_email(self, email: str) -> Dict[str, Any]:
        """Paste site search for email-related dumps."""
        return await self._paste.search_email(email)

    # ------------------------------------------------------------------
    # Password pattern analysis (no external calls)
    # ------------------------------------------------------------------

    def analyze_passwords(self, passwords: List[str]) -> Dict[str, Any]:
        """
        Analyse a list of plaintext passwords for patterns and reuse indicators.

        This is a purely local analysis — no external calls are made.

        Returns::

            {
                "password_count": int,
                "patterns": [
                    {
                        "password": str,
                        "base_word": str | None,
                        "year": str | None,
                        "has_special_char": bool,
                        "has_leet_speak": bool,
                        "length": int,
                        "char_classes": int,
                        "complexity_score": float,
                        "fingerprint": str
                    }, ...
                ],
                "reuse_indicators": [
                    {
                        "base_word": str,
                        "passwords": [str, ...],
                        "reuse_likely": bool
                    }, ...
                ],
                "unique_base_words": int,
                "most_common_year": str | None,
                "most_common_base_word": str | None,
                "high_confidence_reuse": bool
            }
        """
        if not passwords:
            return {
                "password_count": 0,
                "patterns": [],
                "reuse_indicators": [],
                "unique_base_words": 0,
                "most_common_year": None,
                "most_common_base_word": None,
                "high_confidence_reuse": False,
            }

        patterns = [self._analyse_single_password(p) for p in passwords]

        # Group by base word
        base_groups: Dict[str, List[str]] = collections.defaultdict(list)
        year_counter: collections.Counter = collections.Counter()

        for pattern in patterns:
            bw = pattern.get("base_word")
            if bw:
                base_groups[bw].append(pattern["password"])
            yr = pattern.get("year")
            if yr:
                year_counter[yr] += 1

        reuse_indicators = [
            {
                "base_word": word,
                "passwords": pwds,
                "reuse_likely": len(pwds) > 1,
            }
            for word, pwds in base_groups.items()
        ]

        most_common_year = year_counter.most_common(1)[0][0] if year_counter else None
        most_common_base = max(base_groups, key=lambda k: len(base_groups[k]),
                               default=None) if base_groups else None
        high_confidence_reuse = any(
            len(v) >= 3 for v in base_groups.values()
        )

        return {
            "password_count": len(passwords),
            "patterns": patterns,
            "reuse_indicators": reuse_indicators,
            "unique_base_words": len(base_groups),
            "most_common_year": most_common_year,
            "most_common_base_word": most_common_base,
            "high_confidence_reuse": high_confidence_reuse,
        }

    # ------------------------------------------------------------------
    # Full exposure check (orchestrates all sources)
    # ------------------------------------------------------------------

    async def full_exposure_check(
        self,
        target: str,
        target_type: str = "email",
    ) -> Dict[str, Any]:
        """
        Run a comprehensive credential exposure check across all configured sources.

        Parameters
        ----------
        target:
            The email address, domain, or username to investigate.
        target_type:
            One of ``"email"``, ``"domain"``, or ``"username"``.

        All sources are queried concurrently.  Sources that are not configured
        (missing API keys) return graceful error dicts rather than raising.

        Returns::

            {
                "target": str,
                "target_type": str,
                "risk_level": "critical" | "high" | "medium" | "low" | "none",
                "risk_score": float,        // 0.0–100.0
                "summary": {
                    "total_breach_count": int,
                    "total_paste_count": int,
                    "infostealer_found": bool,
                    "dehashed_entries": int,
                    "has_plaintext_passwords": bool,
                    "password_pwned": bool | None  // only for email with HIBP
                },
                "sources": {
                    "hibp":        {...},
                    "dehashed":    {...},
                    "hudson_rock": {...},
                    "paste":       {...}
                }
            }
        """
        if target_type == "email":
            tasks = {
                "hibp":        self.hibp_email(target),
                "dehashed":    self.dehashed_email(target),
                "hudson_rock": self.hudson_rock_email(target),
                "paste":       self.paste_email(target),
            }
        elif target_type == "domain":
            tasks = {
                "hibp":        self.hibp_domain(target),
                "dehashed":    self.dehashed_domain(target),
                "hudson_rock": self.hudson_rock_domain(target),
                "paste":       self.paste_domain(target),
            }
        elif target_type == "username":
            tasks = {
                "dehashed":    self.dehashed_username(target),
                "hudson_rock": self.hudson_rock_username(target),
                "hibp":        {"note": "HIBP does not support username lookups"},
                "paste":       self.paste_email(target),  # username often appears in pastes
            }
        else:
            return {"error": f"Unknown target_type: {target_type!r}", "target": target}

        # Run all tasks concurrently (with individual error isolation)
        results: Dict[str, Any] = {}
        coros = {k: v for k, v in tasks.items() if asyncio.iscoroutine(v)}
        plain = {k: v for k, v in tasks.items() if not asyncio.iscoroutine(v)}

        gathered = await asyncio.gather(*coros.values(), return_exceptions=True)
        for key, result in zip(coros.keys(), gathered):
            results[key] = result if not isinstance(result, Exception) else {"error": str(result)}
        results.update(plain)

        summary = self._build_summary(results, target_type)
        risk_score, risk_level = self._compute_risk(summary)

        return {
            "target": target,
            "target_type": target_type,
            "risk_level": risk_level,
            "risk_score": round(risk_score, 1),
            "summary": summary,
            "sources": results,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    _LEET_MAP = str.maketrans("013456789", "oieasgtbg")
    _YEAR_RE = re.compile(r"(19\d{2}|20\d{2})")
    _SPECIAL_RE = re.compile(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>/?\\|`~]")
    _LEET_CHARS = set("013456789@$!")

    @classmethod
    def _analyse_single_password(cls, password: str) -> Dict[str, Any]:
        """Analyse a single password and return its pattern dict."""
        base_word = cls._extract_base_word(password)
        year_match = cls._YEAR_RE.search(password)
        year = year_match.group(0) if year_match else None
        has_special = bool(cls._SPECIAL_RE.search(password))
        has_leet = any(c in cls._LEET_CHARS for c in password)

        # Count char classes: uppercase, lowercase, digit, special
        classes = sum([
            bool(re.search(r"[A-Z]", password)),
            bool(re.search(r"[a-z]", password)),
            bool(re.search(r"\d", password)),
            has_special,
        ])

        # Simple complexity score 0–100
        length_score = min(len(password) / 20.0, 1.0) * 40
        class_score = (classes / 4.0) * 40
        no_common_word_score = 20 if not base_word else 0
        complexity = length_score + class_score + no_common_word_score

        # Fingerprint: preserve structure, mask chars
        fingerprint = re.sub(r"[a-zA-Z]", "A", password)
        fingerprint = re.sub(r"\d", "0", fingerprint)

        return {
            "password": password,
            "base_word": base_word,
            "year": year,
            "has_special_char": has_special,
            "has_leet_speak": has_leet,
            "length": len(password),
            "char_classes": classes,
            "complexity_score": round(complexity, 1),
            "fingerprint": fingerprint,
        }

    @classmethod
    def _extract_base_word(cls, password: str) -> Optional[str]:
        """
        Extract the 'base word' from a password.

        e.g. Dragon2019! → "dragon"
             P@ssw0rd → "password" (after leet reversal)
        """
        # Apply leet reversal
        de_leet = password.lower().translate(cls._LEET_MAP)
        # Strip leading/trailing non-alpha
        letters_only = re.sub(r"[^a-z]", " ", de_leet).split()
        # Filter: at least 3 chars, not a year
        words = [w for w in letters_only if len(w) >= 3 and not re.fullmatch(r"(19|20)\d{2}", w)]
        if not words:
            return None
        # Return longest word as most likely the base
        return max(words, key=len)

    @staticmethod
    def _build_summary(results: Dict[str, Any], target_type: str) -> Dict[str, Any]:
        """Build a cross-source summary from individual source results."""
        hibp = results.get("hibp", {})
        dehashed = results.get("dehashed", {})
        hudson = results.get("hudson_rock", {})
        paste = results.get("paste", {})

        breach_count = hibp.get("breach_count", 0) if isinstance(hibp, dict) else 0
        paste_count = (hibp.get("paste_count", 0) if isinstance(hibp, dict) else 0) + \
                      (paste.get("paste_count", 0) if isinstance(paste, dict) else 0)

        dehashed_entries = dehashed.get("total", 0) if isinstance(dehashed, dict) else 0
        infostealer_found = hudson.get("found", False) if isinstance(hudson, dict) else False

        # Check if any Dehashed entry has a plaintext password
        has_plain_pwd = any(
            e.get("password") for e in (dehashed.get("entries") or [])
        ) if isinstance(dehashed, dict) else False

        # Check HIBP data classes for plaintext passwords
        dcs = hibp.get("data_classes_exposed", []) if isinstance(hibp, dict) else []
        has_plain_pwd = has_plain_pwd or "Passwords" in dcs

        return {
            "total_breach_count": breach_count,
            "total_paste_count": paste_count,
            "infostealer_found": infostealer_found,
            "dehashed_entries": dehashed_entries,
            "has_plaintext_passwords": has_plain_pwd,
            "password_pwned": hibp.get("has_password_exposure") if isinstance(hibp, dict) else None,
        }

    @staticmethod
    def _compute_risk(summary: Dict[str, Any]) -> tuple[float, str]:
        """Compute a risk score (0–100) and level from a summary dict."""
        score = 0.0
        bc = summary.get("total_breach_count", 0)
        pc = summary.get("total_paste_count", 0)
        is_found = summary.get("infostealer_found", False)
        de = summary.get("dehashed_entries", 0)
        has_pwd = summary.get("has_plaintext_passwords", False)

        # Breach count (up to 30 pts)
        score += min(bc * 5, 30)
        # Paste count (up to 20 pts)
        score += min(pc * 4, 20)
        # Infostealer (30 pts — highest signal)
        if is_found:
            score += 30
        # Dehashed entries (up to 10 pts)
        score += min(de * 0.5, 10)
        # Plaintext passwords (10 pts bonus)
        if has_pwd:
            score += 10

        score = min(score, 100.0)

        if score >= 70:
            level = "critical"
        elif score >= 40:
            level = "high"
        elif score >= 15:
            level = "medium"
        elif score > 0:
            level = "low"
        else:
            level = "none"

        return score, level


# ---------------------------------------------------------------------------
# CredentialIntelMCPServer — MCP protocol handler
# ---------------------------------------------------------------------------


class CredentialIntelMCPServer:
    def __init__(self):
        self.intel: Optional[CredentialIntelligence] = None

    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP protocol requests."""
        method = request.get("method")
        params = request.get("params", {})

        if not self.intel:
            self.intel = CredentialIntelligence()
            await self.intel.__aenter__()

        handlers = {
            "credentials/hibp_email":           lambda **kw: self.intel.hibp_email(**kw),
            "credentials/hibp_domain":          lambda **kw: self.intel.hibp_domain(**kw),
            "credentials/hibp_pastes":          lambda **kw: self.intel.hibp_pastes(**kw),
            "credentials/hibp_password_pwned":  lambda **kw: self.intel.hibp_password_pwned(**kw),
            "credentials/dehashed_search":      lambda **kw: self.intel.dehashed_search(**kw),
            "credentials/dehashed_email":       lambda **kw: self.intel.dehashed_email(**kw),
            "credentials/dehashed_domain":      lambda **kw: self.intel.dehashed_domain(**kw),
            "credentials/dehashed_username":    lambda **kw: self.intel.dehashed_username(**kw),
            "credentials/hudson_rock_email":    lambda **kw: self.intel.hudson_rock_email(**kw),
            "credentials/hudson_rock_domain":   lambda **kw: self.intel.hudson_rock_domain(**kw),
            "credentials/hudson_rock_username": lambda **kw: self.intel.hudson_rock_username(**kw),
            "credentials/paste_domain":         lambda **kw: self.intel.paste_domain(**kw),
            "credentials/paste_email":          lambda **kw: self.intel.paste_email(**kw),
            "credentials/analyze_passwords":    lambda **kw: self.intel.analyze_passwords(**kw),
            "credentials/full_exposure_check":  lambda **kw: self.intel.full_exposure_check(**kw),
        }

        handler = handlers.get(method)
        if handler:
            try:
                result = await handler(**params) if asyncio.iscoroutinefunction(handler) \
                    else await asyncio.get_event_loop().run_in_executor(None, lambda: handler(**params))
                # analyze_passwords is sync — handle both paths
                return {"success": True, "data": result}
            except Exception as exc:
                logger.exception("CredentialIntelMCPServer.handle_request error: %s", exc)
                return {"success": False, "error": str(exc)}

        return {"success": False, "error": f"Unknown method: {method}"}

    async def get_capabilities(self) -> Dict[str, Any]:
        """Return server capabilities."""
        return {
            "name": "Credential Intelligence",
            "version": "1.0.0",
            "description": (
                "Multi-source credential and breach intelligence: HIBP, Dehashed, "
                "Hudson Rock (infostealer), paste site monitoring"
            ),
            "port": 8030,
            "methods": [
                {
                    "name": "credentials/hibp_email",
                    "description": "HIBP breach check for email (requires HIBP_API_KEY)",
                    "params": ["email"],
                },
                {
                    "name": "credentials/hibp_domain",
                    "description": "HIBP domain exposure report (requires HIBP Enterprise API key)",
                    "params": ["domain"],
                },
                {
                    "name": "credentials/hibp_pastes",
                    "description": "HIBP paste site check for email (requires HIBP_API_KEY)",
                    "params": ["email"],
                },
                {
                    "name": "credentials/hibp_password_pwned",
                    "description": "k-anonymity password check via HIBP Passwords API (no key needed)",
                    "params": ["password"],
                },
                {
                    "name": "credentials/dehashed_search",
                    "description": "Dehashed field-qualified search (requires DEHASHED_EMAIL + DEHASHED_API_KEY)",
                    "params": ["query", "size"],
                },
                {
                    "name": "credentials/dehashed_email",
                    "description": "Dehashed lookup by email address",
                    "params": ["email", "size"],
                },
                {
                    "name": "credentials/dehashed_domain",
                    "description": "Dehashed domain exposure — all leaked credentials for @domain emails",
                    "params": ["domain", "size"],
                },
                {
                    "name": "credentials/dehashed_username",
                    "description": "Dehashed lookup by username",
                    "params": ["username", "size"],
                },
                {
                    "name": "credentials/hudson_rock_email",
                    "description": "Hudson Rock infostealer check by email (free, no API key)",
                    "params": ["email"],
                },
                {
                    "name": "credentials/hudson_rock_domain",
                    "description": "Hudson Rock infostealer check by domain (free, no API key)",
                    "params": ["domain"],
                },
                {
                    "name": "credentials/hudson_rock_username",
                    "description": "Hudson Rock infostealer check by username (free, no API key)",
                    "params": ["username"],
                },
                {
                    "name": "credentials/paste_domain",
                    "description": "Paste site credential dump search for domain (free)",
                    "params": ["domain", "fetch_content"],
                },
                {
                    "name": "credentials/paste_email",
                    "description": "Paste site credential dump search for email (free)",
                    "params": ["email"],
                },
                {
                    "name": "credentials/analyze_passwords",
                    "description": "Local password pattern + reuse analysis (no external calls)",
                    "params": ["passwords"],
                },
                {
                    "name": "credentials/full_exposure_check",
                    "description": "Comprehensive credential exposure check across all sources",
                    "params": ["target", "target_type"],
                },
            ],
            "required_api_keys": [
                "HIBP_API_KEY (required for HIBP email/domain/paste checks)",
                "DEHASHED_EMAIL (required for Dehashed searches)",
                "DEHASHED_API_KEY (required for Dehashed searches)",
            ],
            "free_sources": [
                "Hudson Rock Cavalier (no API key)",
                "psbdmp.ws paste monitor (no API key)",
                "HIBP Passwords k-anonymity (no API key)",
            ],
        }


# ---------------------------------------------------------------------------
# FastAPI application
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import uvicorn
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse

    app = FastAPI(
        title="Credential Intelligence MCP Server",
        description="Multi-source credential breach intelligence",
        version="1.0.0",
    )

    mcp_server = CredentialIntelMCPServer()

    @app.get("/")
    async def root():
        return {
            "message": "Credential Intelligence MCP Server",
            "version": "1.0.0",
            "status": "running",
        }

    @app.get("/health")
    async def health():
        return {"status": "healthy", "service": "credential-intel-mcp"}

    @app.get("/capabilities")
    async def get_capabilities():
        return await mcp_server.get_capabilities()

    @app.post("/mcp")
    async def handle_mcp_request(request: dict):
        try:
            return await mcp_server.handle_request(request)
        except Exception as exc:
            raise HTTPException(status_code=500, detail=str(exc))

    # Individual direct-access endpoints

    @app.post("/credentials/hibp/email")
    async def hibp_email(request: dict):
        email = request.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="'email' required")
        async with CredentialIntelligence() as intel:
            return {"success": True, "data": await intel.hibp_email(email)}

    @app.post("/credentials/hibp/domain")
    async def hibp_domain(request: dict):
        domain = request.get("domain")
        if not domain:
            raise HTTPException(status_code=400, detail="'domain' required")
        async with CredentialIntelligence() as intel:
            return {"success": True, "data": await intel.hibp_domain(domain)}

    @app.post("/credentials/hibp/pastes")
    async def hibp_pastes(request: dict):
        email = request.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="'email' required")
        async with CredentialIntelligence() as intel:
            return {"success": True, "data": await intel.hibp_pastes(email)}

    @app.post("/credentials/hibp/password")
    async def hibp_password(request: dict):
        password = request.get("password")
        if not password:
            raise HTTPException(status_code=400, detail="'password' required")
        async with CredentialIntelligence() as intel:
            return {"success": True, "data": await intel.hibp_password_pwned(password)}

    @app.post("/credentials/dehashed/search")
    async def dehashed_search(request: dict):
        query = request.get("query")
        if not query:
            raise HTTPException(status_code=400, detail="'query' required")
        size = request.get("size", 10)
        async with CredentialIntelligence() as intel:
            return {"success": True, "data": await intel.dehashed_search(query, size=size)}

    @app.post("/credentials/dehashed/domain")
    async def dehashed_domain(request: dict):
        domain = request.get("domain")
        if not domain:
            raise HTTPException(status_code=400, detail="'domain' required")
        async with CredentialIntelligence() as intel:
            return {"success": True, "data": await intel.dehashed_domain(domain)}

    @app.post("/credentials/hudson-rock/email")
    async def hudson_rock_email(request: dict):
        email = request.get("email")
        if not email:
            raise HTTPException(status_code=400, detail="'email' required")
        async with CredentialIntelligence() as intel:
            return {"success": True, "data": await intel.hudson_rock_email(email)}

    @app.post("/credentials/hudson-rock/domain")
    async def hudson_rock_domain(request: dict):
        domain = request.get("domain")
        if not domain:
            raise HTTPException(status_code=400, detail="'domain' required")
        async with CredentialIntelligence() as intel:
            return {"success": True, "data": await intel.hudson_rock_domain(domain)}

    @app.post("/credentials/paste/domain")
    async def paste_domain(request: dict):
        domain = request.get("domain")
        if not domain:
            raise HTTPException(status_code=400, detail="'domain' required")
        fetch_content = request.get("fetch_content", False)
        async with CredentialIntelligence() as intel:
            return {"success": True, "data": await intel.paste_domain(domain, fetch_content=fetch_content)}

    @app.post("/credentials/analyze/passwords")
    async def analyze_passwords(request: dict):
        passwords = request.get("passwords", [])
        if not isinstance(passwords, list):
            raise HTTPException(status_code=400, detail="'passwords' must be a list")
        intel = CredentialIntelligence()
        return {"success": True, "data": intel.analyze_passwords(passwords)}

    @app.post("/credentials/full-exposure-check")
    async def full_exposure_check(request: dict):
        target = request.get("target")
        if not target:
            raise HTTPException(status_code=400, detail="'target' required")
        target_type = request.get("target_type", "email")
        async with CredentialIntelligence() as intel:
            return {"success": True, "data": await intel.full_exposure_check(target, target_type)}

    print("Starting Credential Intelligence MCP Server on port 8030...")
    uvicorn.run(app, host="0.0.0.0", port=8030)
