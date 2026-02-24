"""
CIRCL.lu Passive DNS client — free, no API key required.

API documentation: https://www.circl.lu/services/passive-dns/
Endpoint: GET https://www.circl.lu/pdns/query/{rrname}
Response: newline-delimited JSON objects (one per line).

Record fields returned by CIRCL:
  rrname      - queried name
  rrtype      - DNS record type (A, AAAA, MX, NS, CNAME, ...)
  rdata       - resolved value
  time_first  - Unix epoch of first observed resolution
  time_last   - Unix epoch of most recent observed resolution
  count       - number of observations
"""
import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import aiohttp

logger = logging.getLogger(__name__)

_CIRCL_BASE = "https://www.circl.lu/pdns/query"
_USER_AGENT = "Enterprise-OSINT-Platform/2.0 (+https://github.com/daringanitch/Enterprise-OSINT-Platform)"


class CIRCLPassiveDNS:
    """Async CIRCL passive DNS client.

    Usage (inside an async context):
        async with CIRCLPassiveDNS() as client:
            result = await client.query("example.com")
    """

    def __init__(self, timeout: int = 15):
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self._session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self._session = aiohttp.ClientSession(
            timeout=self.timeout,
            headers={"User-Agent": _USER_AGENT, "Accept": "application/json"},
        )
        return self

    async def __aexit__(self, *args):
        if self._session:
            await self._session.close()
            self._session = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def query(self, name: str) -> Dict[str, Any]:
        """Query forward or reverse DNS history for *name*.

        Works for both domain names (forward) and IP addresses (reverse).

        Returns::

            {
              'query': str,
              'records': [
                {
                  'rrname': str,
                  'rdata': str,
                  'rrtype': str,        # 'A', 'AAAA', 'MX', ...
                  'time_first': str,    # ISO-8601
                  'time_last': str,     # ISO-8601
                  'count': int
                }, ...
              ],
              'unique_ips': [str, ...],        # rdata values for A/AAAA records
              'unique_domains': [str, ...],    # rdata values for CNAME/PTR etc.
              'record_count': int,
              'source': 'circl_pdns'
            }
        """
        if self._session is None:
            raise RuntimeError("CIRCLPassiveDNS must be used as an async context manager")

        url = f"{_CIRCL_BASE}/{name}"
        try:
            async with self._session.get(url, ssl=True) as resp:
                if resp.status == 404:
                    return self._empty_result(name)
                if resp.status != 200:
                    logger.warning("CIRCL pDNS returned HTTP %s for %s", resp.status, name)
                    return self._empty_result(name)

                raw_text = await resp.text()
        except aiohttp.ClientError as exc:
            logger.warning("CIRCL pDNS request failed for %s: %s", name, exc)
            return self._empty_result(name)

        records = self._parse_ndjson(raw_text)
        return self._build_result(name, records)

    async def build_timeline(self, domain: str) -> List[Dict[str, Any]]:
        """Return A/AAAA resolutions sorted chronologically (oldest first).

        Each entry::

            {'ip': str, 'first_seen': str (ISO), 'last_seen': str (ISO), 'count': int}
        """
        result = await self.query(domain)
        timeline: List[Dict[str, Any]] = []

        for rec in result["records"]:
            if rec["rrtype"] not in ("A", "AAAA"):
                continue
            timeline.append(
                {
                    "ip": rec["rdata"],
                    "first_seen": rec["time_first"],
                    "last_seen": rec["time_last"],
                    "count": rec["count"],
                }
            )

        # Sort by first_seen ascending so callers see oldest → newest
        timeline.sort(key=lambda x: x["first_seen"])
        return timeline

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_ndjson(text: str) -> List[Dict[str, Any]]:
        """Parse newline-delimited JSON; silently skip malformed lines."""
        records = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError:
                logger.debug("CIRCL pDNS: skipping malformed line: %.80s", line)
        return records

    @staticmethod
    def _epoch_to_iso(epoch) -> str:
        """Convert Unix epoch (int or float or str) to ISO-8601 UTC string."""
        try:
            ts = float(epoch)
            return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OSError):
            return str(epoch)

    def _build_result(self, query: str, raw_records: List[Dict]) -> Dict[str, Any]:
        normalised: List[Dict[str, Any]] = []
        unique_ips: set = set()
        unique_domains: set = set()

        for rec in raw_records:
            rrtype = rec.get("rrtype", "").upper()
            rdata = str(rec.get("rdata", "")).strip().rstrip(".")
            if not rdata:
                continue

            norm = {
                "rrname": str(rec.get("rrname", query)).rstrip("."),
                "rdata": rdata,
                "rrtype": rrtype,
                "time_first": self._epoch_to_iso(rec.get("time_first", 0)),
                "time_last": self._epoch_to_iso(rec.get("time_last", 0)),
                "count": int(rec.get("count", 0)),
            }
            normalised.append(norm)

            if rrtype in ("A", "AAAA"):
                unique_ips.add(rdata)
            elif rrtype in ("CNAME", "NS", "MX", "PTR"):
                unique_domains.add(rdata)

        return {
            "query": query,
            "records": normalised,
            "unique_ips": sorted(unique_ips),
            "unique_domains": sorted(unique_domains),
            "record_count": len(normalised),
            "source": "circl_pdns",
        }

    @staticmethod
    def _empty_result(query: str) -> Dict[str, Any]:
        return {
            "query": query,
            "records": [],
            "unique_ips": [],
            "unique_domains": [],
            "record_count": 0,
            "source": "circl_pdns",
        }
