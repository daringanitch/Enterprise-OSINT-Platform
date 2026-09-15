#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Local GeoIP resolution backed by a MaxMind GeoLite2 City database.

Lookups are answered in-process from an .mmdb file on disk. No network
request is made, so investigation target IPs never leave this host — the
reason this replaced the previous plaintext `http://ip-api.com` call, which
disclosed every target to a third party over an unencrypted connection.

There is deliberately no network fallback. If the database is missing or
unreadable, lookups report themselves unavailable rather than silently
reintroducing the egress this module exists to remove.

The database is not redistributable and is not committed to this repo. It
is downloaded at image build time (see the Dockerfile) or mounted at
GEOIP_DB_PATH. Refresh it periodically; MaxMind publishes updates weekly.
"""

import ipaddress
import logging
import os
import threading
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = '/app/geoip/GeoLite2-City.mmdb'

try:
    import geoip2.database
    import geoip2.errors
    _GEOIP2_AVAILABLE = True
except ImportError:  # pragma: no cover - exercised only in stripped envs
    _GEOIP2_AVAILABLE = False
    logger.warning(
        "geoip2 not installed — GeoIP lookups will report unavailable. "
        "Install with: pip install geoip2"
    )


class LocalGeoIP:
    """Thread-safe reader over a GeoLite2 City database.

    The reader is opened lazily on first use and held open; maxminddb
    readers are safe for concurrent reads and memory-map the file, so
    keeping one open is cheaper than reopening per lookup.
    """

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or os.getenv('GEOIP_DB_PATH', DEFAULT_DB_PATH)
        self._reader = None
        self._lock = threading.Lock()
        self._unavailable_reason = None

    def _get_reader(self):
        """Open the database once, caching both success and failure."""
        if self._reader is not None or self._unavailable_reason is not None:
            return self._reader

        with self._lock:
            # Re-check inside the lock; another thread may have just opened it.
            if self._reader is not None or self._unavailable_reason is not None:
                return self._reader

            if not _GEOIP2_AVAILABLE:
                self._unavailable_reason = 'geoip2 library not installed'
                return None

            if not os.path.exists(self.db_path):
                self._unavailable_reason = f'database not found at {self.db_path}'
                logger.warning(
                    "GeoIP database missing at %s — lookups will report "
                    "unavailable. No network fallback is attempted by design.",
                    self.db_path,
                )
                return None

            try:
                self._reader = geoip2.database.Reader(self.db_path)
                logger.info("GeoIP database loaded from %s", self.db_path)
            except Exception as exc:
                self._unavailable_reason = f'failed to open database: {exc}'
                logger.error("Could not open GeoIP database %s: %s", self.db_path, exc)

            return self._reader

    @property
    def available(self) -> bool:
        """True when lookups can actually resolve."""
        return self._get_reader() is not None

    def lookup(self, ip: str) -> Dict[str, Any]:
        """Resolve an IP to a location.

        Always returns a dict carrying an `available` flag. Callers should
        check it rather than assuming the geographic fields are present:
        private addresses and IPs absent from the database are normal
        outcomes, not errors.
        """
        result: Dict[str, Any] = {
            'ip': ip,
            'available': False,
            'source': 'maxmind-geolite2-local',
        }

        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            result['error'] = 'not a valid IP address'
            return result

        # GeoLite2 has no data for these, and asking is not an error.
        if parsed.is_private or parsed.is_loopback or parsed.is_reserved:
            result['error'] = 'private or reserved address'
            return result

        reader = self._get_reader()
        if reader is None:
            result['error'] = self._unavailable_reason or 'database unavailable'
            return result

        try:
            response = reader.city(ip)
        except geoip2.errors.AddressNotFoundError:
            result['error'] = 'address not present in database'
            return result
        except Exception as exc:
            logger.error("GeoIP lookup failed for %s: %s", ip, exc)
            result['error'] = f'lookup failed: {exc}'
            return result

        result.update({
            'available': True,
            # 'countryCode' is the key the backend's compliance scope
            # derivation reads; keep it stable.
            'countryCode': response.country.iso_code,
            'country': response.country.name,
            'city': response.city.name,
            'region': response.subdivisions.most_specific.name,
            'regionCode': response.subdivisions.most_specific.iso_code,
            'postalCode': response.postal.code,
            'latitude': response.location.latitude,
            'longitude': response.location.longitude,
            'accuracyRadiusKm': response.location.accuracy_radius,
            'timezone': response.location.time_zone,
        })
        return result

    def close(self):
        """Release the database handle."""
        with self._lock:
            if self._reader is not None:
                self._reader.close()
                self._reader = None


# Module-level instance; the reader inside it is opened on first lookup.
_default_client = None
_default_lock = threading.Lock()


def get_client() -> LocalGeoIP:
    """Return the shared LocalGeoIP client."""
    global _default_client
    if _default_client is None:
        with _default_lock:
            if _default_client is None:
                _default_client = LocalGeoIP()
    return _default_client


def lookup(ip: str) -> Dict[str, Any]:
    """Convenience wrapper over the shared client."""
    return get_client().lookup(ip)
