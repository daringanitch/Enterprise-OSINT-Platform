"""
TLS certificate chain analyser.

Uses the `cryptography` library to parse X.509 certificates fetched via a
live SSL handshake.  Falls back gracefully when the host is unreachable or
when the `cryptography` package is not installed.

Example::

    info = await CertificateChainAnalyzer.fetch_live_cert("github.com")
    alert = CertificateChainAnalyzer.expiry_alert(info["days_until_expiry"])
"""
import asyncio
import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional dependency: cryptography library
# ---------------------------------------------------------------------------
try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa
    from cryptography.x509.oid import ExtensionOID, NameOID
    _CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover
    _CRYPTOGRAPHY_AVAILABLE = False
    logger.warning(
        "cert_chain: 'cryptography' package not installed — "
        "live certificate analysis disabled.  Install with: pip install cryptography"
    )


class CertificateChainAnalyzer:
    """Static-method helper for TLS certificate inspection."""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    async def fetch_live_cert(domain: str, port: int = 443, timeout: float = 10.0) -> Dict[str, Any]:
        """Connect to *domain*:*port*, perform TLS handshake, and return
        a dictionary of parsed certificate fields.

        Returns::

            {
              'domain': str,
              'subject': {'CN': str, 'O': str, ...},
              'issuer': {'CN': str, 'O': str, ...},
              'subject_alt_names': [str, ...],   # all SAN DNS entries
              'not_before': str,                 # ISO-8601 UTC
              'not_after': str,                  # ISO-8601 UTC
              'days_until_expiry': int,           # negative = already expired
              'serial_number': str,               # hex
              'sha256_fingerprint': str,          # colon-separated hex pairs
              'signature_algorithm': str,
              'public_key_type': str,             # 'RSA', 'EC', 'DSA', ...
              'public_key_bits': int,
              'is_self_signed': bool,
              'is_ev': bool,                      # Extended Validation heuristic
              'expiry_alert': dict | None,        # see expiry_alert()
              'source': 'live_tls'
            }

        On error returns a dict with an 'error' key instead.
        """
        if not _CRYPTOGRAPHY_AVAILABLE:
            return {
                "domain": domain,
                "error": "cryptography package not installed",
                "source": "live_tls",
            }

        loop = asyncio.get_event_loop()
        try:
            der_bytes = await loop.run_in_executor(
                None,
                lambda: CertificateChainAnalyzer._fetch_der_sync(domain, port, timeout),
            )
        except Exception as exc:
            logger.warning("cert_chain: TLS connect failed for %s:%s — %s", domain, port, exc)
            return {"domain": domain, "error": str(exc), "source": "live_tls"}

        return CertificateChainAnalyzer._parse_der(domain, der_bytes)

    @staticmethod
    def expiry_alert(days: int) -> Optional[Dict[str, Any]]:
        """Return a severity dict if the cert expires within 90 days, else *None*.

        Severity levels:

        * ``critical`` — expires in < 7 days (or already expired)
        * ``high``     — expires in < 30 days
        * ``warning``  — expires in < 90 days
        """
        if days < 7:
            level = "critical"
            msg = f"Certificate expires in {days} days" if days >= 0 else f"Certificate expired {-days} days ago"
        elif days < 30:
            level = "high"
            msg = f"Certificate expires in {days} days"
        elif days < 90:
            level = "warning"
            msg = f"Certificate expires in {days} days"
        else:
            return None

        return {"severity": level, "days_until_expiry": days, "message": msg}

    @staticmethod
    def merge_san_lists(*san_lists: List[str]) -> List[str]:
        """Deduplicate and sort SAN lists from multiple sources (CT logs + live cert)."""
        seen: set = set()
        merged: List[str] = []
        for lst in san_lists:
            for name in lst:
                normalised = name.lower().lstrip("*.")
                if normalised and normalised not in seen:
                    seen.add(normalised)
                    merged.append(name.lower())
        return sorted(merged)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _fetch_der_sync(domain: str, port: int, timeout: float) -> bytes:
        """Blocking TLS connect — intended to run in an executor."""
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        with socket.create_connection((domain, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                return ssock.getpeercert(binary_form=True)

    @staticmethod
    def _parse_der(domain: str, der_bytes: bytes) -> Dict[str, Any]:
        """Parse raw DER certificate bytes using the cryptography library."""
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
        except Exception as exc:
            return {"domain": domain, "error": f"DER parse failed: {exc}", "source": "live_tls"}

        # Subject and issuer as plain dicts
        subject = CertificateChainAnalyzer._name_to_dict(cert.subject)
        issuer = CertificateChainAnalyzer._name_to_dict(cert.issuer)

        # Subject Alternative Names
        san_list: List[str] = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = [str(n.value) for n in san_ext.value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            pass

        # Validity window
        not_before = cert.not_valid_before_utc if hasattr(cert, "not_valid_before_utc") else cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after  = cert.not_valid_after_utc  if hasattr(cert, "not_valid_after_utc")  else cert.not_valid_after.replace(tzinfo=timezone.utc)
        now = datetime.now(tz=timezone.utc)
        days_left = (not_after - now).days

        # Fingerprint
        fp_bytes = cert.fingerprint(hashes.SHA256())
        fp_hex = ":".join(f"{b:02X}" for b in fp_bytes)

        # Signature algorithm
        try:
            sig_alg = cert.signature_algorithm_oid.dotted_string
            # Try to get a human-readable name
            sig_alg = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else sig_alg
        except Exception:
            sig_alg = "unknown"

        # Public key info
        pub_key = cert.public_key()
        pk_type = type(pub_key).__name__.replace("_", " ").replace("PublicKey", "").strip()
        pk_bits = 0
        try:
            if isinstance(pub_key, rsa.RSAPublicKey):
                pk_type = "RSA"
                pk_bits = pub_key.key_size
            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                pk_type = "EC"
                pk_bits = pub_key.key_size
            elif isinstance(pub_key, dsa.DSAPublicKey):
                pk_type = "DSA"
                pk_bits = pub_key.key_size
        except Exception:
            pass

        is_self_signed = subject == issuer
        is_ev = CertificateChainAnalyzer._is_ev(cert)

        result: Dict[str, Any] = {
            "domain": domain,
            "subject": subject,
            "issuer": issuer,
            "subject_alt_names": san_list,
            "not_before": not_before.isoformat(),
            "not_after": not_after.isoformat(),
            "days_until_expiry": days_left,
            "serial_number": format(cert.serial_number, "X"),
            "sha256_fingerprint": fp_hex,
            "signature_algorithm": sig_alg,
            "public_key_type": pk_type,
            "public_key_bits": pk_bits,
            "is_self_signed": is_self_signed,
            "is_ev": is_ev,
            "expiry_alert": CertificateChainAnalyzer.expiry_alert(days_left),
            "source": "live_tls",
        }
        return result

    @staticmethod
    def _name_to_dict(name: "x509.Name") -> Dict[str, str]:
        """Convert an x509.Name to a plain string dict keyed by short OID name."""
        oid_map = {
            NameOID.COMMON_NAME:             "CN",
            NameOID.ORGANIZATION_NAME:       "O",
            NameOID.ORGANIZATIONAL_UNIT_NAME:"OU",
            NameOID.COUNTRY_NAME:            "C",
            NameOID.STATE_OR_PROVINCE_NAME:  "ST",
            NameOID.LOCALITY_NAME:           "L",
        }
        result: Dict[str, str] = {}
        for attr in name:
            key = oid_map.get(attr.oid, attr.oid.dotted_string)
            result[key] = attr.value
        return result

    @staticmethod
    def _is_ev(cert: "x509.Certificate") -> bool:
        """Heuristic check: Certificate Policies extension contains a known EV OID prefix."""
        _EV_OID_PREFIXES = (
            "2.23.140.1.1",   # CA/Browser Forum EV
            "1.3.6.1.4.1.",   # many CA-specific EV OIDs share this prefix
        )
        try:
            cp_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CERTIFICATE_POLICIES)
            for policy in cp_ext.value:
                dotted = policy.policy_identifier.dotted_string
                if any(dotted.startswith(p) for p in _EV_OID_PREFIXES):
                    return True
        except (x509.ExtensionNotFound, Exception):
            pass
        return False
