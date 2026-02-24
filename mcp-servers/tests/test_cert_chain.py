"""
Unit tests for mcp-servers/infrastructure-advanced/cert_chain.py

All network and cryptography I/O is mocked so tests run completely offline.
"""
import sys
import os
import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

# Make the infrastructure-advanced package importable
sys.path.insert(
    0,
    os.path.join(os.path.dirname(__file__), "..", "infrastructure-advanced"),
)

from cert_chain import CertificateChainAnalyzer, _CRYPTOGRAPHY_AVAILABLE


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _days_from_now(days: int) -> datetime:
    return datetime.now(tz=timezone.utc) + timedelta(days=days)


def _build_mock_cert(
    cn_subject: str = "example.com",
    cn_issuer: str = "Let's Encrypt",
    days_until_expiry: int = 120,
    san_list: list | None = None,
    is_self_signed: bool = False,
    is_rsa: bool = True,
    key_size: int = 2048,
):
    """
    Build a minimal mock that quacks like a cryptography x509.Certificate.
    Only used when _CRYPTOGRAPHY_AVAILABLE is True.
    """
    if not _CRYPTOGRAPHY_AVAILABLE:
        return None  # skip construction if lib not installed

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID, ExtensionOID

    san_list = san_list or [cn_subject]

    # Subject / issuer names
    def _make_name(cn, org):
        return x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
        ])

    subject_name = _make_name(cn_subject, "Test Org")
    if is_self_signed:
        # Identical subject/issuer is required for is_self_signed to be True
        issuer_name = subject_name
    else:
        issuer_name = _make_name(cn_issuer, "Let's Encrypt Authority X3")

    # Validity window
    not_before = datetime.now(tz=timezone.utc) - timedelta(days=30)
    not_after = _days_from_now(days_until_expiry)

    # SANs extension
    san_ext = MagicMock()
    san_ext.value.get_values_for_type.return_value = [
        MagicMock(value=n) for n in san_list
    ]

    extensions = MagicMock()
    extensions.get_extension_for_oid.side_effect = (
        lambda oid: san_ext
        if oid == ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        else (_ for _ in ()).throw(x509.ExtensionNotFound("", oid))
    )

    # Public key
    pub_key = MagicMock(spec=rsa.RSAPublicKey)
    pub_key.key_size = key_size

    # Fingerprint — just return 32 zero bytes
    cert = MagicMock()
    cert.subject = subject_name
    cert.issuer = issuer_name
    cert.not_valid_before_utc = not_before
    cert.not_valid_after_utc = not_after
    cert.serial_number = 0xDEADBEEF
    cert.fingerprint.return_value = bytes(32)
    cert.signature_hash_algorithm.name = "sha256"
    cert.public_key.return_value = pub_key
    cert.extensions = extensions

    return cert


# ---------------------------------------------------------------------------
# Tests — expiry_alert()
# ---------------------------------------------------------------------------


def test_expiry_alert_critical_zero_days():
    alert = CertificateChainAnalyzer.expiry_alert(0)
    assert alert is not None
    assert alert["severity"] == "critical"


def test_expiry_alert_critical_negative_expired():
    alert = CertificateChainAnalyzer.expiry_alert(-5)
    assert alert["severity"] == "critical"
    assert "ago" in alert["message"]


def test_expiry_alert_high_15_days():
    alert = CertificateChainAnalyzer.expiry_alert(15)
    assert alert["severity"] == "high"


def test_expiry_alert_warning_60_days():
    alert = CertificateChainAnalyzer.expiry_alert(60)
    assert alert["severity"] == "warning"


def test_expiry_alert_none_120_days():
    alert = CertificateChainAnalyzer.expiry_alert(120)
    assert alert is None


def test_expiry_alert_boundary_6_days():
    """6 days → critical (< 7)."""
    alert = CertificateChainAnalyzer.expiry_alert(6)
    assert alert["severity"] == "critical"


def test_expiry_alert_boundary_7_days():
    """7 days → high (< 30 but >= 7)."""
    alert = CertificateChainAnalyzer.expiry_alert(7)
    assert alert["severity"] == "high"


def test_expiry_alert_boundary_29_days():
    """29 days → high (< 30)."""
    alert = CertificateChainAnalyzer.expiry_alert(29)
    assert alert["severity"] == "high"


def test_expiry_alert_boundary_30_days():
    """30 days → warning (>= 30, < 90)."""
    alert = CertificateChainAnalyzer.expiry_alert(30)
    assert alert["severity"] == "warning"


def test_expiry_alert_boundary_89_days():
    """89 days → warning (< 90)."""
    alert = CertificateChainAnalyzer.expiry_alert(89)
    assert alert["severity"] == "warning"


def test_expiry_alert_boundary_90_days():
    """90 days → None (>= 90)."""
    assert CertificateChainAnalyzer.expiry_alert(90) is None


# ---------------------------------------------------------------------------
# Tests — merge_san_lists()
# ---------------------------------------------------------------------------


def test_merge_san_lists_deduplicates():
    list_a = ["example.com", "www.example.com"]
    list_b = ["www.example.com", "api.example.com"]
    merged = CertificateChainAnalyzer.merge_san_lists(list_a, list_b)
    # No duplicates
    assert len(merged) == len(set(merged))
    assert "example.com" in merged
    assert "api.example.com" in merged


def test_merge_san_lists_sorts():
    list_a = ["z.example.com", "a.example.com"]
    merged = CertificateChainAnalyzer.merge_san_lists(list_a)
    assert merged == sorted(merged)


def test_merge_san_lists_strips_wildcard_dot_for_dedup():
    """*.example.com and example.com should be deduplicated."""
    merged = CertificateChainAnalyzer.merge_san_lists(
        ["*.example.com"], ["example.com"]
    )
    # One of them should survive (the wildcard variant or the bare domain)
    assert len(merged) == 1


def test_merge_san_lists_empty_inputs():
    assert CertificateChainAnalyzer.merge_san_lists([], []) == []


# ---------------------------------------------------------------------------
# Tests — fetch_live_cert() (mocked TLS)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
@pytest.mark.skipif(not _CRYPTOGRAPHY_AVAILABLE, reason="cryptography not installed")
async def test_fetch_live_cert_returns_expected_fields():
    """fetch_live_cert() should return the full structured dict when TLS works."""
    from cryptography import x509 as _x509

    mock_cert = _build_mock_cert("github.com", days_until_expiry=200, san_list=["github.com", "www.github.com"])
    fake_der = b"\x00" * 128  # dummy DER bytes

    with patch.object(
        CertificateChainAnalyzer, "_fetch_der_sync", return_value=fake_der
    ), patch.object(
        _x509, "load_der_x509_certificate", return_value=mock_cert
    ):
        result = await CertificateChainAnalyzer.fetch_live_cert("github.com")

    assert result["domain"] == "github.com"
    assert "subject" in result
    assert "issuer" in result
    assert "subject_alt_names" in result
    assert "days_until_expiry" in result
    assert "sha256_fingerprint" in result
    assert result["source"] == "live_tls"
    assert result.get("expiry_alert") is None  # 200 days → no alert


@pytest.mark.asyncio
@pytest.mark.skipif(not _CRYPTOGRAPHY_AVAILABLE, reason="cryptography not installed")
async def test_fetch_live_cert_expiry_alert_attached():
    """fetch_live_cert() should attach expiry_alert dict when cert expires soon."""
    from cryptography import x509 as _x509

    mock_cert = _build_mock_cert("expiring.com", days_until_expiry=5)
    fake_der = b"\x00" * 128

    with patch.object(
        CertificateChainAnalyzer, "_fetch_der_sync", return_value=fake_der
    ), patch.object(
        _x509, "load_der_x509_certificate", return_value=mock_cert
    ):
        result = await CertificateChainAnalyzer.fetch_live_cert("expiring.com")

    assert result["expiry_alert"] is not None
    assert result["expiry_alert"]["severity"] == "critical"


@pytest.mark.asyncio
@pytest.mark.skipif(not _CRYPTOGRAPHY_AVAILABLE, reason="cryptography not installed")
async def test_fetch_live_cert_self_signed_detected():
    """is_self_signed should be True when subject == issuer."""
    from cryptography import x509 as _x509

    mock_cert = _build_mock_cert("self.example.com", is_self_signed=True)
    fake_der = b"\x00" * 128

    with patch.object(
        CertificateChainAnalyzer, "_fetch_der_sync", return_value=fake_der
    ), patch.object(
        _x509, "load_der_x509_certificate", return_value=mock_cert
    ):
        result = await CertificateChainAnalyzer.fetch_live_cert("self.example.com")

    assert result["is_self_signed"] is True


@pytest.mark.asyncio
async def test_fetch_live_cert_tls_error_returns_error_dict():
    """A connection error should produce an error dict, not raise."""
    with patch.object(
        CertificateChainAnalyzer,
        "_fetch_der_sync",
        side_effect=ConnectionRefusedError("refused"),
    ):
        result = await CertificateChainAnalyzer.fetch_live_cert("unreachable.example.com")

    assert "error" in result
    assert result["domain"] == "unreachable.example.com"
    assert result["source"] == "live_tls"


@pytest.mark.asyncio
async def test_fetch_live_cert_cryptography_unavailable():
    """When the cryptography library is missing, return a graceful error dict."""
    with patch("cert_chain._CRYPTOGRAPHY_AVAILABLE", False):
        result = await CertificateChainAnalyzer.fetch_live_cert("example.com")

    assert "error" in result
    assert "cryptography" in result["error"].lower()
