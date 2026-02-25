"""
Credential Intelligence Blueprint
===================================

REST endpoints for leaked credential intelligence.

Endpoints
---------
GET  /api/credentials/status
    Source availability + API key configuration status.

POST /api/credentials/check/email
    Full credential exposure check for an email address.
    Queries HIBP breaches, HIBP pastes, Dehashed, Hudson Rock, paste sites.

POST /api/credentials/check/domain
    Full credential exposure check for a domain.
    Returns all exposed email addresses and infostealer victims.

POST /api/credentials/check/password
    k-anonymity password breach check via HIBP Passwords API.
    Never sends the full password — uses SHA-1 k-anonymity model.

POST /api/credentials/analyze/passwords
    Local password pattern and reuse analysis.
    No external API calls. Useful for analysing leaked credential dumps.

GET  /api/investigations/<inv_id>/credentials/exposure
    Run credential exposure checks for all email addresses and domains
    found in an existing investigation's correlation data.
"""

import logging
from flask import Blueprint, jsonify, request

from blueprints.auth import require_auth
from credential_intel_service import credential_intel_service

logger = logging.getLogger(__name__)
bp = Blueprint("credentials", __name__)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@bp.route("/api/credentials/status", methods=["GET"])
@require_auth
def credential_sources_status():
    """
    Return the availability and configuration status of each credential source.

    Returns::

        {
            "clients_available": bool,
            "sources": {
                "hibp":        {...},
                "dehashed":    {...},
                "hudson_rock": {...},
                "paste":       {...}
            }
        }
    """
    return jsonify(credential_intel_service.get_source_status())


@bp.route("/api/credentials/check/email", methods=["POST"])
@require_auth
def check_email():
    """
    Full credential exposure check for an email address.

    Request body::

        {
            "email": "user@example.com",
            "sources": ["hibp", "dehashed", "hudson_rock", "paste"]  // optional, default all
        }

    Returns::

        {
            "email": str,
            "risk_level": str,
            "risk_score": float,
            "hibp_breaches": {...},
            "hibp_pastes": {...},
            "dehashed": {...},
            "hudson_rock": {...},
            "paste": {...},
            "summary": {...}
        }
    """
    body = request.get_json(silent=True) or {}
    email = body.get("email", "").strip()

    if not email or "@" not in email:
        return jsonify({"error": "Valid 'email' address required"}), 400

    requested_sources = set(body.get("sources") or ["hibp", "dehashed", "hudson_rock", "paste"])

    logger.info("Credential check: email=%s sources=%s", email, requested_sources)

    results: dict = {"email": email}

    if "hibp" in requested_sources:
        results["hibp_breaches"] = credential_intel_service.check_email_breaches(email)
        results["hibp_pastes"] = credential_intel_service.check_email_pastes(email)
    if "dehashed" in requested_sources:
        results["dehashed"] = credential_intel_service.dehashed_email(email)
    if "hudson_rock" in requested_sources:
        results["hudson_rock"] = credential_intel_service.hudson_rock_email(email)
    if "paste" in requested_sources:
        results["paste"] = credential_intel_service.paste_search_email(email)

    # Build summary + risk score
    summary = _build_email_summary(results)
    results["summary"] = summary
    results["risk_level"] = summary["risk_level"]
    results["risk_score"] = summary["risk_score"]

    return jsonify(results)


@bp.route("/api/credentials/check/domain", methods=["POST"])
@require_auth
def check_domain():
    """
    Full credential exposure check for a domain.

    Request body::

        {
            "domain": "example.com",
            "sources": ["hibp", "dehashed", "hudson_rock", "paste"]  // optional
        }

    Returns::

        {
            "domain": str,
            "risk_level": str,
            "risk_score": float,
            "hibp_domain": {...},       // all exposed emails per HIBP
            "dehashed_domain": {...},   // all leaked credentials from @domain
            "hudson_rock_domain": {...},// infostealer victims
            "paste_domain": {...},      // paste credential dumps
            "summary": {...}
        }
    """
    body = request.get_json(silent=True) or {}
    domain = body.get("domain", "").strip().lower().lstrip("@")

    if not domain or "." not in domain:
        return jsonify({"error": "Valid 'domain' required (e.g. 'example.com')"}), 400

    requested_sources = set(body.get("sources") or ["hibp", "dehashed", "hudson_rock", "paste"])

    logger.info("Credential check: domain=%s sources=%s", domain, requested_sources)

    results: dict = {"domain": domain}

    if "hibp" in requested_sources:
        results["hibp_domain"] = credential_intel_service.check_domain_exposure(domain)
    if "dehashed" in requested_sources:
        results["dehashed_domain"] = credential_intel_service.dehashed_domain(domain)
    if "hudson_rock" in requested_sources:
        results["hudson_rock_domain"] = credential_intel_service.hudson_rock_domain(domain)
    if "paste" in requested_sources:
        results["paste_domain"] = credential_intel_service.paste_search_domain(domain)

    summary = _build_domain_summary(results)
    results["summary"] = summary
    results["risk_level"] = summary["risk_level"]
    results["risk_score"] = summary["risk_score"]

    return jsonify(results)


@bp.route("/api/credentials/check/password", methods=["POST"])
@require_auth
def check_password():
    """
    Check if a password has appeared in known data breaches.

    Uses HIBP's k-anonymity model — only the first 5 characters of the
    SHA-1 hash are sent to HIBP.  The full password never leaves the server.

    Request body::

        {"password": "Dragon2019!"}

    Returns::

        {
            "is_pwned": bool,
            "pwned_count": int,       // number of times seen in breaches
            "password_sha1_prefix": str,  // first 5 chars of SHA-1 (for audit)
            "source": "hibp_passwords"
        }
    """
    body = request.get_json(silent=True) or {}
    password = body.get("password", "")

    if not password:
        return jsonify({"error": "'password' is required"}), 400
    if len(password) > 512:
        return jsonify({"error": "Password too long (max 512 chars)"}), 400

    result = credential_intel_service.check_password_pwned(password)
    return jsonify(result)


@bp.route("/api/credentials/analyze/passwords", methods=["POST"])
@require_auth
def analyze_passwords():
    """
    Analyse a list of plaintext passwords for patterns and reuse indicators.

    This is a purely local analysis — no external API calls are made.
    Useful for analysing a dump of leaked credentials to fingerprint a
    threat actor's password habits.

    Request body::

        {
            "passwords": ["Dragon2019!", "Dragon2018!", "dragon!123"],
            "source": "optional_label"   // for audit purposes
        }

    Returns::

        {
            "password_count": int,
            "patterns": [...],
            "reuse_indicators": [...],
            "unique_base_words": int,
            "most_common_year": str | null,
            "most_common_base_word": str | null,
            "high_confidence_reuse": bool
        }
    """
    body = request.get_json(silent=True) or {}
    passwords = body.get("passwords", [])

    if not isinstance(passwords, list):
        return jsonify({"error": "'passwords' must be a list"}), 400
    if len(passwords) > 10_000:
        return jsonify({"error": "Maximum 10,000 passwords per request"}), 400

    source = body.get("source", "api")
    logger.info("Password pattern analysis: count=%d source=%s", len(passwords), source)

    result = credential_intel_service.analyze_passwords(passwords)
    return jsonify(result)


@bp.route("/api/investigations/<inv_id>/credentials/exposure", methods=["GET"])
@require_auth
def investigation_credential_exposure(inv_id: str):
    """
    Run credential exposure checks for entities found in an investigation.

    Extracts all email addresses and domains from the investigation's
    correlation data, then runs exposure checks across all configured sources.

    Returns::

        {
            "investigation_id": str,
            "emails_checked": [str, ...],
            "domains_checked": [str, ...],
            "email_results": {email: {...}, ...},
            "domain_results": {domain: {...}, ...},
            "highest_risk": {"target": str, "risk_level": str, "risk_score": float},
            "overall_risk_level": str
        }
    """
    from shared import services  # local import to avoid circular deps

    investigation = None
    try:
        investigation = services.get_investigation(inv_id)
    except Exception:
        pass

    if investigation is None:
        return jsonify({"error": f"Investigation '{inv_id}' not found"}), 404

    # Extract email addresses and domains from the investigation
    emails, domains = _extract_targets_from_investigation(investigation)

    if not emails and not domains:
        return jsonify({
            "investigation_id": inv_id,
            "emails_checked": [],
            "domains_checked": [],
            "email_results": {},
            "domain_results": {},
            "highest_risk": None,
            "overall_risk_level": "none",
            "note": "No email addresses or domains found in investigation entities",
        })

    logger.info(
        "Investigation credential exposure: id=%s emails=%d domains=%d",
        inv_id, len(emails), len(domains),
    )

    # Run checks — limit to 10 emails and 5 domains to avoid excessive API usage
    email_results = {}
    for email in list(emails)[:10]:
        email_results[email] = credential_intel_service.full_exposure_check(email, "email")

    domain_results = {}
    for domain in list(domains)[:5]:
        domain_results[domain] = credential_intel_service.full_exposure_check(domain, "domain")

    # Find highest risk target
    all_risks = [
        {"target": t, "risk_level": r.get("risk_level", "none"), "risk_score": r.get("risk_score", 0.0)}
        for results_dict in (email_results, domain_results)
        for t, r in results_dict.items()
        if isinstance(r, dict)
    ]
    highest = max(all_risks, key=lambda x: x["risk_score"]) if all_risks else None

    # Overall risk = highest individual risk
    _risk_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}
    overall = max(
        (r["risk_level"] for r in all_risks),
        key=lambda x: _risk_order.get(x, 0),
        default="none",
    )

    return jsonify({
        "investigation_id": inv_id,
        "emails_checked": list(emails)[:10],
        "domains_checked": list(domains)[:5],
        "email_results": email_results,
        "domain_results": domain_results,
        "highest_risk": highest,
        "overall_risk_level": overall,
    })


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_email_summary(results: dict) -> dict:
    """Build a risk summary from multi-source email results."""
    breach_count = 0
    paste_count = 0
    infostealer = False
    dehashed_entries = 0
    has_plain_pwd = False

    hibp = results.get("hibp_breaches", {})
    if isinstance(hibp, dict):
        breach_count = hibp.get("breach_count", 0)
        has_plain_pwd = hibp.get("has_password_exposure", False)

    hibp_paste = results.get("hibp_pastes", {})
    if isinstance(hibp_paste, dict):
        paste_count += hibp_paste.get("paste_count", 0)

    paste = results.get("paste", {})
    if isinstance(paste, dict):
        paste_count += paste.get("paste_count", 0)

    hudson = results.get("hudson_rock", {})
    if isinstance(hudson, dict):
        infostealer = hudson.get("found", False)

    dh = results.get("dehashed", {})
    if isinstance(dh, dict):
        dehashed_entries = dh.get("total", 0)
        has_plain_pwd = has_plain_pwd or any(
            e.get("password") for e in (dh.get("entries") or [])
        )

    score = 0.0
    score += min(breach_count * 5, 30)
    score += min(paste_count * 4, 20)
    score += 30 if infostealer else 0
    score += min(dehashed_entries * 0.5, 10)
    score += 10 if has_plain_pwd else 0
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

    return {
        "total_breach_count": breach_count,
        "total_paste_count": paste_count,
        "infostealer_found": infostealer,
        "dehashed_entries": dehashed_entries,
        "has_plaintext_passwords": has_plain_pwd,
        "risk_score": round(score, 1),
        "risk_level": level,
    }


def _build_domain_summary(results: dict) -> dict:
    """Build a risk summary from multi-source domain results."""
    exposed_emails = 0
    infostealer_employees = 0
    dehashed_entries = 0
    paste_count = 0

    hibp = results.get("hibp_domain", {})
    if isinstance(hibp, dict):
        exposed_emails += hibp.get("email_count", 0)

    hudson = results.get("hudson_rock_domain", {})
    if isinstance(hudson, dict):
        infostealer_employees = hudson.get("employee_count", 0)

    dh = results.get("dehashed_domain", {})
    if isinstance(dh, dict):
        dehashed_entries = dh.get("total", 0)

    paste = results.get("paste_domain", {})
    if isinstance(paste, dict):
        paste_count = paste.get("paste_count", 0)

    score = 0.0
    score += min(exposed_emails * 2, 25)
    score += min(infostealer_employees * 5, 35)
    score += min(dehashed_entries * 0.3, 20)
    score += min(paste_count * 3, 20)
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

    return {
        "hibp_exposed_emails": exposed_emails,
        "infostealer_employees": infostealer_employees,
        "dehashed_entries": dehashed_entries,
        "paste_count": paste_count,
        "risk_score": round(score, 1),
        "risk_level": level,
    }


def _extract_targets_from_investigation(investigation) -> tuple[set, set]:
    """Extract email addresses and domains from an investigation."""
    from intelligence_correlation import EntityType

    emails: set = set()
    domains: set = set()

    inv_dict = investigation if isinstance(investigation, dict) else getattr(investigation, "__dict__", {})

    # Try to get entities from correlation result if available
    raw_entities = inv_dict.get("entities") or {}
    for entity_id, entity in (raw_entities.items() if isinstance(raw_entities, dict) else []):
        entity_type = (
            entity.get("type") if isinstance(entity, dict)
            else getattr(getattr(entity, "entity_type", None), "value", None)
        )
        value = (
            entity.get("value") if isinstance(entity, dict)
            else getattr(entity, "value", None)
        )
        if not value:
            continue
        if entity_type == EntityType.EMAIL.value:
            emails.add(value.lower())
        elif entity_type == EntityType.DOMAIN.value:
            domains.add(value.lower())

    # Also check target profile
    target = inv_dict.get("target_profile") or {}
    if isinstance(target, dict):
        primary = target.get("primary_identifier", "")
        if primary and "@" in primary:
            emails.add(primary.lower())
        elif primary and "." in primary and "@" not in primary:
            domains.add(primary.lower().lstrip("www.").lstrip("."))

    return emails, domains
