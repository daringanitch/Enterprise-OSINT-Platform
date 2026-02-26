# Enterprise OSINT Platform - API Reference

Complete API documentation for the Enterprise OSINT Platform REST API and MCP server endpoints.

## Table of Contents
1. [Authentication](#authentication)
2. [Investigation Management](#investigation-management)
3. [Pivot Suggestions](#pivot-suggestions)
4. [Threat Actor Dossiers](#threat-actor-dossiers)
5. [Cross-Investigation Correlation](#cross-investigation-correlation)
6. [Investigation Templates](#investigation-templates)
7. [Analytic Tradecraft](#analytic-tradecraft)
8. [Real-Time Monitoring](#real-time-monitoring)
9. [Credential Intelligence](#credential-intelligence)
10. [NLP Intelligence](#nlp-intelligence)
11. [Service Settings](#service-settings)
12. [STIX/MISP Export](#stixmisp-export)
13. [System Status](#system-status)
14. [Graph Intelligence](#graph-intelligence)
15. [MCP Server APIs](#mcp-server-apis)
16. [Error Handling](#error-handling)
17. [Rate Limiting](#rate-limiting)

---

## Authentication

The API uses JWT (JSON Web Token) authentication. All protected endpoints require a valid JWT token in the Authorization header.

### Login
**POST** `/api/auth/login`

Authenticate user and receive access token.

**Request Body:**
```json
{
    "username": "admin",
    "password": "admin123"
}
```

**Response:**
```json
{
    "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "message": "Login successful",
    "user": {
        "user_id": "admin",
        "username": "admin",
        "role": "admin",
        "clearance_level": "confidential"
    }
}
```

**Status Codes:**
- `200` - Login successful
- `401` - Invalid credentials
- `400` - Missing username or password

### Logout
**POST** `/api/auth/logout`

Invalidate current session (client-side token removal).

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
    "message": "Logged out successfully"
}
```

---

## Investigation Management

### List Investigations
**GET** `/api/investigations`

Retrieve list of investigations for the authenticated user.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Query Parameters:**
- `status` (optional): Filter by status (`planning`, `collecting`, `analyzing`, `completed`)
- `limit` (optional): Number of results to return (default: 20)
- `offset` (optional): Pagination offset (default: 0)

**Response:**
```json
{
    "investigations": [
        {
            "id": "605ba974-9a88-4921-855e-c9dbedc2b3d8",
            "target": "example.com",
            "investigation_type": "comprehensive",
            "status": "completed",
            "progress": {
                "overall_progress": 1.0,
                "stage": "completed",
                "current_activity": "Investigation completed"
            },
            "created_at": "2025-08-16T10:30:00Z",
            "completed_at": "2025-08-16T10:45:00Z",
            "risk_assessment": {
                "overall_risk_score": 45,
                "confidence_level": 0.85
            }
        }
    ],
    "total": 1,
    "has_more": false
}
```

### Create Investigation
**POST** `/api/investigations`

Start a new OSINT investigation.

**Headers:**
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body:**
```json
{
    "target": "example.com",
    "investigation_type": "comprehensive",
    "priority": "high",
    "scope": {
        "include_infrastructure": true,
        "include_social_media": true,
        "include_threat_intelligence": true,
        "include_financial": false,
        "max_investigation_hours": 24
    }
}
```

**Request Parameters:**
- `target` (required): Target domain, IP, or organization
- `investigation_type` (required): `comprehensive`, `infrastructure`, `threat`, `social`
- `priority` (optional): `low`, `medium`, `high` (default: `medium`)
- `scope` (optional): Investigation scope configuration

**Response:**
```json
{
    "id": "605ba974-9a88-4921-855e-c9dbedc2b3d8",
    "status": "planning",
    "message": "OSINT investigation started successfully",
    "api_status": {
        "available_apis": {
            "infrastructure": 1,
            "social_media": 1,
            "threat_intelligence": 1,
            "ai_analyzer": 1
        },
        "total_apis": 4
    },
    "progress": {
        "overall_progress": 0.1,
        "stage": "planning",
        "current_activity": "Validating investigation parameters"
    }
}
```

### Get Investigation Details
**GET** `/api/investigations/{id}`

Retrieve complete investigation details including all collected intelligence.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
    "id": "605ba974-9a88-4921-855e-c9dbedc2b3d8",
    "target": "example.com",
    "investigation_type": "comprehensive",
    "status": "completed",
    "progress": {
        "overall_progress": 1.0,
        "stage": "completed",
        "stage_details": {
            "planning": {"status": "completed", "progress": 1.0},
            "profiling": {"status": "completed", "progress": 1.0},
            "collecting": {"status": "completed", "progress": 1.0},
            "analyzing": {"status": "completed", "progress": 1.0},
            "verifying": {"status": "completed", "progress": 1.0},
            "risk_assessment": {"status": "completed", "progress": 1.0},
            "report_generation": {"status": "completed", "progress": 1.0}
        }
    },
    "intelligence": {
        "infrastructure": {
            "domains": [
                {
                    "domain": "example.com",
                    "registrar": "GoDaddy.com, LLC",
                    "creation_date": "2017-12-22",
                    "expiration_date": "2027-12-22",
                    "nameservers": ["ns1.example.com", "ns2.example.com"],
                    "status": "active"
                }
            ],
            "dns_records": {
                "A": ["192.0.2.1"],
                "MX": ["10 mail.example.com"],
                "TXT": ["v=spf1 include:_spf.google.com ~all"]
            },
            "ssl_certificates": [
                {
                    "subject": "CN=example.com",
                    "issuer": "Let's Encrypt Authority X3",
                    "valid_from": "2025-06-01",
                    "valid_to": "2025-09-01",
                    "serial_number": "03a...",
                    "fingerprint": "SHA256:abc123..."
                }
            ]
        },
        "threat_intelligence": {
            "reputation_scores": {
                "VirusTotal": 0,
                "AbuseIPDB": 0,
                "Shodan": 15
            },
            "risk_indicators": [],
            "threat_categories": []
        },
        "ai_analysis": {
            "threat_assessment": {
                "risk_level": "LOW",
                "confidence": 0.85,
                "key_findings": [
                    "Domain has legitimate registration history",
                    "No malicious indicators found in reputation checks",
                    "Standard web hosting configuration"
                ]
            }
        }
    },
    "risk_assessment": {
        "overall_risk_score": 25,
        "confidence_level": 0.85,
        "risk_factors": [
            {
                "category": "Infrastructure",
                "score": 20,
                "description": "Standard hosting configuration with minor exposure"
            }
        ]
    },
    "compliance_assessments": [
        {
            "framework": "GDPR",
            "status": "compliant",
            "assessment_score": 95,
            "recommendations": []
        }
    ],
    "timestamps": {
        "created_at": "2025-08-16T10:30:00Z",
        "started_at": "2025-08-16T10:30:05Z",
        "completed_at": "2025-08-16T10:45:00Z"
    }
}
```

### Generate Investigation Report
**GET** `/api/investigations/{id}/report`

Generate and download a professional PDF report for the investigation.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Query Parameters:**
- `format` (optional): `pdf` (default), `json`, `csv`
- `include_executive_summary` (optional): `true` (default), `false`
- `include_technical_details` (optional): `true` (default), `false`

**Response:**
- Content-Type: `application/pdf` (for PDF format)
- Content-Disposition: `attachment; filename="investigation_report_605ba974.pdf"`

**Status Codes:**
- `200` - Report generated successfully
- `404` - Investigation not found
- `202` - Report generation in progress (retry after delay)

### Delete Investigation
**DELETE** `/api/investigations/{id}`

Delete an investigation and all associated data.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
    "message": "Investigation deleted successfully",
    "deleted_id": "605ba974-9a88-4921-855e-c9dbedc2b3d8"
}
```

---

---

## Pivot Suggestions

Ranked next-pivot recommendations for investigation entities, scored across 5 weighted signals.

### Get Pivot Suggestions
**GET** `/api/investigations/{investigation_id}/pivots`

Returns ranked pivot suggestions for all entities in an investigation.

**Query Parameters:**
- `max` (integer, optional) — Maximum suggestions to return (default: 10)

**Response:**
```json
{
    "investigation_id": "inv-001",
    "target": "evil.example.com",
    "suggestions": [
        {
            "entity_value": "185.220.101.47",
            "entity_type": "ip",
            "pivot_type": "check_reputation",
            "score": 0.87,
            "reason": "High-abuse IP with threat flag — verify across AbuseIPDB, Shodan, VirusTotal",
            "suggested_tools": ["abuseipdb", "shodan", "virustotal"]
        }
    ],
    "coverage_score": 0.72,
    "total_entities_analysed": 8
}
```

**Status Codes:**
- `200` - Success
- `404` - Investigation not found
- `401` - Unauthorized

### Dismiss a Pivot Suggestion
**POST** `/api/investigations/{investigation_id}/pivots/dismiss`

Mark a suggestion as dismissed so it won't recur.

**Request Body:**
```json
{
    "entity_value": "185.220.101.47",
    "pivot_type": "check_reputation"
}
```

### Explain Pivot Scoring
**GET** `/api/pivots/explain`

Returns the scoring weight documentation.

---

## Threat Actor Dossiers

Library of 26 nation-state and criminal actor dossiers with full MITRE ATT&CK mappings.

### List Threat Actors
**GET** `/api/threat-actors`

**Query Parameters:**
- `q` — Full-text search (name, alias, description)
- `sector` — Filter by targeted sector (e.g. `financial`, `government`)
- `technique` — Filter by MITRE ATT&CK technique ID (e.g. `T1566.001`)
- `type` — Filter by actor type (`nation-state`, `criminal`, `hacktivist`)
- `motivation` — Filter by motivation (`espionage`, `financial`, `disruption`)

**Response:**
```json
{
    "actors": [
        {
            "actor_id": "apt28",
            "name": "APT28",
            "actor_type": "nation-state",
            "motivation": "espionage",
            "aliases": ["Fancy Bear", "STRONTIUM", "Forest Blizzard"],
            "origin_country": "RU",
            "confidence": "high"
        }
    ],
    "total": 26
}
```

### Get Actor Dossier
**GET** `/api/threat-actors/{actor_id}`

Returns full dossier including MITRE techniques, tools, infrastructure patterns, and references.

### Match Actors by TTPs
**POST** `/api/threat-actors/match`

Rank actors by TTP overlap with a provided technique list.

**Request Body:**
```json
{
    "techniques": ["T1566.001", "T1071.001", "T1027"],
    "top_n": 5
}
```

**Response:**
```json
{
    "matches": [
        {
            "actor_id": "apt28",
            "name": "APT28",
            "match_score": 0.92,
            "matched_techniques": ["T1566.001", "T1071.001"],
            "total_actor_techniques": 13
        }
    ]
}
```

### Fingerprint Investigation
**POST** `/api/threat-actors/fingerprint`

Auto-extract MITRE techniques from an investigation and return ranked actor candidates.

**Request Body:**
```json
{
    "investigation_id": "inv-001"
}
```

---

## Cross-Investigation Correlation

Detect shared indicators (domains, IPs, emails, certificates, ASNs) across all investigations.

### Full Platform Scan
**GET** `/api/correlations`

Scan all investigations for shared indicators.

**Response:**
```json
{
    "shared_indicators": [
        {
            "indicator_value": "185.220.101.47",
            "indicator_type": "ip",
            "investigation_ids": ["inv-001", "inv-003"],
            "significance": "high",
            "significance_reason": "IP shared directly across investigations"
        }
    ],
    "investigation_links": [
        {
            "investigation_a": "inv-001",
            "investigation_b": "inv-003",
            "link_strength": 0.6,
            "shared_indicators": [...]
        }
    ],
    "shared_indicator_count": 3,
    "investigation_link_count": 2
}
```

### Links for Investigation
**GET** `/api/investigations/{investigation_id}/correlations`

Returns all cross-investigation links involving this investigation.

### Indicator Lookup
**GET** `/api/correlations/indicators/{indicator_value}`

Find all investigations containing a specific indicator value.

---

## Investigation Templates

6 analyst-ready templates with pre-seeded ACH hypotheses, watchlist seeds, and MITRE technique recommendations.

### List Templates
**GET** `/api/templates`

**Query Parameters:**
- `category` — Filter by category (`attribution`, `financial`, `infrastructure`, `hr`)

**Response:**
```json
{
    "templates": [
        {
            "template_id": "apt_attribution",
            "name": "APT Attribution",
            "description": "Full infrastructure and TTP analysis for nation-state attribution.",
            "category": "attribution",
            "ach_hypotheses_count": 4,
            "watchlist_seeds_count": 2,
            "recommended_techniques": ["T1566.001", "T1071.001", "T1027"]
        }
    ],
    "total": 6
}
```

**Available templates:** `apt_attribution`, `ransomware_profiling`, `phishing_infrastructure`, `ma_due_diligence`, `insider_threat`, `vulnerability_exposure`

### Get Template Detail
**GET** `/api/templates/{template_id}`

Returns full template with watchlist seeds, ACH hypotheses, key questions, and analyst guidance.

### List Categories
**GET** `/api/templates/categories`

### Apply Template
**POST** `/api/templates/{template_id}/apply`

Apply a template to a new investigation. Returns pre-populated scope, watchlist seeds, and ACH hypotheses with optional target resolution.

**Request Body:**
```json
{
    "target": "evil-domain.example.com",
    "target_type": "domain",
    "analyst_notes": "SOC ticket #1234 — suspected phishing infrastructure"
}
```

**Response:**
```json
{
    "template_id": "apt_attribution",
    "name": "APT Attribution",
    "scope": {
        "include_infrastructure": true,
        "include_threat_intelligence": true,
        "historical_data_days": 180,
        "max_threat_indicators": 1200,
        "primary_target": "evil-domain.example.com"
    },
    "watchlist_seeds": [...],
    "ach_hypotheses": [
        {
            "title": "Nation-state actor (known APT group)",
            "description": "...",
            "hypothesis_type": "primary"
        }
    ],
    "recommended_techniques": ["T1566.001", "T1071.001", ...],
    "key_questions": [...],
    "analyst_guidance": "Start with infrastructure pivots..."
}
```


## Analytic Tradecraft

Intelligence Community structured analytic techniques endpoints.

### Get Reference Scales
**GET** `/api/tradecraft/scales`

Retrieve NATO/Admiralty source reliability and information credibility scales.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
    "source_reliability": {
        "A": "Completely Reliable",
        "B": "Usually Reliable",
        "C": "Fairly Reliable",
        "D": "Not Usually Reliable",
        "E": "Unreliable",
        "F": "Cannot Be Judged"
    },
    "information_credibility": {
        "1": "Confirmed",
        "2": "Probably True",
        "3": "Possibly True",
        "4": "Doubtful",
        "5": "Improbable",
        "6": "Cannot Be Judged"
    },
    "confidence_levels": ["High", "Moderate", "Low"],
    "wep_scale": ["Almost Certain", "Likely", "Possible", "Unlikely", "Remote"]
}
```

### Create Intel Item
**POST** `/api/tradecraft/investigations/{id}/items`

Add a rated intelligence item to investigation.

**Headers:**
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body:**
```json
{
    "source": "HUMINT - Field Agent",
    "source_reliability": "B",
    "information": "Target registered domain 6 months ago",
    "credibility": "2",
    "collection_date": "2025-02-20T10:30:00Z"
}
```

**Response:**
```json
{
    "item_id": "item-uuid",
    "investigation_id": "inv-uuid",
    "rating": "B/2",
    "status": "collected",
    "timestamp": "2025-02-26T16:45:30Z"
}
```

### Create Hypothesis
**POST** `/api/tradecraft/investigations/{id}/hypotheses`

Add a hypothesis for analysis.

**Request Body:**
```json
{
    "hypothesis": "Target is conducting credential phishing campaign",
    "description": "Evidence suggests malicious intent based on infrastructure patterns",
    "confidence_initial": "Possible"
}
```

**Response:**
```json
{
    "hypothesis_id": "hyp-uuid",
    "hypothesis": "Target is conducting credential phishing campaign",
    "ach_evidence_count": 0,
    "status": "active",
    "created_at": "2025-02-26T16:45:30Z"
}
```

### ACH Matrix Operations
**POST** `/api/tradecraft/investigations/{id}/ach/link`

Link evidence to hypothesis for ACH analysis.

**Request Body:**
```json
{
    "item_id": "item-uuid",
    "hypothesis_id": "hyp-uuid",
    "relationship": "supports",
    "diagnostic_value": "disconfirming"
}
```

**GET** `/api/tradecraft/investigations/{id}/ach/matrix`

Retrieve ACH matrix with Heuer diagnostic scoring.

**Response:**
```json
{
    "hypotheses": [
        {
        "hypothesis_id": "hyp-uuid",
        "hypothesis": "Phishing campaign",
        "total_evidence": 5,
        "supporting": 2,
        "disconfirming": 3,
        "heuer_score": 0.72,
        "inconsistency_index": 0.85
        }
    ],
    "strongest_hypothesis": "hyp-uuid",
    "analysis_timestamp": "2025-02-26T16:45:30Z"
}
```

### Alternative Explanations
**POST** `/api/tradecraft/investigations/{id}/alternatives`

Record rejected alternative explanations.

**Request Body:**
```json
{
    "alternative": "Target is conducting legitimate security research",
    "reason_rejected": "No evidence of legitimate research agenda; infrastructure inconsistent with security firm practices",
    "confidence_in_rejection": "High"
}
```

**GET** `/api/tradecraft/investigations/{id}/alternatives`

List all documented alternatives and rejection justifications.

### Devil's Advocacy
**POST** `/api/tradecraft/investigations/{id}/devils-advocacy`

Capture designated dissent opinion.

**Request Body:**
```json
{
    "advocate_name": "Senior Analyst Smith",
    "contrary_view": "Despite B-source evidence, alternative interpretation is that this is testing our defenses",
    "confidence": "Moderate",
    "key_assumption": "Assumes attacker logic favors operational security"
}
```

### Conclusions
**POST** `/api/tradecraft/investigations/{id}/conclusions`

Record final analytic conclusion.

**Request Body:**
```json
{
    "conclusion": "Target is actively conducting phishing operations against financial sector",
    "confidence": "High",
    "key_evidence": ["item-1", "item-2", "item-3"],
    "key_assumptions": ["No OPSEC deception"],
    "caveats": ["Limited visibility into backend infrastructure"],
    "alternative_views_considered": ["alt-1", "alt-2"]
}
```

**Response:**
```json
{
    "conclusion_id": "conc-uuid",
    "ic_statement": "We assess with high confidence that the target is conducting phishing operations targeting the financial sector, based on domain registration patterns, certificate transparency data, and infrastructure overlap with known threat actor TTPs.",
    "confidence": "High",
    "created_at": "2025-02-26T16:45:30Z"
}
```

---

## Real-Time Monitoring

Continuous infrastructure surveillance and watchlist management.

### Create Watchlist Entry
**POST** `/api/monitoring/watchlist`

Add a target to continuous monitoring.

**Headers:**
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body:**
```json
{
    "name": "Corporate Main Domain",
    "entry_type": "domain",
    "value": "example.com",
    "enabled": true,
    "check_interval_hours": 24,
    "tags": ["corporate", "critical"]
}
```

**Response:**
```json
{
    "entry_id": "watch-uuid",
    "name": "Corporate Main Domain",
    "entry_type": "domain",
    "value": "example.com",
    "enabled": true,
    "check_interval_hours": 24,
    "last_check": null,
    "created_at": "2025-02-26T16:45:30Z"
}
```

### List Watchlist
**GET** `/api/monitoring/watchlist`

Retrieve all watchlist entries.

**Query Parameters:**
- `enabled` (optional): Filter by enabled status (true/false)
- `entry_type` (optional): Filter by type (domain, ip, email, keyword, etc)
- `limit` (optional): Results per page (default: 20)
- `offset` (optional): Pagination offset

**Response:**
```json
{
    "entries": [
        {
            "entry_id": "watch-uuid",
            "name": "Corporate Main Domain",
            "entry_type": "domain",
            "value": "example.com",
            "enabled": true,
            "check_interval_hours": 24,
            "last_check": "2025-02-26T10:00:00Z",
            "created_at": "2025-02-26T16:45:30Z"
        }
    ],
    "total": 5,
    "has_more": false
}
```

### Trigger Watchlist Check
**POST** `/api/monitoring/watchlist/{entry_id}/check`

Manually trigger an immediate check for a watchlist entry.

**Response:**
```json
{
    "entry_id": "watch-uuid",
    "check_timestamp": "2025-02-26T16:45:30Z",
    "new_alerts": 2,
    "snapshot": {
        "dns_records": [...],
        "certificates": [...],
        "open_ports": [22, 80, 443],
        "reputation": {"VirusTotal": 0, "AbuseIPDB": 0}
    }
}
```

### List Alerts
**GET** `/api/monitoring/alerts`

Retrieve alert feed with filtering.

**Query Parameters:**
- `status` (optional): new, acknowledged, in_progress, resolved, dismissed
- `severity` (optional): info, low, medium, high, critical
- `entry_id` (optional): Filter by watchlist entry
- `limit` (optional): Results per page (default: 50)
- `offset` (optional): Pagination offset

**Response:**
```json
{
    "alerts": [
        {
            "alert_id": "alert-uuid",
            "entry_id": "watch-uuid",
            "alert_type": "new_certificate",
            "severity": "medium",
            "status": "new",
            "message": "New SSL certificate issued for example.com",
            "details": {
                "subject": "CN=example.com",
                "issuer": "Let's Encrypt",
                "valid_from": "2025-02-20T00:00:00Z",
                "valid_to": "2025-05-21T00:00:00Z"
            },
            "created_at": "2025-02-26T14:30:00Z"
        }
    ],
    "total": 15,
    "has_more": true
}
```

### Update Alert Status
**PATCH** `/api/monitoring/alerts/{alert_id}`

Update alert status and add notes.

**Request Body:**
```json
{
    "status": "acknowledged",
    "notes": "Reviewed by security team. Valid certificate renewal."
}
```

**Response:**
```json
{
    "alert_id": "alert-uuid",
    "status": "acknowledged",
    "updated_at": "2025-02-26T16:45:30Z"
}
```

---

## Credential Intelligence

Multi-source credential breach detection and password analysis.

### Check Email Exposure
**POST** `/api/credentials/check/email`

Check if email has been exposed in breaches.

**Headers:**
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body:**
```json
{
    "email": "user@example.com"
}
```

**Response:**
```json
{
    "email": "user@example.com",
    "exposure_status": "exposed",
    "risk_score": 72,
    "risk_level": "high",
    "breach_count": 3,
    "paste_count": 1,
    "breaches": [
        {
            "name": "LinkedIn Leak",
            "breach_date": "2023-06-15",
            "affected_fields": ["email", "password_hash", "name"]
        }
    ],
    "dehashed_results": [
        {
            "source": "dehashed",
            "email": "user@example.com",
            "password_hash": "5d41402abc4b2a76b9719d911017c592",
            "hash_type": "MD5"
        }
    ]
}
```

### Check Domain Exposure
**POST** `/api/credentials/check/domain`

Check if domain has exposed employee credentials.

**Request Body:**
```json
{
    "domain": "example.com"
}
```

**Response:**
```json
{
    "domain": "example.com",
    "total_exposed_accounts": 42,
    "risk_score": 65,
    "risk_level": "high",
    "exposed_employees": [
        {
            "email": "admin@example.com",
            "breach_sources": ["HIBP", "Dehashed"],
            "breach_count": 2
        }
    ]
}
```

### Check Password Security
**POST** `/api/credentials/check/password`

Check if password has been exposed using k-anonymity (SHA-1 prefix only).

**Request Body:**
```json
{
    "password": "p@ssw0rd123"
}
```

**Response:**
```json
{
    "exposed": true,
    "exposure_count": 523,
    "risk_level": "critical",
    "message": "This password appears in breached credential databases. Choose a unique password."
}
```

### Analyze Passwords from Investigation
**POST** `/api/credentials/analyze-passwords`

Batch analyze multiple exposed passwords linked to investigation.

**Request Body:**
```json
{
    "investigation_id": "inv-uuid",
    "emails": ["user1@example.com", "user2@example.com"]
}
```

**Response:**
```json
{
    "analysis_id": "analysis-uuid",
    "investigation_id": "inv-uuid",
    "emails_analyzed": 2,
    "critical_exposures": 1,
    "high_risk_exposures": 1,
    "recommendations": [
        "Force password reset for all critical exposure accounts",
        "Enable MFA for high-risk accounts",
        "Monitor for lateral movement from compromised accounts"
    ]
}
```

---

## NLP Intelligence

Natural language processing for entity extraction and text analysis.

### Extract Entities
**POST** `/api/nlp/extract-entities`

Extract persons, organizations, locations, and technical indicators from text.

**Headers:**
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body:**
```json
{
    "text": "John Smith from Acme Corporation in New York was connected to IP 192.0.2.1 and domain malicious.com",
    "include_technical": true
}
```

**Response:**
```json
{
    "entities": {
        "PERSON": [
            {"text": "John Smith", "confidence": 0.98}
        ],
        "ORG": [
            {"text": "Acme Corporation", "confidence": 0.95}
        ],
        "GPE": [
            {"text": "New York", "confidence": 0.99}
        ],
        "IP_ADDRESS": [
            {"text": "192.0.2.1", "confidence": 1.0}
        ],
        "DOMAIN": [
            {"text": "malicious.com", "confidence": 0.99}
        ]
    },
    "text_length": 95,
    "processing_time_ms": 45
}
```

### Classify Text
**POST** `/api/nlp/classify`

Classify text by threat category and sentiment.

**Request Body:**
```json
{
    "text": "We have identified a critical ransomware campaign targeting healthcare organizations",
    "classification_type": "threat_intelligence"
}
```

**Response:**
```json
{
    "classifications": {
        "threat_type": {
            "category": "ransomware",
            "confidence": 0.96,
            "related_categories": ["extortion", "data_encryption"]
        },
        "sentiment": {
            "label": "negative",
            "confidence": 0.88
        }
    },
    "processing_time_ms": 32
}
```

### Extract Report Intelligence
**POST** `/api/nlp/extract-report`

Full intelligence extraction from investigation summary or report.

**Request Body:**
```json
{
    "report_text": "Investigation summary text...",
    "investigation_id": "inv-uuid"
}
```

**Response:**
```json
{
    "entities_extracted": 15,
    "relationships_inferred": 8,
    "keywords": ["phishing", "credential_theft", "domain_registration"],
    "threat_indicators": ["IP", "domain", "email"],
    "confidence_summary": "High confidence in entity extraction, moderate in relationship inference"
}
```

---

## Service Settings

API key management and service configuration.

### List Services
**GET** `/api/settings/services`

Retrieve all available services with configuration status.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Response:**
```json
{
    "services": [
        {
            "id": "virustotal",
            "name": "VirusTotal",
            "category": "threat_intelligence",
            "tier": "freemium",
            "tier_note": "40 API requests per minute (free tier)",
            "has_key": true,
            "enabled": true,
            "works_without_key": true,
            "docs_url": "https://virustotal.com/docs",
            "signup_url": "https://virustotal.com/sign-up"
        }
    ],
    "total": 19
}
```

### Save API Key
**POST** `/api/settings/services/{service_id}/key`

Save or update API key for a service.

**Headers:**
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body:**
```json
{
    "api_key": "your-api-key-here"
}
```

**Response:**
```json
{
    "service_id": "virustotal",
    "key_saved": true,
    "key_hash": "sha256_hash_of_key",
    "last_updated": "2025-02-26T16:45:30Z"
}
```

### Test Service Connection
**POST** `/api/settings/services/{service_id}/test`

Test API connection for a service.

**Response:**
```json
{
    "service_id": "virustotal",
    "status": "connected",
    "response_time_ms": 245,
    "quota_remaining": 3998
}
```

### Delete API Key
**DELETE** `/api/settings/services/{service_id}/key`

Remove API key for a service (falls back to free tier).

**Response:**
```json
{
    "service_id": "virustotal",
    "key_deleted": true,
    "fallback_mode": "free_tier"
}
```

### Get/Switch Mode
**GET** `/api/settings/mode`

Get current Demo/Live mode.

**Response:**
```json
{
    "mode": "demo",
    "demo_until": "2025-02-27T00:00:00Z",
    "services_affected": ["all"]
}
```

**POST** `/api/settings/mode`

Switch between Demo and Live mode.

**Request Body:**
```json
{
    "mode": "live"
}
```

---

## STIX/MISP Export

Standards-compliant threat intelligence export.

### Export as STIX Bundle
**GET** `/api/investigations/{id}/export/stix`

Export investigation as STIX 2.1 bundle.

**Headers:**
```
Authorization: Bearer <jwt_token>
```

**Query Parameters:**
- `include_relationships` (optional): Include relationship objects (default: true)
- `tlp_marking` (optional): TLP:WHITE, TLP:GREEN, TLP:AMBER, TLP:RED (default: TLP:AMBER)

**Response:**
- Content-Type: `application/json`
- Body: STIX 2.1 Bundle JSON

**Example Response:**
```json
{
    "type": "bundle",
    "id": "bundle--uuid",
    "objects": [
        {
            "type": "indicator",
            "id": "indicator--uuid",
            "created": "2025-02-26T16:45:30Z",
            "pattern": "[domain-name:value = 'malicious.com']",
            "labels": ["malicious-activity"],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": "resource-development"
                }
            ]
        }
    ]
}
```

### Export as MISP Event
**GET** `/api/investigations/{id}/export/misp`

Export investigation as MISP event format.

**Query Parameters:**
- `event_info` (optional): Event description (default: investigation target)
- `threat_level_id` (optional): 1-4 (high to low severity)
- `analysis` (optional): 0-2 (ongoing to completed)

**Response:**
```json
{
    "Event": {
        "id": 1,
        "info": "example.com investigation",
        "Attribute": [
            {
                "type": "domain",
                "value": "example.com",
                "comment": "Extracted from investigation"
            }
        ]
    }
}
```

### Push to MISP Instance
**POST** `/api/investigations/{id}/export/misp/push`

Export and push investigation to MISP instance.

**Request Body:**
```json
{
    "misp_url": "https://misp.example.com",
    "api_key": "misp-api-key",
    "threat_level_id": 2,
    "analysis": 1
}
```

**Response:**
```json
{
    "success": true,
    "event_id": 12345,
    "misp_url": "https://misp.example.com/events/12345",
    "attributes_pushed": 23,
    "relationships_pushed": 8
}
```

---

## System Status

### Platform Health Check
**GET** `/api/system/status`

Check overall platform health and component status.

**Response:**
```json
{
    "service": "Enterprise OSINT Platform",
    "status": "operational",
    "version": "2.0.0",
    "components": {
        "postgresql": {
            "status": "connected",
            "version": "15.5",
            "latency_ms": 5
        },
        "redis": {
            "status": "connected", 
            "version": "7.2.0",
            "memory_usage": "45MB"
        },
        "orchestrator": {
            "status": "running",
            "active_investigations": 3
        },
        "mcp_servers": {
            "infrastructure_enhanced": {
                "status": "online",
                "url": "http://mcp-infrastructure-enhanced:8021",
                "response_time_ms": 12
            },
            "threat_enhanced": {
                "status": "online",
                "url": "http://mcp-threat-enhanced:8020",
                "response_time_ms": 8
            },
            "ai_analyzer": {
                "status": "online",
                "url": "http://mcp-technical-enhanced:8050",
                "openai_configured": false
            },
            "social_enhanced": {
                "status": "online",
                "url": "http://mcp-social-enhanced:8010"
            },
            "financial_enhanced": {
                "status": "online",
                "url": "http://mcp-financial-enhanced:8040"
            }
        }
    },
    "metrics": {
        "active_investigations": 3,
        "total_investigations": 157,
        "total_reports_generated": 142,
        "api_availability": "5/5",
        "uptime_hours": 168.5
    },
    "timestamp": "2025-08-16T16:45:30Z"
}
```

### MCP Server Status
**GET** `/api/mcp/servers`

Get detailed status of all MCP servers and their capabilities.

**Response:**
```json
{
    "servers": [
        {
            "name": "Infrastructure Advanced",
            "id": "infrastructure_enhanced",
            "url": "http://mcp-infrastructure-enhanced:8021",
            "status": "online",
            "capabilities": [
                "infrastructure/certificate_transparency",
                "infrastructure/passive_dns",
                "infrastructure/asn_lookup",
                "infrastructure/reverse_ip",
                "infrastructure/port_scan",
                "infrastructure/web_technologies"
            ],
            "response_time_ms": 12,
            "last_check": "2025-08-16T16:45:25Z"
        },
        {
            "name": "Threat Intelligence Aggregator",
            "id": "threat_enhanced", 
            "url": "http://mcp-threat-enhanced:8020",
            "status": "online",
            "capabilities": [
                "threat/check_ip",
                "threat/check_domain", 
                "threat/check_hash",
                "threat/hunt"
            ],
            "required_api_keys": [
                "VIRUSTOTAL_API_KEY",
                "ABUSEIPDB_API_KEY",
                "SHODAN_API_KEY"
            ],
            "response_time_ms": 8,
            "last_check": "2025-08-16T16:45:25Z"
        }
    ]
}
```

---

## Graph Intelligence

Palantir-inspired graph analytics for OSINT investigations. Provides entity relationship mapping, advanced algorithms, and pattern detection.

### Graph Status
**GET** `/api/graph/status`

Check graph intelligence module availability and configuration.

**Response:**
```json
{
    "available": true,
    "neo4j_connected": false,
    "mock_mode": true,
    "algorithms": {
        "centrality": true,
        "paths": true,
        "community": true,
        "similarity": true,
        "anomaly": true,
        "influence": true
    },
    "version": "1.0.0"
}
```

### Sync Investigation to Graph
**POST** `/api/investigations/{id}/graph/sync`

Extract entities from investigation data and sync to graph database.

**Headers:**
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Response:**
```json
{
    "status": "synced",
    "investigation_id": "605ba974-9a88-4921-855e-c9dbedc2b3d8",
    "entities_extracted": 47,
    "relationships_created": 89,
    "entity_breakdown": {
        "IP_ADDRESS": 12,
        "DOMAIN": 8,
        "EMAIL": 5,
        "URL": 15,
        "FILE_HASH": 7
    },
    "sync_timestamp": "2025-08-16T16:45:30Z"
}
```

### Full Graph Analysis
**POST** `/api/investigations/{id}/graph/analyze`

Run comprehensive graph analysis including centrality, communities, and anomalies.

**Headers:**
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body (optional):**
```json
{
    "include_centrality": true,
    "include_communities": true,
    "include_anomalies": true,
    "include_influence": false
}
```

**Response:**
```json
{
    "investigation_id": "605ba974-9a88-4921-855e-c9dbedc2b3d8",
    "analysis_timestamp": "2025-08-16T16:45:30Z",
    "centrality": {
        "top_by_composite": [
            {
                "node_id": "ip_192.0.2.1",
                "composite_score": 0.847,
                "pagerank": 0.156,
                "betweenness": 0.234,
                "closeness": 0.567
            }
        ],
        "hub_nodes": ["ip_192.0.2.1", "domain_example.com"],
        "bridge_nodes": ["email_admin@example.com"]
    },
    "communities": {
        "total_communities": 3,
        "modularity": 0.72,
        "communities": [
            {
                "id": 0,
                "size": 15,
                "members": ["ip_192.0.2.1", "domain_example.com"],
                "density": 0.45
            }
        ]
    },
    "anomalies": {
        "total_anomalies": 5,
        "high_risk": 1,
        "medium_risk": 2,
        "low_risk": 2,
        "anomalies": [
            {
                "node_id": "ip_192.0.2.100",
                "anomaly_type": "degree",
                "severity": "high",
                "z_score": 3.45,
                "description": "Unusually high number of connections"
            }
        ]
    }
}
```

### Find Paths Between Entities
**POST** `/api/investigations/{id}/graph/paths`

Find connection paths between two entities in the investigation graph.

**Headers:**
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body:**
```json
{
    "source_id": "ip_192.0.2.1",
    "target_id": "domain_malicious.com",
    "max_depth": 5,
    "include_weights": true
}
```

**Response:**
```json
{
    "source": "ip_192.0.2.1",
    "target": "domain_malicious.com",
    "paths_found": 3,
    "shortest_path": {
        "length": 3,
        "nodes": ["ip_192.0.2.1", "domain_example.com", "email_admin@example.com", "domain_malicious.com"],
        "edges": [
            {"from": "ip_192.0.2.1", "to": "domain_example.com", "type": "RESOLVES_TO"},
            {"from": "domain_example.com", "to": "email_admin@example.com", "type": "REGISTERED_BY"},
            {"from": "email_admin@example.com", "to": "domain_malicious.com", "type": "REGISTERED_BY"}
        ],
        "total_weight": 2.5
    },
    "all_paths": [...]
}
```

### Blast Radius Analysis
**POST** `/api/investigations/{id}/graph/blast-radius`

Analyze potential impact if an entity is compromised.

**Headers:**
```
Authorization: Bearer <jwt_token>
Content-Type: application/json
```

**Request Body:**
```json
{
    "entity_id": "ip_192.0.2.1",
    "max_hops": 3,
    "propagation_model": "independent_cascade",
    "probability": 0.3
}
```

**Response:**
```json
{
    "source_entity": "ip_192.0.2.1",
    "model": "independent_cascade",
    "max_hops": 3,
    "blast_radius": {
        "total_affected": 23,
        "by_hop": {
            "1": 8,
            "2": 10,
            "3": 5
        },
        "by_entity_type": {
            "IP_ADDRESS": 5,
            "DOMAIN": 8,
            "EMAIL": 3,
            "URL": 7
        },
        "critical_entities": [
            {
                "id": "domain_example.com",
                "type": "DOMAIN",
                "impact_score": 0.89,
                "downstream_count": 12
            }
        ]
    },
    "risk_assessment": {
        "severity": "HIGH",
        "spread_rate": 0.67,
        "containment_priority": ["domain_example.com", "ip_192.0.2.50"]
    }
}
```

### Centrality Analysis
**POST** `/api/graph/centrality`

Compute centrality metrics for graph nodes.

**Request Body:**
```json
{
    "node_ids": ["ip_192.0.2.1", "domain_example.com"],
    "metrics": ["pagerank", "betweenness", "closeness", "eigenvector"],
    "top_k": 10
}
```

**Response:**
```json
{
    "metrics": {
        "pagerank": {
            "ip_192.0.2.1": 0.156,
            "domain_example.com": 0.089
        },
        "betweenness": {
            "ip_192.0.2.1": 0.234,
            "domain_example.com": 0.145
        }
    },
    "top_nodes": [
        {"id": "ip_192.0.2.1", "composite_score": 0.847},
        {"id": "domain_example.com", "composite_score": 0.634}
    ],
    "computation_time_ms": 45
}
```

### Community Detection
**POST** `/api/graph/communities`

Detect communities and clusters in the graph.

**Request Body:**
```json
{
    "algorithm": "louvain",
    "resolution": 1.0,
    "min_community_size": 3
}
```

**Response:**
```json
{
    "algorithm": "louvain",
    "total_communities": 5,
    "modularity": 0.72,
    "communities": [
        {
            "id": 0,
            "size": 15,
            "members": ["ip_192.0.2.1", "domain_example.com", "..."],
            "density": 0.45,
            "dominant_type": "DOMAIN"
        }
    ],
    "computation_time_ms": 120
}
```

### Similarity Search
**POST** `/api/graph/similarity`

Find similar entities based on graph structure.

**Request Body:**
```json
{
    "entity_id": "ip_192.0.2.1",
    "method": "jaccard",
    "top_k": 10,
    "entity_type_filter": "IP_ADDRESS"
}
```

**Response:**
```json
{
    "source_entity": "ip_192.0.2.1",
    "method": "jaccard",
    "similar_entities": [
        {
            "id": "ip_192.0.2.50",
            "similarity_score": 0.78,
            "common_neighbors": 5,
            "entity_type": "IP_ADDRESS"
        }
    ],
    "computation_time_ms": 23
}
```

### Anomaly Detection
**POST** `/api/graph/anomalies`

Detect structural anomalies in the graph.

**Request Body:**
```json
{
    "detection_methods": ["degree", "clustering", "bridge", "star_pattern"],
    "threshold": 2.0,
    "min_severity": "medium"
}
```

**Response:**
```json
{
    "total_anomalies": 8,
    "by_severity": {
        "high": 2,
        "medium": 3,
        "low": 3
    },
    "anomalies": [
        {
            "node_id": "ip_192.0.2.100",
            "anomaly_type": "degree",
            "severity": "high",
            "z_score": 3.45,
            "description": "Node has 45 connections, 3.45 standard deviations above mean",
            "investigation_priority": 1
        },
        {
            "node_id": "domain_suspicious.com",
            "anomaly_type": "star_pattern",
            "severity": "high",
            "description": "Hub node connected to 30+ isolated nodes",
            "investigation_priority": 2
        }
    ],
    "computation_time_ms": 89
}
```

### Influence Propagation
**POST** `/api/graph/influence`

Simulate influence spread through the network.

**Request Body:**
```json
{
    "seed_nodes": ["ip_192.0.2.1"],
    "model": "independent_cascade",
    "probability": 0.3,
    "max_iterations": 100,
    "simulations": 1000
}
```

**Response:**
```json
{
    "model": "independent_cascade",
    "seed_nodes": ["ip_192.0.2.1"],
    "propagation_results": {
        "expected_spread": 15.7,
        "spread_std": 3.2,
        "max_spread": 28,
        "affected_by_iteration": [1, 5, 8, 12, 14, 15],
        "critical_paths": [
            {
                "path": ["ip_192.0.2.1", "domain_example.com", "email_admin@example.com"],
                "probability": 0.67
            }
        ]
    },
    "computation_time_ms": 450
}
```

---

## MCP Server APIs

Direct access to MCP server capabilities for advanced users.

### Infrastructure Advanced MCP (Port 8021)

#### Health Check
**GET** `/health`
```json
{
    "status": "healthy",
    "service": "infrastructure-advanced-mcp"
}
```

#### Get Capabilities
**GET** `/capabilities`
```json
{
    "name": "Infrastructure Advanced Intelligence",
    "version": "2.0.0",
    "methods": [
        {
            "name": "infrastructure/certificate_transparency",
            "description": "Query certificate transparency logs",
            "params": ["domain"]
        },
        {
            "name": "infrastructure/passive_dns", 
            "description": "Get historical DNS records",
            "params": ["domain"]
        }
    ]
}
```

#### Execute Certificate Transparency Search
**POST** `/infrastructure/certificate_transparency`
```json
{
    "domain": "example.com"
}
```

Response:
```json
{
    "success": true,
    "data": {
        "certificates": [
            {
                "subject": "CN=example.com",
                "issuer": "Let's Encrypt Authority X3", 
                "not_before": "2025-06-01T00:00:00Z",
                "not_after": "2025-09-01T00:00:00Z",
                "serial_number": "03a123...",
                "log_entry_index": 123456789
            }
        ],
        "total_found": 15,
        "search_timestamp": "2025-08-16T16:45:30Z"
    }
}
```

### Threat Intelligence Aggregator (Port 8020)

#### Check IP Reputation
**POST** `/threat/check_ip`
```json
{
    "ip": "192.0.2.1"
}
```

Response:
```json
{
    "success": true,
    "data": {
        "ip": "192.0.2.1",
        "timestamp": "2025-08-16T16:45:30Z",
        "reputation_scores": {
            "VirusTotal": 0,
            "AbuseIPDB": 0,
            "Shodan": 15,
            "AlienVault OTX": 0
        },
        "threat_categories": [],
        "confidence": 0.92,
        "risk_level": "LOW"
    }
}
```

### AI-Powered Analyzer (Port 8050)

#### Generate Executive Summary
**POST** `/ai/generate_executive_summary`
```json
{
    "investigation_data": {
        "target": "example.com",
        "findings": {
            "infrastructure": {...},
            "threat_intelligence": {...}
        }
    }
}
```

Response:
```json
{
    "success": true,
    "data": {
        "timestamp": "2025-08-16T16:45:30Z",
        "executive_summary": {
            "overview": "The investigation of example.com reveals a legitimate business domain with standard security posture.",
            "key_findings": [
                "Domain has legitimate registration history",
                "No malicious indicators found",
                "Standard web hosting configuration"
            ],
            "business_impact": "LOW",
            "recommended_actions": [
                "Continue routine monitoring",
                "Verify SSL certificate renewal process"
            ]
        },
        "risk_score": 25,
        "report_classification": "LOW"
    }
}
```

---

## Error Handling

### Standard Error Response Format
```json
{
    "error": {
        "code": "INVALID_REQUEST",
        "message": "The request body is invalid",
        "details": "Missing required field 'target'",
        "timestamp": "2025-08-16T16:45:30Z",
        "request_id": "req_abc123"
    }
}
```

### Common Error Codes

| Code | Status | Description |
|------|--------|-------------|
| `INVALID_REQUEST` | 400 | Request body or parameters are invalid |
| `UNAUTHORIZED` | 401 | Missing or invalid JWT token |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `NOT_FOUND` | 404 | Resource not found |
| `RATE_LIMITED` | 429 | Too many requests |
| `INTERNAL_ERROR` | 500 | Server error |
| `SERVICE_UNAVAILABLE` | 503 | MCP server or database unavailable |

### Investigation-Specific Errors

| Code | Description |
|------|-------------|
| `INVESTIGATION_NOT_FOUND` | Investigation ID does not exist |
| `INVESTIGATION_RUNNING` | Cannot modify running investigation |
| `INVALID_TARGET` | Target format is invalid |
| `MCP_SERVER_ERROR` | One or more MCP servers failed |
| `REPORT_GENERATION_FAILED` | PDF report generation failed |

---

## Rate Limiting

### Default Limits
- **Authentication**: 5 requests per minute per IP
- **Investigation Creation**: 10 requests per hour per user  
- **Investigation Queries**: 100 requests per minute per user
- **System Status**: 60 requests per minute per IP

### Rate Limit Headers
```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1692195600
```

### Rate Limit Exceeded Response
```json
{
    "error": {
        "code": "RATE_LIMITED",
        "message": "Rate limit exceeded",
        "details": "100 requests per minute allowed",
        "retry_after": 60
    }
}
```

---

## Authentication Requirements by Endpoint

| Endpoint | Authentication Required | Role Required |
|----------|------------------------|---------------|
| `POST /api/auth/login` | No | None |
| `POST /api/auth/logout` | Yes | Any |
| `GET /api/investigations` | Yes | Any |
| `POST /api/investigations` | Yes | Analyst+ |
| `GET /api/investigations/{id}` | Yes | Any |
| `DELETE /api/investigations/{id}` | Yes | Admin |
| `GET /api/tradecraft/scales` | Yes | Any |
| `POST /api/tradecraft/investigations/{id}/items` | Yes | Analyst+ |
| `POST /api/tradecraft/investigations/{id}/hypotheses` | Yes | Analyst+ |
| `POST /api/tradecraft/investigations/{id}/ach/link` | Yes | Analyst+ |
| `GET /api/tradecraft/investigations/{id}/ach/matrix` | Yes | Any |
| `POST /api/tradecraft/investigations/{id}/alternatives` | Yes | Analyst+ |
| `GET /api/tradecraft/investigations/{id}/alternatives` | Yes | Any |
| `POST /api/tradecraft/investigations/{id}/devils-advocacy` | Yes | Analyst+ |
| `POST /api/tradecraft/investigations/{id}/conclusions` | Yes | Analyst+ |
| `POST /api/monitoring/watchlist` | Yes | Analyst+ |
| `GET /api/monitoring/watchlist` | Yes | Any |
| `POST /api/monitoring/watchlist/{entry_id}/check` | Yes | Analyst+ |
| `GET /api/monitoring/alerts` | Yes | Any |
| `PATCH /api/monitoring/alerts/{alert_id}` | Yes | Analyst+ |
| `POST /api/credentials/check/email` | Yes | Any |
| `POST /api/credentials/check/domain` | Yes | Any |
| `POST /api/credentials/check/password` | Yes | Any |
| `POST /api/credentials/analyze-passwords` | Yes | Analyst+ |
| `POST /api/nlp/extract-entities` | Yes | Any |
| `POST /api/nlp/classify` | Yes | Any |
| `POST /api/nlp/extract-report` | Yes | Any |
| `GET /api/settings/services` | Yes | Any |
| `POST /api/settings/services/{service_id}/key` | Yes | Admin |
| `POST /api/settings/services/{service_id}/test` | Yes | Analyst+ |
| `DELETE /api/settings/services/{service_id}/key` | Yes | Admin |
| `GET /api/settings/mode` | Yes | Any |
| `POST /api/settings/mode` | Yes | Admin |
| `GET /api/investigations/{id}/export/stix` | Yes | Any |
| `GET /api/investigations/{id}/export/misp` | Yes | Any |
| `POST /api/investigations/{id}/export/misp/push` | Yes | Analyst+ |
| `GET /api/system/status` | No | None |
| `GET /api/mcp/servers` | Yes | Any |
| `GET /api/graph/status` | No | None |
| `POST /api/investigations/{id}/graph/sync` | Yes | Analyst+ |
| `POST /api/investigations/{id}/graph/analyze` | Yes | Any |
| `POST /api/investigations/{id}/graph/paths` | Yes | Any |
| `POST /api/investigations/{id}/graph/blast-radius` | Yes | Any |
| `POST /api/graph/centrality` | Yes | Any |
| `POST /api/graph/communities` | Yes | Any |
| `POST /api/graph/similarity` | Yes | Any |
| `POST /api/graph/anomalies` | Yes | Any |
| `POST /api/graph/influence` | Yes | Any |

### Role Hierarchy
1. **Viewer**: Read-only access to investigations
2. **Analyst**: Can create and view investigations
3. **Admin**: Full access including deletion and system management

---

## SDK and Client Libraries

### Python Client Example
```python
import requests

class OSINTPlatformClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.token = self._authenticate(username, password)
    
    def _authenticate(self, username, password):
        response = requests.post(f"{self.base_url}/api/auth/login", 
                               json={"username": username, "password": password})
        return response.json()["access_token"]
    
    def create_investigation(self, target, investigation_type="comprehensive"):
        headers = {"Authorization": f"Bearer {self.token}"}
        data = {"target": target, "investigation_type": investigation_type}
        response = requests.post(f"{self.base_url}/api/investigations", 
                               json=data, headers=headers)
        return response.json()

# Usage
client = OSINTPlatformClient("http://localhost:5000", "admin", "admin123")
investigation = client.create_investigation("example.com")
```

For complete SDK documentation and examples in multiple languages, see the [SDK Documentation](SDK.md).