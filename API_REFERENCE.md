# Enterprise OSINT Platform - API Reference

Complete API documentation for the Enterprise OSINT Platform REST API and MCP server endpoints.

## Table of Contents
1. [Authentication](#authentication)
2. [Investigation Management](#investigation-management)
3. [System Status](#system-status)
4. [MCP Server APIs](#mcp-server-apis)
5. [Error Handling](#error-handling)
6. [Rate Limiting](#rate-limiting)

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
| `GET /api/system/status` | No | None |
| `GET /api/mcp/servers` | Yes | Any |

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