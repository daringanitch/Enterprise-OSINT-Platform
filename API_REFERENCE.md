# Enterprise OSINT Platform - API Reference

Complete API documentation for the Enterprise OSINT Platform REST API and MCP server endpoints.

## Table of Contents
1. [Authentication](#authentication)
2. [Investigation Management](#investigation-management)
3. [System Status](#system-status)
4. [Graph Intelligence](#graph-intelligence)
5. [MCP Server APIs](#mcp-server-apis)
6. [Error Handling](#error-handling)
7. [Rate Limiting](#rate-limiting)

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