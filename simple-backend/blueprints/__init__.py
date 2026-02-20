#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Flask Blueprints for the Enterprise OSINT Platform.

Each blueprint module encapsulates routes for a specific domain:
- health: Health checks, metrics, readiness probes
- auth: Authentication, JWT token management
- investigations: Investigation CRUD and lifecycle
- reports: Report generation and download
- compliance: Compliance frameworks and assessments
- risk: Risk assessment and intelligence correlation
- intelligence: Intelligence gathering and entity correlation
- graph: Graph intelligence analytics
- analysis: Advanced analysis, MITRE ATT&CK, trends
- admin: Admin operations, system config, monitoring, jobs
"""
