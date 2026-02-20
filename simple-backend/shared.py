#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Shared service singletons for the Enterprise OSINT Platform.

This module holds all application-wide service instances that are initialized
at startup and shared across Flask blueprints. Import `services` from this
module to access any shared service.

Usage in blueprints:
    from shared import services
    # Then: services.orchestrator, services.compliance_engine, etc.
"""


class _Services:
    """Container for all application-wide service singletons.

    Set once during app startup in app.py; imported read-only by blueprints.
    """
    # Core services
    orchestrator = None           # InvestigationOrchestrator
    compliance_engine = None      # ComplianceEngine
    report_generator = None       # InvestigationReportGenerator
    vault_client = None           # VaultClient
    config_manager = None         # ConfigurationManager
    professional_report_generator = None  # ProfessionalReportGenerator
    audit_report_generator = None  # ComprehensiveAuditReportGenerator
    api_monitor = None            # APIConnectionMonitor
    graph_sync = None             # CorrelationSync (or None if unavailable)
    audit_client = None           # PostgreSQL audit client (or None)
    mode_manager = None           # ModeManager
    job_queue_manager = None      # Job queue manager
    demo_provider = None          # Demo data provider

    # In-memory storage (for backward compatibility)
    legacy_investigations: dict = {}
    reports: dict = {}
    reports_audit_history: dict = {}

    # Feature availability flags (set during app startup)
    VALIDATION_ENABLED: bool = False
    CACHING_ENABLED: bool = False
    GRAPH_INTELLIGENCE_AVAILABLE: bool = False
    EXPANDED_SOURCES_AVAILABLE: bool = False
    CORRELATION_AVAILABLE: bool = False
    ADVANCED_ANALYSIS_AVAILABLE: bool = False

    # Optional service instances (set if available)
    cache_service = None
    expanded_data_manager = None
    advanced_analysis_engine = None


# Singleton instance — import this in blueprints
services = _Services()
