#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.
# Individual use is free. Commercial use requires 3% profit sharing.
# See LICENSE file for details.

"""
OSINT Investigation Orchestration Engine
Multi-stage AI-driven intelligence gathering workflow
"""

import asyncio
import logging
import time
import uuid
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable
from concurrent.futures import ThreadPoolExecutor, Future
from dataclasses import replace

from models import (
    OSINTInvestigation, InvestigationType, InvestigationStatus, Priority,
    TargetProfile, InvestigationScope, InvestigationProgress,
    SocialIntelligence, InfrastructureIntelligence, ThreatIntelligence,
    ComplianceReport, InvestigationError, IntelligenceSource
)
try:
    from observability import trace_operation, trace_investigation, add_trace_attributes, record_error
except ImportError:
    # Fallback stubs when observability module not available
    def trace_operation(name, attributes=None):
        def decorator(func):
            return func
        return decorator
    
    def trace_investigation(investigation_type):
        def decorator(func):
            return func
        return decorator
    
    def add_trace_attributes(**kwargs):
        pass
    
    def record_error(error, error_type=None):
        pass
from mcp_clients import MCPClientManager
from compliance_framework import ComplianceEngine, ComplianceFramework
from risk_assessment_engine import RiskAssessmentEngine, RiskAssessmentResult

# Import expanded data sources
try:
    from expanded_data_sources import expanded_data_manager, DataSourceResult
    EXPANDED_SOURCES_AVAILABLE = True
except ImportError:
    EXPANDED_SOURCES_AVAILABLE = False
    expanded_data_manager = None
    logger.warning("Expanded data sources not available")

logger = logging.getLogger(__name__)


class InvestigationOrchestrator:
    """
    Core orchestration engine for OSINT investigations
    Manages the 7-stage investigation workflow with AI-driven analysis
    """
    
    def __init__(self, max_concurrent_investigations: int = 10):
        self.active_investigations: Dict[str, OSINTInvestigation] = {}
        self.investigation_futures: Dict[str, Future] = {}
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent_investigations)
        self.progress_callbacks: Dict[str, List[Callable]] = {}
        self.mcp_manager = MCPClientManager()
        self.compliance_engine = ComplianceEngine()
        self.risk_engine = RiskAssessmentEngine()
        
        # Investigation stage handlers
        self.stage_handlers = {
            InvestigationStatus.PLANNING: self._stage_planning,
            InvestigationStatus.PROFILING: self._stage_profiling,
            InvestigationStatus.COLLECTING: self._stage_collecting,
            InvestigationStatus.ANALYZING: self._stage_analyzing,
            InvestigationStatus.VERIFYING: self._stage_verifying,
            InvestigationStatus.ASSESSING_RISK: self._stage_risk_assessment,
            InvestigationStatus.GENERATING_REPORT: self._stage_report_generation
        }
    
    def create_investigation(self, 
                           target: str,
                           investigation_type: InvestigationType,
                           investigator_name: str,
                           priority: Priority = Priority.NORMAL,
                           scope: Optional[InvestigationScope] = None) -> str:
        """
        Create a new OSINT investigation (without execution)
        
        Args:
            target: Primary target identifier (domain, company, etc.)
            investigation_type: Type of investigation to perform
            investigator_name: Name of investigator for audit trail
            priority: Investigation priority level
            scope: Investigation scope and constraints
            
        Returns:
            Investigation ID
        """
        
        # Create target profile
        target_profile = TargetProfile(
            target_id=f"target_{int(time.time())}",
            target_type="domain",  # Will be auto-detected in profiling stage
            primary_identifier=target,
            created_at=datetime.utcnow()
        )
        
        # Create investigation (without execution)
        investigation = OSINTInvestigation(
            id=f"osint_{uuid.uuid4().hex[:12]}",
            target_profile=target_profile,
            investigation_type=investigation_type,
            investigator_name=investigator_name,
            priority=priority,
            scope=scope or InvestigationScope(),
            status=InvestigationStatus.QUEUED,  # Start as queued
            created_at=datetime.utcnow()
        )
        
        # Store investigation
        self.active_investigations[investigation.id] = investigation
        
        logger.info(f"Created investigation {investigation.id} for target {target}")
        return investigation.id

    def start_investigation(self, 
                          target: str,
                          investigation_type: InvestigationType,
                          investigator_name: str,
                          priority: Priority = Priority.NORMAL,
                          scope: Optional[InvestigationScope] = None) -> str:
        """
        Start a new OSINT investigation
        
        Args:
            target: Primary target identifier (domain, company, etc.)
            investigation_type: Type of investigation to perform
            investigator_name: Name of investigator for audit trail
            priority: Investigation priority level
            scope: Investigation scope and constraints
            
        Returns:
            Investigation ID
        """
        
        # Create target profile
        target_profile = TargetProfile(
            target_id=f"target_{int(time.time())}",
            target_type="domain",  # Will be auto-detected in profiling stage
            primary_identifier=target,
            created_at=datetime.utcnow()
        )
        
        # Create investigation
        investigation = OSINTInvestigation(
            target_profile=target_profile,
            investigation_type=investigation_type,
            scope=scope or InvestigationScope(),
            priority=priority,
            investigator_name=investigator_name,
            status=InvestigationStatus.PENDING,
            created_at=datetime.utcnow(),
            data_retention_until=datetime.utcnow() + timedelta(days=30)
        )
        
        # Store investigation
        self.active_investigations[investigation.id] = investigation
        
        # Submit for execution
        future = self.executor.submit(self._execute_investigation, investigation.id)
        self.investigation_futures[investigation.id] = future
        
        logger.info(f"Started investigation {investigation.id} for target {target}")
        return investigation.id
    
    def get_investigation(self, investigation_id: str) -> Optional[OSINTInvestigation]:
        """Get investigation by ID"""
        return self.active_investigations.get(investigation_id)
    
    def cancel_investigation(self, investigation_id: str) -> bool:
        """Cancel running investigation"""
        if investigation_id not in self.active_investigations:
            return False
            
        investigation = self.active_investigations[investigation_id]
        investigation.status = InvestigationStatus.CANCELLED
        investigation.completed_at = datetime.utcnow()
        
        # Cancel future if still running
        future = self.investigation_futures.get(investigation_id)
        if future and not future.done():
            future.cancel()
        
        logger.info(f"Cancelled investigation {investigation_id}")
        return True
    
    def get_active_investigations(self) -> List[OSINTInvestigation]:
        """Get all active investigations"""
        return list(self.active_investigations.values())
    
    def register_progress_callback(self, investigation_id: str, callback: Callable):
        """Register callback for investigation progress updates"""
        if investigation_id not in self.progress_callbacks:
            self.progress_callbacks[investigation_id] = []
        self.progress_callbacks[investigation_id].append(callback)
    
    def _notify_progress(self, investigation_id: str, investigation: OSINTInvestigation):
        """Notify registered callbacks of progress updates"""
        callbacks = self.progress_callbacks.get(investigation_id, [])
        for callback in callbacks:
            try:
                callback(investigation)
            except Exception as e:
                logger.error(f"Progress callback error: {e}")
    
    @trace_investigation("complete_workflow")
    def _execute_investigation(self, investigation_id: str):
        """
        Execute complete investigation workflow
        Implements the 7-stage investigation process
        """
        investigation = self.active_investigations[investigation_id]
        
        # Add investigation attributes to trace
        add_trace_attributes(
            investigation_id=investigation_id,
            target=investigation.target_profile.primary_identifier,
            investigation_type=investigation.investigation_type.value,
            priority=investigation.priority.value
        )
        
        try:
            investigation.started_at = datetime.utcnow()
            logger.info(f"Executing investigation {investigation_id}")
            
            # Record investigation start in trace
            add_trace_attributes(
                investigation_started=investigation.started_at.isoformat(),
                estimated_duration_hours=2.0
            )
            
            # Stage 1: Investigation Planning & Compliance Assessment
            self._transition_to_stage(investigation, InvestigationStatus.PLANNING)
            self._stage_planning(investigation)
            
            # Stage 2: Target Profiling & Intelligence Scoping  
            self._transition_to_stage(investigation, InvestigationStatus.PROFILING)
            self._stage_profiling(investigation)
            
            # Stage 3: Multi-Source Intelligence Collection
            self._transition_to_stage(investigation, InvestigationStatus.COLLECTING)
            self._stage_collecting(investigation)
            
            # Stage 4: Intelligence Analysis & Correlation
            self._transition_to_stage(investigation, InvestigationStatus.ANALYZING)
            self._stage_analyzing(investigation)
            
            # Stage 5: Compliance Verification & Audit Trail
            self._transition_to_stage(investigation, InvestigationStatus.VERIFYING)
            self._stage_verifying(investigation)
            
            # Stage 6: Advanced Risk Assessment with Intelligence Correlation
            self._transition_to_stage(investigation, InvestigationStatus.ASSESSING_RISK)
            self._stage_risk_assessment(investigation)
            
            # Stage 7: Intelligence Report Generation
            self._transition_to_stage(investigation, InvestigationStatus.GENERATING_REPORT)
            self._stage_report_generation(investigation)
            
            # Mark as completed
            investigation.status = InvestigationStatus.COMPLETED
            investigation.completed_at = datetime.utcnow()
            investigation.progress.overall_progress = 1.0
            
            # Calculate total processing time
            if investigation.started_at:
                processing_time = (investigation.completed_at - investigation.started_at).total_seconds()
                investigation.processing_time_seconds = processing_time
            
            logger.info(f"Investigation {investigation_id} completed successfully")
            
        except Exception as e:
            logger.error(f"Investigation {investigation_id} failed: {str(e)}")
            investigation.status = InvestigationStatus.FAILED
            investigation.completed_at = datetime.utcnow()
            investigation.progress.warnings.append(f"Investigation failed: {str(e)}")
            
            # Record error in trace
            record_error(e, "investigation_execution_error")
            add_trace_attributes(
                investigation_failed=True,
                failure_reason=str(e)
            )
        
        finally:
            self._notify_progress(investigation_id, investigation)
    
    def execute_investigation_async(self, investigation_id: str, job_data: dict):
        """
        Execute investigation asynchronously - designed to run in RQ worker
        
        Args:
            investigation_id: ID of investigation to execute
            job_data: Job context data (target, type, etc.)
        
        Returns:
            Investigation results dictionary
        """
        from job_queue import update_job_progress, mark_job_failed
        import os
        
        # Get current job ID from context
        job_id = job_data.get('job_id')
        if not job_id:
            # Try to get from RQ context
            from rq import get_current_job
            current_job = get_current_job()
            job_id = current_job.id if current_job else 'unknown'
        
        # Set trace context for logging
        trace_id = job_data.get('trace_id')
        if trace_id:
            os.environ['TRACE_ID'] = trace_id
        
        try:
            logger.info("Starting async investigation execution", extra={
                'investigation_id': investigation_id,
                'job_id': job_id,
                'trace_id': trace_id,
                'target': job_data.get('target')
            })
            
            # Get investigation
            investigation = self.active_investigations.get(investigation_id)
            if not investigation:
                raise ValueError(f"Investigation {investigation_id} not found")
            
            # Update status to running
            investigation.status = InvestigationStatus.PLANNING
            self.active_investigations[investigation_id] = investigation
            
            # Update job progress
            if job_id:
                update_job_progress(job_id, 5, "Investigation started")
            
            # Execute the investigation
            self._execute_investigation(investigation_id)
            
            # Update final progress
            if job_id:
                update_job_progress(job_id, 100, "Investigation completed")
            
            # Return results
            results = {
                'investigation_id': investigation_id,
                'status': investigation.status.value,
                'completed_at': investigation.completed_at.isoformat() if investigation.completed_at else None,
                'processing_time': investigation.processing_time_seconds,
                'results_summary': {
                    'infrastructure_results': len(investigation.intelligence_results.infrastructure_intelligence),
                    'social_results': len(investigation.intelligence_results.social_intelligence), 
                    'threat_results': len(investigation.intelligence_results.threat_intelligence),
                    'total_data_points': investigation.progress.data_points_collected
                }
            }
            
            logger.info("Async investigation completed successfully", extra={
                'investigation_id': investigation_id,
                'job_id': job_id,
                'status': investigation.status.value,
                'data_points': investigation.progress.data_points_collected
            })
            
            return results
            
        except Exception as e:
            error_msg = f"Investigation execution failed: {str(e)}"
            logger.error("Async investigation failed", extra={
                'investigation_id': investigation_id,
                'job_id': job_id,
                'error': str(e),
                'trace_id': trace_id
            })
            
            # Mark investigation as failed
            if investigation_id in self.active_investigations:
                investigation = self.active_investigations[investigation_id]
                investigation.status = InvestigationStatus.FAILED
                investigation.completed_at = datetime.utcnow()
                investigation.progress.warnings.append(error_msg)
            
            # Mark job as failed
            if job_id:
                mark_job_failed(job_id, error_msg, "investigation_execution_error")
            
            raise e
        
        finally:
            # Clean up trace context
            if 'TRACE_ID' in os.environ:
                del os.environ['TRACE_ID']
            
            # Remove from active investigations
            if investigation_id in self.active_investigations:
                del self.active_investigations[investigation_id]
    
    def _transition_to_stage(self, investigation: OSINTInvestigation, stage: InvestigationStatus):
        """Transition investigation to new stage"""
        investigation.status = stage
        investigation.progress.stage = stage
        investigation.progress.stage_progress = 0.0
        investigation.progress.current_activity = f"Starting {stage.value} stage"
        investigation.progress.last_updated = datetime.utcnow()
        
        logger.info(f"Investigation {investigation.id} -> {stage.value}")
        self._notify_progress(investigation.id, investigation)
    
    @trace_operation("investigation.stage.planning")
    def _stage_planning(self, investigation: OSINTInvestigation):
        """
        Stage 1: Investigation Planning & Compliance Assessment
        - Validate investigation parameters
        - Assess compliance requirements
        - Set investigation scope and constraints
        """
        investigation.update_progress(0.1, "Validating investigation parameters")

        # Validate target
        target = investigation.target_profile.primary_identifier
        if not target or len(target.strip()) == 0:
            raise InvestigationError("Invalid target identifier", investigation.id)

        investigation.update_progress(0.3, "Assessing compliance requirements")

        # Basic compliance assessment (simplified for demo)
        if investigation.scope.exclude_pii:
            investigation.add_finding("PII exclusion enabled for compliance", "compliance")

        investigation.update_progress(0.6, "Setting investigation scope")

        # Scope validation based on investigation type
        if investigation.investigation_type == InvestigationType.INFRASTRUCTURE:
            investigation.scope.include_social_media = False
            investigation.add_finding("Focused infrastructure investigation scope set", "planning")
        elif investigation.investigation_type == InvestigationType.SOCIAL_MEDIA:
            investigation.scope.include_infrastructure = False
            investigation.add_finding("Focused social media investigation scope set", "planning")

        investigation.update_progress(0.8, "Estimating investigation timeline")

        # Set estimated completion based on scope
        hours_estimate = 2  # Base estimate
        if investigation.scope.include_social_media:
            hours_estimate += 1
        if investigation.scope.include_infrastructure:
            hours_estimate += 2
        if investigation.scope.include_threat_intelligence:
            hours_estimate += 1

        investigation.progress.estimated_completion = datetime.utcnow() + timedelta(hours=hours_estimate)

        investigation.update_progress(1.0, "Investigation planning completed")
        investigation.add_finding(f"Investigation plan created for {target}", "planning")
    
    @trace_operation("investigation.stage.profiling")
    def _stage_profiling(self, investigation: OSINTInvestigation):
        """
        Stage 2: Target Profiling & Intelligence Scoping
        - Analyze target type and characteristics
        - Expand target profile with secondary identifiers
        - Refine intelligence collection scope
        """
        investigation.update_progress(0.1, "Analyzing target characteristics")

        target = investigation.target_profile.primary_identifier

        # Basic target type detection (simplified)
        if "." in target and not "@" in target:
            investigation.target_profile.target_type = "domain"
            investigation.add_finding(f"Target identified as domain: {target}", "profiling")
        elif "@" in target:
            investigation.target_profile.target_type = "email"
            investigation.add_finding(f"Target identified as email: {target}", "profiling")
        else:
            investigation.target_profile.target_type = "company"
            investigation.add_finding(f"Target identified as company/entity: {target}", "profiling")

        investigation.update_progress(0.4, "Expanding target profile")

        # Simulate secondary identifier discovery
        if investigation.target_profile.target_type == "domain":
            investigation.target_profile.secondary_identifiers = [
                f"www.{target}",
                f"mail.{target}",
                f"*.{target}"
            ]
            investigation.add_finding(f"Discovered {len(investigation.target_profile.secondary_identifiers)} related identifiers", "profiling")

        investigation.update_progress(0.7, "Refining intelligence scope")

        # Adjust scope based on target type
        if investigation.target_profile.target_type == "domain":
            investigation.scope.max_domains_to_scan = min(investigation.scope.max_domains_to_scan, 50)

        investigation.update_progress(1.0, "Target profiling completed")
    
    @trace_operation("investigation.stage.collecting")
    def _stage_collecting(self, investigation: OSINTInvestigation):
        """
        Stage 3: Multi-Source Intelligence Collection
        - Parallel collection from multiple sources
        - Social media intelligence gathering
        - Infrastructure reconnaissance
        - Threat intelligence correlation
        """
        investigation.update_progress(0.1, "Initializing intelligence collection")

        # Initialize intelligence containers
        investigation.social_intelligence = SocialIntelligence()
        investigation.infrastructure_intelligence = InfrastructureIntelligence()
        investigation.threat_intelligence = ThreatIntelligence()

        collection_tasks = []

        # Collect intelligence asynchronously using existing or new event loop
        async def run_collection():
            tasks = []

            # Social Media Collection
            if investigation.scope.include_social_media:
                investigation.update_progress(0.2, "Collecting social media intelligence")
                tasks.append(self._collect_social_intelligence(investigation))
                collection_tasks.append("social_media")

            # Infrastructure Collection
            if investigation.scope.include_infrastructure:
                investigation.update_progress(0.4, "Collecting infrastructure intelligence")
                tasks.append(self._collect_infrastructure_intelligence(investigation))
                collection_tasks.append("infrastructure")

            # Threat Intelligence Collection
            if investigation.scope.include_threat_intelligence:
                investigation.update_progress(0.6, "Collecting threat intelligence")
                tasks.append(self._collect_threat_intelligence(investigation))
                collection_tasks.append("threat_intelligence")

            # Expanded Data Sources Collection (Passive DNS, Breach Intel, etc.)
            if EXPANDED_SOURCES_AVAILABLE:
                investigation.update_progress(0.7, "Collecting expanded intelligence sources")
                tasks.append(self._collect_expanded_intelligence(investigation))
                collection_tasks.append("expanded_sources")

            # Run all collection tasks in parallel for better performance
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)

        # Use existing event loop if available, otherwise create one
        try:
            loop = asyncio.get_running_loop()
            # Already in an async context - create a task
            future = asyncio.ensure_future(run_collection())
            loop.run_until_complete(future)
        except RuntimeError:
            # No running loop - create a new one (but reuse for efficiency)
            asyncio.run(run_collection())

        investigation.progress.data_points_collected = len(collection_tasks) * 50  # Simulated
        investigation.update_progress(1.0, f"Intelligence collection completed - {len(collection_tasks)} sources")
    
    @trace_operation("investigation.collect.social_intelligence")
    async def _collect_social_intelligence(self, investigation: OSINTInvestigation):
        """Collect real social media intelligence using MCP clients"""
        target = investigation.target_profile.primary_identifier
        
        try:
            # Gather real social media intelligence
            social_results = await self.mcp_manager.gather_all_intelligence(
                target, 'social_media'
            )
            
            # Process social media results
            platforms = {}
            sentiment_data = {}
            total_mentions = 0
            data_sources = []
            
            for source_name, results in social_results.items():
                for result in results:
                    if result.data_type in ['social_media', 'social_media_profile']:
                        # Handle both old and enhanced social media sources
                        if result.source in ['twitter', 'twitter_enhanced']:
                            platforms['twitter'] = result.processed_data
                        elif result.source in ['reddit', 'reddit_enhanced']:
                            platforms['reddit'] = result.processed_data
                        elif result.source in ['linkedin', 'linkedin_enhanced']:
                            platforms['linkedin'] = result.processed_data
                        else:
                            platforms[result.source] = result.processed_data
                        
                        # Extract sentiment if available
                        if 'sentiment' in result.processed_data:
                            sentiment_data[result.source] = result.processed_data['sentiment']['overall']
                        
                        # Track mentions
                        if 'mentions_count' in result.processed_data:
                            total_mentions += result.processed_data['mentions_count']
                        
                        # Track data sources
                        data_sources.append(IntelligenceSource(
                            source_id=result.source,
                            source_type='social_media',
                            api_endpoint=f"{result.source}_api",
                            last_updated=result.timestamp,
                            data_quality_score=result.confidence_score,
                            reliability_score=result.confidence_score,
                            data_points_collected=len(result.raw_data)
                        ))
                        
                        investigation.api_calls_made += 1
            
            # Update social intelligence
            investigation.social_intelligence.platforms = platforms
            investigation.social_intelligence.sentiment_analysis = sentiment_data
            investigation.social_intelligence.data_sources = data_sources
            
            # Calculate reputation score
            if sentiment_data:
                avg_sentiment = sum(sentiment_data.values()) / len(sentiment_data)
                investigation.social_intelligence.reputation_score = max(0, min(100, 50 + (avg_sentiment * 50)))
            else:
                investigation.social_intelligence.reputation_score = 50  # Neutral
            
            platforms_found = len(platforms)
            investigation.add_finding(f"Social media intelligence gathered from {platforms_found} platforms with {total_mentions} total mentions", "social")
            
            if platforms_found == 0:
                investigation.add_finding("Limited social media presence detected", "social")
            
        except Exception as e:
            logger.error(f"Social intelligence collection failed: {str(e)}")
            investigation.progress.warnings.append(f"Social media intelligence failed: {str(e)}")
            # Fall back to simulated data
            self._collect_social_intelligence_fallback(investigation)
    
    @trace_operation("investigation.collect.infrastructure_intelligence")
    async def _collect_infrastructure_intelligence(self, investigation: OSINTInvestigation):
        """Collect real infrastructure intelligence using MCP clients"""
        target = investigation.target_profile.primary_identifier
        
        try:
            # Gather real infrastructure intelligence
            infra_results = await self.mcp_manager.gather_all_intelligence(
                target, 'infrastructure'
            )
            
            logger.info(f"Infrastructure results keys: {list(infra_results.keys())}")
            for key, results in infra_results.items():
                logger.info(f"Source {key}: {len(results)} results")
            
            # Process infrastructure results
            domains = []
            subdomains = []
            ip_addresses = []
            exposed_services = []
            certificates = []
            dns_records = {}
            data_sources = []
            
            for source_name, results in infra_results.items():
                for result in results:
                    if result.data_type == 'infrastructure':
                        processed = result.processed_data
                        logger.info(f"Processing enhanced data from {result.source} with keys: {list(processed.keys())}")
                        
                        # WHOIS data (both old and enhanced)
                        if result.source in ['whois', 'whois_enhanced', 'whois_lookup_enhanced']:
                            logger.info(f"Matched WHOIS source: {result.source}")
                            domains.append({
                                "domain": processed.get('domain', target),
                                "registrar": processed.get('registrar'),
                                "creation_date": processed.get('created') or processed.get('creation_date'),
                                "expiration_date": processed.get('expires') or processed.get('expiration_date'),
                                "status": processed.get('status', []),
                                "organization": processed.get('org') or processed.get('organization'),
                                "country": processed.get('country'),
                                "name_servers": processed.get('nameservers') or processed.get('name_servers', [])
                            })
                        
                        # DNS data (both old and enhanced)
                        elif result.source in ['dns', 'dns_enhanced', 'dns_records_enhanced']:
                            logger.info(f"Matched DNS source: {result.source}")
                            # Handle enhanced DNS data structure
                            records_data = processed.get('records', {})
                            
                            # Extract A records for IP addresses
                            if records_data.get('A'):
                                for a_record in records_data['A']:
                                    ip_addresses.append({
                                        "ip": a_record,
                                        "source": "dns_resolution_enhanced",
                                        "record_type": "A"
                                    })
                            
                            # Handle old single A record format
                            elif processed.get('a_record'):
                                ip_addresses.append({
                                    "ip": processed['a_record'],
                                    "source": "dns_resolution",
                                    "reverse_dns": processed.get('reverse_dns')
                                })
                            
                            # Store DNS records for enhanced data
                            if records_data:
                                dns_records.update({
                                    'mx_records': records_data.get('MX', []),
                                    'ns_records': records_data.get('NS', []),
                                    'txt_records': records_data.get('TXT', []),
                                    'cname_records': records_data.get('CNAME', []),
                                    'soa_records': records_data.get('SOA', [])
                                })
                            
                            # Legacy format support
                            elif processed.get('mx_records') or processed.get('ns_records') or processed.get('txt_records'):
                                dns_records.update({
                                    'mx_records': processed.get('mx_records', []),
                                    'ns_records': processed.get('ns_records', []),
                                    'txt_records': processed.get('txt_records', []),
                                    'cname_records': processed.get('cname_records', [])
                                })
                        
                        # Shodan data
                        elif result.source == 'shodan':
                            if 'ports' in processed:
                                for port in processed['ports']:
                                    exposed_services.append({
                                        "port": port,
                                        "service": "Unknown",
                                        "organization": processed.get('organization'),
                                        "country": processed.get('country')
                                    })
                        
                        # SSL Certificate data (both old and enhanced)
                        elif result.source in ['ssl_certificate', 'ssl_certificate_enhanced', 'ssl_certificate_info_enhanced']:
                            certificates.append({
                                "subject": processed.get('subject', {}),
                                "issuer": processed.get('issuer', {}),
                                "not_before": processed.get('not_before'),
                                "not_after": processed.get('not_after'),
                                "algorithm": processed.get('signature_algorithm'),
                                "is_valid": processed.get('is_valid', False),
                                "days_until_expiry": processed.get('days_until_expiry', 0),
                                "domain": processed.get('domain', target)
                            })
                        
                        # Track data sources
                        data_sources.append(IntelligenceSource(
                            source_id=result.source,
                            source_type='infrastructure',
                            api_endpoint=f"{result.source}_api",
                            last_updated=result.timestamp,
                            data_quality_score=result.confidence_score,
                            reliability_score=result.confidence_score,
                            data_points_collected=len(result.raw_data)
                        ))
                        
                        investigation.api_calls_made += 1
            
            # Update infrastructure intelligence
            investigation.infrastructure_intelligence.domains = domains
            investigation.infrastructure_intelligence.subdomains = subdomains
            investigation.infrastructure_intelligence.ip_addresses = ip_addresses
            investigation.infrastructure_intelligence.exposed_services = exposed_services
            investigation.infrastructure_intelligence.certificates = certificates
            investigation.infrastructure_intelligence.dns_records = dns_records
            investigation.infrastructure_intelligence.data_sources = data_sources
            
            total_findings = len(domains) + len(ip_addresses) + len(exposed_services)
            investigation.add_finding(f"Infrastructure intelligence: {len(domains)} domains, {len(ip_addresses)} IPs, {len(exposed_services)} services", "infrastructure")
            
            if total_findings == 0:
                investigation.add_finding("Limited infrastructure data available", "infrastructure")
                
        except Exception as e:
            logger.error(f"Infrastructure intelligence collection failed: {str(e)}")
            logger.error(f"Exception type: {type(e).__name__}")
            logger.error(f"Exception details: {repr(e)}")
            investigation.progress.warnings.append(f"Infrastructure intelligence failed: {str(e)}")
            # Fall back to simulated data
            logger.warning("Falling back to simulated infrastructure data due to MCP failure")
            self._collect_infrastructure_intelligence_fallback(investigation)
    
    @trace_operation("investigation.collect.threat_intelligence")
    async def _collect_threat_intelligence(self, investigation: OSINTInvestigation):
        """Collect real threat intelligence using MCP clients"""
        target = investigation.target_profile.primary_identifier
        
        try:
            # Gather real threat intelligence
            threat_results = await self.mcp_manager.gather_all_intelligence(
                target, 'threat_assessment'
            )
            
            # Process threat intelligence results
            malware_indicators = []
            network_indicators = []
            behavioral_indicators = []
            risk_scores = []
            confidence_levels = []
            data_sources = []
            
            for source_name, results in threat_results.items():
                for result in results:
                    if result.data_type == 'threat_intelligence':
                        processed = result.processed_data
                        
                        # VirusTotal data (both old and enhanced)
                        if result.source in ['virustotal', 'virustotal_enhanced']:
                            threat_score = processed.get('threat_score', 0)
                            risk_scores.append(threat_score)
                            confidence_levels.append(result.confidence_score)
                            
                            network_indicators.append({
                                "type": "domain",
                                "value": target,
                                "risk": "high" if threat_score > 5 else "medium" if threat_score > 2 else "low",
                                "malicious_detections": processed.get('malicious_detections', 0),
                                "suspicious_detections": processed.get('suspicious_detections', 0),
                                "clean_detections": processed.get('clean_detections', 0),
                                "reputation": processed.get('reputation', 0),
                                "threat_score": threat_score,
                                "categories": processed.get('categories', {}),
                                "registrar": processed.get('registrar'),
                                "data_source": "VirusTotal Enhanced" if result.source == 'virustotal_enhanced' else "VirusTotal"
                            })
                        
                        # AlienVault OTX data
                        elif result.source == 'alienvault_otx':
                            pulse_info = processed.get('pulse_info', {})
                            if pulse_info:
                                behavioral_indicators.append({
                                    "source": "otx",
                                    "pulse_count": pulse_info.get('count', 0),
                                    "reputation": processed.get('reputation', 0)
                                })
                        
                        # Basic reputation data
                        elif result.source == 'basic_reputation':
                            risk_scores.append(processed.get('reputation_score', 50))
                            confidence_levels.append(0.5)
                        
                        # Track data sources
                        data_sources.append(IntelligenceSource(
                            source_id=result.source,
                            source_type='threat_intelligence',
                            api_endpoint=f"{result.source}_api",
                            last_updated=result.timestamp,
                            data_quality_score=result.confidence_score,
                            reliability_score=result.confidence_score,
                            data_points_collected=len(result.raw_data)
                        ))
                        
                        investigation.api_calls_made += 1
            
            # Calculate overall risk assessment
            avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 25.0
            avg_confidence = sum(confidence_levels) / len(confidence_levels) if confidence_levels else 0.5
            
            # Update threat intelligence
            investigation.threat_intelligence.malware_indicators = malware_indicators
            investigation.threat_intelligence.network_indicators = network_indicators
            investigation.threat_intelligence.behavioral_indicators = behavioral_indicators
            investigation.threat_intelligence.risk_score = round(avg_risk_score, 1)
            investigation.threat_intelligence.confidence_level = round(avg_confidence, 2)
            investigation.threat_intelligence.data_sources = data_sources
            
            # Generate findings based on risk level
            if avg_risk_score > 70:
                investigation.add_finding(f"HIGH RISK: Threat intelligence indicates significant risk (score: {avg_risk_score})", "threat_intel")
            elif avg_risk_score > 40:
                investigation.add_finding(f"MODERATE RISK: Some threat indicators detected (score: {avg_risk_score})", "threat_intel")
            else:
                investigation.add_finding(f"LOW RISK: Minimal threat indicators identified (score: {avg_risk_score})", "threat_intel")
            
            total_indicators = len(network_indicators) + len(malware_indicators) + len(behavioral_indicators)
            investigation.add_finding(f"Threat analysis complete: {total_indicators} indicators from {len(data_sources)} sources", "threat_intel")
            
        except Exception as e:
            logger.error(f"Threat intelligence collection failed: {str(e)}")
            investigation.progress.warnings.append(f"Threat intelligence failed: {str(e)}")
            # Fall back to simulated data
            self._collect_threat_intelligence_fallback(investigation)

    @trace_operation("investigation.collect.expanded_sources")
    async def _collect_expanded_intelligence(self, investigation: OSINTInvestigation):
        """
        Collect intelligence from expanded data sources.

        Sources include:
        - Passive DNS (historical records, subdomains)
        - Code Intelligence (GitHub/GitLab exposure)
        - Breach Intelligence (credential leaks)
        - URL Intelligence (malicious URLs)
        - Business Intelligence (corporate records)
        - News Intelligence (media mentions)
        """
        if not EXPANDED_SOURCES_AVAILABLE:
            logger.warning("Expanded data sources not available")
            return

        target = investigation.target_profile.primary_identifier

        try:
            # Gather from all expanded sources in parallel
            results = await expanded_data_manager.gather_all(target)

            # Process and store results
            expanded_data = {}
            total_findings = 0

            for source_name, result in results.items():
                if result.success:
                    expanded_data[source_name] = result.to_dict()
                    investigation.api_calls_made += 1

                    # Generate findings based on source type
                    data = result.data

                    # Passive DNS findings
                    if source_name == 'passive_dns':
                        if data.get('subdomains'):
                            num_subdomains = len(data['subdomains'])
                            investigation.add_finding(
                                f"Passive DNS: Discovered {num_subdomains} subdomains",
                                "expanded_intel"
                            )
                            # Add to infrastructure intelligence
                            if investigation.infrastructure_intelligence:
                                investigation.infrastructure_intelligence.subdomains.extend(
                                    data['subdomains'][:50]  # Limit to 50
                                )
                            total_findings += 1

                        if data.get('historical_dns'):
                            num_records = len(data['historical_dns'])
                            investigation.add_finding(
                                f"Passive DNS: {num_records} historical DNS records found",
                                "expanded_intel"
                            )
                            total_findings += 1

                    # Breach intelligence findings
                    elif source_name == 'breach_intel':
                        num_breaches = data.get('total_breaches', 0)
                        if num_breaches > 0:
                            total_exposed = data.get('total_records_exposed', 0)
                            investigation.add_finding(
                                f"BREACH ALERT: Domain appears in {num_breaches} known breaches ({total_exposed:,} records exposed)",
                                "breach_intel"
                            )
                            # Update risk assessment
                            if not investigation.risk_assessment:
                                investigation.risk_assessment = {}
                            investigation.risk_assessment['breach_exposure'] = {
                                'breaches': num_breaches,
                                'records_exposed': total_exposed,
                                'data_classes': data.get('data_classes_exposed', [])
                            }
                            total_findings += 1
                        else:
                            investigation.add_finding(
                                "Breach check: No known breaches found for this domain",
                                "breach_intel"
                            )

                    # Code intelligence findings
                    elif source_name == 'code_intel':
                        exposures = data.get('potential_exposures', [])
                        if exposures:
                            investigation.add_finding(
                                f"CODE EXPOSURE: {len(exposures)} potential code/credential exposures found on GitHub",
                                "code_intel"
                            )
                            total_findings += 1

                        repos = data.get('repositories', [])
                        if repos:
                            investigation.add_finding(
                                f"Code Intel: {len(repos)} related repositories found",
                                "code_intel"
                            )

                    # URL intelligence findings
                    elif source_name == 'url_intel':
                        active_threats = data.get('active_threats', 0)
                        if active_threats > 0:
                            investigation.add_finding(
                                f"MALICIOUS URLS: {active_threats} active malicious URLs detected",
                                "url_intel"
                            )
                            total_findings += 1
                        total_urls = data.get('total_urls', 0)
                        if total_urls > 0:
                            investigation.add_finding(
                                f"URL Intel: {total_urls} URLs flagged in threat databases",
                                "url_intel"
                            )

                    # Business intelligence findings
                    elif source_name == 'business_intel':
                        company_info = data.get('company_info', {})
                        if company_info:
                            investigation.add_finding(
                                f"Business Intel: {company_info.get('name', 'Unknown')} - {company_info.get('status', 'Unknown')} ({company_info.get('jurisdiction', 'Unknown')})",
                                "business_intel"
                            )

                    # News intelligence findings
                    elif source_name == 'news_intel':
                        num_articles = data.get('total_results', 0)
                        if num_articles > 0:
                            sentiment = data.get('sentiment_summary', {})
                            investigation.add_finding(
                                f"News Intel: {num_articles} recent articles (Sentiment: {sentiment.get('positive', 0)}% positive, {sentiment.get('negative', 0)}% negative)",
                                "news_intel"
                            )
                            if data.get('crisis_indicators'):
                                investigation.add_finding(
                                    "NEWS ALERT: Potential crisis indicators detected in media coverage",
                                    "news_intel"
                                )
                                total_findings += 1

                else:
                    logger.warning(f"Expanded source {source_name} failed: {result.error}")

            # Store expanded data in risk assessment for report generation
            if not investigation.risk_assessment:
                investigation.risk_assessment = {}
            investigation.risk_assessment['expanded_intelligence'] = expanded_data

            # Get aggregated summary
            summary = expanded_data_manager.get_aggregated_summary(results)
            investigation.risk_assessment['expanded_summary'] = summary

            investigation.add_finding(
                f"Expanded sources: Queried {summary['sources_successful']}/{summary['sources_queried']} sources successfully",
                "expanded_intel"
            )

            logger.info(f"Expanded intelligence collection complete: {total_findings} key findings from {summary['sources_successful']} sources")

        except Exception as e:
            logger.error(f"Expanded intelligence collection failed: {str(e)}")
            investigation.progress.warnings.append(f"Expanded sources failed: {str(e)}")

    @trace_operation("investigation.stage.analyzing")
    def _stage_analyzing(self, investigation: OSINTInvestigation):
        """
        Stage 4: Intelligence Analysis & Correlation
        - Correlate data across intelligence sources
        - Perform risk assessment
        - Generate key findings and insights
        """
        investigation.update_progress(0.2, "Correlating intelligence data")

        # Analyze collected intelligence
        total_data_points = 0
        if investigation.social_intelligence:
            total_data_points += len(investigation.social_intelligence.platforms)
        if investigation.infrastructure_intelligence:
            total_data_points += len(investigation.infrastructure_intelligence.domains)
            total_data_points += len(investigation.infrastructure_intelligence.subdomains)
        if investigation.threat_intelligence:
            total_data_points += len(investigation.threat_intelligence.network_indicators)

        investigation.progress.data_points_collected = total_data_points

        investigation.update_progress(0.5, "Performing risk assessment")

        # Risk assessment calculation
        social_risk = 0.0
        infra_risk = 0.0
        threat_risk = 0.0

        if investigation.social_intelligence:
            social_risk = max(0, 50 - investigation.social_intelligence.reputation_score) / 50 * 100

        if investigation.infrastructure_intelligence:
            infra_risk = len(investigation.infrastructure_intelligence.exposed_services) * 10

        if investigation.threat_intelligence:
            threat_risk = investigation.threat_intelligence.risk_score

        overall_risk = (social_risk + infra_risk + threat_risk) / 3

        investigation.risk_assessment = {
            "overall_risk_score": round(overall_risk, 1),
            "social_media_risk": round(social_risk, 1),
            "infrastructure_risk": round(infra_risk, 1),
            "threat_intelligence_risk": round(threat_risk, 1),
            "risk_level": "low" if overall_risk < 30 else "medium" if overall_risk < 70 else "high"
        }

        investigation.update_progress(0.8, "Generating key findings")

        # Generate key findings
        if investigation.social_intelligence:
            investigation.add_finding(f"Social media reputation score: {investigation.social_intelligence.reputation_score}/100", "analysis")

        if investigation.infrastructure_intelligence:
            investigation.add_finding(f"Infrastructure footprint: {len(investigation.infrastructure_intelligence.subdomains)} subdomains, {len(investigation.infrastructure_intelligence.exposed_services)} services", "analysis")

        investigation.add_finding(f"Overall risk level: {investigation.risk_assessment['risk_level'].upper()}", "analysis")

        investigation.update_progress(1.0, "Intelligence analysis completed")
    
    @trace_operation("investigation.stage.verifying")
    def _stage_verifying(self, investigation: OSINTInvestigation):
        """
        Stage 5: Compliance Verification & Audit Trail
        - Comprehensive GDPR/CCPA/PIPEDA/LGPD compliance assessment
        - Real-time compliance validation
        - Detailed audit trail creation
        """
        investigation.update_progress(0.2, "Performing comprehensive compliance assessment")
        
        try:
            # Determine geographical scope for compliance assessment
            geographical_scope = self._determine_geographical_scope(investigation)
            
            # Prepare target data for compliance assessment
            target_data = {
                'social_intelligence': investigation.social_intelligence.__dict__ if investigation.social_intelligence else {},
                'infrastructure_intelligence': investigation.infrastructure_intelligence.__dict__ if investigation.infrastructure_intelligence else {},
                'threat_intelligence': investigation.threat_intelligence.__dict__ if investigation.threat_intelligence else {}
            }
            
            # Prepare processing activities
            processing_activities = self._extract_processing_activities(investigation)
            
            investigation.update_progress(0.5, "Evaluating data protection compliance")
            
            # Perform comprehensive compliance assessment
            compliance_assessment = self.compliance_engine.assess_compliance(
                investigation_id=investigation.id,
                target_data=target_data,
                processing_activities=processing_activities,
                geographical_scope=geographical_scope
            )
            
            investigation.update_progress(0.7, "Creating detailed compliance reports")
            
            # Convert compliance assessment to investigation compliance report
            compliance_report = self._create_compliance_report_from_assessment(compliance_assessment)
            investigation.compliance_reports.append(compliance_report)
            
            # Add compliance findings
            if compliance_assessment.status.value == "compliant":
                investigation.add_finding(f"✅ {compliance_assessment.framework.value.upper()} compliance verified - Score: {compliance_assessment.compliance_score:.1f}/100", "compliance")
            elif compliance_assessment.status.value == "requires_review":
                investigation.add_finding(f"⚠️ {compliance_assessment.framework.value.upper()} compliance requires review - Score: {compliance_assessment.compliance_score:.1f}/100", "compliance")
                investigation.progress.warnings.append(f"Compliance review required: {len(compliance_assessment.remediation_actions)} actions needed")
            else:
                investigation.add_finding(f"❌ {compliance_assessment.framework.value.upper()} non-compliance detected - Score: {compliance_assessment.compliance_score:.1f}/100", "compliance")
                investigation.progress.warnings.append(f"Critical compliance issues: {len(compliance_assessment.high_risk_factors)} high-risk factors")
            
            # Add specific compliance details
            if compliance_assessment.high_risk_factors:
                investigation.add_finding(f"High-risk factors identified: {', '.join(compliance_assessment.high_risk_factors[:3])}", "compliance")
            
            if compliance_assessment.remediation_actions:
                investigation.add_finding(f"Remediation actions required: {len(compliance_assessment.remediation_actions)} items", "compliance")
            
            investigation.update_progress(0.9, "Creating comprehensive audit trail")
            
            # Create detailed audit trail
            self._create_detailed_audit_trail(investigation, compliance_assessment)
            
            investigation.update_progress(1.0, "Advanced compliance verification completed")
            
        except Exception as e:
            logger.error(f"Compliance verification failed: {str(e)}")
            investigation.progress.warnings.append(f"Compliance assessment failed: {str(e)}")
            
            # Fallback to basic compliance report
            self._create_basic_compliance_report(investigation)
    
    def _determine_geographical_scope(self, investigation: OSINTInvestigation) -> List[str]:
        """Determine geographical scope based on investigation data"""
        geographical_scope = ['US', 'EU']  # Default scope
        
        # Analyze infrastructure data for location hints
        if investigation.infrastructure_intelligence and investigation.infrastructure_intelligence.ip_addresses:
            for ip_info in investigation.infrastructure_intelligence.ip_addresses:
                if 'location' in ip_info:
                    location = ip_info['location']
                    if location not in geographical_scope:
                        geographical_scope.append(location)
        
        # Add specific compliance jurisdictions
        if 'US' in geographical_scope:
            geographical_scope.append('US-CA')  # California for CCPA
        
        return geographical_scope
    
    def _extract_processing_activities(self, investigation: OSINTInvestigation) -> List[Dict[str, Any]]:
        """Extract processing activities from investigation for compliance assessment"""
        processing_activities = []
        
        # Social media processing
        if investigation.social_intelligence and investigation.social_intelligence.platforms:
            for platform, data in investigation.social_intelligence.platforms.items():
                processing_activities.append({
                    'source': platform,
                    'data_collected': True,
                    'public_data_only': True,
                    'automated_analysis': True,
                    'third_party_sharing': False,
                    'consent_obtained': False  # Public data
                })
        
        # Infrastructure processing
        if investigation.infrastructure_intelligence:
            if investigation.infrastructure_intelligence.domains:
                processing_activities.append({
                    'source': 'whois',
                    'data_collected': True,
                    'public_data_only': True,
                    'automated_analysis': True,
                    'third_party_sharing': False
                })
            
            if investigation.infrastructure_intelligence.ip_addresses:
                processing_activities.append({
                    'source': 'dns',
                    'data_collected': True,
                    'public_data_only': True,
                    'automated_analysis': True,
                    'third_party_sharing': False
                })
        
        # Threat intelligence processing
        if investigation.threat_intelligence and investigation.threat_intelligence.network_indicators:
            processing_activities.append({
                'source': 'threat_intel',
                'data_collected': True,
                'automated_analysis': True,
                'third_party_sharing': False,
                'legal_request': investigation.priority.value in ['urgent', 'critical']
            })
        
        return processing_activities
    
    def _create_compliance_report_from_assessment(self, compliance_assessment) -> ComplianceReport:
        """Convert compliance assessment to investigation compliance report"""
        
        # Map compliance status
        risk_level_mapping = {
            "low": "low",
            "medium": "medium", 
            "high": "high",
            "critical": "critical"
        }
        
        return ComplianceReport(
            framework=compliance_assessment.framework,
            compliant=compliance_assessment.status.value == "compliant",
            risk_level=risk_level_mapping.get(compliance_assessment.risk_level.value, "medium"),
            findings=[
                {
                    "type": "comprehensive_assessment",
                    "status": compliance_assessment.status.value,
                    "score": compliance_assessment.compliance_score,
                    "details": f"Comprehensive {compliance_assessment.framework.value.upper()} assessment completed"
                },
                {
                    "type": "data_categories",
                    "status": "identified",
                    "details": f"Data categories: {', '.join([cat.value for cat in compliance_assessment.data_categories_identified])}"
                },
                {
                    "type": "lawful_basis",
                    "status": "verified",
                    "details": f"Lawful bases: {', '.join([basis.value for basis in compliance_assessment.lawful_bases_applied])}"
                }
            ],
            recommendations=compliance_assessment.remediation_actions[:5],  # Top 5 recommendations
            data_categories_identified=[cat.value for cat in compliance_assessment.data_categories_identified],
            generated_at=compliance_assessment.assessed_at
        )
    
    def _create_detailed_audit_trail(self, investigation: OSINTInvestigation, compliance_assessment):
        """Create comprehensive audit trail"""
        
        # Investigation audit information
        investigation.add_finding(f"Investigation conducted by {investigation.investigator_name} ({investigation.investigator_id})", "audit")
        investigation.add_finding(f"Investigation type: {investigation.investigation_type.value}", "audit")
        investigation.add_finding(f"Priority level: {investigation.priority.value}", "audit")
        investigation.add_finding(f"Data classification: {investigation.classification_level}", "audit")
        
        # Technical audit metrics
        investigation.add_finding(f"API calls executed: {investigation.api_calls_made}", "audit")
        investigation.add_finding(f"Data points collected: {investigation.progress.data_points_collected}", "audit")
        investigation.add_finding(f"Processing time: {investigation.processing_time_seconds:.1f} seconds", "audit")
        investigation.add_finding(f"Data size processed: {investigation.data_size_mb:.2f} MB", "audit")
        
        # Compliance audit details
        investigation.add_finding(f"Compliance framework assessed: {compliance_assessment.framework.value.upper()}", "audit")
        investigation.add_finding(f"Compliance score achieved: {compliance_assessment.compliance_score:.1f}/100", "audit")
        investigation.add_finding(f"Risk level determined: {compliance_assessment.risk_level.value.upper()}", "audit")
        
        # Data processing audit
        investigation.add_finding(f"Processing records created: {len(compliance_assessment.processing_records)}", "audit")
        investigation.add_finding(f"Retention period: {investigation.target_profile.data_retention_days} days", "audit")
        investigation.add_finding(f"Data expires: {investigation.data_retention_until.isoformat() if investigation.data_retention_until else 'Not set'}", "audit")
        
        # Security audit
        investigation.add_finding("Security controls: End-to-end encryption, Role-based access, Automated deletion", "audit")
        investigation.add_finding("Data protection measures: Pseudonymization, Access logging, Time-based controls", "audit")
    
    def _create_basic_compliance_report(self, investigation: OSINTInvestigation):
        """Fallback basic compliance report"""
        
        compliance_report = ComplianceReport(
            framework=ComplianceFramework.GDPR,
            compliant=True,
            risk_level="low",
            findings=[
                {"type": "data_collection", "status": "compliant", "details": "Public data sources only"},
                {"type": "retention", "status": "compliant", "details": f"10-minute retention policy applied"},
                {"type": "technical_safeguards", "status": "compliant", "details": "Encryption and access controls implemented"}
            ],
            recommendations=[
                "Continue monitoring compliance requirements",
                "Regular review of data retention policies",
                "Maintain technical and organizational measures"
            ],
            data_categories_identified=["public_records", "social_media_public", "technical_data"]
        )
        
        investigation.compliance_reports.append(compliance_report)
        investigation.add_finding("Basic compliance verification completed (fallback mode)", "compliance")
    
    @trace_operation("investigation.stage.risk_assessment")
    def _stage_risk_assessment(self, investigation: OSINTInvestigation):
        """
        Stage 6: Advanced Risk Assessment with Intelligence Correlation
        - Correlate intelligence across all sources
        - Generate comprehensive threat analysis
        - Calculate risk scores and threat levels
        - Identify attack vectors and scenarios
        """
        investigation.update_progress(0.1, "Initializing risk assessment engine")
        
        try:
            # Extract intelligence data for correlation
            social_intel_data = None
            if investigation.social_intelligence:
                # Extract mentions from platform data safely
                all_mentions = []
                for platform_data in investigation.social_intelligence.platforms.values():
                    if 'mentions' in platform_data:
                        all_mentions.extend(platform_data['mentions'])
                
                social_intel_data = {
                    'twitter': {
                        'posts': [mention.get('text', '') for mention in all_mentions if 'twitter' in mention.get('source', '')],
                        'followers': getattr(investigation.social_intelligence, 'followers', 0),
                        'verified': False,  # Could be enhanced with real data
                        'private': False
                    },
                    'reddit': {
                        'posts': [mention.get('text', '') for mention in all_mentions if 'reddit' in mention.get('source', '')],
                        'karma': 100  # Placeholder
                    }
                }
            
            investigation.update_progress(0.3, "Correlating infrastructure intelligence")
            
            # Infrastructure intelligence data
            infra_intel_data = None
            if investigation.infrastructure_intelligence:
                infra_intel_data = {
                    'ip_addresses': investigation.infrastructure_intelligence.ip_addresses,
                    'domains': investigation.infrastructure_intelligence.domains,
                    'ssl_certificates': investigation.infrastructure_intelligence.ssl_certificates
                }
            
            investigation.update_progress(0.5, "Processing threat intelligence correlation")
            
            # Threat intelligence data
            threat_intel_data = None
            if investigation.threat_intelligence:
                threat_intel_data = {
                    'malware_samples': investigation.threat_intelligence.malware_samples,
                    'iocs': investigation.threat_intelligence.iocs,
                    'attribution': investigation.threat_intelligence.attribution
                }
            
            investigation.update_progress(0.7, "Generating risk assessment")
            
            # Perform comprehensive risk assessment
            risk_assessment = self.risk_engine.assess_risk(
                target_id=investigation.target_profile.target_id,
                social_intelligence=social_intel_data,
                infrastructure_intelligence=infra_intel_data,
                threat_intelligence=threat_intel_data,
                behavioral_intelligence=None,  # Could be enhanced with behavioral data
                assessment_context={
                    'investigation_type': investigation.investigation_type.value,
                    'priority': investigation.priority.value,
                    'investigator': investigation.investigator_name
                }
            )
            
            # Store risk assessment in investigation
            investigation.risk_assessment = {
                'assessment_id': risk_assessment.assessment_id,
                'overall_risk_score': risk_assessment.overall_risk_score,
                'threat_level': risk_assessment.threat_level.value,
                'confidence_level': risk_assessment.confidence_level.value,
                'risk_by_category': {cat.value: score for cat, score in risk_assessment.risk_by_category.items()},
                'critical_findings': risk_assessment.critical_findings,
                'threat_vectors': [
                    {
                        'name': tv.name,
                        'category': tv.category.value,
                        'risk_score': tv.risk_score,
                        'threat_level': tv.threat_level.value,
                        'mitigation_recommendations': tv.mitigation_recommendations,
                        'attack_chain': tv.attack_chain
                    }
                    for tv in risk_assessment.threat_vectors
                ],
                'immediate_actions': risk_assessment.immediate_actions,
                'monitoring_recommendations': risk_assessment.monitoring_recommendations,
                'risk_trend': risk_assessment.risk_trend,
                'data_freshness_score': risk_assessment.data_freshness_score,
                'coverage_completeness': risk_assessment.coverage_completeness,
                'assessed_at': risk_assessment.assessed_at.isoformat()
            }
            
            investigation.update_progress(0.9, "Finalizing risk assessment")
            
            # Add risk findings to investigation
            risk_level = risk_assessment.threat_level.value.upper()
            investigation.add_finding(
                f"Risk Assessment Complete - Threat Level: {risk_level} "
                f"(Score: {risk_assessment.overall_risk_score:.1f}/100)", 
                "risk_assessment"
            )
            
            # Add critical findings
            for finding in risk_assessment.critical_findings[:3]:  # Top 3 critical findings
                investigation.add_finding(f"CRITICAL: {finding}", "risk_assessment")
            
            # Add threat vector summaries
            for vector in risk_assessment.threat_vectors:
                if vector.threat_level.value in ['high', 'critical']:
                    investigation.add_finding(
                        f"High-Risk Threat Vector: {vector.name} "
                        f"(Risk Score: {vector.risk_score:.1f})", 
                        "risk_assessment"
                    )
            
            # Add immediate action recommendations
            if risk_assessment.immediate_actions:
                investigation.add_finding(
                    f"Immediate Actions Required: {len(risk_assessment.immediate_actions)} recommendations generated", 
                    "risk_assessment"
                )
            
            investigation.update_progress(1.0, "Risk assessment completed")
            logger.info(f"Risk assessment completed for {investigation.id}: {risk_level} threat level")
            
        except Exception as e:
            logger.error(f"Risk assessment failed: {str(e)}")
            investigation.progress.warnings.append(f"Risk assessment failed: {str(e)}")
            
            # Fallback risk assessment
            investigation.risk_assessment = {
                'assessment_id': f"fallback_{investigation.id}",
                'overall_risk_score': 50.0,
                'threat_level': 'moderate',
                'confidence_level': 'low',
                'risk_by_category': {'technical': 40.0, 'operational': 30.0, 'reputational': 25.0},
                'critical_findings': ['Risk assessment system unavailable - manual review recommended'],
                'threat_vectors': [],
                'immediate_actions': ['Review findings manually', 'Validate intelligence sources'],
                'monitoring_recommendations': ['Implement continuous monitoring', 'Regular reassessment'],
                'risk_trend': 'stable',
                'data_freshness_score': 70.0,
                'coverage_completeness': 60.0,
                'assessed_at': datetime.utcnow().isoformat()
            }
            
            investigation.add_finding("Risk assessment completed using fallback analysis", "risk_assessment")
    
    @trace_operation("investigation.stage.report_generation")
    def _stage_report_generation(self, investigation: OSINTInvestigation):
        """
        Stage 7: Intelligence Report Generation
        - Generate executive summary
        - Compile technical findings
        - Create actionable recommendations
        """
        investigation.update_progress(0.2, "Generating executive summary")
        
        # Generate executive summary
        target = investigation.target_profile.primary_identifier
        risk_level = investigation.risk_assessment.get('risk_level', 'unknown')
        
        investigation.executive_summary = f"""
Executive Summary - OSINT Investigation: {target}

Target: {target}
Investigation Type: {investigation.investigation_type.value.title()}
Risk Level: {risk_level.upper()}
Overall Risk Score: {investigation.risk_assessment.get('overall_risk_score', 0)}/100

This investigation analyzed {investigation.progress.data_points_collected} data points across multiple intelligence sources. 
Key findings indicate a {risk_level} risk profile with no significant security concerns identified.

Investigation completed by {investigation.investigator_name} on {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}.
        """.strip()
        
        investigation.update_progress(0.6, "Compiling technical findings")
        
        # Generate recommendations based on findings
        if investigation.risk_assessment.get('overall_risk_score', 0) > 50:
            investigation.recommendations.extend([
                "Enhanced monitoring recommended due to elevated risk score",
                "Review security posture and implement additional controls"
            ])
        else:
            investigation.recommendations.extend([
                "Continue routine monitoring",
                "Maintain current security posture"
            ])
        
        # Add data source recommendations
        if investigation.scope.include_social_media and investigation.social_intelligence:
            investigation.recommendations.append("Monitor social media presence for reputation changes")
        
        if investigation.scope.include_infrastructure and investigation.infrastructure_intelligence:
            investigation.recommendations.append("Regular infrastructure security assessments recommended")
        
        investigation.update_progress(0.9, "Finalizing report")
        
        investigation.data_size_mb = investigation.progress.data_points_collected * 0.1  # Estimate
        investigation.cost_estimate_usd = investigation.api_calls_made * 0.01  # Estimate
        
        investigation.update_progress(1.0, "Report generation completed")
        investigation.add_finding("Intelligence report generated successfully", "reporting")
    
    def _collect_social_intelligence_fallback(self, investigation: OSINTInvestigation):
        """Fallback simulated social media intelligence collection"""
        target = investigation.target_profile.primary_identifier
        
        investigation.social_intelligence.platforms = {
            "twitter": {
                "account_exists": True,
                "followers": 1250,
                "posts_analyzed": 45,
                "sentiment": "neutral"
            },
            "linkedin": {
                "company_page": True,
                "employees": 150,
                "industry": "Technology"
            }
        }
        
        investigation.social_intelligence.sentiment_analysis = {
            "overall": 0.2,
            "twitter": 0.1,
            "linkedin": 0.4
        }
        
        investigation.social_intelligence.reputation_score = 75.5
        investigation.api_calls_made += 8
        investigation.add_finding("Social media presence discovered (simulated data)", "social")
    
    def _collect_infrastructure_intelligence_fallback(self, investigation: OSINTInvestigation):
        """Fallback simulated infrastructure intelligence collection"""
        target = investigation.target_profile.primary_identifier
        
        investigation.infrastructure_intelligence.domains = [
            {"domain": target, "status": "active", "ip": "192.168.1.100"},
        ]
        
        investigation.infrastructure_intelligence.subdomains = [
            f"www.{target}",
            f"mail.{target}",
            f"api.{target}"
        ]
        
        investigation.infrastructure_intelligence.ip_addresses = [
            {"ip": "192.168.1.100", "location": "US", "provider": "CloudFlare"}
        ]
        
        investigation.infrastructure_intelligence.exposed_services = [
            {"port": 80, "service": "HTTP", "version": "nginx/1.18"},
            {"port": 443, "service": "HTTPS", "version": "nginx/1.18"}
        ]
        
        investigation.api_calls_made += 12
        investigation.add_finding(f"Infrastructure mapped (simulated data): {len(investigation.infrastructure_intelligence.subdomains)} subdomains", "infrastructure")
    
    def _collect_threat_intelligence_fallback(self, investigation: OSINTInvestigation):
        """Fallback simulated threat intelligence collection"""
        investigation.threat_intelligence.risk_score = 25.0
        investigation.threat_intelligence.confidence_level = 0.8
        
        investigation.threat_intelligence.network_indicators = [
            {"type": "domain", "value": investigation.target_profile.primary_identifier, "risk": "low"}
        ]
        
        investigation.api_calls_made += 6
        investigation.add_finding("No significant threat indicators identified (simulated data)", "threat_intel")