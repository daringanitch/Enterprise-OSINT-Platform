"""
OSINT Investigation Service using MCP servers
"""
import asyncio
import uuid
from typing import Dict, Any, List
from datetime import datetime
import logging

from app.services.mcp_client import MCPClient

logger = logging.getLogger(__name__)


class OSINTInvestigationService:
    """Service for running OSINT investigations using MCP servers"""
    
    def __init__(self):
        self.mcp_client = MCPClient()
    
    async def run_investigation(self, target: str, investigation_type: str = "comprehensive") -> Dict[str, Any]:
        """Run a comprehensive OSINT investigation on a target"""
        investigation_id = str(uuid.uuid4())
        start_time = datetime.now()
        
        logger.info(f"Starting {investigation_type} investigation for {target} (ID: {investigation_id})")
        
        # Initialize results structure
        results = {
            "id": investigation_id,
            "target": target,
            "investigation_type": investigation_type,
            "status": "processing",
            "created_at": start_time.timestamp(),
            "findings": {
                "infrastructure": {},
                "social_media": {},
                "threat_intelligence": {}
            },
            "risk_score": None,
            "summary": None,
            "errors": []
        }
        
        try:
            # Determine what type of target we have
            target_type = self._determine_target_type(target)
            
            # Run different investigations based on type
            if investigation_type == "comprehensive":
                await self._run_comprehensive_investigation(target, target_type, results)
            elif investigation_type == "infrastructure":
                await self._run_infrastructure_investigation(target, target_type, results)
            elif investigation_type == "social_media":
                await self._run_social_media_investigation(target, target_type, results)
            elif investigation_type == "threat_assessment":
                await self._run_threat_investigation(target, target_type, results)
            else:
                results["errors"].append(f"Unknown investigation type: {investigation_type}")
            
            # Calculate overall risk score
            results["risk_score"] = self._calculate_risk_score(results["findings"])
            
            # Generate summary
            results["summary"] = self._generate_summary(results["findings"], results["risk_score"])
            
            # Update status
            results["status"] = "completed" if not results["errors"] else "completed_with_errors"
            results["completed_at"] = datetime.now().timestamp()
            results["duration_seconds"] = results["completed_at"] - results["created_at"]
            
        except Exception as e:
            logger.error(f"Investigation failed: {e}")
            results["status"] = "failed"
            results["errors"].append(str(e))
        
        return results
    
    def _determine_target_type(self, target: str) -> str:
        """Determine the type of target (domain, IP, username, etc.)"""
        # Simple heuristics - can be improved
        if "@" not in target and "." in target:
            # Check if it's an IP address
            parts = target.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return "ip"
            else:
                return "domain"
        elif "@" in target:
            return "email"
        else:
            return "username"
    
    async def _run_comprehensive_investigation(self, target: str, target_type: str, results: Dict[str, Any]):
        """Run all available investigations"""
        tasks = [
            self._run_infrastructure_investigation(target, target_type, results),
            self._run_social_media_investigation(target, target_type, results),
            self._run_threat_investigation(target, target_type, results)
        ]
        
        await asyncio.gather(*tasks, return_exceptions=True)
    
    async def _run_infrastructure_investigation(self, target: str, target_type: str, results: Dict[str, Any]):
        """Run infrastructure-related investigations"""
        if target_type not in ["domain", "ip"]:
            logger.info(f"Skipping infrastructure investigation for {target_type} target")
            return
        
        try:
            # Run multiple infrastructure tools in parallel
            tasks = []
            
            if target_type == "domain":
                tasks.extend([
                    ("whois", self.mcp_client.whois_lookup(target)),
                    ("dns", self.mcp_client.dns_records(target)),
                    ("ssl", self.mcp_client.call_tool("infrastructure", "ssl_certificate_info", {"domain": target})),
                    ("subdomains", self.mcp_client.call_tool("infrastructure", "subdomain_enumeration", {"domain": target}))
                ])
            
            # Execute all tasks
            for name, task in tasks:
                try:
                    result = await task
                    if result.get("success", True):
                        results["findings"]["infrastructure"][name] = result.get("data", result)
                    else:
                        results["errors"].append(f"Infrastructure {name} failed: {result.get('error', 'Unknown error')}")
                except Exception as e:
                    results["errors"].append(f"Infrastructure {name} error: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Infrastructure investigation failed: {e}")
            results["errors"].append(f"Infrastructure investigation failed: {str(e)}")
    
    async def _run_social_media_investigation(self, target: str, target_type: str, results: Dict[str, Any]):
        """Run social media investigations"""
        try:
            tasks = []
            
            # For domains/companies, search for mentions
            if target_type == "domain":
                tasks.append(("reddit_mentions", self.mcp_client.search_reddit(target)))
                # Extract company name from domain for LinkedIn
                company_name = target.split(".")[0]
                tasks.append(("linkedin_company", self.mcp_client.call_tool(
                    "social_media", "analyze_linkedin_company", {"company": company_name}
                )))
            
            # For usernames, analyze profiles
            elif target_type == "username":
                tasks.append(("twitter_profile", self.mcp_client.analyze_twitter_profile(target)))
                tasks.append(("reddit_activity", self.mcp_client.search_reddit(f"author:{target}", limit=20)))
            
            # Execute all tasks
            for name, task in tasks:
                try:
                    result = await task
                    if result.get("success", True):
                        results["findings"]["social_media"][name] = result.get("data", result)
                    else:
                        results["errors"].append(f"Social media {name} failed: {result.get('error', 'Unknown error')}")
                except Exception as e:
                    results["errors"].append(f"Social media {name} error: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Social media investigation failed: {e}")
            results["errors"].append(f"Social media investigation failed: {str(e)}")
    
    async def _run_threat_investigation(self, target: str, target_type: str, results: Dict[str, Any]):
        """Run threat intelligence investigations"""
        try:
            tasks = []
            
            # Run threat assessment for any target type
            tasks.append(("threat_assessment", self.mcp_client.threat_assessment(target, target_type)))
            
            # Check for breaches
            tasks.append(("breach_check", self.mcp_client.call_tool(
                "threat_intel", "breach_check", {"target": target}
            )))
            
            # Check reputation
            tasks.append(("reputation", self.mcp_client.call_tool(
                "threat_intel", "reputation_check", {"target": target}
            )))
            
            # Execute all tasks
            for name, task in tasks:
                try:
                    result = await task
                    if result.get("success", True):
                        results["findings"]["threat_intelligence"][name] = result.get("data", result)
                    else:
                        results["errors"].append(f"Threat intel {name} failed: {result.get('error', 'Unknown error')}")
                except Exception as e:
                    results["errors"].append(f"Threat intel {name} error: {str(e)}")
                    
        except Exception as e:
            logger.error(f"Threat investigation failed: {e}")
            results["errors"].append(f"Threat investigation failed: {str(e)}")
    
    def _calculate_risk_score(self, findings: Dict[str, Any]) -> int:
        """Calculate overall risk score based on findings"""
        risk_score = 0
        risk_factors = 0
        
        # Check threat intelligence findings
        threat_findings = findings.get("threat_intelligence", {})
        
        if threat_assessment := threat_findings.get("threat_assessment", {}).get("data"):
            if threat_level := threat_assessment.get("threat_level"):
                if threat_level == "critical":
                    risk_score += 90
                elif threat_level == "high":
                    risk_score += 70
                elif threat_level == "medium":
                    risk_score += 50
                elif threat_level == "low":
                    risk_score += 20
                risk_factors += 1
        
        if breach_data := threat_findings.get("breach_check", {}).get("data"):
            if breach_data.get("breaches_found", 0) > 0:
                risk_score += min(30 + (breach_data.get("breaches_found", 0) * 10), 80)
                risk_factors += 1
        
        if reputation_data := threat_findings.get("reputation", {}).get("data"):
            if reputation_data.get("malicious", False):
                risk_score += 85
                risk_factors += 1
            elif reputation_data.get("suspicious", False):
                risk_score += 50
                risk_factors += 1
        
        # Check infrastructure findings
        infra_findings = findings.get("infrastructure", {})
        
        if ssl_data := infra_findings.get("ssl", {}).get("data"):
            if ssl_data.get("grade", "F") in ["F", "E"]:
                risk_score += 40
                risk_factors += 1
        
        # Calculate average
        if risk_factors > 0:
            return min(int(risk_score / risk_factors), 100)
        else:
            return 0
    
    def _generate_summary(self, findings: Dict[str, Any], risk_score: int) -> str:
        """Generate a summary of the investigation findings"""
        summary_parts = []
        
        # Risk level
        if risk_score >= 80:
            summary_parts.append("CRITICAL RISK: Immediate attention required.")
        elif risk_score >= 60:
            summary_parts.append("HIGH RISK: Significant security concerns identified.")
        elif risk_score >= 40:
            summary_parts.append("MEDIUM RISK: Some security issues found.")
        elif risk_score >= 20:
            summary_parts.append("LOW RISK: Minor concerns identified.")
        else:
            summary_parts.append("MINIMAL RISK: No significant issues found.")
        
        # Key findings
        key_findings = []
        
        # Check for breaches
        if breach_data := findings.get("threat_intelligence", {}).get("breach_check", {}).get("data"):
            if breaches := breach_data.get("breaches_found", 0):
                key_findings.append(f"Found in {breaches} data breach(es)")
        
        # Check reputation
        if reputation := findings.get("threat_intelligence", {}).get("reputation", {}).get("data"):
            if reputation.get("malicious"):
                key_findings.append("Flagged as malicious by threat intelligence")
            elif reputation.get("suspicious"):
                key_findings.append("Flagged as suspicious")
        
        # Check SSL
        if ssl_data := findings.get("infrastructure", {}).get("ssl", {}).get("data"):
            if ssl_data.get("grade", "F") in ["F", "E"]:
                key_findings.append(f"Poor SSL configuration (Grade: {ssl_data.get('grade')})")
        
        if key_findings:
            summary_parts.append("Key findings: " + "; ".join(key_findings))
        
        return " ".join(summary_parts)