#!/usr/bin/env python3
"""
AI-Powered Intelligence Analyzer MCP Server
Uses OpenAI GPT-4 to enhance OSINT analysis and generate insights
"""

import os
import json
import asyncio
import aiohttp
from datetime import datetime
from typing import Dict, List, Any, Optional
import openai
from openai import AsyncOpenAI

class AIIntelligenceAnalyzer:
    """AI-powered analysis of OSINT data"""
    
    def __init__(self):
        self.has_api_key = os.getenv('OPENAI_API_KEY') is not None
        if self.has_api_key:
            self.client = AsyncOpenAI(api_key=os.getenv('OPENAI_API_KEY'))
        else:
            self.client = None
        self.model = "gpt-4-turbo-preview"
        
    async def analyze_threat_actor(self, profile_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive threat actor profile using AI"""
        
        if not self.has_api_key:
            return {'error': 'OpenAI API key not configured'}
        
        prompt = f"""
        Analyze the following threat intelligence data and create a comprehensive threat actor profile:
        
        Data: {json.dumps(profile_data, indent=2)}
        
        Please provide:
        1. Threat Actor Classification (APT group, cybercriminal, hacktivist, etc.)
        2. Likely Motivations and Objectives
        3. Technical Sophistication Level (1-10 scale with justification)
        4. Probable Geographic Origin (with confidence level)
        5. TTPs (Tactics, Techniques, and Procedures) based on MITRE ATT&CK
        6. Infrastructure Patterns
        7. Potential Targets
        8. Risk Assessment
        9. Recommended Defensive Measures
        10. Intelligence Gaps and Collection Requirements
        
        Format the response as a structured JSON object.
        """
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a senior threat intelligence analyst with expertise in APT groups, cybercrime, and threat actor profiling."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                response_format={"type": "json_object"}
            )
            
            analysis = json.loads(response.choices[0].message.content)
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'ai_model': self.model,
                'analysis': analysis,
                'confidence': self._calculate_confidence(profile_data)
            }
            
        except Exception as e:
            return {'error': str(e)}

    async def correlate_indicators(self, indicators: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Use AI to find patterns and correlations between indicators"""
        
        prompt = f"""
        Analyze these threat indicators and identify patterns, correlations, and relationships:
        
        Indicators: {json.dumps(indicators, indent=2)}
        
        Provide:
        1. Identified Patterns (temporal, geographic, technical)
        2. Indicator Relationships (graph of connections)
        3. Campaign Attribution (if applicable)
        4. Timeline of Activity
        5. Infrastructure Clustering
        6. Predicted Next Actions
        7. Hidden Connections
        8. Confidence Levels for Each Finding
        
        Look for:
        - Shared infrastructure
        - Common TTPs
        - Temporal patterns
        - Geographic clustering
        - Technical similarities
        - Behavioral patterns
        
        Format as structured JSON with clear relationships.
        """
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert in threat intelligence correlation and pattern recognition. You excel at finding hidden connections in data."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4,
                response_format={"type": "json_object"}
            )
            
            correlations = json.loads(response.choices[0].message.content)
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'total_indicators': len(indicators),
                'correlations': correlations,
                'visualization_data': self._prepare_graph_data(correlations)
            }
            
        except Exception as e:
            return {'error': str(e)}

    async def generate_executive_summary(self, investigation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary of investigation findings"""
        
        prompt = f"""
        Create an executive summary of this OSINT investigation for C-level executives:
        
        Investigation Data: {json.dumps(investigation_data, indent=2)}
        
        The summary should include:
        1. Executive Overview (2-3 sentences)
        2. Key Findings (bullet points)
        3. Business Impact Assessment
        4. Risk Level and Justification
        5. Recommended Actions (prioritized)
        6. Resource Requirements
        7. Timeline for Remediation
        8. Success Metrics
        
        Make it concise, business-focused, and actionable. Avoid technical jargon.
        Format as structured JSON.
        """
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a senior security executive who translates technical findings into business language for C-suite executives."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3,
                response_format={"type": "json_object"}
            )
            
            summary = json.loads(response.choices[0].message.content)
            
            # Generate risk score
            risk_score = await self._calculate_risk_score(investigation_data)
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'executive_summary': summary,
                'risk_score': risk_score,
                'report_classification': self._classify_report(risk_score)
            }
            
        except Exception as e:
            return {'error': str(e)}

    async def predict_attack_vectors(self, target_profile: Dict[str, Any]) -> Dict[str, Any]:
        """Predict likely attack vectors based on target profile"""
        
        prompt = f"""
        Based on this target profile, predict the most likely attack vectors and threat scenarios:
        
        Target Profile: {json.dumps(target_profile, indent=2)}
        
        Analyze and provide:
        1. Top 5 Most Likely Attack Vectors (with probability %)
        2. Threat Actor Types Most Likely to Target
        3. Critical Vulnerabilities to Exploit
        4. Social Engineering Scenarios
        5. Supply Chain Risks
        6. Insider Threat Potential
        7. Timeline of Predicted Attack Phases
        8. Early Warning Indicators
        9. Defensive Priorities
        10. Monitoring Requirements
        
        Base predictions on current threat landscape and historical attack patterns.
        Format as structured JSON.
        """
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a threat modeling expert who specializes in predicting attack scenarios based on organizational profiles and current threat intelligence."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.5,
                response_format={"type": "json_object"}
            )
            
            predictions = json.loads(response.choices[0].message.content)
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'predictions': predictions,
                'model_confidence': 0.85,  # Model confidence level
                'data_quality_score': self._assess_data_quality(target_profile)
            }
            
        except Exception as e:
            return {'error': str(e)}

    async def analyze_social_media_sentiment(self, social_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze sentiment and extract intelligence from social media data"""
        
        prompt = f"""
        Analyze this social media data for threat intelligence and sentiment:
        
        Social Media Data: {json.dumps(social_data[:50], indent=2)}  # Limit to 50 posts
        
        Extract:
        1. Overall Sentiment Analysis (positive/negative/neutral with percentages)
        2. Threat Indicators (any mentions of attacks, vulnerabilities, etc.)
        3. Key Topics and Themes
        4. Influential Accounts (high engagement or authority)
        5. Temporal Patterns (posting times, frequency)
        6. Geographic Distribution (if location data available)
        7. Network Analysis (who interacts with whom)
        8. Potential Disinformation Campaigns
        9. Early Warning Signals
        10. Recommended Monitoring Keywords
        
        Focus on security-relevant intelligence.
        Format as structured JSON.
        """
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a social media intelligence analyst specializing in threat detection and sentiment analysis for security purposes."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4,
                response_format={"type": "json_object"}
            )
            
            analysis = json.loads(response.choices[0].message.content)
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'total_posts_analyzed': len(social_data),
                'analysis': analysis,
                'threat_level': self._calculate_social_threat_level(analysis)
            }
            
        except Exception as e:
            return {'error': str(e)}

    async def generate_mitre_mapping(self, attack_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map observed behaviors to MITRE ATT&CK framework"""
        
        prompt = f"""
        Map the following attack data to the MITRE ATT&CK framework:
        
        Attack Data: {json.dumps(attack_data, indent=2)}
        
        Provide:
        1. Tactics Used (with IDs)
        2. Techniques Identified (with IDs and descriptions)
        3. Sub-techniques (if applicable)
        4. Confidence Level for Each Mapping
        5. Evidence Supporting Each Mapping
        6. Potential False Positives
        7. Defensive Recommendations per Technique
        8. Detection Opportunities
        9. Similar APT Groups Using These TTPs
        10. Kill Chain Progression
        
        Be specific with MITRE ATT&CK IDs (e.g., T1566.001).
        Format as structured JSON.
        """
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a MITRE ATT&CK framework expert who maps threat behaviors to specific tactics and techniques with high accuracy."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,  # Lower temperature for accuracy
                response_format={"type": "json_object"}
            )
            
            mapping = json.loads(response.choices[0].message.content)
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'mitre_mapping': mapping,
                'coverage_score': self._calculate_attack_coverage(mapping),
                'defense_priority': self._prioritize_defenses(mapping)
            }
            
        except Exception as e:
            return {'error': str(e)}

    async def identify_intelligence_gaps(self, current_intel: Dict[str, Any]) -> Dict[str, Any]:
        """Identify gaps in current intelligence and suggest collection priorities"""
        
        prompt = f"""
        Review this intelligence collection and identify critical gaps:
        
        Current Intelligence: {json.dumps(current_intel, indent=2)}
        
        Identify:
        1. Critical Intelligence Gaps
        2. Collection Priorities (ranked)
        3. Suggested Collection Methods
        4. Required Data Sources
        5. Estimated Time to Collect
        6. Alternative Intelligence Sources
        7. Risk of Not Collecting
        8. Quick Wins vs Long-term Collection
        9. Budget Considerations
        10. Legal/Ethical Constraints
        
        Focus on actionable recommendations.
        Format as structured JSON.
        """
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an intelligence collection manager who identifies gaps in intelligence and prioritizes collection efforts for maximum impact."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.4,
                response_format={"type": "json_object"}
            )
            
            gaps = json.loads(response.choices[0].message.content)
            
            return {
                'timestamp': datetime.utcnow().isoformat(),
                'intelligence_gaps': gaps,
                'completeness_score': self._calculate_completeness(current_intel),
                'recommended_actions': self._prioritize_actions(gaps)
            }
            
        except Exception as e:
            return {'error': str(e)}

    # Helper methods
    def _calculate_confidence(self, data: Dict[str, Any]) -> float:
        """Calculate confidence score based on data quality"""
        # Simple heuristic - can be enhanced
        score = 0.5
        if data.get('sources', 0) > 3:
            score += 0.2
        if data.get('corroborated', False):
            score += 0.2
        if data.get('recent', False):
            score += 0.1
        return min(score, 1.0)

    def _prepare_graph_data(self, correlations: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for graph visualization"""
        # Create node and edge data for visualization
        nodes = []
        edges = []
        
        # Extract nodes and relationships from correlations
        # This is a simplified version - enhance based on actual correlation structure
        
        return {
            'nodes': nodes,
            'edges': edges,
            'layout': 'force-directed'
        }

    async def _calculate_risk_score(self, data: Dict[str, Any]) -> int:
        """Calculate overall risk score"""
        # Simplified risk calculation
        base_score = 50
        
        if data.get('critical_findings', 0) > 0:
            base_score += 30
        if data.get('active_threats', False):
            base_score += 20
            
        return min(base_score, 100)

    def _classify_report(self, risk_score: int) -> str:
        """Classify report based on risk score"""
        if risk_score >= 80:
            return "CRITICAL"
        elif risk_score >= 60:
            return "HIGH"
        elif risk_score >= 40:
            return "MEDIUM"
        elif risk_score >= 20:
            return "LOW"
        else:
            return "INFORMATIONAL"

    def _assess_data_quality(self, data: Dict[str, Any]) -> float:
        """Assess quality of input data"""
        # Simple quality metrics
        quality = 0.5
        
        if data.get('verified_sources', 0) > 2:
            quality += 0.3
        if data.get('recent_data', False):
            quality += 0.2
            
        return min(quality, 1.0)

    def _calculate_social_threat_level(self, analysis: Dict[str, Any]) -> str:
        """Calculate threat level from social media analysis"""
        threat_indicators = analysis.get('threat_indicators', [])
        
        if len(threat_indicators) > 10:
            return "HIGH"
        elif len(threat_indicators) > 5:
            return "MEDIUM"
        elif len(threat_indicators) > 0:
            return "LOW"
        else:
            return "NONE"

    def _calculate_attack_coverage(self, mapping: Dict[str, Any]) -> float:
        """Calculate MITRE ATT&CK coverage score"""
        # Simplified - count tactics covered
        tactics_covered = len(mapping.get('tactics', []))
        total_tactics = 14  # Total MITRE ATT&CK tactics
        
        return tactics_covered / total_tactics

    def _prioritize_defenses(self, mapping: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prioritize defensive measures based on MITRE mapping"""
        # Extract and prioritize from mapping
        defenses = []
        
        for technique in mapping.get('techniques', []):
            defenses.append({
                'technique_id': technique.get('id'),
                'defense': technique.get('defense'),
                'priority': technique.get('priority', 'MEDIUM')
            })
            
        # Sort by priority
        priority_order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3}
        defenses.sort(key=lambda x: priority_order.get(x['priority'], 99))
        
        return defenses[:10]  # Top 10 defenses

    def _calculate_completeness(self, intel: Dict[str, Any]) -> float:
        """Calculate intelligence completeness score"""
        required_elements = [
            'technical_indicators', 'threat_actors', 'vulnerabilities',
            'timeline', 'attribution', 'impact_assessment'
        ]
        
        present = sum(1 for elem in required_elements if elem in intel)
        return present / len(required_elements)

    def _prioritize_actions(self, gaps: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prioritize collection actions based on gaps"""
        actions = gaps.get('collection_priorities', [])
        
        # Add urgency scoring
        for action in actions:
            risk = action.get('risk_of_not_collecting', 0)
            time = action.get('estimated_time', 999)
            action['urgency_score'] = risk / (time + 1)
        
        # Sort by urgency
        actions.sort(key=lambda x: x.get('urgency_score', 0), reverse=True)
        
        return actions[:5]  # Top 5 actions


# MCP Server Implementation
class AIAnalyzerMCPServer:
    def __init__(self):
        self.analyzer = AIIntelligenceAnalyzer()
        
    async def handle_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Handle MCP protocol requests"""
        method = request.get('method')
        params = request.get('params', {})
        
        # Route to appropriate handler
        handlers = {
            'ai/analyze_threat_actor': self.analyzer.analyze_threat_actor,
            'ai/correlate_indicators': self.analyzer.correlate_indicators,
            'ai/generate_executive_summary': self.analyzer.generate_executive_summary,
            'ai/predict_attack_vectors': self.analyzer.predict_attack_vectors,
            'ai/analyze_social_sentiment': self.analyzer.analyze_social_media_sentiment,
            'ai/generate_mitre_mapping': self.analyzer.generate_mitre_mapping,
            'ai/identify_intelligence_gaps': self.analyzer.identify_intelligence_gaps
        }
        
        handler = handlers.get(method)
        if handler:
            try:
                result = await handler(**params)
                return {
                    'success': True,
                    'data': result
                }
            except Exception as e:
                return {
                    'success': False,
                    'error': str(e)
                }
        
        return {
            'success': False,
            'error': f'Unknown method: {method}'
        }

    async def get_capabilities(self) -> Dict[str, Any]:
        """Return server capabilities"""
        return {
            'name': 'AI-Powered Intelligence Analyzer',
            'version': '1.0.0',
            'ai_model': 'gpt-4-turbo-preview',
            'methods': [
                {
                    'name': 'ai/analyze_threat_actor',
                    'description': 'Generate comprehensive threat actor profile using AI',
                    'params': ['profile_data']
                },
                {
                    'name': 'ai/correlate_indicators',
                    'description': 'Find patterns and correlations between indicators',
                    'params': ['indicators']
                },
                {
                    'name': 'ai/generate_executive_summary',
                    'description': 'Create executive summary of investigation',
                    'params': ['investigation_data']
                },
                {
                    'name': 'ai/predict_attack_vectors',
                    'description': 'Predict likely attack vectors for target',
                    'params': ['target_profile']
                },
                {
                    'name': 'ai/analyze_social_sentiment',
                    'description': 'Analyze social media for threats and sentiment',
                    'params': ['social_data']
                },
                {
                    'name': 'ai/generate_mitre_mapping',
                    'description': 'Map behaviors to MITRE ATT&CK framework',
                    'params': ['attack_data']
                },
                {
                    'name': 'ai/identify_intelligence_gaps',
                    'description': 'Identify gaps in intelligence collection',
                    'params': ['current_intel']
                }
            ],
            'required_api_keys': ['OPENAI_API_KEY']
        }


if __name__ == '__main__':
    import uvicorn
    from fastapi import FastAPI, HTTPException
    from fastapi.responses import JSONResponse
    import asyncio
    
    # Create FastAPI app
    app = FastAPI(
        title="AI-Powered Intelligence Analyzer MCP Server",
        description="AI-enhanced intelligence analysis using OpenAI GPT-4",
        version="1.0.0"
    )
    
    # Initialize MCP server
    mcp_server = AIAnalyzerMCPServer()
    
    @app.get("/")
    async def root():
        return {"message": "AI-Powered Intelligence Analyzer MCP Server", "version": "1.0.0", "status": "running"}
    
    @app.get("/health")
    async def health():
        analyzer = AIIntelligenceAnalyzer()
        return {
            "status": "healthy", 
            "service": "ai-analyzer-mcp",
            "openai_api_configured": analyzer.has_api_key
        }
    
    @app.get("/capabilities")
    async def get_capabilities():
        return await mcp_server.get_capabilities()
    
    @app.post("/mcp")
    async def handle_mcp_request(request: dict):
        try:
            result = await mcp_server.handle_request(request)
            return result
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    # Add individual endpoint routes for direct access
    @app.post("/ai/analyze_threat_actor")
    async def analyze_threat_actor(request: dict):
        profile_data = request.get('profile_data')
        if not profile_data:
            raise HTTPException(status_code=400, detail="Profile data required")
        
        analyzer = AIIntelligenceAnalyzer()
        result = await analyzer.analyze_threat_actor(profile_data)
        return {"success": True, "data": result}
    
    @app.post("/ai/correlate_indicators")
    async def correlate_indicators(request: dict):
        indicators = request.get('indicators', [])
        if not indicators:
            raise HTTPException(status_code=400, detail="Indicators list required")
        
        analyzer = AIIntelligenceAnalyzer()
        result = await analyzer.correlate_indicators(indicators)
        return {"success": True, "data": result}
    
    @app.post("/ai/generate_executive_summary")
    async def generate_executive_summary(request: dict):
        investigation_data = request.get('investigation_data')
        if not investigation_data:
            raise HTTPException(status_code=400, detail="Investigation data required")
        
        analyzer = AIIntelligenceAnalyzer()
        result = await analyzer.generate_executive_summary(investigation_data)
        return {"success": True, "data": result}
    
    @app.post("/ai/predict_attack_vectors")
    async def predict_attack_vectors(request: dict):
        target_profile = request.get('target_profile')
        if not target_profile:
            raise HTTPException(status_code=400, detail="Target profile required")
        
        analyzer = AIIntelligenceAnalyzer()
        result = await analyzer.predict_attack_vectors(target_profile)
        return {"success": True, "data": result}
    
    @app.post("/ai/analyze_social_sentiment")
    async def analyze_social_sentiment(request: dict):
        social_data = request.get('social_data', [])
        if not social_data:
            raise HTTPException(status_code=400, detail="Social media data required")
        
        analyzer = AIIntelligenceAnalyzer()
        result = await analyzer.analyze_social_media_sentiment(social_data)
        return {"success": True, "data": result}
    
    @app.post("/ai/generate_mitre_mapping")
    async def generate_mitre_mapping(request: dict):
        attack_data = request.get('attack_data')
        if not attack_data:
            raise HTTPException(status_code=400, detail="Attack data required")
        
        analyzer = AIIntelligenceAnalyzer()
        result = await analyzer.generate_mitre_mapping(attack_data)
        return {"success": True, "data": result}
    
    @app.post("/ai/identify_intelligence_gaps")
    async def identify_intelligence_gaps(request: dict):
        current_intel = request.get('current_intel')
        if not current_intel:
            raise HTTPException(status_code=400, detail="Current intelligence data required")
        
        analyzer = AIIntelligenceAnalyzer()
        result = await analyzer.identify_intelligence_gaps(current_intel)
        return {"success": True, "data": result}
    
    print("Starting AI-Powered Intelligence Analyzer MCP Server on port 8050...")
    uvicorn.run(app, host="0.0.0.0", port=8050)