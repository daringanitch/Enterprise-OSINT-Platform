#!/usr/bin/env python3
"""
Test Enhanced Intelligence Gathering Capabilities
"""

import asyncio
import sys
import os
import json
sys.path.append('/Users/daringanitch/workspace/enterprise-osint-flask/simple-backend')

from mcp_clients import MCPClientManager

async def test_enhanced_capabilities():
    """Test the enhanced MCP capabilities"""
    print("🚀 Testing Enhanced Intelligence Gathering")
    print("=" * 60)
    
    # Initialize MCP client manager
    client_manager = MCPClientManager()
    
    # Test 1: Check enhanced capabilities
    print("\n📋 1. Checking Enhanced MCP Server Capabilities")
    print("-" * 40)
    
    try:
        capabilities = await client_manager.get_enhanced_capabilities()
        
        for server, caps in capabilities.items():
            print(f"\n🔧 {server.upper()} Server:")
            if 'error' in caps:
                print(f"   ❌ Error: {caps['error']}")
            else:
                print(f"   ✅ Status: Available")
                if 'methods' in caps:
                    print(f"   📚 Methods: {len(caps['methods'])}")
                    for method in caps['methods'][:3]:  # Show first 3 methods
                        print(f"      - {method.get('name', 'unknown')}")
                    if len(caps['methods']) > 3:
                        print(f"      - ... and {len(caps['methods']) - 3} more")
    
    except Exception as e:
        print(f"❌ Capabilities check failed: {e}")
    
    # Test 2: Enhanced Intelligence Gathering
    print("\n🔍 2. Testing Enhanced Intelligence Gathering")
    print("-" * 50)
    
    test_targets = [
        "google.com",
        # "8.8.8.8",  # Comment out to avoid too many requests
    ]
    
    for target in test_targets:
        print(f"\n🎯 Target: {target}")
        print("-" * 30)
        
        try:
            results = await client_manager.gather_enhanced_intelligence(target)
            
            print(f"📊 Results for {target}:")
            print(f"   🕒 Timestamp: {results.get('timestamp', 'unknown')}")
            
            # Infrastructure Advanced Results
            infra_results = results.get('infrastructure_advanced', {})
            if infra_results:
                print(f"   🏗️  Infrastructure Advanced:")
                
                recon = infra_results.get('reconnaissance', {})
                if recon and not recon.get('error'):
                    print(f"      ✅ Reconnaissance: Success")
                    if recon.get('data', {}).get('intelligence'):
                        intel = recon['data']['intelligence']
                        if 'whois' in intel:
                            print(f"         - WHOIS: Available")
                        if 'dns' in intel:
                            print(f"         - DNS: Available")
                        if 'certificate_transparency' in intel:
                            print(f"         - Certificate Transparency: Available")
                else:
                    print(f"      ❌ Reconnaissance: {recon.get('error', 'Failed')}")
                
                ct = infra_results.get('certificate_transparency', {})
                if ct and not ct.get('error'):
                    print(f"      ✅ Certificate Transparency: Success")
                    if ct.get('data', {}).get('subdomains'):
                        subdomain_count = len(ct['data']['subdomains'])
                        print(f"         - Subdomains found: {subdomain_count}")
                else:
                    print(f"      ❌ Certificate Transparency: {ct.get('error', 'Failed')}")
            else:
                print(f"   🏗️  Infrastructure Advanced: No data")
            
            # Threat Aggregator Results
            threat_results = results.get('threat_aggregator', {})
            if threat_results:
                print(f"   🛡️  Threat Intelligence:")
                
                reputation = threat_results.get('reputation', {})
                if reputation and not reputation.get('error'):
                    print(f"      ✅ Reputation Check: Success")
                    if reputation.get('data', {}).get('reputation_scores'):
                        scores = reputation['data']['reputation_scores']
                        print(f"         - Sources checked: {len(scores)}")
                        risk_level = reputation['data'].get('risk_level', 'Unknown')
                        print(f"         - Risk level: {risk_level}")
                else:
                    print(f"      ❌ Reputation Check: {reputation.get('error', 'Failed')}")
            else:
                print(f"   🛡️  Threat Intelligence: No data")
            
            # AI Analysis Results
            ai_results = results.get('ai_analysis', {})
            if ai_results:
                print(f"   🤖 AI Analysis:")
                
                summary = ai_results.get('executive_summary', {})
                if summary and not summary.get('error'):
                    print(f"      ✅ Executive Summary: Generated")
                else:
                    print(f"      ❌ Executive Summary: {summary.get('error', 'Failed')}")
                
                vectors = ai_results.get('attack_vectors', {})
                if vectors and not vectors.get('error'):
                    print(f"      ✅ Attack Vector Prediction: Generated")
                else:
                    print(f"      ❌ Attack Vector Prediction: {vectors.get('error', 'Failed')}")
            else:
                print(f"   🤖 AI Analysis: No data")
                
        except Exception as e:
            print(f"❌ Enhanced intelligence gathering failed for {target}: {e}")
    
    print("\n" + "=" * 60)
    print("🎉 Enhanced Intelligence Testing Complete!")

async def test_individual_servers():
    """Test individual MCP servers directly"""
    print("\n🔧 3. Testing Individual MCP Servers")
    print("-" * 40)
    
    client_manager = MCPClientManager()
    
    # Test Infrastructure Advanced
    if 'infrastructure_advanced' in client_manager.clients:
        print("\n🏗️ Testing Infrastructure Advanced Server:")
        infra_client = client_manager.clients['infrastructure_advanced']
        
        try:
            # Test certificate transparency
            result = await infra_client.call_method(
                'infrastructure/certificate_transparency',
                {'domain': 'example.com'}
            )
            
            if result.get('success'):
                print("   ✅ Certificate Transparency: Working")
            else:
                print(f"   ❌ Certificate Transparency: {result.get('error')}")
                
        except Exception as e:
            print(f"   ❌ Infrastructure Advanced: {e}")
    
    # Test Threat Aggregator
    if 'threat_aggregator' in client_manager.clients:
        print("\n🛡️ Testing Threat Aggregator Server:")
        threat_client = client_manager.clients['threat_aggregator']
        
        try:
            # Test domain reputation
            result = await threat_client.call_method(
                'threat/check_domain',
                {'domain': 'example.com'}
            )
            
            if result.get('success'):
                print("   ✅ Domain Reputation: Working")
            else:
                print(f"   ❌ Domain Reputation: {result.get('error')}")
                
        except Exception as e:
            print(f"   ❌ Threat Aggregator: {e}")
    
    # Test AI Analyzer
    if 'ai_analyzer' in client_manager.clients:
        print("\n🤖 Testing AI Analyzer Server:")
        ai_client = client_manager.clients['ai_analyzer']
        
        try:
            # Test simple analysis
            test_data = {
                'target': 'example.com',
                'findings': ['test finding']
            }
            
            result = await ai_client.call_method(
                'ai/generate_executive_summary',
                {'investigation_data': test_data}
            )
            
            if result.get('success'):
                print("   ✅ AI Analysis: Working")
            else:
                print(f"   ❌ AI Analysis: {result.get('error')}")
                
        except Exception as e:
            print(f"   ❌ AI Analyzer: {e}")

async def main():
    """Run all tests"""
    print("🔍 Enhanced Intelligence Gathering Test Suite")
    print("Version: 1.0.0")
    print("Timestamp:", asyncio.get_event_loop().time())
    
    try:
        await test_enhanced_capabilities()
        await test_individual_servers()
        
    except KeyboardInterrupt:
        print("\n⚠️ Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test suite failed: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())