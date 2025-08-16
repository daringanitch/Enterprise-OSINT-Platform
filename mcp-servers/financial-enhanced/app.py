#!/usr/bin/env python3
"""
Enhanced Financial Intelligence MCP Server - Real Intelligence Implementation
Provides actual financial intelligence gathering via SEC EDGAR and Alpha Vantage APIs
"""

import os
import json
import logging
import requests
from flask import Flask, jsonify, request
from datetime import datetime, timedelta
import hashlib
import re
from typing import Dict, List, Any, Optional
import time

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API Configuration
ALPHA_VANTAGE_API_KEY = os.environ.get('ALPHA_VANTAGE_API_KEY', '')
SEC_EDGAR_USER_AGENT = 'OSINT-MCP-Financial/1.0 (compliance@example.com)'  # Required by SEC

# Cache for API responses (simple in-memory cache)
response_cache = {}
CACHE_DURATION = 3600  # 1 hour for financial data

def get_cache_key(tool: str, params: Dict) -> str:
    """Generate cache key from tool and parameters"""
    param_str = json.dumps(params, sort_keys=True)
    return hashlib.md5(f"{tool}:{param_str}".encode()).hexdigest()

def get_cached_response(cache_key: str) -> Optional[Dict]:
    """Get cached response if still valid"""
    if cache_key in response_cache:
        cached = response_cache[cache_key]
        if datetime.utcnow() < cached['expires']:
            logger.info(f"Cache hit for key: {cache_key}")
            return cached['data']
    return None

def cache_response(cache_key: str, data: Dict):
    """Cache response with expiration"""
    response_cache[cache_key] = {
        'data': data,
        'expires': datetime.utcnow() + timedelta(seconds=CACHE_DURATION)
    }

def search_sec_company(company_name: str) -> Dict[str, Any]:
    """Search for company in SEC EDGAR database"""
    try:
        headers = {
            'User-Agent': SEC_EDGAR_USER_AGENT,
            'Accept-Encoding': 'gzip, deflate',
            'Host': 'www.sec.gov'
        }
        
        # Search for company using SEC company tickers endpoint
        search_url = "https://www.sec.gov/files/company_tickers.json"
        response = requests.get(search_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            companies = response.json()
            
            # Search for matching companies
            matches = []
            company_lower = company_name.lower()
            
            for key, company_data in companies.items():
                if isinstance(company_data, dict):
                    title = company_data.get('title', '').lower()
                    ticker = company_data.get('ticker', '').lower()
                    
                    # Check for matches in company name or ticker
                    if (company_lower in title or 
                        title in company_lower or 
                        company_lower == ticker or
                        ticker in company_lower):
                        
                        matches.append({
                            'cik': str(company_data.get('cik_str', '')).zfill(10),
                            'ticker': company_data.get('ticker', ''),
                            'title': company_data.get('title', ''),
                            'match_score': calculate_match_score(company_name, title, ticker)
                        })
            
            # Sort by match score and return top results
            matches.sort(key=lambda x: x['match_score'], reverse=True)
            
            return {
                'query': company_name,
                'matches_found': len(matches),
                'companies': matches[:10],  # Top 10 matches
                'data_source': 'SEC EDGAR Company Tickers',
                'query_time': datetime.utcnow().isoformat()
            }
        
        return {
            'query': company_name,
            'error': f"SEC EDGAR API error: {response.status_code}",
            'data_source': 'SEC EDGAR (Error)'
        }
        
    except Exception as e:
        logger.error(f"SEC company search failed: {str(e)}")
        return {
            'query': company_name,
            'error': str(e),
            'data_source': 'Error'
        }

def calculate_match_score(query: str, title: str, ticker: str) -> float:
    """Calculate relevance score for company match"""
    query_lower = query.lower()
    title_lower = title.lower()
    ticker_lower = ticker.lower()
    
    score = 0.0
    
    # Exact ticker match gets highest score
    if query_lower == ticker_lower:
        score += 10.0
    elif ticker_lower in query_lower or query_lower in ticker_lower:
        score += 5.0
    
    # Company name matches
    if query_lower == title_lower:
        score += 8.0
    elif query_lower in title_lower:
        score += 6.0
    elif title_lower in query_lower:
        score += 4.0
    
    # Word matches
    query_words = set(query_lower.split())
    title_words = set(title_lower.split())
    common_words = query_words.intersection(title_words)
    
    if common_words:
        score += len(common_words) * 2.0
    
    return score

def get_sec_company_filings(cik: str, ticker: str = '') -> Dict[str, Any]:
    """Get recent SEC filings for a company"""
    try:
        headers = {
            'User-Agent': SEC_EDGAR_USER_AGENT,
            'Accept-Encoding': 'gzip, deflate',
            'Host': 'data.sec.gov'
        }
        
        # Get company filings
        cik_padded = str(cik).zfill(10)
        filings_url = f"https://data.sec.gov/submissions/CIK{cik_padded}.json"
        
        response = requests.get(filings_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            # Extract recent filings
            recent_filings = data.get('filings', {}).get('recent', {})
            
            if not recent_filings:
                return {
                    'cik': cik,
                    'ticker': ticker,
                    'error': 'No recent filings found',
                    'data_source': 'SEC EDGAR Filings'
                }
            
            # Process filings data
            filing_forms = recent_filings.get('form', [])
            filing_dates = recent_filings.get('filingDate', [])
            accession_numbers = recent_filings.get('accessionNumber', [])
            primary_docs = recent_filings.get('primaryDocument', [])
            
            filings = []
            for i in range(min(20, len(filing_forms))):  # Get up to 20 recent filings
                filings.append({
                    'form': filing_forms[i] if i < len(filing_forms) else '',
                    'filing_date': filing_dates[i] if i < len(filing_dates) else '',
                    'accession_number': accession_numbers[i] if i < len(accession_numbers) else '',
                    'document': primary_docs[i] if i < len(primary_docs) else ''
                })
            
            # Get company info
            company_info = {
                'name': data.get('name', ''),
                'sic': data.get('sic', ''),
                'sic_description': data.get('sicDescription', ''),
                'business_address': data.get('addresses', {}).get('business', {}),
                'mailing_address': data.get('addresses', {}).get('mailing', {}),
                'phone': data.get('phone', ''),
                'fiscal_year_end': data.get('fiscalYearEnd', ''),
                'state_of_incorporation': data.get('stateOfIncorporation', ''),
                'entity_type': data.get('entityType', '')
            }
            
            # Count filing types
            filing_counts = {}
            for form in filing_forms:
                filing_counts[form] = filing_counts.get(form, 0) + 1
            
            return {
                'cik': cik,
                'ticker': ticker,
                'company_info': company_info,
                'recent_filings': filings,
                'filing_counts': filing_counts,
                'total_filings': len(filings),
                'data_source': 'SEC EDGAR Filings API',
                'query_time': datetime.utcnow().isoformat()
            }
        
        return {
            'cik': cik,
            'ticker': ticker,
            'error': f"SEC EDGAR API error: {response.status_code}",
            'data_source': 'SEC EDGAR Filings (Error)'
        }
        
    except Exception as e:
        logger.error(f"SEC filings lookup failed: {str(e)}")
        return {
            'cik': cik,
            'ticker': ticker,
            'error': str(e),
            'data_source': 'Error'
        }

def get_alpha_vantage_stock_data(symbol: str) -> Dict[str, Any]:
    """Get stock data from Alpha Vantage API"""
    try:
        if not ALPHA_VANTAGE_API_KEY:
            logger.warning("Alpha Vantage API key not configured")
            return {
                'symbol': symbol,
                'error': 'Alpha Vantage API not configured',
                'data_source': 'Limited Data',
                'note': 'Configure ALPHA_VANTAGE_API_KEY for real stock data'
            }
        
        # Get company overview
        overview_url = "https://www.alphavantage.co/query"
        overview_params = {
            'function': 'OVERVIEW',
            'symbol': symbol,
            'apikey': ALPHA_VANTAGE_API_KEY
        }
        
        response = requests.get(overview_url, params=overview_params, timeout=10)
        
        if response.status_code == 200:
            overview_data = response.json()
            
            # Check for API error
            if 'Error Message' in overview_data:
                return {
                    'symbol': symbol,
                    'error': overview_data['Error Message'],
                    'data_source': 'Alpha Vantage API (Error)'
                }
            
            # Check for rate limit
            if 'Note' in overview_data:
                return {
                    'symbol': symbol,
                    'error': 'API rate limit exceeded',
                    'note': overview_data['Note'],
                    'data_source': 'Alpha Vantage API (Rate Limited)'
                }
            
            # Process company overview data
            financial_data = {
                'symbol': overview_data.get('Symbol', symbol),
                'name': overview_data.get('Name', ''),
                'description': overview_data.get('Description', ''),
                'sector': overview_data.get('Sector', ''),
                'industry': overview_data.get('Industry', ''),
                'market_cap': overview_data.get('MarketCapitalization', ''),
                'pe_ratio': overview_data.get('PERatio', ''),
                'peg_ratio': overview_data.get('PEGRatio', ''),
                'book_value': overview_data.get('BookValue', ''),
                'dividend_per_share': overview_data.get('DividendPerShare', ''),
                'dividend_yield': overview_data.get('DividendYield', ''),
                'eps': overview_data.get('EPS', ''),
                'revenue_per_share': overview_data.get('RevenuePerShareTTM', ''),
                'profit_margin': overview_data.get('ProfitMargin', ''),
                'operating_margin': overview_data.get('OperatingMarginTTM', ''),
                'return_on_assets': overview_data.get('ReturnOnAssetsTTM', ''),
                'return_on_equity': overview_data.get('ReturnOnEquityTTM', ''),
                'revenue_ttm': overview_data.get('RevenueTTM', ''),
                'gross_profit_ttm': overview_data.get('GrossProfitTTM', ''),
                'quarterly_earnings_growth': overview_data.get('QuarterlyEarningsGrowthYOY', ''),
                'quarterly_revenue_growth': overview_data.get('QuarterlyRevenueGrowthYOY', ''),
                'analyst_target_price': overview_data.get('AnalystTargetPrice', ''),
                '52_week_high': overview_data.get('52WeekHigh', ''),
                '52_week_low': overview_data.get('52WeekLow', ''),
                '50_day_moving_average': overview_data.get('50DayMovingAverage', ''),
                '200_day_moving_average': overview_data.get('200DayMovingAverage', ''),
                'shares_outstanding': overview_data.get('SharesOutstanding', ''),
                'beta': overview_data.get('Beta', ''),
                'last_split_factor': overview_data.get('LastSplitFactor', ''),
                'last_split_date': overview_data.get('LastSplitDate', '')
            }
            
            # Calculate financial health score
            health_score = calculate_financial_health_score(financial_data)
            
            return {
                'symbol': symbol,
                'financial_data': financial_data,
                'financial_health_score': health_score,
                'data_source': 'Alpha Vantage API',
                'query_time': datetime.utcnow().isoformat()
            }
        
        return {
            'symbol': symbol,
            'error': f"Alpha Vantage API error: {response.status_code}",
            'data_source': 'Alpha Vantage API (Error)'
        }
        
    except Exception as e:
        logger.error(f"Alpha Vantage stock lookup failed: {str(e)}")
        return {
            'symbol': symbol,
            'error': str(e),
            'data_source': 'Error'
        }

def calculate_financial_health_score(financial_data: Dict[str, Any]) -> float:
    """Calculate a simple financial health score based on key metrics"""
    score = 5.0  # Start with neutral score
    
    try:
        # PE Ratio analysis
        pe_ratio = float(financial_data.get('pe_ratio', 0) or 0)
        if 0 < pe_ratio < 15:
            score += 1.0  # Good value
        elif 15 <= pe_ratio < 25:
            score += 0.5  # Moderate
        elif pe_ratio >= 25:
            score -= 0.5  # Potentially overvalued
        
        # Profit margin analysis
        profit_margin = float(financial_data.get('profit_margin', 0) or 0)
        if profit_margin > 0.15:
            score += 1.0  # Strong profitability
        elif profit_margin > 0.05:
            score += 0.5  # Moderate profitability
        elif profit_margin < 0:
            score -= 1.0  # Unprofitable
        
        # ROE analysis
        roe = float(financial_data.get('return_on_equity', 0) or 0)
        if roe > 0.15:
            score += 1.0  # Excellent ROE
        elif roe > 0.10:
            score += 0.5  # Good ROE
        elif roe < 0:
            score -= 1.0  # Negative ROE
        
        # Dividend yield (if any)
        dividend_yield = float(financial_data.get('dividend_yield', 0) or 0)
        if dividend_yield > 0:
            score += 0.5  # Pays dividends
        
    except (ValueError, TypeError):
        pass  # Skip if data is not numeric
    
    return round(max(0, min(10, score)), 2)  # Clamp between 0-10

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'financial-intel-mcp-enhanced',
        'version': '2.0.0',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/tools', methods=['GET'])
def list_tools():
    """List available tools"""
    return jsonify({
        'tools': {
            'sec_company_search': {
                'description': 'Search for companies in SEC EDGAR database',
                'parameters': {
                    'company_name': {'type': 'string', 'description': 'Company name or ticker to search', 'required': True}
                },
                'intelligence_type': 'REAL',
                'requires_api_key': False,
                'example': {'company_name': 'Apple Inc'}
            },
            'sec_company_filings': {
                'description': 'Get SEC filings and company information',
                'parameters': {
                    'cik': {'type': 'string', 'description': 'Company CIK number', 'required': True},
                    'ticker': {'type': 'string', 'description': 'Stock ticker symbol', 'required': False}
                },
                'intelligence_type': 'REAL',
                'requires_api_key': False,
                'example': {'cik': '0000320193', 'ticker': 'AAPL'}
            },
            'stock_analysis': {
                'description': 'Get comprehensive stock and financial analysis',
                'parameters': {
                    'symbol': {'type': 'string', 'description': 'Stock ticker symbol', 'required': True}
                },
                'intelligence_type': 'REAL',
                'requires_api_key': True,
                'example': {'symbol': 'AAPL'}
            }
        }
    })

@app.route('/execute', methods=['POST'])
def execute_tool():
    """Execute a specific tool"""
    try:
        data = request.get_json()
        tool = data.get('tool')
        parameters = data.get('parameters', {})
        
        # Generate cache key
        cache_key = get_cache_key(tool, parameters)
        
        # Check cache first
        cached_result = get_cached_response(cache_key)
        if cached_result:
            cached_result['metadata']['cache_used'] = True
            return jsonify(cached_result)
        
        start_time = datetime.utcnow()
        
        if tool == 'sec_company_search':
            company_name = parameters.get('company_name')
            if not company_name:
                return jsonify({'error': 'Company name parameter is required'}), 400
            
            result = search_sec_company(company_name)
            
        elif tool == 'sec_company_filings':
            cik = parameters.get('cik')
            ticker = parameters.get('ticker', '')
            if not cik:
                return jsonify({'error': 'CIK parameter is required'}), 400
            
            result = get_sec_company_filings(cik, ticker)
            
        elif tool == 'stock_analysis':
            symbol = parameters.get('symbol')
            if not symbol:
                return jsonify({'error': 'Symbol parameter is required'}), 400
            
            result = get_alpha_vantage_stock_data(symbol)
            
        else:
            return jsonify({'error': f'Unknown tool: {tool}'}), 400
        
        # Calculate processing time
        processing_time = (datetime.utcnow() - start_time).total_seconds() * 1000
        
        response = {
            'tool': tool,
            'parameters': parameters,
            'result': result,
            'success': 'error' not in result,
            'timestamp': datetime.utcnow().isoformat(),
            'metadata': {
                'processing_time_ms': processing_time,
                'cache_used': False,
                'intelligence_type': 'REAL',
                'data_freshness': 'Live' if 'error' not in result else 'Error'
            }
        }
        
        # Cache successful responses
        if 'error' not in result:
            cache_response(cache_key, response)
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Tool execution failed: {str(e)}")
        return jsonify({
            'error': str(e),
            'tool': data.get('tool'),
            'success': False
        }), 500

@app.route('/status', methods=['GET'])
def api_status():
    """Check API configuration status"""
    return jsonify({
        'apis': {
            'sec_edgar': {
                'configured': True,  # Always available, no API key required
                'endpoint': 'www.sec.gov',
                'status': 'active',
                'note': 'Completely free, unlimited access'
            },
            'alpha_vantage': {
                'configured': bool(ALPHA_VANTAGE_API_KEY),
                'endpoint': 'www.alphavantage.co',
                'status': 'active' if ALPHA_VANTAGE_API_KEY else 'not_configured',
                'rate_limit': '25 requests per day (free tier)'
            }
        },
        'cache_stats': {
            'entries': len(response_cache),
            'cache_duration_seconds': CACHE_DURATION
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('MCP_SERVER_PORT', 8040))
    app.run(host='0.0.0.0', port=port, debug=False)