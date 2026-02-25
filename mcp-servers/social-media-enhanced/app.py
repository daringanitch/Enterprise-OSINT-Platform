#!/usr/bin/env python3
"""
Enhanced Social Media MCP Server - Real Intelligence Implementation
Provides actual social media intelligence gathering capabilities
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
import base64

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API Configuration
TWITTER_BEARER_TOKEN = os.environ.get('TWITTER_BEARER_TOKEN', '')
REDDIT_CLIENT_ID = os.environ.get('REDDIT_CLIENT_ID', '')
REDDIT_CLIENT_SECRET = os.environ.get('REDDIT_CLIENT_SECRET', '')
LINKEDIN_API_KEY = os.environ.get('LINKEDIN_API_KEY', '')

# Cache for API responses (simple in-memory cache)
response_cache = {}
CACHE_DURATION = 900  # 15 minutes

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

def get_twitter_data(username: str) -> Dict[str, Any]:
    """Get real Twitter/X user data"""
    try:
        # Check if we have API credentials
        if not TWITTER_BEARER_TOKEN:
            logger.warning("Twitter Bearer Token not configured, returning limited data")
            return {
                'username': username,
                'error': 'Twitter API not configured',
                'data_source': 'Limited Data',
                'note': 'Configure TWITTER_BEARER_TOKEN for real data'
            }
        
        # Twitter API v2 endpoint
        headers = {
            'Authorization': f'Bearer {TWITTER_BEARER_TOKEN}',
            'User-Agent': 'OSINT-MCP-Server/1.0'
        }
        
        # Get user by username
        user_endpoint = f"https://api.twitter.com/2/users/by/username/{username}"
        params = {
            'user.fields': 'created_at,description,public_metrics,verified,location,url,profile_image_url'
        }
        
        response = requests.get(user_endpoint, headers=headers, params=params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                user_data = data['data']
                return {
                    'username': username,
                    'user_id': user_data.get('id'),
                    'name': user_data.get('name'),
                    'description': user_data.get('description', ''),
                    'location': user_data.get('location', 'Not specified'),
                    'created_at': user_data.get('created_at', ''),
                    'verified': user_data.get('verified', False),
                    'profile_image': user_data.get('profile_image_url', ''),
                    'website': user_data.get('url', ''),
                    'metrics': user_data.get('public_metrics', {
                        'followers_count': 0,
                        'following_count': 0,
                        'tweet_count': 0,
                        'listed_count': 0
                    }),
                    'data_source': 'Twitter API v2',
                    'query_time': datetime.utcnow().isoformat()
                }
        
        # Handle API errors
        error_data = response.json() if response.text else {}
        return {
            'username': username,
            'error': f"Twitter API error: {response.status_code}",
            'details': error_data,
            'data_source': 'Twitter API v2 (Error)'
        }
        
    except Exception as e:
        logger.error(f"Twitter data collection failed: {str(e)}")
        return {
            'username': username,
            'error': str(e),
            'data_source': 'Error'
        }

def get_reddit_data(username: str) -> Dict[str, Any]:
    """Get real Reddit user data"""
    try:
        # Reddit doesn't require authentication for public user data
        headers = {
            'User-Agent': 'OSINT-MCP-Server/1.0 (by /u/osint_bot)'
        }
        
        # Get user data
        user_url = f"https://www.reddit.com/user/{username}/about.json"
        response = requests.get(user_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            if 'data' in data:
                user_data = data['data']
                
                # Calculate account age
                created_utc = user_data.get('created_utc', 0)
                account_age_days = (datetime.utcnow() - datetime.fromtimestamp(created_utc)).days if created_utc else 0
                
                return {
                    'username': username,
                    'user_id': user_data.get('id'),
                    'name': user_data.get('name'),
                    'created_utc': created_utc,
                    'created_date': datetime.fromtimestamp(created_utc).isoformat() if created_utc else 'Unknown',
                    'account_age_days': account_age_days,
                    'link_karma': user_data.get('link_karma', 0),
                    'comment_karma': user_data.get('comment_karma', 0),
                    'total_karma': user_data.get('total_karma', user_data.get('link_karma', 0) + user_data.get('comment_karma', 0)),
                    'is_gold': user_data.get('is_gold', False),
                    'is_mod': user_data.get('is_mod', False),
                    'verified': user_data.get('verified', False),
                    'has_verified_email': user_data.get('has_verified_email', False),
                    'profile_image': user_data.get('icon_img', '').split('?')[0] if user_data.get('icon_img') else '',
                    'banner_image': user_data.get('banner_img', ''),
                    'description': user_data.get('subreddit', {}).get('public_description', ''),
                    'data_source': 'Reddit Public API',
                    'query_time': datetime.utcnow().isoformat()
                }
        
        return {
            'username': username,
            'error': f"Reddit API error: {response.status_code}",
            'data_source': 'Reddit API (Error)'
        }
        
    except Exception as e:
        logger.error(f"Reddit data collection failed: {str(e)}")
        return {
            'username': username,
            'error': str(e),
            'data_source': 'Error'
        }

def search_social_media_mentions(query: str) -> Dict[str, Any]:
    """Search for mentions across social media platforms"""
    results = {
        'query': query,
        'platforms': {},
        'total_mentions': 0,
        'data_sources': []
    }
    
    # Reddit search (no auth required for search)
    try:
        headers = {'User-Agent': 'OSINT-MCP-Server/1.0'}
        reddit_search_url = f"https://www.reddit.com/search.json"
        params = {
            'q': query,
            'limit': 25,
            'sort': 'relevance',
            't': 'month'  # Last month
        }
        
        response = requests.get(reddit_search_url, headers=headers, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            posts = data.get('data', {}).get('children', [])
            
            reddit_mentions = []
            for post in posts[:10]:  # Limit to 10 results
                post_data = post.get('data', {})
                reddit_mentions.append({
                    'title': post_data.get('title', ''),
                    'subreddit': post_data.get('subreddit', ''),
                    'author': post_data.get('author', '[deleted]'),
                    'score': post_data.get('score', 0),
                    'created_utc': post_data.get('created_utc', 0),
                    'url': f"https://reddit.com{post_data.get('permalink', '')}",
                    'num_comments': post_data.get('num_comments', 0)
                })
            
            results['platforms']['reddit'] = {
                'mention_count': len(reddit_mentions),
                'mentions': reddit_mentions,
                'search_url': f"https://www.reddit.com/search?q={query}"
            }
            results['total_mentions'] += len(reddit_mentions)
            results['data_sources'].append('Reddit Search API')
    except Exception as e:
        logger.error(f"Reddit search failed: {str(e)}")
        results['platforms']['reddit'] = {'error': str(e)}
    
    # Twitter search would require API access
    if TWITTER_BEARER_TOKEN:
        try:
            headers = {'Authorization': f'Bearer {TWITTER_BEARER_TOKEN}'}
            twitter_search_url = "https://api.twitter.com/2/tweets/search/recent"
            params = {
                'query': query,
                'max_results': 10,
                'tweet.fields': 'created_at,author_id,public_metrics'
            }
            
            response = requests.get(twitter_search_url, headers=headers, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json()
                tweets = data.get('data', [])
                
                twitter_mentions = []
                for tweet in tweets:
                    twitter_mentions.append({
                        'id': tweet.get('id'),
                        'text': tweet.get('text', ''),
                        'author_id': tweet.get('author_id'),
                        'created_at': tweet.get('created_at'),
                        'metrics': tweet.get('public_metrics', {})
                    })
                
                results['platforms']['twitter'] = {
                    'mention_count': len(twitter_mentions),
                    'mentions': twitter_mentions
                }
                results['total_mentions'] += len(twitter_mentions)
                results['data_sources'].append('Twitter API v2')
        except Exception as e:
            logger.error(f"Twitter search failed: {str(e)}")
            results['platforms']['twitter'] = {'error': str(e)}
    
    results['query_time'] = datetime.utcnow().isoformat()
    return results

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'social-media-mcp-enhanced',
        'version': '2.0.0',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/tools', methods=['GET'])
def list_tools():
    """List available tools"""
    return jsonify({
        'tools': {
            'twitter_profile': {
                'description': 'Get real Twitter/X user profile data',
                'parameters': {
                    'username': {'type': 'string', 'description': 'Twitter username', 'required': True}
                },
                'intelligence_type': 'REAL',
                'requires_api_key': True,
                'example': {'username': 'elonmusk'}
            },
            'reddit_profile': {
                'description': 'Get real Reddit user profile data',
                'parameters': {
                    'username': {'type': 'string', 'description': 'Reddit username', 'required': True}
                },
                'intelligence_type': 'REAL',
                'requires_api_key': False,
                'example': {'username': 'spez'}
            },
            'social_media_search': {
                'description': 'Search for mentions across social media platforms',
                'parameters': {
                    'query': {'type': 'string', 'description': 'Search query', 'required': True}
                },
                'intelligence_type': 'REAL',
                'example': {'query': 'forestcore.com'}
            }
        }
    })

@app.route('/execute', methods=['POST'])
def execute_tool():
    """Execute a specific tool"""
    data = {}  # initialised before try so the except clause can safely reference it
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
        
        if tool == 'twitter_profile':
            username = parameters.get('username')
            if not username:
                return jsonify({'error': 'Username parameter is required'}), 400
            
            result = get_twitter_data(username)
            
        elif tool == 'reddit_profile':
            username = parameters.get('username')
            if not username:
                return jsonify({'error': 'Username parameter is required'}), 400
            
            result = get_reddit_data(username)
            
        elif tool == 'social_media_search':
            query = parameters.get('query')
            if not query:
                return jsonify({'error': 'Query parameter is required'}), 400
            
            result = search_social_media_mentions(query)
            
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
            'twitter': {
                'configured': bool(TWITTER_BEARER_TOKEN),
                'endpoint': 'api.twitter.com',
                'status': 'active' if TWITTER_BEARER_TOKEN else 'not_configured'
            },
            'reddit': {
                'configured': True,  # Reddit doesn't require auth for public data
                'endpoint': 'reddit.com',
                'status': 'active'
            },
            'linkedin': {
                'configured': bool(LINKEDIN_API_KEY),
                'endpoint': 'api.linkedin.com',
                'status': 'active' if LINKEDIN_API_KEY else 'not_configured'
            }
        },
        'cache_stats': {
            'entries': len(response_cache),
            'cache_duration_seconds': CACHE_DURATION
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('MCP_SERVER_PORT', 8010))
    app.run(host='0.0.0.0', port=port, debug=False)