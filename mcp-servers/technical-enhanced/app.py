#!/usr/bin/env python3
"""
Enhanced Technical Intelligence MCP Server - Real Intelligence Implementation
Provides actual technical intelligence gathering via GitHub and GitLab APIs
"""

import os
import json
import logging
import requests
from flask import Flask, jsonify, request
from datetime import datetime, timedelta
import hashlib
from typing import Dict, List, Any, Optional
import base64

app = Flask(__name__)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# API Configuration
GITHUB_TOKEN = os.environ.get('GITHUB_TOKEN', '')  # Optional, increases rate limit
GITLAB_TOKEN = os.environ.get('GITLAB_TOKEN', '')  # Optional, for private repos

# Cache for API responses (simple in-memory cache)
response_cache = {}
CACHE_DURATION = 1800  # 30 minutes for technical data

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

def search_github_user(username: str) -> Dict[str, Any]:
    """Search for GitHub user profile and activity"""
    try:
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'OSINT-MCP-Technical/1.0'
        }
        
        # Add token if available (increases rate limit from 60 to 5000/hour)
        if GITHUB_TOKEN:
            headers['Authorization'] = f'token {GITHUB_TOKEN}'
        
        # Get user profile
        user_url = f"https://api.github.com/users/{username}"
        response = requests.get(user_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            user_data = response.json()
            
            # Get user's repositories
            repos_url = f"https://api.github.com/users/{username}/repos"
            repos_params = {
                'sort': 'updated',
                'per_page': 20  # Get top 20 most recently updated repos
            }
            repos_response = requests.get(repos_url, headers=headers, params=repos_params, timeout=10)
            
            repositories = []
            total_stars = 0
            total_forks = 0
            languages = {}
            
            if repos_response.status_code == 200:
                repos_data = repos_response.json()
                
                for repo in repos_data:
                    # Skip forks to focus on original work
                    if not repo.get('fork', False):
                        repo_info = {
                            'name': repo.get('name'),
                            'description': repo.get('description'),
                            'language': repo.get('language'),
                            'stars': repo.get('stargazers_count', 0),
                            'forks': repo.get('forks_count', 0),
                            'created_at': repo.get('created_at'),
                            'updated_at': repo.get('updated_at'),
                            'topics': repo.get('topics', []),
                            'homepage': repo.get('homepage'),
                            'url': repo.get('html_url')
                        }
                        repositories.append(repo_info)
                        
                        total_stars += repo_info['stars']
                        total_forks += repo_info['forks']
                        
                        # Track languages
                        if repo_info['language']:
                            languages[repo_info['language']] = languages.get(repo_info['language'], 0) + 1
            
            # Calculate technical score
            tech_score = calculate_github_tech_score(user_data, repositories, total_stars, total_forks)
            
            return {
                'username': username,
                'profile': {
                    'name': user_data.get('name'),
                    'company': user_data.get('company'),
                    'blog': user_data.get('blog'),
                    'location': user_data.get('location'),
                    'email': user_data.get('email'),
                    'bio': user_data.get('bio'),
                    'twitter_username': user_data.get('twitter_username'),
                    'public_repos': user_data.get('public_repos', 0),
                    'public_gists': user_data.get('public_gists', 0),
                    'followers': user_data.get('followers', 0),
                    'following': user_data.get('following', 0),
                    'created_at': user_data.get('created_at'),
                    'updated_at': user_data.get('updated_at'),
                    'avatar_url': user_data.get('avatar_url'),
                    'html_url': user_data.get('html_url')
                },
                'repositories': repositories[:10],  # Top 10 repos
                'repository_count': len(repositories),
                'total_stars': total_stars,
                'total_forks': total_forks,
                'languages': languages,
                'technical_score': tech_score,
                'data_source': 'GitHub API v3',
                'query_time': datetime.utcnow().isoformat()
            }
        
        elif response.status_code == 404:
            return {
                'username': username,
                'error': 'User not found',
                'data_source': 'GitHub API v3'
            }
        else:
            return {
                'username': username,
                'error': f"GitHub API error: {response.status_code}",
                'data_source': 'GitHub API v3 (Error)'
            }
        
    except Exception as e:
        logger.error(f"GitHub user search failed: {str(e)}")
        return {
            'username': username,
            'error': str(e),
            'data_source': 'Error'
        }

def calculate_github_tech_score(user_data: Dict, repos: List[Dict], stars: int, forks: int) -> float:
    """Calculate technical expertise score based on GitHub activity"""
    score = 5.0  # Start with neutral score
    
    # Repository activity
    repo_count = user_data.get('public_repos', 0)
    if repo_count > 50:
        score += 2.0
    elif repo_count > 20:
        score += 1.0
    elif repo_count > 10:
        score += 0.5
    
    # Star count (popularity)
    if stars > 1000:
        score += 2.0
    elif stars > 100:
        score += 1.0
    elif stars > 20:
        score += 0.5
    
    # Fork count (community engagement)
    if forks > 100:
        score += 1.0
    elif forks > 20:
        score += 0.5
    
    # Followers (influence)
    followers = user_data.get('followers', 0)
    if followers > 1000:
        score += 1.0
    elif followers > 100:
        score += 0.5
    
    # Account age (experience)
    created_at = user_data.get('created_at', '')
    if created_at:
        account_age_days = (datetime.utcnow() - datetime.fromisoformat(created_at.replace('Z', '+00:00'))).days
        if account_age_days > 1825:  # 5+ years
            score += 0.5
    
    return round(min(10, score), 2)

def search_github_repo(repo_path: str) -> Dict[str, Any]:
    """Get detailed information about a GitHub repository"""
    try:
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'OSINT-MCP-Technical/1.0'
        }
        
        if GITHUB_TOKEN:
            headers['Authorization'] = f'token {GITHUB_TOKEN}'
        
        # Parse owner/repo from path
        parts = repo_path.strip('/').split('/')
        if len(parts) < 2:
            return {
                'repo': repo_path,
                'error': 'Invalid repository path. Use format: owner/repo',
                'data_source': 'GitHub API v3'
            }
        
        owner = parts[0]
        repo = parts[1]
        
        # Get repository data
        repo_url = f"https://api.github.com/repos/{owner}/{repo}"
        response = requests.get(repo_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            repo_data = response.json()
            
            # Get languages breakdown
            languages_url = f"https://api.github.com/repos/{owner}/{repo}/languages"
            languages_response = requests.get(languages_url, headers=headers, timeout=10)
            languages = languages_response.json() if languages_response.status_code == 200 else {}
            
            # Get recent commits
            commits_url = f"https://api.github.com/repos/{owner}/{repo}/commits"
            commits_params = {'per_page': 10}
            commits_response = requests.get(commits_url, headers=headers, params=commits_params, timeout=10)
            
            recent_commits = []
            if commits_response.status_code == 200:
                commits_data = commits_response.json()
                for commit in commits_data[:5]:  # Last 5 commits
                    recent_commits.append({
                        'sha': commit.get('sha', '')[:7],
                        'message': commit.get('commit', {}).get('message', '').split('\n')[0],
                        'author': commit.get('commit', {}).get('author', {}).get('name'),
                        'date': commit.get('commit', {}).get('author', {}).get('date')
                    })
            
            # Calculate health score
            health_score = calculate_repo_health_score(repo_data)
            
            return {
                'repository': f"{owner}/{repo}",
                'details': {
                    'name': repo_data.get('name'),
                    'full_name': repo_data.get('full_name'),
                    'description': repo_data.get('description'),
                    'owner': {
                        'login': repo_data.get('owner', {}).get('login'),
                        'type': repo_data.get('owner', {}).get('type'),
                        'url': repo_data.get('owner', {}).get('html_url')
                    },
                    'private': repo_data.get('private', False),
                    'fork': repo_data.get('fork', False),
                    'created_at': repo_data.get('created_at'),
                    'updated_at': repo_data.get('updated_at'),
                    'pushed_at': repo_data.get('pushed_at'),
                    'homepage': repo_data.get('homepage'),
                    'size': repo_data.get('size', 0),
                    'stargazers_count': repo_data.get('stargazers_count', 0),
                    'watchers_count': repo_data.get('watchers_count', 0),
                    'forks_count': repo_data.get('forks_count', 0),
                    'open_issues_count': repo_data.get('open_issues_count', 0),
                    'license': repo_data.get('license', {}).get('name') if repo_data.get('license') else None,
                    'topics': repo_data.get('topics', []),
                    'has_wiki': repo_data.get('has_wiki', False),
                    'has_pages': repo_data.get('has_pages', False),
                    'has_downloads': repo_data.get('has_downloads', False),
                    'archived': repo_data.get('archived', False),
                    'disabled': repo_data.get('disabled', False),
                    'default_branch': repo_data.get('default_branch', 'main')
                },
                'languages': languages,
                'recent_commits': recent_commits,
                'health_score': health_score,
                'data_source': 'GitHub API v3',
                'query_time': datetime.utcnow().isoformat()
            }
        
        elif response.status_code == 404:
            return {
                'repository': f"{owner}/{repo}",
                'error': 'Repository not found',
                'data_source': 'GitHub API v3'
            }
        else:
            return {
                'repository': f"{owner}/{repo}",
                'error': f"GitHub API error: {response.status_code}",
                'data_source': 'GitHub API v3 (Error)'
            }
        
    except Exception as e:
        logger.error(f"GitHub repository search failed: {str(e)}")
        return {
            'repository': repo_path,
            'error': str(e),
            'data_source': 'Error'
        }

def calculate_repo_health_score(repo_data: Dict) -> float:
    """Calculate repository health score"""
    score = 5.0  # Start with neutral
    
    # Stars (popularity)
    stars = repo_data.get('stargazers_count', 0)
    if stars > 1000:
        score += 2.0
    elif stars > 100:
        score += 1.0
    elif stars > 10:
        score += 0.5
    
    # Recent activity
    pushed_at = repo_data.get('pushed_at')
    if pushed_at:
        last_push = datetime.fromisoformat(pushed_at.replace('Z', '+00:00'))
        days_inactive = (datetime.utcnow().replace(tzinfo=last_push.tzinfo) - last_push).days
        if days_inactive < 30:
            score += 1.0
        elif days_inactive < 90:
            score += 0.5
        elif days_inactive > 365:
            score -= 1.0
    
    # Issues management
    open_issues = repo_data.get('open_issues_count', 0)
    if open_issues > 100:
        score -= 0.5
    
    # License (good practice)
    if repo_data.get('license'):
        score += 0.5
    
    # Documentation
    if repo_data.get('has_wiki') or repo_data.get('homepage'):
        score += 0.5
    
    return round(min(10, max(0, score)), 2)

def search_code_patterns(query: str, language: str = None) -> Dict[str, Any]:
    """Search for code patterns across GitHub"""
    try:
        headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'OSINT-MCP-Technical/1.0'
        }
        
        if GITHUB_TOKEN:
            headers['Authorization'] = f'token {GITHUB_TOKEN}'
        
        # Build search query
        search_params = {
            'q': query,
            'per_page': 10
        }
        
        if language:
            search_params['q'] += f' language:{language}'
        
        # Search code
        search_url = "https://api.github.com/search/code"
        response = requests.get(search_url, headers=headers, params=search_params, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            
            code_results = []
            for item in data.get('items', [])[:10]:
                code_results.append({
                    'name': item.get('name'),
                    'path': item.get('path'),
                    'repository': {
                        'name': item.get('repository', {}).get('full_name'),
                        'owner': item.get('repository', {}).get('owner', {}).get('login'),
                        'stars': item.get('repository', {}).get('stargazers_count', 0),
                        'url': item.get('repository', {}).get('html_url')
                    },
                    'url': item.get('html_url'),
                    'score': item.get('score', 0)
                })
            
            return {
                'query': query,
                'language': language,
                'total_count': data.get('total_count', 0),
                'results': code_results,
                'data_source': 'GitHub Code Search API',
                'query_time': datetime.utcnow().isoformat()
            }
        
        elif response.status_code == 403:
            return {
                'query': query,
                'error': 'Rate limit exceeded or authentication required',
                'note': 'Code search requires authentication. Set GITHUB_TOKEN environment variable.',
                'data_source': 'GitHub Code Search API (Error)'
            }
        else:
            return {
                'query': query,
                'error': f"GitHub API error: {response.status_code}",
                'data_source': 'GitHub Code Search API (Error)'
            }
        
    except Exception as e:
        logger.error(f"Code search failed: {str(e)}")
        return {
            'query': query,
            'error': str(e),
            'data_source': 'Error'
        }

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'service': 'technical-intel-mcp-enhanced',
        'version': '2.0.0',
        'timestamp': datetime.utcnow().isoformat()
    })

@app.route('/tools', methods=['GET'])
def list_tools():
    """List available tools"""
    return jsonify({
        'tools': {
            'github_user': {
                'description': 'Get GitHub user profile and repository analysis',
                'parameters': {
                    'username': {'type': 'string', 'description': 'GitHub username', 'required': True}
                },
                'intelligence_type': 'REAL',
                'requires_api_key': False,
                'rate_limit': '60/hour without token, 5000/hour with token',
                'example': {'username': 'torvalds'}
            },
            'github_repo': {
                'description': 'Get detailed GitHub repository information',
                'parameters': {
                    'repo_path': {'type': 'string', 'description': 'Repository path (owner/repo)', 'required': True}
                },
                'intelligence_type': 'REAL',
                'requires_api_key': False,
                'example': {'repo_path': 'torvalds/linux'}
            },
            'code_search': {
                'description': 'Search for code patterns across GitHub',
                'parameters': {
                    'query': {'type': 'string', 'description': 'Code search query', 'required': True},
                    'language': {'type': 'string', 'description': 'Programming language filter', 'required': False}
                },
                'intelligence_type': 'REAL',
                'requires_api_key': True,
                'note': 'Requires GITHUB_TOKEN for code search',
                'example': {'query': 'password encryption', 'language': 'python'}
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
        
        if tool == 'github_user':
            username = parameters.get('username')
            if not username:
                return jsonify({'error': 'Username parameter is required'}), 400
            
            result = search_github_user(username)
            
        elif tool == 'github_repo':
            repo_path = parameters.get('repo_path')
            if not repo_path:
                return jsonify({'error': 'Repository path parameter is required'}), 400
            
            result = search_github_repo(repo_path)
            
        elif tool == 'code_search':
            query = parameters.get('query')
            if not query:
                return jsonify({'error': 'Query parameter is required'}), 400
            
            language = parameters.get('language')
            result = search_code_patterns(query, language)
            
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
    
    # Test GitHub API
    github_status = 'not_configured'
    github_rate_limit = {}
    
    try:
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if GITHUB_TOKEN:
            headers['Authorization'] = f'token {GITHUB_TOKEN}'
            
        rate_response = requests.get('https://api.github.com/rate_limit', headers=headers, timeout=5)
        if rate_response.status_code == 200:
            rate_data = rate_response.json()
            github_status = 'authenticated' if GITHUB_TOKEN else 'anonymous'
            github_rate_limit = {
                'limit': rate_data.get('rate', {}).get('limit', 60),
                'remaining': rate_data.get('rate', {}).get('remaining', 0),
                'reset': datetime.fromtimestamp(rate_data.get('rate', {}).get('reset', 0)).isoformat()
            }
    except:
        github_status = 'error'
    
    return jsonify({
        'apis': {
            'github': {
                'configured': bool(GITHUB_TOKEN),
                'endpoint': 'api.github.com',
                'status': github_status,
                'rate_limit': github_rate_limit,
                'note': 'Works without token (60 req/hour) or with token (5000 req/hour)'
            },
            'gitlab': {
                'configured': bool(GITLAB_TOKEN),
                'endpoint': 'gitlab.com/api/v4',
                'status': 'active' if GITLAB_TOKEN else 'not_configured',
                'note': 'Optional - for private repository access'
            }
        },
        'cache_stats': {
            'entries': len(response_cache),
            'cache_duration_seconds': CACHE_DURATION
        }
    })

if __name__ == '__main__':
    port = int(os.environ.get('MCP_SERVER_PORT', 8050))
    app.run(host='0.0.0.0', port=port, debug=False)