"""
pytest configuration and fixtures for OSINT Platform tests
"""
import os
import sys
import pytest
import tempfile
from unittest.mock import Mock, patch
from datetime import datetime

# Add the app directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Set test environment variables before importing app
os.environ['FLASK_ENV'] = 'testing'
os.environ['JWT_SECRET_KEY'] = 'test-secret-key'
os.environ['POSTGRES_URL'] = 'postgresql://test:test@localhost:5432/test_osint'

from app import app as flask_app
from models import OSINTInvestigation, InvestigationType, InvestigationStatus, Priority


@pytest.fixture
def app():
    """Create and configure a test Flask application."""
    flask_app.config.update({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key",
        "JWT_SECRET_KEY": "test-jwt-secret",
    })
    
    # Create a temporary file for audit storage
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        flask_app.config['AUDIT_FILE'] = tmp.name
    
    yield flask_app
    
    # Cleanup
    if os.path.exists(flask_app.config['AUDIT_FILE']):
        os.unlink(flask_app.config['AUDIT_FILE'])


@pytest.fixture
def client(app):
    """Create a test client for the Flask application."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """Create a test runner for the Flask application."""
    return app.test_cli_runner()


@pytest.fixture
def auth_headers():
    """Provide authentication headers with a valid JWT token."""
    import jwt
    from datetime import datetime, timedelta
    
    payload = {
        'user_id': 'test_user',
        'username': 'testuser',
        'full_name': 'Test User',
        'role': 'admin',
        'clearance_level': 'confidential',
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow()
    }
    
    token = jwt.encode(payload, 'test-secret-key', algorithm='HS256')
    return {'Authorization': f'Bearer {token}'}


@pytest.fixture
def mock_mcp_client():
    """Mock MCP client for testing."""
    mock = Mock()
    mock.gather_all_intelligence.return_value = {
        'infrastructure': [],
        'social_media': [],
        'threat_intelligence': []
    }
    return mock


@pytest.fixture
def mock_postgres_client():
    """Mock PostgreSQL client for testing."""
    mock = Mock()
    mock.test_connection.return_value = True
    mock.execute_query.return_value = []
    return mock


@pytest.fixture
def sample_investigation():
    """Create a sample investigation for testing."""
    from models import TargetProfile, IntelligenceSource
    
    investigation = OSINTInvestigation(
        id='test-investigation-123',
        target_profile=TargetProfile(
            target_id='test-target',
            primary_identifier='example.com',
            target_type='domain'
        ),
        investigation_type=InvestigationType.COMPREHENSIVE,
        priority=Priority.HIGH,
        status=InvestigationStatus.PLANNING,
        created_at=datetime.utcnow(),
        started_at=datetime.utcnow()
    )
    return investigation


@pytest.fixture(autouse=True)
def reset_singletons():
    """Reset any singleton instances between tests."""
    # Reset any global state here
    yield


@pytest.fixture
def mock_external_apis():
    """Mock all external API calls."""
    with patch('requests.get') as mock_get, \
         patch('requests.post') as mock_post:
        
        # Configure default responses
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = {'status': 'ok'}
        
        mock_post.return_value.status_code = 200
        mock_post.return_value.json.return_value = {'status': 'ok'}
        
        yield {
            'get': mock_get,
            'post': mock_post
        }


# Pytest plugins and hooks
def pytest_configure(config):
    """Configure pytest with custom markers."""
    config.addinivalue_line(
        "markers", "unit: Unit tests (fast, no external dependencies)"
    )
    config.addinivalue_line(
        "markers", "integration: Integration tests (may use database/cache)"
    )
    config.addinivalue_line(
        "markers", "e2e: End-to-end tests (full system test)"
    )
    config.addinivalue_line(
        "markers", "security: Security-related tests"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection to add markers based on test location."""
    for item in items:
        # Add markers based on test file location
        if "unit" in str(item.fspath):
            item.add_marker(pytest.mark.unit)
        elif "integration" in str(item.fspath):
            item.add_marker(pytest.mark.integration)
        elif "e2e" in str(item.fspath):
            item.add_marker(pytest.mark.e2e)