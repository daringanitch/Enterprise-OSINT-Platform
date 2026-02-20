#!/usr/bin/env python3
# Copyright (c) 2025 Darin Ganitch
#
# This file is part of the Enterprise OSINT Platform.
# Licensed under the Enterprise OSINT Platform License.

"""
Authentication Blueprint - JWT token management and user login/logout.
"""

import os
import logging
import psycopg2
import bcrypt
import jwt
from functools import wraps
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify

# Import shared services
from shared import services
from mode_manager import mode_manager

# Try to import validators
try:
    from validators import validate_login_request, ValidationError as InputValidationError, get_safe_error_message
    VALIDATION_ENABLED = True
except ImportError:
    VALIDATION_ENABLED = False
    def validate_login_request(data): return data
    def get_safe_error_message(t, d=None): return d or 'An error occurred'

logger = logging.getLogger(__name__)

bp = Blueprint('auth', __name__)


def get_db_connection():
    """Get PostgreSQL database connection"""
    try:
        conn = psycopg2.connect(
            host=os.environ.get('POSTGRES_HOST', 'osint-platform-postgresql'),
            port=os.environ.get('POSTGRES_PORT', '5432'),
            database=os.environ.get('POSTGRES_DB', 'osint_audit'),
            user=os.environ.get('POSTGRES_USER', 'postgres'),
            password=os.environ.get('POSTGRES_PASSWORD', 'password123')
        )
        return conn
    except Exception as e:
        logger.error(f"Database connection error: {e}", exc_info=True)
        return None


def hash_password(password):
    """Hash a password using bcrypt"""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')


def verify_password(password, hashed):
    """Verify a password against its hash"""
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))


def authenticate_user(username, password):
    """Authenticate user against PostgreSQL database or demo fallback"""

    # Demo mode fallback users
    DEMO_USERS = {
        'admin': {
            'password': 'admin123',
            'user_id': 'admin',
            'username': 'admin',
            'full_name': 'System Administrator',
            'role': 'admin',
            'clearance_level': 'confidential'
        },
        'analyst1': {
            'password': 'admin123',
            'user_id': 'analyst1',
            'username': 'analyst1',
            'full_name': 'John Analyst',
            'role': 'analyst',
            'clearance_level': 'internal'
        },
        'analyst2': {
            'password': 'admin123',
            'user_id': 'analyst2',
            'username': 'analyst2',
            'full_name': 'Jane Investigator',
            'role': 'senior_analyst',
            'clearance_level': 'confidential'
        }
    }

    conn = get_db_connection()
    if not conn:
        # Fallback to demo users if database unavailable
        logger.warning("Database unavailable, using demo authentication")
        if username in DEMO_USERS and DEMO_USERS[username]['password'] == password:
            user_data = DEMO_USERS[username].copy()
            del user_data['password']
            return user_data
        return None

    try:
        cursor = conn.cursor()
        # Support both username and email for login
        cursor.execute("""
            SELECT id, user_id, username, email, password_hash, full_name, role, clearance_level, is_active
            FROM public.users
            WHERE (username = %s OR email = %s) AND is_active = true
        """, (username, username))

        user = cursor.fetchone()
        if user and verify_password(password, user[4]):
            # Update last login
            cursor.execute("""
                UPDATE public.users
                SET last_login = NOW()
                WHERE id = %s
            """, (user[0],))
            conn.commit()

            return {
                'user_id': user[1],  # user_id column
                'username': user[2],  # username column
                'full_name': user[5],
                'role': user[6],
                'clearance_level': user[7] or 'internal'
            }
        else:
            # Increment failed login attempts
            cursor.execute("""
                UPDATE public.users
                SET failed_login_attempts = failed_login_attempts + 1
                WHERE username = %s OR email = %s
            """, (username, username))
            conn.commit()

            # Fallback to demo users if DB auth fails and in demo mode
            if mode_manager.is_demo_mode():
                if username in DEMO_USERS and DEMO_USERS[username]['password'] == password:
                    logger.info(f"Demo mode: authenticating user {username}")
                    user_data = DEMO_USERS[username].copy()
                    del user_data['password']
                    return user_data
            return None

    except Exception as e:
        logger.error(f"Authentication error: {e}", exc_info=True)
        # Fallback to demo users on error
        if username in DEMO_USERS and DEMO_USERS[username]['password'] == password:
            logger.warning(f"Database error, using demo fallback for user {username}")
            user_data = DEMO_USERS[username].copy()
            del user_data['password']
            return user_data
        return None
    finally:
        conn.close()


def create_jwt_token(user_info):
    """Create a JWT token for the user"""
    payload = {
        'user_id': user_info['user_id'],
        'username': user_info['username'],
        'full_name': user_info['full_name'],
        'role': user_info['role'],
        'clearance_level': user_info['clearance_level'],
        'exp': datetime.utcnow() + timedelta(hours=8),  # 8 hour expiry
        'iat': datetime.utcnow()
    }

    return jwt.encode(payload, os.environ.get('JWT_SECRET_KEY', 'dev-secret-key-change-in-production'), algorithm='HS256')


def require_auth(f):
    """Decorator to require authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get token from Authorization header
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'error': 'Authentication required'}), 401

        token = auth_header.split(' ')[1]

        try:
            payload = jwt.decode(token, os.environ.get('JWT_SECRET_KEY', 'dev-secret-key-change-in-production'), algorithms=['HS256'])
            request.current_user = payload
            return f(*args, **kwargs)
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
    return decorated_function


def require_role(required_role):
    """Decorator to require specific role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(request, 'current_user'):
                return jsonify({'error': 'Authentication required'}), 401

            role_hierarchy = {'viewer': 1, 'analyst': 2, 'senior_analyst': 3, 'admin': 4}
            user_level = role_hierarchy.get(request.current_user.get('role'), 0)
            required_level = role_hierarchy.get(required_role, 99)

            if user_level < required_level:
                return jsonify({'error': 'Insufficient permissions'}), 403

            return f(*args, **kwargs)
        return decorated_function
    return decorator


@bp.route('/api/auth/login', methods=['POST'])
def login():
    """User authentication endpoint"""
    data = request.json or {}

    # Validate and sanitize login input
    if VALIDATION_ENABLED:
        try:
            validated = validate_login_request(data)
            username = validated.username
            password = validated.password
        except InputValidationError as e:
            # Don't expose validation details for security
            logger.warning("Login validation failed")
            return jsonify({'error': 'Invalid credentials format'}), 400
    else:
        username = data.get('username', '').strip()
        password = data.get('password', '')

        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400

    # Authenticate against PostgreSQL
    user_info = authenticate_user(username, password)
    if user_info:
        access_token = create_jwt_token(user_info)

        return jsonify({
            'message': 'Login successful',
            'user': {
                'user_id': user_info['user_id'],
                'username': user_info['username'],
                'full_name': user_info['full_name'],
                'role': user_info['role'],
                'clearance_level': user_info['clearance_level']
            },
            'access_token': access_token
        })

    return jsonify({'error': 'Invalid credentials'}), 401


@bp.route('/api/auth/logout', methods=['POST'])
@require_auth
def logout():
    """User logout endpoint"""
    # With JWT tokens, logout is handled client-side by discarding the token
    return jsonify({'message': 'Logout successful'})


@bp.route('/api/auth/me', methods=['GET'])
@require_auth
def get_current_user():
    """Get current user information"""
    user = request.current_user
    return jsonify({
        'user': {
            'user_id': user['user_id'],
            'username': user['username'],
            'full_name': user['full_name'],
            'role': user['role'],
            'clearance_level': user['clearance_level']
        }
    })
