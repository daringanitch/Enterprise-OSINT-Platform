"""
Authentication API endpoints
"""
from datetime import datetime
from flask import Blueprint, request, jsonify
from flask_jwt_extended import (
    create_access_token, create_refresh_token, 
    jwt_required, get_jwt_identity, get_jwt
)
from marshmallow import Schema, fields, validate, ValidationError

from app import db
from app.models.user import User
from app.utils.errors import APIError

auth_bp = Blueprint('auth', __name__)


class LoginSchema(Schema):
    """Login validation schema"""
    username = fields.Str(required=True, validate=validate.Length(min=3))
    password = fields.Str(required=True, validate=validate.Length(min=6))


class RegisterSchema(Schema):
    """Registration validation schema"""
    username = fields.Str(required=True, validate=validate.Length(min=3, max=80))
    email = fields.Email(required=True)
    password = fields.Str(required=True, validate=validate.Length(min=8))
    first_name = fields.Str(validate=validate.Length(max=80))
    last_name = fields.Str(validate=validate.Length(max=80))
    organization = fields.Str(validate=validate.Length(max=120))


@auth_bp.route('/register', methods=['POST'])
def register():
    """Register new user"""
    schema = RegisterSchema()
    
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    # Check if user exists
    if User.query.filter_by(username=data['username']).first():
        raise APIError('Username already exists', 409)
    
    if User.query.filter_by(email=data['email']).first():
        raise APIError('Email already registered', 409)
    
    # Create new user
    user = User(
        username=data['username'],
        email=data['email'],
        first_name=data.get('first_name'),
        last_name=data.get('last_name'),
        organization=data.get('organization')
    )
    user.set_password(data['password'])
    
    db.session.add(user)
    db.session.commit()
    
    # Create tokens
    access_token = create_access_token(identity=user.id)
    refresh_token = create_refresh_token(identity=user.id)
    
    return jsonify({
        'message': 'User created successfully',
        'user': user.to_dict(),
        'access_token': access_token,
        'refresh_token': refresh_token
    }), 201


@auth_bp.route('/login', methods=['POST'])
def login():
    """Login user"""
    schema = LoginSchema()
    
    try:
        data = schema.load(request.json)
    except ValidationError as err:
        return jsonify({'errors': err.messages}), 400
    
    # Find user by username or email
    user = User.query.filter(
        (User.username == data['username']) | 
        (User.email == data['username'])
    ).first()
    
    if not user or not user.check_password(data['password']):
        raise APIError('Invalid username or password', 401)
    
    if not user.is_active:
        raise APIError('Account is deactivated', 403)
    
    # Update last login
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Create tokens
    access_token = create_access_token(
        identity=user.id,
        additional_claims={'role': user.role.value}
    )
    refresh_token = create_refresh_token(identity=user.id)
    
    return jsonify({
        'message': 'Login successful',
        'user': user.to_dict(),
        'access_token': access_token,
        'refresh_token': refresh_token
    }), 200


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():
    """Refresh access token"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user or not user.is_active:
        raise APIError('Invalid user', 401)
    
    # Create new access token
    access_token = create_access_token(
        identity=user.id,
        additional_claims={'role': user.role.value}
    )
    
    return jsonify({
        'access_token': access_token
    }), 200


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
def logout():
    """Logout user (client should remove tokens)"""
    # In a production app, you might want to blacklist the token here
    return jsonify({'message': 'Logout successful'}), 200


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    """Get current user profile"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        raise APIError('User not found', 404)
    
    return jsonify({
        'user': user.to_dict()
    }), 200


@auth_bp.route('/me', methods=['PUT'])
@jwt_required()
def update_profile():
    """Update user profile"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        raise APIError('User not found', 404)
    
    data = request.json
    
    # Update allowed fields
    if 'first_name' in data:
        user.first_name = data['first_name']
    if 'last_name' in data:
        user.last_name = data['last_name']
    if 'organization' in data:
        user.organization = data['organization']
    if 'email' in data and data['email'] != user.email:
        # Check if email is already taken
        if User.query.filter_by(email=data['email']).first():
            raise APIError('Email already in use', 409)
        user.email = data['email']
    
    db.session.commit()
    
    return jsonify({
        'message': 'Profile updated successfully',
        'user': user.to_dict()
    }), 200


@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
def change_password():
    """Change user password"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    
    if not user:
        raise APIError('User not found', 404)
    
    data = request.json
    
    if not data.get('current_password') or not data.get('new_password'):
        raise APIError('Current and new password required', 400)
    
    if not user.check_password(data['current_password']):
        raise APIError('Current password is incorrect', 401)
    
    if len(data['new_password']) < 8:
        raise APIError('New password must be at least 8 characters', 400)
    
    user.set_password(data['new_password'])
    db.session.commit()
    
    return jsonify({
        'message': 'Password changed successfully'
    }), 200