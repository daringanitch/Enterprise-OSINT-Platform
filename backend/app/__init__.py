"""
Flask application factory
"""
from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_marshmallow import Marshmallow
from flask_migrate import Migrate
from flask_socketio import SocketIO
from flask_sqlalchemy import SQLAlchemy
from celery import Celery

from config import get_config

# Initialize extensions
db = SQLAlchemy()
ma = Marshmallow()
jwt = JWTManager()
migrate = Migrate()
socketio = SocketIO()
celery = Celery()


def create_app(config_name=None):
    """Create Flask application"""
    app = Flask(__name__)
    
    # Load configuration
    config = get_config()
    app.config.from_object(config)
    
    # Initialize extensions
    db.init_app(app)
    ma.init_app(app)
    jwt.init_app(app)
    migrate.init_app(app, db)
    
    # Initialize CORS
    CORS(app, 
         origins=app.config['CORS_ORIGINS'],
         supports_credentials=True)
    
    # Initialize SocketIO
    socketio.init_app(app, 
                      cors_allowed_origins=app.config['CORS_ORIGINS'],
                      async_mode='gevent')
    
    # Initialize Celery
    celery.conf.update(app.config)
    
    # Register blueprints
    from app.api import auth_bp, investigations_bp, reports_bp, mcp_bp
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(investigations_bp, url_prefix='/api/investigations')
    app.register_blueprint(reports_bp, url_prefix='/api/reports')
    app.register_blueprint(mcp_bp, url_prefix='/api/mcp')
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register WebSocket events
    register_socketio_events(socketio)
    
    # Create database tables
    with app.app_context():
        db.create_all()
    
    return app


def register_error_handlers(app):
    """Register error handlers"""
    from app.utils.errors import APIError
    
    @app.errorhandler(APIError)
    def handle_api_error(error):
        return error.to_dict(), error.status_code
    
    @app.errorhandler(404)
    def handle_not_found(error):
        return {'error': 'Resource not found'}, 404
    
    @app.errorhandler(500)
    def handle_internal_error(error):
        return {'error': 'Internal server error'}, 500


def register_socketio_events(socketio):
    """Register WebSocket event handlers"""
    from app.api.websocket import register_events
    register_events(socketio)