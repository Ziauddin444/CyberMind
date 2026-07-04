"""
Flask Application Configuration
"""

import os
from datetime import timedelta


class Config:
    """Base configuration."""
    
    # Flask settings
    DEBUG = False
    TESTING = False
    
    # Security settings
    SECRET_KEY = os.environ.get('SECRET_KEY', 'cybermind-dev-secret-key-change-in-production')
    PERMANENT_SESSION_LIFETIME = timedelta(hours=24)
    SESSION_COOKIE_SECURE = False  # Set to True in production with HTTPS
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # CORS settings
    CORS_ORIGINS = [
        'http://localhost:3000',
        'http://localhost:3001',
        'http://localhost:5173',
        'http://127.0.0.1:5173'
    ]
    CORS_ALLOW_HEADERS = ['Content-Type', 'Authorization', 'X-User-Role', 'x-user-role']
    CORS_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS']
    
    # Logging
    LOG_LEVEL = 'INFO'
    LOG_FILE = os.path.join(os.path.dirname(__file__), '..', 'logs', 'cybermind.log')
    
    # API settings
    API_VERSION = '1.0.0'
    API_PREFIX = '/api'
    
    # Security services
    FIREWALL_ENABLED = True
    HONEYPOT_ENABLED = True
    MONITORING_ENABLED = True


class DevelopmentConfig(Config):
    """Development configuration."""
    
    DEBUG = True
    TESTING = False
    SESSION_COOKIE_SECURE = False
    LOG_LEVEL = 'DEBUG'


class ProductionConfig(Config):
    """Production configuration."""
    
    DEBUG = False
    TESTING = False
    SESSION_COOKIE_SECURE = True
    SECRET_KEY = os.environ.get('SECRET_KEY')
    
    # Stricter CORS for production
    CORS_ORIGINS = [
        'https://yourdomain.com',
        'https://www.yourdomain.com'
    ]


class TestingConfig(Config):
    """Testing configuration."""
    
    DEBUG = True
    TESTING = True
    WTF_CSRF_ENABLED = False


def get_config():
    """Get configuration based on environment."""
    env = os.environ.get('FLASK_ENV', 'development')
    
    if env == 'production':
        return ProductionConfig
    elif env == 'testing':
        return TestingConfig
    else:
        return DevelopmentConfig
