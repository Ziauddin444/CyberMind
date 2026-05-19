"""
Flask Application Factory
"""

import logging
import os
import subprocess
from flask import Flask, jsonify
from flask_cors import CORS
from datetime import datetime

from app.core.firewall_manager import FirewallManager
from app.services.ai_translator import AITranslator
from app.services.rogue_asset_detector import RogueAssetDetector
from app.services.network_honeypot import NetworkHoneypot
from app.services.phishing_sandbox import PhishingSandbox
from app.services.ip_blacklist_service import IPBlacklistService
from app.services.kill_switch import KillSwitch
from app.services.fleet_monitor import FleetMonitor
from app.services.remediation_playbook import RemediationPlaybook
from app.services.device_manager import DeviceManager
from app.services.honeypot_file_handler import HoneypotFileHandler


def get_mac_ip() -> str:
    """Return the primary Wi-Fi IPv4 address via `ipconfig getifaddr en0`.

    Returns the stripped output string on success, or 'unavailable' if the
    command fails (non-macOS host, Wi-Fi disconnected, or permission error).
    """
    try:
        result = subprocess.run(
            ["ipconfig", "getifaddr", "en0"],
            capture_output=True,
            text=True,
            timeout=3,
        )
        ip = result.stdout.strip()
        return ip if ip else "unavailable"
    except Exception:
        return "unavailable"


def create_app(config_name: str = None):
    """
    Create and configure Flask application.
    
    Args:
        config_name: Configuration name ('development', 'production', 'testing')
        
    Returns:
        Configured Flask application
    """
    
    app = Flask(__name__)
    
    # Load configuration
    if config_name is None:
        config_name = os.environ.get('FLASK_ENV', 'development')
    
    if config_name == 'production':
        from config.config import ProductionConfig
        app.config.from_object(ProductionConfig)
    elif config_name == 'testing':
        from config.config import TestingConfig
        app.config.from_object(TestingConfig)
    else:
        from config.config import DevelopmentConfig
        app.config.from_object(DevelopmentConfig)
    
    # Setup logging
    _setup_logging(app)
    
    # Initialize CORS
    CORS(
        app,
        origins=app.config['CORS_ORIGINS'],
        allow_headers=app.config['CORS_ALLOW_HEADERS'],
        methods=app.config['CORS_METHODS'],
        supports_credentials=True
    )
    
    # Initialize services
    _initialize_services(app)
    
    # Register error handlers
    _register_error_handlers(app)
    
    # Register blueprints
    _register_blueprints(app)
    
    # Register health check endpoints
    _register_health_checks(app)
    
    app.logger.info(f"CyberMind Sentinel Flask App initialized - Mode: {config_name}")
    
    return app


def _setup_logging(app):
    """Setup application logging."""
    
    # Ensure logs directory exists
    log_dir = os.path.dirname(app.config['LOG_FILE'])
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)
    
    # Configure logging level
    log_level = getattr(logging, app.config['LOG_LEVEL'], logging.INFO)
    
    # File handler
    file_handler = logging.FileHandler(app.config['LOG_FILE'])
    file_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s - %(name)s: %(message)s'
    ))
    file_handler.setLevel(log_level)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(logging.Formatter(
        '[%(asctime)s] %(levelname)s: %(message)s'
    ))
    console_handler.setLevel(log_level)
    
    # Add handlers to flask logger
    app.logger.addHandler(file_handler)
    app.logger.addHandler(console_handler)
    app.logger.setLevel(log_level)


def _initialize_services(app):
    """Initialize security services."""
    
    app.logger.info("Initializing CyberMind security services...")
    
    # Initialize all services
    app.firewall_manager = FirewallManager()
    app.ai_translator = AITranslator()
    app.rogue_asset_detector = RogueAssetDetector()
    app.network_honeypot = NetworkHoneypot()
    app.phishing_sandbox = PhishingSandbox()
    app.ip_blacklist_service = IPBlacklistService(app.firewall_manager)
    app.kill_switch = KillSwitch(app.firewall_manager)
    app.fleet_monitor = FleetMonitor()
    app.remediation_playbook = RemediationPlaybook(
        app.firewall_manager,
        app.kill_switch,
        app.ai_translator
    )
    app.device_manager = DeviceManager()
    app.honeypot_file_handler = HoneypotFileHandler()
    
    app.logger.info("All security services initialized successfully")


def _register_blueprints(app):
    """Register API blueprints."""
    
    from app.api.routes import api_blueprint
    app.register_blueprint(api_blueprint, url_prefix='/api')
    
    app.logger.info("API routes registered")


def _register_error_handlers(app):
    """Register error handlers."""
    
    @app.errorhandler(400)
    def bad_request(error):
        return jsonify({
            "success": False,
            "message": "Bad Request",
            "error": str(error),
            "timestamp": datetime.now().isoformat()
        }), 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return jsonify({
            "success": False,
            "message": "Unauthorized",
            "error": str(error),
            "timestamp": datetime.now().isoformat()
        }), 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return jsonify({
            "success": False,
            "message": "Forbidden",
            "error": str(error),
            "timestamp": datetime.now().isoformat()
        }), 403
    
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({
            "success": False,
            "message": "Not Found",
            "error": str(error),
            "timestamp": datetime.now().isoformat()
        }), 404
    
    @app.errorhandler(500)
    def internal_error(error):
        app.logger.error(f"Internal server error: {str(error)}")
        return jsonify({
            "success": False,
            "message": "Internal Server Error",
            "error": "An unexpected error occurred",
            "timestamp": datetime.now().isoformat()
        }), 500


def _register_health_checks(app):
    """Register health check endpoints."""
    
    @app.route('/api/health', methods=['GET'])
    def health_check():
        """Basic health check."""
        return jsonify({
            "status": "healthy",
            "timestamp": datetime.now().isoformat(),
            "version": app.config['API_VERSION']
        }), 200
    
    @app.route('/api/status', methods=['GET'])
    def system_status():
        """Get comprehensive system status."""
        return jsonify({
            "status": "online",
            "timestamp": datetime.now().isoformat(),
            "mac_ip": get_mac_ip(),
            "services": {
                "firewall": "operational",
                "ai_traffic_translation": app.ai_translator.get_status(),
                "rogue_asset_detection": app.rogue_asset_detector.get_status(),
                "honeypot": app.network_honeypot.get_honeypot_stats(),
                "phishing_sandbox": app.phishing_sandbox.get_phishing_statistics(),
                "ip_blacklisting": app.ip_blacklist_service.get_status(),
                "kill_switch": app.kill_switch.get_status()
            }
        }), 200
