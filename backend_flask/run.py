"""
CyberMind Sentinel - Main Entry Point
Run this to start the Flask backend server
"""

import os
import sys
import logging
import socket
from dotenv import load_dotenv

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Load environment variables
load_dotenv()

# Import Flask app factory
from app import create_app

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(name)s: %(message)s'
)

logger = logging.getLogger(__name__)


def _port_is_available(host: str, port: int) -> bool:
    """Return True when the requested TCP port can be bound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def _find_available_port(host: str, preferred_port: int, fallback_ports: range) -> int:
    """Find the first available port, starting with the preferred port."""
    if _port_is_available(host, preferred_port):
        return preferred_port

    for candidate_port in fallback_ports:
        if candidate_port == preferred_port:
            continue
        if _port_is_available(host, candidate_port):
            logger.warning(
                f"Port {preferred_port} is busy; switching CyberMind Sentinel to fallback port {candidate_port}"
            )
            return candidate_port

    logger.warning(
        f"Port {preferred_port} is busy and no fallback ports are available"
    )
    return preferred_port


def main():
    """Main entry point."""
    
    # Get configuration mode
    config_name = os.environ.get('FLASK_ENV', 'development')
    
    logger.info(f"Starting CyberMind Sentinel - Mode: {config_name}")
    
    # Create Flask app
    app = create_app(config_name)
    
    # Get server configuration
    host = os.environ.get('FLASK_HOST', '0.0.0.0')
    port = int(os.environ.get('FLASK_PORT', 5000))
    debug = config_name == 'development'

    if port == 5000:
        port = _find_available_port(host, 5000, range(5001, 5011))
    
    logger.info(f"Server starting: {host}:{port}")
    logger.info(f"Dashboard: http://localhost:{port}")
    logger.info(f"API Docs: http://localhost:{port}/api")
    
    # Start server
    app.run(
        host=host,
        port=port,
        debug=debug,
        use_reloader=debug
    )


if __name__ == '__main__':
    main()
