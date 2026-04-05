"""
CyberMind Sentinel Backend Setup & Testing
Contains utilities for development and deployment
"""

import os
import sys
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class CyberMindSetup:
    """Setup utilities for CyberMind Sentinel backend."""
    
    @staticmethod
    def create_directories():
        """Create necessary directories."""
        directories = [
            'logs',
            'config',
            'data',
            'data/honeypot_logs',
            'data/alerts'
        ]
        
        for directory in directories:
            Path(directory).mkdir(parents=True, exist_ok=True)
            print(f"✓ Created directory: {directory}")
    
    @staticmethod
    def create_default_config():
        """Create default configuration file."""
        config_file = 'config/.env.local'
        
        if os.path.exists(config_file):
            print(f"✓ Configuration file already exists: {config_file}")
            return
        
        default_config = {
            "environment": "development",
            "debug": True,
            "firewall_enabled": True,
            "honeypot_enabled": True,
            "monitoring_enabled": True
        }
        
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        print(f"✓ Created default configuration: {config_file}")
    
    @staticmethod
    def verify_dependencies():
        """Verify all required dependencies are installed."""
        required = [
            'flask',
            'flask_cors',
            'dotenv',
            'bcrypt'
        ]
        
        missing = []
        for package in required:
            try:
                __import__(package.replace('-', '_'))
            except ImportError:
                missing.append(package)
        
        if missing:
            print(f"✗ Missing dependencies: {', '.join(missing)}")
            print(f"  Install with: pip install {' '.join(missing)}")
            return False
        
        print("✓ All dependencies installed")
        return True
    
    @staticmethod
    def test_firewall_manager():
        """Test firewall manager initialization."""
        try:
            from app.core.firewall_manager import FirewallManager
            fm = FirewallManager()
            status = fm.get_status()
            print(f"✓ FirewallManager initialized successfully")
            print(f"  OS: {status['os']}")
            print(f"  Isolation Active: {status['isolation_active']}")
            return True
        except Exception as e:
            print(f"✗ FirewallManager test failed: {str(e)}")
            return False
    
    @staticmethod
    def test_services():
        """Test service initialization."""
        try:
            from app.services.ai_translator import AITranslator
            from app.services.fleet_monitor import FleetMonitor
            from app.services.network_honeypot import NetworkHoneypot
            from app.services.phishing_sandbox import PhishingSandbox
            from app.services.remediation_playbook import RemediationPlaybook
            from app.services.kill_switch import KillSwitch
            
            services = {
                'AITranslator': AITranslator(),
                'FleetMonitor': FleetMonitor(),
                'NetworkHoneypot': NetworkHoneypot(),
                'PhishingSandbox': PhishingSandbox(),
                'RemediationPlaybook': RemediationPlaybook(),
                'KillSwitch': KillSwitch()
            }
            
            for name, service in services.items():
                print(f"✓ {name} initialized")
            
            return True
        except Exception as e:
            print(f"✗ Service test failed: {str(e)}")
            return False
    
    @staticmethod
    def run_all_checks():
        """Run all setup checks."""
        print("\n" + "="*50)
        print("CyberMind Sentinel - Backend Setup Verification")
        print("="*50 + "\n")
        
        CyberMindSetup.create_directories()
        print()
        
        CyberMindSetup.create_default_config()
        print()
        
        if not CyberMindSetup.verify_dependencies():
            return False
        print()
        
        if not CyberMindSetup.test_firewall_manager():
            return False
        print()
        
        if not CyberMindSetup.test_services():
            return False
        print()
        
        print("="*50)
        print("✓ All setup checks passed!")
        print("="*50)
        print("\nNext steps:")
        print("1. Configure .env file with your settings")
        print("2. Run: python run.py")
        print("3. Access API at: http://localhost:5000/api")
        print()
        
        return True


if __name__ == '__main__':
    setup = CyberMindSetup()
    success = setup.run_all_checks()
    sys.exit(0 if success else 1)
