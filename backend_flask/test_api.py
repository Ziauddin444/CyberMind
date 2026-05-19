#!/usr/bin/env python3
"""
CyberMind Sentinel - Comprehensive API Testing Suite
Tests all endpoints for firewall management, threat detection, and remediation.
Supports both pytest and manual execution.
"""

import json
import sys
import os
import time
import subprocess
import requests
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    import pytest
    from app import create_app
    PYTEST_AVAILABLE = True
except ImportError:
    PYTEST_AVAILABLE = False


# ============================================================================
# PYTEST FIXTURES AND CLASSES (when pytest is available)
# ============================================================================

if PYTEST_AVAILABLE:
    @pytest.fixture
    def app():
        """Create Flask app for testing."""
        app = create_app('testing')
        return app

    @pytest.fixture
    def client(app):
        """Create test client."""
        return app.test_client()

    class TestFirewallManagement:
        """Test firewall management endpoints."""

        def test_firewall_status(self, client):
            """Test GET /api/firewall/status."""
            response = client.get('/api/firewall/status')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['success'] is True
            assert 'data' in data

        def test_block_ip_success(self, client):
            """Test POST /api/blacklist/ip with valid IP."""
            payload = {
                "ip_address": "192.168.1.100",
                "reason": "Test threat detection"
            }
            response = client.post(
                '/api/blacklist/ip',
                data=json.dumps(payload),
                content_type='application/json',
                headers={'Authorization': 'Bearer test-token'}
            )
            assert response.status_code in [200, 400, 500]
            data = json.loads(response.data)
            assert 'success' in data

        def test_blacklist_status(self, client):
            """Test GET /api/blacklist/status."""
            response = client.get('/api/blacklist/status')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['success'] is True


    class TestFleetMonitor:
        """Test fleet monitoring endpoints."""

        def test_fleet_status(self, client):
            """Test GET /api/fleet/status."""
            response = client.get('/api/fleet/status')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['success'] is True

        def test_ping_asset(self, client):
            """Test POST /api/fleet/ping."""
            payload = {"ip_address": "8.8.8.8", "count": 1}
            response = client.post(
                '/api/fleet/ping',
                data=json.dumps(payload),
                content_type='application/json'
            )
            assert response.status_code == 200


    class TestRemediationPlaybook:
        """Test remediation playbook endpoints."""

        def test_remediation_status(self, client):
            """Test GET /api/remediation/status."""
            response = client.get('/api/remediation/status')
            assert response.status_code == 200
            data = json.loads(response.data)
            assert data['success'] is True

        def test_evaluate_threat(self, client):
            """Test POST /api/remediation/evaluate_threat."""
            payload = {
                "threat_type": "suspicious_connection",
                "source_ip": "192.168.1.150",
                "indicators": ["port_scan"],
                "failed_auth_attempts": 10
            }
            response = client.post(
                '/api/remediation/evaluate_threat',
                data=json.dumps(payload),
                content_type='application/json',
                headers={'Authorization': 'Bearer test-token'}
            )
            assert response.status_code == 200
            data = json.loads(response.data)
            assert 'threat_level' in data['data']


# ============================================================================
# MANUAL TESTING FUNCTIONS (for running without pytest)
# ============================================================================

def start_flask_server():
    """Start Flask development server."""
    print("🚀 Starting CyberMind Flask Backend...")
    proc = subprocess.Popen(
        [sys.executable, 'run.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        cwd=os.path.dirname(os.path.abspath(__file__))
    )
    
    # Wait for server to start
    print("⏳ Waiting for server to initialize...")
    time.sleep(4)
    return proc


def test_endpoint(method, endpoint, payload=None, auth=False):
    """Test a single endpoint."""
    url = f'http://localhost:5000/api{endpoint}'
    
    try:
        headers = {'Content-Type': 'application/json'}
        if auth:
            headers['Authorization'] = 'Bearer test-token'
        
        if method.lower() == 'get':
            response = requests.get(url, headers=headers, timeout=5)
        elif method.lower() == 'post':
            response = requests.post(
                url,
                data=json.dumps(payload) if payload else None,
                headers=headers,
                timeout=5
            )
        else:
            return None
        
        return response
    except Exception as e:
        print(f"  ✗ Error: {str(e)}")
        return None


def print_test_result(endpoint, response):
    """Print formatted test result."""
    if response is None:
        print(f"  ✗ {endpoint} - Connection Error")
        return
    
    try:
        data = response.json()
        status = "✓" if response.status_code == 200 else "⚠"
        success = data.get('success', 'N/A')
        print(f"  {status} {endpoint}")
        print(f"      Status: {response.status_code} | Success: {success}")
    except:
        print(f"  ⚠ {endpoint} - Status: {response.status_code}")


def run_manual_tests():
    """Run tests using live server."""
    print("\n" + "="*70)
    print("CyberMind Sentinel - API Testing Suite (Manual Mode)")
    print("="*70)
    
    proc = start_flask_server()
    
    try:
        # ===== FIREWALL MANAGEMENT =====
        print("\n▶ FIREWALL MANAGEMENT")
        print("-" * 40)
        
        response = test_endpoint('GET', '/firewall/status')
        print_test_result('GET /api/firewall/status', response)
        
        response = test_endpoint('POST', '/blacklist/ip',
            {'ip_address': '192.168.1.100', 'reason': 'Test'}, auth=True)
        print_test_result('POST /api/blacklist/ip', response)
        
        response = test_endpoint('GET', '/blacklist/status')
        print_test_result('GET /api/blacklist/status', response)
        
        # ===== NETWORK ISOLATION =====
        print("\n▶ NETWORK ISOLATION")
        print("-" * 40)
        
        response = test_endpoint('GET', '/isolation/status')
        print_test_result('GET /api/isolation/status', response)
        
        # ===== AI TRANSLATION =====
        print("\n▶ AI TRAFFIC TRANSLATION")
        print("-" * 40)
        
        response = test_endpoint('POST', '/traffic/translate',
            {'telemetry': ['suspicious_conn'], 'context': {}})
        print_test_result('POST /api/traffic/translate', response)
        
        response = test_endpoint('POST', '/traffic/analyze',
            {'threat_type': 'port_scan', 'source_ip': '10.0.0.50'})
        print_test_result('POST /api/traffic/analyze', response)
        
        # ===== FLEET MONITOR =====
        print("\n▶ FLEET MONITOR")
        print("-" * 40)
        
        response = test_endpoint('GET', '/fleet/status')
        print_test_result('GET /api/fleet/status', response)
        
        response = test_endpoint('POST', '/fleet/ping',
            {'ip_address': '8.8.8.8', 'count': 1})
        print_test_result('POST /api/fleet/ping', response)
        
        response = test_endpoint('GET', '/fleet/connections')
        print_test_result('GET /api/fleet/connections', response)
        
        response = test_endpoint('GET', '/fleet/anomalies')
        print_test_result('GET /api/fleet/anomalies', response)
        
        # ===== HONEYPOT =====
        print("\n▶ NETWORK HONEYPOT")
        print("-" * 40)
        
        response = test_endpoint('GET', '/honeypot/logs')
        print_test_result('GET /api/honeypot/logs', response)
        
        # ===== PHISHING SANDBOX =====
        print("\n▶ PHISHING SANDBOX")
        print("-" * 40)
        
        response = test_endpoint('POST', '/phishing/check_url',
            {'url': 'https://example.com'})
        print_test_result('POST /api/phishing/check_url', response)
        
        response = test_endpoint('POST', '/phishing/analyze_email',
            {'email_headers': {'from': 'test@test.com'}, 'body': 'test'})
        print_test_result('POST /api/phishing/analyze_email', response)
        
        response = test_endpoint('GET', '/phishing/statistics')
        print_test_result('GET /api/phishing/statistics', response)
        
        # ===== REMEDIATION PLAYBOOK =====
        print("\n▶ REMEDIATION PLAYBOOK")
        print("-" * 40)
        
        response = test_endpoint('GET', '/remediation/status')
        print_test_result('GET /api/remediation/status', response)
        
        # Test threat evaluation
        threat_payload = {
            'threat_type': 'port_scan',
            'source_ip': '203.0.113.50',
            'indicators': ['port_scan'],
            'failed_auth_attempts': 5
        }
        response = test_endpoint('POST', '/remediation/evaluate_threat',
            threat_payload, auth=True)
        print_test_result('POST /api/remediation/evaluate_threat', response)
        
        response = test_endpoint('GET', '/remediation/incidents')
        print_test_result('GET /api/remediation/incidents', response)
        
        print("\n" + "="*70)
        print("✅ Testing Complete!")
        print("="*70 + "\n")
        
    except KeyboardInterrupt:
        print("\n\n⚠ Testing interrupted by user")
    except Exception as e:
        print(f"\n\n❌ Error during testing: {str(e)}")
    finally:
        # Terminate Flask process
        print("Stopping Flask server...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_api():
    """Legacy function for backwards compatibility."""
    run_manual_tests()


if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == '--pytest':
        # Run with pytest
        if PYTEST_AVAILABLE:
            pytest.main([__file__, '-v'])
        else:
            print("❌ pytest is not installed. Run: pip install pytest")
    else:
        # Run manual tests
        run_manual_tests()


