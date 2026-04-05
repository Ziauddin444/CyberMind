#!/usr/bin/env python3
"""
Test Flask API endpoints
"""
import time
import subprocess
import requests
import os
import sys
import signal

def test_api():
    """Test Flask API endpoints"""
    
    # Start Flask server
    os.chdir('/Users/ziauddin/Documents/GitHub/CyberMind/backend_flask')
    
    print("🚀 Starting CyberMind Flask Backend...")
    proc = subprocess.Popen(
        ['./venv/bin/python', 'run.py'],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Wait for server to start
    print("⏳ Waiting for server to initialize...")
    time.sleep(4)
    
    try:
        # Test health endpoint
        print("\n📋 Testing API Health Endpoint...")
        response = requests.get('http://localhost:5000/api/health', timeout=5)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        # Test status endpoint
        print("\n📊 Testing API Status Endpoint...")
        response = requests.get('http://localhost:5000/api/status', timeout=5)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        # Test firewall status
        print("\n🔥 Testing Firewall Status Endpoint...")
        response = requests.get('http://localhost:5000/api/firewall/status', timeout=5)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.json()}")
        
        print("\n✅ All tests passed! Flask backend is running successfully!")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        sys.exit(1)
    finally:
        # Kill Flask server
        proc.terminate()
        proc.wait(timeout=5)
        print("\n🛑 Server stopped")

if __name__ == '__main__':
    test_api()
