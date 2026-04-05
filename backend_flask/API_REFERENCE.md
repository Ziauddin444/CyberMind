"""
CyberMind Sentinel Backend - API Documentation & Testing
Quick reference for all API endpoints
"""

# ─── FIREWALL MANAGEMENT APIs ──────────────────────────────────────────────

# 1. Get Firewall Status
GET /api/firewall/status
Response: {
  "success": true,
  "data": {
    "os": "Darwin|Windows|Linux",
    "isolation_active": false,
    "blocked_ips_count": 0,
    "blocked_ips": [],
    "timestamp": "ISO8601"
  }
}

# 2. Block an IP Address
POST /api/firewall/block_ip
Headers: {"Authorization": "Bearer TOKEN"}
Body: {
  "ip_address": "192.168.1.100",
  "reason": "Malicious traffic detected"
}
Response: {
  "success": true,
  "data": {
    "ip": "192.168.1.100",
    "reason": "Malicious traffic detected",
    "os": "Darwin|Windows|Linux",
    "timestamp": "ISO8601"
  }
}

# 3. Get Blocked IPs
GET /api/firewall/blocked_ips
Response: {
  "success": true,
  "data": {
    "blocked_ips": ["192.168.1.100", "192.168.1.101"],
    "count": 2
  }
}

# ─── KILL SWITCH APIs ──────────────────────────────────────────────────────

# 4. Get Kill Switch Status
GET /api/kill_switch/status
Response: {
  "success": true,
  "data": {
    "activated": false,
    "activation_time": null,
    "activation_reason": null,
    "timestamp": "ISO8601"
  }
}

# 5. Activate Kill Switch (EMERGENCY!)
POST /api/kill_switch/activate
Headers: {"Authorization": "Bearer TOKEN"}
Body: {
  "reason": "Advanced persistent threat detected"
}
Response: {
  "success": true,
  "data": {
    "message": "Network isolation initiated - ALL TRAFFIC BLOCKED",
    "activated_at": "ISO8601",
    "reason": "Advanced persistent threat detected",
    "severity": "CRITICAL"
  }
}

# 6. Deactivate Kill Switch
POST /api/kill_switch/deactivate
Headers: {"Authorization": "Bearer TOKEN"}
Body: {
  "authorization_code": "EMERGENCY_AUTH_CODE_12345"
}
Response: {
  "success": true,
  "data": {
    "message": "Network isolation released - connections restored",
    "deactivated_at": "ISO8601"
  }
}

# ─── HONEYPOT APIs ──────────────────────────────────────────────────────────

# 7. Get Honeypot Status
GET /api/honeypot/status
Response: {
  "success": true,
  "data": {
    "status": "online",
    "listening_ports": [22, 23, 80, 443, 3389],
    "total_connections_logged": 156,
    "active_listeners": 5
  }
}

# 8. Bind Honeypot to Port
POST /api/honeypot/bind
Headers: {"Authorization": "Bearer TOKEN"}
Body: {
  "port": 8888,
  "services": ["ssh", "ftp"]
}
Response: {
  "success": true,
  "data": {
    "status": "bound",
    "port": 8888,
    "services": ["ssh", "ftp"],
    "timestamp": "ISO8601"
  }
}

# 9. Get Honeypot Connection Logs
GET /api/honeypot/logs?limit=50
Response: {
  "success": true,
  "data": {
    "status": "success",
    "total_connections": 156,
    "logs": [
      {
        "source_ip": "203.0.113.45",
        "source_port": 54321,
        "target_port": 22,
        "payload": null,
        "timestamp": "ISO8601"
      }
    ]
  }
}

# ─── FLEET MONITORING APIs ────────────────────────────────────────────────

# 10. Get Fleet Status
GET /api/fleet/status
Response: {
  "success": true,
  "data": {
    "status": "online",
    "total_devices": 42,
    "active_connections": 38,
    "devices": []
  }
}

# 11. Perform Ping Sweep
POST /api/fleet/ping_sweep
Headers: {"Authorization": "Bearer TOKEN"}
Body: {
  "network_range": "192.168.1.0/24"
}
Response: {
  "success": true,
  "data": {
    "network": "192.168.1.0/24",
    "discovered_devices": [],
    "scan_time": "ISO8601"
  }
}

# 12. Track Active Connections
GET /api/fleet/connections
Response: {
  "success": true,
  "data": {
    "status": "pending",
    "active_connections": [],
    "total_connections": 0,
    "timestamp": "ISO8601"
  }
}

# ─── PHISHING SANDBOX APIs ────────────────────────────────────────────────

# 13. Check URL Reputation
POST /api/phishing/check_url
Body: {
  "url": "https://suspicious-site.com/phishing"
}
Response: {
  "success": true,
  "data": {
    "url": "https://suspicious-site.com/phishing",
    "reputation": "safe|suspicious|malicious|unknown",
    "vendors_reported": 0,
    "threat_categories": [],
    "safe": true
  }
}

# 14. Analyze Email
POST /api/phishing/analyze_email
Body: {
  "email_headers": {
    "from": "attacker@evil.com",
    "subject": "Urgent: Verify Your Account"
  },
  "body": "Click here to verify: http://phishing-site.com"
}
Response: {
  "success": true,
  "data": {
    "sender": "attacker@evil.com",
    "phishing_score": 0.85,
    "indicators": ["spoofed_sender", "urgent_language"],
    "suspicious_links": ["http://phishing-site.com"],
    "recommendation": "pending_analysis"
  }
}

# 15. Get Phishing Statistics
GET /api/phishing/statistics
Response: {
  "success": true,
  "data": {
    "status": "online",
    "urls_analyzed": 1250,
    "emails_analyzed": 342,
    "malicious_urls_detected": 18,
    "phishing_emails_blocked": 12
  }
}

# ─── REMEDIATION PLAYBOOK APIs ─────────────────────────────────────────────

# 16. Get Available Playbooks
GET /api/remediation/playbooks
Response: {
  "success": true,
  "data": {
    "playbooks": {
      "block_ip": {
        "name": "Block Malicious IP",
        "description": "Blocks IP address on all firewalls",
        "actions": ["block_ip", "notify"]
      },
      "isolate_network": {...},
      "contain_breach": {...}
    },
    "count": 5
  }
}

# 17. Execute Playbook
POST /api/remediation/execute
Headers: {"Authorization": "Bearer TOKEN"}
Body: {
  "playbook_id": "block_ip",
  "parameters": {
    "target_ip": "192.168.1.100",
    "reason": "Detected C2 connection"
  }
}
Response: {
  "success": true,
  "data": {
    "execution_id": 0,
    "playbook_id": "block_ip",
    "status": "pending",
    "message": "Playbook execution started: Block Malicious IP"
  }
}

# ─── AI TRANSLATOR APIs ────────────────────────────────────────────────────

# 18. Analyze Threat with AI
POST /api/ai/analyze_threat
Body: {
  "threat_type": "port_scan",
  "source_ip": "203.0.113.45",
  "severity": "high"
}
Response: {
  "success": true,
  "data": {
    "threat_analysis": "LLM analysis placeholder",
    "severity": "high",
    "recommendations": [
      "Block source IP",
      "Increase monitoring",
      "Review firewall logs"
    ],
    "confidence": 0.92
  }
}

# 19. Translate Security Logs
POST /api/ai/translate_logs
Body: {
  "logs": [
    "FIREWALL BLOCK: 203.0.113.45:54321 -> 192.168.1.1:22",
    "INTRUSION ALERT: SSH brute force detected on port 22"
  ]
}
Response: {
  "success": true,
  "data": {
    "summary": "Translation of security events..."
  }
}

# 20. Ask Security Question
POST /api/ai/ask
Body: {
  "question": "What is a common phishing technique?"
}
Response: {
  "success": true,
  "data": {
    "answer": "AI response pending LLM integration"
  }
}

# ─── HEALTH & STATUS APIs ─────────────────────────────────────────────────

# 21. Health Check
GET /api/health
Response: {
  "status": "healthy",
  "timestamp": "ISO8601",
  "version": "1.0.0"
}

# 22. System Status
GET /api/status
Response: {
  "status": "online",
  "timestamp": "ISO8601",
  "services": {
    "firewall": "operational",
    "ai_translator": {...},
    "fleet_monitor": {...},
    "honeypot": {...},
    "phishing_sandbox": {...},
    "remediation": {...},
    "kill_switch": {...}
  }
}

# ─── ERROR RESPONSES ──────────────────────────────────────────────────────

# 400 Bad Request
{
  "success": false,
  "message": "Bad Request",
  "error": "Description of error",
  "timestamp": "ISO8601"
}

# 401 Unauthorized
{
  "success": false,
  "message": "Unauthorized",
  "error": "Missing authorization header",
  "timestamp": "ISO8601"
}

# 500 Internal Server Error
{
  "success": false,
  "message": "Internal Server Error",
  "error": "An unexpected error occurred",
  "timestamp": "ISO8601"
}

# ─── CURL EXAMPLES ────────────────────────────────────────────────────────

# Get Firewall Status
curl -X GET http://localhost:5000/api/firewall/status

# Block an IP (requires auth)
curl -X POST http://localhost:5000/api/firewall/block_ip \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "ip_address": "192.168.1.100",
    "reason": "Malicious behavior"
  }'

# Activate Kill Switch (EMERGENCY!)
curl -X POST http://localhost:5000/api/kill_switch/activate \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "reason": "Critical threat detected"
  }'

# Check URL Reputation
curl -X POST http://localhost:5000/api/phishing/check_url \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://example.com"
  }'

# Get Available Playbooks
curl -X GET http://localhost:5000/api/remediation/playbooks

# Execute Remediation Playbook
curl -X POST http://localhost:5000/api/remediation/execute \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "playbook_id": "block_ip",
    "parameters": {
      "target_ip": "192.168.1.100",
      "reason": "Detected C2 connection"
    }
  }'
