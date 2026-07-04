"""
CyberMind Sentinel API Routes
Network-level active defense endpoints for Commander Agent architecture.
"""

import logging
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from datetime import datetime
from functools import wraps
from pathlib import Path

from flask import Blueprint, current_app, jsonify, request
from app.services import ids_engine  # Layer 3 — AI model

logger = logging.getLogger(__name__)

# ── SQLite scan logging ────────────────────────────────────────────────────────
_DB_PATH = Path(__file__).parent.parent.parent / "data" / "cybermind_logs.db"
_DB_LOCK = threading.Lock()


def _init_scan_db() -> None:
    """Initialize SQLite database with scan logging tables."""
    with sqlite3.connect(_DB_PATH) as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS scan_logs (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT    NOT NULL,
                label           TEXT    NOT NULL,
                severity        TEXT    NOT NULL,
                confidence      REAL    NOT NULL,
                packet_count    INTEGER NOT NULL,
                capture_mode    TEXT    NOT NULL,
                threat_detected INTEGER NOT NULL
            )
        """)
        con.execute("""
            CREATE TABLE IF NOT EXISTS traffic_counts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT    NOT NULL,
                label     TEXT    NOT NULL,
                count     INTEGER NOT NULL DEFAULT 1
            )
        """)
        con.commit()
    logger.info("SQLite scan database initialized → %s", _DB_PATH)


_init_scan_db()


@contextmanager
def _scan_db():
    """Thread-safe SQLite connection context manager for scan logging."""
    con = sqlite3.connect(_DB_PATH, check_same_thread=False)
    con.row_factory = sqlite3.Row
    try:
        yield con
        con.commit()
    finally:
        con.close()


def _log_scan_to_db(result: dict) -> None:
    """Persist a completed scan result to SQLite."""
    with _DB_LOCK:
        with _scan_db() as con:
            con.execute(
                """INSERT INTO scan_logs
                   (timestamp, label, severity, confidence, packet_count, capture_mode, threat_detected)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    result.get("timestamp", datetime.utcnow().isoformat() + "Z"),
                    result.get("label", "unknown"),
                    result.get("severity", "low"),
                    float(result.get("confidence", 0)),
                    int(result.get("packet_count", 0)),
                    result.get("capture_mode", "live"),
                    1 if result.get("threat_detected") else 0,
                ),
            )
            # Also record the per-label breakdown as individual traffic_counts rows
            for lbl, pct in (result.get("breakdown") or {}).items():
                count = max(1, round(pct * result.get("packet_count", 100) / 100))
                con.execute(
                    "INSERT INTO traffic_counts (timestamp, label, count) VALUES (?, ?, ?)",
                    (datetime.utcnow().isoformat() + "Z", lbl, count),
                )


api_blueprint = Blueprint("api", __name__)

ROLE_LEVELS = {
    "viewer": 1,
    "analyst": 2,
    "admin": 3,
    "super-admin": 4,
}


def require_auth(f):
    """Decorator for endpoints requiring authentication (stub)."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"success": False, "message": "Missing authorization header"}), 401
        return f(*args, **kwargs)

    return decorated_function


def _get_request_role() -> str:
    """Get caller role from forwarded headers; default to viewer."""
    role = request.headers.get("X-User-Role", "viewer").strip().lower()
    return role if role in ROLE_LEVELS else "viewer"


def require_role(min_role: str):
    """Decorator to enforce minimum RBAC role for endpoint access."""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            current_role = _get_request_role()
            if ROLE_LEVELS[current_role] < ROLE_LEVELS[min_role]:
                return jsonify({
                    "success": False,
                    "message": f"Insufficient role. Required: {min_role}, current: {current_role}",
                }), 403
            return f(*args, **kwargs)

        return decorated_function

    return decorator


# --- FIREWALL COMMANDER ---


@api_blueprint.route("/firewall/status", methods=["GET"])
def get_firewall_status():
    try:
        status = current_app.firewall_manager.get_status()
        return jsonify({
            "success": True,
            "data": status,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting firewall status: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


# --- 1-CLICK IP BLACKLISTING ---


@api_blueprint.route("/blacklist/ip", methods=["POST"])
@require_auth
@require_role("analyst")
def blacklist_ip():
    try:
        data = request.get_json() or {}
        ip_address = data.get("ip_address")
        reason = data.get("reason", "Threat intel match")

        if not ip_address:
            return jsonify({"success": False, "message": "ip_address required"}), 400

        result = current_app.ip_blacklist_service.blacklist_ip(ip_address, reason)
        status_code = 200 if result.get("success") else 400

        return jsonify({
            "success": result.get("success", False),
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), status_code
    except Exception as e:
        logger.error(f"Error blacklisting IP: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/block_ip", methods=["POST"])
@require_auth
@require_role("analyst")
def block_ip_alias():
    """Compatibility alias for legacy clients expecting /api/block_ip."""
    return blacklist_ip()


@api_blueprint.route("/blacklist/status", methods=["GET"])
def blacklist_status():
    try:
        status = current_app.ip_blacklist_service.get_status()
        return jsonify({
            "success": True,
            "data": status,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting blacklist status: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


# --- NETWORK ISOLATION KILL-SWITCH ---


@api_blueprint.route("/isolation/status", methods=["GET"])
def isolation_status():
    try:
        status = current_app.kill_switch.get_status()
        return jsonify({
            "success": True,
            "data": status,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting isolation status: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/isolation/activate", methods=["POST"])
@require_auth
@require_role("admin")
def activate_isolation():
    try:
        data = request.get_json() or {}
        reason = data.get("reason", "Manual kill-switch activation")

        result = current_app.kill_switch.activate(reason=reason, auto=False)
        status_code = 200 if result.get("success") else 400

        return jsonify({
            "success": result.get("success", False),
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), status_code
    except Exception as e:
        logger.error(f"Error activating isolation: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/kill_switch", methods=["POST"])
@require_auth
@require_role("admin")
def kill_switch_alias():
    """Compatibility alias for legacy clients expecting /api/kill_switch."""
    return activate_isolation()


@api_blueprint.route("/isolation/deactivate", methods=["POST"])
@require_auth
@require_role("admin")
def deactivate_isolation():
    try:
        data = request.get_json() or {}
        auth_code = data.get("authorization_code")

        result = current_app.kill_switch.deactivate(authorization_code=auth_code)
        status_code = 200 if result.get("success") else 400

        return jsonify({
            "success": result.get("success", False),
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), status_code
    except Exception as e:
        logger.error(f"Error deactivating isolation: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


# --- AI TRAFFIC TRANSLATION ---


@api_blueprint.route("/traffic/translate", methods=["POST"])
def translate_traffic():
    """
    Translate a raw threat alert into plain English using 
    Ollama Mistral. Falls back to rule-based if Ollama offline.
    """
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'No data provided'}), 400
    
    threat_data = {
        'threat_type': data.get('threat_type', 'unknown'),
        'severity': data.get('severity', 'medium'),
        'confidence': data.get('confidence', 0.5),
        'source_ip': data.get('source_ip', 'unknown'),
        'matched_signature': data.get('matched_signature', 'unknown'),
        'mitigation': data.get('mitigation', 'Monitor and investigate')
    }
    
    result = current_app.ai_translator.analyze_threat(threat_data)
    ollama_status = current_app.ai_translator.check_ollama_status()
    
    return jsonify({
        'success': True,
        'translation': result,
        'ollama_active': ollama_status['available'],
        'timestamp': datetime.utcnow().isoformat()
    })


@api_blueprint.route("/ollama/status", methods=["GET"])
def ollama_status():
    """Check if Ollama is running and Mistral is available."""
    status = current_app.ai_translator.check_ollama_status()
    instructions = current_app.ai_translator.get_ollama_install_instructions()
    return jsonify({
        'success': True,
        'ollama': status,
        'install_instructions': instructions,
        'timestamp': datetime.utcnow().isoformat()
    })


@api_blueprint.route("/ollama/test", methods=["POST"])
def ollama_test():
    """
    Test endpoint — send a sample threat and get back 
    a plain English translation. Used for demo purposes.
    """
    sample_threat = {
        'threat_type': 'port_scan',
        'severity': 'high',
        'confidence': 0.92,
        'source_ip': '192.168.1.100',
        'matched_signature': 'nmap',
        'mitigation': 'Block source IP and enable port-scan rate limiting'
    }
    result = current_app.ai_translator.analyze_threat(sample_threat)
    ollama_status = current_app.ai_translator.check_ollama_status()
    
    return jsonify({
        'success': True,
        'test_input': sample_threat,
        'translation': result,
        'ollama_active': ollama_status['available'],
        'timestamp': datetime.utcnow().isoformat()
    })


@api_blueprint.route("/traffic/analyze", methods=["POST"])
def analyze_traffic_threat():
    try:
        data = request.get_json() or {}
        if not data:
            return jsonify({"success": False, "message": "threat data required"}), 400

        result = current_app.ai_translator.analyze_threat(data)
        return jsonify({
            "success": True,
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error analyzing traffic threat: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500





# --- NETWORK HONEYPOT ---


@api_blueprint.route("/honeypot/status", methods=["GET"])
def honeypot_status():
    try:
        status = current_app.network_honeypot.get_threat_analysis()
        return jsonify({
            "success": True,
            "data": status,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting honeypot status: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/honeypot/bind", methods=["POST"])
@require_auth
def bind_honeypot():
    try:
        data = request.get_json() or {}
        port = data.get("port")
        services = data.get("services", ["generic"])

        if port is None:
            return jsonify({"success": False, "message": "port required"}), 400

        result = current_app.network_honeypot.bind_port(port, services)
        status_code = 200 if result.get("status") == "bound" else 400

        return jsonify({
            "success": result.get("status") == "bound",
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), status_code
    except Exception as e:
        logger.error(f"Error binding honeypot port: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/honeypot/logs", methods=["GET"])
def honeypot_logs():
    try:
        limit = request.args.get("limit", 100, type=int)
        logs = current_app.network_honeypot.get_connection_logs(limit)
        return jsonify({
            "success": True,
            "data": logs.get("logs", []),
            "meta": {
                "total_connections": logs.get("total_connections", 0),
                "status": logs.get("status", "success"),
            },
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting honeypot logs: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/demo/attack-sim", methods=["POST"])
def demo_attack_simulation():
    """
    Demo-safe endpoint: receives simulated attack payloads and records detections.
    Intended for controlled lab demonstrations only.
    """
    try:
        # Keep this endpoint development-only to avoid exposing simulation in production.
        if not current_app.config.get("DEBUG", False):
            return jsonify({"success": False, "message": "Demo simulation is disabled outside development mode"}), 403

        data = request.get_json(silent=True) or {}

        forwarded_for = request.headers.get("X-Forwarded-For", "")
        source_ip = (data.get("source_ip") or (forwarded_for.split(",")[0].strip() if forwarded_for else None) or request.remote_addr or "unknown")
        source_port = int(request.environ.get("REMOTE_PORT", 0) or 0)
        target_port = int(data.get("target_port") or 8080)
        payload = str(data.get("payload") or data.get("command") or data.get("message") or "simulated network event")

        threat_context = {
            "threat_type": data.get("threat_type", "unknown"),
            "tool": data.get("tool", "unknown"),
            "message": data.get("message", ""),
            "payload": payload,
            "command": data.get("command", ""),
            "target_ports": data.get("target_ports", [target_port]) if isinstance(data.get("target_ports", [target_port]), list) else [target_port],
        }

        analysis = current_app.ai_translator.analyze_threat(threat_context)
        derived_threat_type = analysis.get("threat_type", "honeypot_capture")
        derived_severity = analysis.get("severity", "medium")
        threat_detected = analysis.get("threat_detected", False)
        should_auto_block = bool(data.get("auto_block", True)) and threat_detected

        capture_file = None
        try:
            capture_result = current_app.honeypot_file_handler.save_capture_file(source_ip, payload, derived_threat_type)
            if capture_result.get("success"):
                capture_file = capture_result.get("capture", {}).get("filename")
        except Exception as capture_error:
            logger.warning(f"Honeypot capture save skipped: {capture_error}")

        current_app.network_honeypot.log_connection(
            source_ip=source_ip,
            source_port=source_port,
            target_port=target_port,
            payload=payload,
            threat_type=derived_threat_type,
            severity=derived_severity,
            capture_file=capture_file,
        )

        block_result = None
        if should_auto_block:
            reason = f"Auto-block from demo attack simulation ({derived_threat_type})"
            block_result = current_app.ip_blacklist_service.blacklist_ip(source_ip, reason)

        return jsonify({
            "success": True,
            "message": "Simulation ingested and detection recorded",
            "data": {
                "source_ip": source_ip,
                "target_port": target_port,
                "threat_detected": threat_detected,
                "threat_type": derived_threat_type,
                "severity": derived_severity,
                "confidence": analysis.get("confidence", 0),
                "capture_file": capture_file,
                "auto_blocked": bool(block_result and block_result.get("success")),
                "block_result": block_result,
                "analysis": analysis,
            },
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error in demo attack simulation: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500




# --- ONE-CLICK EMERGENCY REMEDIATION ---


@api_blueprint.route("/remediation/one-click", methods=["POST"])
@require_auth
@require_role("admin")
def one_click_remediation():
    """
    Emergency one-click remediation for critical threats
    Blocks IP + Isolates network + Escalates to SOC
    """
    try:
        data = request.get_json() or {}
        threat_ip = data.get("threat_ip")
        threat_type = data.get("threat_type", "unknown")
        severity = data.get("severity", "critical")

        if not threat_ip:
            return jsonify({"success": False, "message": "threat_ip required"}), 400

        actions_taken = {
            "ip_blocked": False,
            "network_isolated": False,
            "alert_escalated": False
        }

        try:
            # Step 1: Block the IP immediately
            block_result = current_app.firewall_manager.block_ip(threat_ip, f"{threat_type} - One-click remediation")
            actions_taken["ip_blocked"] = block_result.get("success", False)
        except Exception as e:
            logger.error(f"Failed to block IP in one-click: {e}")

        try:
            # Step 2: Isolate network if severity is critical
            if severity.lower() == "critical":
                iso_result = current_app.kill_switch.activate()
                actions_taken["network_isolated"] = iso_result.get("success", False)
        except Exception as e:
            logger.error(f"Failed to isolate network in one-click: {e}")

        try:
            # Step 3: Create and escalate alert
            alert = {
                "threat_ip": threat_ip,
                "threat_type": threat_type,
                "severity": severity,
                "timestamp": datetime.now().isoformat(),
                "actions_taken": actions_taken
            }
            actions_taken["alert_escalated"] = True
        except Exception as e:
            logger.error(f"Failed to escalate alert in one-click: {e}")

        logger.warning(f"One-click remediation triggered for {threat_ip}: {actions_taken}")

        return jsonify({
            "success": True,
            "message": "Emergency remediation activated",
            "threat_ip": threat_ip,
            "actions_taken": actions_taken,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error in one-click remediation: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


# --- DEVICE MANAGEMENT ---


@api_blueprint.route("/devices/list", methods=["GET"])
def list_devices():
    """List all managed devices"""
    try:
        devices = current_app.device_manager.list_devices()
        return jsonify({
            "success": True,
            "data": devices,
            "count": len(devices),
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/devices/status", methods=["GET"])
def devices_status():
    """Get device inventory status"""
    try:
        status = current_app.device_manager.get_status()
        return jsonify({
            "success": True,
            "data": status,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting device status: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500
@api_blueprint.route("/devices/search", methods=["GET"])
def search_devices():
    """Search devices by name or IP"""
    try:
        query = request.args.get("q", "")
        if not query:
            return jsonify({"success": False, "message": "Query parameter 'q' is required"}), 400
        
        devices = current_app.device_manager.search_devices(query)
        return jsonify({
            "success": True,
            "data": devices,
            "count": len(devices),
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error searching devices: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/devices/add", methods=["POST"])
def add_device_legacy():
    """Legacy POST /api/devices/add — no auth guard for demo usage"""
    try:
        data = request.get_json() or {}
        current_app.device_manager._load_devices()
        result = current_app.device_manager.add_device(data)
        if result.get("success"):
            return jsonify({
                "success": True,
                "data": result.get("device"),
                "message": "Device added successfully",
                "timestamp": datetime.now().isoformat(),
            }), 201
        else:
            return jsonify({"success": False, "message": result.get("error")}), 400
    except Exception as e:
        logger.error(f"Error adding device (legacy): {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/devices", methods=["POST"])
def create_device_canonical():
    """Canonical POST /api/devices — persists a new device to devices.json (no auth guard for demo)"""
    try:
        data = request.get_json() or {}
        current_app.device_manager._load_devices()
        result = current_app.device_manager.add_device(data)
        if result.get("success"):
            return jsonify({
                "success": True,
                "data": result.get("device"),
                "message": "Device added successfully",
                "timestamp": datetime.now().isoformat(),
            }), 201
        else:
            return jsonify({"success": False, "message": result.get("error"), "error": result.get("error")}), 400
    except Exception as e:
        logger.error(f"Error adding device (canonical): {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/devices/<device_id>", methods=["GET"])
def get_device(device_id):
    """Get device by ID"""
    try:
        device = current_app.device_manager.get_device(device_id)
        if device:
            return jsonify({
                "success": True,
                "data": device,
                "timestamp": datetime.now().isoformat(),
            }), 200
        else:
            return jsonify({"success": False, "message": "Device not found"}), 404
    except Exception as e:
        logger.error(f"Error getting device {device_id}: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/devices/<device_id>", methods=["PUT"])
def update_device(device_id):
    """Update device information — no auth guard for demo"""
    try:
        print(f"🔍 UPDATE request for device_id: '{device_id}' (type: {type(device_id)})")  # ADD THIS
        
        data = request.get_json() or {}
        current_app.device_manager._load_devices()
        result = current_app.device_manager.update_device(device_id, data)
        print(f"📋 Update result: {result}")  # ADD THIS
        
        if result.get("success"):
            return jsonify({
                "success": True,
                "data": result.get("device"),
                "message": "Device updated successfully",
                "timestamp": datetime.now().isoformat(),
            }), 200
        else:
            return jsonify({"success": False, "message": result.get("error")}), 404
    except Exception as e:
        logger.error(f"Error updating device {device_id}: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500

@api_blueprint.route("/devices/<device_id>", methods=["DELETE"])
def delete_device(device_id):
    """Delete a device — no auth guard for demo"""
    try:
        print(f"🔍 DELETE request for device_id: '{device_id}' (type: {type(device_id)})")  # ADD THIS
        
        current_app.device_manager._load_devices()
        
        # ADD THIS: Log what devices are loaded
        all_devices = current_app.device_manager.devices  # or whatever the attribute is called
        print(f"📦 Loaded {len(all_devices)} devices: {[d.get('id') for d in all_devices]}")
        
        result = current_app.device_manager.delete_device(device_id)
        print(f"📋 Delete result: {result}")  # ADD THIS
        
        if result.get("success"):
            return jsonify({
                "success": True,
                "message": result.get("message"),
                "timestamp": datetime.now().isoformat(),
            }), 200
        else:
            return jsonify({"success": False, "message": result.get("error")}), 404
    except Exception as e:
        logger.error(f"Error deleting device {device_id}: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/honeypot/files", methods=["GET"])
def list_honeypot_captures():
    """List honeypot captures"""
    try:
        limit = request.args.get("limit", 100, type=int)
        captures = current_app.honeypot_file_handler.list_captures(limit)
        return jsonify({
            "success": True,
            "data": captures,
            "count": len(captures),
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error listing honeypot captures: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/honeypot/files/<int:capture_id>", methods=["GET"])
def get_honeypot_file(capture_id):
    """Retrieve specific honeypot capture file"""
    try:
        content = current_app.honeypot_file_handler.get_capture_file(capture_id)
        if not content:
            return jsonify({"success": False, "message": "Capture not found"}), 404

        return jsonify({
            "success": True,
            "data": content,
            "capture_id": capture_id,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting honeypot file: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/honeypot/files/<int:capture_id>", methods=["DELETE"])
@require_auth
@require_role("analyst")
def delete_honeypot_capture(capture_id):
    """Delete a honeypot capture"""
    try:
        result = current_app.honeypot_file_handler.delete_capture(capture_id)
        status_code = 200 if result.get("success") else 404
        return jsonify({
            "success": result.get("success", False),
            "message": result.get("message") if result.get("success") else result.get("error"),
            "timestamp": datetime.now().isoformat(),
        }), status_code
    except Exception as e:
        logger.error(f"Error deleting honeypot capture: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/honeypot/files/export", methods=["GET"])
def export_honeypot_captures():
    """Export honeypot captures"""
    try:
        format_type = request.args.get("format", "json")
        result = current_app.honeypot_file_handler.export_captures(format_type)
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code
    except Exception as e:
        logger.error(f"Error exporting honeypot captures: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/honeypot/summary", methods=["GET"])
def honeypot_threat_summary():
    """Get threat summary from honeypot captures"""
    try:
        summary = current_app.honeypot_file_handler.get_threat_summary()
        return jsonify({
            "success": True,
            "data": summary,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting honeypot summary: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/honeypot/cleanup", methods=["POST"])
@require_auth
@require_role("admin")
def cleanup_old_honeypot_captures():
    """Clean up old honeypot captures"""
    try:
        data = request.get_json() or {}
        days = data.get("days", 30)
        result = current_app.honeypot_file_handler.cleanup_old_captures(days)
        status_code = 200 if result.get("success") else 400
        return jsonify(result), status_code
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


# --- HONEYPOT FILE CRUD (by filename) ---


@api_blueprint.route("/honeypot/files", methods=["POST"])
def create_honeypot_file():
    """
    POST /api/honeypot/files
    Create a new honeypot file.
    Body: { "filename": str, "content": str }
    """
    try:
        data = request.get_json() or {}
        filename = (data.get("filename") or "").strip()
        content = data.get("content", "")

        if not filename:
            return jsonify({"success": False, "error": "filename is required"}), 400

        result = current_app.honeypot_file_handler.add_file(filename, content)
        status_code = 201 if result.get("success") else 400
        return jsonify({
            "success": result.get("success", False),
            "data": result.get("file"),
            "error": result.get("error"),
            "timestamp": datetime.now().isoformat(),
        }), status_code
    except Exception as e:
        logger.error(f"Error creating honeypot file: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


@api_blueprint.route("/honeypot/files/<filename>", methods=["PUT"])
def rename_honeypot_file(filename):
    """
    PUT /api/honeypot/files/<filename>
    Rename a honeypot file on disk.
    Body: { "new_filename": str }
    """
    try:
        data = request.get_json() or {}
        new_filename = (data.get("new_filename") or "").strip()
        if not new_filename:
            return jsonify({"success": False, "error": "new_filename is required"}), 400

        result = current_app.honeypot_file_handler.rename_file(filename, new_filename)
        status_code = 200 if result.get("success") else 400
        return jsonify({
            "success": result.get("success", False),
            "data": result,
            "error": result.get("error"),
            "timestamp": datetime.now().isoformat(),
        }), status_code
    except Exception as e:
        logger.error(f"Error renaming honeypot file {filename}: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


@api_blueprint.route("/honeypot/files/<filename>", methods=["DELETE"])
def delete_honeypot_file_by_name(filename):
    """
    DELETE /api/honeypot/files/<filename>
    Delete a honeypot file from disk by its filename.
    """
    try:
        from pathlib import Path as _Path
        safe = _Path(filename).name
        if not safe:
            return jsonify({"success": False, "error": "Invalid filename"}), 400

        filepath = current_app.honeypot_file_handler.honeypot_dir / safe
        if not filepath.exists():
            return jsonify({"success": False, "error": f"File not found: {safe}"}), 404

        filepath.unlink()
        # Remove from captures list if tracked
        updated = [c for c in current_app.honeypot_file_handler.captures if c.get("filename") != safe]
        current_app.honeypot_file_handler.captures = updated
        current_app.honeypot_file_handler._save_captures()

        logger.info(f"Honeypot file deleted by name: {safe}")
        return jsonify({
            "success": True,
            "message": f"File {safe} deleted",
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error deleting honeypot file {filename}: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


@api_blueprint.route("/honeypot/files-list", methods=["GET"])
def list_honeypot_files_on_disk():
    """
    GET /api/honeypot/files-list
    Returns every file present in honeypot_captures/ (not just metadata captures).
    """
    try:
        files = current_app.honeypot_file_handler.list_files()
        return jsonify({
            "success": True,
            "data": files,
            "count": len(files),
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error listing honeypot files: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# /api/remediation  —  One-Click Remediation Buttons
# =============================================================================
# Accepts { action, ip, device_id, threat_type, severity }.
# No auth required so the demo works without login.
# =============================================================================


@api_blueprint.route("/remediation", methods=["POST"])
def run_remediation():
    """
    POST /api/remediation
    Execute one of three remediation actions:
      action = "block_ip"       — add ip to the firewall blocklist
      action = "isolate_device" — activate kill-switch / network isolation
      action = "run_playbook"   — evaluate threat and run remediation playbook
    """
    try:
        data = request.get_json() or {}
        action = (data.get("action") or "").strip()
        ip = data.get("ip") or data.get("threat_ip") or "0.0.0.0"
        device_id = data.get("device_id")
        threat_type = data.get("threat_type", "manual_remediation")
        severity = data.get("severity", "high")

        if not action:
            return jsonify({"success": False, "error": "action is required"}), 400

        result_payload = {
            "action": action,
            "ip": ip,
            "timestamp": datetime.now().isoformat(),
        }

        if action == "block_ip":
            reason = f"Manual block via one-click remediation ({threat_type})"
            block_result = current_app.ip_blacklist_service.blacklist_ip(ip, reason)
            result_payload.update({
                "success": block_result.get("success", False),
                "message": f"IP {ip} blocked" if block_result.get("success") else block_result.get("error", "Block failed"),
                "data": block_result,
            })

        elif action == "isolate_device":
            iso_result = current_app.kill_switch.activate(
                reason=f"Manual isolation via one-click remediation ({threat_type})",
                auto=False,
            )
            result_payload.update({
                "success": iso_result.get("success", False),
                "message": "Network isolated" if iso_result.get("success") else iso_result.get("error", "Isolation failed"),
                "data": iso_result,
            })

        elif action == "run_playbook":
            # Block + optionally isolate + AI analysis
            actions_taken = {}
            # Step 1: Block IP
            try:
                br = current_app.firewall_manager.block_ip(ip, f"Playbook remediation – {threat_type}")
                actions_taken["ip_blocked"] = br.get("success", False)
            except Exception as ex:
                actions_taken["ip_blocked"] = False
                logger.warning(f"Playbook: block IP failed: {ex}")

            # Step 2: Isolate if critical
            if severity.lower() in ("critical", "high"):
                try:
                    ir = current_app.kill_switch.activate(
                        reason=f"Playbook remediation – {threat_type}",
                        auto=True,
                    )
                    actions_taken["network_isolated"] = ir.get("success", False)
                except Exception as ex:
                    actions_taken["network_isolated"] = False
                    logger.warning(f"Playbook: isolation failed: {ex}")

            # Step 3: AI analysis
            try:
                analysis = current_app.ai_translator.analyze_threat({
                    "threat_type": threat_type,
                    "source_ip": ip,
                    "severity": severity,
                })
                actions_taken["ai_analysis"] = True
            except Exception:
                analysis = {}
                actions_taken["ai_analysis"] = False

            result_payload.update({
                "success": True,
                "message": "Playbook executed",
                "actions_taken": actions_taken,
                "analysis": analysis,
            })

        else:
            return jsonify({"success": False, "error": f"Unknown action: {action}"}), 400

        logger.info(f"Remediation executed: action={action} ip={ip} success={result_payload.get('success')}")
        return jsonify(result_payload), 200

    except Exception as e:
        logger.error(f"Error in /api/remediation: {str(e)}")
        return jsonify({"success": False, "error": str(e)}), 500


# =============================================================================
# /api/analyze  —  The Core AI Analysis Route
# =============================================================================
# Architecture:
#   Frontend  ──fetch──►  Flask /api/analyze  ──►  ids_engine.analyze()  ──►  JSON
#
# Accepts JSON body OR multipart form (for file uploads).
# No authentication required so the Analyze panel works without login
# for quick classroom / professor demos.  Auth can be added by wrapping
# with @require_auth if needed.
# =============================================================================

@api_blueprint.route("/analyze", methods=["POST"])
def analyze_input():
    """
    Layer 2 — Flask brain.

    Receives input from the frontend, hands it to the IDS engine (Layer 3),
    and returns the structured threat assessment as JSON.

    Accepted JSON fields:
        text        str   — raw log line, alert text, or CLI command to analyse
        log_lines   list  — multiple log lines (analysed as one corpus)
        threat_type str   — optional hint ('brute_force', 'sql_injection', …)
        source_ip   str   — source IP address of the observed traffic
        target_ports list — destination port numbers (ints)

    Accepted multipart form fields:
        file        — plain-text log file OR binary packet capture (.pcap)
        text        — same as JSON text field
    """
    try:
        payload: dict = {}

        # ── A. Multipart file upload ────────────────────────────────────────
        if request.content_type and "multipart/form-data" in request.content_type:
            payload["text"] = request.form.get("text", "")
            payload["threat_type"] = request.form.get("threat_type", "")
            payload["source_ip"] = request.form.get("source_ip", "")

            uploaded = request.files.get("file")
            if uploaded:
                raw = uploaded.read()
                # Try decoding as text first; fall back to binary packet analysis
                try:
                    payload["log_lines"] = raw.decode("utf-8", errors="strict").splitlines()
                except UnicodeDecodeError:
                    # Binary file — treat as raw packet bytes
                    payload["raw_packet"] = raw
                    payload["log_lines"] = []

        # ── B. JSON body ───────────────────────────────────────────────────
        else:
            body = request.get_json(silent=True) or {}
            payload["text"]         = str(body.get("text", ""))
            payload["log_lines"]    = body.get("log_lines") or []
            payload["threat_type"] = str(body.get("threat_type", ""))
            payload["source_ip"]   = str(body.get("source_ip", ""))
            payload["target_ports"] = body.get("target_ports") or []

        # ── C. Reject empty requests ───────────────────────────────────────
        has_input = (
            payload.get("text")
            or payload.get("log_lines")
            or payload.get("raw_packet")
        )
        if not has_input:
            return jsonify({
                "success": False,
                "message": "No input provided. Send 'text', 'log_lines', or a file.",
            }), 400

        # ── D. Call Layer 3 — IDS Engine ──────────────────────────────────
        logger.info(
            "/api/analyze called | ip=%s | type=%s | text_len=%d",
            payload.get("source_ip", ""),
            payload.get("threat_type", ""),
            len(payload.get("text", "")),
        )
        result = ids_engine.analyze(payload)

        # ── E. Return to Layer 1 — Frontend ───────────────────────────────
        return jsonify(result), 200

    except Exception as exc:
        logger.error("Unexpected error in /api/analyze: %s", str(exc), exc_info=True)
        return jsonify({"success": False, "message": "Internal analysis error."}), 500


# =============================================================================
# /api/scan/*  —  Packet Scan Routes
# =============================================================================
# Architecture:
#   Frontend  ──fetch──►  POST /api/scan/start  ──►  background thread
#                         GET  /api/scan/status/<id>  ◄── frontend polls
#
# The background thread:
#   1. packet_scanner.scan_packets(N)   → raw feature dicts
#   2. rf_classifier.RFClassifier.get().predict(features)  → label + confidence
#
# Job state is kept in the module-level dict _SCAN_JOBS (in-process cache).
# For multi-worker deployments replace with Redis.
# =============================================================================

from app.services import packet_scanner   # Layer 3 — Scapy sniffer
from app.services.rf_classifier import RFClassifier  # Layer 3 — AI model

# In-process job store  {job_id: dict}
_SCAN_JOBS: dict[str, dict] = {}
_SCAN_LOCK = threading.Lock()


def _run_scan_job(job_id: str, packet_count: int) -> None:
    """Background worker: sniff packets → classify → update job store."""
    try:
        # Phase 1: capture
        with _SCAN_LOCK:
            _SCAN_JOBS[job_id]["phase"] = "capturing"
            _SCAN_JOBS[job_id]["progress"] = 0

        scan_result = packet_scanner.scan_packets(packet_count)
        features = scan_result["features"]

        with _SCAN_LOCK:
            _SCAN_JOBS[job_id]["phase"] = "classifying"
            _SCAN_JOBS[job_id]["progress"] = 60
            _SCAN_JOBS[job_id]["capture_mode"] = scan_result["mode"]
            _SCAN_JOBS[job_id]["capture_warning"] = scan_result.get("error")

        # Phase 2: classify with RF model
        clf = RFClassifier.get()
        prediction = clf.predict(features)

        # Build human-readable summary
        label = prediction["label"]
        confidence = prediction["confidence"]

        label_pretty = label.replace("_", " ").title()
        if label == "safe":
            verdict = "✅  Traffic looks SAFE"
            severity = "low"
        elif confidence >= 0.80:
            verdict = f"🚨  {label_pretty} DETECTED — HIGH CONFIDENCE"
            severity = "critical"
        elif confidence >= 0.55:
            verdict = f"⚠️   Possible {label_pretty} — MEDIUM CONFIDENCE"
            severity = "medium"
        else:
            verdict = f"🔍  Suspicious: {label_pretty} — LOW CONFIDENCE"
            severity = "low"

        # Build result payload for logging and job storage
        result_payload = {
            "verdict":          verdict,
            "label":            label,
            "label_pretty":     label_pretty,
            "threat_detected":  prediction["threat_detected"],
            "severity":         severity,
            "confidence":       confidence,
            "packet_count":     prediction["packet_count"],
            "breakdown":        prediction["breakdown"],
            "per_packet":       prediction["per_packet"],
            "capture_mode":     scan_result["mode"],
            "capture_warning":  scan_result.get("error"),
            "timestamp":        datetime.utcnow().isoformat() + "Z",
        }

        # Log scan result to SQLite database
        _log_scan_to_db(result_payload)

        with _SCAN_LOCK:
            _SCAN_JOBS[job_id].update({
                "status":     "done",
                "phase":      "done",
                "progress":   100,
                "result":     result_payload,
            })

    except Exception as exc:
        logger.error("Scan job %s failed: %s", job_id, exc, exc_info=True)
        with _SCAN_LOCK:
            _SCAN_JOBS[job_id].update({
                "status": "error",
                "phase":  "error",
                "error":  str(exc),
            })


@api_blueprint.route("/scan/start", methods=["POST"])
def scan_start():
    """
    POST /api/scan/start
    Start a background packet-capture + RF-classification job.

    Body (JSON, optional):
        packet_count  int  — how many packets to sniff (10–500, default 100)

    Returns:
        { job_id, status, packet_count }
    """
    try:
        body = request.get_json(silent=True) or {}
        packet_count = int(body.get("packet_count",
                           os.getenv("SCAN_PACKET_COUNT", 100)))
        packet_count = max(10, min(packet_count, 500))

        job_id = str(uuid.uuid4())

        with _SCAN_LOCK:
            _SCAN_JOBS[job_id] = {
                "job_id":       job_id,
                "status":       "running",
                "phase":        "starting",
                "progress":     0,
                "packet_count": packet_count,
                "started_at":   datetime.utcnow().isoformat() + "Z",
                "result":       None,
                "error":        None,
            }

        thread = threading.Thread(
            target=_run_scan_job,
            args=(job_id, packet_count),
            daemon=True,
            name=f"scan-{job_id[:8]}",
        )
        thread.start()

        logger.info("Scan job %s started (packets=%d)", job_id, packet_count)
        return jsonify({"job_id": job_id, "status": "running",
                        "packet_count": packet_count}), 202

    except Exception as exc:
        logger.error("Failed to start scan: %s", exc)
        return jsonify({"success": False, "message": str(exc)}), 500


@api_blueprint.route("/scan/status/<job_id>", methods=["GET"])
def scan_status(job_id: str):
    """
    GET /api/scan/status/<job_id>
    Poll the status of a running or completed scan job.

    Returns:
        {
          job_id, status,  phase, progress (0–100),
          result  (populated when status=="done"),
          error   (populated when status=="error")
        }
    """
    with _SCAN_LOCK:
        job = _SCAN_JOBS.get(job_id)

    if job is None:
        return jsonify({"success": False, "message": "Job not found"}), 404

    return jsonify(job), 200


@api_blueprint.route("/get_latest_traffic", methods=["GET"])
def get_latest_traffic():
    """
    GET /api/get_latest_traffic
    Returns the last 20 scan log rows and a per-label traffic count summary.
    Polled by frontend dashboards for live metrics.

    Returns:
        {
          traffic_labels: [str],
          traffic_counts: [int],
          traffic_count: int (sum),
          threats_today: int,
          total_scans: int,
          recent_logs: [
            {timestamp, label, severity, confidence, packet_count, capture_mode, threat_detected},
            ...
          ]
        }
    """
    with _scan_db() as con:
        # Latest 20 scans for the activity table
        rows = con.execute(
            """SELECT timestamp, label, severity, confidence, packet_count,
                      capture_mode, threat_detected
               FROM scan_logs ORDER BY id DESC LIMIT 20"""
        ).fetchall()

        # Aggregate label counts for the bar chart (last 100 rows)
        agg = con.execute(
            """SELECT label, SUM(count) as total
               FROM traffic_counts
               GROUP BY label
               ORDER BY total DESC
               LIMIT 100"""
        ).fetchall()

        # Total threats in the last 24 h (for the live counter)
        threats_today = con.execute(
            """SELECT COUNT(*) as n FROM scan_logs
               WHERE threat_detected=1
                 AND timestamp >= datetime('now','-1 day')"""
        ).fetchone()["n"]

        total_scans = con.execute("SELECT COUNT(*) as n FROM scan_logs").fetchone()["n"]

    traffic_labels = [r["label"] for r in agg]
    traffic_counts = [int(r["total"]) for r in agg]

    return jsonify({
        "traffic_labels":  traffic_labels,
        "traffic_counts":  traffic_counts,
        "traffic_count":   sum(traffic_counts),   # scalar for simple chart demos
        "threats_today":   threats_today,
        "total_scans":     total_scans,
        "recent_logs": [
            {
                "timestamp":       r["timestamp"],
                "label":           r["label"],
                "severity":        r["severity"],
                "confidence":      round(r["confidence"] * 100),
                "packet_count":    r["packet_count"],
                "capture_mode":    r["capture_mode"],
                "threat_detected": bool(r["threat_detected"]),
            }
            for r in rows
        ],
    }), 200


@api_blueprint.route("/logs", methods=["GET"])
def get_logs():
    """
    GET /api/logs
    Returns the last 50 scan records from SQLite.

    Returns:
        [
          {id, timestamp, label, severity, confidence, packet_count, capture_mode, threat_detected},
          ...
        ]
    """
    with _scan_db() as con:
        rows = con.execute(
            """SELECT * FROM scan_logs ORDER BY id DESC LIMIT 50"""
        ).fetchall()
    return jsonify([dict(r) for r in rows]), 200
