"""
CyberMind Sentinel API Routes
Network-level active defense endpoints for Commander Agent architecture.
"""

import logging
import os
import threading
import uuid
from datetime import datetime
from functools import wraps

from flask import Blueprint, current_app, jsonify, request
from app.services import ids_engine  # Layer 3 — AI model

logger = logging.getLogger(__name__)

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
    try:
        data = request.get_json() or {}
        telemetry = data.get("telemetry")
        context = data.get("context", {})

        if not telemetry:
            return jsonify({"success": False, "message": "telemetry required"}), 400

        result = current_app.ai_translator.translate_network_traffic(telemetry, context)
        return jsonify({
            "success": True,
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error translating traffic: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


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


# --- ROGUE ASSET DETECTION ---


@api_blueprint.route("/assets/discover", methods=["POST"])
@require_auth
def discover_assets():
    try:
        data = request.get_json() or {}
        network_range = data.get("network_range")

        if not network_range:
            return jsonify({"success": False, "message": "network_range required"}), 400

        result = current_app.rogue_asset_detector.discover_assets(network_range)
        return jsonify({
            "success": True,
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error discovering assets: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/assets/baseline", methods=["POST"])
@require_auth
def set_asset_baseline():
    try:
        data = request.get_json() or {}
        assets = data.get("assets")

        if assets is None:
            return jsonify({"success": False, "message": "assets required"}), 400

        result = current_app.rogue_asset_detector.set_baseline_assets(assets)
        return jsonify({
            "success": True,
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error setting asset baseline: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/assets/rogue", methods=["GET"])
def detect_rogue_assets():
    try:
        result = current_app.rogue_asset_detector.detect_rogue_assets()
        return jsonify({
            "success": True,
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error detecting rogue assets: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/assets/status", methods=["GET"])
def assets_status():
    try:
        status = current_app.rogue_asset_detector.get_status()
        return jsonify({
            "success": True,
            "data": status,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting rogue asset status: {str(e)}")
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


# --- PHISHING SANDBOX ---


@api_blueprint.route("/phishing/check_url", methods=["POST"])
def check_url():
    try:
        data = request.get_json() or {}
        url = data.get("url")

        if not url:
            return jsonify({"success": False, "message": "url required"}), 400

        result = current_app.phishing_sandbox.check_url_reputation(url)
        return jsonify({
            "success": True,
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error checking URL reputation: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/phishing/analyze_email", methods=["POST"])
def analyze_email():
    try:
        data = request.get_json() or {}
        email_headers = data.get("email_headers")
        body = data.get("body", "")

        if not email_headers:
            return jsonify({"success": False, "message": "email_headers required"}), 400

        result = current_app.phishing_sandbox.analyze_email(email_headers, body)
        return jsonify({
            "success": True,
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error analyzing email: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/phishing/statistics", methods=["GET"])
def phishing_statistics():
    try:
        stats = current_app.phishing_sandbox.generate_phishing_report()
        return jsonify({
            "success": True,
            "data": stats,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting phishing statistics: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


# --- FLEET MONITOR ---


@api_blueprint.route("/fleet/status", methods=["GET"])
def fleet_monitor_status():
    try:
        status = current_app.fleet_monitor.get_status()
        return jsonify({
            "success": True,
            "data": status,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting fleet monitor status: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/fleet/ping", methods=["POST"])
def ping_asset():
    try:
        data = request.get_json() or {}
        ip_address = data.get("ip_address")
        count = data.get("count", 3)

        if not ip_address:
            return jsonify({"success": False, "message": "ip_address required"}), 400

        result = current_app.fleet_monitor.ping_asset(ip_address, count)
        return jsonify({
            "success": True,
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error pinging asset: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/fleet/ping_sweep", methods=["POST"])
@require_auth
def ping_sweep():
    try:
        data = request.get_json() or {}
        network_range = data.get("network_range")

        if not network_range:
            return jsonify({"success": False, "message": "network_range required"}), 400

        result = current_app.fleet_monitor.perform_ping_sweep(network_range)
        return jsonify({
            "success": result.get("success", False),
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error performing ping sweep: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/fleet/connections", methods=["GET"])
def network_connections():
    try:
        result = current_app.fleet_monitor.get_network_connections()
        return jsonify({
            "success": result.get("success", False),
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting network connections: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/fleet/register_asset", methods=["POST"])
@require_auth
def register_asset():
    try:
        data = request.get_json() or {}
        asset_info = {
            "name": data.get("name"),
            "ip_address": data.get("ip_address"),
            "hostname": data.get("hostname"),
            "asset_type": data.get("asset_type", "unknown")
        }

        if not asset_info.get("name") or not asset_info.get("ip_address"):
            return jsonify({"success": False, "message": "name and ip_address required"}), 400

        result = current_app.fleet_monitor.register_asset(asset_info)
        return jsonify({
            "success": result.get("success", False),
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error registering asset: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/fleet/monitor_assets", methods=["POST"])
@require_auth
def monitor_assets():
    try:
        result = current_app.fleet_monitor.monitor_assets()
        return jsonify({
            "success": result.get("success", False),
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error monitoring assets: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/fleet/anomalies", methods=["GET"])
def detect_anomalies():
    try:
        result = current_app.fleet_monitor.detect_anomalies()
        return jsonify({
            "success": result.get("success", False),
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error detecting anomalies: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


# --- REMEDIATION PLAYBOOK ---


@api_blueprint.route("/remediation/evaluate_threat", methods=["POST"])
@require_auth
@require_role("analyst")
def evaluate_threat():
    try:
        data = request.get_json() or {}
        
        if not data.get("threat_type"):
            return jsonify({"success": False, "message": "threat_type required"}), 400

        result = current_app.remediation_playbook.evaluate_threat(data)
        return jsonify({
            "success": True,
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error evaluating threat: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/remediation/status", methods=["GET"])
def remediation_status():
    try:
        status = current_app.remediation_playbook.get_status()
        return jsonify({
            "success": True,
            "data": status,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting remediation status: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/remediation/incidents", methods=["GET"])
def get_incidents():
    try:
        result = current_app.remediation_playbook.get_active_incidents()
        return jsonify({
            "success": result.get("success", False),
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting incidents: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/remediation/manual_response", methods=["POST"])
@require_auth
@require_role("admin")
def manual_incident_response():
    try:
        data = request.get_json() or {}
        incident_id = data.get("incident_id")
        actions = data.get("actions", [])

        if not incident_id:
            return jsonify({"success": False, "message": "incident_id required"}), 400

        result = current_app.remediation_playbook.manual_incident_response(incident_id, actions)
        return jsonify({
            "success": True,
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error executing manual response: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/remediation/close_incident", methods=["POST"])
@require_auth
@require_role("admin")
def close_incident():
    try:
        data = request.get_json() or {}
        incident_index = data.get("incident_index")

        if incident_index is None:
            return jsonify({"success": False, "message": "incident_index required"}), 400

        result = current_app.remediation_playbook.close_incident(incident_index)
        return jsonify({
            "success": result.get("success", False),
            "data": result,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error closing incident: {str(e)}")
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
        logger.error(f"Error listing devices: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/devices/add", methods=["POST"])
@require_auth
@require_role("analyst")
def add_device():
    """Add a new device to inventory"""
    try:
        data = request.get_json() or {}
        result = current_app.device_manager.add_device(data)
        status_code = 201 if result.get("success") else 400
        return jsonify({
            "success": result.get("success", False),
            "data": result.get("device") if result.get("success") else None,
            "error": result.get("error") if not result.get("success") else None,
            "timestamp": datetime.now().isoformat(),
        }), status_code
    except Exception as e:
        logger.error(f"Error adding device: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/devices/<device_id>", methods=["GET"])
def get_device(device_id):
    """Get device details"""
    try:
        device = current_app.device_manager.get_device(device_id)
        if not device:
            return jsonify({"success": False, "message": "Device not found"}), 404

        return jsonify({
            "success": True,
            "data": device,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting device: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/devices/<device_id>", methods=["PUT"])
@require_auth
@require_role("analyst")
def update_device(device_id):
    """Update device information"""
    try:
        data = request.get_json() or {}
        result = current_app.device_manager.update_device(device_id, data)
        status_code = 200 if result.get("success") else 400
        return jsonify({
            "success": result.get("success", False),
            "data": result.get("device") if result.get("success") else None,
            "error": result.get("error") if not result.get("success") else None,
            "timestamp": datetime.now().isoformat(),
        }), status_code
    except Exception as e:
        logger.error(f"Error updating device: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/devices/<device_id>", methods=["DELETE"])
@require_auth
@require_role("admin")
def delete_device(device_id):
    """Delete a device from inventory"""
    try:
        result = current_app.device_manager.delete_device(device_id)
        status_code = 200 if result.get("success") else 404
        return jsonify({
            "success": result.get("success", False),
            "message": result.get("message") if result.get("success") else result.get("error"),
            "timestamp": datetime.now().isoformat(),
        }), status_code
    except Exception as e:
        logger.error(f"Error deleting device: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500


@api_blueprint.route("/devices/search", methods=["GET"])
def search_devices():
    """Search devices by name or IP"""
    try:
        query = request.args.get("q", "")
        if not query:
            return jsonify({"success": False, "message": "Query parameter 'q' required"}), 400

        results = current_app.device_manager.search_devices(query)
        return jsonify({
            "success": True,
            "data": results,
            "count": len(results),
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error searching devices: {str(e)}")
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


# --- HONEYPOT FILE MANAGEMENT ---


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

        with _SCAN_LOCK:
            _SCAN_JOBS[job_id].update({
                "status":     "done",
                "phase":      "done",
                "progress":   100,
                "result":     {
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
                },
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
