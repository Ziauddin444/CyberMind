"""
CyberMind Sentinel API Routes
Network-level active defense endpoints for Commander Agent architecture.
"""

import logging
from datetime import datetime
from functools import wraps

from flask import Blueprint, current_app, jsonify, request

logger = logging.getLogger(__name__)

api_blueprint = Blueprint("api", __name__)


def require_auth(f):
    """Decorator for endpoints requiring authentication (stub)."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return jsonify({"success": False, "message": "Missing authorization header"}), 401
        return f(*args, **kwargs)

    return decorated_function


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


@api_blueprint.route("/isolation/deactivate", methods=["POST"])
@require_auth
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
        status = current_app.network_honeypot.get_honeypot_stats()
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
            "data": logs,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting honeypot logs: {str(e)}")
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
        stats = current_app.phishing_sandbox.get_phishing_statistics()
        return jsonify({
            "success": True,
            "data": stats,
            "timestamp": datetime.now().isoformat(),
        }), 200
    except Exception as e:
        logger.error(f"Error getting phishing statistics: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500
