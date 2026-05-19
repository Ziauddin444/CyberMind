"""
AI Translator Service
Integrates with LLM APIs (OpenAI, Anthropic, Hugging Face) for threat analysis and recommendations.
"""

import logging
from typing import Dict, List, Optional
from enum import Enum
from datetime import datetime

logger = logging.getLogger(__name__)


class LLMProvider(Enum):
    """Supported LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    HUGGINGFACE = "huggingface"
    LOCAL = "local"  # For local models


class AITranslator:
    """
    AI Traffic Translator: Converts raw network telemetry and alerts into
    human-readable insights for fast triage by SME defenders.
    """

    def __init__(self, provider: str = "openai", api_key: str = None):
        """
        Initialize AI Translator.
        
        Args:
            provider: LLM provider to use
            api_key: API key for the provider
        """
        self.provider = provider
        self.api_key = api_key
        self.conversation_history: List[Dict] = []
        logger.info(f"AITranslator initialized with provider: {provider}")

    def analyze_threat(self, threat_data: Dict) -> Dict:
        """
        Analyze network threat context using LLM.
        
        Args:
            threat_data: Dict containing threat indicators
            
        Returns:
            Dict with analysis results and recommendations
        """
        logger.info(f"Analyzing traffic threat: {threat_data.get('threat_type', 'unknown')}")

        raw_text = " ".join([
            str(threat_data.get("threat_type", "")),
            str(threat_data.get("tool", "")),
            str(threat_data.get("event", "")),
            str(threat_data.get("message", "")),
            str(threat_data.get("payload", "")),
            str(threat_data.get("command", "")),
        ]).lower()

        signatures = [
            ("nmap", "reconnaissance", "high", 0.92, "Kali scanning activity detected (nmap fingerprint)"),
            ("masscan", "reconnaissance", "critical", 0.95, "High-speed port scan detected (masscan fingerprint)"),
            ("nikto", "web_scan", "high", 0.90, "Web vulnerability scan detected (nikto fingerprint)"),
            ("sqlmap", "injection", "critical", 0.96, "Automated SQL injection attempt detected (sqlmap fingerprint)"),
            ("hydra", "credential_attack", "critical", 0.97, "Brute-force login attack detected (hydra fingerprint)"),
            ("metasploit", "exploitation", "critical", 0.96, "Exploit framework activity detected (metasploit fingerprint)"),
            ("msfconsole", "exploitation", "critical", 0.95, "Exploit console usage detected (msfconsole fingerprint)"),
            ("reverse shell", "post_exploitation", "critical", 0.98, "Reverse-shell behavior detected"),
            ("/etc/passwd", "enumeration", "high", 0.88, "Sensitive file enumeration attempt detected"),
            ("union select", "injection", "high", 0.86, "Potential SQL injection pattern detected"),
            ("wget http", "payload_delivery", "medium", 0.78, "Possible payload download behavior detected"),
            ("nc -e", "post_exploitation", "critical", 0.99, "Netcat remote shell behavior detected"),
        ]

        matches = []
        max_confidence = 0.35
        top_severity = threat_data.get("severity", "low").lower()
        top_type = threat_data.get("threat_type", "unknown")

        severity_rank = {"low": 1, "medium": 2, "high": 3, "critical": 4}

        for marker, attack_type, severity, confidence, reason in signatures:
            if marker in raw_text:
                matches.append({
                    "signature": marker,
                    "attack_type": attack_type,
                    "severity": severity,
                    "confidence": confidence,
                    "reason": reason,
                })
                max_confidence = max(max_confidence, confidence)
                if severity_rank.get(severity, 1) >= severity_rank.get(top_severity, 1):
                    top_severity = severity
                    top_type = attack_type

        suspicious_ports = threat_data.get("target_ports", []) or []
        common_attack_ports = {21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 5900, 8080}
        if any(int(p) in common_attack_ports for p in suspicious_ports if str(p).isdigit()):
            max_confidence = max(max_confidence, 0.72)
            if severity_rank.get(top_severity, 1) < severity_rank["medium"]:
                top_severity = "medium"
            if top_type == "unknown":
                top_type = "suspicious_port_targeting"

        recommendations = [
            "Block the source IP temporarily and monitor repeat attempts",
            "Run one-click remediation if repeated high-confidence indicators are present",
            "Capture full packet traces for forensic review",
            "Increase auth hardening (MFA, lockout policy, geo/IP restrictions)",
        ]

        if matches:
            recommendations.insert(0, f"Detected signatures: {', '.join(m['signature'] for m in matches[:4])}")

        return {
            "status": "analyzed",
            "threat_detected": bool(matches) or max_confidence >= 0.7,
            "threat_type": top_type,
            "threat_analysis": matches[0]["reason"] if matches else "No high-confidence exploit signature matched",
            "severity": top_severity,
            "recommendations": recommendations,
            "confidence": round(max_confidence, 2),
            "matches": matches,
            "model": "hybrid-signature-v1",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

    def translate_logs(self, raw_logs: List[str]) -> str:
        """
        Convert raw network security logs to human-readable format.
        
        Args:
            raw_logs: List of raw log entries
            
        Returns:
            Formatted summary string
        """
        logger.info(f"Translating {len(raw_logs)} network log entries")
        
        # STUB: Placeholder
        return "Network telemetry translation pending LLM integration"

    def translate_network_traffic(self, telemetry: List[str], context: Optional[Dict] = None) -> Dict:
        """
        Translate traffic telemetry into summarized analyst guidance.

        Args:
            telemetry: Raw traffic logs/events
            context: Optional context such as subnet, asset tags, or incident ID

        Returns:
            Dict with translation summary and action hints
        """
        context = context or {}
        logger.info(f"Translating traffic telemetry entries: {len(telemetry)}")

        summary = self.translate_logs(telemetry)

        return {
            "status": "ready",
            "summary": summary,
            "input_events": len(telemetry),
            "provider": self.provider,
            "recommendations": [
                "Review translated summary for immediate action items",
                "Cross-reference with threat intelligence feeds",
                "Escalate to SOC team if suspicious indicators detected"
            ],
            "context": context,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def get_conversation_history(self) -> List[Dict]:
        """
        Get conversation history with LLM.
        
        Returns:
            List of conversation messages
        """
        return self.conversation_history.copy()

    def clear_conversation_history(self) -> Dict:
        """Clear conversation history."""
        self.conversation_history = []
        return {"status": "success", "message": "Conversation history cleared"}

    def get_status(self) -> Dict:
        """Get AI Translator status."""
        return {
            "status": "online",
            "role": "ai_traffic_translation",
            "provider": self.provider,
            "api_configured": bool(self.api_key),
            "conversation_history_length": len(self.conversation_history),
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def generate_report(self, incident_data: Dict) -> str:
        """Generate a structured incident report summary."""
        return (
            f"Incident Report: {incident_data.get('id', 'unknown')}\n"
            f"Type: {incident_data.get('threat_type', 'unknown')}\n"
            f"Severity: {incident_data.get('severity', 'unknown')}\n"
            "Status: Review and containment recommended"
        )

    def ask_security_question(self, question: str) -> str:
        """Return quick responder guidance for a security question."""
        logger.info(f"Answering security question: {question}")
        return (
            "Start with containment, preserve evidence, then eradicate and recover. "
            "Use one-click remediation only after validating affected scope."
        )

    def set_api_key(self, provider: str, api_key: str) -> bool:
        """Update API key for provider."""
        try:
            self.provider = provider
            self.api_key = api_key
            logger.info(f"API key updated for provider: {provider}")
            return True
        except Exception as e:
            logger.error(f"Failed to set API key: {str(e)}")
            return False
