"""
AI Translator Service — Ollama Mistral Integration
Converts technical network alerts into plain English for non-technical users.

Features:
- Local Ollama Mistral integration (no external API keys)
- Graceful fallback to rule-based analysis if Ollama offline
- Non-blocking async-friendly threading
- Cross-platform (Mac, Windows, Linux)
"""

import json
import logging
import platform
import requests
import threading
import time
from datetime import datetime
from typing import Dict, Optional

logger = logging.getLogger(__name__)

# Ollama service configuration
OLLAMA_API_BASE = "http://localhost:11434/api"
OLLAMA_GENERATE_ENDPOINT = f"{OLLAMA_API_BASE}/generate"
OLLAMA_TAGS_ENDPOINT = f"{OLLAMA_API_BASE}/tags"
OLLAMA_MODEL = "mistral"
OLLAMA_REQUEST_TIMEOUT = 30  # seconds


class AITranslator:
    """
    AI Traffic Translator: Uses local Ollama Mistral to convert
    technical network alerts into plain English for SMB owners.
    Falls back to rule-based analysis if Ollama is unavailable.
    """

    def __init__(self):
        """Initialize AI Translator with Ollama availability check."""
        self.ollama_available = False
        self.ollama_last_checked = 0
        self.ollama_check_interval = 60  # Re-check availability every 60 seconds
        self._check_ollama_availability()
        logger.info(
            f"AITranslator initialized — Ollama status: "
            f"{'available' if self.ollama_available else 'unavailable'}"
        )

    def _check_ollama_availability(self) -> bool:
        """
        Check if Ollama is running and responsive.
        Cached for 60 seconds to avoid excessive polling.

        Returns:
            bool: True if Ollama is available, False otherwise
        """
        now = time.time()
        # Skip check if recently checked
        if now - self.ollama_last_checked < self.ollama_check_interval:
            return self.ollama_available

        self.ollama_last_checked = now

        try:
            response = requests.get(
                OLLAMA_TAGS_ENDPOINT,
                timeout=5,
            )
            if response.status_code == 200:
                data = response.json()
                models = data.get("models", [])
                # Check if Mistral model is available
                self.ollama_available = any(
                    m.get("name", "").startswith("mistral") for m in models
                )
                if self.ollama_available:
                    logger.info("✓ Ollama Mistral model detected and available")
                else:
                    logger.warning(
                        "Ollama running but Mistral model not found. "
                        "Run: ollama pull mistral"
                    )
                return self.ollama_available
        except requests.exceptions.ConnectionError:
            self.ollama_available = False
            logger.debug("Ollama not running at http://localhost:11434")
            return False
        except requests.exceptions.Timeout:
            self.ollama_available = False
            logger.debug("Ollama timeout (not responding)")
            return False
        except Exception as e:
            self.ollama_available = False
            logger.debug(f"Ollama check failed: {e}")
            return False

    def _strip_markdown_fences(self, text: str) -> str:
        """
        Remove markdown code fences (```json ... ```) from response.

        Args:
            text: Text potentially containing markdown fences

        Returns:
            Text with fences removed
        """
        text = text.strip()
        # Remove leading ```json or ```
        if text.startswith("```"):
            text = text[text.find("\n") + 1 :] if "\n" in text else text[3:]
        # Remove trailing ```
        if text.endswith("```"):
            text = text[: text.rfind("```")]
        return text.strip()

    def _call_ollama(self, prompt: str) -> Optional[str]:
        """
        Call Ollama Mistral API with the given prompt.
        Non-blocking via threading wrapper.

        Args:
            prompt: The prompt to send to Mistral

        Returns:
            The model's response text, or None if failed
        """
        response_holder = {"response": None, "error": None}

        def _request():
            try:
                payload = {
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,  # Get full response at once
                }
                response = requests.post(
                    OLLAMA_GENERATE_ENDPOINT,
                    json=payload,
                    timeout=OLLAMA_REQUEST_TIMEOUT,
                )
                if response.status_code == 200:
                    data = response.json()
                    response_holder["response"] = data.get("response", "")
                else:
                    response_holder["error"] = f"HTTP {response.status_code}"
            except requests.exceptions.Timeout:
                response_holder["error"] = "Ollama request timeout"
            except requests.exceptions.ConnectionError:
                response_holder["error"] = "Ollama connection failed"
            except Exception as e:
                response_holder["error"] = str(e)

        # Run request in background thread
        thread = threading.Thread(target=_request, daemon=True)
        thread.start()
        thread.join(timeout=OLLAMA_REQUEST_TIMEOUT + 5)

        if response_holder["error"]:
            logger.warning(f"Ollama request error: {response_holder['error']}")
            return None

        return response_holder["response"]

    def analyze_threat(self, threat_data: Dict) -> Dict:
        """
        Analyze a security threat using Ollama Mistral, converting
        technical alert into plain English for business owners.

        Args:
            threat_data: Dict containing:
                - threat_type: str (e.g., "port_scan")
                - severity: str (e.g., "high")
                - confidence: float (0.0-1.0)
                - source_ip: str
                - matched_signature: str (detection method)
                - mitigation: str (technical fix)

        Returns:
            Dict with keys:
                - plain_english_summary: str (max 30 words, no jargon)
                - what_is_happening: str (2-3 sentences in business terms)
                - what_to_do: str (one clear action)
                - risk_level: str (Low/Medium/High/Critical)
                - estimated_impact: str (business impact)
                - source: str ("ollama" or "rule_based")
                - timestamp: str (ISO 8601)
        """
        logger.info(f"Analyzing threat: {threat_data.get('threat_type', 'unknown')}")

        # Check Ollama availability
        if not self._check_ollama_availability():
            logger.debug("Ollama unavailable, using rule-based fallback")
            return self._rule_based_fallback(threat_data)

        # Build prompt for Mistral
        prompt = f"""You are a cybersecurity assistant helping a small business owner understand a network security alert. Translate this technical alert into plain English.

Technical Alert:
- Attack Type: {threat_data.get('threat_type', 'unknown')}
- Severity: {threat_data.get('severity', 'unknown')}
- Confidence: {threat_data.get('confidence', 0) * 100:.0f}%
- Source IP: {threat_data.get('source_ip', 'unknown')}
- Detection Method: {threat_data.get('matched_signature', 'unknown')}
- Technical Mitigation: {threat_data.get('mitigation', 'Apply security patches')}

Respond ONLY with a valid JSON object in this exact format, no other text:
{{
  "plain_english_summary": "one sentence, max 30 words, no technical jargon",
  "what_is_happening": "2-3 sentences explaining the attack in business terms",
  "what_to_do": "one clear action the business owner should take right now",
  "risk_level": "Low / Medium / High / Critical",
  "estimated_impact": "one sentence on business impact"
}}"""

        # Call Ollama
        response_text = self._call_ollama(prompt)

        if not response_text:
            logger.warning("Ollama request failed; falling back to rule-based analysis")
            return self._rule_based_fallback(threat_data)

        # Parse response
        try:
            # Strip markdown fences if present
            clean_response = self._strip_markdown_fences(response_text)

            # Parse JSON
            result = json.loads(clean_response)

            # Validate required fields
            required_fields = [
                "plain_english_summary",
                "what_is_happening",
                "what_to_do",
                "risk_level",
                "estimated_impact",
            ]
            if not all(field in result for field in required_fields):
                raise ValueError("Missing required fields in Ollama response")

            # Add metadata
            result["source"] = "ollama"
            result["timestamp"] = datetime.utcnow().isoformat() + "Z"

            logger.info("✓ Ollama analysis completed successfully")
            return result

        except json.JSONDecodeError as e:
            logger.warning(f"Failed to parse Ollama response as JSON: {e}")
            logger.debug(f"Raw response: {response_text[:200]}")
            return self._rule_based_fallback(threat_data)
        except Exception as e:
            logger.warning(f"Ollama analysis failed: {e}")
            return self._rule_based_fallback(threat_data)

    def _rule_based_fallback(self, threat_data: Dict) -> Dict:
        """
        Rule-based fallback analysis using hardcoded threat patterns.
        Used when Ollama is unavailable.

        Args:
            threat_data: Dict containing threat information

        Returns:
            Dict with plain English analysis
        """
        threat_type = threat_data.get("threat_type", "unknown").lower()
        severity = threat_data.get("severity", "medium").lower()
        source_ip = threat_data.get("source_ip", "unknown")

        # Define rule-based responses for common threats
        threat_rules = {
            "port_scan": {
                "plain_english_summary": f"Someone scanned your network from {source_ip}.",
                "what_is_happening": "An attacker ran a port scanning tool to find open services on your network. This is reconnaissance—they're looking for vulnerable systems to exploit.",
                "what_to_do": "We've automatically blocked this IP address. Monitor your network logs for similar activity.",
                "risk_level": "Medium",
                "estimated_impact": "No data stolen; attacker was gathering information.",
            },
            "brute_force": {
                "plain_english_summary": f"Password attack detected from {source_ip}.",
                "what_is_happening": "An attacker attempted to log in using guessed passwords (brute-force attack). They're trying to gain access to your systems.",
                "what_to_do": "Change passwords immediately. Enable multi-factor authentication (MFA) on all accounts.",
                "risk_level": "High",
                "estimated_impact": "If successful, attacker could access your data and systems.",
            },
            "sql_injection": {
                "plain_english_summary": "A database attack was blocked.",
                "what_is_happening": "An attacker tried to manipulate your database using specially crafted commands. This could expose customer data or corrupt your business records.",
                "what_to_do": "Contact your IT provider immediately. Update your website software to the latest version.",
                "risk_level": "Critical",
                "estimated_impact": "Potential breach of customer data; system downtime.",
            },
            "ddos": {
                "plain_english_summary": f"Your network is being flooded from {source_ip}.",
                "what_is_happening": "A DDoS attack is overwhelming your network with fake traffic. This blocks legitimate customers from accessing your services.",
                "what_to_do": "We've activated network isolation. Contact your ISP to report the attack.",
                "risk_level": "High",
                "estimated_impact": "Your website/services may be unavailable to customers.",
            },
            "malware_c2": {
                "plain_english_summary": "A command-and-control connection was detected.",
                "what_is_happening": "Malware on your network is trying to communicate with a hacker's server. Your computer may be compromised.",
                "what_to_do": "Isolate the affected computer immediately. Run antivirus scans. Contact IT security.",
                "risk_level": "Critical",
                "estimated_impact": "Your data is at risk; ongoing unauthorized access possible.",
            },
        }

        # Get rules for this threat type, or use default
        if threat_type in threat_rules:
            rules = threat_rules[threat_type]
        else:
            # Generic fallback
            rules = {
                "plain_english_summary": "A security threat was detected on your network.",
                "what_is_happening": "Our security system detected suspicious network activity. This could be an attack attempt or misconfigured software.",
                "what_to_do": "Review the threat details below. If concerned, contact your IT provider.",
                "risk_level": severity.capitalize(),
                "estimated_impact": "Unknown; recommend immediate investigation.",
            }

        # Build result
        result = {
            **rules,
            "source": "rule_based",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

        logger.info(f"Using rule-based analysis for {threat_type}")
        return result

    def check_ollama_status(self) -> Dict:
        """
        Check if Ollama is running and report available models.

        Returns:
            Dict with keys:
                - available: bool
                - models: list of model names
                - message: str (human-readable status)
                - timestamp: str (ISO 8601)
        """
        try:
            response = requests.get(OLLAMA_TAGS_ENDPOINT, timeout=5)
            if response.status_code == 200:
                data = response.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                return {
                    "available": True,
                    "models": models,
                    "message": f"Ollama running with {len(models)} model(s)",
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                }
        except Exception as e:
            logger.debug(f"Ollama status check failed: {e}")

        return {
            "available": False,
            "models": [],
            "message": "Ollama not running. Rule-based analysis will be used.",
            "timestamp": datetime.utcnow().isoformat() + "Z",
        }

    def get_status(self) -> dict:
        """
        Returns current status of the AI translator service.
        Called by Flask __init__.py on /api/status endpoint.
        """
        ollama_status = self.check_ollama_status()
        return {
            "service": "ai_translator",
            "status": "operational",
            "mode": "ollama_mistral" if ollama_status["available"] else "rule_based_fallback",
            "ollama_available": ollama_status["available"],
            "ollama_models": ollama_status.get("models", []),
            "message": (
                "Ollama Mistral active — free local LLM translation"
                if ollama_status["available"]
                else "Ollama offline — using rule-based fallback"
            )
        }

    def get_ollama_install_instructions(self) -> str:
        """
        Get platform-specific Ollama installation instructions.

        Returns:
            str with installation steps for current platform
        """
        system = platform.system()

        instructions = {
            "Darwin": """
macOS Installation:
1. Install Ollama via Homebrew:
   brew install ollama

2. Download the Mistral model:
   ollama pull mistral

3. Start Ollama service:
   ollama serve

4. Verify installation:
   curl http://localhost:11434/api/tags

Once Ollama is running, CyberMind will automatically use Mistral 
for threat analysis. If Ollama stops, analysis will fall back to 
rule-based detection.
""",
            "Windows": """
Windows Installation:
1. Download Ollama from https://ollama.ai/download

2. Run the installer and follow the prompts

3. Open PowerShell or Command Prompt and download Mistral:
   ollama pull mistral

4. Ollama will start automatically; verify it's running:
   curl http://localhost:11434/api/tags

5. If you get a "command not found" error, add Ollama to your PATH:
   - Right-click 'This PC' → Properties
   - Click 'Environment Variables'
   - Add C:\\Users\\<YourUsername>\\AppData\\Local\\Programs\\Ollama to PATH

Once running, CyberMind will use Mistral for threat analysis.
""",
            "Linux": """
Linux Installation:
1. Download and install Ollama:
   curl -fsSL https://ollama.ai/install.sh | sh

2. Download the Mistral model:
   ollama pull mistral

3. Start Ollama service:
   ollama serve

   Or run as systemd service:
   sudo systemctl restart ollama

4. Verify installation:
   curl http://localhost:11434/api/tags

Once running, CyberMind will use Mistral for threat analysis. 
If Ollama stops, analysis falls back to rule-based detection.
""",
        }

        return instructions.get(
            system,
            f"""
{system} Installation:
Visit https://ollama.ai/download for {system}-specific instructions.

General steps:
1. Install Ollama
2. Run: ollama pull mistral
3. Start the Ollama service
4. Verify at: http://localhost:11434/api/tags
""",
        )


# Global instance for use by Flask routes
_translator_instance = None


def get_ai_translator() -> AITranslator:
    """
    Get or create the global AITranslator instance.
    Used by Flask routes to avoid re-initialization.

    Returns:
        AITranslator instance
    """
    global _translator_instance
    if _translator_instance is None:
        _translator_instance = AITranslator()
    return _translator_instance




