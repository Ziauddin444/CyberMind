"""
Kill Switch Service
Emergency network isolation - triggers immediate network lockdown.
"""

import logging
from typing import Dict
from datetime import datetime

logger = logging.getLogger(__name__)


class KillSwitch:
    """
    Kill Switch: Emergency network isolation mechanism.
    Can be triggered manually or automatically based on threat detection.
    """

    def __init__(self, firewall_manager):
        """Initialize Kill Switch."""
        self.firewall_manager = firewall_manager
        self.activated = False
        self.activation_timestamp = None
        self.activation_reason = None
        logger.info("KillSwitch initialized")

    def activate(self, reason: str = "Manual kill switch activation", auto: bool = False) -> Dict:
        """
        Activate emergency network isolation.
        
        Args:
            reason: Reason for activation
            auto: Whether activation is automatic or manual
            
        Returns:
            Dict with activation status
        """
        logger.warning(f"KILL SWITCH ACTIVATION INITIATED - Reason: {reason}")
        
        if self.activated:
            return {
                "success": False,
                "message": "Kill switch already active",
                "activated_at": self.activation_timestamp
            }
        
        try:
            result = self.firewall_manager.isolate_network(reason=reason)
            if not result.get("success"):
                return {
                    "success": False,
                    "message": result.get("message", "Failed to activate native firewall isolation"),
                    "reason": reason,
                    "details": result
                }

            self.activated = True
            self.activation_timestamp = datetime.now().isoformat()
            self.activation_reason = reason
            
            logger.warning(f"KILL SWITCH ACTIVATED: {reason}")
            
            return {
                "success": True,
                "message": "Network isolation initiated - ALL TRAFFIC BLOCKED",
                "activated_at": self.activation_timestamp,
                "reason": reason,
                "automatic": auto,
                "severity": "CRITICAL",
                "details": result
            }
        except Exception as e:
            logger.error(f"Kill switch activation failed: {str(e)}")
            return {
                "success": False,
                "message": f"Kill switch activation failed: {str(e)}",
                "reason": reason
            }

    def deactivate(self, authorization_code: str = None) -> Dict:
        """
        Deactivate kill switch and restore network.
        Requires authorization to prevent accidental network restoration.
        
        Args:
            authorization_code: Security code to verify deactivation
            
        Returns:
            Dict with deactivation status
        """
        logger.warning(f"KILL SWITCH DEACTIVATION REQUESTED")
        
        if not self.activated:
            return {
                "success": False,
                "message": "Kill switch is not active"
            }
        
        # STUB: Placeholder for authorization verification
        if authorization_code is None:
            return {
                "success": False,
                "message": "Authorization code required to deactivate kill switch"
            }
        
        try:
            result = self.firewall_manager.release_network_isolation()
            if not result.get("success"):
                return {
                    "success": False,
                    "message": result.get("message", "Failed to release native firewall isolation"),
                    "details": result
                }

            self.activated = False
            
            logger.warning(f"KILL SWITCH DEACTIVATED")
            
            return {
                "success": True,
                "message": "Network isolation released - connections restored",
                "deactivated_at": datetime.now().isoformat(),
                "was_active_for": f"{self.activation_timestamp} to now",
                "details": result
            }
        except Exception as e:
            logger.error(f"Kill switch deactivation failed: {str(e)}")
            return {
                "success": False,
                "message": f"Kill switch deactivation failed: {str(e)}"
            }

    def get_status(self) -> Dict:
        """Get kill switch status."""
        return {
            "activated": self.activated,
            "activation_time": self.activation_timestamp,
            "activation_reason": self.activation_reason,
            "timestamp": datetime.now().isoformat()
        }

    def emergency_network_lockdown(self, alert_level: str = "critical") -> Dict:
        """
        Get Kill Switch status via emergency alert pathway.
        
        Args:
            alert_level: Alert level (critical, high, medium, low)
            
        Returns:
            Dict with lockdown status
        """
        return {
            "alert_level": alert_level,
            "kill_switch_available": True,
            "current_state": "active" if self.activated else "ready",
            "response_time_ms": 100  # STUB value
        }
