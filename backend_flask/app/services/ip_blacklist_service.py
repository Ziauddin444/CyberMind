"""
IP Blacklist Service
One-click IP blacklisting orchestrated through FirewallManager.
"""

import logging
from typing import Dict
from datetime import datetime

logger = logging.getLogger(__name__)


class IPBlacklistService:
    """
    One-click blacklisting service that delegates all enforcement to the
    OS-native firewall through FirewallManager.
    """

    def __init__(self, firewall_manager):
        self.firewall_manager = firewall_manager
        logger.info("IPBlacklistService initialized")

    def blacklist_ip(self, ip_address: str, reason: str = "Threat intel match") -> Dict:
        """
        Block a single IP immediately via FirewallManager.
        """
        logger.warning(f"One-click blacklist requested for IP: {ip_address}")

        result = self.firewall_manager.block_ip(ip_address, reason)
        result["action"] = "ip_blacklist"
        result["timestamp"] = datetime.now().isoformat()
        return result

    def get_status(self) -> Dict:
        """
        Return high-level blacklisting service status.
        """
        blocked_ips = self.firewall_manager.get_blocked_ips()
        return {
            "status": "online",
            "blocked_ips_count": len(blocked_ips),
            "timestamp": datetime.now().isoformat()
        }
