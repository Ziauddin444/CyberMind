"""
IP Blacklist Service
One-click IP blacklisting orchestrated through FirewallManager.
"""

import logging
import json
import os
import threading
from typing import Dict
from datetime import datetime

logger = logging.getLogger(__name__)

# Thread-safe lock for file I/O
_records_lock = threading.Lock()


class IPBlacklistService:
    """
    One-click blacklisting service that delegates all enforcement to the
    OS-native firewall through FirewallManager.
    """

    def __init__(self, firewall_manager):
        self.firewall_manager = firewall_manager
        self.block_records = []
        self.records_file = os.path.join(
            os.path.dirname(__file__), 
            '../../data/blocked_ips.json'
        )
        self._load_records_from_disk()
        logger.info("IPBlacklistService initialized")

    def _load_records_from_disk(self):
        """Load persisted block records from disk."""
        with _records_lock:
            if os.path.exists(self.records_file):
                try:
                    with open(self.records_file, 'r') as f:
                        self.block_records = json.load(f)
                    logger.info(f"Loaded {len(self.block_records)} records from {self.records_file}")
                except Exception as e:
                    logger.error(f"Failed to load block records: {e}")
                    self.block_records = []

    def _save_records_to_disk(self):
        """Persist block records to disk (thread-safe)."""
        with _records_lock:
            try:
                os.makedirs(os.path.dirname(self.records_file), exist_ok=True)
                with open(self.records_file, 'w') as f:
                    json.dump(self.block_records, f, indent=2)
                logger.debug(f"Persisted {len(self.block_records)} block records to disk")
            except Exception as e:
                logger.error(f"Failed to save block records to disk: {e}")

    def blacklist_ip(self, ip_address: str, reason: str = "Threat intel match") -> Dict:
        """
        Block a single IP immediately via FirewallManager.
        Persists the block record to disk in a thread-safe manner.
        """
        logger.warning(f"One-click blacklist requested for IP: {ip_address}")

        result = self.firewall_manager.block_ip(ip_address, reason)
        blocked_at = datetime.now().isoformat()

        with _records_lock:
            # Generate sequential record_id
            max_id = max([r.get("record_id", 0) for r in self.block_records], default=0)
            record_id = max_id + 1
            
            record = {
                "record_id": record_id,
                "ip_address": ip_address,
                "reason": reason,
                "status": "blocked" if result.get("success") else "failed",
                "blocked_at": blocked_at,
                "message": result.get("message", ""),
                "os": result.get("os"),
                "threat_type": result.get("threat_type", "unknown"),
                "timestamp": blocked_at,
            }
            self.block_records.insert(0, record)
            # Keep only recent records to bound memory usage.
            self.block_records = self.block_records[:300]

        # Persist to disk (outside lock to avoid deadlock)
        self._save_records_to_disk()

        result["action"] = "ip_blacklist"
        result["timestamp"] = blocked_at
        result["record"] = record
        return result

    def get_status(self) -> Dict:
        """
        Return high-level blacklisting service status with persisted records.
        """
        blocked_ips = self.firewall_manager.get_blocked_ips()
        
        with _records_lock:
            records_to_return = self.block_records[:100]
        
        return {
            "status": "online",
            "blocked_ips_count": len(blocked_ips),
            "blocked_ips": blocked_ips,
            "blocked_records": records_to_return,
            "timestamp": datetime.now().isoformat()
        }

    def unblock_ip(self, ip_address: str) -> dict:
        """Remove an IP from the blocklist and persist to disk."""
        try:
            record_to_remove = None
            # Find the record in the actual list (self.block_records)
            for record in self.block_records:
                if record.get("ip_address") == ip_address:
                    record_to_remove = record
                    break
            
            if record_to_remove:
                self.block_records.remove(record_to_remove)
                self._save_records_to_disk() # Use the existing thread-safe save method
                return {"success": True, "message": f"IP {ip_address} removed from blocklist"}
            
            # Fallback success for demo purposes if IP wasn't found
            return {"success": True, "message": f"IP {ip_address} was not in the blocklist"}
            
        except Exception as e:
            logger.error(f"Error in unblock_ip: {str(e)}")
            return {"success": False, "message": str(e)}