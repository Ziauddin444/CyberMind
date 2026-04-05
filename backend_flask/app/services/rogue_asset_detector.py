"""
Rogue Asset Detection Service
Performs lightweight network discovery and flags unknown assets for SMEs.
"""

import logging
from typing import Dict, List
from datetime import datetime

logger = logging.getLogger(__name__)


class RogueAssetDetector:
    """
    Rogue Asset Detector: Discovers networked hosts and identifies assets
    that are not part of the approved baseline inventory.
    """

    def __init__(self):
        self.baseline_assets: List[Dict] = []
        self.last_discovery: List[Dict] = []
        self.rogue_assets: List[Dict] = []
        logger.info("RogueAssetDetector initialized")

    def discover_assets(self, network_range: str) -> Dict:
        """
        Discover reachable assets on a given network range.
        """
        logger.info(f"Starting rogue asset discovery on network: {network_range}")

        discovered = []
        self.last_discovery = discovered

        return {
            "status": "pending",
            "network": network_range,
            "discovered_assets": discovered,
            "discovered_count": len(discovered),
            "timestamp": datetime.now().isoformat(),
            "note": "Discovery engine is a stub; plug in nmap/arp scan parser as needed"
        }

    def set_baseline_assets(self, assets: List[Dict]) -> Dict:
        """
        Set approved baseline inventory for rogue detection comparisons.
        """
        self.baseline_assets = assets
        logger.info(f"Updated baseline assets count: {len(assets)}")
        return {
            "success": True,
            "baseline_count": len(self.baseline_assets),
            "timestamp": datetime.now().isoformat()
        }

    def detect_rogue_assets(self) -> Dict:
        """
        Compare last discovered assets with baseline and flag unknown entries.
        """
        baseline_ids = {
            asset.get("ip") or asset.get("hostname")
            for asset in self.baseline_assets
            if asset.get("ip") or asset.get("hostname")
        }

        rogue = []
        for asset in self.last_discovery:
            asset_id = asset.get("ip") or asset.get("hostname")
            if asset_id and asset_id not in baseline_ids:
                rogue.append(asset)

        self.rogue_assets = rogue
        logger.info(f"Rogue assets detected: {len(rogue)}")

        return {
            "status": "success",
            "rogue_assets": rogue,
            "rogue_count": len(rogue),
            "timestamp": datetime.now().isoformat()
        }

    def get_status(self) -> Dict:
        return {
            "status": "online",
            "baseline_assets": len(self.baseline_assets),
            "last_discovery_count": len(self.last_discovery),
            "rogue_assets_count": len(self.rogue_assets),
            "timestamp": datetime.now().isoformat()
        }
