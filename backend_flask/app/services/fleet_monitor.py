"""
Fleet Monitor Service
Real-time network monitoring with ping sweeps, connection tracking, and anomaly detection.
"""

import logging
import subprocess
import socket
import platform
from typing import Dict, List, Tuple
from datetime import datetime
import json

logger = logging.getLogger(__name__)


class FleetMonitor:
    """
    Fleet Monitor: Tracks active network connections, performs ping sweeps,
    and monitors asset health across the network.
    """

    def __init__(self):
        """Initialize Fleet Monitor."""
        self.monitored_assets: List[Dict] = []
        self.active_connections: List[Dict] = []
        self.network_baseline: Dict = {}
        self.anomalies: List[Dict] = []
        self.os_type = platform.system()
        logger.info(f"FleetMonitor initialized for OS: {self.os_type}")

    def _execute_command(self, command: List[str], timeout: int = 10) -> Tuple[bool, str]:
        """
        Execute system command with error handling.
        
        Args:
            command: List of command parts to execute
            timeout: Command timeout in seconds
            
        Returns:
            Tuple of (success: bool, output: str)
        """
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False
            )
            output = (result.stdout + result.stderr).strip()
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            error_msg = f"Command timeout after {timeout}s"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            logger.error(f"Command execution error: {str(e)}")
            return False, str(e)

    def ping_asset(self, ip_address: str, count: int = 3) -> Dict:
        """
        Ping a network asset to check availability.
        
        Args:
            ip_address: IP address to ping
            count: Number of ping packets to send
            
        Returns:
            Dict with ping results
        """
        logger.info(f"Pinging asset: {ip_address}")
        
        try:
            # Different ping command based on OS
            if self.os_type == "Windows":
                cmd = ["ping", "-n", str(count), ip_address]
            else:
                cmd = ["ping", "-c", str(count), ip_address]
            
            success, output = self._execute_command(cmd, timeout=10)
            
            # Parse response
            response_time = 0.0
            packet_loss = 100
            
            if success:
                # Try to extract response time and packet loss
                lines = output.split('\n')
                for line in lines:
                    if 'time=' in line.lower() or 'ms' in line.lower():
                        try:
                            parts = line.split('=')
                            if len(parts) > 1:
                                time_str = parts[-1].strip().replace('ms', '').replace('time ', '')
                                response_time = float(time_str)
                        except:
                            pass
                
                if 'received' in output.lower():
                    try:
                        # Try to extract packet loss percentage
                        import re
                        match = re.search(r'(\d+)%\s*(?:loss|lost)', output, re.IGNORECASE)
                        if match:
                            packet_loss = int(match.group(1))
                        else:
                            packet_loss = 0  # All packets received
                    except:
                        packet_loss = 0
            
            return {
                "status": "online" if success and packet_loss < 100 else "offline",
                "ip_address": ip_address,
                "reachable": success,
                "response_time_ms": response_time,
                "packet_loss_percent": packet_loss,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Ping error for {ip_address}: {str(e)}")
            return {
                "status": "error",
                "ip_address": ip_address,
                "reachable": False,
                "error": str(e),
                "timestamp": datetime.now().isoformat()
            }

    def perform_ping_sweep(self, network_range: str) -> Dict:
        """
        Perform ping sweep on a network range (e.g., 192.168.1.0/24).
        
        Args:
            network_range: Network range in CIDR notation
            
        Returns:
            Dict with sweep results
        """
        logger.info(f"Starting ping sweep on network: {network_range}")
        
        try:
            # Parse CIDR notation
            network_parts = network_range.split('/')
            if len(network_parts) != 2:
                return {
                    "success": False,
                    "message": "Invalid CIDR notation. Use format: 192.168.1.0/24",
                    "network": network_range
                }
            
            base_ip = network_parts[0]
            subnet_mask = int(network_parts[1])
            
            # Calculate IP range from CIDR
            ips_to_scan = self._get_ips_from_cidr(base_ip, subnet_mask)
            
            reachable_hosts = []
            unreachable_hosts = []
            
            # Ping each IP (with timeout for responsiveness)
            for ip in ips_to_scan[:10]:  # Limit to first 10 for demo
                result = self.ping_asset(ip, count=1)
                if result.get("reachable"):
                    reachable_hosts.append(result)
                else:
                    unreachable_hosts.append(result)
            
            return {
                "success": True,
                "network": network_range,
                "ips_scanned": len(ips_to_scan[:10]),
                "reachable_hosts": reachable_hosts,
                "reachable_count": len(reachable_hosts),
                "unreachable_hosts": unreachable_hosts,
                "unreachable_count": len(unreachable_hosts),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Ping sweep error: {str(e)}")
            return {
                "success": False,
                "message": str(e),
                "network": network_range
            }

    def get_network_connections(self) -> Dict:
        """
        Get active network connections on the local system.
        
        Returns:
            Dict with active connections
        """
        logger.info("Retrieving active network connections")
        
        try:
            if self.os_type == "Windows":
                cmd = ["netstat", "-ano"]
            elif self.os_type == "Linux":
                cmd = ["ss", "-tan"]
            elif self.os_type == "Darwin":  # macOS
                cmd = ["netstat", "-an"]
            else:
                return {"success": False, "message": "Unsupported OS"}
            
            success, output = self._execute_command(cmd, timeout=5)
            
            if not success:
                return {
                    "success": False,
                    "message": "Failed to retrieve network connections",
                    "error": output
                }
            
            # Parse connections
            connections = self._parse_connections(output)
            
            self.active_connections = connections
            
            return {
                "success": True,
                "connections_count": len(connections),
                "connections": connections,
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            logger.error(f"Connection retrieval error: {str(e)}")
            return {
                "success": False,
                "message": str(e)
            }

    def register_asset(self, asset_info: Dict) -> Dict:
        """
        Register an asset for continuous monitoring.
        
        Args:
            asset_info: Dict with asset information (name, ip, hostname, etc.)
            
        Returns:
            Dict with registration status
        """
        logger.info(f"Registering asset: {asset_info.get('name', 'unknown')}")
        
        try:
            asset = {
                "id": len(self.monitored_assets) + 1,
                "name": asset_info.get("name"),
                "ip_address": asset_info.get("ip_address"),
                "hostname": asset_info.get("hostname"),
                "asset_type": asset_info.get("asset_type", "unknown"),
                "registered_at": datetime.now().isoformat(),
                "last_seen": None,
                "status": "unknown"
            }
            
            self.monitored_assets.append(asset)
            
            return {
                "success": True,
                "message": f"Asset {asset.get('name')} registered",
                "asset_id": asset.get("id"),
                "asset": asset
            }
        except Exception as e:
            logger.error(f"Asset registration error: {str(e)}")
            return {
                "success": False,
                "message": str(e)
            }

    def monitor_assets(self) -> Dict:
        """
        Monitor all registered assets.
        
        Returns:
            Dict with monitoring results
        """
        logger.info(f"Monitoring {len(self.monitored_assets)} registered assets")
        
        monitored_results = []
        
        for asset in self.monitored_assets:
            ip = asset.get("ip_address")
            if ip:
                result = self.ping_asset(ip, count=1)
                asset["status"] = result.get("status")
                asset["last_seen"] = result.get("timestamp")
                monitored_results.append(result)
        
        return {
            "success": True,
            "monitored_assets_count": len(self.monitored_assets),
            "results": monitored_results,
            "timestamp": datetime.now().isoformat()
        }

    def detect_anomalies(self) -> Dict:
        """
        Detect network anomalies by comparing current state with baseline.
        
        Returns:
            Dict with detected anomalies
        """
        logger.info("Analyzing network for anomalies")
        
        anomalies = []
        
        # Check for unexpected connections
        for conn in self.active_connections:
            state = conn.get("state", "").lower()
            if state in ["syn_recv", "listen", "established"]:
                # Flag unusual high-port listening or suspicious states
                local_port = conn.get("local_port", 0)
                if isinstance(local_port, str):
                    try:
                        local_port = int(local_port)
                    except:
                        local_port = 0
                
                if local_port > 10000 and state == "listen":
                    anomalies.append({
                        "type": "high_port_listener",
                        "connection": conn,
                        "severity": "medium",
                        "timestamp": datetime.now().isoformat()
                    })
        
        self.anomalies = anomalies
        
        return {
            "success": True,
            "anomalies_detected": len(anomalies),
            "anomalies": anomalies,
            "timestamp": datetime.now().isoformat()
        }

    def get_status(self) -> Dict:
        """Get Fleet Monitor status."""
        return {
            "status": "online",
            "monitored_assets": len(self.monitored_assets),
            "active_connections": len(self.active_connections),
            "detected_anomalies": len(self.anomalies),
            "timestamp": datetime.now().isoformat()
        }

    # Helper methods
    
    @staticmethod
    def _get_ips_from_cidr(base_ip: str, subnet_mask: int) -> List[str]:
        """
        Generate list of IPs from CIDR notation.
        
        Args:
            base_ip: Base IP address
            subnet_mask: Subnet mask in CIDR notation
            
        Returns:
            List of IP addresses
        """
        try:
            # For simplicity, generate IPs for /24 subnet
            if subnet_mask == 24:
                parts = base_ip.split('.')
                base = '.'.join(parts[:-1])
                return [f"{base}.{i}" for i in range(1, 255)]
            else:
                # For other masks, return just the base IP
                return [base_ip]
        except Exception as e:
            logger.error(f"CIDR parsing error: {str(e)}")
            return []

    @staticmethod
    def _parse_connections(output: str) -> List[Dict]:
        """
        Parse netstat/ss output into structured format.
        
        Args:
            output: Raw netstat/ss output
            
        Returns:
            List of connection dicts
        """
        connections = []
        lines = output.split('\n')
        
        for line in lines[1:]:  # Skip header
            if not line.strip():
                continue
            
            parts = line.split()
            if len(parts) >= 4:
                try:
                    # Parse connection info
                    conn = {
                        "protocol": parts[0] if len(parts) > 0 else "",
                        "local_address": parts[3] if len(parts) > 3 else "",
                        "remote_address": parts[4] if len(parts) > 4 else "",
                        "state": parts[5] if len(parts) > 5 else "",
                        "raw": line
                    }
                    
                    # Extract port from address
                    if ":" in conn["local_address"]:
                        try:
                            conn["local_port"] = int(conn["local_address"].split(":")[-1])
                        except:
                            conn["local_port"] = 0
                    
                    connections.append(conn)
                except Exception as e:
                    logger.debug(f"Failed to parse connection line: {str(e)}")
        
        return connections
