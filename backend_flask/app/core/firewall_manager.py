"""
Cross-Platform Firewall Manager
Interfaces with native firewalls: Windows Defender (netsh), Linux (iptables/ufw), macOS (pf)
"""

import platform
import subprocess
import logging
from typing import Dict, List, Tuple
from datetime import datetime

logger = logging.getLogger(__name__)


class FirewallManager:
    """
    Autonomous firewall controller that detects OS and manages native firewalls.
    Supports Windows (netsh), Linux (iptables/ufw), and macOS (pf).
    """

    def __init__(self):
        """Initialize firewall manager with OS detection."""
        self.os_type = platform.system()
        self.blocked_ips: List[str] = []
        self.isolation_active = False
        logger.info(f"FirewallManager initialized for OS: {self.os_type}")

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
            if result.returncode != 0:
                lowered = output.lower()
                if "permission denied" in lowered or "operation not permitted" in lowered:
                    hint = "Requires elevated privileges. Re-run with Administrator (Windows) or sudo (Linux/macOS)."
                    return False, f"{output}\n{hint}".strip()
            return result.returncode == 0, output
        except subprocess.TimeoutExpired:
            error_msg = f"Command timeout after {timeout}s: {' '.join(command)}"
            logger.error(error_msg)
            return False, error_msg
        except PermissionError:
            error_msg = f"Permission denied executing: {' '.join(command)}. Run with sudo/admin."
            logger.error(error_msg)
            return False, error_msg
        except FileNotFoundError as e:
            error_msg = f"Command not found: {' '.join(command)}"
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Unexpected error executing command: {str(e)}"
            logger.error(error_msg)
            return False, error_msg

    def block_ip(self, ip_address: str, reason: str = "Security threat detected") -> Dict:
        """
        Block an IP address using native firewall.
        
        Args:
            ip_address: IP address to block
            reason: Reason for blocking
            
        Returns:
            Dict with status, message, and details
        """
        logger.info(f"Attempting to block IP: {ip_address}")
        
        # Validate IP address format
        if not self._validate_ip(ip_address):
            return {
                "success": False,
                "message": f"Invalid IP address: {ip_address}",
                "ip": ip_address,
                "reason": reason
            }
        
        if self.os_type == "Windows":
            return self._block_ip_windows(ip_address, reason)
        elif self.os_type == "Linux":
            return self._block_ip_linux(ip_address, reason)
        elif self.os_type == "Darwin":  # macOS
            return self._block_ip_macos(ip_address, reason)
        else:
            return {
                "success": False,
                "message": f"Unsupported OS: {self.os_type}",
                "ip": ip_address
            }

    def _block_ip_windows(self, ip_address: str, reason: str) -> Dict:
        """Block IP on Windows using netsh firewall."""
        try:
            # Create inbound rule
            rule_name = f"CYBERMIND_BLOCK_{ip_address.replace('.', '_')}"
            inbound_cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name}",
                f"dir=in",
                "action=block",
                f"remoteip={ip_address}",
                "protocol=any"
            ]
            
            success_in, output_in = self._execute_command(inbound_cmd)
            
            # Create outbound rule
            rule_name_out = f"{rule_name}_OUT"
            outbound_cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={rule_name_out}",
                f"dir=out",
                "action=block",
                f"remoteip={ip_address}",
                "protocol=any"
            ]
            
            success_out, output_out = self._execute_command(outbound_cmd)
            
            if success_in and success_out:
                self.blocked_ips.append(ip_address)
                logger.info(f"Successfully blocked IP on Windows: {ip_address}")
                return {
                    "success": True,
                    "message": f"IP {ip_address} blocked successfully",
                    "ip": ip_address,
                    "reason": reason,
                    "os": "Windows",
                    "timestamp": datetime.now().isoformat()
                }
            else:
                error = output_in + output_out
                logger.error(f"Failed to block IP on Windows: {error}")
                return {
                    "success": False,
                    "message": f"Failed to block IP on Windows",
                    "ip": ip_address,
                    "error": error,
                    "os": "Windows"
                }
        except Exception as e:
            logger.error(f"Windows firewall error: {str(e)}")
            return {
                "success": False,
                "message": f"Windows firewall error: {str(e)}",
                "ip": ip_address,
                "os": "Windows"
            }

    def _block_ip_linux(self, ip_address: str, reason: str) -> Dict:
        """Block IP on Linux using iptables or ufw."""
        try:
            # Try ufw first (user-friendly)
            ufw_check = self._execute_command(["which", "ufw"])[0]
            
            if ufw_check:
                return self._block_ip_with_ufw(ip_address, reason)
            else:
                return self._block_ip_with_iptables(ip_address, reason)
        except Exception as e:
            logger.error(f"Linux firewall error: {str(e)}")
            return {
                "success": False,
                "message": f"Linux firewall error: {str(e)}",
                "ip": ip_address,
                "os": "Linux"
            }

    def _block_ip_with_ufw(self, ip_address: str, reason: str) -> Dict:
        """Block IP using ufw (Ubuntu/Debian)."""
        try:
            # Block incoming
            cmd_in = ["sudo", "ufw", "deny", "from", ip_address]
            success_in, output_in = self._execute_command(cmd_in)
            
            if success_in:
                self.blocked_ips.append(ip_address)
                logger.info(f"Successfully blocked IP on Linux (ufw): {ip_address}")
                return {
                    "success": True,
                    "message": f"IP {ip_address} blocked successfully with ufw",
                    "ip": ip_address,
                    "reason": reason,
                    "os": "Linux",
                    "firewall": "ufw",
                    "timestamp": datetime.now().isoformat()
                }
            else:
                logger.error(f"Failed to block IP with ufw: {output_in}")
                return {
                    "success": False,
                    "message": f"Failed to block IP with ufw",
                    "ip": ip_address,
                    "error": output_in,
                    "os": "Linux"
                }
        except Exception as e:
            logger.error(f"ufw error: {str(e)}")
            return {
                "success": False,
                "message": f"ufw error: {str(e)}",
                "ip": ip_address,
                "os": "Linux"
            }

    def _block_ip_with_iptables(self, ip_address: str, reason: str) -> Dict:
        """Block IP using iptables (system-level)."""
        try:
            # Block incoming connections
            cmd_in = ["sudo", "iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"]
            success_in, output_in = self._execute_command(cmd_in)
            
            # Block outgoing connections
            cmd_out = ["sudo", "iptables", "-I", "OUTPUT", "-d", ip_address, "-j", "DROP"]
            success_out, output_out = self._execute_command(cmd_out)
            
            if success_in and success_out:
                self.blocked_ips.append(ip_address)
                logger.info(f"Successfully blocked IP on Linux (iptables): {ip_address}")
                return {
                    "success": True,
                    "message": f"IP {ip_address} blocked successfully with iptables",
                    "ip": ip_address,
                    "reason": reason,
                    "os": "Linux",
                    "firewall": "iptables",
                    "timestamp": datetime.now().isoformat()
                }
            else:
                error = output_in + output_out
                logger.error(f"Failed to block IP with iptables: {error}")
                return {
                    "success": False,
                    "message": f"Failed to block IP with iptables",
                    "ip": ip_address,
                    "error": error,
                    "os": "Linux"
                }
        except Exception as e:
            logger.error(f"iptables error: {str(e)}")
            return {
                "success": False,
                "message": f"iptables error: {str(e)}",
                "ip": ip_address,
                "os": "Linux"
            }

    def _block_ip_macos(self, ip_address: str, reason: str) -> Dict:
        """Block IP on macOS using pf (packet filter)."""
        try:
            pf_rule = f"block drop in from {ip_address}\nblock drop out to {ip_address}\n"
            pf_file = "/etc/pf.conf"
            
            # Note: This requires elevated privileges and careful handling
            # Create a backup and add rule
            cmd = [
                "sudo", "sh", "-c",
                f"cp {pf_file} {pf_file}.bak && echo '{pf_rule}' >> {pf_file} && pfctl -f {pf_file}"
            ]
            
            success, output = self._execute_command(cmd)
            
            if success:
                self.blocked_ips.append(ip_address)
                logger.info(f"Successfully blocked IP on macOS: {ip_address}")
                return {
                    "success": True,
                    "message": f"IP {ip_address} blocked successfully with pf",
                    "ip": ip_address,
                    "reason": reason,
                    "os": "Darwin",
                    "firewall": "pf",
                    "timestamp": datetime.now().isoformat()
                }
            else:
                logger.error(f"Failed to block IP on macOS: {output}")
                return {
                    "success": False,
                    "message": f"Failed to block IP on macOS",
                    "ip": ip_address,
                    "error": output,
                    "os": "Darwin"
                }
        except Exception as e:
            logger.error(f"macOS firewall error: {str(e)}")
            return {
                "success": False,
                "message": f"macOS firewall error: {str(e)}",
                "ip": ip_address,
                "os": "Darwin"
            }

    def isolate_network(self, reason: str = "Emergency network isolation triggered") -> Dict:
        """
        Kill Switch: Isolate network by dropping all connections.
        """
        logger.warning(f"KILL SWITCH ACTIVATED: {reason}")
        
        if self.isolation_active:
            return {
                "success": False,
                "message": "Network already in isolation mode",
                "isolation_active": True
            }
        
        if self.os_type == "Windows":
            return self._isolate_network_windows(reason)
        elif self.os_type == "Linux":
            return self._isolate_network_linux(reason)
        elif self.os_type == "Darwin":
            return self._isolate_network_macos(reason)
        else:
            return {
                "success": False,
                "message": f"Unsupported OS: {self.os_type}"
            }

    def _isolate_network_windows(self, reason: str) -> Dict:
        """Isolate network on Windows."""
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                "name=CYBERMIND_KILL_SWITCH",
                "dir=in",
                "action=block",
                "remoteip=any"
            ]
            success, output = self._execute_command(cmd)
            
            if success:
                self.isolation_active = True
                logger.warning(f"Network isolation activated on Windows: {reason}")
                return {
                    "success": True,
                    "message": "Network isolation activated - all incoming traffic blocked",
                    "os": "Windows",
                    "reason": reason,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                logger.error(f"Failed to isolate network on Windows: {output}")
                return {
                    "success": False,
                    "message": "Failed to activate network isolation",
                    "error": output,
                    "os": "Windows"
                }
        except Exception as e:
            logger.error(f"Windows isolation error: {str(e)}")
            return {
                "success": False,
                "message": f"Windows isolation error: {str(e)}",
                "os": "Windows"
            }

    def _isolate_network_linux(self, reason: str) -> Dict:
        """Isolate network on Linux."""
        try:
            # Drop all incoming and outgoing traffic
            cmd_in = ["sudo", "iptables", "-I", "INPUT", "-j", "DROP"]
            cmd_out = ["sudo", "iptables", "-I", "OUTPUT", "-j", "DROP"]
            
            success_in, output_in = self._execute_command(cmd_in)
            success_out, output_out = self._execute_command(cmd_out)
            
            if success_in and success_out:
                self.isolation_active = True
                logger.warning(f"Network isolation activated on Linux: {reason}")
                return {
                    "success": True,
                    "message": "Network isolation activated - all traffic blocked",
                    "os": "Linux",
                    "reason": reason,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                error = output_in + output_out
                logger.error(f"Failed to isolate network on Linux: {error}")
                return {
                    "success": False,
                    "message": "Failed to activate network isolation",
                    "error": error,
                    "os": "Linux"
                }
        except Exception as e:
            logger.error(f"Linux isolation error: {str(e)}")
            return {
                "success": False,
                "message": f"Linux isolation error: {str(e)}",
                "os": "Linux"
            }

    def _isolate_network_macos(self, reason: str) -> Dict:
        """Isolate network on macOS."""
        try:
            pf_rule = "block drop all\n"
            cmd = [
                "sudo", "sh", "-c",
                f"echo '{pf_rule}' | pfctl -f -"
            ]
            
            success, output = self._execute_command(cmd)
            
            if success:
                self.isolation_active = True
                logger.warning(f"Network isolation activated on macOS: {reason}")
                return {
                    "success": True,
                    "message": "Network isolation activated - all traffic blocked",
                    "os": "Darwin",
                    "reason": reason,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                logger.error(f"Failed to isolate network on macOS: {output}")
                return {
                    "success": False,
                    "message": "Failed to activate network isolation",
                    "error": output,
                    "os": "Darwin"
                }
        except Exception as e:
            logger.error(f"macOS isolation error: {str(e)}")
            return {
                "success": False,
                "message": f"macOS isolation error: {str(e)}",
                "os": "Darwin"
            }

    def release_network_isolation(self) -> Dict:
        """Release network isolation (Kill Switch OFF)."""
        if not self.isolation_active:
            return {
                "success": False,
                "message": "Network is not in isolation mode"
            }
        
        logger.warning("Attempting to release network isolation")
        
        if self.os_type == "Windows":
            return self._release_isolation_windows()
        elif self.os_type == "Linux":
            return self._release_isolation_linux()
        elif self.os_type == "Darwin":
            return self._release_isolation_macos()

    def _release_isolation_windows(self) -> Dict:
        """Release isolation on Windows."""
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "delete", "rule",
                "name=CYBERMIND_KILL_SWITCH"
            ]
            success, output = self._execute_command(cmd)
            
            if success:
                self.isolation_active = False
                logger.info("Network isolation released on Windows")
                return {
                    "success": True,
                    "message": "Network isolation released",
                    "os": "Windows"
                }
            else:
                return {"success": False, "message": output, "os": "Windows"}
        except Exception as e:
            return {"success": False, "message": str(e), "os": "Windows"}

    def _release_isolation_linux(self) -> Dict:
        """Release isolation on Linux."""
        try:
            cmd = ["sudo", "iptables", "-F"]  # Flush all rules
            success, output = self._execute_command(cmd)
            
            if success:
                self.isolation_active = False
                logger.info("Network isolation released on Linux")
                return {
                    "success": True,
                    "message": "Network isolation released",
                    "os": "Linux"
                }
            else:
                return {"success": False, "message": output, "os": "Linux"}
        except Exception as e:
            return {"success": False, "message": str(e), "os": "Linux"}

    def _release_isolation_macos(self) -> Dict:
        """Release isolation on macOS."""
        try:
            cmd = ["sudo", "pfctl", "-d"]  # Disable pf
            success, output = self._execute_command(cmd)
            
            if success:
                self.isolation_active = False
                logger.info("Network isolation released on macOS")
                return {
                    "success": True,
                    "message": "Network isolation released",
                    "os": "Darwin"
                }
            else:
                return {"success": False, "message": output, "os": "Darwin"}
        except Exception as e:
            return {"success": False, "message": str(e), "os": "Darwin"}

    def get_blocked_ips(self) -> List[str]:
        """Get list of currently blocked IPs."""
        return self.blocked_ips.copy()

    def get_status(self) -> Dict:
        """Get current firewall status."""
        return {
            "os": self.os_type,
            "isolation_active": self.isolation_active,
            "blocked_ips_count": len(self.blocked_ips),
            "blocked_ips": self.blocked_ips,
            "timestamp": datetime.now().isoformat()
        }

    @staticmethod
    def _validate_ip(ip_address: str) -> bool:
        """Validate IP address format (basic IPv4 check)."""
        parts = ip_address.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
