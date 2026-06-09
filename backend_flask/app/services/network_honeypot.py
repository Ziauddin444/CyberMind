"""
Network Honeypot Service
Binds to decoy ports, captures connection attempts, and logs threat intelligence.
"""

import logging
import socket
import threading
import time
from typing import Dict, List, Optional
from datetime import datetime
from collections import Counter

logger = logging.getLogger(__name__)


class NetworkHoneypot:
    """
    Network Honeypot: Listens on multiple decoy ports with fake service banners,
    captures connection attempts, and logs attacker data for threat intelligence.
    
    Features:
    - Cross-platform: Works on Mac, Windows, Linux
    - Non-blocking: Each port runs on background thread
    - Graceful shutdown: Clean socket closure on Flask exit
    - Auto-save: Captures saved via honeypot_file_handler
    - Fault-tolerant: Handles port conflicts silently
    """

    HONEYPOT_PORTS = {
        22: {
            'name': 'SSH',
            'banner': 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n',
            'threat_type': 'brute_force',
            'severity': 'high'
        },
        23: {
            'name': 'Telnet',
            'banner': '\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f',
            'threat_type': 'reconnaissance',
            'severity': 'medium'
        },
        8080: {
            'name': 'HTTP-Admin',
            'banner': 'HTTP/1.1 200 OK\r\nServer: Apache/2.4.41\r\nContent-Type: text/html\r\n\r\n<html><title>Admin Login</title></html>',
            'threat_type': 'reconnaissance',
            'severity': 'medium'
        },
        3389: {
            'name': 'RDP',
            'banner': '\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x0f\x08\x00\x02\x00\x00\x00',
            'threat_type': 'brute_force',
            'severity': 'critical'
        }
    }

    def __init__(self, file_handler=None):
        """
        Initialize Network Honeypot.
        
        Args:
            file_handler: HoneypotFileHandler instance for saving captures
        """
        self.file_handler = file_handler
        self.active_listeners: Dict = {}  # {port: {thread, socket, running, stats}}
        self.connection_logs: List[Dict] = []
        self.max_log_size = 1000
        self.total_connections = 0
        self.running = False
        self.logger = logger
        self.logger.info("NetworkHoneypot initialized with %d decoy ports", len(self.HONEYPOT_PORTS))

    def start_all_listeners(self) -> Dict:
        """
        Start listening on all honeypot ports.
        
        Returns:
            Dict with startup summary:
            {
                success: bool,
                listeners_started: [list of ports],
                listeners_failed: [list of ports with errors],
                message: str
            }
        """
        if self.running:
            return {
                'success': False,
                'message': 'Honeypot already running'
            }

        self.running = True
        started = []
        failed = []

        for port in self.HONEYPOT_PORTS.keys():
            result = self.bind_port(port)
            if result.get('success'):
                started.append(port)
            else:
                failed.append(port)

        message = f"Honeypot active on {len(started)} port(s)"
        if failed:
            message += f" ({len(failed)} failed)"

        self.logger.info(message)
        return {
            'success': True,
            'listeners_started': sorted(started),
            'listeners_failed': sorted(failed),
            'message': message
        }

    def bind_port(self, port: int, services: List[str] = None) -> Dict:
        """
        Bind a real TCP socket to a decoy port.
        
        Args:
            port: Port number to listen on
            services: Services to emulate (for legacy compatibility)
            
        Returns:
            Dict with binding status:
            {
                success: bool,
                port: int,
                status: str,
                error: str (if failed)
            }
        """
        port_config = self.HONEYPOT_PORTS.get(port)
        if not port_config:
            return {
                'success': False,
                'port': port,
                'error': 'Port not in honeypot configuration'
            }

        try:
            # Create TCP socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind to port
            sock.bind(('0.0.0.0', port))
            sock.listen(5)
            sock.settimeout(1.0)

            # Start background listener thread
            listener_thread = threading.Thread(
                target=self._listener_loop,
                args=(port, sock),
                daemon=True,
                name=f'honeypot-{port_config["name"]}-{port}'
            )
            listener_thread.start()

            # Store listener state
            self.active_listeners[port] = {
                'thread': listener_thread,
                'socket': sock,
                'running': True,
                'stats': {
                    'connections': 0,
                    'started_at': datetime.utcnow().isoformat()
                }
            }

            self.logger.info(
                f"Honeypot listening on port {port} ({port_config['name']}) "
                f"with threat_type={port_config['threat_type']}"
            )

            return {
                'success': True,
                'port': port,
                'status': 'listening'
            }

        except PermissionError:
            self.logger.warning(
                f"Permission denied for port {port}. "
                f"Ports below 1024 require sudo/administrator privileges."
            )
            return {
                'success': False,
                'port': port,
                'error': 'Permission denied - run with sudo for ports below 1024'
            }

        except OSError as e:
            if 'Address already in use' in str(e) or e.errno == 48:
                self.logger.warning(
                    f"Port {port} already in use (likely by another service). Skipping."
                )
                return {
                    'success': False,
                    'port': port,
                    'error': 'Port in use'
                }
            raise

        except Exception as e:
            self.logger.error(f"Failed to bind port {port}: {str(e)}")
            return {
                'success': False,
                'port': port,
                'error': str(e)
            }

    def _listener_loop(self, port: int, sock: socket.socket) -> None:
        """
        Background thread loop for accepting connections on a honeypot port.
        
        Args:
            port: Port number
            sock: Listening socket
        """
        port_name = self.HONEYPOT_PORTS.get(port, {}).get('name', 'Unknown')

        while port in self.active_listeners:
            try:
                client_sock, addr = sock.accept()

                # Handle connection in separate thread to not block listener
                threading.Thread(
                    target=self._handle_connection,
                    args=(client_sock, addr, port),
                    daemon=True
                ).start()

            except socket.timeout:
                # Timeout is expected; loop continues
                continue

            except Exception as e:
                if port in self.active_listeners:
                    self.logger.error(f"Listener error on port {port}: {e}")
                break

        try:
            sock.close()
            self.logger.info(f"Honeypot socket closed on port {port} ({port_name})")
        except Exception as e:
            self.logger.warning(f"Error closing socket on port {port}: {e}")

    def _handle_connection(self, client_sock: socket.socket, addr: tuple, port: int) -> None:
        """
        Handle an incoming connection to a honeypot port.
        
        Args:
            client_sock: Connected client socket
            addr: (source_ip, source_port) tuple
            port: Honeypot port number
        """
        source_ip = addr[0]
        source_port = addr[1]
        port_config = self.HONEYPOT_PORTS.get(port, {})

        try:
            # Send fake banner
            banner = port_config.get('banner', '')
            if isinstance(banner, str):
                if banner.startswith('HTTP'):
                    # HTTP banner is plain text
                    client_sock.sendall(banner.encode('utf-8'))
                else:
                    # For binary protocols, try to send as bytes
                    try:
                        client_sock.sendall(banner.encode('utf-8'))
                    except (UnicodeDecodeError, UnicodeEncodeError):
                        # Banner contains binary data, try direct bytes
                        client_sock.sendall(banner.encode('latin-1'))

            # Set timeout to receive payload
            client_sock.settimeout(5.0)

            # Receive attacker payload
            try:
                payload_bytes = client_sock.recv(1024)
                payload = payload_bytes.decode('utf-8', errors='replace')
            except socket.timeout:
                payload = 'No payload received (timeout)'
            except Exception as e:
                payload = f'Error reading payload: {str(e)}'

        except Exception as e:
            self.logger.warning(f"Error sending banner to {source_ip}:{source_port}: {e}")
            payload = 'Error during banner transmission'

        finally:
            try:
                client_sock.close()
            except Exception:
                pass

        # Build capture data
        capture_data = {
            'source_ip': source_ip,
            'source_port': source_port,
            'target_port': port,
            'service_name': port_config.get('name', 'Unknown'),
            'payload': payload if payload else 'No payload received',
            'threat_type': port_config.get('threat_type', 'unknown'),
            'severity': port_config.get('severity', 'medium'),
            'timestamp': datetime.utcnow().isoformat(),
            'banner_sent': port_config.get('banner', '')
        }

        # Log connection locally
        self.log_connection(capture_data)

        # Save to disk if file handler available
        if self.file_handler:
            try:
                self.file_handler.save_capture_file(
                    source_ip,
                    str(capture_data),
                    port_config.get('threat_type', 'unknown')
                )
            except Exception as e:
                self.logger.warning(f"Failed to save honeypot capture: {e}")

        # Update listener stats
        if port in self.active_listeners:
            self.active_listeners[port]['stats']['connections'] += 1

    def log_connection(self, capture_data: Dict) -> None:
        """
        Log a honeypot connection to in-memory buffer.
        
        Args:
            capture_data: Dict with connection details
        """
        self.connection_logs.append(capture_data)

        # Trim to max size
        if len(self.connection_logs) > self.max_log_size:
            self.connection_logs = self.connection_logs[-self.max_log_size:]

        self.total_connections += 1

        # Log to Flask logger
        self.logger.info(
            f"HONEYPOT HIT: {capture_data['source_ip']}:{capture_data['source_port']} "
            f"→ Port {capture_data['target_port']} ({capture_data['service_name']}) | "
            f"Threat: {capture_data['threat_type']} | Severity: {capture_data['severity']}"
        )

    def get_connection_logs(self, limit: int = 50) -> List[Dict]:
        """
        Get recent honeypot connection logs.
        
        Args:
            limit: Maximum number of logs to return
            
        Returns:
            List of connection dicts (most recent first)
        """
        return list(reversed(self.connection_logs[-limit:]))

    def get_threat_analysis(self) -> Dict:
        """
        Get comprehensive threat analysis from honeypot data.
        
        Returns:
            Dict with:
            {
                total_connections: int,
                active_ports: [list],
                inactive_ports: [list],
                top_attackers: [(ip, count), ...],
                threat_breakdown: {type: count},
                most_targeted_port: int,
                honeypot_status: "active"|"inactive"
            }
        """
        active_ports = list(self.active_listeners.keys())
        inactive_ports = [p for p in self.HONEYPOT_PORTS.keys() if p not in active_ports]

        # Calculate top attackers
        attacker_ips = Counter(log.get('source_ip') for log in self.connection_logs)
        top_attackers = [(ip, count) for ip, count in attacker_ips.most_common(5)]

        # Calculate threat breakdown
        threat_breakdown = Counter(log.get('threat_type') for log in self.connection_logs)
        threat_breakdown = dict(threat_breakdown)

        # Find most targeted port
        port_hits = Counter(log.get('target_port') for log in self.connection_logs)
        most_targeted = port_hits.most_common(1)
        most_targeted_port = most_targeted[0][0] if most_targeted else None

        return {
            'total_connections': self.total_connections,
            'active_ports': sorted(active_ports),
            'inactive_ports': sorted(inactive_ports),
            'top_attackers': top_attackers,
            'threat_breakdown': threat_breakdown,
            'most_targeted_port': most_targeted_port,
            'honeypot_status': 'active' if active_ports else 'inactive',
            'timestamp': datetime.utcnow().isoformat()
        }

    def stop_port(self, port: int) -> Dict:
        """
        Stop listening on a specific honeypot port.
        
        Args:
            port: Port number to stop
            
        Returns:
            Dict with stop status
        """
        if port not in self.active_listeners:
            return {
                'success': False,
                'port': port,
                'error': 'Port not listening'
            }

        listener = self.active_listeners[port]

        try:
            listener['running'] = False
            listener['socket'].close()
        except Exception as e:
            self.logger.warning(f"Error closing port {port}: {e}")

        del self.active_listeners[port]

        self.logger.info(f"Honeypot listener stopped on port {port}")
        return {
            'success': True,
            'port': port,
            'message': 'Listener stopped'
        }

    def stop_all(self) -> None:
        """Stop all honeypot listeners gracefully."""
        ports_to_stop = list(self.active_listeners.keys())

        for port in ports_to_stop:
            self.stop_port(port)

        self.running = False
        self.logger.info(f"All honeypot listeners stopped. Total connections: {self.total_connections}")

    # ─── Legacy Compatibility Methods (for routes.py) ───────────────────────────

    def start_listener_daemon(self, port: int) -> Dict:
        """
        Start a daemon listener on specified port (legacy method).
        
        Args:
            port: Port to listen on
            
        Returns:
            Dict with listener status
        """
        result = self.bind_port(port)
        if result.get('success'):
            return {
                'success': True,
                'message': f"Listener started on port {port}",
                'port': port
            }
        return {
            'success': False,
            'error': result.get('error', 'Unknown error'),
            'port': port
        }

    def stop_listener(self, port: int) -> Dict:
        """
        Stop listener on specified port (legacy method).
        
        Args:
            port: Port to stop listening on
            
        Returns:
            Dict with stop status
        """
        return self.stop_port(port)

    def get_active_listeners(self) -> Dict:
        """
        Get list of active listeners (legacy method).
        
        Returns:
            Dict with active listeners
        """
        return {
            'status': 'success',
            'active_listeners_count': len(self.active_listeners),
            'listeners': {p: {
                'name': self.HONEYPOT_PORTS.get(p, {}).get('name'),
                'stats': self.active_listeners[p]['stats']
            } for p in self.active_listeners},
            'timestamp': datetime.utcnow().isoformat()
        }

    def get_honeypot_stats(self) -> Dict:
        """Get honeypot statistics (legacy method)."""
        return {
            'status': 'online',
            'listening_ports': list(self.active_listeners.keys()),
            'total_connections_logged': len(self.connection_logs),
            'active_listeners': len(self.active_listeners)
        }

    def emit_service_response(self, port: int, response_type: str) -> str:
        """
        Generate fake service response for honeypot (legacy method).
        
        Args:
            port: Port being probed
            response_type: Type of response to emit
            
        Returns:
            Fake service response string
        """
        port_config = self.HONEYPOT_PORTS.get(port, {})
        return port_config.get('banner', 'Connected\r\n')
