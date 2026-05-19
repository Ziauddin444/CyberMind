"""
Honeypot File Handler Service
Manages honeypot capture files, exports, and analysis
"""
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)
HONEYPOT_DIR = Path(__file__).parent.parent.parent / "data" / "honeypot_captures"


class HoneypotFileHandler:
    """Manages honeypot capture files and artifacts"""

    def __init__(self):
        """Initialize honeypot file handler"""
        self.honeypot_dir = HONEYPOT_DIR
        self.honeypot_dir.mkdir(parents=True, exist_ok=True)
        self.captures_file = self.honeypot_dir / "captures.json"
        self._load_captures()

    def _load_captures(self) -> None:
        """Load capture metadata"""
        try:
            if self.captures_file.exists():
                with open(self.captures_file, 'r') as f:
                    self.captures = json.load(f)
            else:
                self.captures = []
                self._save_captures()
        except Exception as e:
            logger.error(f"Error loading captures: {e}")
            self.captures = []

    def _save_captures(self) -> None:
        """Save capture metadata"""
        try:
            with open(self.captures_file, 'w') as f:
                json.dump(self.captures, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving captures: {e}")

    def save_capture_file(self, source_ip: str, payload: str, threat_type: str = "unknown") -> Dict:
        """
        Save honeypot capture to file
        
        Args:
            source_ip: IP address of attacker
            payload: Attack payload/request
            threat_type: Type of threat detected
        
        Returns:
            Capture metadata
        """
        try:
            timestamp = datetime.utcnow().isoformat()
            filename = f"{source_ip}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt"
            filepath = self.honeypot_dir / filename
            
            # Save payload to file
            with open(filepath, 'w') as f:
                f.write(f"Source IP: {source_ip}\n")
                f.write(f"Threat Type: {threat_type}\n")
                f.write(f"Timestamp: {timestamp}\n")
                f.write(f"{'='*60}\n")
                f.write(payload)
            
            # Record metadata
            capture = {
                "id": len(self.captures) + 1,
                "source_ip": source_ip,
                "filename": filename,
                "threat_type": threat_type,
                "timestamp": timestamp,
                "file_size": len(payload),
                "status": "captured"
            }
            
            self.captures.append(capture)
            self._save_captures()
            
            logger.info(f"Honeypot capture saved: {filename}")
            return {"success": True, "capture": capture}
        except Exception as e:
            logger.error(f"Error saving capture: {e}")
            return {"success": False, "error": str(e)}

    def get_capture_file(self, capture_id: int) -> Optional[str]:
        """Retrieve capture file content"""
        try:
            if 0 <= capture_id < len(self.captures):
                capture = self.captures[capture_id]
                filepath = self.honeypot_dir / capture['filename']
                
                if filepath.exists():
                    with open(filepath, 'r') as f:
                        return f.read()
            return None
        except Exception as e:
            logger.error(f"Error reading capture: {e}")
            return None

    def list_captures(self, limit: int = 100) -> List[Dict]:
        """List all captured payloads"""
        return self.captures[-limit:]

    def list_captures_by_ip(self, source_ip: str) -> List[Dict]:
        """Get all captures from specific IP"""
        return [c for c in self.captures if c['source_ip'] == source_ip]

    def list_captures_by_threat(self, threat_type: str) -> List[Dict]:
        """Get captures by threat type"""
        return [c for c in self.captures if c['threat_type'] == threat_type]

    def delete_capture(self, capture_id: int) -> Dict:
        """Delete a specific capture"""
        try:
            if 0 <= capture_id < len(self.captures):
                capture = self.captures[capture_id]
                filepath = self.honeypot_dir / capture['filename']
                
                if filepath.exists():
                    filepath.unlink()
                
                self.captures.pop(capture_id)
                self._save_captures()
                
                logger.info(f"Capture deleted: {capture['filename']}")
                return {"success": True, "message": f"Capture {capture_id} deleted"}
            
            return {"success": False, "error": "Capture not found"}
        except Exception as e:
            logger.error(f"Error deleting capture: {e}")
            return {"success": False, "error": str(e)}

    def export_captures(self, export_format: str = "json") -> Dict:
        """
        Export all captures
        
        Args:
            export_format: 'json', 'csv', or 'txt'
        
        Returns:
            Exported data
        """
        try:
            if export_format == "json":
                return {
                    "success": True,
                    "format": "json",
                    "data": self.captures,
                    "count": len(self.captures)
                }
            
            elif export_format == "csv":
                csv_data = "ID,Source IP,Threat Type,Timestamp,File Size\n"
                for c in self.captures:
                    csv_data += f"{c['id']},{c['source_ip']},{c['threat_type']},{c['timestamp']},{c['file_size']}\n"
                return {
                    "success": True,
                    "format": "csv",
                    "data": csv_data,
                    "count": len(self.captures)
                }
            
            else:
                return {"success": False, "error": f"Unsupported format: {export_format}"}
        except Exception as e:
            logger.error(f"Error exporting captures: {e}")
            return {"success": False, "error": str(e)}

    def get_threat_summary(self) -> Dict:
        """Get summary of captured threats"""
        summary = {
            "total_captures": len(self.captures),
            "unique_ips": len(set(c['source_ip'] for c in self.captures)),
            "threat_types": {},
            "top_attackers": []
        }
        
        # Count threat types
        for capture in self.captures:
            threat = capture['threat_type']
            summary['threat_types'][threat] = summary['threat_types'].get(threat, 0) + 1
        
        # Get top attackers
        ip_counts = {}
        for capture in self.captures:
            ip = capture['source_ip']
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        summary['top_attackers'] = sorted(
            [{"ip": ip, "count": count} for ip, count in ip_counts.items()],
            key=lambda x: x['count'],
            reverse=True
        )[:10]
        
        return summary

    def cleanup_old_captures(self, days: int = 30) -> Dict:
        """Delete captures older than specified days"""
        try:
            from datetime import timedelta
            cutoff = datetime.utcnow() - timedelta(days=days)
            
            deleted_count = 0
            remaining_captures = []
            
            for capture in self.captures:
                capture_time = datetime.fromisoformat(capture['timestamp'].replace('Z', '+00:00'))
                if capture_time < cutoff:
                    filepath = self.honeypot_dir / capture['filename']
                    if filepath.exists():
                        filepath.unlink()
                    deleted_count += 1
                else:
                    remaining_captures.append(capture)
            
            self.captures = remaining_captures
            self._save_captures()
            
            logger.info(f"Cleaned up {deleted_count} old captures")
            return {
                "success": True,
                "deleted": deleted_count,
                "remaining": len(self.captures)
            }
        except Exception as e:
            logger.error(f"Error cleaning up captures: {e}")
            return {"success": False, "error": str(e)}
