
import json
import logging
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

logger = logging.getLogger(__name__)
DEVICES_FILE = Path(__file__).parent.parent.parent / "data" / "devices.json"
_DEVICE_LOCK = threading.Lock()


class DeviceManager:
    """Manages network device inventory and tracking"""

    def __init__(self):
        """Initialize device manager with persistent storage"""
        self.devices_file = DEVICES_FILE
        self.devices_file.parent.mkdir(parents=True, exist_ok=True)
        self._load_devices()

    def _load_devices(self) -> None:
        """Load devices from JSON file"""
        try:
            if self.devices_file.exists():
                with open(self.devices_file, 'r') as f:
                    data = json.load(f)
                    self.devices = {d['id']: d for d in data.get('devices', [])}
            else:
                self.devices = {}
                # If this fails on init, we want to know
                self._save_devices()
        except Exception as e:
            logger.error(f"Error loading devices: {e}")
            self.devices = {}

    def _save_devices(self) -> None:
        """Save devices to JSON file (thread-safe). No silent failures here."""
        data = {
            "devices": list(self.devices.values()),
            "metadata": {
                "total_devices": len(self.devices),
                "last_updated": datetime.utcnow().isoformat() + "Z"
            }
        }
        self.devices_file.parent.mkdir(parents=True, exist_ok=True)
        with _DEVICE_LOCK:
            with open(self.devices_file, 'w') as f:
                json.dump(data, f, indent=2)

    def add_device(self, device_info: Dict) -> Dict:
        """Add a new device to inventory"""
        try:
            name = (device_info.get('name') or '').strip()
            if not name:
                return {"success": False, "error": "Missing required field: name"}

            max_id = 0
            for existing_id in self.devices.keys():
                if isinstance(existing_id, str) and existing_id.startswith('device_'):
                    suffix = existing_id.split('_')[-1]
                    if suffix.isdigit():
                        max_id = max(max_id, int(suffix))
            device_id = f"device_{max_id + 1:03d}"

            ip_address = device_info.get('ip_address') or f"192.168.1.{(max_id % 240) + 10}"
            mac_address = device_info.get('mac_address') or f"02:00:00:00:{(max_id // 256) % 256:02x}:{(max_id + 1) % 256:02x}"
            device_type = device_info.get('device_type') or 'server'
            os_name = device_info.get('os') or 'unknown'
            
            device = {
                "id": device_id,
                "name": name,
                "ip_address": ip_address,
                "mac_address": mac_address,
                "device_type": device_type,
                "os": os_name,
                "status": "online",
                "last_seen": datetime.utcnow().isoformat() + "Z",
                "tags": device_info.get('tags', []),
                "registered_at": datetime.utcnow().isoformat() + "Z"
            }
            
            # Apply to memory
            self.devices[device_id] = device
            
            # Attempt to save, rollback if it fails
            try:
                self._save_devices()
            except Exception as save_error:
                del self.devices[device_id]
                logger.error(f"Disk write failed: {save_error}")
                return {"success": False, "error": f"Failed to save to disk: {save_error}"}
            
            logger.info(f"Device added: {device_id} - {device['name']}")
            return {"success": True, "device": device}
        except Exception as e:
            logger.error(f"Error adding device: {e}")
            return {"success": False, "error": str(e)}

    def delete_device(self, device_id: str) -> Dict:
        """Delete a device from inventory"""
        try:
            if device_id not in self.devices:
                return {"success": False, "error": f"Device not found: {device_id}"}
            
            # Backup before deleting from memory
            device_backup = self.devices[device_id]
            device_name = device_backup['name']
            del self.devices[device_id]
            
            # Attempt to save, rollback if it fails
            try:
                self._save_devices()
            except Exception as save_error:
                self.devices[device_id] = device_backup
                logger.error(f"Disk write failed: {save_error}")
                return {"success": False, "error": f"Failed to save to disk: {save_error}"}
            
            logger.info(f"Device deleted: {device_id} - {device_name}")
            return {"success": True, "message": f"Device {device_name} deleted"}
        except Exception as e:
            logger.error(f"Error deleting device: {e}")
            return {"success": False, "error": str(e)}

    def update_device(self, device_id: str, updates: Dict) -> Dict:
        """Update device information"""
        try:
            if device_id not in self.devices:
                return {"success": False, "error": f"Device not found: {device_id}"}
            
            # Backup original state for rollback
            original_state = {k: (v.copy() if isinstance(v, list) else v) for k, v in self.devices[device_id].items()}
            device = self.devices[device_id]
            
            allowed_fields = ['name', 'ip_address', 'mac_address', 'os', 'device_type', 'tags', 'status']
            for field, value in updates.items():
                if field in allowed_fields:
                    device[field] = value
            
            device['last_seen'] = datetime.utcnow().isoformat() + "Z"
            
            # Attempt to save, rollback if it fails
            try:
                self._save_devices()
            except Exception as save_error:
                self.devices[device_id] = original_state
                logger.error(f"Disk write failed: {save_error}")
                return {"success": False, "error": f"Failed to save to disk: {save_error}"}
            
            logger.info(f"Device updated: {device_id}")
            return {"success": True, "device": device}
        except Exception as e:
            logger.error(f"Error updating device: {e}")
            return {"success": False, "error": str(e)}

    def get_device(self, device_id: str) -> Optional[Dict]:
        """Get single device by ID"""
        return self.devices.get(device_id)

    def list_devices(self) -> List[Dict]:
        """Get all devices"""
        return list(self.devices.values())

    def list_devices_by_type(self, device_type: str) -> List[Dict]:
        """Get devices filtered by type"""
        return [d for d in self.devices.values() if d['device_type'] == device_type]

    def list_devices_by_status(self, status: str) -> List[Dict]:
        """Get devices filtered by status"""
        return [d for d in self.devices.values() if d['status'] == status]

    def list_devices_by_tag(self, tag: str) -> List[Dict]:
        """Get devices filtered by tag"""
        return [d for d in self.devices.values() if tag in d.get('tags', [])]

    def get_status(self) -> Dict:
        """Get device manager status"""
        return {
            "total_devices": len(self.devices),
            "online_devices": len([d for d in self.devices.values() if d['status'] == 'online']),
            "offline_devices": len([d for d in self.devices.values() if d['status'] == 'offline']),
            "device_types": list(set(d['device_type'] for d in self.devices.values())),
            "last_updated": datetime.utcnow().isoformat() + "Z"
        }

    def search_devices(self, query: str) -> List[Dict]:
        """Search devices by name or IP"""
        results = []
        query_lower = query.lower()
        for device in self.devices.values():
            if (query_lower in device['name'].lower() or 
                query_lower in device['ip_address']):
                results.append(device)
        return results

    def bulk_add_devices(self, devices_list: List[Dict]) -> Dict:
        """Add multiple devices at once"""
        try:
            added = []
            failed = []
            
            for device_info in devices_list:
                result = self.add_device(device_info)
                if result['success']:
                    added.append(result['device'])
                else:
                    failed.append({"device": device_info, "error": result['error']})
            
            return {
                "success": True,
                "added": len(added),
                "failed": len(failed),
                "devices": added,
                "failures": failed
            }
        except Exception as e:
            logger.error(f"Error bulk adding devices: {e}")
            return {"success": False, "error": str(e)}

