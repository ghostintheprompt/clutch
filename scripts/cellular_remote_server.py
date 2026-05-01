#!/usr/bin/env python3
"""
Cellular Remote Monitoring Server
Coordinates threat intelligence across multiple iOS devices
"""

import asyncio
import websockets
import json
import logging
import sqlite3
import os
from datetime import datetime, timedelta
from collections import defaultdict
from typing import Dict, List, Set, Optional

try:
    from opsec_encryption import TelemetryEncryptor
    OPSEC_AVAILABLE = True
except ImportError:
    OPSEC_AVAILABLE = False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('RemoteMonitorServer')

class RemoteCellularThreat:
    def __init__(self, data: Dict):
        self.threat_id = data.get('threat_id', '')
        self.device_id = data.get('device_id', '')
        self.threat_type = data.get('threat_type', '')
        self.severity = data.get('severity', 'low')
        self.description = data.get('description', '')
        self.timestamp = datetime.fromisoformat(data.get('timestamp', datetime.now().isoformat()))
        self.location = data.get('location')
        self.cellular_data = data.get('cellular_data')

class CellularRemoteMonitoringServer:
    def __init__(self, config_path: str = "cellular_remote_config.json"):
        self.config = self._load_config(config_path)
        self.connected_devices: Dict[str, websockets.WebSocketServerProtocol] = {}
        self.device_info: Dict[str, Dict] = {}
        self.active_threats: List[RemoteCellularThreat] = []
        self.db_path = self.config.get('database', 'cellular_remote_monitoring.db')
        self.api_keys = set(self.config.get('api_keys', []))
        
        # Threat correlation
        self.threat_window = timedelta(seconds=self.config.get('threat_correlation_window', 300))
        self.location_threshold_meters = self.config.get('location_correlation_meters', 1000)
        
        # Load rules
        self.monitoring_rules = self._load_rules()
        self._setup_database()
        
        # OPSEC Encryption Setup
        self.encryptor = None
        if OPSEC_AVAILABLE:
            master_key = self.config.get("opsec_master_key")
            self.encryptor = TelemetryEncryptor(base64_key=master_key)
            if self.encryptor.enabled and master_key is None:
                 import base64
                 logger.info(f"NEW OPSEC KEY (Add to iOS config): {base64.b64encode(self.encryptor.key).decode()}")

    def _load_config(self, path: str) -> Dict:
        if os.path.exists(path):
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.error(f"Error loading config: {e}")
        
        # Default config
        import secrets
        default_key = secrets.token_hex(16)
        default_config = {
            "host": "0.0.0.0",
            "port": 8766,
            "ssl": False,
            "database": "cellular_remote_monitoring.db",
            "api_keys": [default_key],
            "threat_correlation_window": 300,
            "location_correlation_meters": 1000,
            "coordinated_attack_threshold": 3,
            "opsec_master_key": None
        }
        
        try:
            with open(path, 'w') as f:
                json.dump(default_config, f, indent=4)
            logger.info(f"Created default config. API Key: {default_key}")
        except Exception as e:
            logger.error(f"Could not save default config: {e}")
            
        return default_config

    def _load_rules(self) -> Dict:
        return {
            "high_priority_threats": [
                "IMSI_CATCHER_SUSPECTED",
                "TECHNOLOGY_DOWNGRADE",
                "CELLULAR_JAMMING"
            ],
            "threat_correlation": True,
            "alert_thresholds": {
                "high": 1,
                "medium": 3,
                "low": 5
            }
        }

    def _setup_database(self):
        """Initialize SQLite database for persistent threat storage."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Threats table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threats (
                id TEXT PRIMARY KEY,
                device_id TEXT,
                threat_type TEXT,
                severity TEXT,
                description TEXT,
                timestamp DATETIME,
                latitude REAL,
                longitude REAL,
                cellular_data TEXT
            )
        ''')
        
        # Devices table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS devices (
                id TEXT PRIMARY KEY,
                name TEXT,
                type TEXT,
                first_seen DATETIME,
                last_seen DATETIME
            )
        ''')
        
        # Monitoring events
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitoring_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT,
                device_id TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                event_data TEXT
            )
        ''')
        
        conn.commit()
        conn.close()

    async def start_server(self):
        """Start the WebSocket server."""
        host = self.config.get('host', '0.0.0.0')
        port = self.config.get('port', 8766)
        
        # SSL Context would be added here for production
        ssl_context = None
        
        logger.info(f"Starting Remote Monitoring Server on ws://{host}:{port}")
        
        try:
            async with websockets.serve(
                self.handle_client,
                host,
                port,
                ssl=ssl_context,
                ping_interval=20,
                ping_timeout=20
            ):
                await asyncio.Future()  # run forever
        except Exception as e:
            logger.error(f"Server error: {e}")

    async def handle_client(self, websocket: websockets.WebSocketServerProtocol, path: str):
        """Handle individual WebSocket client connections."""
        device_id = None
        
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    
                    # Decrypt OPSEC payload if necessary
                    if self.encryptor and data.get("opsec_encrypted"):
                        decrypted = self.encryptor.decrypt_payload(data)
                        if "error" in decrypted:
                            logger.error(f"Decryption failed for message: {message[:50]}...")
                            await websocket.send(json.dumps({"type": "error", "message": "Decryption failed"}))
                            continue
                        data = decrypted

                    msg_type = data.get('type')
                    
                    if msg_type == 'register_device':
                        device_id = await self._handle_registration(websocket, data)
                    
                    elif not device_id:
                        await websocket.send(json.dumps({
                            "type": "error",
                            "message": "Device not registered"
                        }))
                        continue
                        
                    elif msg_type == 'cellular_threat':
                        await self._handle_threat(device_id, data)
                        
                    elif msg_type == 'heartbeat':
                        self._update_device_seen(device_id)
                        
                    elif msg_type == 'status_update':
                        await self._handle_status(device_id, data)
                        
                    else:
                        logger.warning(f"Unknown message type from {device_id}: {msg_type}")
                        
                except json.JSONDecodeError:
                    logger.error("Received invalid JSON")
                except Exception as e:
                    logger.error(f"Error handling message: {e}")
                    
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Connection closed for device {device_id}")
        finally:
            if device_id in self.connected_devices:
                del self.connected_devices[device_id]
                self._log_event('device_disconnected', device_id, {})

    async def _handle_registration(self, websocket: websockets.WebSocketServerProtocol, data: Dict) -> Optional[str]:
        """Handle device registration and authentication."""
        api_key = data.get('api_key')
        device_id = data.get('device_id')
        device_name = data.get('device_name', 'Unknown Device')
        
        if not api_key or api_key not in self.api_keys:
            logger.warning(f"Invalid API key attempt from device {device_name}")
            await websocket.send(json.dumps({
                "type": "error",
                "message": "Invalid API key"
            }))
            return None
            
        if not device_id:
            logger.warning("Registration missing device_id")
            return None
            
        self.connected_devices[device_id] = websocket
        self.device_info[device_id] = {
            "name": device_name,
            "type": data.get('device_type', 'Unknown'),
            "version": data.get('app_version', '1.0'),
            "connected_at": datetime.now()
        }
        
        self._update_device_record(device_id, device_name, data.get('device_type', 'Unknown'))
        self._log_event('device_connected', device_id, self.device_info[device_id])
        
        logger.info(f"Device registered: {device_name} ({device_id})")
        
        # Send registration success
        await websocket.send(json.dumps({
            "type": "registration_success",
            "server_version": "1.0",
            "monitoring_active": True
        }))
        
        return device_id

    async def _handle_threat(self, device_id: str, data: Dict):
        """Process incoming threat data from a device."""
        threat = RemoteCellularThreat(data)
        
        # Add to active threats
        self.active_threats.append(threat)
        
        # Clean up old threats
        cutoff_time = datetime.now() - self.threat_window
        self.active_threats = [t for t in self.active_threats if t.timestamp > cutoff_time]
        
        # Store in database
        self._store_threat(threat)
        
        logger.warning(f"🚨 THREAT from {device_id}: {threat.threat_type} ({threat.severity})")
        
        # Process threat based on rules
        await self.process_threat_alert(threat)
        
        # Acknowledge receipt
        websocket = self.connected_devices.get(device_id)
        if websocket:
            await websocket.send(json.dumps({
                "type": "threat_acknowledged",
                "threat_id": threat.threat_id
            }))

    async def _handle_status(self, device_id: str, data: Dict):
        """Process periodic status updates from devices."""
        self._update_device_seen(device_id)
        
        # Store status metrics if needed
        metrics = data.get('metrics', {})
        if metrics:
            self._log_event('status_update', device_id, metrics)

    def _update_device_record(self, device_id: str, name: str, device_type: str):
        """Update device record in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        now = datetime.now().isoformat()
        
        cursor.execute('''
            INSERT INTO devices (id, name, type, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
            name=excluded.name,
            last_seen=excluded.last_seen
        ''', (device_id, name, device_type, now, now))
        
        conn.commit()
        conn.close()

    def _update_device_seen(self, device_id: str):
        """Update last seen timestamp for a device."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE devices SET last_seen = ? WHERE id = ?
        ''', (datetime.now().isoformat(), device_id))
        
        conn.commit()
        conn.close()

    def _store_threat(self, threat: RemoteCellularThreat):
        """Store threat in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        lat = threat.location.get('latitude') if threat.location else None
        lon = threat.location.get('longitude') if threat.location else None
        cell_data_str = json.dumps(threat.cellular_data) if threat.cellular_data else None
        
        cursor.execute('''
            INSERT OR REPLACE INTO threats 
            (id, device_id, threat_type, severity, description, timestamp, latitude, longitude, cellular_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat.threat_id, threat.device_id, threat.threat_type, 
            threat.severity, threat.description, threat.timestamp.isoformat(),
            lat, lon, cell_data_str
        ))
        
        conn.commit()
        conn.close()

    def _log_event(self, event_type: str, device_id: str, event_data: Dict):
        """Log a monitoring event to the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO monitoring_events (event_type, device_id, event_data)
            VALUES (?, ?, ?)
        ''', (event_type, device_id, json.dumps(event_data)))
        
        conn.commit()
        conn.close()

    async def process_threat_alert(self, threat: RemoteCellularThreat):
        """Process threat alerts based on severity and rules."""
        
        # Check if it's a high priority threat
        if threat.threat_type in self.monitoring_rules.get('high_priority_threats', []):
            await self._broadcast_high_priority_alert(threat)
            
        # Correlate threats if enabled
        if self.monitoring_rules.get('threat_correlation', True):
            await self._correlate_threats(threat)

    async def _broadcast_high_priority_alert(self, threat: RemoteCellularThreat):
        """Broadcast high priority threats to all connected devices."""
        alert_msg = {
            "type": "high_priority_alert",
            "threat": {
                "type": threat.threat_type,
                "severity": threat.severity,
                "description": threat.description,
                "timestamp": threat.timestamp.isoformat()
            }
        }
        
        if self.encryptor and self.encryptor.enabled:
            alert_msg = self.encryptor.encrypt_payload(alert_msg)
            
        message = json.dumps(alert_msg)
        
        # Send to all devices EXCEPT the one that reported it
        for device_id, websocket in self.connected_devices.items():
            if device_id != threat.device_id:
                try:
                    await websocket.send(message)
                except Exception as e:
                    logger.error(f"Failed to broadcast to {device_id}: {e}")

    async def _correlate_threats(self, new_threat: RemoteCellularThreat):
        """Correlate threats to detect coordinated attacks."""
        if not new_threat.location:
            return
            
        recent_threats = []
        for t in self.active_threats:
            if t.threat_id != new_threat.threat_id and t.location:
                # Check if threats are of the same type and from different devices
                if t.threat_type == new_threat.threat_type and t.device_id != new_threat.device_id:
                    # In a real implementation, we would calculate actual distance
                    # For this prototype, we'll just check if they have locations
                    recent_threats.append(t)
                    
        threshold = self.config.get('coordinated_attack_threshold', 3)
        if len(recent_threats) >= threshold - 1: # -1 because we include the new threat
            logger.critical(f"🚨 COORDINATED ATTACK DETECTED: {new_threat.threat_type} across {len(recent_threats) + 1} devices")
            
            alert_msg = {
                "type": "coordinated_attack_detected",
                "attack_type": new_threat.threat_type,
                "device_count": len(recent_threats) + 1,
                "timestamp": datetime.now().isoformat()
            }
            
            if self.encryptor and self.encryptor.enabled:
                alert_msg = self.encryptor.encrypt_payload(alert_msg)
                
            message = json.dumps(alert_msg)
            
            # Broadcast to all devices
            for websocket in self.connected_devices.values():
                try:
                    await websocket.send(message)
                except Exception:
                    pass

    def export_threat_data(self):
        """Export all threat data to JSON for analysis."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM threats ORDER BY timestamp DESC')
        rows = cursor.fetchall()
        
        threats = [dict(row) for row in rows]
        
        conn.close()
        
        filename = f"threat_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(threats, f, indent=4)
            
        logger.info(f"Exported {len(threats)} threats to {filename}")
        return filename

if __name__ == "__main__":
    server = CellularRemoteMonitoringServer()
    
    try:
        asyncio.run(server.start_server())
    except KeyboardInterrupt:
        logger.info("Server stopped by user")
