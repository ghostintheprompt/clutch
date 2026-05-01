#!/usr/bin/env python3
"""
Enhanced Cellular Security Remote Monitoring Server
Receives real-time cellular threat data from iOS devices and provides remote monitoring capabilities.
"""

import asyncio
import websockets
import json
import time
import ssl
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from dataclasses import dataclass, asdict
import logging
import uuid
from pathlib import Path
import sqlite3
import threading
import hashlib
import hmac
import base64

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('cellular_remote_monitoring.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class RemoteCellularThreat:
    """Remote cellular threat data from iOS device."""
    device_id: str
    threat_id: str
    threat_type: str
    severity: str
    timestamp: datetime
    location: Optional[Dict] = None
    cellular_data: Optional[Dict] = None
    description: str = ""
    confidence: float = 0.0
    
    def to_dict(self):
        data = asdict(self)
        data['timestamp'] = self.timestamp.isoformat()
        return data

class CellularRemoteMonitoringServer:
    """Remote monitoring server for cellular security threats."""
    
    def __init__(self, host='0.0.0.0', port=8766, use_ssl=False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.connected_devices: Dict[str, Dict] = {}
        self.threat_history: List[RemoteCellularThreat] = []
        self.monitoring_rules: Dict[str, Dict] = {}
        
        # Initialize database
        self.init_database()
        
        # Load configuration
        self.load_config()
        
        # Authentication
        self.api_keys: Set[str] = set()
        self.load_api_keys()
        
    def init_database(self):
        """Initialize SQLite database for persistent storage."""
        self.db_path = "cellular_remote_monitoring.db"
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cellular_threats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                threat_id TEXT UNIQUE NOT NULL,
                threat_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                location_lat REAL,
                location_lon REAL,
                cellular_data TEXT,
                description TEXT,
                confidence REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS device_sessions (
                device_id TEXT PRIMARY KEY,
                device_name TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                connection_count INTEGER DEFAULT 0,
                threat_count INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS monitoring_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                device_id TEXT,
                event_data TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    
    def load_config(self):
        """Load monitoring configuration."""
        try:
            with open('cellular_remote_config.json', 'r') as f:
                config = json.load(f)
                self.monitoring_rules = config.get('monitoring_rules', {})
                self.notification_settings = config.get('notifications', {})
        except FileNotFoundError:
            # Create default config
            default_config = {
                "monitoring_rules": {
                    "high_severity_immediate": True,
                    "location_tracking": True,
                    "threat_correlation": True,
                    "auto_export": True
                },
                "notifications": {
                    "email_alerts": False,
                    "slack_webhook": "",
                    "telegram_bot_token": ""
                }
            }
            with open('cellular_remote_config.json', 'w') as f:
                json.dump(default_config, f, indent=2)
            self.monitoring_rules = default_config['monitoring_rules']
            self.notification_settings = default_config['notifications']
    
    def load_api_keys(self):
        """Load API keys for device authentication."""
        try:
            with open('cellular_api_keys.txt', 'r') as f:
                for line in f:
                    key = line.strip()
                    if key:
                        self.api_keys.add(key)
        except FileNotFoundError:
            # Generate default API key
            default_key = self.generate_api_key()
            with open('cellular_api_keys.txt', 'w') as f:
                f.write(f"{default_key}\n")
            self.api_keys.add(default_key)
            logger.info(f"Generated default API key: {default_key}")
    
    def generate_api_key(self) -> str:
        """Generate a new API key."""
        return base64.b64encode(uuid.uuid4().bytes).decode('utf-8').rstrip('=')
    
    def authenticate_device(self, api_key: str) -> bool:
        """Authenticate device using API key."""
        return api_key in self.api_keys
    
    async def register_device(self, websocket, device_data: Dict):
        """Register a new device connection."""
        device_id = device_data.get('device_id')
        device_name = device_data.get('device_name', 'Unknown Device')
        api_key = device_data.get('api_key')
        
        if not self.authenticate_device(api_key):
            await self.send_error(websocket, "Authentication failed")
            return False
        
        if not device_id:
            await self.send_error(websocket, "Device ID required")
            return False
        
        # Store device info
        self.connected_devices[device_id] = {
            'websocket': websocket,
            'device_name': device_name,
            'connected_at': datetime.now(),
            'last_seen': datetime.now(),
            'threat_count': 0
        }
        
        # Update database
        self.update_device_session(device_id, device_name)
        
        # Send confirmation
        await self.send_message(websocket, {
            'type': 'registration_success',
            'device_id': device_id,
            'server_time': datetime.now().isoformat(),
            'monitoring_status': 'active'
        })
        
        logger.info(f"Device registered: {device_name} ({device_id})")
        return True
    
    async def handle_cellular_threat(self, device_id: str, threat_data: Dict):
        """Process incoming cellular threat data."""
        try:
            # Parse threat data
            threat = RemoteCellularThreat(
                device_id=device_id,
                threat_id=threat_data.get('threat_id', str(uuid.uuid4())),
                threat_type=threat_data.get('threat_type', 'UNKNOWN'),
                severity=threat_data.get('severity', 'low'),
                timestamp=datetime.fromisoformat(threat_data.get('timestamp', datetime.now().isoformat())),
                location=threat_data.get('location'),
                cellular_data=threat_data.get('cellular_data'),
                description=threat_data.get('description', ''),
                confidence=threat_data.get('confidence', 0.0)
            )
            
            # Store threat
            self.store_threat(threat)
            self.threat_history.append(threat)
            
            # Update device stats
            if device_id in self.connected_devices:
                self.connected_devices[device_id]['threat_count'] += 1
                self.connected_devices[device_id]['last_seen'] = datetime.now()
            
            # Process threat based on severity
            await self.process_threat_alert(threat)
            
            # Send acknowledgment to device
            if device_id in self.connected_devices:
                await self.send_message(self.connected_devices[device_id]['websocket'], {
                    'type': 'threat_acknowledged',
                    'threat_id': threat.threat_id,
                    'processed_at': datetime.now().isoformat()
                })
            
            logger.info(f"Processed threat: {threat.threat_type} from {device_id} (severity: {threat.severity})")
            
        except Exception as e:
            logger.error(f"Error processing threat from {device_id}: {e}")
    
    def store_threat(self, threat: RemoteCellularThreat):
        """Store threat in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        location_lat = None
        location_lon = None
        if threat.location:
            location_lat = threat.location.get('latitude')
            location_lon = threat.location.get('longitude')
        
        cursor.execute('''
            INSERT OR REPLACE INTO cellular_threats 
            (device_id, threat_id, threat_type, severity, timestamp, 
             location_lat, location_lon, cellular_data, description, confidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            threat.device_id,
            threat.threat_id,
            threat.threat_type,
            threat.severity,
            threat.timestamp.isoformat(),
            location_lat,
            location_lon,
            json.dumps(threat.cellular_data) if threat.cellular_data else None,
            threat.description,
            threat.confidence
        ))
        
        conn.commit()
        conn.close()
    
    def update_device_session(self, device_id: str, device_name: str):
        """Update device session in database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO device_sessions 
            (device_id, device_name, last_seen, connection_count, threat_count)
            VALUES (?, ?, CURRENT_TIMESTAMP, 
                   COALESCE((SELECT connection_count FROM device_sessions WHERE device_id = ?) + 1, 1),
                   COALESCE((SELECT threat_count FROM device_sessions WHERE device_id = ?), 0))
        ''', (device_id, device_name, device_id, device_id))
        
        conn.commit()
        conn.close()
    
    async def process_threat_alert(self, threat: RemoteCellularThreat):
        """Process threat alerts based on severity and rules."""
        # High severity threats get immediate attention
        if threat.severity.lower() in ['high', 'critical']:
            await self.send_high_priority_alert(threat)
        
        # Check for threat patterns
        if self.monitoring_rules.get('threat_correlation', True):
            await self.analyze_threat_patterns(threat)
        
        # Export data if auto-export enabled
        if self.monitoring_rules.get('auto_export', False):
            self.export_threat_data()
    
    async def send_high_priority_alert(self, threat: RemoteCellularThreat):
        """Send high priority alert notifications."""
        alert_message = {
            'type': 'high_priority_alert',
            'threat': threat.to_dict(),
            'alert_level': 'URGENT',
            'message': f"🚨 HIGH PRIORITY: {threat.threat_type} detected on {threat.device_id}",
            'timestamp': datetime.now().isoformat()
        }
        
        # Send to all connected monitoring devices
        for device_id, device_info in self.connected_devices.items():
            try:
                await self.send_message(device_info['websocket'], alert_message)
            except:
                pass  # Device might be disconnected
        
        # Log high priority event
        self.log_monitoring_event('high_priority_alert', threat.device_id, threat.to_dict())
        
        logger.warning(f"🚨 HIGH PRIORITY ALERT: {threat.threat_type} from {threat.device_id}")
    
    async def analyze_threat_patterns(self, threat: RemoteCellularThreat):
        """Analyze threat patterns for coordinated attacks."""
        # Look for similar threats in recent history
        recent_threats = [
            t for t in self.threat_history 
            if (datetime.now() - t.timestamp) < timedelta(hours=1)
            and t.device_id != threat.device_id
        ]
        
        # Check for coordinated IMSI catcher attacks
        imsi_threats = [t for t in recent_threats if 'IMSI' in t.threat_type.upper()]
        
        if len(imsi_threats) >= 2:  # Multiple devices detecting IMSI catchers
            coordination_alert = {
                'type': 'coordinated_attack_detected',
                'primary_threat': threat.to_dict(),
                'related_threats': [t.to_dict() for t in imsi_threats],
                'attack_pattern': 'COORDINATED_IMSI_CATCHER',
                'device_count': len(set(t.device_id for t in imsi_threats)) + 1,
                'message': f"🚨 COORDINATED ATTACK: IMSI catchers detected on {len(imsi_threats) + 1} devices",
                'timestamp': datetime.now().isoformat()
            }
            
            # Send coordinated attack alert
            for device_id, device_info in self.connected_devices.items():
                try:
                    await self.send_message(device_info['websocket'], coordination_alert)
                except:
                    pass
            
            logger.critical(f"🚨 COORDINATED ATTACK DETECTED: IMSI catchers on {len(imsi_threats) + 1} devices")
    
    def log_monitoring_event(self, event_type: str, device_id: str, event_data: Dict):
        """Log monitoring events to database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO monitoring_events (event_type, device_id, event_data)
            VALUES (?, ?, ?)
        ''', (event_type, device_id, json.dumps(event_data)))
        
        conn.commit()
        conn.close()
    
    def export_threat_data(self):
        """Export threat data to JSON file."""
        export_data = {
            'export_timestamp': datetime.now().isoformat(),
            'total_threats': len(self.threat_history),
            'connected_devices': len(self.connected_devices),
            'threats': [threat.to_dict() for threat in self.threat_history[-100:]]  # Last 100 threats
        }
        
        filename = f"cellular_threats_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(filename, 'w') as f:
            json.dump(export_data, f, indent=2)
        
        logger.info(f"Threat data exported to {filename}")
    
    async def send_message(self, websocket, message: Dict):
        """Send message to websocket client."""
        try:
            await websocket.send(json.dumps(message))
        except Exception as e:
            logger.error(f"Error sending message: {e}")
    
    async def send_error(self, websocket, error_message: str):
        """Send error message to client."""
        await self.send_message(websocket, {
            'type': 'error',
            'message': error_message,
            'timestamp': datetime.now().isoformat()
        })
    
    async def handle_client_message(self, websocket, path):
        """Handle incoming client messages."""
        device_id = None
        try:
            async for message in websocket:
                try:
                    data = json.loads(message)
                    message_type = data.get('type')
                    
                    if message_type == 'register_device':
                        success = await self.register_device(websocket, data)
                        if success:
                            device_id = data.get('device_id')
                    
                    elif message_type == 'cellular_threat':
                        if device_id:
                            await self.handle_cellular_threat(device_id, data)
                        else:
                            await self.send_error(websocket, "Device not registered")
                    
                    elif message_type == 'heartbeat':
                        if device_id and device_id in self.connected_devices:
                            self.connected_devices[device_id]['last_seen'] = datetime.now()
                            await self.send_message(websocket, {
                                'type': 'heartbeat_ack',
                                'timestamp': datetime.now().isoformat()
                            })
                    
                    elif message_type == 'get_status':
                        await self.send_message(websocket, {
                            'type': 'status_response',
                            'connected_devices': len(self.connected_devices),
                            'total_threats_today': len([
                                t for t in self.threat_history 
                                if (datetime.now() - t.timestamp) < timedelta(days=1)
                            ]),
                            'server_uptime': datetime.now().isoformat(),
                            'monitoring_active': True
                        })
                    
                    else:
                        await self.send_error(websocket, f"Unknown message type: {message_type}")
                
                except json.JSONDecodeError:
                    await self.send_error(websocket, "Invalid JSON message")
                except Exception as e:
                    logger.error(f"Error processing message: {e}")
                    await self.send_error(websocket, "Error processing message")
        
        except websockets.exceptions.ConnectionClosed:
            logger.info(f"Device disconnected: {device_id}")
        except Exception as e:
            logger.error(f"Connection error: {e}")
        finally:
            # Clean up device connection
            if device_id and device_id in self.connected_devices:
                del self.connected_devices[device_id]
                logger.info(f"Cleaned up connection for device: {device_id}")
    
    def get_statistics(self) -> Dict:
        """Get monitoring statistics."""
        now = datetime.now()
        
        # Threats by time period
        threats_1h = len([t for t in self.threat_history if (now - t.timestamp) < timedelta(hours=1)])
        threats_24h = len([t for t in self.threat_history if (now - t.timestamp) < timedelta(days=1)])
        threats_7d = len([t for t in self.threat_history if (now - t.timestamp) < timedelta(days=7)])
        
        # Threat types
        threat_types = {}
        for threat in self.threat_history:
            threat_types[threat.threat_type] = threat_types.get(threat.threat_type, 0) + 1
        
        return {
            'connected_devices': len(self.connected_devices),
            'total_threats': len(self.threat_history),
            'threats_1h': threats_1h,
            'threats_24h': threats_24h,
            'threats_7d': threats_7d,
            'threat_types': threat_types,
            'uptime': datetime.now().isoformat()
        }
    
    async def start_server(self):
        """Start the remote monitoring server."""
        logger.info(f"Starting Cellular Remote Monitoring Server on {self.host}:{self.port}")
        
        # Setup SSL if enabled
        ssl_context = None
        if self.use_ssl:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain("cert.pem", "key.pem")  # You'll need to provide these
        
        # Start WebSocket server
        start_server = websockets.serve(
            self.handle_client_message,
            self.host,
            self.port,
            ssl=ssl_context
        )
        
        logger.info(f"🛡️ Cellular Remote Monitoring Server started on {'wss' if self.use_ssl else 'ws'}://{self.host}:{self.port}")
        logger.info(f"📊 Database: {self.db_path}")
        logger.info(f"🔑 API Keys loaded: {len(self.api_keys)}")
        
        return start_server

def main():
    """Main function to run the server."""
    import argparse
    
    parser = argparse.ArgumentParser(description='Cellular Security Remote Monitoring Server')
    parser.add_argument('--host', default='0.0.0.0', help='Server host (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8766, help='Server port (default: 8766)')
    parser.add_argument('--ssl', action='store_true', help='Enable SSL/TLS encryption')
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    
    args = parser.parse_args()
    
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create and start server
    server = CellularRemoteMonitoringServer(
        host=args.host,
        port=args.port,
        use_ssl=args.ssl
    )
    
    # Run server
    loop = asyncio.get_event_loop()
    start_server = loop.run_until_complete(server.start_server())
    
    try:
        loop.run_until_complete(start_server)
        loop.run_forever()
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
        # Export final data
        server.export_threat_data()
        logger.info("📊 Final threat data exported")
    except Exception as e:
        logger.error(f"Server error: {e}")
    finally:
        loop.close()
        logger.info("Server stopped")

if __name__ == '__main__':
    main()
