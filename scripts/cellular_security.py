#!/usr/bin/env python3
"""
Cellular Security Monitor - IMSI Catcher Detection and Signal Anomaly Analysis
Advanced cellular network security monitoring for detecting IMSI catchers and other threats.
"""

import json
import time
import math
import statistics
import os
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import subprocess
import platform
import re

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    print("Warning: numpy not available. Some advanced analysis features disabled.")

try:
    from geopy.distance import geodesic
    GEOPY_AVAILABLE = True
except ImportError:
    GEOPY_AVAILABLE = False
    print("Warning: geopy not available. Location-based analysis limited.")

try:
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.cluster import DBSCAN
    from sklearn.metrics import silhouette_score
    import joblib
    import pandas as pd
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    print("Warning: scikit-learn not available. Machine learning features disabled.")


@dataclass
class CellularTower:
    """Represents a cellular tower/base station."""
    cell_id: str
    lac: str  # Location Area Code
    mcc: str  # Mobile Country Code
    mnc: str  # Mobile Network Code
    technology: str  # 4G, 5G, 3G
    frequency: Optional[float] = None
    location: Optional[Tuple[float, float]] = None  # (lat, lon)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    signal_strength_history: List[int] = None
    
    def __post_init__(self):
        if self.signal_strength_history is None:
            self.signal_strength_history = []
        if self.first_seen is None:
            self.first_seen = datetime.now()
        self.last_seen = datetime.now()


@dataclass
class CellularMeasurement:
    """Individual cellular measurement."""
    timestamp: datetime
    tower: CellularTower
    signal_strength: int  # dBm
    signal_quality: Optional[int] = None
    technology: str = "Unknown"
    encryption_status: str = "Unknown"
    serving_tower: bool = True
    neighbor_towers: List[CellularTower] = None
    location: Optional[Tuple[float, float]] = None
    device_movement_speed: Optional[float] = None  # km/h
    
    def __post_init__(self):
        if self.neighbor_towers is None:
            self.neighbor_towers = []


@dataclass
class SecurityThreat:
    """Represents a detected security threat."""
    threat_id: str
    threat_type: str
    severity: str  # low, medium, high, critical
    timestamp: datetime
    description: str
    evidence: Dict
    confidence: float  # 0.0 to 1.0
    location: Optional[Tuple[float, float]] = None
    affected_towers: List[str] = None
    mitigation_advice: str = ""
    
    def __post_init__(self):
        if self.affected_towers is None:
            self.affected_towers = []


class CellularSecurityMonitor:
    """Advanced cellular security monitoring and IMSI catcher detection."""
    
    def __init__(self, config_file: str = "cellular_security_config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        
        # Data storage
        self.tower_database: Dict[str, CellularTower] = {}
        self.measurement_history: deque = deque(maxlen=self.config.get('max_measurements', 10000))
        self.security_threats: List[SecurityThreat] = []
        self.baseline_established = False
        self.baseline_period = timedelta(minutes=self.config.get('baseline_period_minutes', 30))
        
        # Analysis state
        self.last_location: Optional[Tuple[float, float]] = None
        self.movement_history: deque = deque(maxlen=100)
        self.signal_anomaly_threshold = self.config.get('signal_anomaly_threshold', 15)  # dBm
        self.tower_change_threshold = self.config.get('tower_change_threshold', 5)  # changes per hour
        
        # IMSI Catcher detection parameters
        self.signal_jump_threshold = self.config.get('signal_jump_threshold', 20)  # dBm
        self.timing_advance_threshold = self.config.get('timing_advance_threshold', 5)
        self.encryption_downgrade_alert = self.config.get('encryption_downgrade_alert', True)
        
        # Machine Learning Components
        self.ml_models = {}
        self.feature_scaler = StandardScaler() if ML_AVAILABLE else None
        self.training_features = []
        self.model_trained = False
        self.feature_history = deque(maxlen=1000)
        
        # Initialize ML models if available
        if ML_AVAILABLE:
            self._initialize_ml_models()
    
    def load_config(self) -> Dict:
        """Load configuration from file or create default."""
        default_config = {
            "monitor_interval": 10,  # seconds
            "baseline_period_minutes": 30,
            "max_measurements": 10000,
            "signal_anomaly_threshold": 15,  # dBm
            "tower_change_threshold": 5,  # changes per hour
            "location_accuracy_threshold": 100,  # meters
            "suspicious_signal_patterns": {
                "sudden_signal_increase": 20,  # dBm
                "rapid_tower_changes": 10,  # changes in 10 minutes
                "encryption_downgrades": True,
                "timing_advance_anomalies": True
            },
            "imsi_catcher_detection": {
                "enabled": True,
                "signal_strength_threshold": 25,
                "location_mismatch_threshold": 500,  # meters
                "encryption_monitoring": True,
                "lac_monitoring": True,
                "technology_downgrade_detection": True
            },
            "notifications": {
                "enabled": True,
                "threat_levels": ["medium", "high", "critical"]
            }
        }
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
                # Merge with defaults
                for key, value in default_config.items():
                    if key not in config:
                        config[key] = value
                return config
        except FileNotFoundError:
            self.save_config(default_config)
            return default_config
    
    def save_config(self, config: Dict = None):
        """Save configuration to file."""
        if config is None:
            config = self.config
        try:
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=2)
        except Exception as e:
            print(f"Error saving config: {e}")
    
    def get_cellular_info(self) -> Optional[CellularMeasurement]:
        """Get current cellular information from the device."""
        # This would interface with actual cellular hardware/APIs
        # For now, we'll simulate data gathering
        try:
            if platform.system() == "Darwin":  # macOS
                return self._get_macos_cellular_info()
            elif platform.system() == "Linux":
                return self._get_linux_cellular_info()
            else:
                print("Cellular monitoring not implemented for this platform")
                return None
        except Exception as e:
            print(f"Error getting cellular info: {e}")
            return None
    
    def _get_macos_cellular_info(self) -> Optional[CellularMeasurement]:
        """Get cellular info on macOS using system_profiler and network tools."""
        try:
            # Get cellular modem info from system_profiler
            result = subprocess.run([
                'system_profiler', 'SPWWANDataType', '-json'
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                wwan_data = data.get('SPWWANDataType', [])
                
                if wwan_data:
                    modem_info = wwan_data[0]
                    
                    # Try to get signal strength from Airport utility if available
                    signal_strength = self._get_signal_strength_macos()
                    
                    # Extract cellular tower information
                    tower = CellularTower(
                        cell_id=modem_info.get('cell_id', f"CELL_{int(time.time())}"),
                        lac=modem_info.get('location_area_code', f"LAC_{int(time.time())}"),
                        mcc=modem_info.get('mobile_country_code', "310"),
                        mnc=modem_info.get('mobile_network_code', "260"),
                        technology=modem_info.get('current_radio_technology', "Unknown"),
                        frequency=modem_info.get('frequency', 0)
                    )
                    
                    measurement = CellularMeasurement(
                        timestamp=datetime.now(),
                        tower=tower,
                        signal_strength=signal_strength or -80,
                        technology=tower.technology,
                        encryption_status=self._detect_encryption_macos(modem_info)
                    )
                    
                    return measurement
                    
        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as e:
            print(f"Warning: Could not get real cellular data on macOS: {e}")
            
        # If we can't get real data, try alternative methods
        return self._get_cellular_fallback_macos()
    
    def _get_linux_cellular_info(self) -> Optional[CellularMeasurement]:
        """Get cellular info on Linux using ModemManager and other tools."""
        try:
            # Method 1: Use ModemManager (mmcli)
            measurement = self._get_modemmanager_data()
            if measurement:
                return measurement
                
            # Method 2: Try AT commands directly
            measurement = self._get_at_command_data()
            if measurement:
                return measurement
                
            # Method 3: Check /proc/net/route for cellular interfaces
            measurement = self._get_cellular_interface_data()
            if measurement:
                return measurement
                
        except Exception as e:
            print(f"Error getting Linux cellular data: {e}")
            
        return None
    
    def _get_modemmanager_data(self) -> Optional[CellularMeasurement]:
        """Get cellular data using ModemManager."""
        try:
            # List modems
            result = subprocess.run(['mmcli', '-L'], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return None
                
            modem_lines = [line for line in result.stdout.split('\n') if '/org/freedesktop/ModemManager1/Modem/' in line]
            if not modem_lines:
                return None
                
            # Get first modem ID
            modem_id = modem_lines[0].split('/')[-1].split()[0]
            
            # Get modem details
            result = subprocess.run(['mmcli', '-m', modem_id], capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                return None
                
            modem_info = self._parse_mmcli_output(result.stdout)
            
            # Get signal quality
            result = subprocess.run(['mmcli', '-m', modem_id, '--signal-get'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                signal_info = self._parse_signal_output(result.stdout)
                modem_info.update(signal_info)
            
            # Get location/cell info
            result = subprocess.run(['mmcli', '-m', modem_id, '--location-get'], capture_output=True, text=True, timeout=10)
            if result.returncode == 0:
                location_info = self._parse_location_output(result.stdout)
                modem_info.update(location_info)
                
            return self._create_measurement_from_mmcli(modem_info)
            
        except Exception as e:
            print(f"ModemManager error: {e}")
            return None
    
    def _get_at_command_data(self) -> Optional[CellularMeasurement]:
        """Get cellular data using AT commands."""
        try:
            # Common modem device paths
            modem_devices = ['/dev/ttyUSB0', '/dev/ttyUSB1', '/dev/ttyUSB2', '/dev/ttyACM0']
            
            for device in modem_devices:
                if os.path.exists(device):
                    try:
                        # Use screen or minicom to send AT commands
                        # AT+CSQ for signal quality
                        result = subprocess.run([
                            'timeout', '5', 'bash', '-c', 
                            f'echo "AT+CSQ" > {device} && sleep 1 && cat {device}'
                        ], capture_output=True, text=True)
                        
                        if 'CSQ:' in result.stdout:
                            signal_data = self._parse_csq_response(result.stdout)
                            if signal_data:
                                return signal_data
                                
                    except Exception:
                        continue
                        
        except Exception as e:
            print(f"AT command error: {e}")
            
        return None
    
    def _get_cellular_interface_data(self) -> Optional[CellularMeasurement]:
        """Get cellular data from network interfaces."""
        try:
            # Check for cellular network interfaces
            result = subprocess.run(['ip', 'route'], capture_output=True, text=True, timeout=5)
            if result.returncode == 0:
                for line in result.stdout.split('\n'):
                    # Look for cellular interfaces (wwan0, ppp0, etc.)
                    if any(iface in line for iface in ['wwan', 'ppp', 'usb']):
                        # Found cellular interface
                        tower = CellularTower(
                            cell_id=f"CELL_LINUX_{int(time.time())}",
                            lac=f"LAC_LINUX_{int(time.time())}",
                            mcc="310",
                            mnc="260",
                            technology="Cellular",
                            frequency=0
                        )
                        
                        return CellularMeasurement(
                            timestamp=datetime.now(),
                            tower=tower,
                            signal_strength=-80,  # Default estimate
                            technology="Cellular",
                            encryption_status="Unknown"
                        )
                        
        except Exception as e:
            print(f"Interface detection error: {e}")
            
        return None
    
    def _simulate_cellular_measurement(self) -> CellularMeasurement:
        """Simulate cellular measurement for testing."""
        import random
        
        # Create a simulated tower
        tower = CellularTower(
            cell_id=f"CELL_{random.randint(1000, 9999)}",
            lac=f"LAC_{random.randint(100, 999)}",
            mcc="310",  # US MCC
            mnc="260",  # T-Mobile MNC
            technology=random.choice(["4G", "5G", "3G"]),
            frequency=random.uniform(1800.0, 2600.0)
        )
        
        measurement = CellularMeasurement(
            timestamp=datetime.now(),
            tower=tower,
            signal_strength=random.randint(-120, -50),  # Typical range in dBm
            signal_quality=random.randint(0, 31),
            technology=tower.technology,
            encryption_status=random.choice(["A5/1", "A5/3", "None", "Unknown"]),
            location=(37.7749 + random.uniform(-0.1, 0.1), -122.4194 + random.uniform(-0.1, 0.1))
        )
        
        return measurement
    
    def _parse_mmcli_output(self, output: str) -> Dict:
        """Parse mmcli modem output for cellular information."""
        info = {}
        for line in output.split('\n'):
            line = line.strip()
            if '|' in line:
                parts = line.split('|', 2)
                if len(parts) >= 3:
                    key = parts[1].strip()
                    value = parts[2].strip()
                    
                    if 'access tech' in key.lower():
                        info['technology'] = value
                    elif 'operator name' in key.lower():
                        info['operator'] = value
                    elif 'state' in key.lower():
                        info['state'] = value
                        
        return info
    
    def _parse_signal_output(self, output: str) -> Dict:
        """Parse mmcli signal output."""
        info = {}
        for line in output.split('\n'):
            line = line.strip()
            if '|' in line:
                parts = line.split('|', 2)
                if len(parts) >= 3:
                    key = parts[1].strip().lower()
                    value = parts[2].strip()
                    
                    try:
                        if 'rssi' in key:
                            info['signal_strength'] = int(float(value.split()[0]))
                        elif 'rsrp' in key:
                            info['rsrp'] = float(value.split()[0])
                        elif 'rsrq' in key:
                            info['rsrq'] = float(value.split()[0])
                        elif 'snr' in key or 'sinr' in key:
                            info['sinr'] = float(value.split()[0])
                    except (ValueError, IndexError):
                        pass
                        
        return info
    
    def _parse_location_output(self, output: str) -> Dict:
        """Parse mmcli location output."""
        info = {}
        for line in output.split('\n'):
            line = line.strip()
            if '|' in line:
                parts = line.split('|', 2)
                if len(parts) >= 3:
                    key = parts[1].strip().lower()
                    value = parts[2].strip()
                    
                    if 'cell id' in key:
                        info['cell_id'] = value
                    elif 'location area code' in key or 'lac' in key:
                        info['lac'] = value
                    elif 'mobile country code' in key or 'mcc' in key:
                        info['mcc'] = value
                    elif 'mobile network code' in key or 'mnc' in key:
                        info['mnc'] = value
                        
        return info
    
    def _create_measurement_from_mmcli(self, info: Dict) -> CellularMeasurement:
        """Create a CellularMeasurement from parsed mmcli data."""
        tower = CellularTower(
            cell_id=info.get('cell_id', f"CELL_MM_{int(time.time())}"),
            lac=info.get('lac', f"LAC_MM_{int(time.time())}"),
            mcc=info.get('mcc', "310"),
            mnc=info.get('mnc', "260"),
            technology=info.get('technology', "Unknown"),
            frequency=0  # Would need additional parsing
        )
        
        # Determine encryption based on technology
        tech = info.get('technology', '').upper()
        if '5G' in tech or 'NR' in tech:
            encryption = "A5/3"
        elif '4G' in tech or 'LTE' in tech:
            encryption = "A5/3"
        elif '3G' in tech or 'UMTS' in tech:
            encryption = "A5/1"
        else:
            encryption = "Unknown"
        
        return CellularMeasurement(
            timestamp=datetime.now(),
            tower=tower,
            signal_strength=info.get('signal_strength', -85),
            technology=tower.technology,
            encryption_status=encryption
        )
    
    def _parse_csq_response(self, output: str) -> Optional[CellularMeasurement]:
        """Parse AT+CSQ response for signal quality."""
        try:
            for line in output.split('\n'):
                if '+CSQ:' in line:
                    # Format: +CSQ: <rssi>,<ber>
                    parts = line.split(':')[1].strip().split(',')
                    if len(parts) >= 1:
                        rssi_raw = int(parts[0])
                        # Convert CSQ RSSI to dBm: dBm = -113 + (2 * rssi)
                        signal_strength = -113 + (2 * rssi_raw) if rssi_raw != 99 else -113
                        
                        tower = CellularTower(
                            cell_id=f"CELL_AT_{int(time.time())}",
                            lac=f"LAC_AT_{int(time.time())}",
                            mcc="310",
                            mnc="260",
                            technology="GSM",
                            frequency=0
                        )
                        
                        return CellularMeasurement(
                            timestamp=datetime.now(),
                            tower=tower,
                            signal_strength=signal_strength,
                            technology="GSM",
                            encryption_status="A5/1"
                        )
                        
        except (ValueError, IndexError) as e:
            print(f"Error parsing CSQ response: {e}")
            
        return None
    
    def analyze_measurement(self, measurement: CellularMeasurement) -> List[SecurityThreat]:
        """Analyze a cellular measurement for security threats."""
        threats = []
        
        # Update tower database
        tower_key = f"{measurement.tower.cell_id}_{measurement.tower.lac}"
        if tower_key not in self.tower_database:
            self.tower_database[tower_key] = measurement.tower
        else:
            # Update existing tower info
            existing_tower = self.tower_database[tower_key]
            existing_tower.last_seen = measurement.timestamp
            existing_tower.signal_strength_history.append(measurement.signal_strength)
        
        # Add to measurement history
        self.measurement_history.append(measurement)
        
        # Perform threat analysis
        threats.extend(self._detect_imsi_catcher(measurement))
        threats.extend(self._detect_signal_anomalies(measurement))
        threats.extend(self._detect_location_anomalies(measurement))
        threats.extend(self._detect_encryption_anomalies(measurement))
        threats.extend(self._detect_tower_behavior_anomalies(measurement))
        
        # Perform machine learning-based advanced analysis
        if ML_AVAILABLE:
            threats.extend(self._ml_anomaly_detection(measurement))
            threats.extend(self._advanced_pattern_analysis(measurement))
        
        # Add threats to database
        for threat in threats:
            self.security_threats.append(threat)
            self._handle_threat_notification(threat)
        
        return threats
    
    def _initialize_ml_models(self):
        """Initialize machine learning models for threat detection."""
        if not ML_AVAILABLE:
            return
            
        try:
            # Anomaly Detection Model - for signal pattern anomalies
            self.ml_models['anomaly_detector'] = IsolationForest(
                contamination=0.1,  # Expect 10% anomalies
                random_state=42,
                n_estimators=100
            )
            
            # Clustering Model - for tower behavior analysis
            self.ml_models['tower_clusterer'] = DBSCAN(
                eps=0.5,
                min_samples=5
            )
            
            # Try to load pre-trained models
            self._load_trained_models()
            
        except Exception as e:
            print(f"Warning: Could not initialize ML models: {e}")
            self.ml_models = {}
    
    def _load_trained_models(self):
        """Load pre-trained ML models if they exist."""
        try:
            self.ml_models['anomaly_detector'] = joblib.load('cellular_anomaly_model.pkl')
            self.feature_scaler = joblib.load('cellular_feature_scaler.pkl')
            self.model_trained = True
            print("Loaded pre-trained ML models successfully")
        except FileNotFoundError:
            print("No pre-trained models found. Will train with new data.")
        except Exception as e:
            print(f"Error loading models: {e}")
    
    def _save_trained_models(self):
        """Save trained ML models for future use."""
        if not ML_AVAILABLE or not self.model_trained:
            return
            
        try:
            joblib.dump(self.ml_models['anomaly_detector'], 'cellular_anomaly_model.pkl')
            joblib.dump(self.feature_scaler, 'cellular_feature_scaler.pkl')
            print("ML models saved successfully")
        except Exception as e:
            print(f"Error saving models: {e}")
    
    def _extract_ml_features(self, measurement: CellularMeasurement) -> Optional[List[float]]:
        """Extract features for machine learning analysis."""
        if not ML_AVAILABLE or len(self.measurement_history) < 5:
            return None
            
        try:
            features = []
            
            # Basic signal features
            features.append(measurement.signal_strength)
            features.append(measurement.signal_quality or 0)
            
            # Historical signal analysis
            recent_signals = [m.signal_strength for m in list(self.measurement_history)[-10:]]
            if len(recent_signals) >= 2:
                features.append(np.mean(recent_signals))
                features.append(np.std(recent_signals))
                features.append(np.max(recent_signals) - np.min(recent_signals))  # Signal range
                features.append(measurement.signal_strength - recent_signals[-1])  # Signal delta
            else:
                features.extend([0, 0, 0, 0])
            
            # Tower behavior features
            tower_changes_1h = self._count_tower_changes(hours=1)
            tower_changes_24h = self._count_tower_changes(hours=24)
            features.append(tower_changes_1h)
            features.append(tower_changes_24h)
            
            # Timing and technology features
            features.append(measurement.timing_advance or 0)
            tech_score = self._technology_to_score(measurement.technology)
            features.append(tech_score)
            
            # Encryption features
            enc_score = self._encryption_to_score(measurement.encryption_status)
            features.append(enc_score)
            
            # Location-based features (if available)
            if measurement.location and GEOPY_AVAILABLE:
                if self.last_location:
                    distance = geodesic(self.last_location, measurement.location).kilometers
                    features.append(distance)
                    
                    # Calculate speed if we have timing
                    if len(self.measurement_history) > 0:
                        time_diff = (measurement.timestamp - self.measurement_history[-1].timestamp).total_seconds() / 3600
                        speed = distance / time_diff if time_diff > 0 else 0
                        features.append(min(speed, 500))  # Cap at 500 km/h
                    else:
                        features.append(0)
                else:
                    features.extend([0, 0])
            else:
                features.extend([0, 0])
            
            return features
            
        except Exception as e:
            print(f"Error extracting ML features: {e}")
            return None
    
    def _technology_to_score(self, tech: str) -> float:
        """Convert technology to numerical score for ML."""
        tech_scores = {"5G": 5.0, "4G": 4.0, "LTE": 4.0, "3G": 3.0, "2G": 2.0, "GSM": 1.0}
        return tech_scores.get(tech, 0.0)
    
    def _encryption_to_score(self, encryption: str) -> float:
        """Convert encryption to numerical score for ML."""
        enc_scores = {"A5/3": 3.0, "A5/1": 1.0, "A5/0": 0.0, "None": 0.0}
        return enc_scores.get(encryption, 0.0)
    
    def _count_tower_changes(self, hours: int) -> int:
        """Count tower changes in the last N hours."""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        tower_changes = 0
        previous_tower = None
        
        for measurement in self.measurement_history:
            if measurement.timestamp < cutoff_time:
                continue
            current_tower = f"{measurement.tower.cell_id}_{measurement.tower.lac}"
            if previous_tower and previous_tower != current_tower:
                tower_changes += 1
            previous_tower = current_tower
            
        return tower_changes
    
    def _ml_anomaly_detection(self, measurement: CellularMeasurement) -> List[SecurityThreat]:
        """Use machine learning for advanced anomaly detection."""
        threats = []
        
        if not ML_AVAILABLE or not self.ml_models:
            return threats
            
        try:
            # Extract features for current measurement
            features = self._extract_ml_features(measurement)
            if not features:
                return threats
                
            # Add to feature history
            self.feature_history.append(features)
            
            # Train model if we have enough data and model not trained
            if len(self.feature_history) >= 50 and not self.model_trained:
                self._train_anomaly_model()
            
            # Predict anomalies if model is trained
            if self.model_trained and self.feature_scaler:
                # Scale features
                features_scaled = self.feature_scaler.transform([features])
                
                # Predict anomaly
                anomaly_score = self.ml_models['anomaly_detector'].decision_function(features_scaled)[0]
                is_anomaly = self.ml_models['anomaly_detector'].predict(features_scaled)[0] == -1
                
                if is_anomaly:
                    # Determine threat type based on feature analysis
                    threat_type = self._classify_anomaly_type(features, anomaly_score)
                    
                    threat = SecurityThreat(
                        threat_id=f"ML_ANOMALY_{int(time.time())}",
                        threat_type=threat_type,
                        severity="medium" if anomaly_score > -0.3 else "high",
                        timestamp=measurement.timestamp,
                        description=f"ML-detected anomaly (score: {anomaly_score:.3f})",
                        evidence={
                            "anomaly_score": anomaly_score,
                            "features": features,
                            "model_confidence": abs(anomaly_score)
                        },
                        confidence=min(abs(anomaly_score), 1.0),
                        location=measurement.location,
                        mitigation_advice="Investigate cellular environment for potential threats."
                    )
                    threats.append(threat)
                    
        except Exception as e:
            print(f"ML anomaly detection error: {e}")
            
        return threats
    
    def _train_anomaly_model(self):
        """Train the anomaly detection model with accumulated data."""
        if not ML_AVAILABLE or len(self.feature_history) < 50:
            return
            
        try:
            # Prepare training data
            X = np.array(list(self.feature_history))
            
            # Remove any rows with NaN or infinite values
            mask = np.isfinite(X).all(axis=1)
            X = X[mask]
            
            if len(X) < 20:
                return
                
            # Fit scaler
            self.feature_scaler.fit(X)
            X_scaled = self.feature_scaler.transform(X)
            
            # Train anomaly detector
            self.ml_models['anomaly_detector'].fit(X_scaled)
            
            self.model_trained = True
            print(f"ML anomaly model trained with {len(X)} samples")
            
            # Save the trained model
            self._save_trained_models()
            
        except Exception as e:
            print(f"Error training ML model: {e}")
    
    def _classify_anomaly_type(self, features: List[float], anomaly_score: float) -> str:
        """Classify the type of anomaly based on feature analysis."""
        # Feature indices based on _extract_ml_features
        signal_strength = features[0]
        signal_std = features[3] if len(features) > 3 else 0
        signal_delta = features[6] if len(features) > 6 else 0
        tower_changes_1h = features[7] if len(features) > 7 else 0
        timing_advance = features[9] if len(features) > 9 else 0
        
        # Classify based on dominant anomalous features
        if abs(signal_delta) > 25:
            return "ML_SIGNAL_MANIPULATION"
        elif tower_changes_1h > 6:
            return "ML_FREQUENT_HANDOVERS"
        elif timing_advance == 0 and signal_strength > -60:
            return "ML_CLOSE_RANGE_THREAT"
        elif signal_std > 20:
            return "ML_SIGNAL_INSTABILITY"
        else:
            return "ML_GENERAL_ANOMALY"
    
    def _advanced_pattern_analysis(self, measurement: CellularMeasurement) -> List[SecurityThreat]:
        """Advanced pattern analysis using multiple ML techniques."""
        threats = []
        
        if not ML_AVAILABLE or len(self.measurement_history) < 20:
            return threats
            
        try:
            # Extract features for pattern analysis
            pattern_features = self._extract_pattern_features()
            if not pattern_features or len(pattern_features) < 10:
                return threats
                
            # Cluster analysis for tower behavior patterns
            clusters = self.ml_models['tower_clusterer'].fit_predict(pattern_features)
            
            # Analyze cluster results
            unique_clusters = set(clusters)
            if len(unique_clusters) > 1 and -1 in clusters:  # -1 indicates outliers
                outlier_count = list(clusters).count(-1)
                outlier_ratio = outlier_count / len(clusters)
                
                if outlier_ratio > 0.2:  # More than 20% outliers
                    threat = SecurityThreat(
                        threat_id=f"ML_PATTERN_{int(time.time())}",
                        threat_type="ML_BEHAVIORAL_ANOMALY",
                        severity="medium",
                        timestamp=measurement.timestamp,
                        description=f"Unusual tower behavior pattern detected ({outlier_ratio:.1%} outliers)",
                        evidence={
                            "outlier_ratio": outlier_ratio,
                            "cluster_count": len(unique_clusters),
                            "total_measurements": len(clusters)
                        },
                        confidence=outlier_ratio,
                        location=measurement.location,
                        mitigation_advice="Monitor for coordinated network manipulation."
                    )
                    threats.append(threat)
                    
        except Exception as e:
            print(f"Advanced pattern analysis error: {e}")
            
        return threats
    
    def _extract_pattern_features(self) -> Optional[np.ndarray]:
        """Extract features for pattern analysis."""
        if not ML_AVAILABLE or len(self.measurement_history) < 10:
            return None
            
        try:
            features = []
            measurements = list(self.measurement_history)[-50:]  # Last 50 measurements
            
            for i, measurement in enumerate(measurements):
                feature_row = []
                
                # Signal characteristics
                feature_row.append(measurement.signal_strength)
                feature_row.append(measurement.signal_quality or 0)
                feature_row.append(measurement.timing_advance or 0)
                
                # Technology and encryption
                feature_row.append(self._technology_to_score(measurement.technology))
                feature_row.append(self._encryption_to_score(measurement.encryption_status))
                
                # Temporal features
                if i > 0:
                    time_diff = (measurement.timestamp - measurements[i-1].timestamp).total_seconds()
                    signal_diff = measurement.signal_strength - measurements[i-1].signal_strength
                    feature_row.append(time_diff)
                    feature_row.append(signal_diff)
                else:
                    feature_row.extend([0, 0])
                    
                features.append(feature_row)
                
            return np.array(features) if features else None
            
        except Exception as e:
            print(f"Error extracting pattern features: {e}")
            return None

    def _detect_imsi_catcher(self, measurement: CellularMeasurement) -> List[SecurityThreat]:
        """Detect potential IMSI catcher attacks."""
        threats = []
        
        if not self.config.get('imsi_catcher_detection', {}).get('enabled', True):
            return threats
        
        # Check for sudden signal strength increase (fake tower nearby)
        if len(self.measurement_history) > 1:
            prev_measurement = self.measurement_history[-2]
            signal_jump = measurement.signal_strength - prev_measurement.signal_strength
            
            if signal_jump > self.signal_jump_threshold:
                threat = SecurityThreat(
                    threat_id=f"IMSI_SIGNAL_{int(time.time())}",
                    threat_type="IMSI_CATCHER_SUSPECTED",
                    severity="high",
                    timestamp=measurement.timestamp,
                    description=f"Sudden signal strength increase of {signal_jump} dBm detected",
                    evidence={
                        "signal_jump": signal_jump,
                        "previous_strength": prev_measurement.signal_strength,
                        "current_strength": measurement.signal_strength,
                        "tower_id": measurement.tower.cell_id
                    },
                    confidence=0.7,
                    location=measurement.location,
                    affected_towers=[measurement.tower.cell_id],
                    mitigation_advice="Monitor for additional IMSI catcher indicators. Consider disabling automatic cell selection."
                )
                threats.append(threat)
        
        # Check for encryption downgrade
        if measurement.encryption_status in ["None", "A5/0"]:
            threat = SecurityThreat(
                threat_id=f"IMSI_ENCRYPT_{int(time.time())}",
                threat_type="ENCRYPTION_DOWNGRADE",
                severity="high",
                timestamp=measurement.timestamp,
                description="Encryption downgrade or disabled encryption detected",
                evidence={
                    "encryption_status": measurement.encryption_status,
                    "tower_id": measurement.tower.cell_id
                },
                confidence=0.8,
                location=measurement.location,
                affected_towers=[measurement.tower.cell_id],
                mitigation_advice="Avoid sensitive communications. Move to a different location and monitor."
            )
            threats.append(threat)
        
        # Check for forced 2G/3G downgrade
        if measurement.technology in ["2G", "GSM"] and len(self.measurement_history) > 1:
            recent_techs = [m.technology for m in list(self.measurement_history)[-5:]]
            if any(tech in ["4G", "LTE", "5G"] for tech in recent_techs):
                threat = SecurityThreat(
                    threat_id=f"IMSI_DOWNGRADE_{int(time.time())}",
                    threat_type="FORCED_TECHNOLOGY_DOWNGRADE",
                    severity="medium",
                    timestamp=measurement.timestamp,
                    description=f"Forced downgrade to {measurement.technology} detected",
                    evidence={
                        "current_technology": measurement.technology,
                        "recent_technologies": recent_techs,
                        "tower_id": measurement.tower.cell_id
                    },
                    confidence=0.6,
                    location=measurement.location,
                    affected_towers=[measurement.tower.cell_id],
                    mitigation_advice="Verify if legitimate coverage issue or potential IMSI catcher."
                )
                threats.append(threat)
        
        return threats
    
    def _detect_signal_anomalies(self, measurement: CellularMeasurement) -> List[SecurityThreat]:
        """Detect unusual signal patterns."""
        threats = []
        
        if len(self.measurement_history) < 10:
            return threats  # Need more data for analysis
        
        # Analyze signal strength patterns
        recent_signals = [m.signal_strength for m in list(self.measurement_history)[-10:]]
        
        if NUMPY_AVAILABLE:
            signal_std = np.std(recent_signals)
            signal_mean = np.mean(recent_signals)
        else:
            signal_std = statistics.stdev(recent_signals) if len(recent_signals) > 1 else 0
            signal_mean = statistics.mean(recent_signals)
        
        # Check for unusual signal variation
        if signal_std > self.signal_anomaly_threshold:
            threat = SecurityThreat(
                threat_id=f"SIGNAL_ANOMALY_{int(time.time())}",
                threat_type="SIGNAL_STRENGTH_ANOMALY",
                severity="medium",
                timestamp=measurement.timestamp,
                description=f"Unusual signal strength variation detected (std: {signal_std:.1f} dBm)",
                evidence={
                    "signal_std": signal_std,
                    "signal_mean": signal_mean,
                    "recent_signals": recent_signals,
                    "threshold": self.signal_anomaly_threshold
                },
                confidence=0.5,
                location=measurement.location,
                mitigation_advice="Monitor for consistent patterns that might indicate interference or jamming."
            )
            threats.append(threat)
        
        return threats
    
    def _detect_location_anomalies(self, measurement: CellularMeasurement) -> List[SecurityThreat]:
        """Detect location-based anomalies."""
        threats = []
        
        if not GEOPY_AVAILABLE or not measurement.location:
            return threats
        
        # Check for impossible movement speeds
        if self.last_location and len(self.measurement_history) > 1:
            prev_time = self.measurement_history[-2].timestamp
            time_diff = (measurement.timestamp - prev_time).total_seconds() / 3600  # hours
            
            if time_diff > 0:
                distance = geodesic(self.last_location, measurement.location).kilometers
                speed = distance / time_diff  # km/h
                
                # Flag impossibly high speeds (likely spoofed location)
                if speed > 500:  # Faster than commercial aircraft
                    threat = SecurityThreat(
                        threat_id=f"LOCATION_ANOMALY_{int(time.time())}",
                        threat_type="IMPOSSIBLE_MOVEMENT_SPEED",
                        severity="high",
                        timestamp=measurement.timestamp,
                        description=f"Impossible movement speed detected: {speed:.1f} km/h",
                        evidence={
                            "calculated_speed": speed,
                            "distance": distance,
                            "time_diff": time_diff,
                            "previous_location": self.last_location,
                            "current_location": measurement.location
                        },
                        confidence=0.9,
                        location=measurement.location,
                        mitigation_advice="Possible location spoofing or measurement error. Verify device location."
                    )
                    threats.append(threat)
        
        self.last_location = measurement.location
        return threats
    
    def _detect_encryption_anomalies(self, measurement: CellularMeasurement) -> List[SecurityThreat]:
        """Detect encryption-related anomalies."""
        threats = []
        
        # Track encryption status changes
        if len(self.measurement_history) > 1:
            prev_encryption = self.measurement_history[-2].encryption_status
            current_encryption = measurement.encryption_status
            
            # Check for encryption downgrades
            encryption_strength = {
                "A5/3": 3, "A5/1": 2, "A5/0": 1, "None": 0, "Unknown": -1
            }
            
            prev_strength = encryption_strength.get(prev_encryption, -1)
            current_strength = encryption_strength.get(current_encryption, -1)
            
            if prev_strength > current_strength and current_strength >= 0:
                threat = SecurityThreat(
                    threat_id=f"ENCRYPTION_DOWNGRADE_{int(time.time())}",
                    threat_type="ENCRYPTION_DOWNGRADE",
                    severity="medium",
                    timestamp=measurement.timestamp,
                    description=f"Encryption downgraded from {prev_encryption} to {current_encryption}",
                    evidence={
                        "previous_encryption": prev_encryption,
                        "current_encryption": current_encryption,
                        "tower_id": measurement.tower.cell_id
                    },
                    confidence=0.7,
                    location=measurement.location,
                    affected_towers=[measurement.tower.cell_id],
                    mitigation_advice="Potential IMSI catcher or network issue. Monitor for other indicators."
                )
                threats.append(threat)
        
        return threats
    
    def _detect_tower_behavior_anomalies(self, measurement: CellularMeasurement) -> List[SecurityThreat]:
        """Detect anomalous cellular tower behavior."""
        threats = []
        
        # Count tower changes in recent period
        if len(self.measurement_history) >= 10:
            recent_towers = [m.tower.cell_id for m in list(self.measurement_history)[-10:]]
            unique_towers = len(set(recent_towers))
            
            if unique_towers > self.tower_change_threshold:
                threat = SecurityThreat(
                    threat_id=f"TOWER_CHANGES_{int(time.time())}",
                    threat_type="EXCESSIVE_TOWER_CHANGES",
                    severity="medium",
                    timestamp=measurement.timestamp,
                    description=f"Excessive tower changes detected: {unique_towers} towers in recent measurements",
                    evidence={
                        "tower_count": unique_towers,
                        "recent_towers": recent_towers,
                        "threshold": self.tower_change_threshold
                    },
                    confidence=0.6,
                    location=measurement.location,
                    mitigation_advice="Possible interference or forced handovers. Monitor for IMSI catcher activity."
                )
                threats.append(threat)
        
        return threats
    
    def _handle_threat_notification(self, threat: SecurityThreat):
        """Handle threat notifications."""
        if not self.config.get('notifications', {}).get('enabled', True):
            return
        
        threat_levels = self.config.get('notifications', {}).get('threat_levels', ['medium', 'high', 'critical'])
        
        if threat.severity in threat_levels:
            print(f"\n🚨 CELLULAR SECURITY THREAT DETECTED 🚨")
            print(f"Type: {threat.threat_type}")
            print(f"Severity: {threat.severity.upper()}")
            print(f"Description: {threat.description}")
            print(f"Confidence: {threat.confidence:.2f}")
            print(f"Time: {threat.timestamp}")
            if threat.location:
                print(f"Location: {threat.location[0]:.6f}, {threat.location[1]:.6f}")
            print(f"Mitigation: {threat.mitigation_advice}")
            print("-" * 60)
    
    def start_monitoring(self):
        """Start continuous cellular security monitoring."""
        print("🛡️ Starting Cellular Security Monitor...")
        print(f"Monitoring interval: {self.config['monitor_interval']} seconds")
        print("Press Ctrl+C to stop monitoring\n")
        
        try:
            while True:
                measurement = self.get_cellular_info()
                if measurement:
                    threats = self.analyze_measurement(measurement)
                    
                    # Show basic status
                    tower_count = len(self.tower_database)
                    measurement_count = len(self.measurement_history)
                    threat_count = len([t for t in self.security_threats if 
                                     (datetime.now() - t.timestamp).total_seconds() < 3600])  # Last hour
                    
                    status = f"📊 Towers: {tower_count} | Measurements: {measurement_count} | Threats (1h): {threat_count}"
                    print(f"\r{status}", end="", flush=True)
                
                time.sleep(self.config['monitor_interval'])
                
        except KeyboardInterrupt:
            print("\n\n🛑 Cellular Security Monitor stopped")
            self.generate_report()
    
    def generate_report(self):
        """Generate a security report."""
        print("\n" + "="*60)
        print("🛡️ CELLULAR SECURITY REPORT")
        print("="*60)
        
        # Summary statistics
        total_measurements = len(self.measurement_history)
        total_towers = len(self.tower_database)
        total_threats = len(self.security_threats)
        
        print(f"Total Measurements: {total_measurements}")
        print(f"Unique Towers Observed: {total_towers}")
        print(f"Security Threats Detected: {total_threats}")
        
        if self.security_threats:
            print("\n🚨 DETECTED THREATS:")
            threat_counts = defaultdict(int)
            for threat in self.security_threats:
                threat_counts[threat.threat_type] += 1
            
            for threat_type, count in threat_counts.items():
                print(f"  - {threat_type}: {count}")
            
            # Show recent high-severity threats
            recent_high_threats = [
                t for t in self.security_threats 
                if t.severity in ['high', 'critical'] and 
                (datetime.now() - t.timestamp).total_seconds() < 3600
            ]
            
            if recent_high_threats:
                print(f"\n⚠️ RECENT HIGH-SEVERITY THREATS ({len(recent_high_threats)}):")
                for threat in recent_high_threats[-5:]:  # Show last 5
                    print(f"  [{threat.timestamp.strftime('%H:%M:%S')}] {threat.threat_type}")
                    print(f"    {threat.description}")
        
        # Tower analysis
        if self.tower_database:
            print(f"\n📡 TOWER ANALYSIS:")
            tech_counts = defaultdict(int)
            for tower in self.tower_database.values():
                tech_counts[tower.technology] += 1
            
            for tech, count in tech_counts.items():
                print(f"  - {tech}: {count} towers")
        
        print("="*60)
    
    def export_data(self, filename: str = None):
        """Export collected data to JSON file."""
        if filename is None:
            filename = f"cellular_security_data_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        
        export_data = {
            'metadata': {
                'export_time': datetime.now().isoformat(),
                'total_measurements': len(self.measurement_history),
                'total_towers': len(self.tower_database),
                'total_threats': len(self.security_threats)
            },
            'towers': {k: asdict(v) for k, v in self.tower_database.items()},
            'threats': [asdict(threat) for threat in self.security_threats],
            'config': self.config
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(export_data, f, indent=2, default=str)
            print(f"Data exported to {filename}")
        except Exception as e:
            print(f"Error exporting data: {e}")
    
    def _get_signal_strength_macos(self) -> Optional[int]:
        """Get cellular signal strength on macOS using various methods."""
        try:
            # Method 1: Try to use networksetup
            result = subprocess.run([
                'networksetup', '-getinfo', 'iPhone USB'
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Parse signal strength from output
                for line in result.stdout.split('\n'):
                    if 'signal' in line.lower() or 'rssi' in line.lower():
                        # Extract numerical value
                        import re
                        match = re.search(r'-?\d+', line)
                        if match:
                            return int(match.group())
            
            # Method 2: Check if iPhone is connected via USB and get info
            result = subprocess.run([
                'system_profiler', 'SPUSBDataType', '-json'
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                # Look for iPhone in USB devices
                usb_data = data.get('SPUSBDataType', [])
                for bus in usb_data:
                    for device in bus.get('_items', []):
                        if 'iPhone' in device.get('_name', ''):
                            # If iPhone is connected, signal strength is likely good
                            return -60  # Assume decent signal if USB connected
                            
        except Exception as e:
            print(f"Could not get signal strength: {e}")
            
        return None
    
    def _detect_encryption_macos(self, modem_info: Dict) -> str:
        """Detect encryption status from modem information."""
        # Check for encryption indicators in modem info
        current_tech = modem_info.get('current_radio_technology', '').upper()
        
        if '5G' in current_tech or 'NR' in current_tech:
            return "A5/3"  # 5G uses strong encryption
        elif '4G' in current_tech or 'LTE' in current_tech:
            return "A5/3"  # LTE typically uses A5/3
        elif '3G' in current_tech or 'UMTS' in current_tech:
            return "A5/1"  # 3G often uses A5/1
        elif '2G' in current_tech or 'GSM' in current_tech:
            return "A5/1"  # 2G uses A5/1 or worse
        else:
            return "Unknown"
    
    def _get_cellular_fallback_macos(self) -> Optional[CellularMeasurement]:
        """Fallback method to get cellular info on macOS."""
        try:
            # Method: Check network interfaces for cellular
            result = subprocess.run([
                'ifconfig'
            ], capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Look for cellular interfaces (pdp_ip0, etc.)
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines):
                    if 'pdp_ip' in line or 'cellular' in line.lower():
                        # Found cellular interface
                        tower = CellularTower(
                            cell_id=f"CELL_REAL_{int(time.time())}",
                            lac=f"LAC_REAL_{int(time.time())}",
                            mcc="310",  # US
                            mnc="260",  # Default carrier
                            technology="Cellular",
                            frequency=0
                        )
                        
                        return CellularMeasurement(
                            timestamp=datetime.now(),
                            tower=tower,
                            signal_strength=-75,  # Estimated
                            technology="Cellular",
                            encryption_status="Unknown"
                        )
                        
        except Exception as e:
            print(f"Fallback cellular detection failed: {e}")
            
        # Last resort: return None to indicate no cellular available
        return None
        

def main():
    """Main function for cellular security monitoring."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Cellular Security Monitor - IMSI Catcher Detection")
    parser.add_argument('--config', default='cellular_security_config.json', help='Config file path')
    parser.add_argument('--interval', type=int, help='Monitoring interval in seconds')
    parser.add_argument('--report', action='store_true', help='Generate report and exit')
    parser.add_argument('--export', type=str, help='Export data to file')
    parser.add_argument('--simulate', action='store_true', help='Use simulated data for testing')
    
    args = parser.parse_args()
    
    # Create monitor instance
    monitor = CellularSecurityMonitor(config_file=args.config)
    
    # Override config with command line arguments
    if args.interval:
        monitor.config['monitor_interval'] = args.interval
    
    # Handle report command
    if args.report:
        monitor.generate_report()
        return
    
    # Handle export command
    if args.export:
        monitor.export_data(args.export)
        return
    
    # Save any config changes
    monitor.save_config()
    
    # Start monitoring
    try:
        monitor.start_monitoring()
    except KeyboardInterrupt:
        print("\nExiting...")


if __name__ == "__main__":
    main()
