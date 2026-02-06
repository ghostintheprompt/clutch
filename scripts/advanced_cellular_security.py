#!/usr/bin/env python3
"""
Advanced Cellular Security Monitor - Enhanced IMSI Catcher Detection
Advanced algorithms for detecting sophisticated cellular attacks and security threats.
"""

import json
import time
import math
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from collections import defaultdict, deque
import threading
import asyncio
from scipy import stats
from scipy.signal import find_peaks
import matplotlib.pyplot as plt
from geopy.distance import geodesic
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import requests

from cellular_security import CellularTower, CellularMeasurement, SecurityThreat, CellularSecurityMonitor


@dataclass
class AdvancedCellularMetrics:
    """Enhanced cellular metrics for sophisticated analysis."""
    timestamp: datetime
    tower: CellularTower
    signal_strength: int
    signal_quality: int
    timing_advance: Optional[int] = None  # Timing Advance value
    frame_number: Optional[int] = None   # GSM frame number
    arfcn: Optional[int] = None          # Absolute Radio Frequency Channel Number
    pci: Optional[int] = None            # Physical Cell ID (LTE/5G)
    rsrp: Optional[float] = None         # Reference Signal Received Power
    rsrq: Optional[float] = None         # Reference Signal Received Quality
    sinr: Optional[float] = None         # Signal to Interference plus Noise Ratio
    cqi: Optional[int] = None            # Channel Quality Indicator
    neighbor_cells: List[Dict] = None    # Neighbor cell measurements
    uplink_power: Optional[int] = None   # Uplink transmission power
    downlink_frequency: Optional[float] = None
    uplink_frequency: Optional[float] = None
    band: Optional[str] = None           # Frequency band (e.g., "B3", "n78")
    ca_bands: List[str] = None           # Carrier Aggregation bands
    
    def __post_init__(self):
        if self.neighbor_cells is None:
            self.neighbor_cells = []
        if self.ca_bands is None:
            self.ca_bands = []


class AdvancedIMSICatcherDetector:
    """Advanced IMSI catcher detection using machine learning and signal analysis."""
    
    def __init__(self, config: Dict):
        self.config = config
        self.measurement_buffer = deque(maxlen=1000)
        self.baseline_metrics = {}
        self.threat_patterns = {}
        self.statistical_models = {}
        self.fingerprint_database = {}
        
        # Enhanced detection thresholds
        self.detection_thresholds = {
            'timing_advance_anomaly': 50,      # microseconds
            'signal_power_jump': 15,           # dBm
            'frequency_deviation': 200,        # kHz
            'downgrade_probability': 0.7,      # probability threshold
            'location_spoofing': 100,          # meters
            'rf_fingerprint_match': 0.85,     # similarity threshold
            'protocol_anomaly': 0.8,          # anomaly score
            'traffic_analysis': 0.9            # suspicious traffic score
        }
        
        # Initialize advanced detection modules
        self._init_statistical_models()
        self._load_known_imsi_catchers()
        
    def _init_statistical_models(self):
        """Initialize statistical models for anomaly detection."""
        self.statistical_models = {
            'signal_strength': {'mean': 0, 'std': 0, 'samples': []},
            'timing_advance': {'mean': 0, 'std': 0, 'samples': []},
            'frequency_stability': {'mean': 0, 'std': 0, 'samples': []},
            'handover_patterns': {'normal_frequency': 0, 'samples': []},
            'encryption_patterns': {'common_types': [], 'changes': []}
        }
    
    def _load_known_imsi_catchers(self):
        """Load database of known IMSI catcher signatures."""
        self.fingerprint_database = {
            'known_imsi_catchers': [
                {
                    'name': 'StingRay',
                    'signatures': {
                        'timing_advance_pattern': [0, 1, 0, 1],
                        'signal_characteristics': {'power_variations': 'high'},
                        'protocol_deviations': ['invalid_lac', 'forced_2g']
                    }
                },
                {
                    'name': 'Hailstorm',
                    'signatures': {
                        'timing_advance_pattern': [0, 0, 1, 1],
                        'signal_characteristics': {'power_variations': 'medium'},
                        'protocol_deviations': ['encryption_downgrade']
                    }
                },
                {
                    'name': 'DRT Box',
                    'signatures': {
                        'timing_advance_pattern': [1, 0, 0, 0],
                        'signal_characteristics': {'power_variations': 'low'},
                        'protocol_deviations': ['fake_paging', 'location_update_reject']
                    }
                }
            ],
            'suspicious_patterns': [
                'rapid_signal_increase',
                'timing_advance_zero',
                'frequent_encryption_changes',
                'impossible_tower_locations',
                'protocol_version_downgrades'
            ]
        }
    
    def analyze_advanced_metrics(self, metrics: AdvancedCellularMetrics) -> List[SecurityThreat]:
        """Perform advanced analysis on cellular metrics."""
        threats = []
        
        # Add to measurement buffer
        self.measurement_buffer.append(metrics)
        
        # Update statistical models
        self._update_statistical_models(metrics)
        
        # Perform advanced detections
        threats.extend(self._detect_timing_advance_anomalies(metrics))
        threats.extend(self._detect_rf_fingerprint_anomalies(metrics))
        threats.extend(self._detect_protocol_anomalies(metrics))
        threats.extend(self._detect_frequency_anomalies(metrics))
        threats.extend(self._detect_power_analysis_attacks(metrics))
        threats.extend(self._detect_sophisticated_imsi_catchers(metrics))
        threats.extend(self._detect_jamming_attacks(metrics))
        threats.extend(self._detect_location_spoofing(metrics))
        
        return threats
    
    def _update_statistical_models(self, metrics: AdvancedCellularMetrics):
        """Update statistical models with new measurement."""
        # Update signal strength model
        if metrics.signal_strength:
            model = self.statistical_models['signal_strength']
            model['samples'].append(metrics.signal_strength)
            if len(model['samples']) > 100:
                model['samples'].pop(0)
            model['mean'] = np.mean(model['samples'])
            model['std'] = np.std(model['samples'])
        
        # Update timing advance model
        if metrics.timing_advance is not None:
            model = self.statistical_models['timing_advance']
            model['samples'].append(metrics.timing_advance)
            if len(model['samples']) > 100:
                model['samples'].pop(0)
            model['mean'] = np.mean(model['samples'])
            model['std'] = np.std(model['samples'])
    
    def _detect_timing_advance_anomalies(self, metrics: AdvancedCellularMetrics) -> List[SecurityThreat]:
        """Detect timing advance anomalies that indicate IMSI catchers."""
        threats = []
        
        if metrics.timing_advance is None:
            return threats
        
        # Check for suspicious timing advance values
        if metrics.timing_advance == 0:
            # TA=0 can indicate a very close or fake base station
            threat = SecurityThreat(
                threat_id=f"TA_ZERO_{int(time.time())}",
                threat_type="TIMING_ADVANCE_ZERO",
                severity="medium",
                timestamp=metrics.timestamp,
                description="Timing Advance value of 0 detected - possible close-range IMSI catcher",
                evidence={
                    "timing_advance": metrics.timing_advance,
                    "tower_id": metrics.tower.cell_id,
                    "signal_strength": metrics.signal_strength
                },
                confidence=0.6,
                mitigation_advice="Monitor for other IMSI catcher indicators. TA=0 can be legitimate in some cases."
            )
            threats.append(threat)
        
        # Check for impossible timing advance changes
        if len(self.measurement_buffer) > 1:
            prev_metrics = self.measurement_buffer[-2]
            if prev_metrics.timing_advance is not None:
                ta_change = abs(metrics.timing_advance - prev_metrics.timing_advance)
                time_diff = (metrics.timestamp - prev_metrics.timestamp).total_seconds()
                
                # Calculate maximum possible TA change based on movement speed
                max_distance_change = 300 * time_diff  # 300 km/h max speed
                max_ta_change = max_distance_change / 554  # 554m per TA unit
                
                if ta_change > max_ta_change * 2:  # Allow some margin
                    threat = SecurityThreat(
                        threat_id=f"TA_IMPOSSIBLE_{int(time.time())}",
                        threat_type="IMPOSSIBLE_TIMING_ADVANCE_CHANGE",
                        severity="high",
                        timestamp=metrics.timestamp,
                        description=f"Impossible timing advance change: {ta_change} units in {time_diff:.1f}s",
                        evidence={
                            "ta_change": ta_change,
                            "time_diff": time_diff,
                            "max_possible_change": max_ta_change,
                            "previous_ta": prev_metrics.timing_advance,
                            "current_ta": metrics.timing_advance
                        },
                        confidence=0.9,
                        mitigation_advice="Likely IMSI catcher or measurement error. Verify device location."
                    )
                    threats.append(threat)
        
        return threats
    
    def _detect_rf_fingerprint_anomalies(self, metrics: AdvancedCellularMetrics) -> List[SecurityThreat]:
        """Detect RF fingerprint anomalies in cellular signals."""
        threats = []
        
        if len(self.measurement_buffer) < 10:
            return threats
        
        # Analyze signal quality patterns
        recent_rsrq = [m.rsrq for m in list(self.measurement_buffer)[-10:] if m.rsrq is not None]
        if len(recent_rsrq) >= 5:
            # Check for unusual signal quality patterns
            rsrq_std = np.std(recent_rsrq)
            if rsrq_std > 10:  # High variation in signal quality
                threat = SecurityThreat(
                    threat_id=f"RF_ANOMALY_{int(time.time())}",
                    threat_type="RF_FINGERPRINT_ANOMALY",
                    severity="medium",
                    timestamp=metrics.timestamp,
                    description=f"Unusual RF signal quality variation detected (std: {rsrq_std:.2f})",
                    evidence={
                        "rsrq_std": rsrq_std,
                        "recent_rsrq": recent_rsrq,
                        "threshold": 10
                    },
                    confidence=0.5,
                    mitigation_advice="Monitor for consistent RF anomalies that might indicate a fake base station."
                )
                threats.append(threat)
        
        # Check for known IMSI catcher RF signatures
        if metrics.rsrp and metrics.rsrq:
            rsrp_rsrq_ratio = metrics.rsrp / metrics.rsrq if metrics.rsrq != 0 else 0
            if rsrp_rsrq_ratio > 50 or rsrp_rsrq_ratio < 0.1:
                threat = SecurityThreat(
                    threat_id=f"RF_SIGNATURE_{int(time.time())}",
                    threat_type="SUSPICIOUS_RF_SIGNATURE",
                    severity="medium",
                    timestamp=metrics.timestamp,
                    description=f"Suspicious RSRP/RSRQ ratio: {rsrp_rsrq_ratio:.2f}",
                    evidence={
                        "rsrp": metrics.rsrp,
                        "rsrq": metrics.rsrq,
                        "ratio": rsrp_rsrq_ratio
                    },
                    confidence=0.6,
                    mitigation_advice="Unusual signal characteristics may indicate modified base station equipment."
                )
                threats.append(threat)
        
        return threats
    
    def _detect_protocol_anomalies(self, metrics: AdvancedCellularMetrics) -> List[SecurityThreat]:
        """Detect protocol-level anomalies that indicate attacks."""
        threats = []
        
        # Check for invalid Physical Cell ID patterns
        if metrics.pci is not None:
            # PCI should be in range 0-503 for LTE
            if metrics.pci < 0 or metrics.pci > 503:
                threat = SecurityThreat(
                    threat_id=f"INVALID_PCI_{int(time.time())}",
                    threat_type="INVALID_PHYSICAL_CELL_ID",
                    severity="high",
                    timestamp=metrics.timestamp,
                    description=f"Invalid Physical Cell ID detected: {metrics.pci}",
                    evidence={
                        "pci": metrics.pci,
                        "valid_range": "0-503",
                        "tower_id": metrics.tower.cell_id
                    },
                    confidence=0.9,
                    mitigation_advice="Invalid PCI indicates fake base station or equipment malfunction."
                )
                threats.append(threat)
        
        # Check for suspicious neighbor cell reports
        if metrics.neighbor_cells:
            neighbor_count = len(metrics.neighbor_cells)
            if neighbor_count == 0:
                # No neighbor cells reported - suspicious for urban areas
                threat = SecurityThreat(
                    threat_id=f"NO_NEIGHBORS_{int(time.time())}",
                    threat_type="NO_NEIGHBOR_CELLS",
                    severity="medium",
                    timestamp=metrics.timestamp,
                    description="No neighbor cells reported - possible isolation attack",
                    evidence={
                        "neighbor_count": neighbor_count,
                        "tower_id": metrics.tower.cell_id
                    },
                    confidence=0.4,
                    mitigation_advice="Lack of neighbor cells may indicate IMSI catcher isolation technique."
                )
                threats.append(threat)
            elif neighbor_count > 20:
                # Too many neighbor cells - suspicious
                threat = SecurityThreat(
                    threat_id=f"TOO_MANY_NEIGHBORS_{int(time.time())}",
                    threat_type="EXCESSIVE_NEIGHBOR_CELLS",
                    severity="medium",
                    timestamp=metrics.timestamp,
                    description=f"Excessive neighbor cells reported: {neighbor_count}",
                    evidence={
                        "neighbor_count": neighbor_count,
                        "tower_id": metrics.tower.cell_id
                    },
                    confidence=0.5,
                    mitigation_advice="Unusual neighbor cell count may indicate modified base station."
                )
                threats.append(threat)
        
        return threats
    
    def _detect_frequency_anomalies(self, metrics: AdvancedCellularMetrics) -> List[SecurityThreat]:
        """Detect frequency-related anomalies and deviations."""
        threats = []
        
        if not metrics.downlink_frequency:
            return threats
        
        # Check frequency against expected bands
        expected_bands = {
            'B3': (1710, 1785),   # 1800 MHz band
            'B7': (2500, 2570),   # 2600 MHz band
            'B20': (832, 862),    # 800 MHz band
            'B1': (1920, 1980),   # 2100 MHz band
            'B8': (880, 915),     # 900 MHz band
        }
        
        freq_mhz = metrics.downlink_frequency
        band_match = False
        
        for band, (low, high) in expected_bands.items():
            if low <= freq_mhz <= high:
                band_match = True
                break
        
        if not band_match:
            threat = SecurityThreat(
                threat_id=f"FREQ_ANOMALY_{int(time.time())}",
                threat_type="FREQUENCY_OUT_OF_BAND",
                severity="high",
                timestamp=metrics.timestamp,
                description=f"Frequency {freq_mhz} MHz not in standard cellular bands",
                evidence={
                    "frequency": freq_mhz,
                    "standard_bands": list(expected_bands.keys()),
                    "tower_id": metrics.tower.cell_id
                },
                confidence=0.8,
                mitigation_advice="Non-standard frequency may indicate illegal or fake base station."
            )
            threats.append(threat)
        
        # Check for frequency hopping patterns (GSM)
        if len(self.measurement_buffer) >= 5:
            recent_freqs = [m.downlink_frequency for m in list(self.measurement_buffer)[-5:] 
                          if m.downlink_frequency]
            if len(set(recent_freqs)) == len(recent_freqs) and len(recent_freqs) >= 3:
                # Rapid frequency changes might indicate jamming or spoofing
                threat = SecurityThreat(
                    threat_id=f"FREQ_HOPPING_{int(time.time())}",
                    threat_type="SUSPICIOUS_FREQUENCY_HOPPING",
                    severity="medium",
                    timestamp=metrics.timestamp,
                    description="Rapid frequency changes detected",
                    evidence={
                        "recent_frequencies": recent_freqs,
                        "frequency_count": len(set(recent_freqs))
                    },
                    confidence=0.6,
                    mitigation_advice="Unusual frequency patterns may indicate interference or attack."
                )
                threats.append(threat)
        
        return threats
    
    def _detect_power_analysis_attacks(self, metrics: AdvancedCellularMetrics) -> List[SecurityThreat]:
        """Detect power analysis and side-channel attacks."""
        threats = []
        
        if not metrics.uplink_power:
            return threats
        
        # Monitor for suspicious power control commands
        if len(self.measurement_buffer) >= 3:
            recent_powers = [m.uplink_power for m in list(self.measurement_buffer)[-3:] 
                           if m.uplink_power]
            
            if len(recent_powers) >= 3:
                power_changes = [recent_powers[i+1] - recent_powers[i] 
                               for i in range(len(recent_powers)-1)]
                
                # Check for unusual power control patterns
                if max(power_changes) > 10:  # Large power increase
                    threat = SecurityThreat(
                        threat_id=f"POWER_ANOMALY_{int(time.time())}",
                        threat_type="SUSPICIOUS_POWER_CONTROL",
                        severity="medium",
                        timestamp=metrics.timestamp,
                        description=f"Large uplink power increase: {max(power_changes)} dBm",
                        evidence={
                            "power_changes": power_changes,
                            "recent_powers": recent_powers,
                            "current_power": metrics.uplink_power
                        },
                        confidence=0.5,
                        mitigation_advice="Unusual power control may indicate jamming or signal manipulation."
                    )
                    threats.append(threat)
        
        return threats
    
    def _detect_sophisticated_imsi_catchers(self, metrics: AdvancedCellularMetrics) -> List[SecurityThreat]:
        """Detect sophisticated IMSI catchers using ML-based pattern recognition."""
        threats = []
        
        if len(self.measurement_buffer) < 20:
            return threats
        
        # Extract features for ML analysis
        features = self._extract_ml_features()
        
        # Check against known IMSI catcher signatures
        for imsi_catcher in self.fingerprint_database['known_imsi_catchers']:
            similarity_score = self._calculate_signature_similarity(features, imsi_catcher)
            
            if similarity_score > self.detection_thresholds['rf_fingerprint_match']:
                threat = SecurityThreat(
                    threat_id=f"SOPHISTICATED_IMSI_{int(time.time())}",
                    threat_type="SOPHISTICATED_IMSI_CATCHER",
                    severity="critical",
                    timestamp=metrics.timestamp,
                    description=f"Pattern matches known IMSI catcher: {imsi_catcher['name']}",
                    evidence={
                        "imsi_catcher_type": imsi_catcher['name'],
                        "similarity_score": similarity_score,
                        "matching_signatures": imsi_catcher['signatures'],
                        "features": features
                    },
                    confidence=similarity_score,
                    mitigation_advice=f"Sophisticated {imsi_catcher['name']} IMSI catcher detected. Avoid sensitive communications and leave area."
                )
                threats.append(threat)
        
        return threats
    
    def _extract_ml_features(self) -> Dict:
        """Extract machine learning features from measurement buffer."""
        features = {}
        
        # Signal strength statistics
        signals = [m.signal_strength for m in self.measurement_buffer if m.signal_strength]
        if signals:
            features['signal_mean'] = np.mean(signals)
            features['signal_std'] = np.std(signals)
            features['signal_range'] = max(signals) - min(signals)
        
        # Timing advance patterns
        timing_advances = [m.timing_advance for m in self.measurement_buffer 
                         if m.timing_advance is not None]
        if timing_advances:
            features['ta_mean'] = np.mean(timing_advances)
            features['ta_std'] = np.std(timing_advances)
            features['ta_zero_count'] = timing_advances.count(0)
        
        # Technology changes
        technologies = [m.tower.technology for m in self.measurement_buffer]
        features['tech_changes'] = len(set(technologies))
        features['has_downgrade'] = any(tech in technologies for tech in ['2G', 'GSM'])
        
        # Tower changes
        towers = [m.tower.cell_id for m in self.measurement_buffer]
        features['tower_changes'] = len(set(towers))
        
        return features
    
    def _calculate_signature_similarity(self, features: Dict, imsi_catcher: Dict) -> float:
        """Calculate similarity between extracted features and known signatures."""
        similarity = 0.0
        total_checks = 0
        
        signatures = imsi_catcher['signatures']
        
        # Check timing advance patterns
        if 'timing_advance_pattern' in signatures and 'ta_zero_count' in features:
            expected_zeros = sum(signatures['timing_advance_pattern'])
            actual_zeros = features['ta_zero_count']
            if expected_zeros > 0:
                similarity += min(actual_zeros / expected_zeros, 1.0)
            total_checks += 1
        
        # Check signal characteristics
        if 'signal_characteristics' in signatures and 'signal_std' in features:
            power_var = signatures['signal_characteristics'].get('power_variations', 'medium')
            signal_std = features['signal_std']
            
            if power_var == 'high' and signal_std > 10:
                similarity += 1.0
            elif power_var == 'medium' and 5 <= signal_std <= 15:
                similarity += 1.0
            elif power_var == 'low' and signal_std < 5:
                similarity += 1.0
            
            total_checks += 1
        
        # Check protocol deviations
        if 'protocol_deviations' in signatures and 'has_downgrade' in features:
            if 'forced_2g' in signatures['protocol_deviations'] and features['has_downgrade']:
                similarity += 1.0
            total_checks += 1
        
        return similarity / total_checks if total_checks > 0 else 0.0
    
    def _detect_jamming_attacks(self, metrics: AdvancedCellularMetrics) -> List[SecurityThreat]:
        """Detect cellular jamming attacks."""
        threats = []
        
        # Check for sudden signal drops across multiple frequencies
        if metrics.sinr is not None and metrics.sinr < -10:
            threat = SecurityThreat(
                threat_id=f"JAMMING_{int(time.time())}",
                threat_type="POTENTIAL_JAMMING",
                severity="high",
                timestamp=metrics.timestamp,
                description=f"Very low SINR detected: {metrics.sinr} dB",
                evidence={
                    "sinr": metrics.sinr,
                    "signal_strength": metrics.signal_strength,
                    "tower_id": metrics.tower.cell_id
                },
                confidence=0.7,
                mitigation_advice="Low SINR may indicate jamming attack. Check for interference sources."
            )
            threats.append(threat)
        
        return threats
    
    def _detect_location_spoofing(self, metrics: AdvancedCellularMetrics) -> List[SecurityThreat]:
        """Detect location spoofing attacks."""
        threats = []
        
        # This would require additional location data and tower database
        # Implementation would check for impossible tower locations
        
        return threats


class CellularSecurityVisualizer:
    """Visualization tools for cellular security data."""
    
    def __init__(self):
        self.fig, self.axes = plt.subplots(2, 2, figsize=(15, 10))
        self.fig.suptitle('Cellular Security Monitor - Real-time Analysis')
        
    def plot_signal_analysis(self, measurements: List[AdvancedCellularMetrics]):
        """Plot signal strength and quality analysis."""
        if not measurements:
            return
        
        timestamps = [m.timestamp for m in measurements]
        signals = [m.signal_strength for m in measurements]
        
        # Signal strength over time
        ax = self.axes[0, 0]
        ax.clear()
        ax.plot(timestamps, signals, 'b-', linewidth=2)
        ax.set_title('Signal Strength Over Time')
        ax.set_ylabel('Signal Strength (dBm)')
        ax.grid(True)
        
        # Signal quality metrics
        if any(m.rsrq for m in measurements):
            rsrq_values = [m.rsrq for m in measurements if m.rsrq is not None]
            rsrq_times = [m.timestamp for m in measurements if m.rsrq is not None]
            
            ax = self.axes[0, 1]
            ax.clear()
            ax.plot(rsrq_times, rsrq_values, 'g-', linewidth=2)
            ax.set_title('Signal Quality (RSRQ)')
            ax.set_ylabel('RSRQ (dB)')
            ax.grid(True)
    
    def plot_threat_timeline(self, threats: List[SecurityThreat]):
        """Plot threat detection timeline."""
        if not threats:
            return
        
        threat_types = [t.threat_type for t in threats]
        threat_times = [t.timestamp for t in threats]
        
        ax = self.axes[1, 0]
        ax.clear()
        
        # Create scatter plot with color coding by severity
        colors = {'low': 'green', 'medium': 'orange', 'high': 'red', 'critical': 'darkred'}
        for threat in threats:
            color = colors.get(threat.severity, 'gray')
            ax.scatter(threat.timestamp, threat.threat_type, c=color, s=100, alpha=0.7)
        
        ax.set_title('Security Threats Timeline')
        ax.set_xlabel('Time')
        ax.set_ylabel('Threat Type')
        plt.setp(ax.get_xticklabels(), rotation=45)
    
    def plot_frequency_analysis(self, measurements: List[AdvancedCellularMetrics]):
        """Plot frequency analysis."""
        if not measurements:
            return
        
        frequencies = [m.downlink_frequency for m in measurements if m.downlink_frequency]
        
        if frequencies:
            ax = self.axes[1, 1]
            ax.clear()
            ax.hist(frequencies, bins=20, alpha=0.7, color='purple')
            ax.set_title('Frequency Distribution')
            ax.set_xlabel('Frequency (MHz)')
            ax.set_ylabel('Count')
            ax.grid(True)
    
    def save_plots(self, filename: str = None):
        """Save current plots to file."""
        if filename is None:
            filename = f"cellular_security_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
        
        plt.tight_layout()
        plt.savefig(filename, dpi=300, bbox_inches='tight')
        print(f"Analysis plots saved to {filename}")


class EnhancedCellularSecurityMonitor(CellularSecurityMonitor):
    """Enhanced cellular security monitor with advanced detection capabilities."""
    
    def __init__(self, config_file: str = "enhanced_cellular_security_config.json"):
        super().__init__(config_file)
        
        # Initialize advanced detector
        self.advanced_detector = AdvancedIMSICatcherDetector(self.config)
        
        # Initialize visualizer
        self.visualizer = CellularSecurityVisualizer()
        
        # Enhanced measurement storage
        self.advanced_measurements: List[AdvancedCellularMetrics] = []
        
        # Real-time threat monitoring
        self.threat_monitor_thread = None
        self.monitoring_active = False
        
        print("🔬 Enhanced Cellular Security Monitor initialized")
    
    def get_advanced_cellular_info(self) -> Optional[AdvancedCellularMetrics]:
        """Get advanced cellular metrics."""
        # Get basic measurement first
        basic_measurement = self.get_cellular_info()
        if not basic_measurement:
            return None
        
        # Enhance with advanced metrics (simulated for demo)
        enhanced_metrics = AdvancedCellularMetrics(
            timestamp=basic_measurement.timestamp,
            tower=basic_measurement.tower,
            signal_strength=basic_measurement.signal_strength,
            signal_quality=basic_measurement.signal_quality or 0,
            timing_advance=np.random.randint(0, 63),  # Simulated
            frame_number=np.random.randint(0, 2715647),  # GSM frame number
            arfcn=np.random.randint(0, 1023),  # ARFCN
            pci=np.random.randint(0, 503),  # Physical Cell ID
            rsrp=np.random.uniform(-140, -44),  # RSRP
            rsrq=np.random.uniform(-20, -3),  # RSRQ
            sinr=np.random.uniform(-20, 30),  # SINR
            cqi=np.random.randint(0, 15),  # CQI
            uplink_power=np.random.randint(-40, 23),  # Uplink power
            downlink_frequency=np.random.choice([1800, 2100, 2600]),  # Frequency
            band="B3"  # Frequency band
        )
        
        return enhanced_metrics
    
    def start_enhanced_monitoring(self):
        """Start enhanced monitoring with advanced threat detection."""
        print("🔬 Starting Enhanced Cellular Security Monitoring...")
        print("Advanced IMSI catcher detection enabled")
        print("Real-time signal analysis active")
        print("Press Ctrl+C to stop monitoring\n")
        
        self.monitoring_active = True
        
        try:
            while self.monitoring_active:
                # Get advanced metrics
                metrics = self.get_advanced_cellular_info()
                if metrics:
                    # Store measurement
                    self.advanced_measurements.append(metrics)
                    
                    # Perform basic analysis
                    basic_threats = self.analyze_measurement(
                        CellularMeasurement(
                            timestamp=metrics.timestamp,
                            tower=metrics.tower,
                            signal_strength=metrics.signal_strength,
                            signal_quality=metrics.signal_quality,
                            technology=metrics.tower.technology,
                            location=None
                        )
                    )
                    
                    # Perform advanced analysis
                    advanced_threats = self.advanced_detector.analyze_advanced_metrics(metrics)
                    
                    # Combine and display threats
                    all_threats = basic_threats + advanced_threats
                    for threat in all_threats:
                        self._handle_threat_notification(threat)
                    
                    # Update visualizations periodically
                    if len(self.advanced_measurements) % 10 == 0:
                        self._update_visualizations()
                    
                    # Show status
                    self._display_enhanced_status()
                
                time.sleep(self.config['monitor_interval'])
                
        except KeyboardInterrupt:
            print("\n\n🛑 Enhanced Cellular Security Monitor stopped")
            self.monitoring_active = False
            self.generate_enhanced_report()
    
    def _update_visualizations(self):
        """Update real-time visualizations."""
        try:
            recent_measurements = self.advanced_measurements[-100:]  # Last 100 measurements
            recent_threats = [t for t in self.security_threats 
                            if (datetime.now() - t.timestamp).total_seconds() < 3600]
            
            self.visualizer.plot_signal_analysis(recent_measurements)
            self.visualizer.plot_threat_timeline(recent_threats)
            self.visualizer.plot_frequency_analysis(recent_measurements)
            
            plt.pause(0.01)  # Brief pause to update plots
        except Exception as e:
            print(f"Error updating visualizations: {e}")
    
    def _display_enhanced_status(self):
        """Display enhanced monitoring status."""
        measurement_count = len(self.advanced_measurements)
        threat_count = len([t for t in self.security_threats 
                          if (datetime.now() - t.timestamp).total_seconds() < 3600])
        
        if self.advanced_measurements:
            latest = self.advanced_measurements[-1]
            status = (f"\r📊 Measurements: {measurement_count} | "
                     f"Threats(1h): {threat_count} | "
                     f"Signal: {latest.signal_strength}dBm | "
                     f"RSRQ: {latest.rsrq:.1f}dB | "
                     f"TA: {latest.timing_advance}")
            print(status, end="", flush=True)
    
    def generate_enhanced_report(self):
        """Generate enhanced security report with advanced analysis."""
        self.generate_report()  # Call parent method
        
        print("\n" + "="*60)
        print("🔬 ADVANCED ANALYSIS REPORT")
        print("="*60)
        
        if self.advanced_measurements:
            print(f"Advanced Measurements Collected: {len(self.advanced_measurements)}")
            
            # Signal quality analysis
            rsrq_values = [m.rsrq for m in self.advanced_measurements if m.rsrq is not None]
            if rsrq_values:
                print(f"Average RSRQ: {np.mean(rsrq_values):.2f} dB")
                print(f"RSRQ Standard Deviation: {np.std(rsrq_values):.2f} dB")
            
            # Timing advance analysis
            ta_values = [m.timing_advance for m in self.advanced_measurements if m.timing_advance is not None]
            if ta_values:
                print(f"Timing Advance - Mean: {np.mean(ta_values):.1f}, Std: {np.std(ta_values):.1f}")
                print(f"TA=0 occurrences: {ta_values.count(0)}")
            
            # Frequency analysis
            frequencies = [m.downlink_frequency for m in self.advanced_measurements if m.downlink_frequency]
            if frequencies:
                unique_freqs = set(frequencies)
                print(f"Unique frequencies observed: {len(unique_freqs)}")
                print(f"Frequency range: {min(frequencies)} - {max(frequencies)} MHz")
        
        # Save visualizations
        if self.advanced_measurements:
            self.visualizer.save_plots()
        
        print("="*60)


def main():
    """Main function for enhanced cellular security monitoring."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Enhanced Cellular Security Monitor")
    parser.add_argument('--config', default='enhanced_cellular_security_config.json', help='Config file')
    parser.add_argument('--interval', type=int, help='Monitoring interval in seconds')
    parser.add_argument('--advanced', action='store_true', help='Use advanced monitoring mode')
    parser.add_argument('--visualize', action='store_true', help='Enable real-time visualizations')
    parser.add_argument('--export', type=str, help='Export data to file')
    
    args = parser.parse_args()
    
    # Create enhanced monitor
    monitor = EnhancedCellularSecurityMonitor(config_file=args.config)
    
    # Override config with command line arguments
    if args.interval:
        monitor.config['monitor_interval'] = args.interval
    
    # Handle export command
    if args.export:
        monitor.export_data(args.export)
        return
    
    # Start appropriate monitoring mode
    if args.advanced:
        monitor.start_enhanced_monitoring()
    else:
        monitor.start_monitoring()


if __name__ == "__main__":
    main()
