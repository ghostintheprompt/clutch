# Clutch — Attack Vector Mapping

Maps every detection capability in Clutch to the real-world threat it exists to counter. Each entry names the attack, explains the physical or protocol mechanism, identifies the MITRE ATT&CK reference, and describes the specific signal Clutch monitors to detect it.

---

## Cellular Layer

### 1. IMSI Capture via Cell-Site Simulator

**Threat:** A portable radio transceiver (StingRay, Harris HailStorm, DRT Box) broadcasts a stronger signal than legitimate towers in range. Phones connect because they trust the strongest signal without verifying tower authenticity. The device reveals its IMSI (permanent identifier), enabling location tracking and targeted interception.

**MITRE:** T1430 (Location Tracking), T1428 (Exploitation of Remote Services — mobile)

**How Clutch detects it:**
- Timing Advance (TA) value of 0 — indicates a tower physically adjacent to the device where no legitimate tower exists
- Impossible TA change rate — TA cannot jump faster than the device could physically move
- Cell ID outside the valid geographic range for the observed MCC/MNC
- Sudden +25 dBm or greater RSSI spike — legitimate towers don't teleport

**Module:** `AdvancedIMSICatcherDetector._detect_timing_advance_anomalies()`

---

### 2. Forced Protocol Downgrade (2G Rollback)

**Threat:** IMSI catchers reject 4G/5G capability negotiation, causing the device to fall back to 2G/GSM. GSM encryption (A5/1) is cryptographically broken and well-documented. Some configurations use A5/0 (no encryption). This enables real-time plaintext voice and SMS interception without requiring key material.

**MITRE:** T1040 (Network Sniffing), T1600.002 (Downgrade Attack)

**How Clutch detects it:**
- Technology transition 4G→3G→2G without geographic justification (rural coverage gaps)
- Technology regression correlated with simultaneous TA anomaly (compound indicator)
- `has_downgrade` flag in ML feature extraction triggers `_detect_sophisticated_imsi_catchers()`

**Module:** `AdvancedIMSICatcherDetector._extract_ml_features()` → `has_downgrade`

---

### 3. RF Fingerprint Anomaly

**Threat:** Legitimate base stations have stable, predictable RF characteristics for a fixed location. IMSI catchers — particularly consumer-grade hardware — exhibit RF signature differences: unusual RSRP/RSRQ ratios, high signal quality variance, and emission patterns inconsistent with legitimate carrier equipment.

**MITRE:** T1205 (Traffic Signaling)

**How Clutch detects it:**
- RSRQ standard deviation > 10 dB over a 10-measurement window (legitimate: typically < 3 dB for stationary device)
- RSRP/RSRQ ratio outside expected bounds (flags non-standard amplifier characteristics)
- RF fingerprint database comparison against known StingRay, HailStorm, DRT Box signatures

**Module:** `AdvancedIMSICatcherDetector._detect_rf_fingerprint_anomalies()`

---

### 4. Cellular Jamming

**Threat:** Active jamming uses a wideband RF transmitter to saturate the cellular frequency band, forcing devices to disconnect. Used to create a communications blackout, drive targeted devices to a secondary (attacker-controlled) network, or prevent emergency communications.

**MITRE:** T1499 (Endpoint Denial of Service), T1498 (Network Denial of Service)

**How Clutch detects it:**
- SINR below −10 dB — signal-to-interference ratio this low indicates an active interference source, not just poor coverage
- Correlated signal drop across all measurements simultaneously
- No tower change despite complete loss of signal quality

**Module:** `AdvancedIMSICatcherDetector._detect_jamming_attacks()`

---

### 5. Invalid Physical Cell ID

**Threat:** LTE Physical Cell IDs (PCI) are assigned in the range 0–503 per 3GPP TS 36.211. A cell advertising a PCI outside this range cannot be legitimate carrier equipment. This error appears in low-budget or improperly configured IMSI catcher software.

**MITRE:** T1205 (Traffic Signaling — protocol manipulation)

**How Clutch detects it:**
- PCI < 0 or PCI > 503 triggers `INVALID_PHYSICAL_CELL_ID` with 0.9 confidence
- Combined with other indicators, elevates overall threat assessment to critical

**Module:** `AdvancedIMSICatcherDetector._detect_protocol_anomalies()`

---

### 6. Neighbor Cell Isolation

**Threat:** Legitimate LTE towers in any populated area report 6–20 neighbor cells in the system information blocks they broadcast. An IMSI catcher often reports zero neighbor cells because it has no coordination with the actual carrier network. This is a passive isolation technique — the device has no other towers to compare against.

**MITRE:** T1563 (Remote Service Session Hijacking)

**How Clutch detects it:**
- Zero neighbor cells reported in an urban or suburban context flags `NO_NEIGHBOR_CELLS`
- Neighbor count > 20 flags `EXCESSIVE_NEIGHBOR_CELLS` (spoofed broadcast)
- Low confidence (0.4) individually; confidence rises when co-occurring with TA=0 or RF anomaly

**Module:** `AdvancedIMSICatcherDetector._detect_protocol_anomalies()`

---

### 7. Non-Standard Frequency Operation

**Threat:** Licensed carriers operate on allocated spectrum within defined band plans (3GPP). An IMSI catcher operating outside these allocations is either using unlicensed spectrum or misconfigured carrier-band emulation software. Non-standard frequencies may also indicate interference from co-channel transmitters used in coordinated attacks.

**MITRE:** T1205 (Traffic Signaling)

**How Clutch detects it:**
- Downlink frequency checked against known band allocation table (B1, B3, B7, B8, B20)
- Frequency outside any standard band triggers `FREQUENCY_OUT_OF_BAND` (0.8 confidence)
- Rapid frequency changes across successive measurements flag `SUSPICIOUS_FREQUENCY_HOPPING`

**Module:** `AdvancedIMSICatcherDetector._detect_frequency_anomalies()`

---

### 8. Geofencing Violation (Regional Lock)

**Threat:** In high-risk environments (embassy neighborhoods, protest routes, court complexes) operators may designate specific MCC/MNC values as the only acceptable operators. A connection attempt to any other operator indicates either geographic displacement or a foreign/rogue network masquerading as a domestic carrier.

**MITRE:** T1430 (Location Tracking), T1456 (Drive-by Compromise — mobile)

**How Clutch detects it:**
- `CellularGeofencing` cross-references observed MCC/MNC against operator whitelist
- GPS bounding-box check flags device leaving the designated safe zone perimeter
- Both checks trigger `GEOFENCE_VIOLATION` at critical severity with 0.95–0.98 confidence

**Module:** `CellularGeofencing.check_tower()`

---

## Network Layer

### 9. ARP Cache Poisoning (LAN MITM)

**Threat:** On Layer 2 Ethernet and Wi-Fi networks, ARP maps IP addresses to MAC addresses with no authentication. An attacker sends gratuitous ARP replies associating their MAC with the gateway or target IP. Both devices update their cache; subsequent traffic routes through the attacker for inspection, modification, or credential harvesting.

**MITRE:** T1557.002 (Adversary-in-the-Middle: ARP Cache Poisoning)

**How Clutch detects it (validation):**
- `ARPPoisoningEmulator` in `adversary_emulation.py` injects this pattern on test networks
- Detection expected from network monitoring layer: ARP churn, duplicate IP claims
- `DetectionValidationRunner` verifies the pipeline catches this pattern

**Module:** `scripts/adversary_emulation.py:ARPPoisoningEmulator`

---

### 10. DNS Response Injection

**Threat:** After gaining MITM position (via ARP poisoning or rogue DHCP), an attacker races the legitimate DNS resolver, injecting spoofed A-record responses before the real answer arrives. The target caches the malicious mapping. All subsequent connections to the hijacked domain go to attacker-controlled infrastructure.

**MITRE:** T1071.004 (Application Layer Protocol: DNS)

**How Clutch detects it (validation):**
- `DNSHijackEmulator` runs a rogue DNS responder on port 5353, validates injection works
- Production detection: DNSSEC validation; DNS TTL anomaly monitoring; resolver IP change detection
- Clutch server logs capture resolver changes via coordinated remote device reporting

**Module:** `scripts/adversary_emulation.py:DNSHijackEmulator`

---

## Incident Response & Forensics

### 11. Evidence Preservation Gap

**Threat:** Cellular attacks are transient — an IMSI catcher drives past, captures identifiers, and leaves. Without triggered evidence capture, the only record is a detection log. Forensic gaps allow attackers to operate with impunity and complicate post-incident attribution.

**How Clutch addresses it:**
- `TriggeredPCAPCapture` initiates a `tcpdump` session when high/critical threats fire
- Captures stored under `/forensics/pcap/<threat_id>_<timestamp>.pcap`
- `IncidentReporter` compiles threat timeline, tower metadata, and system state into a tamper-evident JSON incident report (SHA-256 integrity hash over the full document)

**Module:** `TriggeredPCAPCapture.trigger()`, `IncidentReporter.generate()`

---

### 12. Unauthorized IP Connection

**Threat:** Malware, rogue processes, or compromised network equipment may establish outbound connections to command-and-control infrastructure. Without automated blocking, detection alone is insufficient in high-risk environments.

**How Clutch addresses it:**
- `ActiveBlockingModule.null_route_ip()` inserts a DROP rule via `iptables` (Linux) or `pfctl` (macOS)
- All blocking actions are written to `/forensics/blocks/block_audit.json` for post-incident review
- `dry_run=True` mode allows posture validation without modifying firewall state

**Module:** `ActiveBlockingModule.null_route_ip()`

---

## Threat Summary Table

| # | Threat | MITRE ID | Clutch Module | Severity |
|---|--------|----------|---------------|----------|
| 1 | IMSI Capture | T1430 | `_detect_timing_advance_anomalies` | High |
| 2 | Protocol Downgrade | T1600.002 | `_extract_ml_features` | Critical |
| 3 | RF Fingerprint Anomaly | T1205 | `_detect_rf_fingerprint_anomalies` | Medium |
| 4 | Cellular Jamming | T1498 | `_detect_jamming_attacks` | High |
| 5 | Invalid PCI | T1205 | `_detect_protocol_anomalies` | High |
| 6 | Neighbor Isolation | T1563 | `_detect_protocol_anomalies` | Medium |
| 7 | Non-Standard Frequency | T1205 | `_detect_frequency_anomalies` | High |
| 8 | Geofence Violation | T1430 | `CellularGeofencing` | Critical |
| 9 | ARP Poisoning | T1557.002 | `ARPPoisoningEmulator` | High |
| 10 | DNS Hijacking | T1071.004 | `DNSHijackEmulator` | High |
| 11 | Evidence Gap | — | `TriggeredPCAPCapture` | Operational |
| 12 | Unauthorized IP | T1071 | `ActiveBlockingModule` | High |

---

## Compound Threat Scoring

No single indicator is proof of an attack. Clutch's confidence model is additive:

```
confidence_composite = sum(indicator.confidence * indicator.weight)

High-confidence compound pattern (StingRay):
  TA=0                     → 0.6
  PCI out of range         → 0.9
  SINR < -10 dB            → 0.7
  No neighbor cells        → 0.4
  Non-standard frequency   → 0.8
  ─────────────────────────────
  Composite (weighted avg) → 0.87 → CRITICAL alert
```

Individually ambiguous signals become high-confidence threat detections in combination. This mirrors how professional threat analysts work: corroborating evidence across independent data sources before escalating.

---

*Detection logic: `scripts/advanced_cellular_security.py`*
*Validation suite: `scripts/adversary_emulation.py`*
*Active defense: see `ActiveBlockingModule`, `CellularGeofencing`, `TriggeredPCAPCapture`*
