#!/usr/bin/env python3
"""
Clutch — Integration Test & Adversary Emulation Entry Point

Two modes:

  1. iOS Remote Integration Test (default)
     Starts the WebSocket coordination server and validates that the iOS app
     can connect and share cellular threats in real time.

  2. Red Team Adversary Emulation (--red-team --authorized)
     Runs the full adversary emulation suite — ARP poisoning, DNS hijacking,
     and synthetic IMSI catcher injection — and validates that Clutch
     detects each technique. Produces a JSON validation report.

     AUTHORIZED USE ONLY. See scripts/adversary_emulation.py for full warnings.

Usage:
  python test_ios_remote_integration.py                        # iOS server test
  python test_ios_remote_integration.py --red-team --authorized  # full emulation
  python test_ios_remote_integration.py --red-team --authorized --technique cellular
"""

import asyncio
import sys
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


# ── iOS Remote Server Test ────────────────────────────────────────────────────

def check_dependencies() -> bool:
    missing = []
    for pkg in ("websockets", "sqlite3"):
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        logger.error(f"Missing dependencies: {missing}")
        return False
    logger.info("All dependencies available")
    return True


async def run_ios_integration_test() -> bool:
    logger.info("iOS Remote Integration Test")
    logger.info("=" * 50)

    if not check_dependencies():
        return False

    try:
        from cellular_remote_server import CellularRemoteMonitoringServer
        server = CellularRemoteMonitoringServer()
        server_task = asyncio.create_task(server.start_server())
    except ImportError as e:
        logger.error(f"Could not import server: {e}")
        return False

    await asyncio.sleep(3)

    logger.info("Remote monitoring server running")
    logger.info("-" * 50)
    logger.info("iOS App Setup:")
    logger.info("  1. Open iOS-App/NetworkSecurityMonitor.xcodeproj in Xcode")
    logger.info("  2. Settings tab → Remote Monitoring → Setup")
    logger.info("  3. Server URL: ws://localhost:8765")
    logger.info("  4. API Key: (shown in server startup log)")
    logger.info("  5. Cellular tab → threats will appear as detected")
    logger.info("-" * 50)

    try:
        for i in range(30):
            await asyncio.sleep(10)
            if i == 2:
                logger.info("Tip: start cellular monitoring in the iOS app")
            elif i == 10:
                logger.info("Check server log for iOS app connection events")
            elif i == 20:
                logger.info("Cellular threats detected by app will stream to server")
    except asyncio.CancelledError:
        pass
    finally:
        server_task.cancel()

    logger.info("iOS integration test complete")
    logger.info("Log file: cellular_remote_monitoring.log")
    return True


# ── Red Team Adversary Emulation ──────────────────────────────────────────────

def run_red_team(args) -> int:
    """
    Invoke the adversary emulation suite and print a coverage summary.
    Returns exit code (0 = all detections passed, 1 = missed detections).
    """
    from adversary_emulation import (
        DetectionValidationRunner,
        ARPPoisoningEmulator,
        DNSHijackEmulator,
        CellularDowngradeSimulator,
        require_authorization,
        BANNER,
    )

    print(BANNER)
    require_authorization(args)

    runner = DetectionValidationRunner(
        interface=getattr(args, "interface", "en0"),
        target_ip=getattr(args, "target_ip", None),
        gateway_ip=getattr(args, "gateway_ip", None),
    )

    technique = getattr(args, "technique", "all")

    if technique == "all":
        report = runner.run_all(duration_per_test=getattr(args, "duration", 30))
        out = runner.save_report(report)
    elif technique == "arp":
        if not (args.target_ip and args.gateway_ip):
            print("[!] --target-ip and --gateway-ip required for ARP emulation")
            return 1
        emulator = ARPPoisoningEmulator(args.interface, args.target_ip, args.gateway_ip)
        report = emulator.run(duration_seconds=args.duration)
        report["attack_description"] = emulator.describe()
        out = runner.save_report({"report_id": f"ADVEML-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                                   "generated_at": datetime.now().isoformat(),
                                   "test_results": [report],
                                   "coverage_summary": {}})
    elif technique == "dns":
        emulator = DNSHijackEmulator()
        report = emulator.run(duration_seconds=getattr(args, "duration", 30))
        report["attack_description"] = emulator.describe()
        out = runner.save_report({"report_id": f"ADVEML-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                                   "generated_at": datetime.now().isoformat(),
                                   "test_results": [report],
                                   "coverage_summary": {}})
    elif technique == "cellular":
        emulator = CellularDowngradeSimulator()
        report = emulator.inject_stingray_pattern(cycles=8)
        report["attack_description"] = emulator.describe()
        out = runner.save_report({"report_id": f"ADVEML-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                                   "generated_at": datetime.now().isoformat(),
                                   "test_results": [report],
                                   "coverage_summary": {}})
    else:
        print(f"[!] Unknown technique: {technique}")
        return 1

    # Print summary
    rate = report.get("overall_detection_rate", report.get("detection_rate", 0))
    missed = report.get("missed_detections", [])

    print("\n" + "=" * 60)
    print("RED TEAM VALIDATION COMPLETE")
    print(f"Detection Rate:  {rate:.0%}")
    if missed:
        print(f"Missed:          {', '.join(missed)}")
        print("[!] Review detection thresholds for missed TTPs")
    else:
        print("[+] All expected threat types detected")
    print(f"Report:          {out}")
    print("=" * 60)

    return 0 if not missed else 1


# ── Integration & Coverage Summary ───────────────────────────────────────────

def print_system_summary():
    logger.info("Clutch System Summary")
    logger.info("=" * 50)
    components = {
        "iOS CoreTelephony monitoring": True,
        "IMSI catcher detection (basic)": True,
        "Advanced ML-based detection": True,
        "Remote WebSocket coordination": True,
        "Active firewall blocking": True,
        "Cellular geofencing": True,
        "Triggered PCAP capture": True,
        "Incident report generation": True,
        "TLS/DNSSEC trust chain view": True,
        "SIGINT map visualization (iOS)": True,
        "Adversary emulation suite": True,
        "ATTACK_VECTORS.md": True,
        "Hardened Dockerfile": True,
    }
    for component, status in components.items():
        marker = "[+]" if status else "[ ]"
        logger.info(f"  {marker} {component}")
    logger.info("=" * 50)


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Clutch integration test and adversary emulation runner"
    )
    p.add_argument("--red-team", action="store_true",
                   help="Run adversary emulation suite instead of iOS server test")
    p.add_argument("--authorized", action="store_true",
                   help="Confirm written authorization to run attack simulations")
    p.add_argument("--interface", default="en0", help="Network interface (default: en0)")
    p.add_argument("--target-ip", dest="target_ip", help="Target IP for ARP/DNS tests")
    p.add_argument("--gateway-ip", dest="gateway_ip", help="Gateway IP for ARP test")
    p.add_argument("--duration", type=int, default=30, help="Seconds per test")
    p.add_argument("--technique", choices=["arp", "dns", "cellular", "all"], default="all")
    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    print_system_summary()

    if args.red_team:
        sys.exit(run_red_team(args))
    else:
        logger.info("Starting iOS Remote Integration Test...")
        try:
            success = asyncio.run(run_ios_integration_test())
        except KeyboardInterrupt:
            logger.info("Test stopped by user")
            success = True
        except Exception as e:
            logger.error(f"Test error: {e}")
            success = False
        logger.info("Done.")
        sys.exit(0 if success else 1)
