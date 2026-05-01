#!/usr/bin/env python3
"""
CLUTCH CONTROL (clutch_ctl.py)
==============================
Unified Command & Control suite for the Clutch Cellular Security System.
Operates as the single point of entry for service management and forensics.
"""

import os
import sys
import json
import base64
import subprocess
import signal
import time
import argparse
import logging
import tarfile
from pathlib import Path
from datetime import datetime

# Setup paths
SCRIPT_DIR = Path(__file__).parent.absolute()
PROJECT_ROOT = SCRIPT_DIR.parent
FORENSICS_DIR = PROJECT_ROOT / "forensics"
CONFIG_PATH = PROJECT_ROOT / "cellular_remote_config.json"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ClutchCtl")

class ClutchController:
    def __init__(self):
        self.services = {}

    def get_opsec_key(self):
        """Extract or generate the current AES-256 OPSEC key."""
        if not CONFIG_PATH.exists():
            logger.info("Config not found. Run server once to generate defaults.")
            return None
            
        with open(CONFIG_PATH, "r") as f:
            config = json.load(f)
            
        key = config.get("opsec_master_key")
        if not key:
            # Generate one if missing
            new_key = base64.b64encode(os.urandom(32)).decode()
            config["opsec_master_key"] = new_key
            with open(CONFIG_PATH, "w") as f:
                json.dump(config, f, indent=4)
            return new_key
        return key

    def show_ios_config(self):
        """Generate a JSON snippet for iOS app setup."""
        key = self.get_opsec_key()
        api_key = "development-key-123" # Default fallback
        
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "r") as f:
                cfg = json.load(f)
                api_key = cfg.get("api_keys", [api_key])[0]

        setup = {
            "remote_server": "ws://<YOUR_IP>:8766",
            "api_key": api_key,
            "opsec_encryption_key": key,
            "instructions": "Enter these in the iOS App 'Settings -> Remote Setup' screen."
        }
        print("\n--- CLUTCH iOS PROVISIONING SNIPPET ---")
        print(json.dumps(setup, indent=2))
        print("---------------------------------------\n")

    def launch_services(self, sdr_sim=False):
        """Start the remote server and heatmap generator."""
        logger.info("🚀 Launching Clutch Defensive Services...")
        
        # 1. Start Remote Server
        server_cmd = [sys.executable, str(SCRIPT_DIR / "cellular_remote_server.py")]
        p_server = subprocess.Popen(server_cmd, cwd=PROJECT_ROOT)
        self.services["server"] = p_server
        
        # 2. Start SDR Simulation if requested
        if sdr_sim:
            logger.info("[SDR-SIM] Phantom Tower Simulation active.")
            # Note: In a real orchestrator, this might be a separate background worker
            # For now, we note it's handled by the detection scripts logic

        logger.info("Services running. Press Ctrl+C to shutdown.")
        try:
            while True:
                time.sleep(10)
                # Periodically trigger heatmap update
                subprocess.run([sys.executable, str(SCRIPT_DIR / "sigint_heatmap.py")], 
                               cwd=PROJECT_ROOT, capture_output=True)
        except KeyboardInterrupt:
            self.shutdown()

    def shutdown(self):
        logger.info("🛑 Shutting down Clutch services...")
        for name, proc in self.services.items():
            logger.info(f"Terminating {name}...")
            proc.terminate()
        sys.exit(0)

    def export_forensics(self):
        """Bundle all evidence into a secure archive."""
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        export_name = f"clutch_forensics_{ts}.tar.gz"
        
        if not FORENSICS_DIR.exists():
            logger.error("No forensics directory found. Nothing to export.")
            return

        logger.info(f"📦 Bundling forensics into {export_name}...")
        with tarfile.open(export_name, "w:gz") as tar:
            tar.add(str(FORENSICS_DIR), arcname="forensics")
            # Include audit logs and database
            if (PROJECT_ROOT / "cellular_remote_monitoring.db").exists():
                tar.add(str(PROJECT_ROOT / "cellular_remote_monitoring.db"), arcname="threat_intel.db")
                
        logger.info(f"✅ Export complete: {os.path.abspath(export_name)}")

def main():
    parser = argparse.ArgumentParser(description="Clutch C2 Suite")
    subparsers = parser.add_subparsers(dest="command")

    # Start command
    start_p = subparsers.add_parser("start", help="Start all monitoring services")
    start_p.add_argument("--sdr-sim", action="store_true", help="Enable SDR Phantom Tower simulation")

    # Provision command
    subparsers.add_parser("provision", help="Show iOS app encryption/API keys")

    # Export command
    subparsers.add_parser("export", help="Bundle all evidence/PCAPs/logs for analysis")

    args = parser.parse_args()
    ctl = ClutchController()

    if args.command == "start":
        ctl.launch_services(sdr_sim=args.sdr_sim)
    elif args.command == "provision":
        ctl.show_ios_config()
    elif args.command == "export":
        ctl.export_forensics()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
