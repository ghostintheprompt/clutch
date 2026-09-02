#!/usr/bin/env python3
import unittest
from datetime import datetime
from advanced_cellular_security import (
    AdvancedCellularMetrics,
    AdvancedIMSICatcherDetector,
)
from cellular_security import CellularTower


class TestCellularSecurity(unittest.TestCase):
    def setUp(self):
        self.detector = AdvancedIMSICatcherDetector(config={})

    def test_imsi_catcher_detection(self):
        # A close-range/fake base station pattern: strong signal, TA=0.
        metrics = AdvancedCellularMetrics(
            timestamp=datetime.now(),
            tower=CellularTower(
                cell_id="CELL_9999",
                lac="999", mcc="001", mnc="01",
                technology="LTE",
                frequency=1950.0,
            ),
            signal_strength=-40,  # Suspect: too strong for a legitimate distant tower
            signal_quality=3,
            timing_advance=0,     # Suspect: TA=0 indicates a very close/fake base station
            uplink_power=23.0,
        )

        threats = self.detector.analyze_advanced_metrics(metrics)

        self.assertTrue(len(threats) > 0, "Failed to detect blatant IMSI catcher pattern")
        self.assertTrue(any(t.threat_type == "TIMING_ADVANCE_ZERO" for t in threats))


if __name__ == "__main__":
    unittest.main()
