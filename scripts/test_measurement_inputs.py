#!/usr/bin/env python3
"""Synthetic rule/input regression tests. No collectors, networking or model fitting."""
import unittest
from collections import deque
from datetime import datetime, timedelta
import cellular_security as source

class MeasurementInputs(unittest.TestCase):
    def setUp(self):
        self.monitor = source.CellularSecurityMonitor.__new__(source.CellularSecurityMonitor)
        self.monitor.config = {}
        self.monitor.analysis_status = {}
        self.monitor.measurement_history = deque()
        self.monitor.last_location = None
        self.monitor.signal_jump_threshold = 20
        self.tower = source.CellularTower('fixture', 'fixture', '001', '01', 'GSM')

    def row(self, **overrides):
        args = dict(timestamp=datetime.now(), tower=self.tower, signal_strength=-80,
                    signal_quality=0, technology='GSM', encryption_status='A5/1', timing_advance=0)
        args.update(overrides)
        return source.CellularMeasurement(**args)

    def history(self):
        for n in range(10):
            self.monitor.measurement_history.append(self.row(timestamp=datetime.now()-timedelta(seconds=10-n)))

    def test_timing_advance_defaults_to_unavailable(self):
        row=source.CellularMeasurement(datetime.now(),self.tower,-80)
        self.assertIsNone(row.timing_advance)
        self.assertEqual(set(self.monitor._feature_input_issues(row)),
                         {'signal_quality','timing_advance','technology','encryption_status'})

    def test_supplied_zero_is_not_missing(self):
        self.assertEqual(self.monitor._feature_input_issues(self.row()), [])

    def test_invalid_fields_rejected(self):
        for field, value in [('signal_strength',float('nan')),('signal_quality',True),
                             ('timing_advance',-1),('timing_advance',float('inf')),
                             ('technology','Unknown'),('encryption_status','Unknown')]:
            with self.subTest(field=field,value=value):
                self.assertIn(field,self.monitor._feature_input_issues(self.row(**{field:value})))

    def test_invalid_signal_does_not_enter_history(self):
        self.assertEqual(self.monitor.analyze_measurement(self.row(signal_strength=float('nan'))), [])
        self.assertEqual(len(self.monitor.measurement_history),0)
        self.assertEqual(self.monitor.analysis_status['measurement']['state'],'unavailable')

    def test_signal_jump_units_and_rule_weight(self):
        previous=self.row(signal_strength=-90)
        current=self.row(signal_strength=-62)
        self.monitor.measurement_history.extend([previous,current])
        threats=self.monitor._detect_imsi_catcher(current)
        jump=next(t for t in threats if t.threat_type=='IMSI_CATCHER_SUSPECTED')
        self.assertEqual(jump.evidence['signal_jump'],28)
        self.assertEqual(jump.evidence['signal_jump_unit'],'dB')
        self.assertEqual(jump.confidence,0.7)

    def test_unknown_cipher_does_not_mean_disabled(self):
        self.assertEqual(self.monitor._detect_imsi_catcher(self.row(encryption_status='Unknown')),[])
        self.assertTrue(any(t.threat_type=='ENCRYPTION_DOWNGRADE' for t in
                            self.monitor._detect_imsi_catcher(self.row(encryption_status='None'))))

    @unittest.skipUnless(source.NUMPY_AVAILABLE,'requires real NumPy for feature extraction')
    def test_actual_vector_shapes_and_zero_values(self):
        self.history()
        vector=self.monitor._extract_ml_features(self.monitor.measurement_history[-1])
        matrix=self.monitor._extract_pattern_features()
        self.assertEqual(len(vector),13)
        self.assertEqual(matrix.shape,(10,7))
        self.assertEqual(vector[1],0)
        self.assertEqual(vector[8],0)
        self.assertEqual(matrix[0,2],0)

    @unittest.skipUnless(source.NUMPY_AVAILABLE,'requires real NumPy for feature extraction')
    def test_missing_history_field_blocks_both_paths(self):
        self.history()
        self.monitor.measurement_history[0].timing_advance=None
        self.assertIsNone(self.monitor._extract_ml_features(self.monitor.measurement_history[-1]))
        self.assertIsNone(self.monitor._extract_pattern_features())
        for stage in ['ml_features','pattern_features']:
            self.assertEqual(self.monitor.analysis_status[stage]['state'],'unavailable')
            self.assertIn('timing_advance',self.monitor.analysis_status[stage]['issues'])

if __name__=='__main__':
    unittest.main(verbosity=2)
