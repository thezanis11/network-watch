import io
import json
import unittest

import numpy as np
import pandas as pd

from network_watch.data import normalize_zeek, read_zeek, read_eve, assign_splits
from network_watch.features import OnlineFeatures, extract
from network_watch.incidents import correlate, episode_metrics
from network_watch.benchmark import metric, threshold_for


def event(t=0, src='192.0.2.1', dst='192.0.2.2', port=443, label=0, state='SF'):
    return dict(start=t, available_at=t, duration=0, uid=str(t), src=src, dst=dst, src_port=40000,
                dst_port=port, proto='tcp', service='ssl', state=state, sent_bytes=100,
                received_bytes=200, sent_packets=2, received_packets=3, label=label,
                detailed_label='test', external_signature='', capture='fixture')


class AdapterTests(unittest.TestCase):
    def test_missing_values_and_unknown_labels(self):
        raw = {'ts': 1, 'duration': '-', 'id.orig_h': '192.0.2.1', 'id.resp_h': '192.0.2.2', 'label': 'Background'}
        e = normalize_zeek(raw)
        self.assertEqual(e['label'], -1)
        self.assertEqual(e['available_at'], 1)

    def test_completion_not_start_defines_availability(self):
        raw = {'ts': 1, 'duration': 9, 'id.orig_h': '192.0.2.1', 'id.resp_h': '192.0.2.2'}
        self.assertEqual(normalize_zeek(raw)['available_at'], 10)

    def test_ascii_and_json_zeek_agree(self):
        ascii_log = '#fields\tts\tid.orig_h\tid.resp_h\tduration\tlabel\n1\t192.0.2.1\t192.0.2.2\t9\tBenign\n'
        obj = {'ts': 1, 'id.orig_h': '192.0.2.1', 'id.resp_h': '192.0.2.2', 'duration': 9, 'label': 'Benign'}
        self.assertEqual(read_zeek(io.StringIO(ascii_log)), read_zeek(io.StringIO(json.dumps(obj))))

    def test_bad_header_port_and_nonfinite_are_rejected(self):
        with self.assertRaises(ValueError):
            read_zeek(io.StringIO('1\tmissing-header\n'))
        for value in (65536, 1.5):
            with self.assertRaises(ValueError):
                normalize_zeek({'ts': 1, 'id.orig_h': 'a', 'id.resp_h': 'b', 'id.resp_p': value})
        with self.assertRaises(ValueError):
            normalize_zeek({'ts': float('nan'), 'id.orig_h': 'a', 'id.resp_h': 'b'})

    def test_eve_flow_and_signature(self):
        obj = {'timestamp': '2026-01-01T00:00:02Z', 'event_type': 'alert', 'src_ip': '192.0.2.1',
               'dest_ip': '192.0.2.2', 'dest_port': 443, 'proto': 'TCP', 'flow': {'start': '2026-01-01T00:00:00Z', 'bytes_toserver': 50},
               'alert': {'signature': 'fixture signature'}}
        e = read_eve(io.StringIO(json.dumps(obj)))[0]
        self.assertEqual(e['duration'], 2)
        self.assertEqual(e['external_signature'], 'fixture signature')
        self.assertEqual(e['label'], -1)

    def test_eve_requires_timezone_and_nonnegative_duration(self):
        obj = {'timestamp': '2026-01-01T00:00:02', 'event_type': 'flow', 'src_ip': 'a', 'dest_ip': 'b'}
        with self.assertRaises(ValueError):
            read_eve(io.StringIO(json.dumps(obj)))


class CausalityTests(unittest.TestCase):
    def test_history_uses_past_flows_not_future(self):
        a = pd.DataFrame([event(0), event(1)])
        b = pd.DataFrame([event(0), event(1), event(2, port=22, label=1)])
        fa, _, _ = extract(a)
        fb, _, _ = extract(b)
        pd.testing.assert_frame_equal(fa, fb.iloc[:2].reset_index(drop=True))
        self.assertEqual(fa.log_prior_flows.iloc[0], 0)
        self.assertAlmostEqual(fa.log_prior_flows.iloc[1], np.log(2), places=6)

    def test_labels_addresses_and_uids_are_not_model_values(self):
        a = pd.DataFrame([event(0), event(1)])
        b = a.copy()
        b['label'] = 1
        b['detailed_label'] = 'CHANGED'
        b['uid'] = 'CHANGED'
        b['src'] = '203.0.113.7'
        b['dst'] = '203.0.113.8'
        fa, _, _ = extract(a)
        fb, _, _ = extract(b)
        pd.testing.assert_frame_equal(fa, fb)
        self.assertFalse(any(s in c for c in fa.columns for s in ('label', 'uid', 'src', 'dst', 'capture')))

    def test_absolute_clock_shift_does_not_change_features(self):
        a = pd.DataFrame([event(0), event(1), event(2)])
        b = a.copy()
        b['start'] += 1000000
        b['available_at'] += 1000000
        fa, _, _ = extract(a)
        fb, _, _ = extract(b)
        pd.testing.assert_frame_equal(fa, fb)

    def test_expired_host_counts_leave_window(self):
        engine = OnlineFeatures(horizon=60)
        engine.transform_one(event(0, port=22))
        f, _, _ = engine.transform_one(event(61, port=443))
        self.assertEqual(f['log_prior_ports'], 0)

    def test_scan_rule_has_explicit_evidence(self):
        engine = OnlineFeatures()
        for i in range(25):
            _, reasons, risk = engine.transform_one(event(i, port=i+1, state='S0'))
        self.assertIn('vertical_port_scan', reasons)
        self.assertGreater(risk, 80)

    def test_unsorted_availability_is_rejected(self):
        engine = OnlineFeatures()
        engine.transform_one(event(2))
        with self.assertRaises(ValueError):
            engine.transform_one(event(1))

    def test_temporal_splits_have_real_purge_gaps(self):
        frame = pd.DataFrame({'available_at': np.arange(10000, dtype=float)})
        splits = assign_splits(frame, 'benign-user')
        a = frame.available_at.to_numpy()[splits == 'train']
        b = frame.available_at.to_numpy()[splits == 'validation']
        self.assertGreater(b.min()-a.max(), 600)


class IncidentAndMetricTests(unittest.TestCase):
    def test_correlation_ignores_labels_for_grouping(self):
        a = pd.DataFrame([event(0, label=0), event(1, label=1)])
        b = a.copy()
        b['label'] = -1
        ia = correlate(a, [1, 1], [1., 1.], ['same', 'same'])
        ib = correlate(b, [1, 1], [1., 1.], ['same', 'same'])
        self.assertEqual(len(ia), 1)
        self.assertEqual(ia.alert_flows.tolist(), ib.alert_flows.tolist())
        self.assertEqual(ib.retrospective_status.iloc[0], 'unscored_unknown_present')

    def test_gap_splits_incidents_and_reference_episodes(self):
        frame = pd.DataFrame([event(0, label=1), event(500, label=1)])
        self.assertEqual(len(correlate(frame, [1, 1], [1., 1.], ['x', 'x'])), 2)
        episodes = episode_metrics(frame, [0, 1])
        self.assertEqual(len(episodes), 2)
        self.assertFalse(episodes[0]['detected'])
        self.assertTrue(episodes[1]['detected'])

    def test_constant_positive_baseline_exposes_imbalance(self):
        y = np.r_[np.zeros(2), np.ones(98)]
        m = metric(y, np.ones(100), .5)
        self.assertGreater(m['f1'], .98)
        self.assertEqual(m['balanced_accuracy'], .5)
        self.assertEqual(m['mcc'], 0)

    def test_strict_threshold_uses_validation_benign(self):
        y = np.r_[np.zeros(100), np.ones(5)]
        scores = np.r_[np.arange(100), np.full(5, 200)]
        threshold = threshold_for(y, scores, low_fpr=True)
        self.assertLessEqual(np.mean(scores[y == 0] > threshold), .01)


if __name__ == '__main__':
    unittest.main()
