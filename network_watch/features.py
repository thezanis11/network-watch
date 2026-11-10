"""Online features use completed current flows and earlier observations only."""
from collections import Counter, defaultdict, deque
import math

import numpy as np
import pandas as pd

FAILED = {'S0', 'REJ', 'RSTO', 'RSTR', 'RSTOS0', 'RSTRH', 'SH', 'SHR'}


class HostHistory:
    def __init__(self):
        self.events = deque()
        self.ports = Counter()
        self.hosts = Counter()
        self.failed = 0
        self.sent = self.received = 0.0

    def expire(self, now, horizon):
        while self.events and self.events[0][0] < now-horizon:
            _, port, dst, failed, sent, received = self.events.popleft()
            self.ports[port] -= 1
            self.hosts[dst] -= 1
            if not self.ports[port]:
                del self.ports[port]
            if not self.hosts[dst]:
                del self.hosts[dst]
            self.failed -= failed
            self.sent -= sent
            self.received -= received

    def add(self, event):
        failed = int(event['state'] in FAILED)
        self.events.append((event['available_at'], event['dst_port'], event['dst'], failed,
                            event['sent_bytes'], event['received_bytes']))
        self.ports[event['dst_port']] += 1
        self.hosts[event['dst']] += 1
        self.failed += failed
        self.sent += event['sent_bytes']
        self.received += event['received_bytes']


class OnlineFeatures:
    def __init__(self, horizon=60.0):
        self.horizon = horizon
        self.hosts = defaultdict(HostHistory)
        self.pairs = {}
        self.last_time = -float('inf')

    def transform_one(self, event):
        now = event['available_at']
        if now < self.last_time:
            raise ValueError('Online features require availability-time ordering')
        self.last_time = now
        history = self.hosts[event['src']]
        history.expire(now, self.horizon)
        count = len(history.events)
        pair = (event['src'], event['dst'], event['dst_port'])
        if pair not in self.pairs:
            self.pairs[pair] = (now, deque(maxlen=12))
        previous, intervals = self.pairs[pair]
        prior_mean = float(np.mean(intervals)) if intervals else 0.0
        prior_cv = float(np.std(intervals)/max(prior_mean, 1e-9)) if len(intervals) >= 3 else 1.0
        elapsed = now-previous
        features = dict(log_duration=math.log1p(event['duration']),
                        log_sent=math.log1p(event['sent_bytes']), log_received=math.log1p(event['received_bytes']),
                        log_sent_packets=math.log1p(event['sent_packets']), log_received_packets=math.log1p(event['received_packets']),
                        byte_asymmetry=(event['sent_bytes']-event['received_bytes'])/max(event['sent_bytes']+event['received_bytes'], 1),
                        packet_asymmetry=(event['sent_packets']-event['received_packets'])/max(event['sent_packets']+event['received_packets'], 1),
                        failed=int(event['state'] in FAILED), no_response=int(event['received_packets'] == 0),
                        tcp=int(event['proto'] == 'tcp'), udp=int(event['proto'] == 'udp'), icmp=int(event['proto'] in ('icmp', 'icmp6')),
                        service_dns=int('dns' in event['service'].lower()), service_tls=int(event['service'] in ('ssl', 'tls')),
                        service_http=int(event['service'] == 'http'), well_known_port=int(event['dst_port'] < 1024),
                        high_port=int(event['dst_port'] >= 49152),
                        log_prior_flows=math.log1p(count), log_prior_ports=math.log1p(len(history.ports)),
                        log_prior_destinations=math.log1p(len(history.hosts)),
                        prior_failure_fraction=history.failed/max(count, 1),
                        prior_byte_asymmetry=(history.sent-history.received)/max(history.sent+history.received, 1),
                        log_pair_gap=math.log1p(max(0, elapsed)), pair_samples=len(intervals),
                        log_pair_interval_mean=math.log1p(prior_mean), pair_interval_cv=min(prior_cv, 10.0))
        # Rule evidence is independent from supplied labels and external signatures.
        reasons = []
        if count >= 20 and len(history.ports) >= 15 and history.failed/max(count, 1) >= .7:
            reasons.append('vertical_port_scan')
        if count >= 30 and len(history.hosts) >= 20 and history.failed/max(count, 1) >= .6:
            reasons.append('horizontal_scan')
        if len(intervals) >= 8 and prior_cv < .12 and 1 <= prior_mean <= 600 and event['sent_bytes']+event['received_bytes'] < 5000:
            reasons.append('periodic_small_flow')
        if event.get('external_signature'):
            reasons.append('suricata_signature')
        risk = min(100, 85*int('vertical_port_scan' in reasons or 'horizontal_scan' in reasons) +
                   45*int('periodic_small_flow' in reasons) + 90*int('suricata_signature' in reasons))
        history.add(event)
        if elapsed > 0:
            intervals.append(elapsed)
        self.pairs[pair] = (now, intervals)
        return features, reasons, risk


def extract(frame):
    engine = OnlineFeatures()
    rows, evidence, risks = [], [], []
    for event in frame.to_dict('records'):
        features, reasons, risk = engine.transform_one(event)
        rows.append(features)
        evidence.append('|'.join(reasons))
        risks.append(risk)
    return pd.DataFrame(rows, dtype=np.float32), evidence, np.asarray(risks, dtype=np.float32)
