"""Correlate alerts without labels; score reference episodes separately."""
import hashlib

import numpy as np
import pandas as pd


def host_alias(host):
    return 'host-' + hashlib.sha256(str(host).encode()).hexdigest()[:10]


def correlate(frame, alerts, scores, reasons, gap_seconds=120):
    active = {}
    finished = []
    for i, event in enumerate(frame.to_dict('records')):
        if not alerts[i]:
            continue
        reason = reasons[i] or 'behavioral_model'
        key = (event['capture'], event['src'], reason)
        incident = active.get(key)
        if incident is None or event['available_at'] - incident['last_seen'] > gap_seconds:
            if incident is not None:
                finished.append(incident)
            incident = dict(capture=event['capture'], host=host_alias(event['src']), reason=reason,
                            first_seen=event['available_at'], last_seen=event['available_at'],
                            alert_flows=0, max_score=0.0, malicious=0, benign=0, unknown=0)
            active[key] = incident
        incident['last_seen'] = event['available_at']
        incident['alert_flows'] += 1
        incident['max_score'] = max(incident['max_score'], float(scores[i]))
        # Labels attached only for retrospective evaluation, never correlation.
        incident['malicious' if event['label'] == 1 else 'benign' if event['label'] == 0 else 'unknown'] += 1
    finished.extend(active.values())
    for item in finished:
        item['retrospective_status'] = ('contains_labeled_attack' if item['malicious'] else
                                        'unscored_unknown_present' if item['unknown'] else 'labeled_benign_only')
    return pd.DataFrame(finished).sort_values('first_seen').reset_index(drop=True) if finished else pd.DataFrame()


def episode_metrics(frame, alerts, gap_seconds=300):
    """Reference episodes are derived from labeled malicious flows, not expert incidents."""
    episodes = []
    tmp = frame.copy()
    tmp['alert'] = np.asarray(alerts, dtype=bool)
    positives = tmp.loc[tmp.label == 1]
    for (capture, src, detail), group in positives.groupby(['capture', 'src', 'detailed_label']):
        group = group.sort_values('available_at')
        partitions = (group.available_at.diff().fillna(0) > gap_seconds).cumsum()
        for _, part in group.groupby(partitions):
            detected = part.loc[part.alert]
            episodes.append(dict(capture=capture, host=host_alias(src), behavior=detail,
                                 start=float(part.available_at.min()), end=float(part.available_at.max()),
                                 flows=len(part), detected=bool(len(detected)),
                                 first_detection_delay_seconds=float(detected.available_at.min()-part.available_at.min()) if len(detected) else None))
    return episodes
