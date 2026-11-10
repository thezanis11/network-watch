"""Validated Zeek and Suricata EVE adapters and a fixed capture split."""
from datetime import datetime
import io
import json
from pathlib import Path
import zipfile

import numpy as np
import pandas as pd


def number(value):
    if value in ('-', '(empty)', '', None):
        return 0.0
    result = float(value)
    if not np.isfinite(result) or result < 0:
        raise ValueError(f'Invalid nonnegative traffic measurement: {value}')
    return result


def port(value):
    result = number(value)
    if result != int(result) or not 0 <= result <= 65535:
        raise ValueError('Port must be an integer in 0..65535')
    return int(result)


def normalize_zeek(raw):
    start = float(raw['ts'])
    if not np.isfinite(start):
        raise ValueError('Non-finite flow timestamp')
    duration = number(raw.get('duration'))
    label = str(raw.get('label', 'Unknown'))
    return dict(start=start, available_at=start+duration, duration=duration,
                uid=str(raw.get('uid', '')), src=str(raw['id.orig_h']), dst=str(raw['id.resp_h']),
                src_port=port(raw.get('id.orig_p')), dst_port=port(raw.get('id.resp_p')),
                proto=str(raw.get('proto', 'unknown')), service=str(raw.get('service', '-')),
                state=str(raw.get('conn_state', '-')),
                sent_bytes=number(raw.get('orig_bytes')), received_bytes=number(raw.get('resp_bytes')),
                sent_packets=number(raw.get('orig_pkts')), received_packets=number(raw.get('resp_pkts')),
                label=1 if label.lower() == 'malicious' else 0 if label.lower() == 'benign' else -1,
                detailed_label=str(raw.get('detailedlabel', 'unknown')), external_signature='')


def read_zeek(stream):
    text = stream.read()
    if isinstance(text, bytes):
        text = text.decode('utf-8')
    first = next((line for line in text.splitlines() if line.strip() and not line.startswith('#')), '')
    if first.startswith('{'):
        return [normalize_zeek(json.loads(line)) for line in text.splitlines() if line.strip()]
    fields = None
    rows = []
    for line in text.splitlines():
        if line.startswith('#fields\t'):
            fields = line.split('\t')[1:]
        elif line and not line.startswith('#'):
            if fields is None:
                raise ValueError('Zeek ASCII log needs a #fields header')
            cells = line.split('\t')
            if len(cells) != len(fields):
                raise ValueError('Zeek row length differs from header')
            rows.append(normalize_zeek(dict(zip(fields, cells))))
    return rows


def read_eve(stream):
    events = []
    for line in stream:
        if not line.strip():
            continue
        item = json.loads(line)
        if item.get('event_type') not in ('flow', 'alert'):
            continue
        flow = item.get('flow', {})
        end_dt = datetime.fromisoformat(item['timestamp'].replace('Z', '+00:00'))
        start_dt = datetime.fromisoformat(flow.get('start', item['timestamp']).replace('Z', '+00:00'))
        if end_dt.tzinfo is None or start_dt.tzinfo is None:
            raise ValueError('EVE timestamps must include a timezone')
        end, start = end_dt.timestamp(), start_dt.timestamp()
        if end < start:
            raise ValueError('Flow ends before it starts')
        alert = item.get('alert', {})
        events.append(dict(start=start, available_at=end, duration=end-start,
                           uid=str(item.get('flow_id', '')), src=item['src_ip'], dst=item['dest_ip'],
                           src_port=port(item.get('src_port')), dst_port=port(item.get('dest_port')),
                           proto=item.get('proto', 'unknown').lower(), service=item.get('app_proto', '-'),
                           state='SF' if flow.get('state') in ('established', 'closed') else 'S0',
                           sent_bytes=number(flow.get('bytes_toserver')), received_bytes=number(flow.get('bytes_toclient')),
                           sent_packets=number(flow.get('pkts_toserver')), received_packets=number(flow.get('pkts_toclient')),
                           label=-1, detailed_label='unknown', external_signature=str(alert.get('signature', ''))))
    return events


def load_dataset(archive):
    captures = {}
    with zipfile.ZipFile(archive) as z:
        for name in sorted(z.namelist()):
            if name.startswith('zeek/') and name.endswith('.conn-labeled.log'):
                capture = Path(name).name.removesuffix('.conn-labeled.log')
                with z.open(name) as stream:
                    frame = pd.DataFrame(read_zeek(stream))
                # Zeek connection statistics become available only at log time,
                # approximated by connection start + observed duration.
                frame = frame.sort_values(['available_at', 'uid'], kind='stable').reset_index(drop=True)
                frame['capture'] = capture
                captures[capture] = frame
    if len(captures) != 6:
        raise ValueError('Expected six official captures')
    return captures


def assign_splits(frame, capture, purge_seconds=300):
    if 'benign-user' in capture:
        # One benign recording: chronological splits with time gaps, not random
        # rows. History is reset per partition downstream.
        a, b = np.quantile(frame.available_at, [.6, .8])
        split = np.full(len(frame), 'purged', dtype=object)
        times = frame.available_at.to_numpy()
        split[times < a-purge_seconds] = 'train'
        split[(times > a+purge_seconds) & (times < b-purge_seconds)] = 'validation'
        split[times > b+purge_seconds] = 'test'
        return split
    if capture.endswith('malware-1') or capture.endswith('portscan-1'):
        return np.full(len(frame), 'train', dtype=object)
    if capture.endswith('portscan-2'):
        return np.full(len(frame), 'validation', dtype=object)
    return np.full(len(frame), 'test', dtype=object)
