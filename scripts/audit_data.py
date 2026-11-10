"""Record source-count discrepancies, duplicate checks and purge accounting."""
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from network_watch.data import load_dataset, assign_splits

captures = load_dataset(ROOT/'data/raw/zeek.zip')
documentation = (ROOT/'data/raw/README.md').read_text(encoding='utf-8')
match = re.search(r'([\d,]+) labeled network flows', documentation)
declared = int(match.group(1).replace(',', '')) if match else None
records = []
for name, frame in captures.items():
    splits = assign_splits(frame, name)
    records.append(dict(capture=name, raw_flows=len(frame), duplicate_uids=int(frame.uid.duplicated().sum()),
                        benign=int((frame.label==0).sum()), malicious=int((frame.label==1).sum()),
                        background=int((frame.label<0).sum()), purged=int((splits=='purged').sum())))
actual = sum(i['raw_flows'] for i in records)
result = dict(declared_in_author_readme=declared, actual_parsed_log_rows=actual,
              difference=None if declared is None else actual-declared, captures=records,
              interpretation='Exact checked source files are authoritative for this run; do not invent missing rows to match documentation.')
folder = ROOT/'reports'
folder.mkdir(exist_ok=True)
(folder/'data_quality.json').write_text(json.dumps(result, indent=2), encoding='utf-8')
print(json.dumps(result, indent=2))
