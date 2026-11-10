"""Analyze one real held-out capture and check its known-label score replay."""
from pathlib import Path
import sys
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from network_watch.benchmark import analyze

name = 'ctu-idseval-6-malicious-malware-2.conn-labeled.log'
target = ROOT/'data/raw'/name
with zipfile.ZipFile(ROOT/'data/raw/zeek.zip') as archive:
    target.write_bytes(archive.read('zeek/'+name))
analyze(target, out=ROOT/'reports/demo_incidents.csv')
