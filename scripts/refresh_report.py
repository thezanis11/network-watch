import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import pandas as pd
from network_watch.report import build_report

out = ROOT/'reports'
manifest = json.loads((out/'experiment.json').read_text(encoding='utf-8'))
prediction = pd.read_csv(out/'test_predictions.csv.gz')
traces = {r['model']: prediction['rules_score' if r['model']=='Explainable rules' else r['model'].lower().replace(' ', '_')+'_score'].to_numpy() for r in manifest['results']}
build_report(manifest, prediction, traces, pd.read_csv(out/'incidents.csv'), out)
