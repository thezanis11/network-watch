"""Fixed capture/temporal split, causal preprocessing, training and incident audit."""
import hashlib
import json
from pathlib import Path
import platform
import time

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import average_precision_score, confusion_matrix, f1_score, matthews_corrcoef, precision_score, recall_score, roc_auc_score

from .data import load_dataset, assign_splits, read_zeek, read_eve
from .features import extract
from .incidents import correlate, episode_metrics

ROOT = Path(__file__).resolve().parents[1]
SEED = 42


def metric(y, scores, threshold):
    y = np.asarray(y, dtype=int)
    alert = np.asarray(scores) > threshold
    tn, fp, fn, tp = confusion_matrix(y, alert, labels=[0, 1]).ravel()
    return dict(flows=len(y), attacks=int(y.sum()), precision=float(precision_score(y, alert, zero_division=0)),
                recall=float(recall_score(y, alert, zero_division=0)), f1=float(f1_score(y, alert, zero_division=0)),
                average_precision=float(average_precision_score(y, scores)) if len(np.unique(y)) == 2 else None,
                roc_auc=float(roc_auc_score(y, scores)) if len(np.unique(y)) == 2 else None,
                false_positive_rate=float(fp/(fp+tn)) if fp+tn else None,
                balanced_accuracy=float(.5*(tp/(tp+fn)+tn/(tn+fp))) if tp+fn and tn+fp else None,
                mcc=float(matthews_corrcoef(y, alert)) if len(np.unique(y)) == 2 else None,
                false_positive_flows=int(fp), detected_attack_flows=int(tp), missed_attack_flows=int(fn))


def threshold_for(y, scores, low_fpr=False):
    benign = np.asarray(scores)[np.asarray(y) == 0]
    if not len(benign):
        raise ValueError('Validation needs known benign flows')
    if low_fpr:
        return float(np.quantile(benign, .99, method='higher'))
    candidates = np.unique(np.r_[np.nextafter(min(scores), -np.inf), np.quantile(scores, np.linspace(0, 1, 401))])
    values = [f1_score(y, scores > t, zero_division=0) for t in candidates]
    return float(candidates[int(np.argmax(values))])


def score_model(model, x):
    if isinstance(model, IsolationForest):
        return -model.score_samples(x)
    return model.predict_proba(x)[:, 1]


def prepare():
    target = ROOT / 'data/processed'
    target.mkdir(parents=True, exist_ok=True)
    signature = hashlib.sha256(b''.join(Path(__file__).with_name(n).read_bytes() for n in ('data.py', 'features.py'))).hexdigest()
    path = target / f'flows-{signature[:12]}.pkl'
    if path.exists():
        return pd.read_pickle(path), signature
    captures = load_dataset(ROOT / 'data/raw/zeek.zip')
    blocks = []
    for capture, frame in captures.items():
        frame['split'] = assign_splits(frame, capture)
        for split, part in frame.groupby('split', sort=True):
            if split == 'purged':
                continue
            part = part.reset_index(drop=True)
            features, reasons, risk = extract(part)
            features = features.add_prefix('f_')
            block = pd.concat([part, features], axis=1)
            block['rule_reasons'] = reasons
            block['rule_score'] = risk
            blocks.append(block)
            print(f'{capture} / {split}: {len(part):,} completed flows', flush=True)
    all_flows = pd.concat(blocks, ignore_index=True)
    all_flows.to_pickle(path)
    return all_flows, signature


def benchmark():
    out = ROOT / 'reports'
    models = ROOT / 'models'
    out.mkdir(exist_ok=True)
    models.mkdir(exist_ok=True)
    frame, signature = prepare()
    columns = sorted(c for c in frame if c.startswith('f_'))
    known = frame.loc[frame.label >= 0].reset_index(drop=True)
    parts = {s: known.loc[known.split == s].reset_index(drop=True) for s in ('train', 'validation', 'test')}
    x = {s: p[columns].to_numpy(dtype=np.float32) for s, p in parts.items()}
    y = {s: p.label.to_numpy(dtype=int) for s, p in parts.items()}
    definitions = {
        'Logistic Regression': make_pipeline(StandardScaler(), LogisticRegression(C=1, class_weight='balanced', max_iter=1000, random_state=SEED)),
        'Isolation Forest': IsolationForest(n_estimators=160, max_samples=4096, random_state=SEED, n_jobs=2),
        'Random Forest': RandomForestClassifier(n_estimators=180, min_samples_leaf=5, max_features='sqrt', class_weight='balanced_subsample', n_jobs=2, random_state=SEED),
        'Random Forest without history': RandomForestClassifier(n_estimators=180, min_samples_leaf=5, max_features='sqrt', class_weight='balanced_subsample', n_jobs=2, random_state=SEED),
    }
    history_words = ('prior_', 'pair_')
    local_columns = [i for i, c in enumerate(columns) if not any(word in c for word in history_words)]
    results = []
    prediction = parts['test'][['capture', 'available_at', 'label', 'detailed_label']].copy()
    traces = {}
    artifacts = {}
    for name, model in definitions.items():
        indices = local_columns if name.endswith('without history') else list(range(len(columns)))
        train_x = x['train'][:, indices]
        train_y = y['train']
        begin = time.perf_counter()
        if isinstance(model, IsolationForest):
            model.fit(train_x[train_y == 0])
        else:
            model.fit(train_x, train_y)
        elapsed = time.perf_counter()-begin
        val_scores = score_model(model, x['validation'][:, indices])
        threshold = threshold_for(y['validation'], val_scores)
        strict = threshold_for(y['validation'], val_scores, low_fpr=True)
        begin = time.perf_counter()
        test_scores = score_model(model, x['test'][:, indices])
        scoring_time = time.perf_counter()-begin
        result = dict(model=name, train_seconds=elapsed, score_seconds=scoring_time, threshold=threshold,
                      validation=metric(y['validation'], val_scores, threshold), test=metric(y['test'], test_scores, threshold),
                      low_fpr=dict(threshold=strict, validation=metric(y['validation'], val_scores, strict), test=metric(y['test'], test_scores, strict)))
        result['by_capture'] = {capture: metric(part.label.to_numpy(), test_scores[parts['test'].capture.to_numpy() == capture], threshold)
                                for capture, part in parts['test'].groupby('capture', sort=True)}
        slug = name.lower().replace(' ', '_')
        artifacts[name] = dict(model=model, columns=[columns[i] for i in indices], threshold=threshold, name=name, schema_version=1,
                               sklearn_version=sklearn.__version__,
                               privacy='addresses and absolute timestamps excluded from model features')
        joblib.dump(artifacts[name], models / f'{slug}.joblib', compress=3)
        prediction[f'{slug}_score'] = test_scores
        traces[name] = test_scores
        results.append(result)
        print(f'{name}: val F1={result["validation"]["f1"]:.3f}, test F1={result["test"]["f1"]:.3f}', flush=True)
    rule_scores = parts['test'].rule_score.to_numpy()
    rule_result = dict(model='Explainable rules', threshold=44, validation=metric(y['validation'], parts['validation'].rule_score.to_numpy(), 44),
                       test=metric(y['test'], rule_scores, 44))
    rule_result['by_capture'] = {capture: metric(part.label.to_numpy(), part.rule_score.to_numpy(), 44) for capture, part in parts['test'].groupby('capture')}
    results.append(rule_result)
    traces['Explainable rules'] = rule_scores
    prediction['rules_score'] = rule_scores
    # Selection uses validation only; the rules can win without needing a model artifact.
    champion = max(results, key=lambda r: r['validation']['f1'])
    # A high F1 can be trivial on attack-heavy traffic: publish constant baselines.
    for name, value in [('Always benign', 0.0), ('Always malicious', 1.0)]:
        scores = np.full(len(parts['test']), value)
        dummy = dict(model=name, threshold=.5,
                     validation=metric(y['validation'], np.full(len(y['validation']), value), .5),
                     test=metric(y['test'], scores, .5))
        dummy['by_capture'] = {capture: metric(part.label.to_numpy(), np.full(len(part), value), .5) for capture, part in parts['test'].groupby('capture')}
        results.append(dummy)
        traces[name] = scores
        prediction[name.lower().replace(' ', '_') + '_score'] = scores
    if champion['model'] in artifacts:
        joblib.dump(artifacts[champion['model']], models / 'champion.joblib', compress=3)
    else:
        joblib.dump(dict(name='Explainable rules', threshold=44, columns=columns, schema_version=1), models / 'champion.joblib')
    # Operational correlation sees even unknown/background flows. Retrospective
    # truth annotations are attached after correlation and never used to group.
    full_test = frame.loc[frame.split == 'test'].reset_index(drop=True)
    artifact = joblib.load(models / 'champion.joblib')
    full_scores = full_test.rule_score.to_numpy() if champion['model'] == 'Explainable rules' else score_model(artifact['model'], full_test[artifact['columns']].to_numpy(dtype=np.float32))
    alerts = full_scores > artifact['threshold']
    incidents = correlate(full_test, alerts, full_scores, full_test.rule_reasons.to_numpy())
    incidents.to_csv(out / 'incidents.csv', index=False)
    episodes = episode_metrics(full_test, alerts)
    (out / 'reference_episodes.json').write_text(json.dumps(episodes, indent=2, allow_nan=False), encoding='utf-8')
    prediction.to_csv(out / 'test_predictions.csv', index=False)
    prediction.to_csv(out / 'test_predictions.csv.gz', index=False, compression={'method': 'gzip', 'mtime': 0})
    pd.DataFrame([dict(model=r['model'], **r['test']) for r in results]).to_csv(out / 'metrics.csv', index=False)
    importance = pd.DataFrame(dict(feature=columns, importance=definitions['Random Forest'].feature_importances_)).sort_values('importance', ascending=False)
    importance.to_csv(out / 'feature_importance.csv', index=False)
    inventory = []
    for (capture, split), part in frame.groupby(['capture', 'split'], sort=True):
        inventory.append(dict(capture=capture, split=split, flows=len(part), benign=int((part.label==0).sum()),
                              malicious=int((part.label==1).sum()), unknown=int((part.label<0).sum()),
                              start_available=float(part.available_at.min()), end_available=float(part.available_at.max())))
    manifest = dict(dataset='CTU-IDSEVAL-6', seed=SEED, python=platform.python_version(), feature_recipe_sha256=signature,
                    sklearn_version=sklearn.__version__,
                    study_status='exploratory benchmark; test inspected during evaluation development; fixed split and model recipe, not a blind final audit',
                    feature_columns=columns, features=len(columns), inventory=inventory, evaluated_test_flows=len(parts['test']),
                    observed_flows=len(frame), unknown_flows_excluded_from_binary=int((frame.label<0).sum()),
                    provenance=json.loads((ROOT / 'data/raw/provenance.json').read_text(encoding='utf-8')),
                    champion=champion['model'], selection='maximum validation F1; no test-guided tuning', results=results,
                    incidents=len(incidents), alert_flows=int(alerts.sum()), reference_episodes=len(episodes),
                    episode_recall=float(np.mean([e['detected'] for e in episodes])) if episodes else None,
                    operational_incident_status=incidents.retrospective_status.value_counts().to_dict() if len(incidents) else {},
                    caveats=['Background is unknown, not benign; excluded from binary metrics but retained in causal history',
                             'Benign recording split chronologically with 300 s purges; other captures kept intact',
                             'Available time approximated as connection start + duration, not original log ingestion timestamp',
                             'Flow completion can introduce detection latency beyond measured episode delay',
                             'One held-out malware capture and one large held-out scan limit statistical generalization',
                             'Suricata EVE adapter is fixture-tested; no Suricata deployment benchmark claimed',
                             'Reference episodes are label-derived, not independently annotated incidents'])
    (out / 'experiment.json').write_text(json.dumps(manifest, indent=2, allow_nan=False), encoding='utf-8')
    from .report import build_report
    build_report(manifest, prediction, traces, incidents, out)
    return manifest


def analyze(path, format='zeek', model_path=None, out=None):
    artifact = joblib.load(model_path or ROOT/'models/champion.joblib')
    with Path(path).open('r', encoding='utf-8') as source:
        events = read_eve(source) if format == 'eve' else read_zeek(source)
    frame = pd.DataFrame(events).sort_values(['available_at', 'uid'], kind='stable').reset_index(drop=True)
    frame['capture'] = Path(path).name
    features, reasons, rules = extract(frame)
    features = features.add_prefix('f_')
    scores = rules if artifact['name'] == 'Explainable rules' else score_model(artifact['model'], features[artifact['columns']].to_numpy(dtype=np.float32))
    incidents = correlate(frame, scores > artifact['threshold'], scores, reasons)
    destination = Path(out or ROOT/'reports/local_incidents.csv')
    destination.parent.mkdir(parents=True, exist_ok=True)
    incidents.to_csv(destination, index=False)
    print(f'{len(events)} completed flow events; {len(incidents)} correlated incidents; output: {destination}', flush=True)


if __name__ == '__main__':
    benchmark()
