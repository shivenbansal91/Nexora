"""Train application-event models on independent generator partitions.

Run: python -m detection.train_baseline. Existing artifacts are backed up first.
Flow benchmarks remain separate. Live flags still come from explainable rules.
"""
from __future__ import annotations

import json
import shutil
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'p2-pipeline'))
from simulator.generator import NormalTrafficGenerator, iso  # noqa: E402
from simulator.injectors import AttackInjector, ATTACK_TYPES  # noqa: E402
from .features import FEATURE_NAMES, events_to_matrix  # noqa: E402
from .benchmark_cicids import calibrate_threshold  # noqa: E402

MODELS_DIR = Path(__file__).resolve().parent / 'models'
PROCESSED_DIR = ROOT / 'data' / 'processed'


def _spread_timestamps(events, base, step_s=3.0):
    for index, event in enumerate(events):
        event.timestamp = iso(base + timedelta(seconds=index * step_s))
    return events


def build_dataset(n_benign_windows=400, n_attack_each=120, seed=42):
    """Each call generates whole windows from its own seed before extraction."""
    gen, inj, rng = NormalTrafficGenerator(seed=seed), AttackInjector(seed=seed), np.random.default_rng(seed)
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    matrices, labels = [], []
    kinds = [None] * n_benign_windows + [k for k in ATTACK_TYPES for _ in range(n_attack_each)]
    for index, kind in enumerate(kinds):
        start = base + timedelta(minutes=index * 20)
        normal = list(gen.stream_sessions(3)) if index % 2 else list(gen.stream(15))
        events = [e.to_dict() for e in _spread_timestamps(normal, start, float(rng.uniform(1, 5)))]
        if kind:
            attack = [e.to_dict() for e in inj.inject(kind, start + timedelta(seconds=20))]
            # Both normal and compressed demo timing are represented.
            if index % 2:
                for j, e in enumerate(attack):
                    e['timestamp'] = iso(start + timedelta(seconds=20 + j * 6 / max(1, len(attack)-1)))
            if kind == 'brute_force' and index % 3 == 0:
                for j, e in enumerate(attack):
                    if e['event_type'] == 'auth_login_failure':
                        e.update(ip=f'192.0.2.{j+1}', session=f'failure-{seed}-{index}-{j}')
            events.extend(attack)
        elif index % 4 == 0:
            # Legitimate bulk exports overlap attacks in volume; identity/context matters.
            export = [e.to_dict() for e in inj.inject('data_exfiltration', start + timedelta(seconds=30))]
            for e in export:
                e['attack_label'] = 'benign'
            events.extend(export)
        elif index % 4 == 1:
            retries = [e.to_dict() for e in inj.inject('port_scan', start + timedelta(seconds=30))]
            for e in retries:
                e['metadata']['dest_port'] = 443
                e['attack_label'] = 'benign'
            events.extend(retries)
        matrix, order = events_to_matrix(events)
        matrices.append(matrix)
        labels.extend(events[i].get('attack_label') or 'benign' for i in order)
    return np.vstack(matrices), np.array(labels)


def _anomaly_detection_metrics(model, norm, X_te, y_te, threshold=.6):
    from sklearn.metrics import precision_score, recall_score, f1_score
    raw = -model.score_samples(X_te)
    span = norm['p99'] - norm['p1'] or 1.0
    scores = np.clip(.6 + (raw - norm['raw_threshold']) / span, 0, 1) if 'raw_threshold' in norm else np.clip((raw - norm['p1']) / span, 0, 1)
    truth, predicted = y_te != 'benign', scores >= threshold
    return dict(model='IsolationForest, benign fit; validation-calibrated', threshold=threshold,
                precision=round(float(precision_score(truth,predicted,zero_division=0)),4),
                recall=round(float(recall_score(truth,predicted,zero_division=0)),4),
                f1=round(float(f1_score(truth,predicted,zero_division=0)),4),
                false_positive_rate_benign=round(float(predicted[~truth].mean()),4) if (~truth).any() else None)


def main():
    import joblib
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.metrics import classification_report

    # Seeds and final test set are fixed before candidate selection.
    train, validation, test = [build_dataset(400 if s == 42 else 150, 120 if s == 42 else 45, seed=s) for s in (42,43,45)]
    X_train,y_train = train
    X_val,y_val = validation
    X_test,y_test = test
    benign = X_train[y_train == 'benign']
    candidates = []
    for samples in (256,1024,4096):
        model = IsolationForest(n_estimators=200,max_samples=samples,random_state=42,n_jobs=-1).fit(benign)
        threshold, f1 = calibrate_threshold(-model.score_samples(X_val), (y_val != 'benign').astype(int), max_fpr=.02)
        candidates.append((f1,samples,threshold,model))
    _, samples, threshold, model = max(candidates,key=lambda item:item[0])
    raw = -model.score_samples(benign)
    norm = dict(p1=float(np.percentile(raw,1)),p99=float(np.percentile(raw,99)),raw_threshold=threshold,
                feature_names=FEATURE_NAMES, score_interpretation='0.6 is the validation-selected review threshold, not a probability')
    anomaly = _anomaly_detection_metrics(model,norm,X_test,y_test)
    anomaly['per_attack_recall'] = {k: _anomaly_detection_metrics(model,norm,X_test[(y_test==k)|(y_test=='benign')],y_test[(y_test==k)|(y_test=='benign')])['recall'] for k in ATTACK_TYPES}
    classifier = RandomForestClassifier(n_estimators=200,max_depth=16,min_samples_leaf=3,class_weight='balanced',random_state=42,n_jobs=-1).fit(X_train,y_train)
    report = classification_report(y_test,classifier.predict(X_test),output_dict=True,zero_division=0)
    metrics = dict(source='simulated', generated_at=datetime.now(timezone.utc).isoformat(),
                   note='Independent generated windows, seeds 42/43/45 for train/validation/final test. Development seed 44 exposed missing destination-diversity features; final seed 45 is excluded from selection. Severity and time-of-day excluded. Benign examples include bulk exports and connection retries. IF fits benign training events; its threshold and sample count use labelled validation data with a 2% benign FPR budget. Synthetic performance does not establish real-log accuracy; live alert flags remain rule-based.',
                   n_train=len(y_train),n_validation=len(y_val),n_test=len(y_test),
                   partition_seeds=dict(train=42,validation=43,test=45),feature_names=FEATURE_NAMES,
                   model='RandomForestClassifier, 200 trees, depth 16, minimum leaf 3',
                   macro_f1=round(report['macro avg']['f1-score'],4),accuracy=round(report['accuracy'],4),
                   per_class={k:dict(precision=v['precision'],recall=v['recall'],f1=v['f1-score'],support=int(v['support'])) for k,v in report.items() if k in ['benign']+ATTACK_TYPES},
                   anomaly_detection=anomaly,false_positive_rate_benign=anomaly['false_positive_rate_benign'],
                   calibration=dict(max_samples=samples,validation_fpr_budget=.02,raw_threshold=threshold))
    MODELS_DIR.mkdir(exist_ok=True)
    backup = MODELS_DIR / 'backups' / datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%f')
    backup.mkdir(parents=True)
    for path in MODELS_DIR.glob('*'):
        if path.is_file(): shutil.copy2(path,backup/path.name)
    joblib.dump(model,MODELS_DIR/'isoforest.joblib')
    joblib.dump(classifier,MODELS_DIR/'classifier.joblib')
    (MODELS_DIR/'isoforest_norm.json').write_text(json.dumps(norm,indent=2))
    (MODELS_DIR/'metrics.json').write_text(json.dumps(metrics,indent=2))
    PROCESSED_DIR.mkdir(parents=True,exist_ok=True)
    (PROCESSED_DIR/'metrics.json').write_text(json.dumps(metrics,indent=2))
    print(json.dumps(metrics,indent=2))
    print(f'Previous artifacts backed up: {backup}')


if __name__ == '__main__':
    main()
