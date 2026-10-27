"""
Train the detection models on *simulated* data and write the metrics the
dashboard reports.

Run:  python -m detection.train_baseline     (from repo root)

Produces, under detection/models/:
  - isoforest.joblib        IsolationForest fit on normal traffic only
  - isoforest_norm.json     score normalisation (p1/p99) for anomaly_score
  - classifier.joblib       RandomForest attack-type classifier
  - metrics.json            per-class precision/recall/F1 + confusion + FPR

metrics.json is also copied to data/processed/metrics.json for the backend
/metrics endpoint. These are honestly labelled "simulated" per plan §4 — the
real-dataset numbers come from detection/benchmark_cicids.py.
"""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import numpy as np

# Make 'simulator' importable (p2-pipeline has a hyphen -> not a package name).
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "p2-pipeline"))

from simulator.generator import NormalTrafficGenerator  # noqa: E402
from simulator.injectors import AttackInjector, ATTACK_TYPES  # noqa: E402

from .features import events_to_matrix  # noqa: E402

MODELS_DIR = Path(__file__).resolve().parent / "models"
MODELS_DIR.mkdir(exist_ok=True)
PROCESSED_DIR = ROOT / "data" / "processed"


def _spread_timestamps(events, base, step_s=3.0):
    """Normal generator stamps everything at 'now'; spread a batch out in time
    so rolling-context features are meaningful."""
    from simulator.generator import iso
    t = base
    for e in events:
        e.timestamp = iso(t)
        t += timedelta(seconds=step_s)
    return events


def build_dataset(n_benign_windows=400, n_attack_each=120, seed=42):
    gen = NormalTrafficGenerator(seed=seed)
    inj = AttackInjector(seed=seed)
    X_parts, y_parts = [], []
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)

    # Benign-only windows
    for k in range(n_benign_windows):
        evs = _spread_timestamps(list(gen.stream_sessions(3)), base + timedelta(minutes=5 * k))
        dicts = [e.to_dict() for e in evs]
        X, order = events_to_matrix(dicts)
        X_parts.append(X)
        y_parts.extend(["benign"] * len(order))

    # Attack windows: one injected attack embedded in benign traffic
    offset = n_benign_windows
    for atk_i, atk in enumerate(ATTACK_TYPES):
        for k in range(n_attack_each):
            win_base = base + timedelta(minutes=5 * (offset + atk_i * n_attack_each + k))
            benign = _spread_timestamps(list(gen.stream_sessions(2)), win_base)
            attack = inj.inject(atk, start_time=win_base + timedelta(seconds=20))
            dicts = [e.to_dict() for e in benign] + [e.to_dict() for e in attack]
            X, order = events_to_matrix(dicts)
            labels = [d.get("attack_label") or "benign" for d in dicts]
            X_parts.append(X)
            y_parts.extend([labels[i] for i in order])

    X = np.vstack(X_parts)
    y = np.array(y_parts)
    return X, y


def train_isolation_forest(seed=42):
    from sklearn.ensemble import IsolationForest
    import joblib

    gen = NormalTrafficGenerator(seed=seed)
    base = datetime(2026, 1, 1, tzinfo=timezone.utc)
    dicts = []
    for k in range(600):
        evs = _spread_timestamps(list(gen.stream_sessions(3)), base + timedelta(minutes=2 * k))
        dicts.extend(e.to_dict() for e in evs)

    X, _ = events_to_matrix(dicts)
    iso = IsolationForest(n_estimators=200, contamination="auto", random_state=seed, n_jobs=-1)
    iso.fit(X)
    raw = -iso.score_samples(X)
    norm = {"p1": float(np.percentile(raw, 1)), "p99": float(np.percentile(raw, 99))}

    joblib.dump(iso, MODELS_DIR / "isoforest.joblib")
    (MODELS_DIR / "isoforest_norm.json").write_text(json.dumps(norm, indent=2))
    print(f"[isoforest] trained on {len(X)} normal events; norm={norm}")
    return iso


def _anomaly_detection_metrics(iso, norm, X_te, y_te, threshold=0.6):
    """Evaluate the UNSUPERVISED IsolationForest as an attack/benign anomaly
    detector on held-out data. This is the honest, transferable number — unlike
    the supervised classifier, the IF never sees labels, so it does not trivially
    separate simulated attacks. Mirrors the notebook's IF evaluation."""
    from sklearn.metrics import precision_score, recall_score, f1_score
    raw = -iso.score_samples(X_te)
    span = (norm["p99"] - norm["p1"]) or 1.0
    scores = np.clip((raw - norm["p1"]) / span, 0.0, 1.0)
    y_true = (y_te != "benign").astype(int)
    y_hat = (scores >= threshold).astype(int)
    return {
        "model": "IsolationForest (unsupervised), attack-vs-benign",
        "threshold": threshold,
        "precision": round(float(precision_score(y_true, y_hat, zero_division=0)), 4),
        "recall": round(float(recall_score(y_true, y_hat, zero_division=0)), 4),
        "f1": round(float(f1_score(y_true, y_hat, zero_division=0)), 4),
    }


def train_classifier(seed=42, iso=None, norm=None):
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    import joblib

    print("[classifier] building labeled dataset ...")
    X, y = build_dataset(seed=seed)
    print(f"[classifier] dataset: {X.shape[0]} events, classes={dict(zip(*np.unique(y, return_counts=True)))}")

    X_tr, X_te, y_tr, y_te = train_test_split(
        X, y, test_size=0.3, random_state=seed, stratify=y
    )
    clf = RandomForestClassifier(
        n_estimators=200, class_weight="balanced", random_state=seed, n_jobs=-1
    )
    clf.fit(X_tr, y_tr)
    y_pred = clf.predict(X_te)

    report = classification_report(y_te, y_pred, output_dict=True, zero_division=0)
    labels_sorted = sorted(np.unique(y))
    cm = confusion_matrix(y_te, y_pred, labels=labels_sorted).tolist()

    # False-positive rate on benign (benign predicted as any attack)
    benign_idx = labels_sorted.index("benign") if "benign" in labels_sorted else None
    fpr = None
    if benign_idx is not None:
        benign_total = sum(cm[benign_idx])
        benign_fp = benign_total - cm[benign_idx][benign_idx]
        fpr = round(benign_fp / benign_total, 4) if benign_total else None

    joblib.dump(clf, MODELS_DIR / "classifier.joblib")

    anomaly = None
    if iso is not None and norm is not None:
        anomaly = _anomaly_detection_metrics(iso, norm, X_te, y_te)
        print(f"[anomaly] IsolationForest attack-vs-benign: "
              f"P={anomaly['precision']} R={anomaly['recall']} F1={anomaly['f1']}")

    metrics = {
        "source": "simulated",
        "note": "Supervised per-class metrics on held-out SIMULATED data are near-"
                "perfect BY CONSTRUCTION (injected attacks are separable) — this is "
                "the circularity trap, not a headline claim. The unsupervised "
                "IsolationForest number is the honest, transferable one. Real-dataset "
                "numbers come from detection/benchmark_cicids.py (CICIDS2017/UNSW-NB15).",
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "model": "RandomForestClassifier(n_estimators=200, class_weight=balanced)",
        "n_test": int(len(y_te)),
        "labels": labels_sorted,
        "per_class": {
            lbl: {
                "precision": round(report[lbl]["precision"], 4),
                "recall": round(report[lbl]["recall"], 4),
                "f1": round(report[lbl]["f1-score"], 4),
                "support": int(report[lbl]["support"]),
            }
            for lbl in labels_sorted
        },
        "macro_f1": round(report["macro avg"]["f1-score"], 4),
        "accuracy": round(report["accuracy"], 4),
        "false_positive_rate_benign": fpr,
        "anomaly_detection": anomaly,
        "confusion_matrix": cm,
    }

    (MODELS_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    (PROCESSED_DIR / "metrics.json").write_text(json.dumps(metrics, indent=2))
    print(f"[classifier] macro-F1={metrics['macro_f1']} acc={metrics['accuracy']} FPR(benign)={fpr}")
    for lbl in labels_sorted:
        pc = metrics["per_class"][lbl]
        print(f"    {lbl:18s} P={pc['precision']:.3f} R={pc['recall']:.3f} F1={pc['f1']:.3f} n={pc['support']}")
    return metrics


def main():
    print("== Nexora detection: training on simulated data ==")
    iso = train_isolation_forest()
    norm = json.loads((MODELS_DIR / "isoforest_norm.json").read_text())
    train_classifier(iso=iso, norm=norm)
    print("Done. Models + metrics written to detection/models/ and data/processed/metrics.json")


if __name__ == "__main__":
    main()
