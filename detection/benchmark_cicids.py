"""
Real-dataset benchmark (plan §4) — the defensible precision/recall/F1.

The live demo runs on the simulator; this script produces the honest number on
REAL labelled network-intrusion data. It is NOT run automatically (the datasets
are hundreds of MB and are not committed). Drop a dataset into data/raw/ and run:

    python -m detection.benchmark_cicids --dataset cicids2017
    python -m detection.benchmark_cicids --dataset unsw

Expected layout:
    data/raw/CICIDS2017/*.csv          (the MachineLearningCVE CSVs)
    data/raw/UNSW-NB15/UNSW_NB15_training-set.csv
    data/raw/UNSW-NB15/UNSW_NB15_testing-set.csv

Writes data/processed/metrics_real.json with per-class metrics, a binary
attack-vs-benign IsolationForest result, and the benign false-positive rate.
This mirrors the Week-1/Week-2 notebook methodology but as a repeatable script.
"""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
RAW = ROOT / "data" / "raw"
OUT = ROOT / "data" / "processed" / "metrics_real.json"


def _clean_numeric(df: pd.DataFrame) -> pd.DataFrame:
    df = df.replace([np.inf, -np.inf], np.nan).dropna()
    return df


def load_cicids2017(sample: int | None = 200_000, seed: int = 42) -> tuple[pd.DataFrame, pd.Series]:
    files = sorted(RAW.rglob("*.csv"))
    if not files:
        raise FileNotFoundError(
            "No CICIDS2017 CSVs found under data/raw/CICIDS2017/ (the "
            "MachineLearningCVE CSVs). See the module docstring."
        )
    rng = np.random.default_rng(seed)
    df = pd.DataFrame()
    for file in files:
        for chunk in pd.read_csv(file, low_memory=False, chunksize=50_000, encoding="cp1252"):
            chunk.columns = chunk.columns.str.strip()
            if "Label" not in chunk.columns:
                continue
            chunk["__sample_key__"] = rng.random(len(chunk))
            df = pd.concat([df, chunk], ignore_index=True)
            if sample and len(df) > sample:
                df = df.nsmallest(sample, "__sample_key__")
    if df.empty:
        raise ValueError("No CSV with a Label column found under data/raw/.")
    df = df.drop(columns="__sample_key__").reset_index(drop=True)
    label_col = "Label"
    y = df[label_col].astype(str).str.strip()
    X = df.drop(columns=[label_col]).select_dtypes(include=[np.number])
    data = _clean_numeric(pd.concat([X, y.rename("__label__")], axis=1))
    return data.drop(columns="__label__"), data["__label__"]


def load_unsw() -> tuple[pd.DataFrame, pd.Series]:
    tr = RAW / "UNSW-NB15" / "UNSW_NB15_training-set.csv"
    te = RAW / "UNSW-NB15" / "UNSW_NB15_testing-set.csv"
    if not tr.exists():
        raise FileNotFoundError("No UNSW-NB15 CSVs under data/raw/UNSW-NB15/.")
    frames = [pd.read_csv(tr)]
    if te.exists():
        frames.append(pd.read_csv(te))
    df = pd.concat(frames, ignore_index=True)
    y = df["attack_cat"].fillna("Normal").astype(str) if "attack_cat" in df.columns \
        else df["label"].map({0: "Normal", 1: "Attack"})
    drop = [c for c in ("id", "label", "attack_cat") if c in df.columns]
    X = df.drop(columns=drop).select_dtypes(include=[np.number])
    data = _clean_numeric(pd.concat([X, y.rename("__label__")], axis=1))
    return data.drop(columns="__label__"), data["__label__"]


def calibrate_threshold(scores, labels, max_fpr=0.05):
    """Choose highest validation F1 subject to a benign false-positive budget."""
    order = np.argsort(-scores)
    ordered_scores = np.asarray(scores)[order]
    targets = np.asarray(labels)[order]
    tp = np.cumsum(targets)
    fp = np.cumsum(1 - targets)
    # Evaluate complete groups of tied scores; prediction uses >= threshold.
    ends = np.r_[ordered_scores[:-1] != ordered_scores[1:], True]
    fpr = fp / max(1, (targets == 0).sum())
    f1 = 2 * tp / np.maximum(1, tp + fp + targets.sum())
    valid = ends & (fpr <= max_fpr)
    if not valid.any():
        return float(np.nextafter(ordered_scores.max(), np.inf)), 0.0
    index = int(np.argmax(np.where(valid, f1, -1)))
    return float(ordered_scores[index]), float(f1[index])


def run(dataset: str, sample: int | None = 200_000, seed: int = 42) -> dict:
    from sklearn.model_selection import train_test_split
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.metrics import (classification_report, precision_score,
                                 recall_score, f1_score, confusion_matrix)

    X, y = load_cicids2017(sample, seed) if dataset == "cicids2017" else load_unsw()
    benign_name = "BENIGN" if dataset == "cicids2017" else "Normal"

    if sample and len(X) > sample:
        X = X.sample(sample, random_state=seed)
        y = y.loc[X.index]

    is_attack = (y != benign_name).astype(int)

    X_dev, X_te, y_dev, y_te, atk_dev, atk_te = train_test_split(
        X, y, is_attack, test_size=0.3, random_state=seed, stratify=is_attack
    )
    X_tr, X_val, y_tr, y_val, atk_tr, atk_val = train_test_split(
        X_dev, y_dev, atk_dev, test_size=2/7, random_state=seed, stratify=atk_dev
    )
    scaler = StandardScaler().fit(X_tr)
    X_tr_s, X_te_s = scaler.transform(X_tr), scaler.transform(X_te)

    # --- Supervised multi-class classifier ---
    clf = RandomForestClassifier(n_estimators=200, class_weight="balanced",
                                 random_state=seed, n_jobs=-1)
    clf.fit(X_tr_s, y_tr)
    y_pred = clf.predict(X_te_s)
    report = classification_report(y_te, y_pred, output_dict=True, zero_division=0)

    # Heavy-tailed flow counters make raw random splits insensitive to smaller attacks.
    # Fit only benign training flows; labels calibrate the operating point on validation.
    candidates = []
    for transform in ("raw", "signed_log1p"):
        tr = X_tr.to_numpy(dtype=float)
        val = X_val.to_numpy(dtype=float)
        if transform == "signed_log1p":
            tr, val = np.sign(tr) * np.log1p(np.abs(tr)), np.sign(val) * np.log1p(np.abs(val))
        for max_samples in (256, 1024, 4096):
            iso = IsolationForest(n_estimators=200, max_samples=max_samples,
                                  random_state=seed, n_jobs=-1)
            iso.fit(tr[atk_tr.values == 0])
            threshold, validation_f1 = calibrate_threshold(-iso.score_samples(val), atk_val.values)
            candidates.append((validation_f1, transform, max_samples, threshold, iso))
    validation_f1, transform, max_samples, thr, iso = max(candidates, key=lambda c: c[0])
    test_values = X_te.to_numpy(dtype=float)
    if transform == "signed_log1p":
        test_values = np.sign(test_values) * np.log1p(np.abs(test_values))
    raw = -iso.score_samples(test_values)
    anom_pred = (raw >= thr).astype(int)
    classifier_attack_pred = (y_pred != benign_name).astype(int)

    labels_sorted = sorted(y.unique())
    cm = confusion_matrix(y_te, y_pred, labels=labels_sorted).tolist()
    bi = labels_sorted.index(benign_name)
    benign_total = sum(cm[bi])
    fpr = round(float(anom_pred[atk_te.values == 0].mean()), 4) if benign_total else None

    metrics = {
        "source": f"real:{dataset}",
        "note": "Measured on sampled network flows with separate 50/20/30 train/validation/test splits. IsolationForest fits benign training flows; preprocessing and threshold are selected on labelled validation flows with a 5% benign false-positive budget. Test data is excluded from selection. These are offline flow models, separate from application-event detection and correlation.",
        "n_test": int(len(y_te)),
        "n_train": int(len(y_tr)),
        "n_validation": int(len(y_val)),
        "seed": seed,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "classifier": {
            "model": "RandomForestClassifier(class_weight=balanced)",
            "macro_f1": round(report["macro avg"]["f1-score"], 4),
            "accuracy": round(report["accuracy"], 4),
            "attack_detection": {
                "precision": round(float(precision_score(atk_te, classifier_attack_pred, zero_division=0)), 4),
                "recall": round(float(recall_score(atk_te, classifier_attack_pred, zero_division=0)), 4),
                "f1": round(float(f1_score(atk_te, classifier_attack_pred, zero_division=0)), 4),
                "false_positive_rate_benign": round(float(classifier_attack_pred[atk_te.values == 0].mean()), 4),
            },
            "per_class": {
                k: {"precision": round(v["precision"], 4),
                    "recall": round(v["recall"], 4),
                    "f1": round(v["f1-score"], 4),
                    "support": int(v["support"])}
                for k, v in report.items()
                if k not in ("accuracy", "macro avg", "weighted avg")
            },
        },
        "anomaly_detection": {
            "threshold": float(thr),
            "model": "IsolationForest · benign fit, validation-calibrated threshold",
            "preprocessing": transform,
            "max_samples": max_samples,
            "validation_f1": round(validation_f1, 4),
            "validation_fpr_budget": 0.05,
            "precision": round(float(precision_score(atk_te, anom_pred, zero_division=0)), 4),
            "recall": round(float(recall_score(atk_te, anom_pred, zero_division=0)), 4),
            "f1": round(float(f1_score(atk_te, anom_pred, zero_division=0)), 4),
        },
        "false_positive_rate_benign": fpr,
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    temporary = OUT.with_suffix(".tmp")
    temporary.write_text(json.dumps(metrics, indent=2))
    temporary.replace(OUT)
    print(json.dumps(metrics, indent=2))
    print(f"\nWritten to {OUT}")
    return metrics


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dataset", choices=["cicids2017", "unsw"], default="cicids2017")
    ap.add_argument("--sample", type=int, default=200_000,
                    help="maximum random sample rows; 0 for all")
    args = ap.parse_args()
    run(args.dataset, sample=args.sample or None)
