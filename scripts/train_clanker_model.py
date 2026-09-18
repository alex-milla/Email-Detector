#!/usr/bin/env python3
"""
train_clanker_model.py — Reentrena SOLO el Modelo 10 (Anti-Clanker).

A diferencia de train_model.py (que entrena el ensemble completo y en el
proceso genera anti_clanker.joblib), este script:

  * Usa únicamente las columnas clanker_* del CSV de features.
  * NO toca email_classifier.joblib ni all_models/.
  * Reporta AUC, F2-óptimo, matriz de confusión e importancia de features,
    verificando explícitamente el peso de las features v1.2.0
    (CSS sobre-ingenierizado, clipboard_abuse, script/event handlers).
  * Actualiza models/model_metadata.json solo en los campos anti_clanker_*.

Uso:
    python scripts/train_clanker_model.py
    python scripts/train_clanker_model.py --csv data/processed/clanker_synthetic_raw.csv
    python scripts/train_clanker_model.py --data-dir data/processed --dry-run
"""

import os
import sys
import json
import glob
import argparse
from datetime import datetime

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (
    roc_auc_score, f1_score, precision_score, recall_score,
    confusion_matrix, precision_recall_curve,
)

PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..")
MODEL_DIR   = os.path.join(PROJECT_DIR, "models")
METADATA_PATH = os.path.join(MODEL_DIR, "model_metadata.json")


def _json_default(o):
    """Convierte tipos numpy a tipos nativos para json.dump."""
    if isinstance(o, np.integer):
        return int(o)
    if isinstance(o, np.floating):
        return float(o)
    if isinstance(o, np.bool_):
        return bool(o)
    if isinstance(o, np.ndarray):
        return o.tolist()
    return str(o)


def _write_json(path, data):
    """Escritura atómica: no deja el fichero a medias si falla el dump."""
    tmp = path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2, default=_json_default)
    os.replace(tmp, path)

# Features introducidas en Anti-Clanker v1.2.0 que el modelo debe aprender a usar
NEW_FEATURES_V120 = [
    "clanker_score_overengineered_css",
    "clanker_score_clipboard_abuse",
    "clanker_score_prompt_injection",
    "clanker_css_property_count",
    "clanker_suspicious_css_count",
    "clanker_script_block_count",
    "clanker_event_handler_count",
]


def _load_dataset(csv_paths):
    frames = []
    for path in csv_paths:
        df = pd.read_csv(path)
        if "label" not in df.columns:
            print(f"  SKIP {path}: sin columna 'label'")
            continue
        frames.append(df)
    if not frames:
        raise SystemExit("ERROR: ningun CSV valido con columna 'label'")
    return pd.concat(frames, ignore_index=True)


def _find_optimal_threshold(y_true, y_proba, metric="f2"):
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_proba)
    if metric == "f2":
        scores = [(1 + 4) * p * r / (4 * p + r + 1e-10)
                  for p, r in zip(precisions[:-1], recalls[:-1])]
    else:
        scores = [2 * p * r / (p + r + 1e-10)
                  for p, r in zip(precisions[:-1], recalls[:-1])]
    best_idx = int(np.argmax(scores))
    best_threshold = float(thresholds[best_idx]) if best_idx < len(thresholds) else 0.5
    if best_threshold < 0.1 or best_threshold > 0.9:
        best_threshold = 0.5
    return round(best_threshold, 4)


def main():
    parser = argparse.ArgumentParser(description="Reentrena el Modelo 10 Anti-Clanker")
    parser.add_argument("--csv", action="append", default=[],
                        help="CSV(s) de features procesadas. Repetible.")
    parser.add_argument("--data-dir", default=os.path.join(PROJECT_DIR, "data", "processed"),
                        help="Directorio del que leer todos los *.csv si no se pasa --csv")
    parser.add_argument("--dry-run", action="store_true", help="No guardar modelo ni metadata")
    args = parser.parse_args()

    if args.csv:
        csv_paths = args.csv
    else:
        csv_paths = sorted(glob.glob(os.path.join(args.data_dir, "*.csv")))
    if not csv_paths:
        raise SystemExit(f"ERROR: no hay CSVs en {args.data_dir}")

    print("=" * 60)
    print(" Reentrenamiento Anti-Clanker (Modelo 10)")
    print("=" * 60)
    print(f"  CSVs: {', '.join(os.path.basename(p) for p in csv_paths)}")

    df = _load_dataset(csv_paths)

    clanker_cols = [c for c in df.columns if c.startswith("clanker_")]
    if not clanker_cols:
        raise SystemExit("ERROR: el dataset no contiene columnas clanker_*")

    X = df[clanker_cols].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    y = pd.to_numeric(df["label"], errors="coerce").fillna(0).astype(int)

    n_benign    = int((y == 0).sum())
    n_malicious = int((y == 1).sum())
    print(f"  Muestras: {len(df)}  Benignos: {n_benign}  Maliciosos: {n_malicious}")
    print(f"  Features clanker_*: {len(clanker_cols)}")

    if n_benign < 2 or n_malicious < 2:
        raise SystemExit("ERROR: se necesitan al menos 2 muestras de cada clase")

    missing_new = [f for f in NEW_FEATURES_V120 if f not in clanker_cols]
    if missing_new:
        print(f"  AVISO: faltan features v1.2.0 en el CSV: {', '.join(missing_new)}")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y)

    model = Pipeline([
        ("scaler", StandardScaler()),
        ("clf", RandomForestClassifier(
            n_estimators=100, max_depth=6,
            class_weight="balanced", random_state=42, n_jobs=-1)),
    ])
    model.fit(X_train, y_train)

    y_proba = model.predict_proba(X_test)[:, 1]
    auc = roc_auc_score(y_test, y_proba)
    threshold = _find_optimal_threshold(y_test, y_proba, metric="f2")
    y_pred = (y_proba >= threshold).astype(int)

    print("-" * 60)
    print(f"  AUC test:            {auc:.4f}")
    print(f"  Umbral optimo (F2):  {threshold:.3f}")
    print(f"  F1:                  {f1_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"  Precision:           {precision_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"  Recall:              {recall_score(y_test, y_pred, zero_division=0):.4f}")
    print(f"  Confusion matrix:    {confusion_matrix(y_test, y_pred).tolist()}")

    cv_auc = None
    try:
        cv = cross_val_score(model, X, y, cv=StratifiedKFold(5, shuffle=True, random_state=42),
                             scoring="roc_auc")
        cv_auc = float(cv.mean())
        print(f"  AUC CV (5-fold):     {cv.mean():.4f} +/- {cv.std():.4f}")
    except Exception as e:
        print(f"  AVISO: CV no disponible: {e}")

    # Importancia de features (RandomForest dentro del Pipeline)
    importances = model.named_steps["clf"].feature_importances_
    ranked = sorted(zip(clanker_cols, importances), key=lambda x: -x[1])
    total = sum(importances) or 1.0
    print("-" * 60)
    print("  Top features:")
    for name, imp in ranked[:15]:
        print(f"    {name:38s} {imp / total:6.2%}")

    print("  Features v1.2.0:")
    for name in NEW_FEATURES_V120:
        if name in clanker_cols:
            imp = dict(ranked).get(name, 0.0)
            print(f"    {name:38s} {imp / total:6.2%}")

    if args.dry_run:
        print("\n  --dry-run: no se guarda nada.")
        return

    os.makedirs(MODEL_DIR, exist_ok=True)
    joblib.dump(model, os.path.join(MODEL_DIR, "anti_clanker.joblib"))
    _write_json(os.path.join(MODEL_DIR, "anti_clanker_cols.json"), clanker_cols)
    print(f"\n  Modelo guardado: {os.path.join(MODEL_DIR, 'anti_clanker.joblib')}")

    metadata = {}
    if os.path.exists(METADATA_PATH):
        try:
            with open(METADATA_PATH) as f:
                metadata = json.load(f)
        except Exception:
            metadata = {}
    metadata.update({
        "anti_clanker_trained":    True,
        "anti_clanker_trained_at": datetime.now().isoformat(),
        "anti_clanker_auc":        round(float(auc), 4),
        "anti_clanker_cv_auc":     round(cv_auc, 4) if cv_auc is not None else None,
        "anti_clanker_threshold":  threshold,
        "anti_clanker_features":   clanker_cols,
        "anti_clanker_samples":    {"benign": n_benign, "malicious": n_malicious},
    })
    _write_json(METADATA_PATH, metadata)
    print(f"  Metadata actualizada: {METADATA_PATH}")
    print("\n  NOTA: email_classifier.joblib y all_models/ NO han sido modificados.")


if __name__ == "__main__":
    main()
