#!/usr/bin/env python3
"""
train_model.py — Entrena todos los modelos disponibles y elige el mejor.
Modelos: DecisionTree, RandomForest, ExtraTrees, Bagging,
         GradientBoosting, HistGradientBoosting, AdaBoost,
         XGBoost (si instalado), LightGBM (si instalado), CatBoost (si instalado)
GPU: activable via USE_GPU=true en config/.env
"""

import os, sys, json
import pandas as pd
import numpy as np
from datetime import datetime
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import (
    RandomForestClassifier, ExtraTreesClassifier,
    GradientBoostingClassifier, HistGradientBoostingClassifier,
    AdaBoostClassifier, BaggingClassifier,
)
from sklearn.metrics import confusion_matrix, roc_auc_score
import joblib

try:
    from imblearn.over_sampling import SMOTE
    HAS_SMOTE = True
except ImportError:
    HAS_SMOTE = False
    print("AVISO: imblearn no instalado. Sin SMOTE.")

PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..")
ENV_PATH    = os.path.join(PROJECT_DIR, "config", ".env")
USE_GPU     = False
try:
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH) as f:
            for line in f:
                if line.strip().startswith("USE_GPU="):
                    USE_GPU = line.strip().split("=", 1)[1].lower() in ("true", "1", "yes")
except Exception:
    pass

HAS_XGB = HAS_LGB = HAS_CAT = False
try:
    import xgboost as xgb
    HAS_XGB = True
    print("  OK: XGBoost")
except ImportError:
    print("  INFO: XGBoost no instalado")
try:
    import lightgbm as lgb
    HAS_LGB = True
    print("  OK: LightGBM")
except ImportError:
    print("  INFO: LightGBM no instalado")
try:
    import catboost as cb
    HAS_CAT = True
    print("  OK: CatBoost")
except ImportError:
    print("  INFO: CatBoost no instalado")

print("  GPU:", "activada" if USE_GPU else "desactivada (CPU)")

DATA_DIR  = os.path.join(PROJECT_DIR, "data", "processed")
MODEL_DIR = os.path.join(PROJECT_DIR, "models")
os.makedirs(MODEL_DIR, exist_ok=True)

print("=" * 60)
print(" PASO 1: Cargando datos")
print("=" * 60)
csv_files = [f for f in os.listdir(DATA_DIR) if f.endswith(".csv")]
if not csv_files:
    print("ERROR: No hay CSVs en data/processed/")
    sys.exit(1)

df = pd.concat([pd.read_csv(os.path.join(DATA_DIR, f)) for f in csv_files], ignore_index=True)
if "label" not in df.columns:
    print("ERROR: falta columna label")
    sys.exit(1)

n_benign    = len(df[df["label"] == 0])
n_malicious = len(df[df["label"] == 1])
print(f"  Total: {len(df)}  Benignos: {n_benign}  Maliciosos: {n_malicious}")

X             = df.drop(columns=["label"])
y             = df["label"]
feature_names = list(X.columns)

print("=" * 60)
print(" PASO 2: Balanceando")
print("=" * 60)
ratio = n_benign / max(n_malicious, 1)
if HAS_SMOTE and (ratio < 0.5 or ratio > 2.0):
    smote = SMOTE(random_state=42)
    X_balanced, y_balanced = smote.fit_resample(X, y)
    print("  SMOTE aplicado")
else:
    X_balanced, y_balanced = X, y
    print("  Sin cambios")

X_train, X_test, y_train, y_test = train_test_split(
    X_balanced, y_balanced, test_size=0.3, random_state=42, stratify=y_balanced)
print(f"  Entrenamiento: {len(X_train)}  Test: {len(X_test)}")

print("=" * 60)
print(" PASO 3: Entrenando modelos")
print("=" * 60)

models = {
    "DecisionTree":         DecisionTreeClassifier(max_depth=8, min_samples_leaf=5, class_weight="balanced", random_state=42),
    "RandomForest":         RandomForestClassifier(n_estimators=200, max_depth=12, min_samples_leaf=3, class_weight="balanced", random_state=42, n_jobs=-1),
    "ExtraTrees":           ExtraTreesClassifier(n_estimators=200, max_depth=12, min_samples_leaf=3, class_weight="balanced", random_state=42, n_jobs=-1),
    "Bagging":              BaggingClassifier(estimator=DecisionTreeClassifier(max_depth=8), n_estimators=100, random_state=42, n_jobs=-1),
    "GradientBoosting":     GradientBoostingClassifier(n_estimators=150, max_depth=6, learning_rate=0.1, random_state=42),
    "HistGradientBoosting": HistGradientBoostingClassifier(max_iter=200, max_depth=8, learning_rate=0.1, random_state=42),
    "AdaBoost":             AdaBoostClassifier(n_estimators=150, learning_rate=0.1, random_state=42),
}

if HAS_XGB:
    models["XGBoost"] = xgb.XGBClassifier(
        n_estimators=200, max_depth=7, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, eval_metric="logloss",
        random_state=42, device="cuda" if USE_GPU else "cpu",
        n_jobs=-1, scale_pos_weight=n_benign / max(n_malicious, 1))
if HAS_LGB:
    models["LightGBM"] = lgb.LGBMClassifier(
        n_estimators=200, max_depth=8, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8, random_state=42,
        device="gpu" if USE_GPU else "cpu", n_jobs=-1,
        class_weight="balanced", verbose=-1)
if HAS_CAT:
    models["CatBoost"] = cb.CatBoostClassifier(
        iterations=200, depth=8, learning_rate=0.1, random_seed=42,
        task_type="GPU" if USE_GPU else "CPU",
        auto_class_weights="Balanced", verbose=0)

best_model_name = None
best_auc        = 0.0
results         = {}

for name, model in models.items():
    print(f"\n  -- {name} --")
    try:
        model.fit(X_train, y_train)
        y_proba = model.predict_proba(X_test)[:, 1]
        auc     = roc_auc_score(y_test, y_proba)
        cm      = confusion_matrix(y_test, model.predict(X_test))
        cv      = cross_val_score(model, X_balanced, y_balanced,
                                  cv=StratifiedKFold(5, shuffle=True, random_state=42),
                                  scoring="roc_auc")
        results[name] = {
            "auc_test":         round(auc, 4),
            "auc_cv_mean":      round(cv.mean(), 4),
            "auc_cv_std":       round(cv.std(), 4),
            "confusion_matrix": cm.tolist(),
        }
        print(f"  AUC: {auc:.4f}  CV: {cv.mean():.4f}+/-{cv.std():.4f}")
        if auc > best_auc:
            best_auc        = auc
            best_model_name = name
    except Exception as e:
        print(f"  ERROR: {e}")
        results[name] = {"error": str(e)}

print("=" * 60)
print(" PASO 4: Guardando")
print("=" * 60)
best_model = models[best_model_name]
joblib.dump(best_model, os.path.join(MODEL_DIR, "email_classifier.joblib"))

all_dir = os.path.join(MODEL_DIR, "all_models")
os.makedirs(all_dir, exist_ok=True)
for name, model in models.items():
    if "error" not in results.get(name, {}):
        joblib.dump(model, os.path.join(all_dir, f"{name}.joblib"))

smote_applied = HAS_SMOTE and (ratio < 0.5 or ratio > 2.0)
metadata = {
    "best_model":       best_model_name,
    "auc":              best_auc,
    "feature_names":    feature_names,
    "results":          results,
    "threshold":        0.5,
    "trained_at":       datetime.now().isoformat(),
    "total_samples":    len(df),
    "smote_applied":    smote_applied,
    "gpu_used":         USE_GPU,
    "models_available": [n for n in results if "error" not in results.get(n, {})],
}
with open(os.path.join(MODEL_DIR, "model_metadata.json"), "w") as f:
    json.dump(metadata, f, indent=2)

print(f"\n  Mejor modelo: {best_model_name} (AUC {best_auc:.4f})")
ranking = sorted(
    [(n, r["auc_test"]) for n, r in results.items() if "auc_test" in r],
    key=lambda x: x[1], reverse=True)
for i, (n, a) in enumerate(ranking, 1):
    marker = " <- MEJOR" if n == best_model_name else ""
    print(f"  {i:2d}. {n:25s} {a:.4f}{marker}")
print("\n" + "=" * 60)
print(" ENTRENAMIENTO COMPLETADO")
print("=" * 60)

# ─── Modelo 10: Anti-Clanker (LLM Artifact Detector) ─────────────────────────
def _train_clanker_model(X_train, y_train, feature_names):
    """Entrena el Modelo 10: detector de artefactos LLM (Anti-Clanker)."""
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler

    clanker_cols = [i for i, fn in enumerate(feature_names)
                    if fn.startswith("clanker_")]
    if not clanker_cols:
        return None, []

    X_clanker = X_train[:, clanker_cols] if hasattr(X_train, "__getitem__") else X_train
    try:
        model = Pipeline([
            ("scaler", StandardScaler()),
            ("clf", RandomForestClassifier(
                n_estimators=100, max_depth=6,
                class_weight="balanced", random_state=42, n_jobs=-1)),
        ])
        model.fit(X_clanker, y_train)
        return model, clanker_cols
    except Exception as e:
        import logging
        logging.getLogger(__name__).warning("Modelo 10 entrenamiento fallido: %s", e)
        return None, []
# ─────────────────────────────────────────────────────────────────────────────
