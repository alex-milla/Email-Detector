#!/usr/bin/env python3
"""
train_model.py — Entrena todos los modelos disponibles y elige el mejor.
Modelos: DecisionTree, RandomForest, ExtraTrees, Bagging,
         GradientBoosting, HistGradientBoosting, AdaBoost,
         XGBoost (si instalado), LightGBM (si instalado), CatBoost (si instalado)
GPU: activable via USE_GPU=true en config/.env
"""

import os, sys, json
import hashlib
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
from sklearn.metrics import confusion_matrix, roc_auc_score, f1_score, precision_recall_curve
from sklearn.calibration import CalibratedClassifierCV
from sklearn.preprocessing import StandardScaler
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

    # Soportar tanto numpy arrays como pandas DataFrames
    try:
        import pandas as pd
        if isinstance(X_train, pd.DataFrame):
            X_clanker = X_train.iloc[:, clanker_cols].to_numpy()
        else:
            X_clanker = X_train[:, clanker_cols]
    except Exception:
        import numpy as np
        X_clanker = np.array(X_train)[:, clanker_cols]
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


def _analyze_feature_importance(model, feature_names, X_test, y_test):
    """Analiza importancia de features y detecta colinealidad."""
    if not hasattr(model, "feature_importances_"):
        return {}, []

    importances = model.feature_importances_
    ranked = sorted(zip(feature_names, importances), key=lambda x: -x[1])
    total = sum(importances)

    # Detectar features con importancia casi nula (<1% del total)
    low_importance = [name for name, imp in ranked if imp / total < 0.01]
    # Detectar features dominantes (>20% de la importancia total)
    dominant = [name for name, imp in ranked if imp / total > 0.20]

    # Detectar correlación alta entre features numéricas
    high_corr_pairs = []
    try:
        X_df = pd.DataFrame(X_test, columns=feature_names)
        corr_matrix = X_df.corr().abs()
        upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
        for col in upper.columns:
            correlated = list(upper.index[upper[col] > 0.95])
            for row in correlated:
                high_corr_pairs.append((col, row, round(upper.loc[row, col], 4)))
    except Exception:
        pass

    return {
        "feature_importance": {name: round(imp, 4) for name, imp in ranked},
        "low_importance_features": low_importance,
        "dominant_features": dominant,
        "high_correlation_pairs": high_corr_pairs[:10],
    }, low_importance


def _prune_features(X_train, X_test, feature_names, low_importance):
    """Elimina features de baja importancia si hay suficientes muestras."""
    if not low_importance or len(X_train) < 100:
        return X_train, X_test, feature_names

    keep_mask = [fn not in low_importance for fn in feature_names]
    keep_names = [fn for fn in feature_names if fn not in low_importance]
    print(f"  Podadas {len(low_importance)} features de baja importancia")

    X_train_pruned = X_train[:, keep_mask] if hasattr(X_train, "shape") else X_train
    X_test_pruned = X_test[:, keep_mask] if hasattr(X_test, "shape") else X_test

    # Si después de podar solo queda 1 feature, revertir
    if len(keep_names) < 2:
        print("  Demasiadas features eliminadas, revirtiendo poda")
        return X_train, X_test, feature_names

    return X_train_pruned, X_test_pruned, keep_names


def _find_optimal_threshold(model, X_val, y_val, metric="f1"):
    """Encuentra el umbral óptimo según la métrica especificada."""
    try:
        y_proba = model.predict_proba(X_val)[:, 1]
        precisions, recalls, thresholds = precision_recall_curve(y_val, y_proba)

        if metric == "f2":
            # F2 da más peso al recall (minimizar falsos negativos en malware)
            scores = [ (1 + 4) * p * r / (4 * p + r + 1e-10)
                      for p, r in zip(precisions[:-1], recalls[:-1]) ]
        else:
            # F1 estándar
            scores = [ 2 * p * r / (p + r + 1e-10)
                      for p, r in zip(precisions[:-1], recalls[:-1]) ]

        best_idx = np.argmax(scores)
        best_threshold = float(thresholds[best_idx]) if best_idx < len(thresholds) else 0.5
        best_score = float(scores[best_idx])

        if best_threshold < 0.1 or best_threshold > 0.9:
            best_threshold = 0.5

        print(f"  Umbral óptimo ({metric}): {best_threshold:.3f} (score: {best_score:.4f})")
        return round(best_threshold, 4)
    except Exception:
        return 0.5


def _wrap_calibrated(model, X_train, y_train):
    """Envuelve un modelo en CalibratedClassifierCV si hay suficientes datos."""
    try:
        if len(np.unique(y_train)) < 2:
            return model
        calibrated = CalibratedClassifierCV(model, cv=3, method="sigmoid")
        calibrated.fit(X_train, y_train)
        return calibrated
    except Exception:
        return model


def _compute_checksum(filepath):
    """Calcula SHA256 de un archivo."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
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

    # Entrenar modelo Anti-Clanker si hay features disponibles
    clanker_model, clanker_cols = _train_clanker_model(X_train, y_train, feature_names)
    if clanker_model is not None:
        print("  Anti-Clanker entrenado")

    best_model_name = None
    best_auc        = 0.0
    results         = {}

    for name, model in models.items():
        print(f"\n  -- {name} --")
        try:
            model.fit(X_train, y_train)
            # Calibrar si hay suficientes datos
            if len(X_train) >= 50:
                model = _wrap_calibrated(model, X_train, y_train)
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
                "calibrated":       len(X_train) >= 50,
            }
            print(f"  AUC: {auc:.4f}  CV: {cv.mean():.4f}+/-{cv.std():.4f}")
            if auc > best_auc:
                best_auc        = auc
                best_model_name = name
        except Exception as e:
            print(f"  ERROR: {e}")
            results[name] = {"error": str(e)}

    print("=" * 60)
    print(" PASO 4: Analizando features")
    print("=" * 60)
    best_model = models.get(best_model_name)
    feat_analysis, low_imp = _analyze_feature_importance(best_model, feature_names, X_test, y_test)

    X_train_pruned, X_test_pruned, f_names_pruned = _prune_features(
        X_train.values if hasattr(X_train, "values") else X_train,
        X_test.values if hasattr(X_test, "values") else X_test,
        feature_names, low_imp)
    if len(f_names_pruned) != len(feature_names):
        feature_names = f_names_pruned
        X_train = X_train_pruned
        X_test = X_test_pruned
        print(f"  Features finales: {len(feature_names)}")

    print("=" * 60)
    print(" PASO 5: Guardando")
    print("=" * 60)

    # Encontrar umbral óptimo si hay suficientes datos
    optimal_threshold = 0.5
    if len(X_train) >= 50 and best_model is not None:
        optimal_threshold = _find_optimal_threshold(best_model, X_test, y_test, metric="f2")

    # Guardar todos los modelos
    all_dir = os.path.join(MODEL_DIR, "all_models")
    os.makedirs(all_dir, exist_ok=True)
    for name, model in models.items():
        if "error" not in results.get(name, {}):
            joblib.dump(model, os.path.join(all_dir, f"{name}.joblib"))

    # Re-entrenar mejor modelo con datos completos y calibrar
    print(f"  Re-entrenando {best_model_name} con datos completos...")
    final_model = models[best_model_name]
    final_model.fit(X_balanced, y_balanced)
    if len(X_balanced) >= 50:
        final_model = _wrap_calibrated(final_model, X_balanced.values if hasattr(X_balanced, "values") else X_balanced, y_balanced.values if hasattr(y_balanced, "values") else y_balanced)
    joblib.dump(final_model, os.path.join(MODEL_DIR, "email_classifier.joblib"))

    # Guardar modelo Anti-Clanker si se entrenó
    if clanker_model is not None:
        joblib.dump(clanker_model, os.path.join(MODEL_DIR, "anti_clanker.joblib"))
        with open(os.path.join(MODEL_DIR, "anti_clanker_cols.json"), "w") as f:
            json.dump(clanker_cols, f)
        print("  Anti-Clanker guardado")

    # Checksums para validación en producción
    checksums = {}
    for root, _, files in os.walk(MODEL_DIR):
        for fname in files:
            if fname.endswith(".joblib"):
                fpath = os.path.join(root, fname)
                checksums[os.path.relpath(fpath, MODEL_DIR)] = _compute_checksum(fpath)
    with open(os.path.join(MODEL_DIR, "model_checksums.json"), "w") as f:
        json.dump(checksums, f, indent=2)
    print("  Checksums SHA256 guardados")

    smote_applied = HAS_SMOTE and (ratio < 0.5 or ratio > 2.0)
    metadata = {
        "best_model":              best_model_name,
        "auc":                     best_auc,
        "feature_names":           feature_names,
        "results":                 results,
        "threshold":               optimal_threshold,
        "trained_at":              datetime.now().isoformat(),
        "total_samples":           len(df),
        "smote_applied":           smote_applied,
        "gpu_used":                USE_GPU,
        "models_available":        [n for n in results if "error" not in results.get(n, {})],
        "anti_clanker_trained":    clanker_model is not None,
        "feature_importance":      feat_analysis.get("feature_importance", {}),
        "feature_pruning_applied": len(f_names_pruned) != len(low_imp) if low_imp else False,
        "n_features_before_prune": len(feature_names) + len(low_imp) if low_imp else len(feature_names),
        "n_features_after_prune":  len(feature_names),
        "calibration_applied":     len(X_balanced) >= 50,
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


if __name__ == "__main__":
    main()
