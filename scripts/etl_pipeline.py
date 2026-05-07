#!/usr/bin/env python3
"""
etl_pipeline.py — Pipeline ETL para preparar datasets de entrenamiento.
Lee .eml de directorios estructurados, extrae features, normaliza,
deduplica, balancea y genera CSVs listos para train_model.py.

Uso:
    python scripts/etl_pipeline.py --ham-dir data/downloads/public/ham --spam-dir data/downloads/public/spam
    python scripts/etl_pipeline.py --ham-dir data/labeled/benign --spam-dir data/labeled/malicious
    python scripts/etl_pipeline.py --all  # usa data/labeled/ + data/downloads/
"""

import os
import sys
import json
import csv
import hashlib
import argparse
from pathlib import Path
from collections import Counter

PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..")
sys.path.insert(0, os.path.dirname(__file__))

from extract_features import extract_features_from_eml, batch_extract


PROCESSED_DIR = os.path.join(PROJECT_DIR, "data", "processed")
DEDUP_CACHE_PATH = os.path.join(PROCESSED_DIR, ".dedup_cache.json")


def _body_hash(eml_path):
    """Hash simple del cuerpo del correo para deduplicación."""
    try:
        with open(eml_path, "rb") as f:
            content = f.read()
        return hashlib.sha256(content[:5000]).hexdigest()
    except Exception:
        return None


def find_eml_files(directory):
    """Encuentra todos los .eml en un directorio (recursivo)."""
    return list(Path(directory).glob("**/*.eml")) if os.path.isdir(directory) else []


def deduplicate(features_list, eml_paths, cache_path=None):
    """Elimina duplicados por hash del cuerpo."""
    seen = set()
    unique_features = []
    unique_paths = []

    cache = {}
    if cache_path and os.path.exists(cache_path):
        try:
            with open(cache_path) as f:
                cache = json.load(f)
        except Exception:
            cache = {}

    for feats, path in zip(features_list, eml_paths):
        path_str = str(path)
        if path_str in cache:
            h = cache[path_str]
        else:
            h = _body_hash(path)
            if h and cache_path is not None:
                cache[path_str] = h

        if h and h in seen:
            continue
        if h:
            seen.add(h)
        unique_features.append(feats)
        unique_paths.append(path_str)

    if cache_path is not None:
        try:
            with open(cache_path, "w") as f:
                json.dump(cache, f, indent=2)
        except Exception:
            pass

    return unique_features, unique_paths


def balance_dataset(csv_path, method="auto", random_state=42):
    """
    Balancea el dataset final.
    method='auto': usa SMOTE si la proporción es >2:1 o <1:2
    method='undersample': reduce la clase mayoritaria
    method='oversample': duplica la clase minoritaria (solo para CSV)
    """
    import pandas as pd

    df = pd.read_csv(csv_path)
    if "label" not in df.columns:
        print("  ERROR: falta columna label")
        return

    counts = df["label"].value_counts()
    n_benign = counts.get(0, 0)
    n_malicious = counts.get(1, 0)
    ratio = max(n_benign, n_malicious) / max(min(n_benign, n_malicious), 1)

    print(f"  Pre-balanceo: benignos={n_benign} maliciosos={n_malicious} ratio=1:{ratio:.1f}")

    if method == "auto" and ratio < 2.0:
        print("  Dataset ya balanceado, sin cambios")
        return

    if method == "auto" or method == "oversample":
        try:
            from imblearn.over_sampling import SMOTE
            X = df.drop(columns=["label"])
            y = df["label"]
            smote = SMOTE(random_state=random_state)
            X_res, y_res = smote.fit_resample(X, y)
            df_res = pd.concat([pd.DataFrame(X_res, columns=X.columns),
                                pd.Series(y_res, name="label")], axis=1)
            df_res.to_csv(csv_path, index=False)
            new_counts = df_res["label"].value_counts()
            print(f"  SMOTE aplicado: benignos={new_counts.get(0,0)} maliciosos={new_counts.get(1,0)}")
        except ImportError:
            print("  SMOTE no disponible, saltando")

    elif method == "undersample":
        from sklearn.utils import resample
        df_benign = df[df["label"] == 0]
        df_malicious = df[df["label"] == 1]
        if len(df_benign) > len(df_malicious):
            df_benign = resample(df_benign, replace=False,
                                  n_samples=len(df_malicious), random_state=random_state)
        else:
            df_malicious = resample(df_malicious, replace=False,
                                     n_samples=len(df_benign), random_state=random_state)
        df_balanced = pd.concat([df_benign, df_malicious]).sample(frac=1, random_state=random_state)
        df_balanced.to_csv(csv_path, index=False)
        print(f"  Undersample: {len(df_balanced)} total")


def run_pipeline(ham_dirs, spam_dirs, output_prefix="dataset", balance=True, dedup=True):
    """Ejecuta el pipeline completo ETL."""
    os.makedirs(PROCESSED_DIR, exist_ok=True)

    print("=" * 60)
    print(" ETL Pipeline — Extracción")
    print("=" * 60)

    ham_files = []
    for d in ham_dirs:
        ham_files.extend(find_eml_files(d))
    spam_files = []
    for d in spam_dirs:
        spam_files.extend(find_eml_files(d))

    print(f"  Ham (benignos):   {len(ham_files)} .eml encontrados")
    print(f"  Spam (maliciosos): {len(spam_files)} .eml encontrados")

    if not ham_files and not spam_files:
        print("  ERROR: No hay archivos .eml en los directorios especificados")
        return

    # Extraer features
    all_features = []
    all_paths = []

    for eml_path in ham_files:
        try:
            feats, _ = extract_features_from_eml(str(eml_path))
            feats["label"] = 0
            all_features.append(feats)
            all_paths.append(eml_path)
        except Exception as e:
            print(f"  ERROR: {eml_path.name}: {e}")

    for eml_path in spam_files:
        try:
            feats, _ = extract_features_from_eml(str(eml_path))
            feats["label"] = 1
            all_features.append(feats)
            all_paths.append(eml_path)
        except Exception as e:
            print(f"  ERROR: {eml_path.name}: {e}")

    if not all_features:
        print("  No se extrajeron features")
        return

    print(f"\n  Features extraídas: {len(all_features)}")

    # Deduplicación
    if dedup:
        cache_path = DEDUP_CACHE_PATH if dedup else None
        all_features, all_paths = deduplicate(all_features, all_paths, cache_path)
        print(f"  Post-dedup: {len(all_features)}")

    # Guardar CSV temporal
    all_keys = sorted(set().union(*(f.keys() for f in all_features)))
    temp_csv = os.path.join(PROCESSED_DIR, f"{output_prefix}_raw.csv")
    with open(temp_csv, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_keys)
        writer.writeheader()
        for feats in all_features:
            for k in all_keys:
                feats.setdefault(k, 0)
            writer.writerow(feats)
    print(f"  CSV guardado: {temp_csv}")

    # Balanceo
    if balance:
        print(f"\n{'>'*40}")
        print(" Balanceo")
        print('<' * 40)
        balance_dataset(temp_csv)

    print(f"\n  Dataset listo: {temp_csv}")
    print(f"  Para entrenar: python scripts/train_model.py")
    print(f"  (train_model.py lee automáticamente todos los CSVs en data/processed/)")

    return temp_csv


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Pipeline ETL para datasets de correos")
    parser.add_argument("--ham-dir", action="append", default=[], help="Directorio(s) con .eml benignos")
    parser.add_argument("--spam-dir", action="append", default=[], help="Directorio(s) con .eml maliciosos")
    parser.add_argument("--all", action="store_true", help="Usar data/labeled/ + data/downloads/")
    parser.add_argument("--output", default="dataset", help="Prefijo del CSV de salida")
    parser.add_argument("--no-balance", action="store_true", help="Saltar balanceo")
    parser.add_argument("--no-dedup", action="store_true", help="Saltar deduplicación")
    args = parser.parse_args()

    if args.all:
        ham_dirs = [
            os.path.join(PROJECT_DIR, "data", "labeled", "benign"),
            os.path.join(PROJECT_DIR, "data", "downloads", "public", "ham"),
        ]
        spam_dirs = [
            os.path.join(PROJECT_DIR, "data", "labeled", "malicious"),
            os.path.join(PROJECT_DIR, "data", "downloads", "public", "spam"),
        ]
    else:
        ham_dirs = args.ham_dir or [os.path.join(PROJECT_DIR, "data", "labeled", "benign")]
        spam_dirs = args.spam_dir or [os.path.join(PROJECT_DIR, "data", "labeled", "malicious")]

    run_pipeline(ham_dirs, spam_dirs, args.output, balance=not args.no_balance, dedup=not args.no_dedup)
