#!/usr/bin/env python3
"""
retrain_clanker.py — Orquesta el reentrenamiento del Modelo 10 (Anti-Clanker).

Pasos:
  1. Localiza los CSV de features en data/processed/ (datos reales).
  2. Si no hay ninguno, o se pasa --synthetic, genera un dataset sintético
     con generate_synthetic_clanker_dataset.py + etl_pipeline.py.
  3. Entrena SOLO el Anti-Clanker con train_clanker_model.py.

Uso:
    python scripts/retrain_clanker.py                 # CSVs existentes o sintético
    python scripts/retrain_clanker.py --synthetic     # forzar sintético
    python scripts/retrain_clanker.py --csv a.csv --csv b.csv
"""

import os
import sys
import glob
import argparse
import subprocess

PROJECT_DIR   = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCRIPTS_DIR   = os.path.join(PROJECT_DIR, "scripts")
PROCESSED_DIR = os.path.join(PROJECT_DIR, "data", "processed")
SYNTH_DIR     = os.path.join(PROJECT_DIR, "data", "synthetic_clanker")

GEN_SCRIPT   = os.path.join(SCRIPTS_DIR, "generate_synthetic_clanker_dataset.py")
ETL_SCRIPT   = os.path.join(SCRIPTS_DIR, "etl_pipeline.py")
TRAIN_SCRIPT = os.path.join(SCRIPTS_DIR, "train_clanker_model.py")


def _run(cmd):
    print(f"\n>>> {' '.join(cmd)}\n", flush=True)
    subprocess.run(cmd, check=True, cwd=PROJECT_DIR)


def resolve_csvs(processed_dir, explicit=None, synthetic=False):
    """Devuelve la lista de CSV a usar, o None si hay que generar sintéticos."""
    if explicit:
        return list(explicit)
    found = sorted(glob.glob(os.path.join(processed_dir, "*.csv")))
    if found and not synthetic:
        return found
    return None


def generate_synthetic(benign, malicious):
    _run([sys.executable, GEN_SCRIPT,
          "--benign", str(benign), "--malicious", str(malicious)])
    _run([sys.executable, ETL_SCRIPT,
          "--ham-dir", os.path.join(SYNTH_DIR, "benign"),
          "--spam-dir", os.path.join(SYNTH_DIR, "malicious"),
          "--output", "clanker_synthetic", "--no-balance"])
    return [os.path.join(PROCESSED_DIR, "clanker_synthetic_raw.csv")]


def main():
    parser = argparse.ArgumentParser(description="Reentrena el Anti-Clanker (orquestador)")
    parser.add_argument("--csv", action="append", default=[],
                        help="CSV(s) de features. Si se omite, usa data/processed/*.csv")
    parser.add_argument("--synthetic", action="store_true",
                        help="Forzar generacion de dataset sintetico")
    parser.add_argument("--benign", type=int, default=120)
    parser.add_argument("--malicious", type=int, default=120)
    args = parser.parse_args()

    csvs = resolve_csvs(PROCESSED_DIR, args.csv, args.synthetic)
    if csvs is None:
        print("No hay CSVs en data/processed (o se pidio --synthetic). "
              "Generando dataset sintetico Anti-Clanker...")
        csvs = generate_synthetic(args.benign, args.malicious)
        # ETL puede deduplicar y dejar el CSV con otro nombre; usar el existente
        if not os.path.exists(csvs[0]):
            print(f"ERROR: no se genero {csvs[0]}")
            return 1

    cmd = [sys.executable, TRAIN_SCRIPT]
    for c in csvs:
        cmd += ["--csv", c]
    _run(cmd)
    return 0


if __name__ == "__main__":
    sys.exit(main())
