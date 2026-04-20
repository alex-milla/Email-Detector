#!/usr/bin/env python3
"""
auto_scan.py — Descarga correos nuevos y los analiza automáticamente.
Pensado para ejecutarse como tarea cron cada X tiempo.
"""

import os
import sys
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))
from mailbox_connector import download_emails
from predict import predict_email

RESULTS_DIR  = os.path.join(os.path.dirname(__file__), "..", "results")
HISTORY_PATH = os.path.join(RESULTS_DIR, "history.json")
HISTORY_MAX_ENTRIES = 1000
os.makedirs(RESULTS_DIR, exist_ok=True)


def load_history():
    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH) as f:
            return json.load(f)
    return []


def save_history(history):
    # Rotar si excede el límite: guardar solo las últimas N entradas
    if len(history) > HISTORY_MAX_ENTRIES:
        history = history[-HISTORY_MAX_ENTRIES:]
    with open(HISTORY_PATH, "w") as f:
        json.dump(history, f, indent=2, default=str)


if __name__ == "__main__":
    print(f"\n[{datetime.now()}] Iniciando análisis automático...")

    # Descargar correos nuevos (último día para no repetir)
    provider   = os.getenv("AUTO_SCAN_PROVIDER", "imap")
    downloaded = download_emails(provider, max_emails=20, days_back=1)

    if not downloaded:
        print("No hay correos nuevos.")
        sys.exit(0)

    # Analizar cada correo
    history = load_history()
    alerts  = []

    for eml_path in downloaded:
        try:
            result = predict_email(eml_path, use_virustotal=True)
            history.append(result)
            if result.get("prediction") == "MALICIOSO":
                alerts.append(result)
        except Exception as e:
            print(f"  ERROR analizando {eml_path}: {e}")

    save_history(history)

    # Resumen
    print(f"\nAnalizados: {len(downloaded)}")
    print(f"Maliciosos: {len(alerts)}")

    if alerts:
        print("\n ALERTAS:")
        for a in alerts:
            print(f"  [!] {a['file']} — {a.get('subject','')[:60]} — Riesgo: {a['risk_score']}%")
    else:
        print("Sin amenazas detectadas.")
