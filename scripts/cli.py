#!/usr/bin/env python3
"""
cli.py — Interfaz de línea de comandos para Email Malware Detector.
No requiere Flask ni servidor web.

Uso:
    # Analizar un solo archivo
    python scripts/cli.py analyze correo.eml

    # Analizar toda una carpeta
    python scripts/cli.py batch /ruta/correos/ --output resultados.json

    # Descargar y analizar desde IMAP
    python scripts/cli.py fetch --provider imap --max 10

    # Ver estado del modelo
    python scripts/cli.py status
"""

import os
import sys
import json
import argparse
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from extract_features import extract_features_from_eml, batch_extract
from predict import predict_email


def cmd_analyze(args):
    """Analiza un solo archivo .eml."""
    if not os.path.exists(args.file):
        print(f"ERROR: {args.file} no existe")
        sys.exit(1)

    result = predict_email(args.file, use_virustotal=not args.skip_vt)

    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False, default=str))
    else:
        print(f"\nArchivo: {result.get('file', '?')}")
        print(f"Asunto:  {result.get('subject', '?')}")
        print(f"De:      {result.get('from', '?')}")
        print(f"Predicción: {result.get('prediction', '?')}")
        print(f"Riesgo:  {result.get('risk_level', '?')} ({result.get('risk_score', 0)}%)")
        print(f"Confianza: {result.get('ml_confidence', 0)}%")
        print(f"Modelos: {result.get('models_count', 0)}")
        if result.get("virustotal"):
            vt = result["virustotal"].get("summary", {})
            print(f"VirusTotal: {vt.get('malicious_files', 0)} archivos, {vt.get('malicious_urls', 0)} URLs maliciosas")


def cmd_batch(args):
    """Procesa una carpeta de correos y exporta resultados."""
    if not os.path.isdir(args.directory):
        print(f"ERROR: {args.directory} no es un directorio válido")
        sys.exit(1)

    from pathlib import Path
    eml_files = list(Path(args.directory).glob("*.eml"))
    print(f"Encontrados {len(eml_files)} archivos .eml")

    results = []
    for eml_path in eml_files:
        try:
            result = predict_email(str(eml_path), use_virustotal=not args.skip_vt)
            results.append(result)
            status = "⚠️" if result.get("prediction") == "MALICIOSO" else "✅"
            print(f"  {status} {eml_path.name}: {result.get('prediction')} ({result.get('risk_score', 0)}%)")
        except Exception as e:
            print(f"  ❌ {eml_path.name}: {e}")

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump({
                "summary": {
                    "total": len(results),
                    "malicious": sum(1 for r in results if r.get("prediction") == "MALICIOSO"),
                    "benign": sum(1 for r in results if r.get("prediction") == "BENIGNO"),
                    "errors": len(eml_files) - len(results),
                },
                "results": results,
            }, f, indent=2, ensure_ascii=False, default=str)
        print(f"\nResultados guardados en: {args.output}")


def cmd_fetch(args):
    """Descarga correos desde IMAP y los analiza."""
    from mailbox_connector import download_emails

    downloaded = download_emails(args.provider, args.max, args.days)
    if not downloaded:
        print("No se descargaron correos")
        return

    for filepath in downloaded:
        try:
            result = predict_email(filepath, use_virustotal=not args.skip_vt)
            status = "⚠️" if result.get("prediction") == "MALICIOSO" else "✅"
            print(f"  {status} {os.path.basename(filepath)}: {result.get('prediction')} ({result.get('risk_score', 0)}%)")
        except Exception as e:
            print(f"  ❌ {filepath}: {e}")


def cmd_status(args):
    """Muestra estado del modelo y estadísticas."""
    models_dir = os.path.join(os.path.dirname(__file__), "..", "models")
    meta_path = os.path.join(models_dir, "model_metadata.json")

    if not os.path.exists(meta_path):
        print("No hay modelo entrenado. Ejecuta: python scripts/train_model.py")
        return

    with open(meta_path) as f:
        meta = json.load(f)

    print(f"\nMejor modelo: {meta.get('best_model', '?')}")
    print(f"AUC:         {meta.get('auc', 0)}")
    print(f"Muestras:    {meta.get('total_samples', 0)}")
    print(f"Features:    {len(meta.get('feature_names', []))}")
    print(f"Umbral:      {meta.get('threshold', 0.5)}")
    print(f"GPU:         {'sí' if meta.get('gpu_used') else 'no'}")
    print(f"SMOTE:       {'sí' if meta.get('smote_applied') else 'no'}")
    print(f"AntiClanker: {'sí' if meta.get('anti_clanker_trained') else 'no'}")
    print(f"Entrenado:   {meta.get('trained_at', '?')}\n")

    ranking = sorted(
        [(n, r.get("auc_test", 0)) for n, r in meta.get("results", {}).items()],
        key=lambda x: -x[1]
    )
    for i, (name, auc) in enumerate(ranking, 1):
        marker = " ← mejor" if name == meta.get("best_model") else ""
        print(f"  {i}. {name:25s} AUC={auc:.4f}{marker}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Email Malware Detector CLI")
    subparsers = parser.add_subparsers(dest="command", help="Comando a ejecutar")

    p_analyze = subparsers.add_parser("analyze", help="Analiza un archivo .eml")
    p_analyze.add_argument("file", help="Ruta al archivo .eml")
    p_analyze.add_argument("--json", action="store_true", help="Salida en JSON")
    p_analyze.add_argument("--skip-vt", action="store_true", help="Omitir VirusTotal")

    p_batch = subparsers.add_parser("batch", help="Analiza toda una carpeta")
    p_batch.add_argument("directory", help="Directorio con archivos .eml")
    p_batch.add_argument("--output", "-o", default="", help="Guardar resultados en JSON")
    p_batch.add_argument("--skip-vt", action="store_true", help="Omitir VirusTotal")

    p_fetch = subparsers.add_parser("fetch", help="Descarga y analiza desde IMAP")
    p_fetch.add_argument("--provider", default="imap", choices=["imap", "gmail", "m365"])
    p_fetch.add_argument("--max", type=int, default=10, help="Máximo de correos")
    p_fetch.add_argument("--days", type=int, default=1, help="Días hacia atrás")
    p_fetch.add_argument("--skip-vt", action="store_true", help="Omitir VirusTotal")

    p_status = subparsers.add_parser("status", help="Estado del modelo")

    args = parser.parse_args()

    if args.command == "analyze":
        cmd_analyze(args)
    elif args.command == "batch":
        cmd_batch(args)
    elif args.command == "fetch":
        cmd_fetch(args)
    elif args.command == "status":
        cmd_status(args)
    else:
        parser.print_help()
