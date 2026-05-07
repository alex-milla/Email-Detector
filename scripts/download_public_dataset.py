#!/usr/bin/env python3
"""
download_public_dataset.py — Descarga datasets públicos de correos etiquetados.
Fuentes: Enron (benignos), SpamAssassin (spam + ham).

Uso:
    python scripts/download_public_dataset.py
    python scripts/download_public_dataset.py --max-emails 500
    python scripts/download_public_dataset.py --only-spam
"""

import os
import sys
import json
import argparse
import urllib.request
import urllib.error
import tarfile
import zipfile
import email
import re
from pathlib import Path
from email import policy

PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..")
RAW_DIR = os.path.join(PROJECT_DIR, "data", "downloads")
os.makedirs(RAW_DIR, exist_ok=True)

SPAM_ASSASSIN_URL = (
    "https://spamassassin.apache.org/old/publiccorpus/"
    "20030228_spam_2.tar.bz2"
)
SPAM_ASSASSIN_HAM_URL = (
    "https://spamassassin.apache.org/old/publiccorpus/"
    "20030228_easy_ham_2.tar.bz2"
)
SPAM_ASSASSIN_HARD_HAM_URL = (
    "https://spamassassin.apache.org/old/publiccorpus/"
    "20030228_hard_ham.tar.bz2"
)


def _download_file(url, dest):
    print(f"  Descargando {os.path.basename(url)}...")
    try:
        urllib.request.urlretrieve(url, dest)
        return True
    except Exception as e:
        print(f"  ERROR: {e}")
        return False


def _extract_eml_from_tar(tar_path, extract_dir, label, max_emails=1000):
    extracted = []
    try:
        with tarfile.open(tar_path, "r:bz2") as tar:
            members = [m for m in tar.getmembers() if m.isfile() and not m.name.startswith(".")]
            members = members[:max_emails]
            for m in members:
                try:
                    f = tar.extractfile(m)
                    if f is None:
                        continue
                    raw = f.read()
                    if not raw:
                        continue
                    try:
                        msg = email.message_from_bytes(raw, policy=policy.default)
                        subject = msg.get("Subject", "sin_asunto")
                    except Exception:
                        subject = "sin_asunto"
                    safe_subj = re.sub(r'[^\w\-_ ]', '_', str(subject))[:50]
                    fname = f"{label}_{len(extracted):04d}_{safe_subj}.eml"
                    fpath = os.path.join(extract_dir, fname)
                    with open(fpath, "wb") as out:
                        out.write(raw)
                    extracted.append(fpath)
                except Exception:
                    continue
    except Exception as e:
        print(f"  ERROR extrayendo {tar_path}: {e}")
    return extracted


def download_spamassassin(max_emails=1000, output_dir=None):
    if output_dir is None:
        output_dir = os.path.join(RAW_DIR, "spamassassin")
    ham_dir = os.path.join(output_dir, "ham")
    spam_dir = os.path.join(output_dir, "spam")
    os.makedirs(ham_dir, exist_ok=True)
    os.makedirs(spam_dir, exist_ok=True)

    archives = {
        SPAM_ASSASSIN_URL: ("spam_2.tar.bz2", spam_dir, "spam"),
        SPAM_ASSASSIN_HAM_URL: ("easy_ham_2.tar.bz2", ham_dir, "ham"),
        SPAM_ASSASSIN_HARD_HAM_URL: ("hard_ham.tar.bz2", ham_dir, "ham"),
    }

    total = 0
    for url, (fname, dest_dir, label) in archives.items():
        local_path = os.path.join(RAW_DIR, fname)
        if not os.path.exists(local_path):
            ok = _download_file(url, local_path)
            if not ok:
                continue
        extracted = _extract_eml_from_tar(local_path, dest_dir, label, max_emails)
        total += len(extracted)
        print(f"  {label}: {len(extracted)} correos extraídos")

    return total


def download_enron(max_emails=1000, output_dir=None):
    if output_dir is None:
        output_dir = os.path.join(RAW_DIR, "enron")
    print("  NOTA: El dataset Enron requiere descarga manual desde:")
    print("  https://www.cs.cmu.edu/~enron/enron_mail_20150507.tar.gz")
    print(f"  Extrae los .eml benignos en: {output_dir}/ham/")
    os.makedirs(os.path.join(output_dir, "ham"), exist_ok=True)
    return 0


def summary(extracted_dirs):
    total = 0
    for d in extracted_dirs:
        if os.path.exists(d):
            count = len(list(Path(d).glob("*.eml")))
            total += count
            label = "benignos" if "ham" in d else "maliciosos"
            print(f"  {os.path.basename(os.path.dirname(d))}/{os.path.basename(d)}: {count} {label}")
    print(f"\nTotal: {total} correos descargados")
    return total


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Descarga datasets públicos de correos")
    parser.add_argument("--max-emails", type=int, default=1000, help="Máx correos por categoría")
    parser.add_argument("--output", default=os.path.join(RAW_DIR, "public"), help="Directorio de salida")
    args = parser.parse_args()

    print("=" * 60)
    print(" Descarga de datasets públicos")
    print("=" * 60)

    data_dir = args.output
    ham_dir = os.path.join(data_dir, "ham")
    spam_dir = os.path.join(data_dir, "spam")

    print("\n[1/2] SpamAssassin...")
    n = download_spamassassin(args.max_emails, data_dir)

    print(f"\n[2/2] Enron (benignos)...")
    download_enron(args.max_emails, data_dir)

    print("\n" + "=" * 60)
    print(" Resumen")
    print("=" * 60)
    summary([ham_dir, spam_dir])
