#!/bin/bash
# download_dataset.sh — Descarga el SpamAssassin Public Corpus

set -e

echo "======================================================"
echo " Descargando SpamAssassin Public Corpus"
echo "======================================================"

BASE_URL="https://spamassassin.apache.org/old/publiccorpus"
TMPDIR="data/tmp_spamassassin"
mkdir -p "$TMPDIR" data/labeled/benign data/labeled/malicious

HAM_FILES=("20021010_easy_ham.tar.bz2" "20021010_easy_ham_2.tar.bz2" "20021010_hard_ham.tar.bz2")
SPAM_FILES=("20021010_spam.tar.bz2" "20021010_spam_2.tar.bz2")

echo "[1/4] Descargando correos legitimos..."
for f in "${HAM_FILES[@]}"; do
    [ -f "$TMPDIR/$f" ] && echo "  Ya descargado: $f" && continue
    echo "  Descargando: $f"
    wget -q --show-progress -P "$TMPDIR" "$BASE_URL/$f"
done

echo "[2/4] Extrayendo correos legitimos..."
for f in "${HAM_FILES[@]}"; do
    [ -f "$TMPDIR/$f" ] && tar -xjf "$TMPDIR/$f" -C "$TMPDIR" 2>/dev/null || true
done

echo "[3/4] Descargando spam..."
for f in "${SPAM_FILES[@]}"; do
    [ -f "$TMPDIR/$f" ] && echo "  Ya descargado: $f" && continue
    echo "  Descargando: $f"
    wget -q --show-progress -P "$TMPDIR" "$BASE_URL/$f"
done

echo "[4/4] Extrayendo spam..."
for f in "${SPAM_FILES[@]}"; do
    [ -f "$TMPDIR/$f" ] && tar -xjf "$TMPDIR/$f" -C "$TMPDIR" 2>/dev/null || true
done

echo "Organizando correos..."
python3 << 'PYEOF'
import os, shutil, glob

TMPDIR    = "data/tmp_spamassassin"
BENIGN    = "data/labeled/benign"
MALICIOUS = "data/labeled/malicious"

def copy_emails(pattern, dest, prefix):
    count = 0
    for fpath in sorted(glob.glob(pattern)):
        fname = os.path.basename(fpath)
        if fname.startswith("cmd") or fname == "SHA1SUMS": continue
        dest_path = os.path.join(dest, f"{prefix}_{fname}.eml")
        if not os.path.exists(dest_path):
            shutil.copy2(fpath, dest_path); count += 1
    return count

n_ham  = sum(copy_emails(f"{TMPDIR}/{f}/*", BENIGN,    f) for f in ["easy_ham","easy_ham_2","hard_ham"])
n_spam = sum(copy_emails(f"{TMPDIR}/{f}/*", MALICIOUS, f) for f in ["spam","spam_2"])
print(f"  Correos legitimos: {n_ham}")
print(f"  Correos spam:      {n_spam}")
print(f"  Total:             {n_ham + n_spam}")
PYEOF

rm -rf "$TMPDIR"
echo ""
echo "======================================================"
echo " Dataset listo"
echo "  Benignos:   $(ls data/labeled/benign/ | wc -l)"
echo "  Maliciosos: $(ls data/labeled/malicious/ | wc -l)"
echo "======================================================"
