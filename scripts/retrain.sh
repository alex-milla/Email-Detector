#!/bin/bash
# ============================================================
# retrain.sh — Re-entrena el modelo con todos los datos
#              disponibles en data/labeled/
#
# Uso:
#   ./scripts/retrain.sh
#   ./scripts/retrain.sh --move-samples   (mueve primero los
#                          .eml de data/samples/ a labeled/)
# ============================================================

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PYTHON="$PROJECT_DIR/venv/bin/python"
cd "$PROJECT_DIR"

echo "======================================================"
echo " Re-entrenamiento del modelo"
echo " $(date)"
echo "======================================================"

# Opción: mover correos de samples/ a labeled/ antes de entrenar
if [ "$1" = "--move-samples" ]; then
    echo ""
    echo "¿Mover correos de data/samples/ a labeled/?"
    echo "  Los archivos que empiezan por 'good_' → benign/"
    echo "  Los archivos que empiezan por 'bad_'  → malicious/"
    echo ""
    moved=0
    for f in data/samples/good_*.eml; do
        [ -f "$f" ] || continue
        mv "$f" data/labeled/benign/
        echo "  → benign: $(basename $f)"
        moved=$((moved+1))
    done
    for f in data/samples/bad_*.eml; do
        [ -f "$f" ] || continue
        mv "$f" data/labeled/malicious/
        echo "  → malicious: $(basename $f)"
        moved=$((moved+1))
    done
    echo "  Movidos: $moved archivos"
fi

# Contar correos disponibles
BENIGN_COUNT=$(ls data/labeled/benign/*.eml 2>/dev/null | wc -l)
MALICIOUS_COUNT=$(ls data/labeled/malicious/*.eml 2>/dev/null | wc -l)
TOTAL=$((BENIGN_COUNT + MALICIOUS_COUNT))

echo ""
echo "Dataset disponible:"
echo "  Benignos:    $BENIGN_COUNT"
echo "  Maliciosos:  $MALICIOUS_COUNT"
echo "  Total:       $TOTAL"

if [ "$TOTAL" -lt 50 ]; then
    echo ""
    echo "AVISO: Menos de 50 correos. El modelo puede no ser fiable."
    echo "       Se recomienda al menos 200 (100 por clase)."
    echo "       Continúa bajo tu responsabilidad."
    echo ""
fi

# Extraer features
echo ""
echo "[1/3] Extrayendo features de correos benignos..."
$PYTHON scripts/extract_features.py data/labeled/benign     --batch --output data/processed/benign.csv --label 0

echo ""
echo "[2/3] Extrayendo features de correos maliciosos..."
$PYTHON scripts/extract_features.py data/labeled/malicious     --batch --output data/processed/malicious.csv --label 1

# Entrenar
echo ""
echo "[3/3] Entrenando el modelo..."
$PYTHON scripts/train_model.py

# Nota: el servicio NO se reinicia aquí cuando se lanza desde la GUI
# El nuevo modelo se carga automáticamente en la próxima predicción
echo ""
echo "  ✓ Modelo guardado. Se cargará en la próxima consulta."

echo ""
echo "======================================================"
echo " Re-entrenamiento completado — $(date)"
echo " Revisa las métricas arriba para validar el modelo."
echo "======================================================"
