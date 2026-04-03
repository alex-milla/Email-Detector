#!/bin/bash
# ============================================================
# backup.sh — Hace backup del modelo, datos y configuración
#
# Uso:
#   ./scripts/backup.sh              (backup en ~/)
#   ./scripts/backup.sh /ruta/dest   (backup en otra ruta)
# ============================================================

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
DEST_DIR="${1:-$HOME}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_FILE="$DEST_DIR/backup_email_detector_$TIMESTAMP.tar.gz"

echo "======================================================"
echo " Backup Email Detector — $(date)"
echo "======================================================"
echo ""

# Verificar espacio disponible (al menos 500MB)
AVAIL=$(df "$DEST_DIR" | awk 'NR==2 {print $4}')
if [ "$AVAIL" -lt 512000 ]; then
    echo "AVISO: Poco espacio en disco ($(($AVAIL/1024)) MB disponibles)"
fi

echo "Incluyendo en el backup:"
echo "  ✓ models/          (modelo entrenado)"
echo "  ✓ data/processed/  (CSVs de features)"
echo "  ✓ data/labeled/    (correos etiquetados)"
echo "  ✓ results/         (historial de análisis)"
echo "  ✓ config/.env      (configuración y claves)"
echo ""

tar -czf "$BACKUP_FILE"     -C "$(dirname $PROJECT_DIR)"     "$(basename $PROJECT_DIR)/models/"     "$(basename $PROJECT_DIR)/data/processed/"     "$(basename $PROJECT_DIR)/data/labeled/"     "$(basename $PROJECT_DIR)/results/"     "$(basename $PROJECT_DIR)/config/.env"     2>/dev/null || true

SIZE=$(du -sh "$BACKUP_FILE" 2>/dev/null | cut -f1)

echo "======================================================"
echo " Backup completado"
echo " Archivo: $BACKUP_FILE"
echo " Tamaño:  $SIZE"
echo ""
echo " Para restaurar:"
echo "   tar -xzf $BACKUP_FILE -C $(dirname $PROJECT_DIR)"
echo "======================================================"
