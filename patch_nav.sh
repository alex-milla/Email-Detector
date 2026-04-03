#!/bin/bash
# ============================================================
#  patch_nav.sh — Añade el enlace 🔄 Actualizaciones al navbar
#  de los templates HTML existentes.
#
#  Uso: bash patch_nav.sh /root/email-detector
#  Solo modifica los ficheros que no tienen ya el enlace.
# ============================================================

set -e

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; N='\033[0m'

ok()   { printf "  ${G}OK${N}: %s\n" "$1"; }
warn() { printf "  ${Y}SKIP${N}: %s\n" "$1"; }
err()  { printf "  ${R}ERROR${N}: %s\n" "$1"; exit 1; }

INSTALL_DIR="${1:-/root/email-detector}"
TEMPLATES_DIR="$INSTALL_DIR/web/templates"

echo ""
echo "  Parcheando navbars en: $TEMPLATES_DIR"
echo ""

# El enlace a insertar (justo antes de <div class="nav-right">)
UPDATE_LINK='        {% if user.role == '"'"'admin'"'"' %}<a href="/update" class="nav-link">\xf0\x9f\x94\x84 Actualizaciones<\/a>{% endif %}'

# Función que inserta el enlace antes de nav-right si no existe ya
patch_template() {
    local FILE="$1"
    local BASE
    BASE=$(basename "$FILE")

    if [ ! -f "$FILE" ]; then
        warn "$BASE — no encontrado, omitiendo"
        return
    fi

    # Comprobar si ya está parcheado
    if grep -q 'href="/update"' "$FILE" 2>/dev/null; then
        warn "$BASE — ya tiene el enlace, omitiendo"
        return
    fi

    # Hacer backup antes de modificar
    cp "$FILE" "${FILE}.bak_$(date +%Y%m%d_%H%M%S)"

    # Insertar el enlace antes de la línea que contiene nav-right
    # Compatible con GNU sed (Linux)
    sed -i 's|<div class="nav-right">|'"        {% if user.role == 'admin' %}<a href=\"/update\" class=\"nav-link\">🔄 Actualizaciones</a>{% endif %}"'\n        <div class="nav-right">|' "$FILE"

    # Verificar que el cambio se aplicó
    if grep -q 'href="/update"' "$FILE"; then
        ok "$BASE"
    else
        err "$BASE — el parche no se aplicó correctamente. Restaurando backup..."
        cp "${FILE}.bak_"* "$FILE"
    fi
}

# Parchear los 4 templates
patch_template "$TEMPLATES_DIR/index.html"
patch_template "$TEMPLATES_DIR/training.html"
patch_template "$TEMPLATES_DIR/settings.html"
patch_template "$TEMPLATES_DIR/users.html"

echo ""
echo "  Reiniciando servicio..."
if systemctl restart email-detector 2>/dev/null; then
    sleep 2
    if systemctl is-active --quiet email-detector; then
        ok "Servicio reiniciado correctamente"
    else
        printf "  ${Y}WARN${N}: Revisar con: journalctl -u email-detector -n 20\n"
    fi
else
    warn "systemctl no disponible — reinicia manualmente"
fi

echo ""
echo "  ✅ Listo. Accede a /update en la GUI para verificar."
echo ""
