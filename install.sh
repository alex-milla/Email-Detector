#!/bin/bash
# ============================================================
#  Email Malware Detector — Instalador
#  Uso: chmod +x install.sh && ./install.sh
# ============================================================
set -e

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1m'; N='\033[0m'

step()  { echo ""; printf "  ${C}[%s]${N} %s\n" "$1" "$2"; }
ok()    { printf "  ${G}OK${N}: %s\n" "$1"; }
warn()  { printf "  ${Y}WARN${N}: %s\n" "$1"; }
err()   { printf "  ${R}ERROR${N}: %s\n" "$1"; exit 1; }
info()  { printf "  %s\n" "$1"; }

# Directorio donde está este script (raíz del repo)
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

svc_restart() {
    if systemctl is-active --quiet email-detector 2>/dev/null || \
       systemctl is-failed --quiet email-detector 2>/dev/null; then
        systemctl restart email-detector && sleep 2
        systemctl is-active --quiet email-detector \
            && ok "servicio reiniciado" \
            || warn "revisar con: journalctl -u email-detector -n 30"
    fi
}

# ─────────────────────────────────────────────────────────────
#  CABECERA
# ─────────────────────────────────────────────────────────────
clear
printf "${B}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║       Email Malware Detector — Instalador           ║"
echo "  ╚══════════════════════════════════════════════════════╝"
printf "${N}\n"

# ─────────────────────────────────────────────────────────────
#  PREGUNTAS INICIALES
# ─────────────────────────────────────────────────────────────
printf "  ${B}Directorio de instalación [/root/email-detector]:${N} "
read INSTALL_DIR
INSTALL_DIR="${INSTALL_DIR:-/root/email-detector}"

IS_FRESH=false
if [ ! -d "$INSTALL_DIR" ] || [ ! -f "$INSTALL_DIR/web/app.py" ]; then
    IS_FRESH=true
fi

if $IS_FRESH; then
    printf "  ${B}Puerto de la GUI web [5000]:${N} "
    read WEB_PORT; WEB_PORT="${WEB_PORT:-5000}"
    printf "  ${B}Instalar servicio systemd? [S/n]:${N} "
    read INSTALL_SVC; INSTALL_SVC="${INSTALL_SVC:-S}"
    printf "  ${B}Instalar cron jobs? [S/n]:${N} "
    read INSTALL_CRON; INSTALL_CRON="${INSTALL_CRON:-S}"
else
    WEB_PORT=$(grep -E "^WEB_PORT=" "$INSTALL_DIR/config/.env" 2>/dev/null \
               | cut -d= -f2 | tr -d '[:space:]') || true
    WEB_PORT="${WEB_PORT:-5000}"
    INSTALL_SVC="S"
    INSTALL_CRON="S"
    info "Instalación existente detectada en $INSTALL_DIR"
fi

printf "  ${B}Instalar ClamAV? [S/n]:${N} "
read DO_CLAMAV; DO_CLAMAV="${DO_CLAMAV:-S}"

printf "  ${B}Habilitar HTTPS (cert autofirmado)? [s/N]:${N} "
read DO_HTTPS; DO_HTTPS="${DO_HTTPS:-N}"

# MED-07: días de validez del certificado (máximo 365)
CERT_DAYS=365
case "$DO_HTTPS" in [Ss]*)
    printf "  ${B}Días de validez del certificado [365, máx 365]:${N} "
    read CERT_DAYS_INPUT
    if [[ "$CERT_DAYS_INPUT" =~ ^[0-9]+$ ]] && [ "$CERT_DAYS_INPUT" -gt 0 ] && [ "$CERT_DAYS_INPUT" -le 365 ]; then
        CERT_DAYS="$CERT_DAYS_INPUT"
    else
        CERT_DAYS=365
        info "Valor no válido — se usarán 365 días"
    fi
;; esac

echo ""
echo "  ─────────────────────────────────────────────────────"
echo "  Directorio : $INSTALL_DIR"
echo "  Puerto     : $WEB_PORT"
echo "  ClamAV     : $DO_CLAMAV   |   HTTPS: $DO_HTTPS"
echo "  ─────────────────────────────────────────────────────"
printf "  Continuar? [S/n] "; read CONFIRM
case "$CONFIRM" in [Nn]*) echo "Cancelado."; exit 0;; esac
echo ""

# ─────────────────────────────────────────────────────────────
#  BLOQUE 1 — DEPENDENCIAS DEL SISTEMA
# ─────────────────────────────────────────────────────────────
step "1/6" "Instalando dependencias del sistema"
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv git curl wget cron
case "$DO_CLAMAV" in [Ss]*)
    apt-get install -y -qq clamav clamav-daemon
    ok "ClamAV instalado"
;; esac
ok "$(python3 --version)"

# ─────────────────────────────────────────────────────────────
#  BLOQUE 2 — ESTRUCTURA DE DIRECTORIOS
# ─────────────────────────────────────────────────────────────
step "2/6" "Creando estructura de directorios"
mkdir -p "$INSTALL_DIR"/{config,logs,models/all_models,results,scripts}
mkdir -p "$INSTALL_DIR"/data/{raw,processed,samples,labeled/benign,labeled/malicious}
mkdir -p "$INSTALL_DIR"/web/templates
mkdir -p "$INSTALL_DIR"/web/static/{css,js}
ok "$INSTALL_DIR"

# ─────────────────────────────────────────────────────────────
#  BLOQUE 3 — ENTORNO PYTHON
# ─────────────────────────────────────────────────────────────
step "3/6" "Creando entorno virtual Python"
cd "$INSTALL_DIR"
python3 -m venv venv
. venv/bin/activate
pip install --upgrade pip --quiet
info "Instalando librerías Python (puede tardar 2-3 min)..."
pip install -r "$REPO_DIR/requirements.txt" --quiet
ok "librerías instaladas"

# Modelos opcionales con GPU
pip install xgboost --quiet  && ok "xgboost"   || warn "xgboost falló (opcional)"
pip install lightgbm --quiet && ok "lightgbm"  || warn "lightgbm falló (opcional)"
pip install catboost --quiet && ok "catboost"  || warn "catboost falló (opcional)"

# ─────────────────────────────────────────────────────────────
#  BLOQUE 4 — COPIAR CÓDIGO FUENTE
# ─────────────────────────────────────────────────────────────
step "4/6" "Copiando archivos del proyecto"

# Web
cp "$REPO_DIR/web/app.py"              "$INSTALL_DIR/web/"
cp "$REPO_DIR/web/auth.py"             "$INSTALL_DIR/web/"
cp "$REPO_DIR/web/settings_manager.py" "$INSTALL_DIR/web/"

# Templates
cp "$REPO_DIR/web/templates/"*.html    "$INSTALL_DIR/web/templates/"

# Scripts Python
cp "$REPO_DIR/scripts/"*.py            "$INSTALL_DIR/scripts/"

# Scripts bash
cp "$REPO_DIR/scripts/backup.sh"       "$INSTALL_DIR/scripts/"
cp "$REPO_DIR/scripts/retrain.sh"      "$INSTALL_DIR/scripts/"
chmod +x "$INSTALL_DIR/scripts/"*.sh
chmod +x "$INSTALL_DIR/scripts/"*.py

# Script descarga dataset (en raíz del proyecto)
cp "$REPO_DIR/download_dataset.sh" "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/download_dataset.sh"

# Config
cp "$REPO_DIR/config/clanker_rules.yaml" "$INSTALL_DIR/config/"

ok "archivos copiados"

# ─────────────────────────────────────────────────────────────
#  BLOQUE 5 — CONFIGURACIÓN
# ─────────────────────────────────────────────────────────────
step "5/6" "Generando configuración"

SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_hex(32))" 2>/dev/null || echo "changeme_$(date +%s)")

# .env (solo si no existe)
ENV_FILE="$INSTALL_DIR/config/.env"
if [ ! -f "$ENV_FILE" ]; then
    cp "$REPO_DIR/config/.env.example" "$ENV_FILE"
    sed -i "s|cambia_esto_por_un_valor_aleatorio|$SECRET_KEY|" "$ENV_FILE"
    sed -i "s|^WEB_PORT=.*|WEB_PORT=$WEB_PORT|" "$ENV_FILE"
    ok ".env generado desde .env.example"
else
    info ".env existente — no se sobreescribe"
fi

# MED-08: el .env contiene credenciales sensibles — restringir acceso.
# Se aplica siempre, tanto en instalación nueva como en actualización.
chown root:root "$ENV_FILE"
chmod 600 "$ENV_FILE"
ok ".env protegido (chmod 600, root:root)"

# HTTPS: certificado autofirmado
case "$DO_HTTPS" in [Ss]*)
    SSL_DIR="$INSTALL_DIR/config/ssl"
    mkdir -p "$SSL_DIR"
    if [ ! -f "$SSL_DIR/cert.pem" ]; then
        SERVER_HN=$(hostname -f 2>/dev/null || echo "localhost")
        # MED-07: ECDSA P-256 (más seguro y rápido que RSA-2048) + días configurables
        openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
            -nodes -days "$CERT_DAYS" \
            -keyout "$SSL_DIR/key.pem" -out "$SSL_DIR/cert.pem" \
            -subj "/C=ES/ST=Spain/L=Local/O=Email Malware Detector/OU=Security/CN=$SERVER_HN" \
            2>/dev/null
        grep -q "^SSL_CERT=" "$ENV_FILE" 2>/dev/null \
            || echo "SSL_CERT=$SSL_DIR/cert.pem" >> "$ENV_FILE"
        grep -q "^SSL_KEY="  "$ENV_FILE" 2>/dev/null \
            || echo "SSL_KEY=$SSL_DIR/key.pem"   >> "$ENV_FILE"
        ok "certificado ECDSA P-256 generado en $SSL_DIR (válido $CERT_DAYS días)"
    else
        info "certificado ya existe — no se regenera"
    fi

    # MED-07: cron de aviso de expiración — avisa 30 días antes por log
    # La GUI lee /api/ssl/status para mostrar el estado y botón de renovación
    CERT_CHECK_SCRIPT="$INSTALL_DIR/scripts/check_cert_expiry.sh"
    cat > "$CERT_CHECK_SCRIPT" << 'CERT_EOF'
#!/bin/bash
# Comprueba la expiración del certificado TLS y avisa si faltan <=30 días.
# Ejecutado diariamente por cron. La GUI lee /api/ssl/status para el mismo dato.
CERT="INSTALL_DIR_PLACEHOLDER/config/ssl/cert.pem"
LOG="INSTALL_DIR_PLACEHOLDER/logs/cert_expiry.log"
[ ! -f "$CERT" ] && exit 0
EXPIRY=$(openssl x509 -enddate -noout -in "$CERT" 2>/dev/null | cut -d= -f2)
EXPIRY_EPOCH=$(date -d "$EXPIRY" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$EXPIRY" +%s 2>/dev/null)
NOW_EPOCH=$(date +%s)
DAYS_LEFT=$(( (EXPIRY_EPOCH - NOW_EPOCH) / 86400 ))
echo "$(date '+%Y-%m-%d %H:%M') — Certificado expira en $DAYS_LEFT días ($EXPIRY)" >> "$LOG"
if [ "$DAYS_LEFT" -le 30 ]; then
    echo "$(date '+%Y-%m-%d %H:%M') — AVISO: el certificado expira en $DAYS_LEFT días. Renuévalo desde la GUI." >> "$LOG"
fi
CERT_EOF
    # Sustituir placeholder por ruta real
    sed -i "s|INSTALL_DIR_PLACEHOLDER|$INSTALL_DIR|g" "$CERT_CHECK_SCRIPT"
    chmod +x "$CERT_CHECK_SCRIPT"
    ok "script de aviso de expiración creado en scripts/check_cert_expiry.sh"
;; esac

# Base de datos inicial — delegamos en auth.py que tiene el esquema completo
VENV_DIR="$INSTALL_DIR/venv"
"$VENV_DIR/bin/python3" - <<PYEOF_DB
import sys, os
sys.path.insert(0, os.path.join("$INSTALL_DIR", "web"))
os.chdir("$INSTALL_DIR")
from auth import init_db
init_db()
print("  OK: base de datos inicializada en config/users.db (admin/admin1234)")
PYEOF_DB

# Estado inicial de entrenamiento
"$VENV_DIR/bin/python3" -c "
import json, os
s = {'running': False, 'success': None, 'stdout': '', 'stderr': '', 'started_at': None, 'ended_at': None}
path = os.path.join('$INSTALL_DIR', 'results', 'training_state.json')
with open(path, 'w') as f: json.dump(s, f)
print('  OK: training_state.json')
"

ok "configuración completada"

# ─────────────────────────────────────────────────────────────
#  BLOQUE 6 — SERVICIOS
# ─────────────────────────────────────────────────────────────
step "6/6" "Configurando servicios"

PYTHON_BIN="$INSTALL_DIR/venv/bin/python"
GUNICORN="$INSTALL_DIR/venv/bin/gunicorn"

# systemd
case "$INSTALL_SVC" in [Ss]*)
    PROTO="http"
    case "$DO_HTTPS" in [Ss]*) PROTO="https";; esac

    # Construir ExecStart con o sin SSL
    SSL_ARGS=""
    case "$DO_HTTPS" in [Ss]*)
        SSL_ARGS="--certfile=$INSTALL_DIR/config/ssl/cert.pem --keyfile=$INSTALL_DIR/config/ssl/key.pem"
    ;; esac

    cat > /etc/systemd/system/email-detector.service << EOF
[Unit]
Description=Email Malware Detector
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/config/.env
ExecStart=$GUNICORN --bind 0.0.0.0:$WEB_PORT --workers 2 --timeout 300 --preload $SSL_ARGS web.app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    systemctl enable email-detector
    svc_restart
    ok "servicio systemd configurado"
;; esac

# Cron jobs
case "$INSTALL_CRON" in [Ss]*)
    (crontab -l 2>/dev/null | grep -v "email-detector" || true
     echo "# Email Malware Detector"
     echo "0 2  * * * $INSTALL_DIR/scripts/backup.sh >> $INSTALL_DIR/logs/backup.log 2>&1"
     echo "*/5 * * * * $PYTHON_BIN $INSTALL_DIR/scripts/auto_scan.py >> $INSTALL_DIR/logs/auto_scan.log 2>&1"
     echo "0 9  * * * $PYTHON_BIN $INSTALL_DIR/scripts/update_clanker_rules.py >> $INSTALL_DIR/logs/clanker_update.log 2>&1"
     echo "0 8  * * * $INSTALL_DIR/scripts/check_cert_expiry.sh >> $INSTALL_DIR/logs/cert_expiry.log 2>&1"
    ) | crontab -
    touch "$INSTALL_DIR/logs/backup.log" \
          "$INSTALL_DIR/logs/auto_scan.log" \
          "$INSTALL_DIR/logs/clanker_update.log" \
          "$INSTALL_DIR/logs/cert_expiry.log" 2>/dev/null || true
    ok "cron jobs configurados"

    # HIGH-06: logrotate — evita que los logs de cron llenen el disco.
    # Rotación diaria, 14 días de historial comprimido.
    LOGROTATE_CONF="$REPO_DIR/email-detector-logrotate"
    if [ -f "$LOGROTATE_CONF" ]; then
        # Sustituir la ruta de instalación en la plantilla y copiar al sistema
        sed "s|INSTALL_DIR|$INSTALL_DIR|g" "$LOGROTATE_CONF" \
            > /etc/logrotate.d/email-detector
        chmod 644 /etc/logrotate.d/email-detector
        ok "logrotate configurado (/etc/logrotate.d/email-detector)"
    else
        warn "No se encontró email-detector-logrotate — configura logrotate manualmente"
    fi
;; esac

# ─────────────────────────────────────────────────────────────
#  RESUMEN FINAL
# ─────────────────────────────────────────────────────────────
IP=$(hostname -I | awk '{print $1}' 2>/dev/null || echo "TU_IP")
PROTO="http"
case "$DO_HTTPS" in [Ss]*) PROTO="https";; esac

printf "${B}${G}"
echo ""
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║         Instalación completada ✓                    ║"
echo "  ╚══════════════════════════════════════════════════════╝"
printf "${N}"
echo ""
echo "  Acceso      : $PROTO://$IP:$WEB_PORT"
echo "  Usuario     : admin"
echo "  Contraseña  : admin"
echo ""
printf "  ${Y}Cambia la contraseña en: $PROTO://$IP:$WEB_PORT/users${N}\n"
echo ""
echo "  Comandos útiles:"
echo "    systemctl status email-detector"
echo "    journalctl -u email-detector -f"
echo "    cd $INSTALL_DIR && source venv/bin/activate"
echo ""
case "$DO_HTTPS" in [Ss]*)
    printf "  ${Y}HTTPS con cert autofirmado: acepta la excepción en tu navegador.${N}\n"
    printf "  ${Y}Para Let's Encrypt: sustituye config/ssl/cert.pem y config/ssl/key.pem${N}\n"
    echo ""
;; esac
