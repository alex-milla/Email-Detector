#!/bin/bash
# ============================================================
#  Email Malware Detector — Despliegue Universal
#
#  Un solo script para cualquier Linux pelado:
#    - VM con systemd (Debian, Ubuntu, RHEL, Arch)
#    - Contenedor LXC sin privilegios (Proxmox)
#    - WSL, bare-metal, VPS cloud...
#
#  Uso:
#    chmod +x deploy.sh && ./deploy.sh
# ============================================================
set -e

R='\033[0;31m'; G='\033[0;32m'; Y='\033[1;33m'
C='\033[0;36m'; B='\033[1m'; N='\033[0m'

step()  { echo ""; printf "  ${C}[%s]${N} %s\n" "$1" "$2"; }
ok()    { printf "  ${G}OK${N}: %s\n" "$1"; }
warn()  { printf "  ${Y}WARN${N}: %s\n" "$1"; }
err()   { printf "  ${R}ERROR${N}: %s\n" "$1"; exit 1; }
info()  { printf "  %s\n" "$1"; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ─────────────────────────────────────────────────────────────
#  DETECCIÓN DE ENTORNO
# ─────────────────────────────────────────────────────────────

# ¿Tenemos systemd funcional?
HAS_SYSTEMD=false
if command -v systemctl &>/dev/null && systemctl --version &>/dev/null; then
    # Algunos contenedores tienen el binario pero no el daemon corriendo
    if systemctl is-system-running &>/dev/null || systemctl status &>/dev/null; then
        HAS_SYSTEMD=true
    fi
fi

# ¿Tenemos permisos de root?
HAS_ROOT=false
[ "$EUID" -eq 0 ] && HAS_ROOT=true

# ¿Qué gestor de paquetes tenemos?
PKG_MANAGER=""
if command -v apt-get &>/dev/null; then
    PKG_MANAGER="apt-get"
elif command -v dnf &>/dev/null; then
    PKG_MANAGER="dnf"
elif command -v yum &>/dev/null; then
    PKG_MANAGER="yum"
elif command -v pacman &>/dev/null; then
    PKG_MANAGER="pacman"
fi

# ─────────────────────────────────────────────────────────────
#  CABECERA
# ─────────────────────────────────────────────────────────────
clear
printf "${B}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║    Email Malware Detector — Despliegue Universal    ║"
echo "  ╚══════════════════════════════════════════════════════╝"
printf "${N}\n"

info "Entorno detectado:"
info "  Distro : $(source /etc/os-release 2>/dev/null && echo "$NAME $VERSION_ID" || echo "desconocida")"
info "  systemd: $HAS_SYSTEMD"
info "  root   : $HAS_ROOT"
info "  pkg    : ${PKG_MANAGER:-ninguno detectado}"
echo ""

# ─────────────────────────────────────────────────────────────
#  PREGUNTAS INICIALES
# ─────────────────────────────────────────────────────────────

# Directorio por defecto: /opt si tenemos root, ~/ si no
if $HAS_ROOT; then
    DEFAULT_DIR="/opt/email-detector"
else
    DEFAULT_DIR="$HOME/email-detector"
fi

printf "  ${B}Directorio de instalación [$DEFAULT_DIR]:${N} "
read INSTALL_DIR
INSTALL_DIR="${INSTALL_DIR:-$DEFAULT_DIR}"

IS_FRESH=false
if [ ! -d "$INSTALL_DIR" ] || [ ! -f "$INSTALL_DIR/web/app.py" ]; then
    IS_FRESH=true
fi

if $IS_FRESH; then
    printf "  ${B}Puerto de la GUI web [5000]:${N} "
    read WEB_PORT; WEB_PORT="${WEB_PORT:-5000}"

    if $HAS_SYSTEMD && $HAS_ROOT; then
        printf "  ${B}Instalar servicio systemd? [S/n]:${N} "
        read INSTALL_SVC; INSTALL_SVC="${INSTALL_SVC:-S}"
    else
        info "systemd no disponible o sin root — se usará modo standalone"
        INSTALL_SVC="N"
    fi

    if command -v crontab &>/dev/null; then
        printf "  ${B}Instalar cron jobs? [S/n]:${N} "
        read INSTALL_CRON; INSTALL_CRON="${INSTALL_CRON:-S}"
    else
        info "cron no disponible — se omiten tareas programadas"
        INSTALL_CRON="N"
    fi
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
echo "  systemd    : $INSTALL_SVC"
echo "  cron       : $INSTALL_CRON"
echo "  ClamAV     : $DO_CLAMAV   |   HTTPS: $DO_HTTPS"
echo "  ─────────────────────────────────────────────────────"
printf "  Continuar? [S/n] "; read CONFIRM
case "$CONFIRM" in [Nn]*) echo "Cancelado."; exit 0;; esac
echo ""

# ─────────────────────────────────────────────────────────────
#  BLOQUE 1 — DEPENDENCIAS DEL SISTEMA
# ─────────────────────────────────────────────────────────────
step "1/6" "Instalando dependencias del sistema"

install_pkgs() {
    case "$PKG_MANAGER" in
        apt-get)
            apt-get update -qq
            apt-get install -y -qq python3 python3-pip python3-venv git curl wget cron openssl
            case "$DO_CLAMAV" in [Ss]*)
                apt-get install -y -qq clamav clamav-daemon
                ok "ClamAV instalado"
            ;; esac
            ;;
        dnf|yum)
            $PKG_MANAGER install -y python3 python3-pip python3-virtualenv git curl wget cronie openssl
            case "$DO_CLAMAV" in [Ss]*)
                $PKG_MANAGER install -y clamav clamav-scanner
                ok "ClamAV instalado"
            ;; esac
            ;;
        pacman)
            pacman -Sy --noconfirm python python-pip python-virtualenv git curl wget cronie openssl
            case "$DO_CLAMAV" in [Ss]*)
                pacman -Sy --noconfirm clamav
                ok "ClamAV instalado"
            ;; esac
            ;;
        *)
            warn "No se detectó gestor de paquetes conocido."
            warn "Asegúrate de tener instalados: python3, python3-venv, git, curl, wget, cron, openssl"
            ;;
    esac
}

if $HAS_ROOT; then
    install_pkgs
else
    warn "Sin permisos de root. Si falla la instalación de dependencias Python,"
    warn "instala manualmente: python3 python3-venv git curl wget openssl"
fi

python3 --version || err "Python 3 no está instalado"
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

# Reutilizar venv existente si es válido
if [ -d "venv" ] && [ -f "venv/bin/python" ]; then
    info "venv existente detectado — se reutiliza"
else
    python3 -m venv venv
    ok "venv creado"
fi

. venv/bin/activate
pip install --upgrade pip --quiet
info "Instalando librerías Python (puede tardar 2-3 min)..."
pip install -r "$REPO_DIR/requirements.txt" --quiet
ok "librerías base instaladas"

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
cp "$REPO_DIR/web/updater.py"          "$INSTALL_DIR/web/"

# Templates
cp "$REPO_DIR/web/templates/"*.html    "$INSTALL_DIR/web/templates/"

# Scripts Python
cp "$REPO_DIR/scripts/"*.py            "$INSTALL_DIR/scripts/"

# Scripts bash
cp "$REPO_DIR/scripts/backup.sh"  "$INSTALL_DIR/scripts/"
cp "$REPO_DIR/scripts/retrain.sh" "$INSTALL_DIR/scripts/"

# Script descarga dataset
cp "$REPO_DIR/download_dataset.sh" "$INSTALL_DIR/"

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
    if [ -f "$REPO_DIR/config/.env.example" ]; then
        cp "$REPO_DIR/config/.env.example" "$ENV_FILE"
    elif [ -f "$REPO_DIR/config/env.example" ]; then
        cp "$REPO_DIR/config/env.example" "$ENV_FILE"
    else
        err "No se encuentra config/.env.example en el repositorio"
    fi
    sed -i "s|cambia_esto_por_un_valor_aleatorio|$SECRET_KEY|" "$ENV_FILE"
    sed -i "s|^WEB_PORT=.*|WEB_PORT=$WEB_PORT|" "$ENV_FILE"
    ok ".env generado"
else
    info ".env existente — no se sobreescribe"
fi

# HTTPS: certificado autofirmado
case "$DO_HTTPS" in [Ss]*)
    SSL_DIR="$INSTALL_DIR/config/ssl"
    mkdir -p "$SSL_DIR"
    if [ ! -f "$SSL_DIR/cert.pem" ]; then
        SERVER_HN=$(hostname -f 2>/dev/null || echo "localhost")
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

    CERT_CHECK_SCRIPT="$INSTALL_DIR/scripts/check_cert_expiry.sh"
    cat > "$CERT_CHECK_SCRIPT" << 'CERT_EOF'
#!/bin/bash
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
    sed -i "s|INSTALL_DIR_PLACEHOLDER|$INSTALL_DIR|g" "$CERT_CHECK_SCRIPT"
    chmod +x "$CERT_CHECK_SCRIPT"
    ok "script de aviso de expiración creado"
;; esac

# Base de datos inicial — delegamos en auth.py
VENV_DIR="$INSTALL_DIR/venv"
DB_INIT_OUT=$("$VENV_DIR/bin/python3" - <<PYEOF_DB
import sys, os
sys.path.insert(0, os.path.join("$INSTALL_DIR", "web"))
os.chdir("$INSTALL_DIR")
from auth import init_db
init_db()
PYEOF_DB
)
echo "$DB_INIT_OUT"

# Estado inicial de entrenamiento
"$VENV_DIR/bin/python3" -c "
import json, os
s = {'running': False, 'success': None, 'stdout': '', 'stderr': '', 'started_at': None, 'ended_at': None}
path = os.path.join('$INSTALL_DIR', 'results', 'training_state.json')
with open(path, 'w') as f: json.dump(s, f)
print('  OK: training_state.json')
"

# Recuperar contraseña de admin generada
FIRST_LOGIN="$INSTALL_DIR/config/first-login.txt"
ADMIN_PASS=""
if [ -f "$FIRST_LOGIN" ]; then
    ADMIN_PASS=$(cut -d: -f2 "$FIRST_LOGIN" | tr -d '\n')
fi

ok "configuración completada"

# ─────────────────────────────────────────────────────────────
#  BLOQUE 6 — SERVICIOS
# ─────────────────────────────────────────────────────────────
step "6/6" "Configurando servicios"

PYTHON_BIN="$INSTALL_DIR/venv/bin/python"
GUNICORN="$INSTALL_DIR/venv/bin/gunicorn"

# ── Modo systemd ────────────────────────────────────────────
case "$INSTALL_SVC" in [Ss]*)
    SVC_USER="emaildetector"
    if ! id "$SVC_USER" &>/dev/null; then
        useradd --system --no-create-home --shell /usr/sbin/nologin "$SVC_USER"
        ok "usuario de servicio '$SVC_USER' creado"
    fi

    chown -R "$SVC_USER":"$SVC_USER" "$INSTALL_DIR"
    chmod 600 "$ENV_FILE"

    PROTO="http"
    case "$DO_HTTPS" in [Ss]*) PROTO="https";; esac

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
User=$SVC_USER
WorkingDirectory=$INSTALL_DIR
EnvironmentFile=$INSTALL_DIR/config/.env
ExecStart=$GUNICORN --bind 0.0.0.0:$WEB_PORT --workers 2 --timeout 300 --preload $SSL_ARGS web.app:app
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

    # Sudoers
    SUDOERS_FILE="/etc/sudoers.d/email-detector"
    cat > "$SUDOERS_FILE" << SUDOERS_EOF
$SVC_USER ALL=(ALL) NOPASSWD: /bin/systemctl restart email-detector, /bin/systemctl start email-detector, /bin/systemctl stop email-detector, /bin/systemctl reload email-detector
$SVC_USER ALL=(root) NOPASSWD: $INSTALL_DIR/download_dataset.sh, $INSTALL_DIR/scripts/retrain.sh
SUDOERS_EOF
    chmod 440 "$SUDOERS_FILE"
    ok "sudoers configurado"

    systemctl daemon-reload
    systemctl enable email-detector
    if systemctl is-active --quiet email-detector 2>/dev/null || \
       systemctl is-failed --quiet email-detector 2>/dev/null; then
        systemctl restart email-detector && sleep 2
        systemctl is-active --quiet email-detector \
            && ok "servicio reiniciado" \
            || warn "revisar con: journalctl -u email-detector -n 30"
    else
        systemctl start email-detector
        ok "servicio systemd iniciado"
    fi
    ok "servicio systemd configurado"
;; esac

# ── Modo standalone (sin systemd) ───────────────────────────
if [ "$INSTALL_SVC" != "S" ] && [ "$INSTALL_SVC" != "s" ]; then
    info "Modo standalone — generando scripts de arranque manual"

    # run.sh: arranca gunicorn en foreground
    cat > "$INSTALL_DIR/run.sh" << EOF
#!/bin/bash
# Arranca Email Detector en foreground (para nohup, screen, tmux)
cd "$INSTALL_DIR"
source venv/bin/activate

SSL_ARGS=""
if [ -f "$INSTALL_DIR/config/ssl/cert.pem" ] && [ -f "$INSTALL_DIR/config/ssl/key.pem" ]; then
    SSL_ARGS="--certfile=$INSTALL_DIR/config/ssl/cert.pem --keyfile=$INSTALL_DIR/config/ssl/key.pem"
fi

echo "Iniciando Email Detector en http://0.0.0.0:$WEB_PORT"
mkdir -p "$INSTALL_DIR/logs"
exec gunicorn --bind 0.0.0.0:$WEB_PORT --workers 2 --timeout 300 \\
    --access-logfile "$INSTALL_DIR/logs/access.log" \\
    --error-logfile "$INSTALL_DIR/logs/error.log" \\
    \$SSL_ARGS web.app:app
EOF
    chmod +x "$INSTALL_DIR/run.sh"
    ok "run.sh generado"

    # stop.sh: mata el proceso por PID
    cat > "$INSTALL_DIR/stop.sh" << 'EOF'
#!/bin/bash
PID=$(pgrep -f "gunicorn.*web.app:app" || true)
if [ -n "$PID" ]; then
    echo "Deteniendo Email Detector (PID $PID)..."
    kill "$PID"
    sleep 2
    # Si persiste, forzar
    if pgrep -f "gunicorn.*web.app:app" >/dev/null; then
        pkill -f "gunicorn.*web.app:app"
    fi
    echo "Detenido."
else
    echo "Email Detector no está corriendo."
fi
EOF
    chmod +x "$INSTALL_DIR/stop.sh"
    ok "stop.sh generado"

    # Asegurar permisos del usuario actual
    chown -R "$(whoami)":"$(whoami)" "$INSTALL_DIR" 2>/dev/null || true
    chmod 600 "$ENV_FILE"
fi

# ── Cron jobs (común a ambos modos si hay cron) ─────────────
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

    # logrotate
    LOGROTATE_CONF="$REPO_DIR/email-detector-logrotate"
    if [ -f "$LOGROTATE_CONF" ] && $HAS_ROOT; then
        sed "s|INSTALL_DIR|$INSTALL_DIR|g" "$LOGROTATE_CONF" \
            > /etc/logrotate.d/email-detector
        chmod 644 /etc/logrotate.d/email-detector
        ok "logrotate configurado"
    else
        info "logrotate omitido (sin root o sin plantilla)"
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
echo "  ║         Despliegue completado ✓                     ║"
echo "  ╚══════════════════════════════════════════════════════╝"
printf "${N}"
echo ""
echo "  Acceso      : $PROTO://$IP:$WEB_PORT"
echo "  Usuario     : admin"
if [ -n "$ADMIN_PASS" ]; then
    echo "  Contraseña  : $ADMIN_PASS"
else
    echo "  Contraseña  : (ver $FIRST_LOGIN)"
fi
echo ""

if [ "$INSTALL_SVC" != "S" ] && [ "$INSTALL_SVC" != "s" ]; then
    echo "  Modo standalone:"
    echo "    $INSTALL_DIR/run.sh   # iniciar"
    echo "    $INSTALL_DIR/stop.sh  # detener"
    echo ""
    echo "  Ejemplo con nohup:"
    echo "    nohup $INSTALL_DIR/run.sh > $INSTALL_DIR/logs/server.log 2>&1 &"
    echo ""
else
    echo "  Comandos útiles:"
    echo "    systemctl status email-detector"
    echo "    journalctl -u email-detector -f"
    echo ""
fi

echo "  Cambia la contraseña en: $PROTO://$IP:$WEB_PORT/users"
echo ""

case "$DO_HTTPS" in [Ss]*)
    printf "  ${Y}HTTPS con cert autofirmado: acepta la excepción en tu navegador.${N}\n"
    printf "  ${Y}Para Let's Encrypt: sustituye config/ssl/cert.pem y config/ssl/key.pem${N}\n"
    echo ""
;; esac
