# Email Malware Detector

Herramienta de detección de correos maliciosos mediante modelos de aprendizaje automático. Incluye interfaz web, conexión IMAP/OAuth2, integración con VirusTotal y un detector de correos generados por IA (Anti-Clanker).

## Características

- **10 modelos de análisis** en ensemble (XGBoost, LightGBM, CatBoost y otros)
- Conexión a **Gmail vía IMAP** (App Password o OAuth2) y **Microsoft 365**
- Análisis de adjuntos con múltiples modelos ML en ensemble
- Consulta opcional a **VirusTotal API**
- **Modelo 10 — Anti-Clanker**: detecta correos generados por LLMs mediante reglas YAML actualizables
- Sistema **multiusuario**: admins y usuarios limitados
- Re-entrenamiento con feedback manual o archivos `.eml`
- Soporte opcional de **GPU** (CUDA) para el modelo Anti-Clanker
- Interfaz web con **HTTPS** configurable

## Despliegue rápido

Un solo script para cualquier Linux pelado: VM, LXC, VPS, bare-metal...

```bash
git clone https://github.com/alex-milla/Email-Detector.git
cd Email-Detector
chmod +x deploy.sh
./deploy.sh
```

El script detecta automáticamente si tienes **systemd** y configura el servicio; si no (LXC sin privilegios, WSL...), genera scripts `run.sh` / `stop.sh` para arranque manual.

### Requisitos

- Linux con Python 3.9+
- 2 GB RAM, 10 GB disco
- Puerto TCP libre (por defecto 5000)

### Al finalizar

Accede a `http://TU_IP:5000` con el usuario **`admin`** y la contraseña que el script genera automáticamente (se muestra en pantalla y se guarda en `config/first-login.txt`).

> **Cambia la contraseña** en `/users` antes de usar en producción.

## Estructura del proyecto

```
email-detector/
├── deploy.sh               # Despliegue universal (systemd / standalone)
├── install.sh              # Instalador legacy (Debian/Ubuntu con systemd)
├── requirements.txt        # Dependencias Python
├── web/
│   ├── app.py              # Aplicación Flask principal
│   ├── auth.py             # Autenticación y sesiones
│   ├── settings_manager.py # Gestión de configuración
│   └── templates/          # Plantillas HTML
├── scripts/
│   ├── extract_features.py # Extracción de features de correos
│   ├── predict.py          # Predicción con el ensemble
│   ├── train_model.py      # Entrenamiento de modelos
│   ├── mailbox_connector.py# Conexión IMAP / OAuth2
│   ├── virustotal.py       # Integración VirusTotal
│   ├── predict.py            # Ensemble de 10 modelos ML + Anti-Clanker
│   ├── extract_clanker_features.py  # Features Anti-Clanker
│   ├── update_clanker_rules.py      # Auto-actualización de reglas
│   ├── auto_scan.py        # Escaneo automático (cron)
│   └── backup.sh           # Backup periódico
└── config/
    ├── .env.example        # Plantilla de configuración
    └── clanker_rules.yaml  # Reglas del detector Anti-Clanker
```

## Configuración

Copia `config/.env.example` a `config/.env` y rellena los valores necesarios:

```bash
cp config/.env.example config/.env
nano config/.env
```

Variables principales:

| Variable | Descripción |
|---|---|
| `SECRET_KEY` | Clave secreta Flask (generada automáticamente en despliegue) |
| `IMAP_SERVER` / `IMAP_USER` / `IMAP_PASSWORD` | Conexión IMAP genérica |
| `GMAIL_CLIENT_ID` / `GMAIL_CLIENT_SECRET` | OAuth2 Gmail |
| `MS365_CLIENT_ID` / `MS365_TENANT_ID` | Microsoft 365 |
| `VIRUSTOTAL_API_KEY` | API de VirusTotal |
| `USE_GPU` | `true` para habilitar GPU en Anti-Clanker |
| `CLANKER_RULES_URL` | URL para auto-actualizar reglas Anti-Clanker |

## Actualización

Para actualizar el código sin reinstalar:

```bash
cd /opt/email-detector   # o ~/email-detector en standalone
git pull origin main
./deploy.sh
```

`deploy.sh` es **idempotente**: no sobrescribe `.env`, `users.db`, modelos ni datos etiquetados.

## Actualización de reglas Anti-Clanker

Las reglas se pueden actualizar:

- **Manual**: reemplaza `config/clanker_rules.yaml` y reinicia el servicio
- **Desde la GUI**: sección *Anti-Clanker* en `/settings`
- **Automática**: configura `CLANKER_RULES_URL` en `.env` (cron diario a las 09:00)

El formato de las reglas está documentado en `CLANKER_RULES_FORMAT.md` (generado tras la instalación).

## Comandos útiles

### Con systemd

```bash
# Estado del servicio
systemctl status email-detector

# Logs en tiempo real
journalctl -u email-detector -f

# Entorno virtual
cd /opt/email-detector && source venv/bin/activate
```

### Modo standalone (sin systemd)

```bash
# Iniciar
cd ~/email-detector
nohup ./run.sh > logs/server.log 2>&1 &

# Detener
./stop.sh

# Logs
tail -f logs/access.log logs/error.log
```

### Actualizar reglas Anti-Clanker manualmente

```bash
cd /opt/email-detector   # o tu directorio de instalación
source venv/bin/activate
python scripts/update_clanker_rules.py --force
```

## Troubleshooting

Consulta [docs/TROUBLESHOOTING.md](docs/TROUBLESHOOTING.md) para problemas comunes:
- LXC sin privilegios
- Dependencias que fallan
- Puerto ocupado
- xgboost/lightgbm/catboost no compilan
- VirusTotal API key inválida

## Desarrollo y Releases

### Validación pre-release (obligatoria)

Antes de generar cualquier release, ejecuta la validación para evitar romper producción:

```bash
python3 scripts/validate_release.py
```

Esto verifica:
- Sintaxis de todos los `.py` y `.sh`
- Que `web.app` importa sin errores (simula `gunicorn --preload`)
- Que `train_model.py` no ejecuta side-effects al importar
- Que no hay referencias a variables antes de su definición en `app.py`

### Generar una release nueva

```bash
python3 scripts/bump_version.py
```

Este script:
1. Ejecuta `validate_release.py` (bloquea si falla)
2. Pide la nueva versión y changelog
3. Actualiza `VERSION` y `version.json`
4. Crea commit + tag y hace push a GitHub
5. Crea la release en GitHub (requiere `GITHUB_TOKEN`)

> **Nunca generes una release sin pasar validate_release.py primero.**

## Licencia

MIT
