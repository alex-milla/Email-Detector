# Email Malware Detector

Herramienta de detección de correos maliciosos mediante modelos de aprendizaje automático. Incluye interfaz web, conexión IMAP/OAuth2, análisis con ClamAV, integración con VirusTotal y un detector de correos generados por IA (Anti-Clanker).

## Características

- **10 modelos de análisis** en ensemble (XGBoost, LightGBM, CatBoost y otros)
- Conexión a **Gmail vía IMAP** (App Password o OAuth2) y **Microsoft 365**
- Análisis de adjuntos con **ClamAV**
- Consulta opcional a **VirusTotal API**
- **Modelo 10 — Anti-Clanker**: detecta correos generados por LLMs mediante reglas YAML actualizables
- Sistema **multiusuario**: admins y usuarios limitados
- Re-entrenamiento con feedback manual o archivos `.eml`
- Soporte opcional de **GPU** (CUDA) para el modelo Anti-Clanker
- Interfaz web con **HTTPS** configurable

## Instalación

```bash
git clone https://github.com/tu-usuario/email-detector.git
cd email-detector
chmod +x install.sh
./install.sh
```

El instalador pregunta el directorio destino (por defecto `/root/email-detector`), el puerto web, y si instalar ClamAV y HTTPS.

Al finalizar, accede a `http://TU_IP:5000` con las credenciales iniciales `admin / admin`.

> **Cambia la contraseña** en `/users` antes de usar en producción.

## Estructura del proyecto

```
email-detector/
├── install.sh              # Instalador (no contiene código de la app)
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
│   ├── clamav_scanner.py   # Integración ClamAV
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
| `SECRET_KEY` | Clave secreta Flask (generada automáticamente en instalación) |
| `IMAP_SERVER` / `IMAP_USER` / `IMAP_PASSWORD` | Conexión IMAP genérica |
| `GMAIL_CLIENT_ID` / `GMAIL_CLIENT_SECRET` | OAuth2 Gmail |
| `MS365_CLIENT_ID` / `MS365_TENANT_ID` | Microsoft 365 |
| `VIRUSTOTAL_API_KEY` | API de VirusTotal |
| `USE_GPU` | `true` para habilitar GPU en Anti-Clanker |
| `CLANKER_RULES_URL` | URL para auto-actualizar reglas Anti-Clanker |

## Actualización

Para actualizar el código sin reinstalar:

```bash
git pull
cp web/*.py      /root/email-detector/web/
cp web/templates/*.html /root/email-detector/web/templates/
cp scripts/*.py  /root/email-detector/scripts/
cp config/clanker_rules.yaml /root/email-detector/config/
systemctl restart email-detector
```

## Actualización de reglas Anti-Clanker

Las reglas se pueden actualizar:

- **Manual**: reemplaza `config/clanker_rules.yaml` y reinicia el servicio
- **Desde la GUI**: sección *Anti-Clanker* en `/settings`
- **Automática**: configura `CLANKER_RULES_URL` en `.env` (cron diario a las 09:00)

El formato de las reglas está documentado en `CLANKER_RULES_FORMAT.md` (generado tras la instalación).

## Comandos útiles

```bash
# Estado del servicio
systemctl status email-detector

# Logs en tiempo real
journalctl -u email-detector -f

# Entorno virtual
cd /root/email-detector && source venv/bin/activate

# Actualizar reglas Anti-Clanker manualmente
python scripts/update_clanker_rules.py --force
```

## Licencia

MIT
