# Email Malware Detector

Herramienta de detección de correos maliciosos mediante modelos de aprendizaje automático. Incluye interfaz web, conexión IMAP/OAuth2, integración con VirusTotal, detección de códigos QR (quishing) y un detector de correos generados por IA (Anti-Clanker).

## Características

- **10 modelos de análisis** en ensemble (XGBoost, LightGBM, CatBoost y otros)
- Conexión a **Gmail vía IMAP** (App Password o OAuth2) y **Microsoft 365**
- Análisis de adjuntos con múltiples modelos ML en ensemble
- Consulta opcional a **VirusTotal API**
- **Detección de QR (v2.0)**: escanea imágenes inline y adjuntas, resuelve redirecciones HTTP/meta/JS y alimenta 9 nuevas features ML
- **Modelo 10 — Anti-Clanker**: detecta correos generados por LLMs mediante reglas YAML actualizables
- **Motor ClickFix (v1.3.0)**: detecta el engaño de copiar/pegar PowerShell ofuscado, lo desofusca (Base64/UTF-16LE, `fromCharCode`, `atob`, escapes, concatenación) y extrae la URL/dominio/IP original (C2). Escala a MALICIOSO con alta confianza
- **Contenido oculto / Prompt injection (v1.4.0)**: detecta instrucciones dirigidas a una IA escondidas al ojo humano (CSS oculto, atributos/metadatos, Unicode invisible/bidi) y las marca. Multi-idioma configurable por el admin
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
│   ├── extract_features.py # Extracción de features de correos (incluye QR)
│   ├── predict.py          # Predicción con el ensemble
│   ├── train_model.py      # Entrenamiento de modelos
│   ├── mailbox_connector.py# Conexión IMAP / OAuth2
│   ├── virustotal.py       # Integración VirusTotal
│   ├── qr_decoder.py       # Decodificación de QR (pyzbar + OpenCV)
│   ├── url_resolver.py     # Resolución de redirecciones HTTP/meta/JS
│   ├── extract_clanker_features.py  # Features Anti-Clanker
│   ├── clickfix_decoder.py          # Motor ClickFix (detección, desofuscado, IoCs)
│   ├── hidden_text.py               # Contenido oculto / prompt injection (multi-idioma)
│   ├── update_clanker_rules.py      # Auto-actualización de reglas
│   ├── train_clanker_model.py       # Reentrena solo el Modelo 10 (Anti-Clanker)
│   ├── retrain_clanker.py           # Orquestador: dataset + reentrenar Anti-Clanker
│   ├── generate_synthetic_qr_dataset.py       # Dataset sintético con QR
│   ├── generate_synthetic_clanker_dataset.py # Dataset sintético Anti-Clanker
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
| `QR_USE_JS_RESOLVER` | `true` (default) para resolver redirecciones JS con Playwright; `false` para solo HTTP+meta |
| `HIDDEN_TEXT_LANGS` | Idiomas esperados en contenido oculto (coma). Por defecto `es,en`; el resto sube sospecha |

## Actualización

Para actualizar el código sin reinstalar:

```bash
cd /opt/email-detector   # o ~/email-detector en standalone
git pull origin main
./deploy.sh
```

`deploy.sh` es **idempotente**: no sobrescribe `.env`, `users.db`, modelos ni datos etiquetados, y **reinstala las dependencias dentro del `venv`** del proyecto.

> **No uses el `pip` del sistema** (`pip install -r requirements.txt` a secas). En Debian/Ubuntu modernos falla con `externally-managed-environment` (PEP 668). Usa `./deploy.sh`, la actualización desde la GUI (`/update`) o el pip del entorno virtual:
>
> ```bash
> cd ~/Email-Detector        # o /opt/email-detector
> source venv/bin/activate
> pip install -r requirements.txt
> ```

### Actualización a v2.0.0 (breaking change)

La versión 2.0.0 añade **9 features de QR** al modelo. El modelo entrenado en v1.x **no es compatible**.

Pasos obligatorios tras actualizar a v2.0.0:

1. Instalar dependencias del sistema: `apt-get install -y libzbar0`
2. Instalar dependencias Python: `pip install pyzbar opencv-python-headless Pillow beautifulsoup4 playwright`
3. Instalar navegador Playwright: `python -m playwright install chromium --with-deps`
4. **Reentrenar el modelo** con tu dataset etiquetado (ver sección *Reentrenamiento*)
5. Reiniciar el servicio

## Actualización de reglas Anti-Clanker

Las reglas se pueden actualizar:

- **Manual**: reemplaza `config/clanker_rules.yaml` y reinicia el servicio
- **Desde la GUI**: sección *Anti-Clanker* en `/settings`
- **Automática**: configura `CLANKER_RULES_URL` en `.env` (cron diario a las 09:00)

El formato de las reglas está documentado en `CLANKER_RULES_FORMAT.md` (generado tras la instalación).

## External Dynamic Lists (EDL)

Permiten descargar y consultar localmente listas externas de indicadores
maliciosos. Se gestionan desde **Ajustes → Detección → Listas EDL** (solo admin):
añadir/editar listas, activarlas, sincronizarlas y programar su intervalo.

- **Formatos**: lista plana (URL, dominio o IP/CIDR por línea), formato hosts
  (`0.0.0.0 dominio`), comentarios `#`/`;`/`//` y ofuscación (`hxxp`, `[.]`).
  El tipo se detecta automáticamente, incluso en listas mixtas.
- **Espacios independientes**: URL (coincidencia exacta), dominio (exacto +
  subdominios) e IP (exacta + CIDR). Una entrada nunca se expande a otro espacio.
- **Efecto**: una coincidencia fuerza el veredicto a `MALICIOSO` (riesgo ≥ 90),
  igual que VirusTotal o ClickFix.
- **Higiene**: cada sincronización reemplaza la lista completa, por lo que los
  indicadores retirados de la fuente desaparecen automáticamente.
- **Solo HTTPS** y bloqueo de hosts internos (anti-SSRF); nunca se ejecuta el
  contenido descargado.
- **Programación**: activa "Auto-sincronizar" en la GUI; un heartbeat de cron
  cada 15 min sincroniza las listas cuyo intervalo haya vencido.

### Sincronizar las EDL manualmente

```bash
cd /opt/email-detector   # o tu directorio de instalación
source venv/bin/activate
python scripts/update_edl.py            # todas las listas activas
python scripts/update_edl.py --due      # solo las vencidas
python scripts/update_edl.py --list ID  # una lista concreta
python scripts/update_edl.py --show     # estado sin descargar
```

## Comandos útiles

### Health check

```bash
# Estado básico + resumen de dependencias (público)
curl -sk https://localhost:5000/health

# Detalle completo de dependencias (solo admin, requiere sesión)
curl -sk https://localhost:5000/health/dependencies
```

`/health` incluye `dependencies` (sqlite, modelo, reglas Anti-Clanker, Chromium
y VirusTotal) y `dependencies_ok`. Chromium y VirusTotal son opcionales: no
afectan al estado global.

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

`run.sh` (gunicorn) y el arranque directo `python web/app.py` escriben
`logs/access.log` y `logs/error.log` con rotación (5 MB × 5).

### Reentrenamiento del modelo

Entrena un modelo nuevo con correos `.eml` etiquetados:

```bash
cd /opt/email-detector
source venv/bin/activate

# Extraer features
python scripts/extract_features.py --batch /ruta/a/benignos --output data/processed/benign.csv --label 0
python scripts/extract_features.py --batch /ruta/a/maliciosos --output data/processed/malicious.csv --label 1

# Entrenar ensemble
python scripts/train_model.py
```

El script lee automáticamente todos los CSVs de `data/processed/` y genera `models/email_classifier.joblib` junto con `model_metadata.json`.

### Reentrenamiento del Anti-Clanker (Modelo 10)

Si no dispones de correos etiquetados, genera un dataset sintético que ejercita
las features Anti-Clanker v1.2.0 (CSS sobre-ingenierizado, clipboard abuse,
prompt injection, script/event handlers):

```bash
cd /opt/email-detector
source venv/bin/activate

# 1. Generar .eml sintéticos (benign + malicious)
python scripts/generate_synthetic_clanker_dataset.py

# 2. Extraer features
python scripts/etl_pipeline.py \
  --ham-dir data/synthetic_clanker/benign \
  --spam-dir data/synthetic_clanker/malicious \
  --output clanker_synthetic --no-balance

# 3. Reentrenar SOLO el Modelo 10 (no toca email_classifier.joblib)
python scripts/train_clanker_model.py --csv data/processed/clanker_synthetic_raw.csv
```

`train_clanker_model.py` reporta AUC, umbral F2 e importancia de cada feature
(incluidas las nuevas de v1.2.0) y actualiza `models/model_metadata.json`. Con
datos reales, apunta `--csv` a los CSV de `data/processed/` generados por el ETL.

También disponible el orquestador (genera el sintético si no hay CSVs) y la GUI:

```bash
python scripts/retrain_clanker.py                 # usa data/processed/*.csv
python scripts/retrain_clanker.py --synthetic     # fuerza dataset sintético
```

En **Entrenamiento → Puesta en marcha → 3. Anti-Clanker** (solo admin) hay dos
botones: *Reentrenar con CSVs* y *Generar sintético + Reentrenar*. El proceso
corre en background y no toca `email_classifier.joblib`.

La página de Entrenamiento está organizada en tres pestañas: **Puesta en
marcha** (solo la primera vez: obtener datos, entrenar el modelo base y, si se
quiere, preparar el Anti-Clanker), **Mantenimiento** (lo habitual: reentrenar
con las correcciones marcadas) y **Modelos** (avanzado, admin: ranking y
activación de modelos). Una tarjeta de estado superior indica los pasos que
faltan y ofrece la acción recomendada.

### Detección de ClickFix (v1.3.0)

El motor ClickFix analiza el cuerpo HTML, el texto plano y los adjuntos
`.html/.htm/.xhtml/.svg`:

- Detecta Clipboard API, `document.execCommand('copy')`, textarea oculto,
  frases señuelo (Win+R, "verify you are human", "pega el comando") y
  falso CAPTCHA.
- Desofusca por capas, **sin ejecutar nada**: Base64 (incl. UTF-16LE de
  `-enc`), `String.fromCharCode`, `atob`, escapes `\x`/`\u`, concatenación de
  literales y **reconstrucción estática** de cadenas ensambladas con variables
  JS (`a='http://…'; b='…'; writeText(a+b)`), arrays numéricos y secuencias
  `[char]NN` de PowerShell.
- Extrae los indicadores originales (URL/dominio/IP) del comando ofuscado y
  los consulta en VirusTotal.
- Con alta confianza (comando ofuscado + vector de copiado + IoCs) escala el
  veredicto a **MALICIOSO**. Los indicadores aparecen en el detalle y el
  informe.

Las features `clanker_clickfix_*` alimentan el Modelo 10: reentrena el
Anti-Clanker para que el modelo las aproveche. Las reglas YAML de la categoría
`clickfix` (CLK-033…CLK-041) se actualizan como el resto de reglas Anti-Clanker.

### Contenido oculto / Prompt injection (v1.4.0)

Detecta prompts maliciosos ocultos al ojo humano dentro del correo:

- **CSS visual**: `display:none`, `visibility:hidden`, `font-size:0`, color igual
  al fondo, off-screen, `mso-hide:all`, `clip`, `transform:scale(0)`... en
  estilos inline y reglas `<style>`.
- **Atributos/metadatos**: `hidden`, `aria-hidden`, `alt`, `title`,
  `aria-label`, `<title>`, meta description/keywords, `<noscript>`.
- **Unicode invisible**: zero-width, BOM, soft hyphen y control bidi (RLO/LRO).
- **Comentarios HTML** (reglas CLK-030/031/032).

Si encuentra un **patrón de prompt injection** en ese texto oculto, **escala a
MALICIOSO** y muestra el texto, el motivo y la coincidencia. El texto oculto en
un idioma **no esperado** sube el riesgo (sin forzar MALICIOSO); el texto oculto
legítimo (p. ej. el *preheader* de marketing) no escala.

Idiomas habituales: tarjeta **🌐 Idiomas habituales en contenido oculto** al
inicio de *Configuración → Detección* (solo admin), con un **desplegable
buscable de 97 idiomas** (identificación offline con `langid`) o la variable
`HIDDEN_TEXT_LANGS` en `.env` (por defecto `es,en`). El texto oculto en un
idioma no seleccionado sube la sospecha. Los patrones de inyección se amplían
por idioma en `config/clanker_rules.yaml` (campo `lang`).

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
