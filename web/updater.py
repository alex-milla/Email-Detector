#!/usr/bin/env python3
"""
updater.py — Gestión de actualizaciones de Email Malware Detector.

Responsabilidades:
  - Leer la versión instalada localmente (fichero VERSION)
  - Consultar la versión disponible en GitHub (version.json)
  - Comparar versiones y determinar si hay actualización
  - Descargar el ZIP de actualización
  - Validar su contenido (lista blanca de rutas, sin path traversal)
  - Hacer backup de los ficheros afectados
  - Aplicar los nuevos ficheros
  - Reiniciar el servicio systemd
  - Rollback automático si el servicio no levanta
"""

import os
import json
import shutil
import subprocess
import tempfile
import threading
import zipfile
from datetime import datetime

import requests
from packaging.version import Version

# ── Configuración ──────────────────────────────────────────────────────────────

VERSION_JSON_URL = (
    "https://raw.githubusercontent.com/alex-milla/Email-Detector/main/version.json"
)

_BASE_DIR    = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VERSION_FILE = os.path.join(_BASE_DIR, "VERSION")
BACKUP_DIR   = os.path.join(_BASE_DIR, "config", "update_backups")
SERVICE_NAME = "email-detector"
UPDATE_STATE_FILE = os.path.join(_BASE_DIR, "results", "update_state.json")
REQUEST_TIMEOUT = 15

# Rutas permitidas dentro del ZIP (lista blanca)
# Ningún fichero fuera de estas rutas se aplicará nunca
ALLOWED_PATHS = {
    "web/",
    "scripts/",
    "config/clanker_rules.yaml",
    "VERSION",
    "version.json",
    "requirements.txt",
}

# ── Estado global del proceso de actualización ────────────────────────────────

_update_state = {
    "running":     False,
    "success":     None,
    "log":         [],
    "started_at":  None,
    "ended_at":    None,
    "backup_path": None,
}
_update_lock = threading.Lock()


def get_update_state() -> dict:
    """Devuelve una copia del estado actual del proceso."""
    with _update_lock:
        return {
            "running":     _update_state["running"],
            "success":     _update_state["success"],
            "log":         list(_update_state["log"]),
            "started_at":  _update_state["started_at"],
            "ended_at":    _update_state["ended_at"],
            "backup_path": _update_state["backup_path"],
        }


def _log(msg: str):
    """Añade una línea al log con timestamp."""
    ts   = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with _update_lock:
        _update_state["log"].append(line)


def _set_state(**kwargs):
    with _update_lock:
        _update_state.update(kwargs)


def _save_state_to_disk():
    """Guarda el estado actual en disco para sobrevivir reinicios del servicio."""
    try:
        os.makedirs(os.path.dirname(UPDATE_STATE_FILE), exist_ok=True)
        with _update_lock:
            state = dict(_update_state)
        with open(UPDATE_STATE_FILE, "w") as f:
            json.dump(state, f)
    except Exception as e:
        print(f"[updater] No se pudo guardar estado en disco: {e}")


def _load_state_from_disk():
    """Carga el estado desde disco al arrancar (recuperación tras reinicio)."""
    try:
        if os.path.exists(UPDATE_STATE_FILE):
            with open(UPDATE_STATE_FILE) as f:
                saved = json.load(f)
            # Si el proceso anterior marcó running=True pero ya no hay proceso,
            # significa que el servicio se reinició — marcamos como completado.
            if saved.get("running"):
                saved["running"] = False
                if saved.get("success") is None:
                    saved["success"] = True  # El reinicio fue exitoso
            with _update_lock:
                _update_state.update(saved)
    except Exception as e:
        print(f"[updater] No se pudo cargar estado desde disco: {e}")


# Cargar estado persistido al importar el módulo
_load_state_from_disk()


# ── Versiones ──────────────────────────────────────────────────────────────────

def get_local_version() -> str:
    try:
        with open(VERSION_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "0.0.0"
    except Exception as e:
        return f"error: {e}"


def get_remote_version_info() -> dict:
    try:
        resp = requests.get(VERSION_JSON_URL, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()
    except requests.exceptions.ConnectionError:
        return {"error": "No se puede conectar con GitHub. Comprueba la red."}
    except requests.exceptions.Timeout:
        return {"error": "Tiempo de espera agotado al contactar GitHub."}
    except requests.exceptions.HTTPError as e:
        return {"error": f"Error HTTP al obtener version.json: {e}"}
    except json.JSONDecodeError:
        return {"error": "El fichero version.json remoto no es JSON válido."}
    except Exception as e:
        return {"error": f"Error inesperado: {e}"}


def check_for_updates() -> dict:
    local = get_local_version()
    if local.startswith("error:"):
        return {
            "local_version": local, "remote_version": None,
            "update_available": False,
            "error": f"No se pudo leer la versión local: {local}"
        }

    remote_info = get_remote_version_info()
    if "error" in remote_info:
        return {
            "local_version": local, "remote_version": None,
            "update_available": False, "error": remote_info["error"]
        }

    remote = remote_info.get("version", "0.0.0")
    try:
        update_available = Version(remote) > Version(local)
    except Exception:
        update_available = False

    return {
        "local_version":    local,
        "remote_version":   remote,
        "update_available": update_available,
        "changelog":        remote_info.get("changelog", ""),
        "zip_url":          remote_info.get("zip_url", ""),
        "release_date":     remote_info.get("release_date", ""),
        "error":            None,
    }


# ── Descarga ───────────────────────────────────────────────────────────────────

def _download_zip(zip_url: str, dest_path: str) -> bool:
    _log(f"Descargando ZIP desde: {zip_url}")
    try:
        resp = requests.get(zip_url, timeout=60, stream=True)
        resp.raise_for_status()
        downloaded = 0
        with open(dest_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
                downloaded += len(chunk)
        _log(f"ZIP descargado correctamente ({downloaded // 1024} KB)")
        return True
    except requests.exceptions.RequestException as e:
        _log(f"ERROR al descargar ZIP: {e}")
        return False


# ── Validación ─────────────────────────────────────────────────────────────────

def _validate_zip(zip_path: str):
    """
    Valida el contenido del ZIP.
    - Comprueba que es un ZIP válido
    - Detecta path traversal (../)
    - Filtra por lista blanca de rutas permitidas
    Devuelve (ok: bool, files_to_apply: list of (zip_name, dest_relative))
    """
    _log("Validando contenido del ZIP...")
    try:
        if not zipfile.is_zipfile(zip_path):
            _log("ERROR: El fichero descargado no es un ZIP válido.")
            return False, []

        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()

        files_to_apply = []
        rejected       = []

        for name in names:
            # Ignorar entradas de directorio
            if name.endswith("/"):
                continue

            # Detectar path traversal
            if ".." in name or name.startswith("/"):
                _log(f"  RECHAZADO (path traversal): {name}")
                rejected.append(name)
                continue

            # Quitar prefijo del paquete si existe
            # Soporta cualquier prefijo de un nivel: v1.0.1/, update_package/, etc.
            # Solo se elimina si el primer componente NO es carpeta conocida del proyecto.
            parts = name.split("/")
            known_roots = {"web", "scripts", "config"}
            if len(parts) > 1 and parts[0] not in known_roots:
                clean = "/".join(parts[1:])
            else:
                clean = name

            if not clean:
                continue

            # Comprobar contra lista blanca
            allowed = any(
                clean == p or clean.startswith(p)
                for p in ALLOWED_PATHS
            )

            if allowed:
                files_to_apply.append((name, clean))
                _log(f"  OK: {clean}")
            else:
                _log(f"  IGNORADO (fuera de lista blanca): {clean}")

        if rejected:
            _log(f"ERROR: {len(rejected)} fichero(s) con rutas peligrosas detectados. Abortando.")
            return False, []

        if not files_to_apply:
            _log("ERROR: El ZIP no contiene ningún fichero aplicable.")
            return False, []

        _log(f"Validación OK — {len(files_to_apply)} fichero(s) a aplicar.")
        return True, files_to_apply

    except zipfile.BadZipFile:
        _log("ERROR: ZIP corrupto o inválido.")
        return False, []
    except Exception as e:
        _log(f"ERROR inesperado durante validación: {e}")
        return False, []


# ── Backup ─────────────────────────────────────────────────────────────────────

def _backup_files(files_to_apply: list) -> str:
    ts          = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_path = os.path.join(BACKUP_DIR, f"backup_{ts}")
    os.makedirs(backup_path, exist_ok=True)
    _log(f"Creando backup en: config/update_backups/backup_{ts}")

    backed_up = 0
    for _, dest_relative in files_to_apply:
        src = os.path.join(_BASE_DIR, dest_relative)
        if os.path.exists(src):
            dest_backup = os.path.join(backup_path, dest_relative)
            os.makedirs(os.path.dirname(dest_backup), exist_ok=True)
            shutil.copy2(src, dest_backup)
            backed_up += 1

    _log(f"Backup completado: {backed_up} fichero(s) guardados.")
    return backup_path


# ── Apply ──────────────────────────────────────────────────────────────────────

def _apply_files(zip_path: str, files_to_apply: list) -> bool:
    _log("Aplicando ficheros...")
    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            for zip_name, dest_relative in files_to_apply:
                dest_abs = os.path.join(_BASE_DIR, dest_relative)
                os.makedirs(os.path.dirname(dest_abs), exist_ok=True)
                with zf.open(zip_name) as src_f, open(dest_abs, "wb") as dst_f:
                    shutil.copyfileobj(src_f, dst_f)

                # Los scripts .sh deben ser ejecutables por root y legibles
                # por el grupo, pero nunca escribibles por nadie más.
                # open() crea archivos con 0o644 por defecto — sin ejecución.
                # Sin este chmod, retrain.sh quedaría bloqueado por la
                # validación de seguridad (CRIT-03) en cada actualización.
                if dest_relative.endswith(".sh"):
                    os.chmod(dest_abs, 0o750)  # rwxr-x--- (root:root)
                    _log(f"  Aplicado: {dest_relative} [chmod 750]")
                else:
                    _log(f"  Aplicado: {dest_relative}")

        _log("Todos los ficheros aplicados correctamente.")
        return True
    except Exception as e:
        _log(f"ERROR al aplicar ficheros: {e}")
        return False


# ── Rollback ───────────────────────────────────────────────────────────────────

def _rollback(backup_path: str):
    _log(f"⚠️  Iniciando rollback...")
    try:
        for root, _, files in os.walk(backup_path):
            for fname in files:
                src      = os.path.join(root, fname)
                relative = os.path.relpath(src, backup_path)
                dest     = os.path.join(_BASE_DIR, relative)
                os.makedirs(os.path.dirname(dest), exist_ok=True)
                shutil.copy2(src, dest)
                _log(f"  Restaurado: {relative}")
        _log("Rollback completado.")
    except Exception as e:
        _log(f"ERROR durante rollback: {e}")


# ── Servicio ───────────────────────────────────────────────────────────────────

def _restart_service() -> bool:
    _log(f"Reiniciando servicio '{SERVICE_NAME}'...")
    try:
        # Guardar estado en disco ANTES de reiniciar — el worker morirá con el SIGTERM
        _set_state(success=True, ended_at=datetime.now().isoformat())
        _save_state_to_disk()
        _log("Estado guardado en disco. Reiniciando servicio...")

        result = subprocess.run(
            ["sudo", "systemctl", "restart", SERVICE_NAME],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            _log(f"ERROR al reiniciar: {result.stderr.strip()}")
            return False

        import time; time.sleep(3)

        check = subprocess.run(
            ["systemctl", "is-active", SERVICE_NAME],
            capture_output=True, text=True, timeout=10
        )
        if check.stdout.strip() == "active":
            _log("Servicio activo y funcionando correctamente.")
            return True
        else:
            _log(f"ERROR: Servicio no activo tras reinicio ({check.stdout.strip()}).")
            return False
    except subprocess.TimeoutExpired:
        _log("ERROR: Timeout al reiniciar el servicio.")
        return False
    except FileNotFoundError:
        _log("AVISO: systemctl no disponible — reinicia el servicio manualmente.")
        return True
    except Exception as e:
        _log(f"ERROR inesperado al reiniciar: {e}")
        return False


# ── Proceso principal ──────────────────────────────────────────────────────────

def _run_update(zip_url: str):
    """Proceso completo de actualización. Se ejecuta en un thread separado."""
    _set_state(
        running=True, success=None, log=[],
        started_at=datetime.now().isoformat(),
        ended_at=None, backup_path=None
    )

    tmp_zip     = None
    backup_path = None

    try:
        # 1. Descargar
        tmp_fd, tmp_zip = tempfile.mkstemp(suffix=".zip", prefix="emd_update_")
        os.close(tmp_fd)

        if not _download_zip(zip_url, tmp_zip):
            _set_state(running=False, success=False, ended_at=datetime.now().isoformat())
            return

        # 2. Validar
        ok, files_to_apply = _validate_zip(tmp_zip)
        if not ok:
            _set_state(running=False, success=False, ended_at=datetime.now().isoformat())
            return

        # 3. Backup
        backup_path = _backup_files(files_to_apply)
        _set_state(backup_path=backup_path)

        # 4. Aplicar
        if not _apply_files(tmp_zip, files_to_apply):
            _log("Aplicación fallida — iniciando rollback...")
            _rollback(backup_path)
            _set_state(running=False, success=False, ended_at=datetime.now().isoformat())
            return

        # 4b. Instalar dependencias si el ZIP incluía requirements.txt
        # Necesario para que nuevas librerías (ej: flask-limiter) estén disponibles
        # antes de que gunicorn arranque con el código nuevo.
        req_file = os.path.join(_BASE_DIR, "requirements.txt")
        req_included = any(dest == "requirements.txt" for _, dest in files_to_apply)
        if req_included and os.path.isfile(req_file):
            _log("Instalando dependencias desde requirements.txt...")
            pip_bin = os.path.join(_BASE_DIR, "venv", "bin", "pip")
            if not os.path.isfile(pip_bin):
                pip_bin = "pip3"
            pip_result = subprocess.run(
                [pip_bin, "install", "-r", req_file, "--quiet"],
                capture_output=True, text=True, timeout=300
            )
            if pip_result.returncode == 0:
                _log("Dependencias instaladas correctamente.")
            else:
                _log(f"AVISO: pip install completó con errores: {pip_result.stderr[-500:]}")
                # No abortamos — puede que las dependencias críticas ya estuvieran instaladas

        # 5. Reiniciar servicio
        if not _restart_service():
            _log("El servicio no levantó — iniciando rollback...")
            _rollback(backup_path)
            _restart_service()
            _set_state(running=False, success=False, ended_at=datetime.now().isoformat())
            return

        _log("✅ Actualización completada correctamente.")
        _set_state(running=False, success=True, ended_at=datetime.now().isoformat())

    except Exception as e:
        _log(f"ERROR crítico inesperado: {e}")
        if backup_path:
            _rollback(backup_path)
            _restart_service()
        _set_state(running=False, success=False, ended_at=datetime.now().isoformat())
    finally:
        if tmp_zip and os.path.exists(tmp_zip):
            try:
                os.unlink(tmp_zip)
            except Exception:
                pass


def start_update(zip_url: str) -> tuple:
    """
    Lanza el proceso de actualización en background.
    Devuelve (ok: bool, error_msg: str)
    """
    state = get_update_state()
    if state["running"]:
        return False, "Ya hay una actualización en curso."
    if not zip_url:
        return False, "No hay URL de descarga en version.json. Publica una Release primero."

    t = threading.Thread(target=_run_update, args=(zip_url,), daemon=True)
    t.start()
    return True, ""
