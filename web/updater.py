#!/usr/bin/env python3
"""
updater.py — Gestión de actualizaciones de Email Malware Detector.

Responsabilidades:
  - Leer la versión instalada localmente (fichero VERSION)
  - Consultar la versión disponible en GitHub (version.json)
  - Comparar versiones y determinar si hay actualización
  - (Fases futuras) Descargar ZIP, validar, hacer backup y aplicar

No modifica ningún fichero existente. Solo lectura en esta fase.
"""

import os
import json
import requests
from packaging.version import Version

# ── Configuración ─────────────────────────────────────────────────────────────

# URL del version.json en la rama main del repositorio público
VERSION_JSON_URL = (
    "https://raw.githubusercontent.com/alex-milla/Email-Detector/main/version.json"
)

# Ruta al fichero VERSION local (raíz del proyecto, un nivel arriba de web/)
_BASE_DIR    = os.path.join(os.path.dirname(__file__), "..")
VERSION_FILE = os.path.join(_BASE_DIR, "VERSION")

# Timeout para peticiones HTTP (segundos)
REQUEST_TIMEOUT = 10

# ── Funciones públicas ────────────────────────────────────────────────────────

def get_local_version() -> str:
    """
    Lee la versión instalada desde el fichero VERSION en la raíz del proyecto.
    Devuelve '0.0.0' si el fichero no existe (instalación antigua sin versionado).
    """
    try:
        with open(VERSION_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "0.0.0"
    except Exception as e:
        return f"error: {e}"


def get_remote_version_info() -> dict:
    """
    Descarga el version.json del repositorio GitHub y lo devuelve como dict.

    Devuelve un dict con esta estructura en caso de éxito:
        {
            "version":      "1.1.0",
            "release_date": "2026-04-10",
            "changelog":    "Descripción de cambios",
            "min_version":  "1.0.0",
            "zip_url":      "https://..."
        }

    En caso de error devuelve:
        {
            "error": "descripción del problema"
        }
    """
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
    """
    Compara la versión local con la remota y devuelve un resumen completo.

    Resultado posible:
        {
            "local_version":    "1.0.0",
            "remote_version":   "1.1.0",
            "update_available": True,
            "changelog":        "...",
            "zip_url":          "https://...",
            "release_date":     "2026-04-10",
            "error":            None          # o mensaje de error
        }
    """
    local = get_local_version()

    # Si la versión local es un error, lo propagamos
    if local.startswith("error:"):
        return {
            "local_version":    local,
            "remote_version":   None,
            "update_available": False,
            "error":            f"No se pudo leer la versión local: {local}"
        }

    remote_info = get_remote_version_info()

    # Si hay error al obtener el remoto, lo propagamos
    if "error" in remote_info:
        return {
            "local_version":    local,
            "remote_version":   None,
            "update_available": False,
            "error":            remote_info["error"]
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
        "error":            None
    }
