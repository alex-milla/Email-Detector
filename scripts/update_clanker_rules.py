#!/usr/bin/env python3
"""update_clanker_rules.py — Actualización automática de reglas Anti-Clanker.

Consulta CLANKER_RULES_URL (de .env) y descarga una nueva versión del fichero
de reglas si es superior a la actual. Valida la estructura antes de reemplazar.
Registra el resultado en logs/clanker_update.log.

Uso: python update_clanker_rules.py [--force]
"""
import os
import sys
import re
import shutil
import logging
import argparse
from datetime import datetime
from typing import Optional, Tuple

# ── Setup ─────────────────────────────────────────────────────────────────────
INSTALL_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_FILE   = os.path.join(INSTALL_DIR, "config", "clanker_rules.yaml")
LOG_FILE     = os.path.join(INSTALL_DIR, "logs", "clanker_update.log")
ENV_FILE     = os.path.join(INSTALL_DIR, "config", ".env")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s  %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("clanker_update")


# ── Helpers ───────────────────────────────────────────────────────────────────
def _load_env() -> dict:
    env = {}
    if not os.path.isfile(ENV_FILE):
        return env
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()
    return env


def _parse_version(ver_str: str) -> Tuple[int, ...]:
    parts = re.findall(r"\d+", str(ver_str))
    return tuple(int(p) for p in parts) if parts else (0,)


def _validate_yaml(raw: str) -> Tuple[bool, str]:
    """Valida estructura YAML y reglas."""
    try:
        import yaml
        data = yaml.safe_load(raw)
    except Exception as e:
        return False, f"YAML inválido: {e}"

    if not isinstance(data, dict):
        return False, "El fichero no es un dict YAML válido"
    if "rules" not in data:
        return False, "Falta clave 'rules'"
    if "meta" not in data:
        return False, "Falta clave 'meta'"

    for rule in data["rules"]:
        for field in ("id", "pattern", "target", "severity", "enabled"):
            if field not in rule:
                return False, f"Campo obligatorio '{field}' faltante en regla {rule.get('id','?')}"
        try:
            re.compile(rule["pattern"])
        except re.error as e:
            return False, f"Regex inválido en {rule['id']}: {e}"

    return True, "OK"


def _current_version() -> str:
    if not os.path.isfile(RULES_FILE):
        return "0.0.0"
    try:
        import yaml
        with open(RULES_FILE) as f:
            data = yaml.safe_load(f) or {}
        return data.get("meta", {}).get("version", "0.0.0")
    except Exception:
        return "0.0.0"


def _backup_current():
    if os.path.isfile(RULES_FILE):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup = f"{RULES_FILE}.bak_{ts}"
        shutil.copy2(RULES_FILE, backup)
        logger.info("Backup creado: %s", backup)
        return backup
    return None


# ── Lógica principal ──────────────────────────────────────────────────────────
def update(force: bool = False) -> bool:
    env = _load_env()
    url = env.get("CLANKER_RULES_URL", "").strip()

    if not url:
        logger.info("CLANKER_RULES_URL no configurada — actualización omitida")
        return False

    # HIGH-04: forzar HTTPS como segunda línea de defensa.
    # La primera línea es la validación en clanker_set_url (app.py).
    # Esta comprobación protege también cuando la URL se edita manualmente en .env.
    # Nota: no se implementa firma criptográfica porque el modelo de distribución
    # libre permite URLs arbitrarias de terceros — la autenticidad del origen
    # es responsabilidad del administrador que configura la URL.
    if not url.startswith("https://"):
        logger.error(
            "CLANKER_RULES_URL usa HTTP o esquema no permitido — "
            "solo se aceptan URLs HTTPS para prevenir ataques MITM. URL rechazada: %s", url
        )
        return False

    logger.info("Comprobando actualizaciones de reglas en: %s", url)
    current_ver = _current_version()
    logger.info("Versión actual: %s", current_ver)

    # Descargar
    try:
        import urllib.request
        with urllib.request.urlopen(url, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
    except Exception as e:
        logger.error("Error descargando reglas: %s", e)
        return False

    # Validar esquema antes de tocar ningún archivo
    valid, msg = _validate_yaml(raw)
    if not valid:
        logger.error("Fichero descargado inválido: %s — no se aplica ningún cambio", msg)
        return False

    # Comparar versión
    try:
        import yaml
        data = yaml.safe_load(raw)
        remote_ver = data.get("meta", {}).get("version", "0.0.0")
    except Exception:
        remote_ver = "0.0.0"

    logger.info("Versión remota: %s", remote_ver)

    if not force and _parse_version(remote_ver) <= _parse_version(current_ver):
        logger.info("No hay actualización disponible (remota %s <= local %s)",
                    remote_ver, current_ver)
        return False

    # Backup antes de escribir
    backup_path = _backup_current()

    # Escribir nuevo archivo con rollback automático si algo falla
    try:
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            f.write(raw)

        # Verificación post-escritura: releer y revalidar para detectar
        # corrupción de disco o truncado parcial durante la escritura
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            written = f.read()
        recheck, rechk_msg = _validate_yaml(written)
        if not recheck:
            raise ValueError(f"Verificación post-escritura fallida: {rechk_msg}")

    except Exception as e:
        logger.error("ERROR al aplicar reglas: %s — iniciando rollback", e)
        if backup_path and os.path.isfile(backup_path):
            shutil.copy2(backup_path, RULES_FILE)
            logger.info("Rollback completado: restaurado desde %s", backup_path)
        else:
            logger.error("No hay backup disponible para restaurar — revisa %s manualmente", RULES_FILE)
        return False

    logger.info("Reglas actualizadas de %s → %s (%d reglas)",
                current_ver, remote_ver, len(data.get("rules", [])))
    return True


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Actualiza clanker_rules.yaml")
    parser.add_argument("--force", action="store_true",
                        help="Forzar descarga aunque la versión sea igual")
    args = parser.parse_args()
    ok = update(force=args.force)
    sys.exit(0 if ok or not args.force else 1)