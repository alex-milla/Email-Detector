#!/usr/bin/env python3
"""update_edl.py — Sincronización de External Dynamic Lists (EDL).

Pensado para ejecutarse desde cron (heartbeat) o desde la interfaz web.

Opciones:
    (sin flags)   Sincroniza todas las listas activas (manual).
    --due         Sincroniza solo las listas cuyo intervalo ha vencido.
    --list ID     Sincroniza una lista concreta.
    --show        Muestra el estado de configuración sin descargar.
"""

import os
import sys
import argparse
import logging

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from edl_manager import (  # noqa: E402
    sync_all, sync_due, sync_list, schedule_info, get_public_lists,
)

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LOG_FILE = os.path.join(PROJECT_DIR, "logs", "edl_update.log")


def _configure_logging():
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s  %(levelname)-7s  %(message)s",
        handlers=[
            logging.FileHandler(LOG_FILE, encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )


def _describe(result):
    if result.get("busy"):
        return "EDL: sincronización ya en curso"
    if "total" not in result:
        if result.get("success"):
            return f"EDL: lista '{result.get('name') or result.get('list_id')}' " \
                   f"sincronizada ({result.get('entries', 0)} indicadores)"
        return f"EDL: error — {result.get('error', 'desconocido')}"
    if result["total"] == 0:
        return "EDL: no hay listas pendientes de sincronizar"
    message = (f"EDL: {result['synced']} de {result['total']} listas sincronizadas "
               f"({result['entries']} indicadores)")
    if result["failed"]:
        first_error = next((r.get("error") for r in result["results"]
                            if not r.get("success")), "")
        message += f" — {result['failed']} con error"
        if first_error:
            message += f": {first_error}"
    return message


def _show_status():
    info = schedule_info()
    print(f"Auto-sincronización: {'activada' if info['auto_enabled'] else 'desactivada'}")
    print(f"Intervalo por defecto: {info['default_interval_h']} h")
    lists = get_public_lists()
    if not lists:
        print("No hay listas configuradas.")
        return
    for entry in lists:
        state = "activa" if entry.get("enabled", True) else "deshabilitada"
        print(f"  - {entry.get('name')} [{state}] "
              f"tipo={entry.get('kind')} entradas={entry.get('entries', 0)} "
              f"última={entry.get('last_sync') or 'nunca'} "
              f"estado={entry.get('last_status')}")


def main():
    parser = argparse.ArgumentParser(description="Sincroniza las listas EDL")
    parser.add_argument("--due", action="store_true",
                        help="Sincronizar solo las listas vencidas según su intervalo")
    parser.add_argument("--list", dest="list_id", default=None,
                        help="Sincronizar una lista concreta por su ID")
    parser.add_argument("--show", action="store_true",
                        help="Mostrar el estado sin descargar nada")
    args = parser.parse_args()

    _configure_logging()
    logging.getLogger("edl_update").info("Iniciando sincronización EDL")

    if args.show:
        _show_status()
        return 0

    if args.list_id:
        result = sync_list(args.list_id)
    elif args.due:
        result = sync_due()
    else:
        result = sync_all()

    message = _describe(result)
    print(message)
    logging.getLogger("edl_update").info(message)

    if result.get("total") is not None:
        return 0 if result.get("failed", 0) == 0 else 1
    return 0 if result.get("success") else 1


if __name__ == "__main__":
    sys.exit(main())
