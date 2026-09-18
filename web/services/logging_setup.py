#!/usr/bin/env python3
"""
logging_setup.py — Logs de acceso y error a fichero para modo standalone.

En despliegues con gunicorn (systemd o run.sh) los logs ya se escriben via
`--access-logfile` / `--error-logfile`. Este modulo cubre el arranque directo
(`python web/app.py`), escribiendo `logs/access.log` y `logs/error.log` con
rotacion (5 MB x 5 backups).
"""

import logging
import os
from logging.handlers import RotatingFileHandler

from flask import request

_FORMAT = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
_MAX_BYTES = 5 * 1024 * 1024
_BACKUPS = 5

_ERROR_MARKER = "_emd_error"
_ACCESS_MARKER = "_emd_access"


def _rotating_handler(path, level, formatter, marker):
    handler = RotatingFileHandler(path, maxBytes=_MAX_BYTES,
                                  backupCount=_BACKUPS, encoding="utf-8")
    handler.setLevel(level)
    handler.setFormatter(formatter)
    setattr(handler, marker, True)
    return handler


def _has_handler(logger, marker):
    return any(getattr(h, marker, False) for h in logger.handlers)


def configure_standalone_logging(app, logs_dir):
    """Configura logs de acceso/error a fichero e instrumenta `app`.

    Idempotente: llamarla varias veces no duplica handlers ni loggers.
    Devuelve el logger de acceso.
    """
    os.makedirs(logs_dir, exist_ok=True)
    formatter = logging.Formatter(_FORMAT)

    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not _has_handler(root, _ERROR_MARKER):
        root.addHandler(_rotating_handler(
            os.path.join(logs_dir, "error.log"),
            logging.WARNING, formatter, _ERROR_MARKER))

    access_logger = logging.getLogger("web.access")
    access_logger.setLevel(logging.INFO)
    access_logger.propagate = False
    if not _has_handler(access_logger, _ACCESS_MARKER):
        access_logger.addHandler(_rotating_handler(
            os.path.join(logs_dir, "access.log"),
            logging.INFO, formatter, _ACCESS_MARKER))

    if not getattr(app, "_emd_access_registered", False):
        @app.after_request
        def _log_access(response):
            access_logger.info(
                '%s "%s %s" %s',
                request.remote_addr or "-",
                request.method,
                request.full_path.rstrip("?"),
                response.status_code,
            )
            return response
        app._emd_access_registered = True

    return access_logger
