"""
web package - centraliza la configuracion de sys.path.

Al importar cualquier modulo de web (app, routes, services),
Python ejecuta primero este __init__.py, garantizando que
los directorios scripts/ y web/ estan en sys.path antes de
cualquier import de predict, mailbox_connector, etc.
"""

import os
import sys

_PROJECT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
_SCRIPTS = os.path.join(_PROJECT, "scripts")
_WEB = os.path.dirname(__file__)

for _p in (_SCRIPTS, _WEB):
    if _p not in sys.path:
        sys.path.insert(0, _p)
