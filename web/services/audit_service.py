import os
import json
import logging
from datetime import datetime

logger = logging.getLogger("audit")
AUDIT_LOG = os.path.join(os.path.dirname(__file__), "..", "..", "logs", "audit.log")

os.makedirs(os.path.dirname(AUDIT_LOG), exist_ok=True)

_handler = logging.FileHandler(AUDIT_LOG)
_handler.setFormatter(logging.Formatter("%(asctime)s [AUDIT] %(message)s"))
logger.addHandler(_handler)
logger.setLevel(logging.INFO)


def log_event(user_id, username, action, detail=""):
    logger.info("%s | %s | %s | %s", user_id or "-", username or "-", action, detail)


def log_admin_action(user_id, username, action, detail=""):
    log_event(user_id, username, f"ADMIN:{action}", detail)
