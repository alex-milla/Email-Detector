#!/usr/bin/env python3
"""
notifier.py — Envía notificaciones cuando se detecta un correo malicioso.
Soporta: Slack webhook, Telegram bot, email SMTP.

Uso:
    python scripts/notifier.py <result_json>
    python scripts/notifier.py --check  # modo cron: lee results/history.json
"""

import os
import sys
import json
import logging
from datetime import datetime

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..")
ENV_PATH = os.path.join(PROJECT_DIR, "config", ".env")

try:
    from dotenv import load_dotenv
    load_dotenv(ENV_PATH)
except ImportError:
    pass

SLACK_WEBHOOK = os.getenv("NOTIFY_SLACK_WEBHOOK", "")
TELEGRAM_BOT_TOKEN = os.getenv("NOTIFY_TELEGRAM_TOKEN", "")
TELEGRAM_CHAT_ID = os.getenv("NOTIFY_TELEGRAM_CHAT", "")
SMTP_SERVER = os.getenv("NOTIFY_SMTP_SERVER", "")
SMTP_PORT = int(os.getenv("NOTIFY_SMTP_PORT", "587"))
SMTP_USER = os.getenv("NOTIFY_SMTP_USER", "")
SMTP_PASSWORD = os.getenv("NOTIFY_SMTP_PASSWORD", "")
NOTIFY_TO = os.getenv("NOTIFY_EMAIL_TO", "")


def _format_alert(result):
    return (
        f"🚨 *Alerta Email Malware Detector*\n"
        f"*Archivo:* {result.get('file', '?')}\n"
        f"*Asunto:* {result.get('subject', '?')}\n"
        f"*Remitente:* {result.get('from', '?')}\n"
        f"*Predicción:* {result.get('prediction', '?')}\n"
        f"*Riesgo:* {result.get('risk_level', '?')} ({result.get('risk_score', 0)}%)\n"
        f"*Confianza ML:* {result.get('ml_confidence', 0)}%\n"
        f"*URLs:* {len(result.get('metadata', {}).get('urls_found', []))}\n"
        f"*Adjuntos:* {len(result.get('metadata', {}).get('attachments', []))}\n"
        f"*Timestamp:* {result.get('timestamp', '?')}"
    )


def notify_slack(result):
    if not SLACK_WEBHOOK:
        return False
    try:
        import requests
        text = _format_alert(result).replace("*", "**")
        payload = {"text": text}
        resp = requests.post(SLACK_WEBHOOK, json=payload, timeout=10)
        resp.raise_for_status()
        logger.info("Notificación Slack enviada")
        return True
    except Exception as e:
        logger.error("Slack falló: %s", e)
        return False


def notify_telegram(result):
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    try:
        import requests
        text = _format_alert(result)
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        resp = requests.post(url, json={
            "chat_id": TELEGRAM_CHAT_ID,
            "text": text,
            "parse_mode": "Markdown",
        }, timeout=10)
        resp.raise_for_status()
        logger.info("Notificación Telegram enviada")
        return True
    except Exception as e:
        logger.error("Telegram falló: %s", e)
        return False


def notify_email(result):
    if not all([SMTP_SERVER, SMTP_USER, SMTP_PASSWORD, NOTIFY_TO]):
        return False
    try:
        import smtplib
        from email.mime.text import MIMEText
        text = _format_alert(result).replace("*", "").replace("_", "")
        msg = MIMEText(text, "plain", "utf-8")
        msg["Subject"] = f"🚨 ALERTA: Correo malicioso detectado — {result.get('subject', '')[:50]}"
        msg["From"] = SMTP_USER
        msg["To"] = NOTIFY_TO
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASSWORD)
            server.send_message(msg)
        logger.info("Notificación email enviada a %s", NOTIFY_TO)
        return True
    except Exception as e:
        logger.error("Email falló: %s", e)
        return False


def notify_all(result):
    sent = 0
    if notify_slack(result):
        sent += 1
    if notify_telegram(result):
        sent += 1
    if notify_email(result):
        sent += 1
    return sent


def check_history():
    history_path = os.path.join(PROJECT_DIR, "results", "history.json")
    if not os.path.exists(history_path):
        logger.info("No hay historial")
        return
    with open(history_path) as f:
        history = json.load(f)
    recent = [h for h in history if h.get("prediction") == "MALICIOSO"]
    if not recent:
        logger.info("Sin detecciones maliciosas recientes")
        return
    for alert in recent[-5:]:
        notify_all(alert)


if __name__ == "__main__":
    if "--check" in sys.argv:
        check_history()
    elif len(sys.argv) > 1:
        with open(sys.argv[1]) as f:
            result = json.load(f)
        notify_all(result)
    else:
        print("Uso: python notifier.py <result.json> | python notifier.py --check")
