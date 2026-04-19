#!/usr/bin/env python3
"""
mailbox_connector.py — Conecta a buzones IMAP / M365.
Soporta selección de carpeta y rango de fechas exacto.
"""

import os
import sys
import email
import imaplib
import time
from datetime import datetime, timedelta
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), "..", "config", ".env"))

RAW_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "raw")
os.makedirs(RAW_DIR, exist_ok=True)


def _safe_filename(subject, prefix, index):
    safe = "".join(c if c.isalnum() or c in " -_" else "_"
                   for c in (subject or "sin_asunto"))[:50]
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{ts}_{index:03d}_{safe}.eml"


def _list_imap_folders(mail):
    """Lista todas las carpetas disponibles en el servidor."""
    _, folder_list = mail.list()
    folders = []
    for f in folder_list:
        try:
            parts = f.decode().split('"')
            name  = parts[-2] if len(parts) >= 2 else f.decode().split()[-1]
            folders.append(name.strip())
        except Exception:
            pass
    return folders


def _find_spam_folder(mail):
    """
    Detecta automáticamente la carpeta de spam/junk.
    Prueba nombres comunes en español e inglés.
    """
    candidates = [
        "[Gmail]/Spam",
        "[Gmail]/Correo no deseado",
        "[Gmail]/Junk",
        "Spam", "Junk", "Correo no deseado",
        "Junk Email", "Bulk Mail",
    ]
    available = _list_imap_folders(mail)
    available_lower = {f.lower(): f for f in available}

    for candidate in candidates:
        if candidate in available:
            return candidate
        if candidate.lower() in available_lower:
            return available_lower[candidate.lower()]

    # Buscar por palabras clave
    for folder in available:
        fl = folder.lower()
        if "spam" in fl or "junk" in fl or "no deseado" in fl or "bulk" in fl:
            return folder

    return None


def _find_inbox_folder(mail):
    """Detecta la bandeja de entrada."""
    available = _list_imap_folders(mail)
    for folder in available:
        if folder.upper() == "INBOX":
            return folder
    return "INBOX"


def download_emails_imap(max_emails=50, date_from=None, date_to=None,
                         folder="inbox", days_back=7):
    """
    Descarga correos por IMAP con rango de fechas.
    Siempre analiza únicamente la bandeja de entrada (INBOX).

    Parámetros:
        date_from: datetime o None (usa days_back si es None)
        date_to:   datetime o None (usa hoy si es None)
        folder:    ignorado — siempre se usa 'inbox'
        days_back: fallback si no hay date_from
    """
    folder = "inbox"  # Fijo: solo se analiza la bandeja de entrada
    server   = os.getenv("IMAP_SERVER", "")
    port     = int(os.getenv("IMAP_PORT", "993"))
    user     = os.getenv("IMAP_USER", "")
    password = os.getenv("IMAP_PASSWORD", "")

    if not all([server, user, password]):
        print("ERROR: Faltan variables IMAP en config/.env")
        return []

    # Calcular rango de fechas
    if date_to is None:
        date_to = datetime.now()
    if date_from is None:
        date_from = date_to - timedelta(days=days_back)

    since_str  = date_from.strftime("%d-%b-%Y")
    before_str = (date_to + timedelta(days=1)).strftime("%d-%b-%Y")

    print(f"Conectando a {server}:{port}...")
    print(f"Rango: {date_from.strftime('%d/%m/%Y')} → {date_to.strftime('%d/%m/%Y')}")

    mail = imaplib.IMAP4_SSL(server, port)
    mail.login(user, password)

    downloaded = []

    # Siempre se analiza únicamente la bandeja de entrada
    imap_folder = _find_inbox_folder(mail)
    print(f"\n  📥 Conectando a bandeja de entrada: '{imap_folder}'...")

    # Seleccionar carpeta
    status, _ = mail.select(f'"{imap_folder}"')
    if status != "OK":
        status, _ = mail.select(imap_folder)
    if status != "OK":
        print(f"  ✗ No se pudo acceder a '{imap_folder}'")
        mail.logout()
        return []

    # Buscar correos en el rango de fechas
    search_criteria = f'(SINCE {since_str} BEFORE {before_str})'
    status, msg_ids = mail.search(None, search_criteria)

    if status != "OK" or not msg_ids[0]:
        print("  Sin correos en el rango de fechas")
        mail.logout()
        return []

    id_list = msg_ids[0].split()
    # Limitar a los más recientes
    id_list = id_list[-max_emails:]
    print(f"  Encontrados: {len(id_list)} correos")

    for i, msg_id in enumerate(id_list):
        status, msg_data = mail.fetch(msg_id, "(RFC822)")
        if status == "OK":
            raw_email = msg_data[0][1]
            parsed    = email.message_from_bytes(raw_email)
            subject   = parsed.get("Subject", "") or ""
            filename  = _safe_filename(subject, "imap_inbox", i)
            filepath  = os.path.join(RAW_DIR, filename)
            with open(filepath, "wb") as f:
                f.write(raw_email)
            downloaded.append(filepath)
            print(f"  [{i+1}/{len(id_list)}] {filename[:70]}")

    mail.logout()
    print(f"\nTotal descargados: {len(downloaded)}")
    return downloaded


def download_emails_m365(max_emails=50, date_from=None, date_to=None,
                         folder="inbox", days_back=7):
    try:
        import msal
        import requests as req
    except ImportError:
        print("ERROR: pip install msal requests")
        return []

    client_id     = os.getenv("MS365_CLIENT_ID", "")
    client_secret = os.getenv("MS365_CLIENT_SECRET", "")
    tenant_id     = os.getenv("MS365_TENANT_ID", "")
    user_email    = os.getenv("MS365_USER_EMAIL", "")

    if not all([client_id, client_secret, tenant_id, user_email]):
        print("ERROR: Faltan variables M365")
        return []

    if date_to is None:
        date_to = datetime.utcnow()
    if date_from is None:
        date_from = date_to - timedelta(days=days_back)

    app = msal.ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret,
    )
    result = app.acquire_token_for_client(
        scopes=["https://graph.microsoft.com/.default"]
    )
    if "access_token" not in result:
        print(f"ERROR auth M365: {result.get('error_description')}")
        return []

    token   = result["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    folder_map = {"inbox": "inbox", "spam": "junkemail", "sent": "sentitems"}
    folders_to_check = ["inbox", "spam"] if folder == "all" else [folder]
    downloaded = []

    since_str = date_from.strftime("%Y-%m-%dT%H:%M:%SZ")
    to_str    = date_to.strftime("%Y-%m-%dT%H:%M:%SZ")

    for f in folders_to_check:
        gf  = folder_map.get(f, "inbox")
        url = (f"https://graph.microsoft.com/v1.0/users/{user_email}"
               f"/mailFolders/{gf}/messages"
               f"?$top={max_emails}"
               f"&$filter=receivedDateTime ge {since_str} and receivedDateTime le {to_str}"
               f"&$select=id,subject,receivedDateTime"
               f"&$orderby=receivedDateTime desc")

        print(f"\n  📂 M365 carpeta: {gf}")
        response = req.get(url, headers=headers)
        if response.status_code != 200:
            print(f"  Error: {response.status_code}")
            continue

        messages = response.json().get("value", [])
        for i, msg in enumerate(messages):
            mime_url = (f"https://graph.microsoft.com/v1.0/users/{user_email}"
                        f"/messages/{msg['id']}/$value")
            mime_r = req.get(mime_url, headers=headers)
            if mime_r.status_code == 200:
                subject  = msg.get("subject", "") or ""
                filename = _safe_filename(subject, f"m365_{f}", i)
                filepath = os.path.join(RAW_DIR, filename)
                with open(filepath, "wb") as fp:
                    fp.write(mime_r.content)
                downloaded.append(filepath)
                print(f"  [{i+1}/{len(messages)}] {filename[:70]}")
            time.sleep(0.2)

    print(f"\nTotal descargados: {len(downloaded)}")
    return downloaded


def download_emails(provider="imap", max_emails=50, days_back=7,
                    folder="inbox", date_from=None, date_to=None):
    print(f"\n{'='*55}")
    print(f" Descargando ({provider}) — carpeta: {folder}")
    if date_from:
        print(f" Desde: {date_from.strftime('%d/%m/%Y')} → {(date_to or datetime.now()).strftime('%d/%m/%Y')}")
    else:
        print(f" Últimos {days_back} días")
    print(f"{'='*55}\n")

    if provider == "m365":
        return download_emails_m365(max_emails, date_from, date_to, folder, days_back)
    elif provider == "imap":
        return download_emails_imap(max_emails, date_from, date_to, folder, days_back)
    else:
        print(f"ERROR: Proveedor desconocido: {provider}")
        return []


if __name__ == "__main__":
    provider  = sys.argv[1] if len(sys.argv) > 1 else "imap"
    max_e     = int(sys.argv[2]) if len(sys.argv) > 2 else 10
    folder    = sys.argv[3] if len(sys.argv) > 3 else "inbox"
    results   = download_emails(provider, max_e, folder=folder)
    print(f"\nArchivos descargados: {len(results)}")
