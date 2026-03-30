#!/usr/bin/env python3
"""
settings_manager.py — Funciones de test de conexión para proveedores de correo.
La configuración se almacena en SQLite (auth.py), no en .env.
"""

import os
from dotenv import load_dotenv

ENV_PATH = os.path.join(os.path.dirname(__file__), "..", "config", ".env")
load_dotenv(ENV_PATH)

# Clave de VirusTotal sigue siendo global (en .env)
ALLOWED_GLOBAL = {"VIRUSTOTAL_API_KEY", "WEB_HOST", "WEB_PORT", "SECRET_KEY", "USE_GPU", "DISABLED_MODELS"}


def read_global_env():
    values = {}
    if not os.path.exists(ENV_PATH):
        return values
    with open(ENV_PATH) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, val = line.partition("=")
                if key.strip() in ALLOWED_GLOBAL:
                    values[key.strip()] = val.strip()
    return values


def write_global_env(updates: dict):
    updates = {k: v for k, v in updates.items() if k in ALLOWED_GLOBAL}
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH) as f:
            lines = f.readlines()
    else:
        lines = []
    updated = set()
    new_lines = []
    for line in lines:
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and "=" in stripped:
            key = stripped.split("=", 1)[0].strip()
            if key in updates:
                new_lines.append(f"{key}={updates[key]}\n")
                updated.add(key)
                continue
        new_lines.append(line)
    for key, val in updates.items():
        if key not in updated:
            new_lines.append(f"{key}={val}\n")
    with open(ENV_PATH, "w") as f:
        f.writelines(new_lines)


def test_imap(server, port, user, password):
    import imaplib
    try:
        mail = imaplib.IMAP4_SSL(server, int(port))
        mail.login(user, password)
        mail.logout()
        return True, "Conexión IMAP correcta ✓"
    except imaplib.IMAP4.error as e:
        return False, f"Error de autenticación: {e}"
    except Exception as e:
        return False, f"Error de conexión: {e}"


def test_virustotal(api_key):
    import requests
    try:
        r = requests.get(
            "https://www.virustotal.com/api/v3/files/44d88612fea8a8f36de82e1278abb02f",
            headers={"x-apikey": api_key}, timeout=10
        )
        if r.status_code == 200:   return True,  "API Key válida ✓"
        elif r.status_code == 401: return False, "API Key inválida"
        else:                      return False, f"Error HTTP {r.status_code}"
    except Exception as e:
        return False, f"Error de conexión: {e}"


def test_m365(client_id, client_secret, tenant_id):
    try:
        import msal
        app = msal.ConfidentialClientApplication(
            client_id,
            authority=f"https://login.microsoftonline.com/{tenant_id}",
            client_credential=client_secret,
        )
        result = app.acquire_token_for_client(
            scopes=["https://graph.microsoft.com/.default"]
        )
        if "access_token" in result:
            return True, "Autenticación M365 correcta ✓"
        return False, result.get("error_description", "Error desconocido")
    except Exception as e:
        return False, f"Error: {e}"
