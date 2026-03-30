#!/usr/bin/env python3
"""
virustotal.py — Consulta hashes de archivos y URLs en VirusTotal.
Respeta los límites de la API gratuita (4 peticiones/minuto).

Uso:
    from virustotal import check_hash, check_url, check_email_artifacts
"""

import os
import sys
import time
import json
import hashlib
import requests
from datetime import datetime
from dotenv import load_dotenv

# Cargar configuración
load_dotenv(os.path.join(os.path.dirname(__file__), "..", "config", ".env"))

API_KEY  = os.getenv("VIRUSTOTAL_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

# ── Control de velocidad (rate limiter) ──
# La API gratuita permite 4 peticiones por minuto.
# Dejamos 16 segundos entre peticiones para estar seguros.
RATE_LIMIT_SECONDS = 16
_last_request_time = 0


def _wait_for_rate_limit():
    """Espera el tiempo necesario para no superar el límite de la API."""
    global _last_request_time
    elapsed = time.time() - _last_request_time
    if elapsed < RATE_LIMIT_SECONDS:
        wait_time = RATE_LIMIT_SECONDS - elapsed
        print(f"    ⏳ Esperando {wait_time:.0f}s (límite API gratuita)...")
        time.sleep(wait_time)
    _last_request_time = time.time()


def _make_request(endpoint, method="GET", data=None):
    """Hace una petición a la API de VirusTotal."""
    if not API_KEY:
        return {"error": "No hay API Key configurada en config/.env"}

    _wait_for_rate_limit()

    headers = {"x-apikey": API_KEY}
    url     = f"{BASE_URL}/{endpoint}"

    try:
        if method == "GET":
            response = requests.get(url, headers=headers, timeout=30)
        elif method == "POST":
            response = requests.post(url, headers=headers, data=data, timeout=30)
        else:
            return {"error": f"Método HTTP no soportado: {method}"}

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            return {"not_found": True, "message": "No encontrado en VirusTotal"}
        elif response.status_code == 429:
            return {"error": "Límite de API superado. Espera unos minutos."}
        else:
            return {"error": f"HTTP {response.status_code}: {response.text[:200]}"}

    except requests.exceptions.Timeout:
        return {"error": "Timeout: VirusTotal no respondió a tiempo"}
    except requests.exceptions.RequestException as e:
        return {"error": f"Error de conexión: {str(e)}"}


def check_hash(file_hash):
    """
    Busca un hash (MD5, SHA1 o SHA256) de archivo en VirusTotal.

    Devuelve:
        Diccionario con:
        - found:      True/False
        - malicious:  nº de antivirus que lo detectan como malware
        - total:      nº total de antivirus que lo analizaron
        - score:      porcentaje de detección (0-100)
        - detections: nombre de la amenaza según los principales AV
    """
    print(f"    🔍 Consultando hash: {file_hash[:16]}...")
    result = _make_request(f"files/{file_hash}")

    if "error" in result:
        return {"found": False, "error": result["error"]}

    if "not_found" in result:
        return {
            "found":   False,
            "hash":    file_hash,
            "message": "Archivo no conocido por VirusTotal"
        }

    stats     = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total     = sum(stats.values())

    # Detecciones de los principales antivirus
    analysis = result.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    detections   = {}
    important_avs = [
        "Microsoft", "Kaspersky", "ESET-NOD32", "BitDefender",
        "Avast", "Symantec", "McAfee", "CrowdStrike"
    ]
    for av_name in important_avs:
        if av_name in analysis:
            av_result = analysis[av_name]
            if av_result.get("category") == "malicious":
                detections[av_name] = av_result.get("result", "Detectado")

    return {
        "found":      True,
        "hash":       file_hash,
        "malicious":  malicious,
        "suspicious": suspicious,
        "total":      total,
        "score":      round((malicious / total) * 100, 1) if total > 0 else 0,
        "detections": detections,
    }


def check_url(url_to_check):
    """
    Comprueba si una URL está catalogada como maliciosa en VirusTotal.

    Devuelve:
        Diccionario con found, malicious, suspicious, total, score.
    """
    import base64

    print(f"    🔍 Consultando URL: {url_to_check[:60]}...")

    # VirusTotal requiere la URL codificada en base64 (sin padding)
    url_id = base64.urlsafe_b64encode(
        url_to_check.encode()
    ).decode().rstrip("=")

    result = _make_request(f"urls/{url_id}")

    if "error" in result:
        return {"found": False, "url": url_to_check, "error": result["error"]}

    if "not_found" in result:
        return {
            "found":   False,
            "url":     url_to_check,
            "message": "URL no conocida por VirusTotal"
        }

    stats     = result.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total     = sum(stats.values())

    return {
        "found":      True,
        "url":        url_to_check,
        "malicious":  malicious,
        "suspicious": suspicious,
        "total":      total,
        "score":      round((malicious / total) * 100, 1) if total > 0 else 0,
    }


def check_email_artifacts(attachment_hashes, urls, max_checks=10):
    """
    Comprueba todos los elementos de un correo en VirusTotal.
    Respeta los límites de la API procesando de forma secuencial.

    Parámetros:
        attachment_hashes: lista de dicts con 'sha256' y 'filename'
        urls:              lista de URLs encontradas en el correo
        max_checks:        máximo total de consultas a hacer

    Devuelve:
        Diccionario con resultados para archivos y URLs, más un resumen.
    """
    results = {
        "files": [],
        "urls":  [],
        "summary": {
            "total_checked":      0,
            "malicious_files":    0,
            "malicious_urls":     0,
            "api_key_configured": bool(API_KEY),
        }
    }

    if not API_KEY:
        results["summary"]["error"] = "API Key no configurada"
        return results

    checks_done = 0

    # 1. Comprobar hashes de adjuntos
    for att in attachment_hashes:
        if checks_done >= max_checks:
            break
        sha256 = att.get("sha256")
        if sha256:
            file_result = check_hash(sha256)
            file_result["filename"] = att.get("filename", "desconocido")
            results["files"].append(file_result)
            checks_done += 1
            if file_result.get("malicious", 0) > 0:
                results["summary"]["malicious_files"] += 1

    # 2. Comprobar URLs (máximo 5 para no gastar toda la cuota)
    max_urls = min(5, max_checks - checks_done)
    for url in urls[:max_urls]:
        if checks_done >= max_checks:
            break
        url_result = check_url(url)
        results["urls"].append(url_result)
        checks_done += 1
        if url_result.get("malicious", 0) > 0:
            results["summary"]["malicious_urls"] += 1

    results["summary"]["total_checked"] = checks_done
    results["summary"]["timestamp"]     = datetime.now().isoformat()

    return results


# ── Prueba directa ──
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Uso:")
        print("  python virustotal.py hash <sha256>")
        print("  python virustotal.py url  <url>")
        sys.exit(1)

    mode  = sys.argv[1]
    value = sys.argv[2]

    if mode == "hash":
        result = check_hash(value)
    elif mode == "url":
        result = check_url(value)
    else:
        print(f"Modo desconocido: {mode}")
        sys.exit(1)

    print(json.dumps(result, indent=2, ensure_ascii=False))
