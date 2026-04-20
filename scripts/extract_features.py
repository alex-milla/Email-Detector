#!/usr/bin/env python3
"""
extract_features.py — Extrae todas las características numéricas de un correo .eml.

Este script es el "traductor" que convierte un correo electrónico
en un conjunto de números que la IA puede entender.

Uso:
    # Analizar un solo correo:
    python extract_features.py /ruta/al/correo.eml

    # Analizar todos los .eml de una carpeta y generar CSV:
    python extract_features.py --batch /ruta/a/carpeta --output features.csv
"""

import email
import re
import sys
import os
import json
import csv
import hashlib
import argparse
from email import policy
from urllib.parse import urlparse
from pathlib import Path

# Importar nuestro módulo de entropía
sys.path.insert(0, os.path.dirname(__file__))
from shannon_entropy import calculate_entropy, calculate_entropy_bytes

# Importar Anti-Clanker (soft-fail si no está disponible)
try:
    from extract_clanker_features import extract_clanker_features
    _CLANKER_FEATS_AVAILABLE = True
except Exception:
    _CLANKER_FEATS_AVAILABLE = False


def extract_urls(text):
    """Encuentra todas las URLs en un texto."""
    if not text:
        return []
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text)


def count_special_chars(text):
    """Cuenta caracteres que no son letras, números ni espacios."""
    if not text:
        return 0
    return len(re.findall(r'[^a-zA-Z0-9\s]', text))


def detect_urgency_keywords(text):
    """
    Cuenta palabras que crean sensación de urgencia.
    Los correos de phishing suelen usar estas tácticas.
    """
    keywords = [
        # Español
        "urgente", "inmediato", "acción requerida", "cuenta suspendida",
        "verificar", "confirmar identidad", "haga clic", "en 24 horas",
        "última advertencia", "actúa ya", "su cuenta será",
        "acceso no autorizado", "actividad sospechosa",
        # Inglés
        "urgent", "immediately", "action required", "verify your account",
        "suspended", "click here", "within 24 hours", "last warning",
        "act now", "unauthorized access", "suspicious activity",
        "confirm your identity", "your account will be",
    ]
    text_lower = (text or "").lower()
    return sum(1 for kw in keywords if kw in text_lower)


def check_mismatched_urls(html_body):
    """
    Detecta URLs donde lo que ves no es lo que obtienes.
    Ejemplo: el texto dice "www.banco.com" pero el enlace real
    va a "www.sitio-malicioso.com". Esto es phishing clásico.
    """
    if not html_body:
        return 0
    pattern   = r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>(https?://[^<]+)</a>'
    matches   = re.findall(pattern, html_body, re.IGNORECASE)
    mismatched = 0
    for href, visible_text in matches:
        href_domain    = urlparse(href).netloc.lower()
        visible_domain = urlparse(visible_text).netloc.lower()
        if href_domain and visible_domain and href_domain != visible_domain:
            mismatched += 1
    return mismatched


def get_attachment_risk(filename):
    """
    Puntúa lo peligrosa que es una extensión de archivo.
    Un .exe es mucho más peligroso que un .jpg.
    """
    risk_map = {
        # Muy alto riesgo: ejecutables
        ".exe": 10, ".bat": 10, ".cmd": 10, ".scr": 10, ".com": 10,
        # Alto riesgo: scripts
        ".ps1": 8,  ".vbs": 8,  ".js":  8,  ".jar": 8,  ".py":  7,
        # Riesgo medio: documentos con macros
        ".doc": 6,  ".xls": 6,  ".ppt": 6,
        ".docm": 7, ".xlsm": 7, ".pptm": 7,
        # Riesgo bajo-medio: comprimidos (pueden contener cualquier cosa)
        ".zip": 4,  ".rar": 4,  ".7z":  4,  ".tar": 4,  ".gz":  4,
        # Riesgo bajo: documentos seguros
        ".pdf": 3,
        # Sin riesgo apreciable: imágenes y texto
        ".jpg": 1,  ".jpeg": 1, ".png": 1,  ".gif": 1,
        ".txt": 1,  ".csv": 1,
    }
    ext = os.path.splitext(filename.lower())[1]
    return risk_map.get(ext, 2)


# Límites de seguridad contra DoS por archivos enormes
MAX_EML_SIZE_BYTES = 50 * 1024 * 1024      # 50 MB total por .eml
MAX_ATTACHMENT_SIZE_BYTES = 25 * 1024 * 1024  # 25 MB por adjunto


def get_attachment_hashes(part):
    """
    Calcula los hashes de un adjunto (para enviar a VirusTotal).
    Devuelve MD5, SHA1 y SHA256. Omite adjuntos que excedan el tamaño máximo.
    """
    payload = part.get_payload(decode=True)
    if not payload:
        return {}
    if len(payload) > MAX_ATTACHMENT_SIZE_BYTES:
        return {
            "md5": "", "sha1": "", "sha256": "",
            "size": len(payload),
            "entropy": 0.0,
            "skipped": True,
            "reason": f"Adjunto excede {MAX_ATTACHMENT_SIZE_BYTES // (1024*1024)} MB",
        }
    return {
        "md5":     hashlib.md5(payload).hexdigest(),
        "sha1":    hashlib.sha1(payload).hexdigest(),
        "sha256":  hashlib.sha256(payload).hexdigest(),
        "size":    len(payload),
        "entropy": calculate_entropy_bytes(payload),
    }


def extract_features_from_eml(eml_path):
    """
    FUNCIÓN PRINCIPAL: lee un archivo .eml y devuelve un diccionario
    con todas las features numéricas que necesita el modelo.
    """
    file_size = os.path.getsize(eml_path)
    if file_size > MAX_EML_SIZE_BYTES:
        raise ValueError(
            f"Archivo .eml demasiado grande ({file_size / (1024*1024):.1f} MB). "
            f"Máximo permitido: {MAX_EML_SIZE_BYTES // (1024*1024)} MB."
        )

    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    # ── Datos básicos del correo ──
    subject     = msg.get("Subject", "") or ""
    from_header = msg.get("From", "")    or ""
    to_header   = msg.get("To", "")      or ""

    # ── Extraer cuerpo (texto y HTML por separado) ──
    MAX_BODY_CHARS = 500_000  # ~1 MB de texto, suficiente para análisis
    MAX_BODY_PART_BYTES = 2 * 1024 * 1024  # 2 MB por parte; si es mayor, omitimos
    body_text = ""
    body_html = ""
    for part in msg.walk():
        content_type = part.get_content_type()
        # Evitar cargar partes enormes en memoria antes de decodificar
        payload = part.get_payload(decode=True)
        if payload and len(payload) > MAX_BODY_PART_BYTES:
            continue
        try:
            if content_type == "text/plain":
                body_text += (part.get_content() or "")
            elif content_type == "text/html":
                body_html += (part.get_content() or "")
        except Exception:
            pass
        # Truncar temprano si ya superamos el límite
        if len(body_text) > MAX_BODY_CHARS:
            body_text = body_text[:MAX_BODY_CHARS]
        if len(body_html) > MAX_BODY_CHARS:
            body_html = body_html[:MAX_BODY_CHARS]

    full_text = body_text if body_text else body_html

    # ── URLs ──
    urls         = extract_urls(full_text)
    url_lengths  = [len(u) for u in urls]
    url_length_avg = sum(url_lengths) / len(url_lengths) if url_lengths else 0.0

    # ── Adjuntos ──
    attachments      = []
    attachment_hashes = []
    for part in msg.walk():
        fn = part.get_filename()
        if fn:
            attachments.append(fn)
            hashes = get_attachment_hashes(part)
            if hashes:
                hashes["filename"] = fn
                attachment_hashes.append(hashes)

    has_attachment     = 1 if attachments else 0
    attachment_ext_risk = max(
        (get_attachment_risk(fn) for fn in attachments), default=0
    )

    # ── Cabeceras de autenticación (SPF, DKIM, DMARC) ──
    auth_results = (msg.get("Authentication-Results", "") or "").lower()
    spf_pass  = 1 if "spf=pass"  in auth_results else 0
    dkim_pass = 1 if "dkim=pass" in auth_results else 0
    dmarc_pass = 1 if "dmarc=pass" in auth_results else 0

    # ── Anomalías en cabeceras ──
    header_anomalies  = 0
    if not msg.get("Message-ID"):  header_anomalies += 1
    if not msg.get("Date"):        header_anomalies += 1
    received_headers = msg.get_all("Received") or []
    if len(received_headers) > 10: header_anomalies += 1
    if not msg.get("MIME-Version"): header_anomalies += 1

    # ── Puerto (extraer del primer Received header) ──
    port = 25
    if received_headers:
        port_match = re.search(r'port\s+(\d+)', received_headers[0])
        if port_match:
            port = int(port_match.group(1))

    # ══════════════════════════════════════════════
    #  ENTROPÍA DE SHANNON
    # ══════════════════════════════════════════════

    body_entropy    = calculate_entropy(full_text)
    subject_entropy = calculate_entropy(subject)

    url_entropies   = [calculate_entropy(u) for u in urls] if urls else [0.0]
    url_entropy_max = max(url_entropies)
    url_entropy_avg = sum(url_entropies) / len(url_entropies)

    attachment_name_entropies     = [calculate_entropy(fn) for fn in attachments] if attachments else [0.0]
    attachment_name_entropy_max   = max(attachment_name_entropies)

    attachment_content_entropy_max = 0.0
    if attachment_hashes:
        attachment_content_entropy_max = max(
            h.get("entropy", 0.0) for h in attachment_hashes
        )

    # ── Diccionario de features ──
    features = {
        # Features clásicas
        "url_length_avg":       round(url_length_avg, 2),
        "url_count":            len(urls),
        "num_special_chars":    count_special_chars(subject + " " + full_text),
        "has_attachment":       has_attachment,
        "attachment_ext_risk":  attachment_ext_risk,
        "subject_length":       len(subject),
        "body_length":          len(full_text),
        "spf_pass":             spf_pass,
        "dkim_pass":            dkim_pass,
        "dmarc_pass":           dmarc_pass,
        "urgency_keywords":     detect_urgency_keywords(subject + " " + full_text),
        "mismatched_urls":      check_mismatched_urls(body_html),
        "header_anomalies":     header_anomalies,
        "port":                 port,
        # Features de entropía
        "body_entropy":                    body_entropy,
        "subject_entropy":                 subject_entropy,
        "url_entropy_max":                 url_entropy_max,
        "url_entropy_avg":                 round(url_entropy_avg, 4),
        "attachment_name_entropy_max":     attachment_name_entropy_max,
        "attachment_content_entropy_max":  attachment_content_entropy_max,
    }

    # ── Anti-Clanker features (integradas al vector de entrenamiento) ──
    if _CLANKER_FEATS_AVAILABLE and body_html:
        try:
            clanker_feats = extract_clanker_features(body_html)
            features.update(clanker_feats)
        except Exception:
            pass

    # Metadatos (no van al modelo, útiles para VirusTotal, Anti-Clanker y GUI)
    metadata = {
        "filename":          os.path.basename(eml_path),
        "subject":           subject,
        "from":              from_header,
        "to":                to_header,
        "urls_found":        urls,
        "attachments":       attachments,
        "attachment_hashes": attachment_hashes,
        "body_html":         body_html,
    }

    return features, metadata


# ══════════════════════════════════════════════════
#  PROCESAMIENTO POR LOTES (genera el CSV para entrenar)
# ══════════════════════════════════════════════════

def batch_extract(input_dir, output_csv, label=None):
    """
    Procesa todos los .eml de una carpeta y genera un CSV.

    Parámetros:
        input_dir:  carpeta con archivos .eml
        output_csv: ruta donde guardar el CSV
        label:      si se proporciona (0 o 1), se añade como columna
                    0 = benigno, 1 = malicioso
    """
    eml_files = list(Path(input_dir).glob("**/*.eml"))
    print(f"Encontrados {len(eml_files)} archivos .eml")

    if not eml_files:
        print("No se encontraron archivos .eml")
        return

    all_features = []
    for i, eml_path in enumerate(eml_files):
        try:
            features, metadata = extract_features_from_eml(str(eml_path))
            if label is not None:
                features["label"] = label
            all_features.append(features)
            print(f"  [{i+1}/{len(eml_files)}] OK: {eml_path.name}")
        except Exception as e:
            print(f"  [{i+1}/{len(eml_files)}] ERROR: {eml_path.name} → {e}")

    if all_features:
        os.makedirs(os.path.dirname(output_csv) or ".", exist_ok=True)
        keys = all_features[0].keys()
        with open(output_csv, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=keys)
            writer.writeheader()
            writer.writerows(all_features)
        print(f"\nCSV generado: {output_csv} ({len(all_features)} filas)")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Extrae features de correos .eml")
    parser.add_argument("path",     help="Ruta a un .eml o carpeta")
    parser.add_argument("--batch",  action="store_true", help="Procesar toda una carpeta")
    parser.add_argument("--output", default="data/processed/features.csv",
                        help="Ruta del CSV de salida (modo batch)")
    parser.add_argument("--label",  type=int, choices=[0, 1],
                        help="Etiqueta: 0=benigno, 1=malicioso")
    args = parser.parse_args()

    if args.batch:
        batch_extract(args.path, args.output, args.label)
    else:
        features, metadata = extract_features_from_eml(args.path)
        print("\n── FEATURES (para el modelo) ──")
        print(json.dumps(features, indent=2))
        print("\n── METADATOS (info adicional) ──")
        print(json.dumps(metadata, indent=2, default=str))
