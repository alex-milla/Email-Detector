"""
Plugin de ejemplo para Email Malware Detector.
Añade una feature personalizada y ajusta el riesgo si se detectan
ciertos patrones en el asunto o remitente.
"""

import re


def analyze(features, metadata):
    result = {"features": {}, "boost": 0.0, "tags": []}

    subject = metadata.get("subject", "")
    from_addr = metadata.get("from", "")

    suspicious_domains = {"tempmail.com", "mailinator.com", "guerrillamail.com"}
    for domain in suspicious_domains:
        if domain in from_addr.lower():
            result["boost"] += 0.15
            result["tags"].append(f"dominio_temporal:{domain}")

    body_text = metadata.get("body_html", "") or metadata.get("body_text", "") or " "
    result["features"]["custom_subject_ratio"] = round(
        len(subject) / max(len(body_text), 1), 4
    )

    return result
