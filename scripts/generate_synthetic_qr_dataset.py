#!/usr/bin/env python3
"""
generate_synthetic_qr_dataset.py — Genera correos .eml sintéticos con y sin QR.

Crea un dataset mínimo para reentrenar el modelo con las nuevas features qr_*.
Requiere: qrcode, Pillow (ya están en requirements.txt)

Uso:
    python scripts/generate_synthetic_qr_dataset.py
"""

import os
import random
import io
from pathlib import Path
from email.message import EmailMessage
from email.policy import SMTP

import qrcode
from PIL import Image

# Directorios de salida
BASE_DIR = Path(__file__).resolve().parent.parent / "data" / "synthetic"
BENIGN_DIR    = BASE_DIR / "benign"
MALICIOUS_DIR = BASE_DIR / "malicious"

# URLs para QR
BENIGN_URLS = [
    "https://www.google.com/search?q=email+detector",
    "https://github.com/alex-milla/Email-Detector",
    "https://stackoverflow.com/questions/tagged/python",
    "https://docs.python.org/3/",
    "https://www.wikipedia.org/wiki/Email",
]

# URLs "maliciosas" (simuladas — no se visitan realmente, solo para features)
MALICIOUS_URLS = [
    "https://bit.ly/3xyZphish",          # acortador
    "https://tinyurl.com/y7malware",     # acortador
    "https://login-microsoft.evil-site.tk/",  # typosquatting
    "https://secure-bank.update-verify.ru/login",  # dominio sospechoso
    "https://t.co/abc123bad",            # acortador
]

SUBJECTS_BENIGN = [
    "Reunión de equipo martes 10am",
    "Factura #1234 pagada correctamente",
    "Tu pedido ha sido enviado",
    "Resumen semanal de actividad",
    "Invitación a evento corporativo",
    "Actualización de políticas internas",
    "Recordatorio: revisar documentación",
    "Confirmación de registro",
]

SUBJECTS_MALICIOUS = [
    "URGENTE: Verifica tu cuenta ahora",
    "⚠️ Actividad sospechosa detectada",
    "Factura vencida — pago inmediato requerido",
    "Actualiza tus datos bancarios",
    "Ganaste un premio — reclama aquí",
    "Tu cuenta será suspendida hoy",
    "Documento confidencial adjunto",
    "Verificación de seguridad obligatoria",
]

BODY_BENIGN_HTML = """\
<html><body>
<p>Hola,</p>
<p>{msg}</p>
<p>Saludos,<br>Equipo de soporte</p>
</body></html>
"""

BODY_MALICIOUS_HTML = """\
<html><body>
<p>Estimado usuario,</p>
<p>{msg}</p>
<p style="color:red;font-weight:bold">⚠️ Debes actuar antes de las 24h o tu cuenta será bloqueada.</p>
<p><a href="https://legit-but-scary.example.com/click">Haz clic aquí para verificar</a></p>
</body></html>
"""


def _make_qr_image(url: str) -> bytes:
    """Genera un PNG con el QR de la URL."""
    img = qrcode.make(url)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def _create_email(subject: str, body_html: str, qr_url: str = None, inline: bool = False) -> bytes:
    """Crea un mensaje .eml con QR opcional."""
    msg = EmailMessage(policy=SMTP)
    msg["Subject"] = subject
    msg["From"] = "noreply@example.com"
    msg["To"] = "user@example.com"
    msg["Message-ID"] = f"<synthetic-{random.randint(100000,999999)}@example.com>"
    msg["Date"] = "Mon, 01 Jan 2024 00:00:00 +0000"
    msg["MIME-Version"] = "1.0"

    if qr_url:
        # Generar imagen QR
        qr_bytes = _make_qr_image(qr_url)

        # Construir HTML con referencia CID si es inline
        if inline:
            cid = "qr-image-1"
            html = body_html.replace("</body>", f'<p><img src="cid:{cid}" alt="QR"></p></body>')
        else:
            html = body_html

        msg.make_mixed()
        alt = EmailMessage(policy=SMTP)
        alt.make_alternative()
        alt.add_alternative(html, subtype="html")
        msg.attach(alt)

        # Adjuntar imagen
        img_part = EmailMessage(policy=SMTP)
        img_part.set_content(qr_bytes, maintype="image", subtype="png")
        img_part["Content-Disposition"] = 'inline; filename="qr.png"' if inline else 'attachment; filename="qr.png"'
        if inline:
            img_part["Content-ID"] = f"<qr-image-1>"
        msg.attach(img_part)
    else:
        msg.add_alternative(body_html, subtype="html")

    return msg.as_bytes()


def _generate_set(output_dir: Path, subjects, body_template, urls, n_total=20):
    output_dir.mkdir(parents=True, exist_ok=True)
    count = 0

    # Distribución: 25% sin QR, 25% QR inline benigno/malo,
    # 25% QR adjunto, 25% sin QR (diferente asunto)
    for i in range(n_total):
        has_qr = random.choice([True, True, True, False])  # 75% con QR
        inline = random.choice([True, False])
        url = random.choice(urls) if has_qr else None
        subject = random.choice(subjects)
        body = body_template.format(msg=f"Mensaje de prueba número {i+1}.")

        eml_bytes = _create_email(subject, body, qr_url=url, inline=inline)
        fname = output_dir / f"synthetic_{count:03d}.eml"
        fname.write_bytes(eml_bytes)
        count += 1

    print(f"  Generados {count} correos en {output_dir}")


def main():
    print("Generando dataset sintético con QR...")
    random.seed(42)

    print("[1/2] Benignos")
    _generate_set(BENIGN_DIR, SUBJECTS_BENIGN, BODY_BENIGN_HTML, BENIGN_URLS, n_total=30)

    print("[2/2] Maliciosos")
    _generate_set(MALICIOUS_DIR, SUBJECTS_MALICIOUS, BODY_MALICIOUS_HTML, MALICIOUS_URLS, n_total=30)

    print("\nDataset listo.")
    print(f"  Benignos:    {len(list(BENIGN_DIR.glob('*.eml')))}")
    print(f"  Maliciosos:  {len(list(MALICIOUS_DIR.glob('*.eml')))}")


if __name__ == "__main__":
    main()
