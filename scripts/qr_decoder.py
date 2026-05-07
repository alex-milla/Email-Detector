#!/usr/bin/env python3
"""
qr_decoder.py — Decodifica códigos QR de imágenes.

Usa pyzbar como motor primario y OpenCV como fallback, porque ningún motor
open-source pilla el 100% de los QR reales (los benchmarks de 2025-2026
muestran que cada uno detecta unos QR que el otro pierde).

Uso:
    from qr_decoder import decode_qr_from_bytes
    payloads = decode_qr_from_bytes(image_bytes)  # ['https://...', ...]
"""

import io
import logging
from typing import List

log = logging.getLogger(__name__)

# Imports defensivos: si una librería no está, el módulo sigue funcionando
# con la otra. Solo falla si NINGUNA está disponible.
try:
    from PIL import Image
    _PIL_OK = True
except ImportError:
    _PIL_OK = False
    log.warning("Pillow no disponible — qr_decoder deshabilitado")

try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    from pyzbar.pyzbar import ZBarSymbol
    _PYZBAR_OK = True
except (ImportError, OSError):
    # OSError ocurre cuando libzbar0 no está instalado en el sistema
    _PYZBAR_OK = False
    log.warning("pyzbar no disponible (¿falta libzbar0? `apt install libzbar0`)")

try:
    import cv2
    import numpy as np
    _CV2_OK = True
except ImportError:
    _CV2_OK = False
    log.warning("opencv-python no disponible — fallback de QR deshabilitado")


# Tamaño máximo de imagen a procesar (defensa contra DoS).
# 25 MB es coherente con MAX_ATTACHMENT_SIZE_BYTES de extract_features.py
MAX_IMAGE_BYTES = 25 * 1024 * 1024

# Máximo de QRs a procesar por imagen (defensa contra DoS por QR-bomb)
MAX_QR_PER_IMAGE = 50


def is_available() -> bool:
    """True si al menos un decoder está operativo."""
    return _PIL_OK and (_PYZBAR_OK or _CV2_OK)


def _decode_with_pyzbar(pil_image) -> List[str]:
    """Intenta decodificar con pyzbar. Devuelve solo símbolos QRCODE."""
    if not _PYZBAR_OK:
        return []
    try:
        results = pyzbar_decode(pil_image, symbols=[ZBarSymbol.QRCODE])
        out = []
        for r in results:
            try:
                # El doble decode arregla problemas de encoding con QRs
                # generados en Asia (shift-jis) — es un truco conocido
                # del proyecto QReader.
                payload = r.data.decode("utf-8")
            except UnicodeDecodeError:
                try:
                    payload = r.data.decode("utf-8", errors="replace")
                except Exception:
                    continue
            if payload:
                out.append(payload)
        return out[:MAX_QR_PER_IMAGE]
    except Exception as e:
        log.debug("pyzbar falló: %s", e)
        return []


def _decode_with_opencv(pil_image) -> List[str]:
    """Fallback con cv2.QRCodeDetector. Soporta múltiples QRs por imagen."""
    if not _CV2_OK:
        return []
    try:
        # PIL → numpy (cv2 espera BGR pero detectAndDecode tolera grayscale)
        arr = np.array(pil_image.convert("RGB"))
        bgr = cv2.cvtColor(arr, cv2.COLOR_RGB2BGR)

        detector = cv2.QRCodeDetector()
        # detectAndDecodeMulti es más robusto que detectAndDecode (single)
        retval, decoded_info, _points, _straight_qr = detector.detectAndDecodeMulti(bgr)
        if not retval:
            return []
        return [s for s in decoded_info if s][:MAX_QR_PER_IMAGE]
    except Exception as e:
        log.debug("opencv QR falló: %s", e)
        return []


def decode_qr_from_bytes(image_bytes: bytes) -> List[str]:
    """
    Punto de entrada principal. Recibe bytes de una imagen (PNG, JPG, GIF...)
    y devuelve una lista de payloads de QR encontrados.

    Estrategia: pyzbar primero (más rápido y mejor en QR estándar),
    OpenCV como fallback si pyzbar no encontró nada (mejor en QR dañados,
    con logo central, o no compliant).
    """
    if not is_available():
        return []
    if not image_bytes:
        return []
    if len(image_bytes) > MAX_IMAGE_BYTES:
        log.info("Imagen omitida (%d bytes > MAX)", len(image_bytes))
        return []

    try:
        pil_img = Image.open(io.BytesIO(image_bytes))
        # Normalizar: algunos formatos (GIF animado, modo P) dan problemas
        if pil_img.mode not in ("RGB", "RGBA", "L"):
            pil_img = pil_img.convert("RGB")
    except Exception as e:
        log.debug("No se pudo abrir imagen: %s", e)
        return []

    # 1er intento: pyzbar
    payloads = _decode_with_pyzbar(pil_img)
    if payloads:
        return _dedupe(payloads)

    # 2º intento: OpenCV (solo si pyzbar no encontró nada)
    payloads = _decode_with_opencv(pil_img)
    return _dedupe(payloads)


def _dedupe(items: List[str]) -> List[str]:
    """Elimina duplicados conservando orden."""
    seen = set()
    out = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Uso: python qr_decoder.py <imagen>")
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    found = decode_qr_from_bytes(data)
    print(f"Encontrados {len(found)} QR:")
    for p in found:
        print(f"  → {p}")
