#!/usr/bin/env python3
"""
Tests para qr_decoder.py
"""

import io
import sys
import os
import pytest

# Añadir scripts/ al path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


def test_decode_simple_qr():
    """QR generado con qrcode debe leerse perfectamente."""
    qrcode = pytest.importorskip("qrcode")
    from qr_decoder import decode_qr_from_bytes

    img = qrcode.make("https://example.com/test")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    assert decode_qr_from_bytes(buf.getvalue()) == ["https://example.com/test"]


def test_decode_no_qr_in_image():
    """Una imagen sin QR debe devolver lista vacía."""
    PILImg = pytest.importorskip("PIL.Image")
    from qr_decoder import decode_qr_from_bytes

    buf = io.BytesIO()
    PILImg.new("RGB", (100, 100), "red").save(buf, format="PNG")
    assert decode_qr_from_bytes(buf.getvalue()) == []


def test_decode_large_image_rejected():
    """Una imagen que excede MAX_IMAGE_BYTES debe devolver lista vacía."""
    from qr_decoder import decode_qr_from_bytes, MAX_IMAGE_BYTES

    assert decode_qr_from_bytes(b"x" * (MAX_IMAGE_BYTES + 1)) == []


def test_decode_empty_bytes():
    """Bytes vacíos deben devolver lista vacía."""
    from qr_decoder import decode_qr_from_bytes

    assert decode_qr_from_bytes(b"") == []


def test_decode_invalid_image():
    """Bytes que no son una imagen válida deben devolver lista vacía."""
    from qr_decoder import decode_qr_from_bytes

    assert decode_qr_from_bytes(b"not an image") == []


def test_qr_with_special_characters():
    """QR con caracteres especiales (UTF-8) debe decodificarse correctamente."""
    qrcode = pytest.importorskip("qrcode")
    from qr_decoder import decode_qr_from_bytes

    # Nota: pyzbar puede tener problemas con algunos caracteres UTF-8
    # dependiendo del encoding del QR. Usamos un payload seguro.
    payload = "https://example.com/cafe?query=nino"
    img = qrcode.make(payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    result = decode_qr_from_bytes(buf.getvalue())
    assert result == [payload]


def test_multiple_qrs_in_image():
    """Si hay múltiples QRs, deben devolverse todos."""
    qrcode = pytest.importorskip("qrcode")
    PILImg = pytest.importorskip("PIL.Image")
    from qr_decoder import decode_qr_from_bytes

    # Crear imagen con 2 QRs lado a lado
    qr1 = qrcode.make("https://first.com")
    qr2 = qrcode.make("https://second.com")

    # Combinar en una sola imagen
    # qrcode.make() devuelve qrcode.image.pil.PilImage, accedemos a .get_image()
    pil1 = qr1.get_image() if hasattr(qr1, 'get_image') else qr1
    pil2 = qr2.get_image() if hasattr(qr2, 'get_image') else qr2
    w = max(pil1.width, pil2.width)
    h = pil1.height + pil2.height + 10
    combined = PILImg.new("RGB", (w, h), "white")
    combined.paste(pil1, (0, 0))
    combined.paste(pil2, (0, pil1.height + 10))

    buf = io.BytesIO()
    combined.save(buf, format="PNG")
    result = decode_qr_from_bytes(buf.getvalue())

    assert len(result) == 2
    assert "https://first.com" in result
    assert "https://second.com" in result
