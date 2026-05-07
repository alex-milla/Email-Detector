#!/usr/bin/env python3
"""
Tests de integración para QR detection en extract_features.py
"""

import io
import sys
import os
import tempfile
import email.mime.multipart
import email.mime.text
import email.mime.image
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts"))


def _create_eml_with_qr(qr_payload, subject="Test QR", inline=True, filename="qr.png"):
    """Crea un archivo .eml temporal con una imagen que contiene un QR."""
    qrcode = pytest.importorskip("qrcode")

    msg = email.mime.multipart.MIMEMultipart()
    msg["Subject"] = subject
    msg["From"] = "test@example.com"
    msg["To"] = "victim@example.com"
    msg.attach(email.mime.text.MIMEText("<p>Scan the QR code below</p>", "html"))

    img = qrcode.make(qr_payload)
    buf = io.BytesIO()
    img.save(buf, format="PNG")

    img_part = email.mime.image.MIMEImage(buf.getvalue())
    if inline:
        img_part.add_header("Content-Disposition", "inline", filename=filename)
        img_part.add_header("Content-ID", "<qr001@example.com>")
    else:
        img_part.add_header("Content-Disposition", "attachment", filename=filename)
    msg.attach(img_part)

    fd, path = tempfile.mkstemp(suffix=".eml")
    with os.fdopen(fd, "wb") as f:
        f.write(msg.as_bytes())
    return path


def test_extract_features_finds_qr_in_inline_image():
    """El extractor debe encontrar un QR en una imagen inline."""
    pytest.importorskip("qrcode")
    from extract_features import extract_features_from_eml

    path = _create_eml_with_qr("https://example.com/inline-test", inline=True)
    try:
        features, metadata = extract_features_from_eml(path)

        assert "qr_codes_found" in metadata
        assert len(metadata["qr_codes_found"]) >= 1

        qr = metadata["qr_codes_found"][0]
        assert qr["raw_payload"] == "https://example.com/inline-test"
        assert qr["is_inline"] is True
        # Si tiene filename, se usa ese; si no, se usa <inline cid:...>
        assert qr["source_filename"] in ("qr.png", "<inline <qr001@example.com>>")
        assert qr["is_url"] is True
    finally:
        os.unlink(path)


def test_extract_features_finds_qr_in_attachment():
    """El extractor debe encontrar un QR en una imagen adjunta."""
    pytest.importorskip("qrcode")
    from extract_features import extract_features_from_eml

    path = _create_eml_with_qr("https://example.com/attachment-test", inline=False, filename="invoice.png")
    try:
        features, metadata = extract_features_from_eml(path)

        assert "qr_codes_found" in metadata
        assert len(metadata["qr_codes_found"]) >= 1

        qr = metadata["qr_codes_found"][0]
        assert qr["raw_payload"] == "https://example.com/attachment-test"
        assert qr["is_inline"] is False
        assert qr["source_filename"] == "invoice.png"
    finally:
        os.unlink(path)


def test_extract_features_no_qr():
    """Un correo sin imágenes no debe tener qr_codes_found."""
    pytest.importorskip("PIL.Image")
    from extract_features import extract_features_from_eml

    msg = email.mime.multipart.MIMEMultipart()
    msg["Subject"] = "No QR here"
    msg["From"] = "test@example.com"
    msg["To"] = "victim@example.com"
    msg.attach(email.mime.text.MIMEText("<p>Just text, no images</p>", "html"))

    fd, path = tempfile.mkstemp(suffix=".eml")
    with os.fdopen(fd, "wb") as f:
        f.write(msg.as_bytes())

    try:
        features, metadata = extract_features_from_eml(path)
        assert metadata.get("qr_codes_found", []) == []
    finally:
        os.unlink(path)


def test_extract_features_non_url_qr():
    """Un QR con texto plano (no URL) debe marcarse is_url=False."""
    pytest.importorskip("qrcode")
    from extract_features import extract_features_from_eml

    path = _create_eml_with_qr("WIFI:S:MyNetwork;T:WPA;P:password;;", inline=True)
    try:
        features, metadata = extract_features_from_eml(path)

        assert len(metadata["qr_codes_found"]) >= 1
        qr = metadata["qr_codes_found"][0]
        assert qr["raw_payload"] == "WIFI:S:MyNetwork;T:WPA;P:password;;"
        assert qr["is_url"] is False
    finally:
        os.unlink(path)


def test_features_dict_unchanged():
    """En Fase 2, el dict features NO debe contener qr_* todavía."""
    pytest.importorskip("qrcode")
    from extract_features import extract_features_from_eml

    path = _create_eml_with_qr("https://example.com/test", inline=True)
    try:
        features, metadata = extract_features_from_eml(path)

        # Verificar que NO hay features qr_* todavía
        for key in features:
            assert not key.startswith("qr_"), f"Feature {key} no debe existir en Fase 2"
    finally:
        os.unlink(path)
