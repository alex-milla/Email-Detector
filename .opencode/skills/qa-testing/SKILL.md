# Skill: QA y Testing para QR Detection

## Alcance
Validación completa de la funcionalidad QR: unit tests, integración, E2E y validación de modelo.

## Estrategia de testing por fases

### Fase 1: Unit tests (módulos aislados)
Archivo: `tests/test_qr_decoder.py`
```python
import pytest
import io
from PIL import Image

def test_decode_simple_qr():
    import qrcode
    img = qrcode.make("https://example.com/test")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    from scripts.qr_decoder import decode_qr_from_bytes
    assert decode_qr_from_bytes(buf.getvalue()) == ["https://example.com/test"]

def test_decode_no_qr():
    buf = io.BytesIO()
    Image.new("RGB", (100, 100), "red").save(buf, format="PNG")
    from scripts.qr_decoder import decode_qr_from_bytes
    assert decode_qr_from_bytes(buf.getvalue()) == []

def test_decode_large_image_rejected():
    from scripts.qr_decoder import decode_qr_from_bytes, MAX_IMAGE_BYTES
    assert decode_qr_from_bytes(b"x" * (MAX_IMAGE_BYTES + 1)) == []

def test_decode_fallback_opencv():
    # Crear QR que pyzbar falle pero OpenCV lo detecte (raro, pero posible)
    pass  # Implementar con imagen específica
```

Archivo: `tests/test_url_resolver.py`
```python
def test_shortener_detection():
    from scripts.url_resolver import is_shortener
    assert is_shortener("https://bit.ly/3xyZ") is True
    assert is_shortener("https://example.com") is False

def test_http_redirect_chain():
    # Requiere pytest-httpserver o mock de requests
    pass

def test_meta_refresh_detection():
    from scripts.url_resolver import _detect_meta_refresh
    html = '<meta http-equiv="refresh" content="0;url=https://evil.com">'
    assert _detect_meta_refresh(html, "https://start.com") == "https://evil.com"

def test_ssrf_blocked():
    from scripts.url_resolver import resolve_url
    result = resolve_url("http://192.168.1.1/admin", use_js=False)
    assert result.get("error") or result["hop_count"] == 0
```

### Fase 2: Integration tests (flujo completo)
Archivo: `tests/test_qr_integration.py`
```python
def test_extract_features_with_qr():
    # Crear .eml de prueba con imagen inline que contenga QR
    import email.mime.multipart
    import email.mime.image
    import email.mime.text
    
    msg = email.mime.multipart.MIMEMultipart()
    msg["Subject"] = "Test QR"
    msg.attach(email.mime.text.MIMEText("<p>Scan me</p>", "html"))
    
    # Adjuntar imagen con QR
    import qrcode
    img = qrcode.make("https://bit.ly/test123")
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    
    img_part = email.mime.image.MIMEImage(buf.getvalue())
    img_part.add_header("Content-Disposition", "inline", filename="qr.png")
    msg.attach(img_part)
    
    # Guardar y analizar
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".eml", delete=False) as f:
        f.write(msg.as_bytes())
        path = f.name
    
    from scripts.extract_features import extract_features_from_eml
    features, metadata = extract_features_from_eml(path)
    
    assert features.get("qr_count", 0) >= 1
    assert metadata.get("qr_codes_found", []) != []
```

### Fase 3: E2E tests (web)
- Subir .eml con QR vía interfaz web
- Verificar que la sección "📱 Códigos QR detectados" aparece en el modal
- Verificar que la cadena de redirecciones se muestra correctamente

### Fase 4: Validación de modelo
- Verificar que `feature_names` en `model_metadata.json` incluye todas las `qr_*`
- Verificar que `predict.py` no falla con modelo nuevo + correo antiguo
- Verificar que `predict.py` no falla con modelo antiguo + correo nuevo (features default 0)

## Herramientas recomendadas
```
pytest
pytest-cov          # cobertura
pytest-httpserver   # mocks de HTTP para url_resolver
qrcode              # generar QRs de prueba
Pillow              # generar imágenes de prueba
```

## Métricas de calidad
- Cobertura mínima: 80% en qr_decoder.py y url_resolver.py
- Todos los tests de seguridad deben pasar
- Tiempo de test < 60 segundos (Playwright puede ser lento; marcar como `slow`)

## Comandos de ejecución
```bash
# Todos los tests
python -m pytest tests/ -v

# Solo rápidos (sin Playwright)
python -m pytest tests/ -v -m "not slow"

# Con cobertura
python -m pytest tests/ --cov=scripts --cov-report=term-missing
```
