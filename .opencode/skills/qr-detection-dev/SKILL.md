# Skill: Desarrollo de Detección QR (QR Detection Dev)

## Alcance
Desarrollo de los módulos `qr_decoder.py` y `url_resolver.py` para el proyecto Email-Detector, siguiendo la arquitectura propuesta en `md/QR_DETECTION_PROPOSAL.md`.

## Principios de diseño
1. **Defensive imports**: Cada librería opcional se importa con try/except. El módulo nunca falla por una dependencia ausente.
2. **Fallback automático**: `pyzbar` primero, OpenCV como fallback si no encuentra nada.
3. **Límites de seguridad**: MAX_IMAGE_BYTES = 25 MB, MAX_HOPS = 15, timeouts en todas las operaciones de red.
4. **Logging silencioso**: Los fallos de decoding se loguean a nivel DEBUG, no WARNING/ERROR.
5. **Sin side-effects al importar**: Nunca ejecutar código que abra sockets o lea archivos al hacer `import`.

## Estructura de archivos
- `scripts/qr_decoder.py` — Decodificación de QR en imágenes
- `scripts/url_resolver.py` — Resolución de redirecciones HTTP/meta/JS
- `scripts/extract_features.py` — Modificaciones para integrar QR

## Dependencias nuevas
```
pyzbar                    # decoder primario (requiere libzbar0)
opencv-python-headless    # fallback (~60 MB, sin GUI)
Pillow                    # manipulación de imágenes
beautifulsoup4            # parsing meta-refresh
playwright                # detección JS redirects (~300 MB con chromium)
```

## Decisiones técnicas obligatorias
- Usar `ZBarSymbol.QRCODE` en pyzbar (no detectar barcodes por error)
- Usar `detectAndDecodeMulti` de OpenCV (no `detectAndDecode` simple)
- En url_resolver, usar `stream=True` en requests para no descargar payloads enormes
- Limitar HTML leído a 256 KB en requests
- En Playwright: `headless=True`, `accept_downloads=False`, bloquear popups

## Patrones de código

### qr_decoder.py — patrón defensivo
```python
try:
    from pyzbar.pyzbar import decode as pyzbar_decode
    from pyzbar.pyzbar import ZBarSymbol
    _PYZBAR_OK = True
except (ImportError, OSError):
    _PYZBAR_OK = False
```

### url_resolver.py — SSRF protection (OBLIGATORIO)
```python
import ipaddress, socket

def _is_safe_url(url):
    try:
        host = urlparse(url).hostname
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return not (ip.is_private or ip.is_loopback or 
                    ip.is_link_local or ip.is_reserved)
    except Exception:
        return False
```

## Testing unitario mínimo
Cada función pública debe tener al menos:
1. Test del caso feliz
2. Test del caso vacío/error
3. Test de límite (imagen grande, URL inválida, etc.)

## Integración con extract_features
- Añadir imports defensivos al principio del archivo
- Crear función `_scan_email_for_qr_codes(msg)` que itere `msg.walk()`
- Las features QR se añaden al dict `features` y los metadatos al dict `metadata`
- Las URLs finales de QR se inyectan en `urls[]` para que VT las consulte automáticamente

## Compatibilidad
- Python 3.9+
- Linux/Windows (ajustar `libzbar0` vs instalación Windows)
- No romper el modelo existente hasta la fase 5 de activación
