# Skill: Ciberseguridad en QR Detection

## Alcance
Análisis de amenazas, mitigaciones y validaciones de seguridad para la funcionalidad de detección QR en Email-Detector.

## Vector de ataque 1: SSRF (Server-Side Request Forgery)
**Riesgo**: CRÍTICO. El atacante pone en un QR `http://192.168.1.1/admin/restart` y el servidor lo visita.

**Mitigación obligatoria**:
- Filtrar IPs privadas/loopback/link-local/reserved ANTES de cualquier petición HTTP
- Validar tanto en `_http_follow` como en `_resolve_with_js`
- Implementar `_is_safe_url()` con resolución DNS

```python
def _is_safe_url(url):
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return not (ip.is_private or ip.is_loopback or 
                    ip.is_link_local or ip.is_reserved or ip.is_multicast)
    except Exception:
        return False
```

**Tests de seguridad**:
```python
def test_ssrf_blocked():
    from url_resolver import resolve_url
    result = resolve_url("http://127.0.0.1/secret")
    assert "error" in result or result["hop_count"] == 0
```

## Vector de ataque 2: DoS por QR-bomb
**Riesgo**: MEDIO. Imagen 50MB con 1000 QRs sintéticos.

**Mitigaciones**:
- `MAX_IMAGE_BYTES = 25 * 1024 * 1024` en qr_decoder
- `MAX_QR_PER_EMAIL = 20` (limitar número de QRs procesados por correo)
- Timeouts en todas las operaciones de red (HTTP_TIMEOUT = 10s, JS_TIMEOUT = 15s)
- `MAX_HOPS = 15` en url_resolver

## Vector de ataque 3: Playwright resource exhaustion
**Riesgo**: MEDIO. Cada instancia de Chromium consume ~200MB RAM.

**Mitigaciones**:
- Solo invocar Playwright cuando `is_shortener(current) or hops == 0`
- Usar `browser.close()` siempre (try/finally)
- Considerar un pool de browsers o timeout estricto

## Vector de ataque 4: Privacidad / data leakage
**Riesgo**: BAJO. Al visitar URLs, el sitio recibe la IP del servidor.

**Documentar**:
- Añadir nota en README sobre que el análisis de QR revela la IP del servidor
- Sugerir proxy/Tor para análisis sensibles

## Vector de ataque 5: VirusTotal rate limit exhaustion
**Riesgo**: BAJO. Un correo con 5 QRs consume toda la cuota del minuto.

**Mitigaciones ya existentes**:
- `max_checks=6` en `check_email_artifacts`
- Mantener esta cifra; no aumentarla por defecto
- Las URLs de QR se añaden a `urls[]` y compiten con URLs de texto por el mismo presupuesto

## Checklist de seguridad pre-merge
- [ ] `_is_safe_url()` implementado y testeado
- [ ] `MAX_IMAGE_BYTES` configurado
- [ ] `MAX_QR_PER_EMAIL` configurado
- [ ] Playwright solo para shorteners
- [ ] Tests SSRF pasan
- [ ] No hay credenciales en código
- [ ] No se ejecuta código del atacante (Playwright sandbox activo)
