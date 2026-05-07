#!/usr/bin/env python3
"""
url_resolver.py — Resuelve una URL siguiendo TODA la cadena de redirecciones.

3 niveles de detección:
  1. HTTP redirects (301/302/303/307/308) — con `requests`
  2. Meta refresh (<meta http-equiv="refresh" content="0;url=...">) — BeautifulSoup
  3. JavaScript redirects (location.href, window.location, etc.) — Playwright

Uso:
    from url_resolver import resolve_url
    info = resolve_url("https://bit.ly/3xyZ")
    # {
    #   "original": "https://bit.ly/3xyZ",
    #   "final":    "https://login-microsoft.evil.tk/",
    #   "chain":    ["https://bit.ly/3xyZ", "https://t.co/abc", "https://login-microsoft.evil.tk/"],
    #   "hop_count": 2,
    #   "used_meta_refresh": False,
    #   "used_js": True,
    #   "error": None
    # }
"""

import re
import ipaddress
import socket
import logging
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Optional

log = logging.getLogger(__name__)

try:
    import requests
    _REQUESTS_OK = True
except ImportError:
    _REQUESTS_OK = False

try:
    from bs4 import BeautifulSoup
    _BS4_OK = True
except ImportError:
    _BS4_OK = False

try:
    from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout
    _PLAYWRIGHT_OK = True
except ImportError:
    _PLAYWRIGHT_OK = False
    log.info("Playwright no disponible — JS redirects no se detectarán")


# Configuración
HTTP_TIMEOUT = 10              # segundos por petición HTTP
JS_TIMEOUT = 15_000            # ms para Playwright (15 s)
MAX_HOPS = 15                  # nº máximo de redirecciones a seguir
USER_AGENT = "Mozilla/5.0 (compatible; EmailDetector/2.0; +security-scan)"

# Lista de acortadores conocidos (para feature qr_uses_shortener)
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "shorte.st", "rebrand.ly", "cutt.ly", "rb.gy", "shorturl.at",
    "tiny.cc", "lnkd.in", "fb.me", "dlvr.it", "trib.al", "qr.ae", "v.gd",
    "x.gd", "soo.gd", "s.id", "linktr.ee",
}


def is_shortener(url: str) -> bool:
    """True si el dominio de la URL es un acortador conocido."""
    try:
        host = urlparse(url).netloc.lower()
        # Quitar puerto si lo hay
        host = host.split(":")[0]
        return host in SHORTENER_DOMAINS
    except Exception:
        return False


def _is_safe_url(url: str) -> bool:
    """
    Protección SSRF: bloquea URLs con IPs privadas, loopback,
    link-local, reservadas o multicast.
    """
    try:
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            return False
        # Resolver hostname a IP
        ip = ipaddress.ip_address(socket.gethostbyname(host))
        return not (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        )
    except Exception:
        # Si no podemos resolver, consideramos inseguro
        return False


def _http_follow(url: str) -> Dict:
    """
    Sigue redirecciones HTTP estándar.
    Devuelve el último response y la cadena.
    """
    chain = [url]
    if not _REQUESTS_OK:
        return {"chain": chain, "final": url, "html": None, "error": "requests no disponible"}

    if not _is_safe_url(url):
        return {"chain": chain, "final": url, "html": None, "error": "SSRF: URL con IP privada o loopback bloqueada"}

    try:
        # allow_redirects=True hace que requests siga 3xx automáticamente.
        # En `response.history` quedan todas las respuestas intermedias.
        resp = requests.get(
            url,
            allow_redirects=True,
            timeout=HTTP_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            # Importante: NO verificamos contenido descargado, solo cabeceras y HTML inicial
            stream=True,
        )
        for h in resp.history:
            chain.append(h.url)
        if resp.url not in chain:
            chain.append(resp.url)

        # Solo leer HTML si el content-type es texto y el tamaño es razonable
        content_type = resp.headers.get("Content-Type", "").lower()
        html = None
        if "html" in content_type:
            # Limitamos a 256 KB para evitar descargar payloads enormes
            html = resp.raw.read(256 * 1024, decode_content=True)
            try:
                html = html.decode(resp.encoding or "utf-8", errors="replace")
            except Exception:
                html = None
        resp.close()

        return {"chain": chain, "final": resp.url, "html": html, "error": None}
    except requests.exceptions.SSLError as e:
        return {"chain": chain, "final": chain[-1], "html": None, "error": f"SSL: {e}"}
    except requests.exceptions.Timeout:
        return {"chain": chain, "final": chain[-1], "html": None, "error": "timeout"}
    except requests.exceptions.RequestException as e:
        return {"chain": chain, "final": chain[-1], "html": None, "error": str(e)[:200]}


def _detect_meta_refresh(html: str, base_url: str) -> Optional[str]:
    """
    Busca <meta http-equiv="refresh" content="N; url=DESTINO">.
    Devuelve la URL destino o None.
    """
    if not html or not _BS4_OK:
        return None
    try:
        soup = BeautifulSoup(html, "html.parser")
        meta = soup.find("meta", attrs={"http-equiv": re.compile(r"^refresh$", re.I)})
        if not meta:
            return None
        content = meta.get("content", "")
        # Formato típico: "0; url=https://destino.com"
        m = re.search(r'url\s*=\s*["\']?([^"\'\s;]+)', content, re.I)
        if m:
            target = m.group(1).strip()
            return urljoin(base_url, target)
    except Exception as e:
        log.debug("meta-refresh parse falló: %s", e)
    return None


def _resolve_with_js(url: str) -> Dict:
    """
    Usa Playwright para ejecutar JavaScript y capturar la URL final real.
    Solo se invoca si los pasos previos no resolvieron del todo.
    """
    if not _PLAYWRIGHT_OK:
        return {"chain": [url], "final": url, "error": "playwright no disponible"}

    if not _is_safe_url(url):
        return {"chain": [url], "final": url, "error": "SSRF: URL con IP privada o loopback bloqueada"}

    chain = [url]
    final = url
    error = None

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            context = browser.new_context(
                user_agent=USER_AGENT,
                # Bloqueamos descargas y popups para seguridad
                accept_downloads=False,
            )
            page = context.new_page()

            # Capturar TODAS las navegaciones (incluye JS redirects)
            def on_frame_navigated(frame):
                if frame == page.main_frame:
                    new_url = frame.url
                    if new_url and new_url != chain[-1]:
                        chain.append(new_url)

            page.on("framenavigated", on_frame_navigated)

            try:
                # wait_until="networkidle" espera a que se calmen las redirecciones JS
                page.goto(url, timeout=JS_TIMEOUT, wait_until="networkidle")
            except PWTimeout:
                # Aunque haya timeout, recogemos la URL alcanzada
                pass

            final = page.url
            if final not in chain:
                chain.append(final)

            browser.close()
    except Exception as e:
        error = f"playwright: {str(e)[:200]}"
        log.debug("Playwright falló para %s: %s", url, e)

    return {"chain": chain, "final": final, "error": error}


def resolve_url(url: str, use_js: bool = True) -> Dict:
    """
    Resuelve una URL siguiendo redirecciones HTTP, meta-refresh y JS.

    Parámetros:
        url:    URL a resolver
        use_js: si False, omite el paso de Playwright (más rápido)

    Devuelve dict con:
        - original:          URL inicial
        - final:             URL final tras todas las redirecciones
        - chain:             lista ordenada de URLs visitadas
        - hop_count:         len(chain) - 1
        - used_meta_refresh: True si hubo redirección por <meta refresh>
        - used_js:           True si hubo redirección por JS (solo si use_js=True)
        - is_shortener:      True si la URL inicial es un acortador conocido
        - error:             None o mensaje de error
    """
    if not url or not url.startswith(("http://", "https://")):
        return {
            "original": url, "final": url, "chain": [url],
            "hop_count": 0, "used_meta_refresh": False, "used_js": False,
            "is_shortener": False, "error": "URL inválida",
        }

    full_chain = [url]
    used_meta = False
    used_js = False
    error = None

    # ── PASO 1: HTTP redirects ───────────────────────────────
    http_result = _http_follow(url)
    for u in http_result["chain"]:
        if u not in full_chain:
            full_chain.append(u)
    current = http_result["final"]
    error = http_result["error"]

    # ── PASO 2: Meta-refresh ─────────────────────────────────
    # Hasta MAX_HOPS para evitar bucles
    html = http_result.get("html")
    hops = 0
    while html and hops < MAX_HOPS:
        meta_target = _detect_meta_refresh(html, current)
        if not meta_target or meta_target == current:
            break
        used_meta = True
        full_chain.append(meta_target)
        # Seguimos esa nueva URL con HTTP otra vez
        sub = _http_follow(meta_target)
        for u in sub["chain"]:
            if u not in full_chain:
                full_chain.append(u)
        current = sub["final"]
        html = sub.get("html")
        hops += 1

    # ── PASO 3: JavaScript redirects (solo si pidió use_js) ──
    # Optimización: solo ejecutamos Playwright si la URL aún no parece final.
    # Heurística: si el dominio actual es un shortener, hay que profundizar.
    if use_js and _PLAYWRIGHT_OK and (is_shortener(current) or hops == 0):
        # Probamos JS sobre la URL actual
        js_result = _resolve_with_js(current)
        if js_result.get("final") and js_result["final"] != current:
            used_js = True
            for u in js_result["chain"]:
                if u not in full_chain:
                    full_chain.append(u)
            current = js_result["final"]

    # Truncar cadena por seguridad
    if len(full_chain) > MAX_HOPS:
        full_chain = full_chain[:MAX_HOPS] + ["...(truncated)"]

    return {
        "original": url,
        "final": current,
        "chain": full_chain,
        "hop_count": max(0, len(full_chain) - 1),
        "used_meta_refresh": used_meta,
        "used_js": used_js,
        "is_shortener": is_shortener(url),
        "error": error,
    }


if __name__ == "__main__":
    import sys, json
    if len(sys.argv) < 2:
        print("Uso: python url_resolver.py <url> [--no-js]")
        sys.exit(1)
    use_js = "--no-js" not in sys.argv
    info = resolve_url(sys.argv[1], use_js=use_js)
    print(json.dumps(info, indent=2, ensure_ascii=False))
