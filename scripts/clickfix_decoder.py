#!/usr/bin/env python3
"""clickfix_decoder.py — Motor de detección y desofuscado de ClickFix.

ClickFix es una técnica de ingeniería social en la que la víctima es engañada
para copiar (a menudo mediante la Clipboard API) un comando PowerShell ofuscado
y pegarlo en el diálogo Ejecutar (Win+R) o en una terminal.

Este módulo:

  * Detecta la superficie ClickFix (Clipboard API, execCommand('copy'),
    textarea oculto, frases señuelo, Win+R, fake-CAPTCHA...).
  * Extrae comandos candidatos del HTML, del texto plano y de adjuntos HTML.
  * Desofusca por capas SIN EJECUTAR NADA: Base64 (incl. UTF-16LE de -enc),
    String.fromCharCode, atob(), escapes \\x/\\u, concatenación de literales y
    reconstrucción estática de cadenas (variables/arrays JS y [char] de
    PowerShell). No revierte XOR/aritmética arbitraria.
  * Extrae los indicadores originales: URLs, dominios e IPs embebidos en el
    comando ofuscado (la siguiente etapa / C2) y la URL señuelo.
  * Genera features numéricas ``clanker_clickfix_*`` para reentrenar el
    Modelo 10 (Anti-Clanker).

Solo usa la biblioteca estándar. Diseñado para hacer soft-fail: nunca lanza
excepciones hacia el llamador.
"""

import base64
import binascii
import ipaddress
import re
import sys
from typing import Any, Dict, List, Optional

MAX_INPUT_CHARS = 500_000
MAX_COMMAND_CHARS = 8_192
MAX_LAYERS = 4
MAX_CANDIDATES = 40
MAX_COMMANDS = 10
MAX_INDICATORS = 30

# ── Patrones de superficie ClickFix ──────────────────────────────────────────

_CLIPBOARD_API_RE = re.compile(
    r"navigator\.clipboard(?:\.writeText|\.write|\s*\[)|"
    r"new\s+ClipboardItem|"
    r"document\.execCommand\s*\(\s*['\"](?:copy|cut)['\"]|"
    r"document\.getSelection\s*\(\s*\)",
    re.IGNORECASE,
)

_EXEC_COPY_RE = re.compile(
    r"document\.execCommand\s*\(\s*['\"](?:copy|cut)['\"]", re.IGNORECASE
)

_HIDDEN_COPY_RE = re.compile(
    r"<(?:textarea|input)[^>]*(?:hidden|readonly|style\s*=\s*['\"][^'\"]*"
    r"(?:display\s*:\s*none|opacity\s*:\s*0|position\s*:\s*absolute))"
    r"[^>]*>",
    re.IGNORECASE,
)

_SELECT_COPY_RE = re.compile(
    r"\.select\s*\(\s*\)[\s\S]{0,200}?(?:execCommand|clipboard)", re.IGNORECASE
)

_LURE_PHRASES = (
    r"win(?:dows)?\s*\+\s*r",
    r"tecla(?:s)?\s+windows\s*\+\s*r",
    r"cuadro\s+de\s+ejecutar",
    r"run\s+dialog",
    r"press\s+(?:the\s+)?(?:windows|win)\s*(?:\+|key)",
    r"peg(?:a|ar|ue)\s+(?:el\s+)?comando",
    r"paste\s+(?:the\s+)?command",
    r"cop(?:y|ia|iar)\s+(?:el\s+)?comando",
    r"ctrl\s*\+\s*v",
    r"i'?m\s+not\s+a\s+robot",
    r"no\s+soy\s+un\s+robot",
    r"verify\s+(?:you\s+are|that\s+you\s+are)\s+human",
    r"verifica\s+que\s+eres\s+humano",
    r"re-?captcha",
    r"h-?captcha",
    r"cloudflare",
    r"press\s+win(?:dows)?\s*\+\s*r",
)
_LURE_RES = [re.compile(p, re.IGNORECASE) for p in _LURE_PHRASES]

_WIN_R_RE = re.compile(r"win(?:dows)?\s*\+\s*r", re.IGNORECASE)

_COMMAND_KEYWORDS = (
    r"powershell(?:\.exe)?",
    r"-encodedcommand",
    r"\s-enc\s",
    r"\biex\b",
    r"invoke-expression",
    r"invoke-webrequest",
    r"\biwr\b",
    r"downloadstring",
    r"frombase64string",
    r"\bmshta\b",
    r"\bcertutil\b",
    r"\bbitsadmin\b",
    r"\brundll32\b",
    r"\bregsvr32\b",
    r"\bwscript\b",
    r"\bcscript\b",
    r"\bcmd(?:\.exe)?\s*/\s*c\b",
    r"\bconhost\b",
    r"start-process",
    r"\bcurl\b",
    r"\bwget\b",
    r"add-mppreference",
    r"set-mppreference",
    r"exclusionpath",
    r"\bpowershell\s+-[a-z]",
)
_COMMAND_RE = re.compile("|".join(_COMMAND_KEYWORDS), re.IGNORECASE)

_ENCODED_RE = re.compile(
    r"(?:-encodedcommand|-enc|-e)\s+([A-Za-z0-9+/=]{40,})", re.IGNORECASE
)

_BASE64_TOKEN_RE = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}")

_FROMCHARCODE_RE = re.compile(
    r"String\.fromCharCode(?:\.apply\s*\(\s*(?:null|this)\s*,\s*\[|\s*\()"
    r"\s*([0-9]{1,4}(?:\s*,\s*[0-9]{1,4})*)\s*[\])]",
    re.IGNORECASE,
)

_ATOB_RE = re.compile(
    r"(?:atob|Buffer\.from)\s*\(\s*(['\"])([A-Za-z0-9+/=]{4,})\1"
    r"(?:\s*,\s*['\"]base64['\"])?\s*\)",
    re.IGNORECASE,
)

_CONCAT_RE = re.compile(
    r"(?:'[^']*'|\"[^\"]*\")(?:\s*\+\s*(?:'[^']*'|\"[^\"]*\"))+"
)

_ESCAPE_RE = re.compile(r"\\x([0-9a-fA-F]{2})|\\u([0-9a-fA-F]{4})")

# ── Reconstrucción estática de cadenas (JS y PowerShell) ─────────────────────
# Permite recuperar URLs/comandos ensamblados con variables o arrays sin
# ejecutar nada. NO intenta revertir XOR/aritmética arbitraria.

_JS_ASSIGN_RE = re.compile(
    r"(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*(\+?=)\s*([^;\n]+)",
    re.IGNORECASE,
)
_JS_ARRAY_ASSIGN_RE = re.compile(
    r"(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*"
    r"\[\s*(\d{1,5}(?:\s*,\s*\d{1,5})*)\s*\]",
    re.IGNORECASE,
)
_JS_EXPR_RE = re.compile(
    r"(?:[A-Za-z_$][\w$]*|'[^']*'|\"[^\"]*\")"
    r"(?:\s*\+\s*(?:[A-Za-z_$][\w$]*|'[^']*'|\"[^\"]*\"))+"
)
_JS_FCC_ARRAY_RE = re.compile(
    r"String\.fromCharCode(?:\.apply\s*\(\s*(?:null|this)\s*,\s*"
    r"([A-Za-z_$][\w$]*)|"
    r"\s*\(\s*([A-Za-z_$][\w$]*))\s*\)",
    re.IGNORECASE,
)
_JS_ATOB_VAR_RE = re.compile(
    r"atob\s*\(\s*([A-Za-z_$][\w$]*)\s*\)", re.IGNORECASE
)
_LITERAL_RE = re.compile(
    r"'((?:[^'\\]|\\.)*)'|\"((?:[^\"\\]|\\.)*)\"", re.DOTALL
)
_IDENT_RE = re.compile(r"^[A-Za-z_$][\w$]*$")

_PS_CHAR_SEQ_RE = re.compile(
    r"(?:\[char\]\s*(?:0x[0-9a-fA-F]+|\d{1,5})\s*(?:\+\s*)?){3,}",
    re.IGNORECASE,
)
_PS_CHAR_CODE_RE = re.compile(
    r"\[char\]\s*(0x[0-9a-fA-F]+|\d{1,5})", re.IGNORECASE
)
_PS_CHAR_ARRAY_RE = re.compile(
    r"\[char\[\]\]\s*@?\(\s*(\d{1,5}(?:\s*,\s*\d{1,5})*)\s*\)",
    re.IGNORECASE,
)

_MAX_SYMBOLS = 200

_URL_RE = re.compile(
    r"(?:https?|hxxps?|ftp)://[^\s<>\"'\}]+",
    re.IGNORECASE,
)

_DOMAIN_RE = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:[a-zA-Z]{2,24})\b"
)

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")

# Solo se aceptan dominios "sueltos" (no extraídos de una URL) cuyo TLD sea
# un TLD real conocido. Así se evitan clases .NET (Net.WebClient) y métodos
# (navigator.clipboard.writeText) que no son dominios.
_KNOWN_TLDS = {
    "com", "net", "org", "edu", "gov", "mil", "int", "io", "co", "uk", "de",
    "fr", "es", "it", "nl", "be", "ru", "cn", "jp", "kr", "in", "br", "au",
    "ca", "ch", "se", "no", "fi", "dk", "pl", "ua", "tr", "ir", "sa", "za",
    "mx", "ar", "cl", "us", "eu", "info", "biz", "me", "tv", "cc", "xyz",
    "top", "club", "online", "site", "website", "shop", "store", "app",
    "dev", "cloud", "live", "icu", "tk", "ml", "ga", "cf", "gq", "pw",
    "buzz", "link", "click", "rest", "monster", "quest", "sbs", "cyou",
    "uno", "fit", "work", "party", "science", "review", "stream", "download",
    "racing", "loan", "win", "bid", "men", "date", "faith", "cricket",
    "account", "pro", "name", "mobi", "asia", "cat", "jobs", "tel", "su",
    "ws", "to", "nu", "is", "li", "lt", "lv", "ee", "cz", "sk", "hu", "ro",
    "bg", "gr", "pt", "ie", "at", "by", "kz", "uz", "ge", "az", "am", "md",
    "rs", "hr", "si", "ba", "mk", "al", "mt", "cy", "lu", "id", "ph", "th",
    "vn", "my", "sg", "hk", "tw", "nz", "pe", "ve", "ec", "uy", "py", "bo",
}
_DENY_DOMAINS = {
    "system.io", "system.net", "system.text", "system.security",
    "system.diagnostics", "system.reflection", "system.management",
    "system.threading", "system.collections", "system.web",
    "microsoft.win32", "microsoft.powershell", "windows.system",
    "net.webclient", "net.webrequest", "navigator.clipboard",
}


# ── Utilidades internas ──────────────────────────────────────────────────────
def _safe_text(value: Any, limit: int = MAX_INPUT_CHARS) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    text = str(value)
    return text[:limit]


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return printable / len(text)


def _normalize_url(url: str) -> str:
    url = url.strip().rstrip(".,;)]}\"'")
    url = re.sub(r"hxxp", "http", url, flags=re.IGNORECASE)
    url = url.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":")
    url = url.replace("[", "").replace("]", "")
    return url


def _base64_decode_candidates(token: str) -> List[str]:
    """Decodifica un token Base64 como bytes y como UTF-16LE (típico de -enc)."""
    out: List[str] = []
    padded = token + "=" * (-len(token) % 4)
    try:
        raw = base64.b64decode(padded, validate=False)
    except (binascii.Error, ValueError):
        return out
    if not raw:
        return out
    for encoding in ("utf-16-le", "utf-8"):
        try:
            decoded = raw.decode(encoding)
        except (UnicodeDecodeError, ValueError):
            continue
        if _printable_ratio(decoded) >= 0.85 and len(decoded.strip()) >= 4:
            out.append(decoded)
    return out


def _decode_escapes(text: str) -> Optional[str]:
    if "\\x" not in text and "\\u" not in text:
        return None

    def _repl(match: "re.Match") -> str:
        hex_code = match.group(1) or match.group(2)
        try:
            return chr(int(hex_code, 16))
        except (ValueError, OverflowError):
            return match.group(0)

    return _ESCAPE_RE.sub(_repl, text)


def _join_concatenations(text: str) -> List[str]:
    joined: List[str] = []
    for match in _CONCAT_RE.finditer(text):
        parts = re.findall(r"'([^']*)'|\"([^\"]*)\"", match.group(0))
        value = "".join(a or b for a, b in parts)
        if len(value) >= 4:
            joined.append(value)
    return joined


def _expand_from_charcode(text: str) -> List[str]:
    out: List[str] = []
    for match in _FROMCHARCODE_RE.finditer(text):
        numbers = re.findall(r"[0-9]{1,4}", match.group(1))
        try:
            chars = "".join(chr(int(n)) for n in numbers if int(n) <= 0x10FFFF)
        except (ValueError, OverflowError):
            continue
        if chars and _printable_ratio(chars) >= 0.8:
            out.append(chars)
    return out


def _expand_atob(text: str) -> List[str]:
    out: List[str] = []
    for match in _ATOB_RE.finditer(text):
        out.extend(_base64_decode_candidates(match.group(2)))
    return out


def _decode_base64_tokens(text: str) -> List[str]:
    out: List[str] = []
    for match in _BASE64_TOKEN_RE.finditer(text):
        token = match.group(0)
        if len(token) < 20:
            continue
        out.extend(_base64_decode_candidates(token))
    return out


def _split_plus_terms(expr: str) -> List[str]:
    """Divide una expresión por '+' respetando el contenido entre comillas."""
    terms: List[str] = []
    buf: List[str] = []
    quote = None
    i = 0
    while i < len(expr):
        ch = expr[i]
        if quote:
            buf.append(ch)
            if ch == "\\" and i + 1 < len(expr):
                buf.append(expr[i + 1])
                i += 2
                continue
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in "'\"":
            quote = ch
            buf.append(ch)
            i += 1
            continue
        if ch == "+":
            terms.append("".join(buf).strip())
            buf = []
            i += 1
            continue
        buf.append(ch)
        i += 1
    terms.append("".join(buf).strip())
    return [term for term in terms if term]


def _resolve_expr(expr: str, symbols: Dict[str, str]) -> Optional[str]:
    """Resuelve una expresión JS de literales/variables conocidas."""
    expr = (expr or "").strip()
    if not expr or len(expr) > MAX_COMMAND_CHARS:
        return None
    parts: List[str] = []
    for term in _split_plus_terms(expr):
        literal = _LITERAL_RE.fullmatch(term)
        if literal:
            parts.append(literal.group(1) if literal.group(1) is not None
                         else literal.group(2))
            continue
        if _IDENT_RE.match(term):
            if term in symbols:
                parts.append(symbols[term])
                continue
            return None
        return None
    return "".join(parts)


def _collect_js_symbols(text: str):
    """Extrae variables string y arrays numéricos de un fragmento JS."""
    symbols: Dict[str, str] = {}
    arrays: Dict[str, List[int]] = {}

    for match in _JS_ARRAY_ASSIGN_RE.finditer(text):
        if len(arrays) >= _MAX_SYMBOLS:
            break
        numbers = re.findall(r"\d{1,5}", match.group(2))
        arrays[match.group(1)] = [int(n) for n in numbers]

    for _ in range(MAX_LAYERS):
        changed = False
        for match in _JS_ASSIGN_RE.finditer(text):
            if len(symbols) >= _MAX_SYMBOLS and match.group(1) not in symbols:
                break
            name, op, rhs = match.group(1), match.group(2), match.group(3)
            value = _resolve_expr(rhs, symbols)
            if value is None:
                continue
            new_value = symbols.get(name, "") + value if op == "+=" else value
            if symbols.get(name) != new_value:
                symbols[name] = new_value
                changed = True
        if not changed:
            break

    return symbols, arrays


def _reconstruct_expressions(
    text: str, symbols: Dict[str, str], arrays: Dict[str, List[int]]
) -> List[str]:
    """Reconstruye cadenas ensambladas con variables/arrays JS."""
    out: List[str] = []
    if not symbols and not arrays:
        return out

    for match in _JS_EXPR_RE.finditer(text):
        value = _resolve_expr(match.group(0), symbols)
        if value and len(value) >= 4:
            out.append(value)

    for match in _JS_FCC_ARRAY_RE.finditer(text):
        name = match.group(1) or match.group(2)
        codes = arrays.get(name)
        if not codes:
            continue
        try:
            chars = "".join(chr(c) for c in codes if c <= 0x10FFFF)
        except (ValueError, OverflowError):
            continue
        if chars and _printable_ratio(chars) >= 0.8:
            out.append(chars)

    for match in _JS_ATOB_VAR_RE.finditer(text):
        encoded = symbols.get(match.group(1))
        if encoded:
            out.extend(_base64_decode_candidates(encoded))

    return out


def _decode_powershell_chars(text: str) -> List[str]:
    """Decodifica secuencias [char]NN de PowerShell sin ejecutar."""
    out: List[str] = []
    for match in _PS_CHAR_SEQ_RE.finditer(text):
        codes = []
        for code in _PS_CHAR_CODE_RE.finditer(match.group(0)):
            raw = code.group(1)
            try:
                codes.append(int(raw, 16) if raw.lower().startswith("0x")
                             else int(raw))
            except ValueError:
                continue
        if codes:
            chars = "".join(chr(c) for c in codes if c <= 0x10FFFF)
            if chars and _printable_ratio(chars) >= 0.8:
                out.append(chars)

    for match in _PS_CHAR_ARRAY_RE.finditer(text):
        numbers = re.findall(r"\d{1,5}", match.group(1))
        try:
            chars = "".join(chr(int(n)) for n in numbers if int(n) <= 0x10FFFF)
        except (ValueError, OverflowError):
            continue
        if chars and _printable_ratio(chars) >= 0.8:
            out.append(chars)
    return out


def _has_string_assembly(text: str) -> bool:
    """True si se ensamblan cadenas con variables/arrays/[char] de forma real.

    Requiere que la reconstrucción estática produzca algo: así "Win+R" o una
    simple suma de números no cuentan como ensamblado de cadenas.
    """
    if _PS_CHAR_SEQ_RE.search(text) or _PS_CHAR_ARRAY_RE.search(text):
        return True
    symbols, arrays = _collect_js_symbols(text)
    if arrays and _JS_FCC_ARRAY_RE.search(text):
        return True
    if symbols:
        for match in _JS_EXPR_RE.finditer(text):
            if _resolve_expr(match.group(0), symbols):
                return True
    return False


def _derive(text: str) -> List[str]:
    derived: List[str] = []
    escaped = _decode_escapes(text)
    if escaped and escaped != text:
        derived.append(escaped)
    derived.extend(_join_concatenations(text))
    derived.extend(_expand_from_charcode(text))
    derived.extend(_expand_atob(text))
    derived.extend(_decode_base64_tokens(text))
    symbols, arrays = _collect_js_symbols(text)
    derived.extend(_reconstruct_expressions(text, symbols, arrays))
    derived.extend(_decode_powershell_chars(text))
    return derived


def deobfuscate_layers(text: str) -> List[str]:
    """Devuelve todas las cadenas derivadas por desofuscado (sin ejecutar)."""
    text = _safe_text(text)
    if not text:
        return []
    results: List[str] = []
    seen = {text}
    frontier = [text]
    for _ in range(MAX_LAYERS):
        next_frontier: List[str] = []
        for current in frontier:
            for derived in _derive(current):
                if len(derived) > MAX_COMMAND_CHARS:
                    continue
                if derived not in seen:
                    seen.add(derived)
                    results.append(derived)
                    next_frontier.append(derived)
        if not next_frontier:
            break
        frontier = next_frontier
    return results


def extract_indicators(text: str) -> Dict[str, List[str]]:
    """Extrae URLs, dominios e IPs de un texto (incluye variantes defang)."""
    text = _safe_text(text)
    indicators: Dict[str, List[str]] = {"urls": [], "domains": [], "ips": []}
    if not text:
        return indicators

    urls: List[str] = []
    for match in _URL_RE.finditer(text):
        url = _normalize_url(match.group(0))
        if url and url not in urls:
            urls.append(url)
    indicators["urls"] = urls[:MAX_INDICATORS]

    domains: List[str] = []
    for url in urls:
        host = re.sub(r"^[a-z]+://", "", url, flags=re.IGNORECASE).split("/")[0]
        host = host.split("@")[-1].split(":")[0].lower()
        if host and re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host) is None:
            if host not in domains:
                domains.append(host)
    for match in _DOMAIN_RE.finditer(text):
        domain = match.group(0).lower().rstrip(".")
        tld = domain.rsplit(".", 1)[-1]
        if tld not in _KNOWN_TLDS and not tld.startswith("xn--"):
            continue
        if domain in _DENY_DOMAINS:
            continue
        if domain in domains:
            continue
        domains.append(domain)
    indicators["domains"] = domains[:MAX_INDICATORS]

    ips: List[str] = []
    for match in _IPV4_RE.finditer(text):
        candidate = match.group(0)
        try:
            if str(ipaddress.ip_address(candidate)) == candidate and candidate not in ips:
                ips.append(candidate)
        except ValueError:
            continue
    for match in _IPV6_RE.finditer(text):
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
            if candidate not in ips:
                ips.append(candidate)
        except ValueError:
            continue
    indicators["ips"] = ips[:MAX_INDICATORS]
    return indicators


# ── Recolección de candidatos ────────────────────────────────────────────────
def _collect_candidates(
    html_raw: str,
    body_text: str,
    html_attachments: Optional[List[Dict[str, str]]] = None,
) -> List[str]:
    candidates: List[str] = []

    def _add(value: Optional[str]) -> None:
        value = _safe_text(value)
        if value and len(value) <= MAX_COMMAND_CHARS and value not in candidates:
            candidates.append(value)

    if html_raw:
        for match in re.finditer(
            r"<(?:script|pre|code|textarea)[^>]*>(.*?)</(?:script|pre|code|textarea)>",
            html_raw,
            re.DOTALL | re.IGNORECASE,
        ):
            _add(match.group(1))
        for match in re.finditer(
            r"(?:value|data-[\w-]+|on\w+)\s*=\s*([\"'])(.*?)\1",
            html_raw,
            re.DOTALL | re.IGNORECASE,
        ):
            _add(match.group(2))
        _add(html_raw)

    if body_text:
        _add(body_text)

    for attachment in html_attachments or []:
        if isinstance(attachment, dict):
            _add(attachment.get("content", ""))

    return candidates[:MAX_CANDIDATES]


# ── API pública ──────────────────────────────────────────────────────────────
def analyze_clickfix(
    html_raw: str = "",
    body_text: str = "",
    html_attachments: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    """Analiza un correo en busca de ClickFix y extrae sus indicadores."""
    result: Dict[str, Any] = {
        "clickfix_detected": False,
        "high_confidence": False,
        "clickfix_score": 0.0,
        "clickfix_threshold": 0.5,
        "techniques": [],
        "clipboard_apis": [],
        "lure_phrases": [],
        "raw_commands": [],
        "decoded_commands": [],
        "payload_urls": [],
        "payload_domains": [],
        "payload_ips": [],
        "source_attachments": [],
        "obfuscation_layers": 0,
        "preview": "",
    }
    try:
        html_raw = _safe_text(html_raw)
        body_text = _safe_text(body_text)

        combined = "\n".join(
            [html_raw, body_text]
            + [a.get("content", "") for a in (html_attachments or [])
               if isinstance(a, dict)]
        )
        if not combined.strip():
            return result

        techniques: List[str] = []
        clipboard_apis: List[str] = []
        for match in _CLIPBOARD_API_RE.finditer(combined):
            token = match.group(0).strip()
            if token not in clipboard_apis:
                clipboard_apis.append(token)
        if clipboard_apis:
            techniques.append("clipboard_api")
        if _EXEC_COPY_RE.search(combined):
            techniques.append("exec_command_copy")
        if _HIDDEN_COPY_RE.search(combined) and _SELECT_COPY_RE.search(combined):
            techniques.append("hidden_copy_widget")
        if _ENCODED_RE.search(combined):
            techniques.append("encoded_command")
        if _FROMCHARCODE_RE.search(combined):
            techniques.append("fromcharcode")
        if _ATOB_RE.search(combined):
            techniques.append("atob")

        lure_phrases: List[str] = []
        for regex in _LURE_RES:
            match = regex.search(combined)
            if match:
                phrase = match.group(0).strip()
                if phrase and phrase.lower() not in [p.lower() for p in lure_phrases]:
                    lure_phrases.append(phrase)

        has_win_r = bool(_WIN_R_RE.search(combined))
        has_powershell = bool(re.search(r"powershell(?:\.exe)?", combined, re.IGNORECASE))
        has_encoded = "encoded_command" in techniques
        has_base64 = bool(_BASE64_TOKEN_RE.search(combined))

        candidates = _collect_candidates(html_raw, body_text, html_attachments)

        raw_commands: List[str] = []
        decoded_commands: List[str] = []
        max_layers = 0
        indicator_pool: List[str] = []
        assembly_detected = False

        for candidate in candidates:
            if _COMMAND_RE.search(candidate):
                raw_commands.append(candidate[:MAX_COMMAND_CHARS])
                indicator_pool.append(candidate)
            if not assembly_detected and _has_string_assembly(candidate):
                assembly_detected = True
            layers = deobfuscate_layers(candidate)
            max_layers = max(max_layers, len(layers))
            for layer in layers:
                if _COMMAND_RE.search(layer) or _URL_RE.search(layer):
                    if layer not in decoded_commands:
                        decoded_commands.append(layer[:MAX_COMMAND_CHARS])
                indicator_pool.append(layer)

        indicators = extract_indicators("\n".join(indicator_pool))

        if decoded_commands:
            techniques.append("deobfuscated_command")
        if assembly_detected:
            techniques.append("string_assembly")

        score = 0.0
        if clipboard_apis:
            score += 0.35
        if "exec_command_copy" in techniques:
            score += 0.25
        if "hidden_copy_widget" in techniques:
            score += 0.20
        if lure_phrases:
            score += 0.20
        if raw_commands:
            score += 0.25
        if decoded_commands:
            score += 0.15
        if has_win_r:
            score += 0.15
        if has_encoded:
            score += 0.10
        if "string_assembly" in techniques:
            score += 0.15
        if lure_phrases and (clipboard_apis or "exec_command_copy" in techniques):
            score += 0.15
        score = round(min(score, 1.0), 4)

        detected = score >= 0.5
        ui_vector = bool(
            clipboard_apis
            or "exec_command_copy" in techniques
            or "hidden_copy_widget" in techniques
            or has_win_r
            or lure_phrases
        )
        has_command = bool(raw_commands or decoded_commands)
        has_payload = bool(
            indicators["urls"] or indicators["domains"] or indicators["ips"]
        )
        # Alta confianza: interacción de la víctima (clipboard/Win+R/señuelo)
        # + comando, o un comando codificado con indicadores extraídos.
        high_confidence = bool(
            detected
            and has_command
            and (
                (ui_vector and (has_payload or has_encoded))
                or (has_encoded and has_payload)
            )
        )

        source_attachments: List[str] = []
        for attachment in html_attachments or []:
            if isinstance(attachment, dict) and _COMMAND_RE.search(
                attachment.get("content", "")
            ):
                name = attachment.get("filename", "")
                if name and name not in source_attachments:
                    source_attachments.append(name)

        preview = ""
        if decoded_commands or raw_commands:
            preview = (decoded_commands or raw_commands)[0][:400]

        result.update({
            "clickfix_detected": detected,
            "high_confidence": high_confidence,
            "clickfix_score": score,
            "techniques": techniques,
            "clipboard_apis": clipboard_apis[:MAX_COMMANDS],
            "lure_phrases": lure_phrases[:MAX_COMMANDS],
            "raw_commands": raw_commands[:MAX_COMMANDS],
            "decoded_commands": decoded_commands[:MAX_COMMANDS],
            "payload_urls": indicators["urls"],
            "payload_domains": indicators["domains"],
            "payload_ips": indicators["ips"],
            "source_attachments": source_attachments,
            "obfuscation_layers": max_layers,
            "preview": preview,
            "has_powershell": has_powershell,
            "has_win_r": has_win_r,
            "has_encoded_command": has_encoded,
            "has_base64": has_base64,
        })
    except Exception:
        return result
    return result


def extract_clickfix_features(result: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Convierte el resultado de analyze_clickfix en features numéricas.

    Las claves usan el prefijo ``clanker_`` para que los entrenadores del
    Modelo 10 (Anti-Clanker) las recojan automáticamente.
    """
    result = result or {}
    payload_urls = result.get("payload_urls") or []
    payload_domains = result.get("payload_domains") or []
    payload_ips = result.get("payload_ips") or []
    raw_commands = result.get("raw_commands") or []
    decoded_commands = result.get("decoded_commands") or []
    return {
        "clanker_clickfix_detected": 1 if result.get("clickfix_detected") else 0,
        "clanker_clickfix_high_confidence": 1 if result.get("high_confidence") else 0,
        "clanker_clickfix_score": round(float(result.get("clickfix_score", 0.0)), 4),
        "clanker_clickfix_clipboard_api_count": len(result.get("clipboard_apis") or []),
        "clanker_clickfix_lure_phrase_count": len(result.get("lure_phrases") or []),
        "clanker_clickfix_raw_command_count": len(raw_commands),
        "clanker_clickfix_decoded_command_count": len(decoded_commands),
        "clanker_clickfix_payload_url_count": len(payload_urls),
        "clanker_clickfix_payload_domain_count": len(payload_domains),
        "clanker_clickfix_payload_ip_count": len(payload_ips),
        "clanker_clickfix_obfuscation_layers": int(result.get("obfuscation_layers", 0)),
        "clanker_clickfix_has_win_r": 1 if result.get("has_win_r") else 0,
        "clanker_clickfix_has_encoded_command": 1 if result.get("has_encoded_command") else 0,
        "clanker_clickfix_has_base64": 1 if result.get("has_base64") else 0,
        "clanker_clickfix_has_powershell": 1 if result.get("has_powershell") else 0,
    }


def get_clickfix_score(
    html_raw: str = "", body_text: str = "",
    html_attachments: Optional[List[Dict[str, str]]] = None,
) -> float:
    """Devuelve solo el score ClickFix normalizado [0, 1]."""
    return analyze_clickfix(html_raw, body_text, html_attachments).get(
        "clickfix_score", 0.0
    )


if __name__ == "__main__":
    import json

    source = sys.argv[1] if len(sys.argv) > 1 else ""
    if source and not source.lstrip().startswith("<") and "\n" not in source:
        try:
            with open(source, "r", encoding="utf-8", errors="ignore") as fh:
                source = fh.read()
        except OSError:
            pass
    if not source:
        source = (
            "<html><body><h3>Verify you are human</h3>"
            "<p>Press Win+R and paste the command:</p>"
            "<pre>powershell -enc "
            "VwByAGkAdABlAC0ASABvAHMAdAAgACcAUABPAEMAIABjAGwAaQBjAGsAZgBpAHgA"
            "JwA=</pre></body></html>"
        )
    print(json.dumps(analyze_clickfix(source), indent=2, ensure_ascii=False))
