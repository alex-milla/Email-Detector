#!/usr/bin/env python3
"""edl_manager.py — Gestión de External Dynamic Lists (EDL).

Descarga, valida e indexa listas externas de indicadores maliciosos
(URLs, dominios e IPs) para consultarlas localmente y con rapidez durante
el análisis de correo.

Los tres espacios de indicadores son independientes:

* URL     -> coincidencia exacta de URL normalizada.
* DOMAIN  -> coincidencia exacta y por subdominios.
* IP      -> coincidencia exacta y por rangos CIDR.

Una entrada de una lista nunca se expande a otro espacio: una URL no
bloquea su dominio ni una IP bloquea el dominio que resuelve. Esto evita
falsos positivos sobre dominios legítimos comprometidos.
"""

import os
import re
import glob
import json
import time
import shutil
import socket
import hashlib
import logging
import ipaddress
from datetime import datetime, timezone, timedelta
from urllib.parse import urlparse, urljoin

log = logging.getLogger(__name__)

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
EDL_DIR = os.path.join(PROJECT_DIR, "config", "edl")
REGISTRY_FILE = os.path.join(EDL_DIR, "lists.json")
LOCK_FILE = os.path.join(EDL_DIR, ".sync.lock")

BACKUP_KEEP = 3
DEFAULT_INTERVAL_H = 6
CACHE_TTL = 300
MAX_REDIRECTS = 5
HTTP_TIMEOUT = 30
MAX_LINE_LEN = 4096
DEFAULT_MAX_FILE_MB = 50.0
DEFAULT_MAX_ENTRIES = 1_000_000

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)
_IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
_IPV6_BRACKET_RE = re.compile(r"\[([0-9a-fA-F:]{2,45})\]")

_DEFANG_PATTERNS = (
    (re.compile(r"hxxps", re.I), "https"),
    (re.compile(r"hxxp", re.I), "http"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\{\.\}"), "."),
    (re.compile(r"\[dot\]", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[at\]", re.I), "@"),
)

_HOSTS_TOKENS = ("0.0.0.0", "127.0.0.1", "::1", "255.255.255.255", "0")


# ── Utilidades básicas ────────────────────────────────────────────────────────
def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _parse_iso(value):
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except (ValueError, TypeError):
        return None


def _undefang(value):
    text = str(value or "")
    for pattern, repl in _DEFANG_PATTERNS:
        text = pattern.sub(repl, text)
    return text


def _ensure_dir():
    os.makedirs(EDL_DIR, exist_ok=True)


def _max_file_bytes():
    try:
        mb = float(os.getenv("EDL_MAX_FILE_MB", str(DEFAULT_MAX_FILE_MB)))
    except (TypeError, ValueError):
        mb = DEFAULT_MAX_FILE_MB
    return int(max(1.0, mb) * 1024 * 1024)


def _max_entries():
    try:
        return max(1, int(os.getenv("EDL_MAX_ENTRIES", str(DEFAULT_MAX_ENTRIES))))
    except (TypeError, ValueError):
        return DEFAULT_MAX_ENTRIES


def _received_ips_enabled():
    val = os.getenv("EDL_CHECK_RECEIVED_IPS", "true").strip().lower()
    return val not in ("false", "0", "no", "off")


def _is_safe_host(host):
    """Bloquea hosts que resuelven a direcciones privadas/loopback (SSRF)."""
    if not host:
        return False
    if host.strip().lower() in ("localhost", "localhost.localdomain"):
        return False
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return True
    for info in infos:
        addr = info[4][0]
        if "%" in addr:
            addr = addr.split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if (ip.is_private or ip.is_loopback or ip.is_link_local
                or ip.is_reserved or ip.is_multicast or ip.is_unspecified):
            return False
    return True


def validate_url(url):
    """Valida que la URL use HTTPS, tenga host y no apunte a una IP interna."""
    if not url or not isinstance(url, str):
        return False
    parsed = urlparse(url.strip())
    if parsed.scheme != "https" or not parsed.hostname:
        return False
    return _is_safe_host(parsed.hostname)


# ── Normalización y clasificación de indicadores ──────────────────────────────
def _normalize_domain(value):
    domain = _undefang(value).strip().lower().rstrip(".")
    if domain.startswith("*."):
        domain = domain[2:]
    elif domain.startswith("."):
        domain = domain[1:]
    return domain


def _normalize_url(value):
    raw = _undefang(value).strip()
    try:
        parsed = urlparse(raw)
    except ValueError:
        return None
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return None
    scheme = parsed.scheme.lower()
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = "[" + host + "]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        port = None
    netloc = host if port is None else f"{host}:{port}"
    url = f"{scheme}://{netloc}{parsed.path}"
    if parsed.query:
        url += "?" + parsed.query
    return url


def _classify(token):
    text = _undefang(token).strip()
    if not text:
        return (None, None)
    if text.lower().startswith(("http://", "https://")):
        url = _normalize_url(text)
        return ("url", url) if url else (None, None)
    try:
        if "/" in text:
            net = ipaddress.ip_network(text, strict=False)
            return ("network", net.with_prefixlen)
        ip = ipaddress.ip_address(text)
        return ("ip", str(ip))
    except ValueError:
        pass
    domain = _normalize_domain(text)
    if domain and _DOMAIN_RE.match(domain):
        return ("domain", domain)
    return (None, None)


def detect_and_parse(raw):
    """Clasifica cada línea de una lista externa en URL, dominio o IP/CIDR.

    Soporta lista plana, formato hosts (0.0.0.0 dominio), comentarios con
    ``#``/``;``/``//``, comentarios inline y ofuscación (hxxp, [.]).
    """
    if isinstance(raw, bytes):
        text = raw.decode("utf-8", errors="replace")
    else:
        text = str(raw or "")
    if text and text[0] == "\ufeff":
        text = text[1:]

    urls, domains, ips, networks = set(), set(), set(), set()
    invalid = 0
    lines = 0

    for line in text.splitlines():
        lines += 1
        stripped = line.strip()
        if not stripped or stripped[0] in "#;":
            continue
        if stripped.startswith("//"):
            continue
        for marker in (" #", "\t#", " ;"):
            idx = stripped.find(marker)
            if idx > 0:
                stripped = stripped[:idx]
                break
        stripped = stripped.strip()
        if not stripped:
            continue
        if len(stripped) > MAX_LINE_LEN:
            invalid += 1
            continue

        tokens = stripped.split()
        if len(tokens) >= 2 and tokens[0] in _HOSTS_TOKENS:
            candidate = tokens[1]
        else:
            candidate = tokens[0]
        candidate = candidate.strip().strip('"').strip("'").rstrip(",")
        if not candidate:
            continue

        kind, value = _classify(candidate)
        if kind == "url":
            urls.add(value)
        elif kind == "domain":
            domains.add(value)
        elif kind == "ip":
            ips.add(value)
        elif kind == "network":
            networks.add(value)
        else:
            invalid += 1

    total_ips = len(ips) + len(networks)
    populated = sum(1 for c in (len(urls), len(domains), total_ips) if c)
    if populated > 1:
        kind = "mixed"
    elif urls:
        kind = "url"
    elif domains:
        kind = "domain"
    elif total_ips:
        kind = "ip"
    else:
        kind = "empty"

    return {
        "urls": sorted(urls),
        "domains": sorted(domains),
        "ips": sorted(ips),
        "networks": sorted(networks),
        "counts": {"urls": len(urls), "domains": len(domains), "ips": total_ips},
        "kind": kind,
        "invalid": invalid,
        "lines": lines,
    }


def _entry_total(parsed):
    return (len(parsed["urls"]) + len(parsed["domains"])
            + len(parsed["ips"]) + len(parsed["networks"]))


# ── Registro de listas ────────────────────────────────────────────────────────
def _default_registry():
    return {
        "version": 1,
        "schedule": {
            "auto_enabled": False,
            "default_interval_h": DEFAULT_INTERVAL_H,
        },
        "lists": [],
    }


def load_registry():
    _ensure_dir()
    if not os.path.exists(REGISTRY_FILE):
        return _default_registry()
    try:
        with open(REGISTRY_FILE, encoding="utf-8") as f:
            data = json.load(f)
    except (ValueError, OSError):
        return _default_registry()
    if not isinstance(data, dict):
        return _default_registry()
    data.setdefault("version", 1)
    schedule = data.get("schedule")
    if not isinstance(schedule, dict):
        schedule = {}
    schedule.setdefault("auto_enabled", False)
    schedule.setdefault("default_interval_h", DEFAULT_INTERVAL_H)
    data["schedule"] = schedule
    if not isinstance(data.get("lists"), list):
        data["lists"] = []
    return data


def save_registry(data):
    _ensure_dir()
    tmp = REGISTRY_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, REGISTRY_FILE)


def _find_entry(registry, list_id):
    for entry in registry.get("lists", []):
        if entry.get("id") == list_id:
            return entry
    return None


def _slugify(text):
    slug = re.sub(r"[^a-z0-9]+", "_", str(text or "").lower()).strip("_")
    return slug or "lista"


def _unique_id(registry, base):
    existing = {e.get("id") for e in registry.get("lists", [])}
    if base not in existing:
        return base
    idx = 2
    while f"{base}_{idx}" in existing:
        idx += 1
    return f"{base}_{idx}"


def add_list(name, url, interval_h=None, headers=None):
    """Añade una lista al registro. Lanza ValueError si los datos son inválidos."""
    name = str(name or "").strip()
    url = str(url or "").strip()
    if not name:
        raise ValueError("El nombre es obligatorio")
    if not validate_url(url):
        raise ValueError("La URL debe usar HTTPS y apuntar a un host válido")
    registry = load_registry()
    if any(str(e.get("url", "")).strip().lower() == url.lower()
           for e in registry.get("lists", [])):
        raise ValueError("Ya existe una lista con esa URL")
    list_id = _unique_id(registry, _slugify(name))
    entry = {
        "id": list_id,
        "name": name,
        "url": url,
        "enabled": True,
        "interval_h": float(interval_h) if interval_h else None,
        "headers": dict(headers) if headers else {},
        "added_at": _now_iso(),
        "last_sync": None,
        "last_status": "never",
        "last_error": "",
        "entries": 0,
        "counts": {"urls": 0, "domains": 0, "ips": 0},
        "kind": "unknown",
        "sha256": "",
        "file": f"{list_id}.list",
    }
    registry["lists"].append(entry)
    save_registry(registry)
    return entry


def update_list(list_id, name=None, url=None, interval_h=None):
    registry = load_registry()
    entry = _find_entry(registry, list_id)
    if not entry:
        raise ValueError("Lista no encontrada")
    if name is not None:
        name = str(name).strip()
        if not name:
            raise ValueError("El nombre no puede estar vacío")
        entry["name"] = name
    if url is not None:
        url = str(url).strip()
        if not validate_url(url):
            raise ValueError("La URL debe usar HTTPS y apuntar a un host válido")
        entry["url"] = url
    if interval_h is not None:
        try:
            value = float(interval_h)
        except (TypeError, ValueError):
            raise ValueError("Intervalo inválido")
        entry["interval_h"] = value if value > 0 else None
    save_registry(registry)
    invalidate_index()
    return entry


def toggle_list(list_id):
    registry = load_registry()
    entry = _find_entry(registry, list_id)
    if not entry:
        raise ValueError("Lista no encontrada")
    entry["enabled"] = not entry.get("enabled", True)
    save_registry(registry)
    invalidate_index()
    return entry


def remove_list(list_id):
    registry = load_registry()
    entry = _find_entry(registry, list_id)
    if not entry:
        raise ValueError("Lista no encontrada")
    registry["lists"] = [e for e in registry["lists"] if e.get("id") != list_id]
    save_registry(registry)
    path = os.path.join(EDL_DIR, entry.get("file") or f"{list_id}.list")
    for candidate in [path] + sorted(glob.glob(path + ".bak_*")):
        try:
            os.remove(candidate)
        except OSError:
            pass
    invalidate_index()
    return entry


def set_schedule(auto_enabled=None, default_interval_h=None):
    registry = load_registry()
    schedule = registry["schedule"]
    if auto_enabled is not None:
        schedule["auto_enabled"] = bool(auto_enabled)
    if default_interval_h is not None:
        try:
            value = float(default_interval_h)
        except (TypeError, ValueError):
            raise ValueError("Intervalo inválido")
        schedule["default_interval_h"] = value if value > 0 else DEFAULT_INTERVAL_H
    save_registry(registry)
    return schedule


def _effective_interval(entry, schedule):
    value = entry.get("interval_h") or schedule.get("default_interval_h") or DEFAULT_INTERVAL_H
    try:
        return max(0.25, float(value))
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL_H


def _next_run(entry, schedule):
    if not entry.get("enabled", True):
        return None
    last = _parse_iso(entry.get("last_sync"))
    if last is None:
        return None
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    return (last + timedelta(hours=_effective_interval(entry, schedule))).isoformat()


def list_is_due(entry, schedule, now=None):
    if not entry.get("enabled", True):
        return False
    if not schedule.get("auto_enabled"):
        return False
    last = _parse_iso(entry.get("last_sync"))
    if last is None:
        return True
    if last.tzinfo is None:
        last = last.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    delta = (now - last).total_seconds()
    return delta >= _effective_interval(entry, schedule) * 3600


def schedule_info():
    registry = load_registry()
    schedule = registry["schedule"]
    return {
        "auto_enabled": schedule.get("auto_enabled", False),
        "default_interval_h": schedule.get("default_interval_h", DEFAULT_INTERVAL_H),
    }


def get_public_lists():
    registry = load_registry()
    schedule = registry["schedule"]
    result = []
    for entry in registry.get("lists", []):
        item = {k: v for k, v in entry.items() if k != "headers"}
        item["has_headers"] = bool(entry.get("headers"))
        item["next_run"] = _next_run(entry, schedule)
        result.append(item)
    return result


# ── Descarga ──────────────────────────────────────────────────────────────────
def _download(url, headers=None):
    import requests

    if not validate_url(url):
        raise ValueError("URL rechazada: se requiere HTTPS y host no interno")

    max_bytes = _max_file_bytes()
    session = requests.Session()
    current = url
    for _ in range(MAX_REDIRECTS + 1):
        parsed = urlparse(current)
        if parsed.scheme != "https":
            raise ValueError("Redirección a HTTP no permitida")
        if not _is_safe_host(parsed.hostname):
            raise ValueError("Host no permitido (posible SSRF)")
        resp = session.get(
            current, headers=headers or {}, stream=True,
            timeout=HTTP_TIMEOUT, allow_redirects=False,
        )
        try:
            if resp.status_code in (301, 302, 303, 307, 308):
                location = resp.headers.get("Location")
                if not location:
                    raise ValueError("Redirección sin cabecera Location")
                current = urljoin(current, location)
                continue
            if resp.status_code >= 400:
                raise ValueError(f"HTTP {resp.status_code}")
            chunks = []
            total = 0
            for chunk in resp.iter_content(65536):
                if not chunk:
                    continue
                total += len(chunk)
                if total > max_bytes:
                    raise ValueError(f"La lista supera {max_bytes // (1024 * 1024)} MB")
                chunks.append(chunk)
            return b"".join(chunks)
        finally:
            resp.close()
    raise ValueError("Demasiadas redirecciones")


def preview_url(url, headers=None):
    """Descarga y analiza una URL sin guardarla. Devuelve recuentos."""
    raw = _download(url, headers)
    parsed = detect_and_parse(raw)
    total = _entry_total(parsed)
    if total > _max_entries():
        raise ValueError(f"La lista supera el máximo de {_max_entries()} entradas")
    return {
        "kind": parsed["kind"],
        "counts": parsed["counts"],
        "entries": total,
        "bytes": len(raw),
    }


# ── Índice en memoria ─────────────────────────────────────────────────────────
class EdlIndex:
    def __init__(self):
        self.enabled = False
        self.maps = {"url": {}, "domain": {}, "ip": {}}
        self.networks = []
        self.list_names = {}

    def _register(self, kind, value, list_id, list_name):
        self.maps[kind].setdefault(value, [])
        self.maps[kind][value].append((list_id, list_name))

    def add_entry(self, list_id, list_name, parsed):
        self.list_names[list_id] = list_name
        for url in parsed["urls"]:
            self._register("url", url, list_id, list_name)
        for domain in parsed["domains"]:
            self._register("domain", domain, list_id, list_name)
        for ip in parsed["ips"]:
            self._register("ip", ip, list_id, list_name)
        for net in parsed["networks"]:
            try:
                self.networks.append((ipaddress.ip_network(net), list_id, list_name))
            except ValueError:
                continue
        if (parsed["urls"] or parsed["domains"] or parsed["ips"]
                or parsed["networks"]):
            self.enabled = True

    def match_url(self, value):
        norm = _normalize_url(value) or str(value or "").strip()
        return [{"list_id": lid, "list_name": name}
                for lid, name in self.maps["url"].get(norm, [])]

    def match_domain(self, host):
        domain = _normalize_domain(host)
        if not domain or "." not in domain:
            return []
        matches = []
        parts = domain.split(".")
        for i in range(len(parts) - 1):
            suffix = ".".join(parts[i:])
            for lid, name in self.maps["domain"].get(suffix, []):
                matches.append({"list_id": lid, "list_name": name, "matched": suffix})
        return matches

    def match_ip(self, value):
        try:
            ip = ipaddress.ip_address(str(value or "").strip())
        except ValueError:
            return []
        matches = []
        for lid, name in self.maps["ip"].get(str(ip), []):
            matches.append({"list_id": lid, "list_name": name, "matched": str(ip)})
        for network, lid, name in self.networks:
            if ip in network:
                matches.append({"list_id": lid, "list_name": name,
                                "matched": str(network)})
        return matches


_INDEX_CACHE = {"sig": None, "ts": 0.0, "index": None}


def _index_signature(registry):
    parts = []
    for entry in registry.get("lists", []):
        if not entry.get("enabled", True):
            continue
        path = os.path.join(EDL_DIR, entry.get("file") or f"{entry['id']}.list")
        try:
            st = os.stat(path)
            parts.append((entry.get("id"), st.st_mtime_ns, st.st_size))
        except OSError:
            parts.append((entry.get("id"), None, None))
    return tuple(parts)


def _build_index(registry):
    index = EdlIndex()
    for entry in registry.get("lists", []):
        if not entry.get("enabled", True):
            continue
        path = os.path.join(EDL_DIR, entry.get("file") or f"{entry['id']}.list")
        if not os.path.exists(path):
            continue
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                parsed = detect_and_parse(f.read())
        except OSError:
            continue
        index.add_entry(entry.get("id"), entry.get("name") or entry.get("id"), parsed)
    return index


def load_index(force=False):
    registry = load_registry()
    signature = _index_signature(registry)
    now = time.time()
    cached = _INDEX_CACHE
    if (not force and cached["index"] is not None
            and cached["sig"] == signature and (now - cached["ts"]) < CACHE_TTL):
        return cached["index"]
    index = _build_index(registry)
    cached["sig"] = signature
    cached["ts"] = now
    cached["index"] = index
    return index


def invalidate_index():
    _INDEX_CACHE["sig"] = None
    _INDEX_CACHE["ts"] = 0.0
    _INDEX_CACHE["index"] = None


# ── Matching sobre metadatos de un correo ─────────────────────────────────────
def _host_of(value):
    try:
        return urlparse(value).hostname
    except (ValueError, AttributeError):
        return None


def _extract_received_ips(raw_headers):
    if not _received_ips_enabled():
        return []
    found = []
    received = (raw_headers or {}).get("Received") or []
    if isinstance(received, str):
        received = [received]
    for header in received:
        text = str(header)
        for match in _IPV6_BRACKET_RE.finditer(text):
            try:
                ip = ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            if str(ip) not in found:
                found.append(str(ip))
        for match in _IPV4_RE.finditer(text):
            try:
                ip = ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            if str(ip) not in found:
                found.append(str(ip))
    return found


def _match_namespace(index, kind, value, source):
    if kind == "url":
        found = index.match_url(value)
    elif kind == "domain":
        found = index.match_domain(value)
    elif kind == "ip":
        found = index.match_ip(value)
    else:
        return []
    return [{"indicator": value, "kind": kind, "source": source, **item}
            for item in found]


def edl_enabled():
    val = os.getenv("EDL_ENABLED", "true").strip().lower()
    return val not in ("false", "0", "no", "off")


def match_email_indicators(meta):
    """Busca los indicadores del correo en el índice EDL cargado."""
    if not edl_enabled():
        return {"enabled": False, "count": 0, "matches": []}
    try:
        index = load_index()
    except Exception as exc:  # pragma: no cover - salvaguarda
        return {"enabled": False, "count": 0, "matches": [], "error": str(exc)}
    if not index.enabled:
        return {"enabled": False, "count": 0, "matches": []}

    matches = []
    seen = set()

    def add(kind, value, source):
        for item in _match_namespace(index, kind, value, source):
            key = (item["kind"], item["indicator"], item["list_id"], item["source"])
            if key in seen:
                continue
            seen.add(key)
            matches.append(item)

    for url in meta.get("urls_found") or []:
        add("url", url, "url")
        host = _host_of(url)
        if host:
            add("ip" if _is_ip_literal(host) else "domain", host, "url_host")

    clickfix = meta.get("clickfix") or {}
    for url in clickfix.get("payload_urls") or []:
        add("url", url, "clickfix_url")
        host = _host_of(url)
        if host:
            add("ip" if _is_ip_literal(host) else "domain", host, "clickfix_url_host")
    for domain in clickfix.get("payload_domains") or []:
        add("domain", domain, "clickfix_domain")
    for ip in clickfix.get("payload_ips") or []:
        add("ip", ip, "clickfix_ip")

    for ip in _extract_received_ips(meta.get("raw_headers")):
        add("ip", ip, "received")

    return {"enabled": True, "count": len(matches), "matches": matches}


def _is_ip_literal(value):
    try:
        ipaddress.ip_address(str(value).strip().strip("[]"))
        return True
    except ValueError:
        return False


# ── Sincronización ────────────────────────────────────────────────────────────
def _create_backup(path, keep=BACKUP_KEEP):
    if not os.path.exists(path):
        return None
    backup = f"{path}.bak_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}"
    try:
        shutil.copy2(path, backup)
    except OSError:
        return None
    backups = sorted(glob.glob(path + ".bak_*"))
    stale = backups if keep <= 0 else backups[:-keep]
    for old in stale:
        try:
            os.remove(old)
        except OSError:
            pass
    return backup


def _acquire_lock():
    _ensure_dir()
    try:
        fd = os.open(LOCK_FILE, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        os.write(fd, str(os.getpid()).encode())
        os.close(fd)
        return True
    except FileExistsError:
        try:
            if time.time() - os.path.getmtime(LOCK_FILE) > 3600:
                os.remove(LOCK_FILE)
                return _acquire_lock()
        except OSError:
            pass
        return False
    except OSError:
        return False


def _release_lock():
    try:
        os.remove(LOCK_FILE)
    except OSError:
        pass


def _sync_list_impl(list_id):
    registry = load_registry()
    entry = _find_entry(registry, list_id)
    if not entry:
        return {"success": False, "list_id": list_id, "error": "Lista no encontrada"}
    if not entry.get("enabled", True):
        return {"success": False, "list_id": list_id, "error": "Lista deshabilitada"}
    url = entry.get("url", "")
    if not validate_url(url):
        entry["last_status"] = "error"
        entry["last_error"] = "URL no HTTPS o host no permitido"
        save_registry(registry)
        return {"success": False, "list_id": list_id, "error": entry["last_error"]}

    try:
        raw = _download(url, entry.get("headers") or {})
        parsed = detect_and_parse(raw)
        total = _entry_total(parsed)
        if total == 0:
            raise ValueError("La lista no contiene indicadores válidos")
        if total > _max_entries():
            raise ValueError(f"La lista supera el máximo de {_max_entries()} entradas")
    except Exception as exc:
        entry["last_status"] = "error"
        entry["last_error"] = str(exc)[:300]
        save_registry(registry)
        return {"success": False, "list_id": list_id, "error": str(exc)}

    path = os.path.join(EDL_DIR, entry.get("file") or f"{list_id}.list")
    backup = _create_backup(path)
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            if isinstance(raw, bytes):
                f.write(raw.decode("utf-8", errors="replace"))
            else:
                f.write(str(raw))
        with open(tmp, encoding="utf-8", errors="replace") as f:
            recheck = detect_and_parse(f.read())
        if _entry_total(recheck) == 0:
            raise ValueError("Verificación post-escritura fallida")
        os.replace(tmp, path)
    except Exception as exc:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass
        if backup:
            try:
                shutil.copy2(backup, path)
            except OSError:
                pass
        entry["last_status"] = "error"
        entry["last_error"] = f"escritura: {exc}"[:300]
        save_registry(registry)
        return {"success": False, "list_id": list_id, "error": str(exc)}

    raw_bytes = raw if isinstance(raw, bytes) else str(raw).encode("utf-8")
    entry.update({
        "last_sync": _now_iso(),
        "last_status": "ok",
        "last_error": "",
        "entries": total,
        "counts": parsed["counts"],
        "kind": parsed["kind"],
        "sha256": hashlib.sha256(raw_bytes).hexdigest(),
    })
    save_registry(registry)
    invalidate_index()
    return {
        "success": True, "list_id": list_id, "name": entry.get("name"),
        "entries": total, "counts": parsed["counts"], "kind": parsed["kind"],
    }


def _sync_lists(entries):
    results = []
    for entry in entries:
        results.append(_sync_list_impl(entry.get("id")))
    synced = [r for r in results if r.get("success")]
    failed = [r for r in results if not r.get("success")]
    return {
        "success": not failed,
        "total": len(results),
        "synced": len(synced),
        "failed": len(failed),
        "entries": sum(r.get("entries", 0) for r in synced),
        "results": results,
    }


def _enabled_entries():
    registry = load_registry()
    return [e for e in registry.get("lists", []) if e.get("enabled", True)]


def _due_entries():
    registry = load_registry()
    schedule = registry["schedule"]
    now = datetime.now(timezone.utc)
    return [e for e in registry.get("lists", []) if list_is_due(e, schedule, now)]


def _run_locked(fn, *args, **kwargs):
    if not _acquire_lock():
        return {"success": False, "error": "Sincronización en curso", "busy": True}
    try:
        return fn(*args, **kwargs)
    finally:
        _release_lock()


def sync_list(list_id):
    return _run_locked(_sync_list_impl, list_id)


def sync_all():
    return _run_locked(_sync_lists, _enabled_entries())


def sync_due():
    return _run_locked(_sync_lists, _due_entries())
