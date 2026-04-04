"""clamav_scanner.py — Wrapper ClamAV para Email Malware Detector."""
import os, time, subprocess, logging
from datetime import datetime, timezone, timedelta
from typing import Optional

def _local_now() -> datetime:
    """Hora local del sistema, con zona horaria, sin dependencias externas."""
    try:
        from zoneinfo import ZoneInfo
        import subprocess as _sp
        # Leer TZ del sistema (timedatectl o /etc/timezone)
        tz_name = None
        try:
            r = _sp.run(["timedatectl","show","-p","Timezone","--value"],
                        capture_output=True, text=True, timeout=3)
            tz_name = r.stdout.strip() or None
        except Exception:
            pass
        if not tz_name:
            try:
                with open("/etc/timezone") as _f:
                    tz_name = _f.read().strip() or None
            except Exception:
                pass
        if tz_name:
            return datetime.now(ZoneInfo(tz_name))
    except Exception:
        pass
    # Fallback: offset UTC del sistema
    offset = -time.timezone if time.daylight == 0 else -time.altzone
    return datetime.now(timezone(timedelta(seconds=offset)))

def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")

logger = logging.getLogger(__name__)
CLAMD_SOCKET  = "/var/run/clamav/clamd.ctl"
SCAN_TIMEOUT  = 60
MAX_FILE_SIZE = 50 * 1024 * 1024

def _get_clamd():
    try:
        import pyclamd
        cd = pyclamd.ClamdUnixSocket(CLAMD_SOCKET)
        cd.ping()
        return cd
    except Exception as e:
        logger.warning(f"ClamAV no disponible: {e}")
        return None

def is_available():   return _get_clamd() is not None
def get_version():
    cd = _get_clamd()
    if cd:
        try: return cd.version()
        except: pass
    try:
        r = subprocess.run(["clamscan","--version"], capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except: return "No disponible"

def get_db_info():
    info = {"version": get_version(), "updated_at": None, "signatures": None}
    for p in ["/var/lib/clamav/daily.cld", "/var/lib/clamav/daily.cvd"]:
        if os.path.exists(p):
            info["updated_at"] = _fmt(_local_now().fromtimestamp(os.path.getmtime(p), tz=_local_now().tzinfo))
            break
    return info

def scan_file(filepath):
    result = {"clean": False, "infected": False, "threat": None, "error": None,
              "engine": get_version(), "scanned_at": _local_now().isoformat()}
    if not os.path.isfile(filepath):
        result["error"] = f"Archivo no encontrado: {filepath}"; return result
    fsize = os.path.getsize(filepath)
    if fsize > MAX_FILE_SIZE:
        result["error"] = f"Archivo demasiado grande"; return result
    if fsize == 0:
        result["clean"] = True; return result
    cd = _get_clamd()
    if cd:
        try:
            sr = cd.scan_file(filepath)
            if sr is None: result["clean"] = True
            else:
                v = sr.get(filepath, ('OK', None))
                if v[0] == 'FOUND': result["infected"] = True; result["threat"] = v[1]
                else: result["clean"] = True
            return result
        except Exception as e:
            logger.warning(f"clamd falló: {e}")
    try:
        proc = subprocess.run(["clamscan","--no-summary",filepath],
                              capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        if proc.returncode == 0: result["clean"] = True
        elif proc.returncode == 1:
            result["infected"] = True
            for line in proc.stdout.splitlines():
                if "FOUND" in line:
                    parts = line.split(":")
                    if len(parts) >= 2: result["threat"] = parts[-1].strip().replace(" FOUND",""); break
        else: result["error"] = proc.stderr.strip() or "Error desconocido"
    except subprocess.TimeoutExpired: result["error"] = f"Timeout ({SCAN_TIMEOUT}s)"
    except FileNotFoundError:         result["error"] = "clamscan no encontrado"
    return result

def scan_bytes(data, filename="stream"):
    import tempfile
    result = {"clean": False, "infected": False, "threat": None, "error": None,
              "engine": get_version(), "scanned_at": _local_now().isoformat(), "filename": filename}
    if not data: result["clean"] = True; return result
    with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}") as tmp:
        tmp.write(data); tmp_path = tmp.name
    try:
        file_result = scan_file(tmp_path); result.update(file_result)
    finally:
        try: os.unlink(tmp_path)
        except: pass
    return result

def scan_email_attachments(email_path):
    import email as email_lib, email.policy
    results = []
    if not os.path.isfile(email_path): return results
    try:
        with open(email_path, "rb") as f:
            msg = email_lib.message_from_binary_file(f, policy=email_lib.policy.default)
    except Exception as e:
        return [{"error": f"No se pudo parsear el email: {e}"}]
    for part in msg.walk():
        cd_str = str(part.get("Content-Disposition",""))
        ct = part.get_content_type()
        if "attachment" not in cd_str and ct in ("text/plain","text/html"): continue
        filename = part.get_filename()
        if not filename and "attachment" not in cd_str: continue
        filename = filename or f"part_{len(results)}.bin"
        try:
            payload = part.get_payload(decode=True)
            if payload is None: continue
            results.append(scan_bytes(payload, filename))
        except Exception as e:
            results.append({"filename":filename,"error":str(e),"clean":False,"infected":False,
                            "threat":None,"scanned_at":_local_now().isoformat()})
    return results

def update_signatures():
    subprocess.run(["systemctl","stop","clamav-freshclam"], capture_output=True)
    time.sleep(1)
    try:
        proc = subprocess.run(["sudo", "freshclam", "--quiet"], capture_output=True, text=True, timeout=300)
        result = {"success": proc.returncode == 0,
                  "output": (proc.stdout or proc.stderr or "Sin salida").strip(),
                  "updated_at": _local_now().isoformat()}
    except subprocess.TimeoutExpired: result = {"success": False, "output": "Timeout"}
    except FileNotFoundError:         result = {"success": False, "output": "freshclam no encontrado"}
    finally:
        subprocess.run(["systemctl","start","clamav-freshclam"], capture_output=True)
    return result