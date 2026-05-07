import os
import re

EML_MAX_SIZE_BYTES = 10 * 1024 * 1024
EML_ALLOWED_MIMETYPES = {
    "message/rfc822",
    "text/plain",
    "application/octet-stream",
}


def validate_eml_upload(file) -> tuple:
    filename = file.filename or ""

    parts = filename.lower().split(".")
    if len(parts) > 2:
        dangerous_exts = {
            "exe", "bat", "cmd", "sh", "ps1", "vbs", "js", "jar",
            "py", "rb", "php", "asp", "dll", "msi", "com", "scr",
        }
        if parts[-2] in dangerous_exts:
            return False, f"Nombre de archivo sospechoso (doble extensión): {filename}"

    mime = (file.content_type or "").split(";")[0].strip().lower()
    if mime and mime not in EML_ALLOWED_MIMETYPES:
        return False, f"Tipo MIME no permitido: {mime}"

    header_bytes = file.read(4096)
    file.seek(0)

    file_size = file.seek(0, 2)
    file.seek(0)

    if file_size > EML_MAX_SIZE_BYTES:
        return False, (
            f"Archivo demasiado grande: {file_size // 1024} KB "
            f"(máximo {EML_MAX_SIZE_BYTES // 1024 // 1024} MB)"
        )

    try:
        header_text = header_bytes.decode("utf-8", errors="replace")
        first_lines = header_text.splitlines()[:10]
        has_rfc822_header = any(
            re.match(r'^[A-Za-z0-9\-]+\s*:', line)
            for line in first_lines
            if line.strip()
        )
        if not has_rfc822_header and header_bytes[:3] not in (b'\xef\xbb\xbf',):
            return False, "El archivo no parece un correo RFC 822 válido"
    except Exception:
        return False, "No se pudo leer el contenido del archivo"

    return True, ""


def validate_script_path(script_path: str, allowed_dir: str) -> tuple:
    try:
        real_script = os.path.realpath(script_path)
        real_allowed = os.path.realpath(allowed_dir)

        try:
            common = os.path.commonpath([real_script, real_allowed])
        except ValueError:
            return False, f"Ruta fuera del directorio permitido: {real_script}"
        if common != real_allowed:
            return False, f"Ruta fuera del directorio permitido: {real_script}"

        st = os.stat(real_script)

        relax = os.environ.get("EMAIL_DETECTOR_RELAX_SCRIPT_CHECK", "").lower() in (
            "1", "true", "yes",
        )
        if not relax and hasattr(os, 'getuid'):
            current_uid = os.getuid()
            if st.st_uid != 0 and st.st_uid != current_uid:
                return False, (
                    f"El script no pertenece a root ni al usuario actual "
                    f"(owner={st.st_uid}, current={current_uid})"
                )
            if st.st_mode & 0o022:
                return False, "El script es escribible por grupo u otros (permisos inseguros)"

        return True, ""

    except FileNotFoundError:
        return False, "El script no existe"
    except PermissionError:
        return False, "Sin permisos para inspeccionar el script"
    except Exception as e:
        return False, f"Error inesperado al validar el script: {e}"
