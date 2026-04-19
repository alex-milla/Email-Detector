#!/usr/bin/env python3
"""
bump_version.py — Genera una release de forma segura.

Flujo:
  1. Ejecuta validate_release.py (bloquea si falla)
  2. Pide nueva versión
  3. Actualiza VERSION y version.json
  4. Git commit + tag
  5. Push a origin
  6. Crea release en GitHub via API (opcional)

Uso:
    python scripts/bump_version.py

Requisitos:
    - Git configurado con remote a GitHub
    - Variable de entorno GITHUB_TOKEN con permisos repo (opcional, para crear release)
"""

import json
import os
import re
import subprocess
import sys
from datetime import datetime

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VERSION_FILE = os.path.join(PROJECT_DIR, "VERSION")
VERSION_JSON = os.path.join(PROJECT_DIR, "version.json")
VALIDATE_SCRIPT = os.path.join(PROJECT_DIR, "scripts", "validate_release.py")


def _run(cmd, check=True, capture=True):
    """Ejecuta un comando shell y devuelve (returncode, stdout, stderr)."""
    kwargs = {"cwd": PROJECT_DIR}
    if capture:
        kwargs["capture_output"] = True
        kwargs["text"] = True
    result = subprocess.run(cmd, shell=True, **kwargs)
    if check and result.returncode != 0:
        err = result.stderr.strip() if capture else ""
        raise RuntimeError(f"Comando falló: {cmd}\n{err}")
    return result.returncode, (result.stdout.strip() if capture else ""), (result.stderr.strip() if capture else "")


def validate():
    """Paso 1: validaciones pre-release."""
    print("\n[1/6] Ejecutando validaciones pre-release...")
    code, out, err = _run(f"python3 {VALIDATE_SCRIPT}", check=False)
    print(out)
    if err:
        print(err, file=sys.stderr)
    if code != 0:
        print("\n❌ RELEASE BLOQUEADA por errores de validación.")
        sys.exit(1)
    print("✅ Validaciones OK")


def get_current_version():
    with open(VERSION_FILE, "r", encoding="utf-8") as f:
        return f.read().strip()


def ask_new_version(current):
    print(f"\n[2/6] Versión actual: {current}")
    new = input("Nueva versión (ej: 1.2.17): ").strip()
    if not re.match(r"^\d+\.\d+\.\d+", new):
        print("❌ Formato inválido. Usa semver (ej: 1.2.17).")
        sys.exit(1)
    return new


def update_version_files(new_version):
    print(f"\n[3/6] Actualizando VERSION y version.json a {new_version}...")

    with open(VERSION_FILE, "w", encoding="utf-8") as f:
        f.write(new_version + "\n")

    changelog = input("Resumen del changelog (una línea): ").strip()
    if not changelog:
        changelog = f"Release {new_version}"

    version_data = {
        "version": new_version,
        "release_date": datetime.now().strftime("%Y-%m-%d"),
        "changelog": changelog,
        "min_version": "1.0.0",
        "zip_url": f"https://github.com/alex-milla/Email-Detector/archive/v{new_version}.zip",
    }

    with open(VERSION_JSON, "w", encoding="utf-8") as f:
        json.dump(version_data, f, indent=2)
        f.write("\n")

    print("✅ Archivos actualizados")


def git_commit_and_tag(new_version):
    print(f"\n[4/6] Git commit + tag v{new_version}...")
    _run("git add VERSION version.json")
    _run(f'git commit -m "release: {new_version}"')
    _run(f'git tag -a v{new_version} -m "release {new_version}"')
    print("✅ Commit y tag creados")


def git_push():
    print("\n[5/6] Push a origin...")
    _run("git push origin main")
    _run("git push origin --tags")
    print("✅ Push completado")


def create_github_release(new_version, changelog):
    print("\n[6/6] Creando release en GitHub...")
    token = os.getenv("GITHUB_TOKEN", "")
    if not token:
        print("⚠️  GITHUB_TOKEN no definido. Saltando creación de release en GitHub.")
        print("   Puedes crearla manualmente en: https://github.com/alex-milla/Email-Detector/releases/new")
        return

    import urllib.request
    import urllib.error

    url = "https://api.github.com/repos/alex-milla/Email-Detector/releases"
    body = json.dumps({
        "tag_name": f"v{new_version}",
        "name": f"Email Malware Detector v{new_version}",
        "body": changelog,
        "draft": False,
        "prerelease": False,
    }).encode("utf-8")

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Authorization", f"token {token}")
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("Content-Type", "application/json")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode())
            print(f"✅ Release creada: {data.get('html_url')}")
    except urllib.error.HTTPError as e:
        print(f"❌ Error creando release: {e.code} {e.reason}")
        print(e.read().decode())
    except Exception as e:
        print(f"❌ Error inesperado: {e}")


def main():
    print("=" * 60)
    print("GENERADOR DE RELEASES SEGURO")
    print("=" * 60)

    validate()
    current = get_current_version()
    new_version = ask_new_version(current)
    update_version_files(new_version)
    git_commit_and_tag(new_version)
    git_push()
    create_github_release(new_version, f"Release {new_version}")

    print("\n" + "=" * 60)
    print(f"🎉 Release v{new_version} publicada correctamente.")
    print("=" * 60)


if __name__ == "__main__":
    main()
