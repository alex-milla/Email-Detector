#!/usr/bin/env python3
"""
validate_release.py — Validaciones previas a generar una release.

Este script DEBE pasar antes de subir VERSION/version.json.
Fallará con código de error != 0 si algo no pasa, bloqueando la release.

Uso:
    python scripts/validate_release.py
"""

import ast
import os
import py_compile
import subprocess
import sys
import tempfile

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WEB_DIR = os.path.join(PROJECT_DIR, "web")
SCRIPTS_DIR = os.path.join(PROJECT_DIR, "scripts")


def _clean_modules(prefixes):
    """Elimina módulos importados de sys.modules para evitar contaminación."""
    to_remove = [mod for mod in sys.modules if any(mod.startswith(p) for p in prefixes)]
    for mod in to_remove:
        del sys.modules[mod]


def validate_python_syntax():
    """Compila todos los .py para detectar errores de sintaxis."""
    errors = []
    skip_dirs = {".git", "venv", ".venv", "__pycache__", ".github", "node_modules"}
    for root, _, files in os.walk(PROJECT_DIR):
        if any(d in root for d in skip_dirs):
            continue
        for fname in files:
            if fname.endswith(".py"):
                fpath = os.path.join(root, fname)
                try:
                    py_compile.compile(fpath, doraise=True)
                except py_compile.PyCompileError as e:
                    errors.append(f"{os.path.relpath(fpath, PROJECT_DIR)}: {e}")
    return errors


def validate_shell_scripts():
    """bash -n en todos los .sh para validar sintaxis."""
    errors = []
    skip_dirs = {".git", "venv", ".venv", "__pycache__"}
    for root, _, files in os.walk(PROJECT_DIR):
        if any(d in root for d in skip_dirs):
            continue
        for fname in files:
            if fname.endswith(".sh"):
                fpath = os.path.join(root, fname)
                result = subprocess.run(
                    ["bash", "-n", fpath],
                    capture_output=True, text=True
                )
                if result.returncode != 0:
                    err = result.stderr.strip().replace("\n", "; ")
                    errors.append(f"{os.path.relpath(fpath, PROJECT_DIR)}: {err}")
    return errors


def validate_critical_imports():
    """
    Verifica que los módulos críticos importan sin errores.
    Simula lo que hace gunicorn --preload.
    """
    errors = []
    old_cwd = os.getcwd()
    old_path = list(sys.path)
    env_path = os.path.join(PROJECT_DIR, "config", ".env")
    env_backup = None

    try:
        os.chdir(PROJECT_DIR)

        # Asegurar que .env existe con SECRET_KEY (gunicorn preload lo necesita)
        if not os.path.exists(env_path):
            env_backup = "__missing__"
            with open(env_path, "w") as f:
                f.write('SECRET_KEY="validation-dummy-key-do-not-use-in-production"\n')
        else:
            with open(env_path, "r") as f:
                env_backup = f.read()
            if "SECRET_KEY=" not in env_backup:
                with open(env_path, "a") as f:
                    f.write('\nSECRET_KEY="validation-dummy-key-do-not-use-in-production"\n')

        sys.path.insert(0, WEB_DIR)
        sys.path.insert(0, SCRIPTS_DIR)

        # 1. web.app (simula gunicorn --preload)
        try:
            import web.app as app_module
            if not hasattr(app_module, "app"):
                errors.append("web.app no exporta 'app'")
        except Exception as e:
            errors.append(f"web.app import failed: {e}")
        finally:
            _clean_modules(("web.",))

        # 2. scripts.train_model (no debe ejecutar side-effects)
        try:
            import scripts.train_model as tm
            # Si hay side-effects globales, best_model_name o similar existirían
            if hasattr(tm, "best_model_name") and tm.best_model_name is not None:
                errors.append("train_model.py ejecuta código al importar (side-effect detectado)")
        except Exception as e:
            errors.append(f"scripts.train_model import failed: {e}")
        finally:
            _clean_modules(("scripts.", "imblearn", "xgboost", "lightgbm", "catboost"))

        # 3. scripts.predict
        try:
            import scripts.predict as pred
        except Exception as e:
            errors.append(f"scripts.predict import failed: {e}")
        finally:
            _clean_modules(("scripts.",))

    finally:
        os.chdir(old_cwd)
        sys.path[:] = old_path
        # Restaurar .env
        if env_backup == "__missing__":
            try:
                os.remove(env_path)
            except Exception:
                pass
        elif env_backup is not None:
            with open(env_path, "w") as f:
                f.write(env_backup)

    return errors


def validate_no_forward_reference_in_app():
    """
    Análisis AST básico de web/app.py para detectar referencias a variables
    de nivel de módulo antes de su asignación (el bug del NameError).
    """
    fpath = os.path.join(WEB_DIR, "app.py")
    with open(fpath, "r", encoding="utf-8") as f:
        source = f.read()

    try:
        tree = ast.parse(source)
    except SyntaxError as e:
        return [f"web/app.py syntax error: {e}"]

    defined = set()
    errors = []

    def _check_expr(node, lineno):
        """Revisa una expresión en busca de Name que no estén definidos."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and isinstance(child.ctx, ast.Load):
                if child.id not in defined and child.id not in {
                    "os", "sys", "json", "re", "sqlite3", "subprocess",
                    "threading", "datetime", "Path", "wraps", "Flask",
                    "render_template", "request", "jsonify", "redirect",
                    "url_for", "session", "Limiter", "get_remote_address",
                    "load_dotenv", "secure_filename", "predict_email",
                    "download_emails", "init_db", "authenticate", "create_user",
                    "delete_user", "get_all_users", "change_password",
                    "get_mail_config", "save_mail_config", "get_all_mail_configs",
                    "read_global_env", "write_global_env", "test_imap",
                    "test_virustotal", "test_m365", "check_for_updates",
                    "get_update_state", "start_update", "email", "time",
                    "tempfile", "zipfile", "shutil", "hashlib", "base64",
                    "requests", "Version", "warnings", "math", "collections",
                    "functools", "typing", "pathlib", "csv", "argparse",
                    "urllib", "random", "string", "inspect", "builtins",
                    "None", "True", "False", "print", "len", "range", "list",
                    "dict", "set", "tuple", "int", "str", "float", "bool",
                    "type", "isinstance", "hasattr", "getattr", "setattr",
                    "open", "Exception", "FileNotFoundError", "ValueError",
                    "RuntimeError", "ImportError", "KeyError", "IndexError",
                }:
                    errors.append(
                        f"web/app.py:{lineno}: referencia a '{child.id}' antes de su definición"
                    )

    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.Assign):
            # Primero revisar el value (lado derecho) porque ahí están las referencias
            _check_expr(node.value, getattr(node, "lineno", 0))
            # Luego añadir targets a definidos
            for target in node.targets:
                if isinstance(target, ast.Name):
                    defined.add(target.id)
                elif isinstance(target, ast.Tuple):
                    for elt in target.elts:
                        if isinstance(elt, ast.Name):
                            defined.add(elt.id)
        elif isinstance(node, ast.AnnAssign):
            if node.value:
                _check_expr(node.value, getattr(node, "lineno", 0))
            if isinstance(node.target, ast.Name):
                defined.add(node.target.id)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, ast.Expr):
            _check_expr(node.value, getattr(node, "lineno", 0))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                defined.add(alias.asname or alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                defined.add(alias.asname or alias.name)

    return errors


def main():
    print("=" * 60)
    print("VALIDACIÓN PRE-RELEASE")
    print("=" * 60)

    all_errors = []

    print("\n[1/5] Sintaxis Python (.py)...")
    errs = validate_python_syntax()
    if errs:
        all_errors.extend(errs)
        print(f"  FAIL: {len(errs)} errores")
        for e in errs[:5]:
            print(f"    - {e}")
        if len(errs) > 5:
            print(f"    ... y {len(errs)-5} más")
    else:
        print("  OK")

    print("\n[2/5] Sintaxis Shell (.sh)...")
    errs = validate_shell_scripts()
    if errs:
        all_errors.extend(errs)
        print(f"  FAIL: {len(errs)} errores")
        for e in errs[:5]:
            print(f"    - {e}")
    else:
        print("  OK")

    print("\n[3/5] Importación de módulos críticos...")
    errs = validate_critical_imports()
    if errs:
        all_errors.extend(errs)
        print(f"  FAIL: {len(errs)} errores")
        for e in errs:
            print(f"    - {e}")
    else:
        print("  OK")

    print("\n[4/5] Referencias forward en web/app.py...")
    errs = validate_no_forward_reference_in_app()
    if errs:
        all_errors.extend(errs)
        print(f"  FAIL: {len(errs)} errores")
        for e in errs[:5]:
            print(f"    - {e}")
    else:
        print("  OK")

    print("\n[5/5] Resumen...")
    if all_errors:
        print(f"  FAIL: {len(all_errors)} errores totales. RELEASE BLOQUEADA.")
        print("  Corrige los errores y vuelve a ejecutar este script.")
        sys.exit(1)
    else:
        print("  OK: Todas las validaciones pasaron.")
        print("  Puedes ejecutar scripts/bump_version.py para generar la release.")
        sys.exit(0)


if __name__ == "__main__":
    main()
