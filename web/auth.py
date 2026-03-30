#!/usr/bin/env python3
"""
auth.py — Gestión de usuarios, sesiones y configuración de correo por usuario.
"""

import os
import sqlite3
import bcrypt
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "config", "users.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    # Tabla de usuarios
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            username    TEXT UNIQUE NOT NULL,
            password    TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'user',
            created_at  TEXT NOT NULL,
            last_login  TEXT
        )
    """)

    # Tabla de configuración de correo por usuario
    conn.execute("""
        CREATE TABLE IF NOT EXISTS mail_config (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id        INTEGER NOT NULL UNIQUE,
            -- IMAP
            imap_server    TEXT DEFAULT '',
            imap_port      TEXT DEFAULT '993',
            imap_user      TEXT DEFAULT '',
            imap_password  TEXT DEFAULT '',
            -- Microsoft 365
            ms365_client_id     TEXT DEFAULT '',
            ms365_client_secret TEXT DEFAULT '',
            ms365_tenant_id     TEXT DEFAULT '',
            ms365_user_email    TEXT DEFAULT '',
            -- Gmail
            gmail_client_id     TEXT DEFAULT '',
            gmail_client_secret TEXT DEFAULT '',
            -- Proveedor activo por defecto
            default_provider    TEXT DEFAULT 'imap',
            updated_at          TEXT,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    """)

    # Historial de análisis
    conn.execute("""
        CREATE TABLE IF NOT EXISTS analysis_history (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id        INTEGER,
            timestamp      TEXT,
            filename       TEXT,
            subject        TEXT,
            sender         TEXT,
            prediction     TEXT,
            risk_score     REAL,
            risk_level     TEXT,
            ml_prediction  TEXT,
            body_entropy   REAL,
            url_entropy    REAL,
            feedback_label TEXT,
            details        TEXT
        )
    """)

    # Feedback de correcciones manuales
    conn.execute("""
        CREATE TABLE IF NOT EXISTS feedback (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id      INTEGER,
            analysis_id  INTEGER,
            prediction   TEXT,
            label        TEXT,
            eml_filename TEXT,
            labeled_path TEXT,
            created_at   TEXT
        )
    """)

    # Feedback de entrenamiento
    conn.execute("""
        CREATE TABLE IF NOT EXISTS training_feedback (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id    INTEGER,
            filename   TEXT,
            label      TEXT,
            created_at TEXT
        )
    """)

    conn.commit()

    # Crear admin por defecto si no existe ningún usuario
    if not conn.execute("SELECT 1 FROM users").fetchone():
        create_user("admin", "admin1234", role="admin")
        print("  ✓ Usuario admin creado (password: admin1234)")

    conn.close()


# ══════════════════════════════════════════════════
#  USUARIOS
# ══════════════════════════════════════════════════

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_user(username, password, role="user"):
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO users (username, password, role, created_at) VALUES (?, ?, ?, ?)",
            (username, hash_password(password), role, datetime.now().isoformat())
        )
        user_id = cur.lastrowid
        # Crear entrada vacía de mail_config para el nuevo usuario
        conn.execute(
            "INSERT OR IGNORE INTO mail_config (user_id, updated_at) VALUES (?, ?)",
            (user_id, datetime.now().isoformat())
        )
        conn.commit()
        return True, "Usuario creado correctamente"
    except sqlite3.IntegrityError:
        return False, "El usuario ya existe"
    finally:
        conn.close()


def delete_user(user_id):
    conn = get_db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def get_user_by_username(username):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_user_by_id(user_id):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return dict(user) if user else None


def get_all_users():
    conn = get_db()
    users = conn.execute(
        "SELECT id, username, role, created_at, last_login FROM users ORDER BY id"
    ).fetchall()
    conn.close()
    return [dict(u) for u in users]


def update_last_login(username):
    conn = get_db()
    conn.execute(
        "UPDATE users SET last_login = ? WHERE username = ?",
        (datetime.now().isoformat(), username)
    )
    conn.commit()
    conn.close()


def change_password(user_id, new_password):
    conn = get_db()
    conn.execute(
        "UPDATE users SET password = ? WHERE id = ?",
        (hash_password(new_password), user_id)
    )
    conn.commit()
    conn.close()


def authenticate(username, password):
    user = get_user_by_username(username)
    if user and check_password(password, user["password"]):
        update_last_login(username)
        return user
    return None


# ══════════════════════════════════════════════════
#  CONFIGURACIÓN DE CORREO POR USUARIO
# ══════════════════════════════════════════════════

def get_mail_config(user_id):
    """Devuelve la configuración de correo de un usuario."""
    conn = get_db()
    row = conn.execute(
        "SELECT * FROM mail_config WHERE user_id = ?", (user_id,)
    ).fetchone()
    conn.close()
    if row:
        return dict(row)
    # Si no existe, devolver estructura vacía
    return {
        "user_id": user_id,
        "imap_server": "", "imap_port": "993",
        "imap_user": "", "imap_password": "",
        "ms365_client_id": "", "ms365_client_secret": "",
        "ms365_tenant_id": "", "ms365_user_email": "",
        "gmail_client_id": "", "gmail_client_secret": "",
        "default_provider": "imap",
    }


def save_mail_config(user_id, data: dict):
    """Guarda o actualiza la configuración de correo de un usuario."""
    allowed = {
        "imap_server", "imap_port", "imap_user", "imap_password",
        "ms365_client_id", "ms365_client_secret",
        "ms365_tenant_id", "ms365_user_email",
        "gmail_client_id", "gmail_client_secret",
        "default_provider",
    }
    filtered = {k: v for k, v in data.items() if k in allowed}
    filtered["updated_at"] = datetime.now().isoformat()
    filtered["user_id"]    = user_id

    conn = get_db()
    # Upsert
    conn.execute(
        "INSERT OR IGNORE INTO mail_config (user_id, updated_at) VALUES (?, ?)",
        (user_id, filtered["updated_at"])
    )
    for key, val in filtered.items():
        if key not in ("user_id",):
            conn.execute(
                f"UPDATE mail_config SET {key} = ? WHERE user_id = ?",
                (val, user_id)
            )
    conn.commit()
    conn.close()


def get_all_mail_configs():
    """Solo para admin: devuelve config de todos los usuarios."""
    conn = get_db()
    rows = conn.execute("""
        SELECT u.id, u.username, u.role,
               mc.default_provider, mc.imap_server, mc.imap_user,
               mc.ms365_user_email, mc.gmail_client_id, mc.updated_at
        FROM users u
        LEFT JOIN mail_config mc ON u.id = mc.user_id
        ORDER BY u.id
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]
