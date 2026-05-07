import os
import json
import sqlite3
from datetime import datetime

PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
DB_PATH = os.path.join(PROJECT_DIR, "config", "users.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def normalize_result(result):
    if not isinstance(result, dict):
        return result
    level_map = {
        "M\u00cdNIMO": "MINIMO", "MÍNIMO": "MINIMO", "MíNIMO": "MINIMO",
        "CR\u00cdTICO": "CRITICO", "CRÍTICO": "CRITICO", "CRíTICO": "CRITICO",
        "ALTO": "ALTO", "MEDIO": "MEDIO", "BAJO": "BAJO",
        "MINIMO": "MINIMO", "CRITICO": "CRITICO",
    }
    rl = result.get("risk_level", "")
    result["risk_level"] = level_map.get(rl, rl.upper().replace("Í", "I").replace("Ó", "O"))
    return result


def save_result(user_id, result):
    result = normalize_result(result)
    ea = result.get("entropy_analysis") or {}
    vt = result.get("virustotal") or {}
    vt_s = vt.get("summary") or {}
    conn = get_db()
    conn.execute("""
        INSERT INTO analysis_history
            (user_id, timestamp, filename, subject, from_addr,
             prediction, risk_score, risk_level, ml_prediction,
             body_entropy, url_entropy,
             vt_malicious_files, vt_malicious_urls, full_json)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        user_id,
        result.get("timestamp", datetime.now().isoformat()),
        result.get("file", ""),
        result.get("subject", ""),
        result.get("from", ""),
        result.get("prediction", ""),
        result.get("risk_score", 0),
        result.get("risk_level", ""),
        result.get("ml_prediction", ""),
        ea.get("body_entropy", 0),
        ea.get("url_entropy_max", 0),
        vt_s.get("malicious_files", 0),
        vt_s.get("malicious_urls", 0),
        json.dumps(result, default=str),
    ))
    conn.commit()
    conn.close()


def get_history(user_id, limit=200):
    conn = get_db()
    rows = conn.execute("""
        SELECT id, full_json FROM analysis_history
        WHERE user_id = ?
        ORDER BY id DESC LIMIT ?
    """, (user_id, limit)).fetchall()
    conn.close()
    results = []
    for r in rows:
        try:
            item = json.loads(r["full_json"])
            item["_db_id"] = r["id"]
            results.append(item)
        except Exception:
            pass
    return results


def get_history_page(user_id, page=1, per_page=25):
    offset = (page - 1) * per_page
    conn = get_db()
    total = conn.execute(
        "SELECT COUNT(*) FROM analysis_history WHERE user_id = ?", (user_id,)
    ).fetchone()[0]
    rows = conn.execute("""
        SELECT id, timestamp, filename, subject, prediction,
               risk_score, risk_level, body_entropy
        FROM analysis_history
        WHERE user_id = ?
        ORDER BY id DESC LIMIT ? OFFSET ?
    """, (user_id, per_page, offset)).fetchall()
    conn.close()
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "pages": max(1, (total + per_page - 1) // per_page),
        "items": [dict(r) for r in rows],
    }


def get_history_item(user_id, db_id):
    conn = get_db()
    row = conn.execute(
        "SELECT full_json FROM analysis_history WHERE id = ? AND user_id = ?",
        (db_id, user_id)
    ).fetchone()
    conn.close()
    if row:
        try:
            return json.loads(row["full_json"])
        except Exception:
            pass
    return None


def get_history_summary(user_id):
    conn = get_db()
    row = conn.execute("""
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN prediction='MALICIOSO' THEN 1 ELSE 0 END) as malicious
        FROM analysis_history WHERE user_id = ?
    """, (user_id,)).fetchone()
    conn.close()
    total = row["total"] or 0 if row else 0
    malicious = row["malicious"] or 0 if row else 0
    return total, malicious, total - malicious


def clear_history(user_id):
    conn = get_db()
    conn.execute("DELETE FROM analysis_history WHERE user_id = ?", (user_id,))
    conn.commit()
    conn.close()


def get_model_meta():
    models_dir = os.path.join(PROJECT_DIR, "models")
    p = os.path.join(models_dir, "model_metadata.json")
    if os.path.exists(p):
        with open(p) as f:
            return json.load(f)
    return {}
