import os
import sys
import json
import shutil
from datetime import datetime, timedelta

import csv as csv_module
import io

from flask import request, jsonify, session, Response
from werkzeug.utils import secure_filename

from web.services.decorators import login_required
from web.services.history_service import (
    save_result, get_history, get_history_page,
    get_history_item, clear_history,
)
from web.services.validation_service import validate_eml_upload

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))

from predict import predict_email
from mailbox_connector import download_emails


def register_routes(app):
    PROJECT_DIR = os.path.join(os.path.dirname(__file__), "..", "..")
    UPLOAD_DIR = os.path.join(PROJECT_DIR, "data", "samples")
    os.makedirs(UPLOAD_DIR, exist_ok=True)

    @app.route("/analyze", methods=["POST"])
    @login_required
    def analyze():
        if "files" not in request.files:
            return jsonify({"error": "No se subieron archivos"}), 400
        files = request.files.getlist("files")
        use_vt = request.form.get("use_virustotal", "true") == "true"
        uid = session["user_id"]
        results = []
        for file in files:
            if not file.filename:
                continue
            safe_name = secure_filename(file.filename)
            if not safe_name.lower().endswith(".eml"):
                results.append({"error": "Solo se aceptan archivos .eml", "file": safe_name})
                continue

            ok, reason = validate_eml_upload(file)
            if not ok:
                results.append({"error": f"Archivo rechazado: {reason}", "file": safe_name})
                continue

            filepath = os.path.join(UPLOAD_DIR, safe_name)
            file.save(filepath)
            try:
                result = predict_email(filepath, use_virustotal=use_vt)
                result["analyzed_by"] = session.get("username")
                save_result(uid, result)
                results.append(result)
            except Exception as e:
                results.append({"error": str(e), "file": safe_name})
        return jsonify({"results": results, "total_analyzed": len(results)})

    @app.route("/fetch-emails", methods=["POST"])
    @login_required
    def fetch_emails():
        from datetime import datetime as dt
        uid = session["user_id"]
        from web.auth import get_mail_config
        cfg = get_mail_config(uid)
        body = request.get_json(silent=True) or {}
        provider = body.get("provider", cfg.get("default_provider", "imap"))
        max_emails = min(int(body.get("max_emails", 20)), 50)
        folder = "inbox"
        use_vt = body.get("use_virustotal", False)

        date_from = date_to = None
        days_back = 7
        raw_from = body.get("date_from")
        raw_to = body.get("date_to")
        if raw_from:
            try:
                date_from = dt.strptime(raw_from, "%Y-%m-%d")
                date_to = dt.strptime(raw_to, "%Y-%m-%d") if raw_to else dt.now()
            except ValueError:
                pass
        else:
            days_back = int(body.get("days_back", 7))

        env_map = {
            "imap": {"IMAP_SERVER": cfg["imap_server"], "IMAP_PORT": cfg["imap_port"],
                     "IMAP_USER": cfg["imap_user"], "IMAP_PASSWORD": cfg["imap_password"]},
            "m365": {"MS365_CLIENT_ID": cfg["ms365_client_id"],
                      "MS365_CLIENT_SECRET": cfg["ms365_client_secret"],
                      "MS365_TENANT_ID": cfg["ms365_tenant_id"],
                      "MS365_USER_EMAIL": cfg["ms365_user_email"]},
            "gmail": {"GMAIL_CLIENT_ID": cfg["gmail_client_id"],
                       "GMAIL_CLIENT_SECRET": cfg["gmail_client_secret"]},
        }
        backup = {}
        for k, v in env_map.get(provider, {}).items():
            backup[k] = os.environ.get(k, "")
            os.environ[k] = v

        try:
            downloaded = download_emails(provider, max_emails, days_back,
                                           folder=folder, date_from=date_from, date_to=date_to)
            results = []
            analyzed = 0
            errors = 0
            for filepath in downloaded:
                try:
                    result = predict_email(filepath, use_virustotal=use_vt)
                    result["analyzed_by"] = session.get("username")
                    save_result(uid, result)
                    results.append({
                        "file": result.get("file"),
                        "subject": result.get("subject", ""),
                        "prediction": result.get("prediction"),
                        "risk_level": result.get("risk_level"),
                        "risk_score": result.get("risk_score"),
                    })
                    analyzed += 1
                except Exception:
                    errors += 1

            return jsonify({
                "success": True,
                "downloaded": len(downloaded),
                "analyzed": analyzed,
                "errors": errors,
                "results": results,
            })
        except Exception as e:
            return jsonify({"success": False, "error": str(e)}), 500
        finally:
            for k, v in backup.items():
                os.environ[k] = v

    @app.route("/history")
    @login_required
    def history():
        return jsonify(get_history(session["user_id"]))

    @app.route("/history/page/<int:page>")
    @login_required
    def history_page(page):
        data = get_history_page(session["user_id"], page=page, per_page=25)
        return jsonify(data)

    @app.route("/history/<int:db_id>")
    @login_required
    def history_detail(db_id):
        item = get_history_item(session["user_id"], db_id)
        if item:
            return jsonify(item)
        return jsonify({"error": "No encontrado"}), 404

    @app.route("/history/clear", methods=["POST"])
    @login_required
    def history_clear():
        clear_history(session["user_id"])
        return jsonify({"success": True})

    @app.route("/feedback/<int:db_id>", methods=["POST"])
    @login_required
    def submit_feedback(db_id):
        data = request.get_json(silent=True) or {}
        label = data.get("label")
        if label not in (0, 1):
            return jsonify({"error": "label debe ser 0 (benigno) o 1 (malicioso)"}), 400

        uid = session["user_id"]
        item = get_history_item(uid, db_id)
        if not item:
            return jsonify({"error": "Análisis no encontrado"}), 404

        label_dir = os.path.join(PROJECT_DIR, "data", "labeled",
                                 "benign" if label == 0 else "malicious")
        os.makedirs(label_dir, exist_ok=True)

        eml_filename = item.get("file", "")
        labeled_path = None
        for search_dir in ["data/raw", "data/samples"]:
            candidate = os.path.join(PROJECT_DIR, search_dir, eml_filename)
            if os.path.exists(candidate):
                dest = os.path.join(label_dir, eml_filename)
                shutil.copy2(candidate, dest)
                labeled_path = dest
                break

        from web.auth import get_db
        conn = get_db()
        old = conn.execute(
            "SELECT labeled_path FROM feedback WHERE analysis_id=? AND user_id=?",
            (db_id, uid)
        ).fetchone()
        if old and old["labeled_path"] and os.path.exists(old["labeled_path"]):
            try:
                os.remove(old["labeled_path"])
            except Exception:
                pass
        conn.execute("DELETE FROM feedback WHERE analysis_id=? AND user_id=?", (db_id, uid))

        conn.execute("""
            INSERT INTO feedback
                (analysis_id, user_id, original_pred, corrected_label,
                 eml_filename, labeled_path, created_at)
            VALUES (?,?,?,?,?,?,?)
        """, (db_id, uid, item.get("prediction", ""), label, eml_filename,
              labeled_path, datetime.now().isoformat()))

        conn.execute(
            "UPDATE analysis_history SET feedback_label=? WHERE id=? AND user_id=?",
            (label, db_id, uid)
        )
        conn.commit()
        conn.close()

        label_str = "BENIGNO" if label == 0 else "MALICIOSO"
        msg = f"Marcado como {label_str}"
        if labeled_path:
            msg += " y copiado a data/labeled"
        else:
            msg += " (archivo .eml no encontrado, solo registrado)"
        return jsonify({"success": True, "message": msg, "label": label})

    @app.route("/feedback/<int:db_id>", methods=["DELETE"])
    @login_required
    def delete_feedback(db_id):
        uid = session["user_id"]
        from web.auth import get_db
        conn = get_db()
        row = conn.execute(
            "SELECT labeled_path FROM feedback WHERE analysis_id=? AND user_id=?",
            (db_id, uid)
        ).fetchone()
        if row and row["labeled_path"] and os.path.exists(row["labeled_path"]):
            try:
                os.remove(row["labeled_path"])
            except Exception:
                pass
        conn.execute("DELETE FROM feedback WHERE analysis_id=? AND user_id=?", (db_id, uid))
        conn.execute(
            "UPDATE analysis_history SET feedback_label=NULL WHERE id=? AND user_id=?",
            (db_id, uid)
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": "Feedback eliminado"})

    @app.route("/feedback/stats")
    @login_required
    def feedback_stats():
        from web.auth import get_db
        conn = get_db()
        total = conn.execute("SELECT COUNT(*) FROM feedback").fetchone()[0]
        benign = conn.execute("SELECT COUNT(*) FROM feedback WHERE corrected_label=0").fetchone()[0]
        malicious = conn.execute("SELECT COUNT(*) FROM feedback WHERE corrected_label=1").fetchone()[0]
        conn.close()
        return jsonify({"total": total, "benign": benign, "malicious": malicious})

    @app.route("/analyze/virustotal/<int:db_id>", methods=["POST"])
    @login_required
    def analyze_virustotal(db_id):
        import sys
        sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "scripts"))
        from virustotal import check_email_artifacts

        item = get_history_item(session["user_id"], db_id)
        if not item:
            return jsonify({"error": "Análisis no encontrado"}), 404

        metadata = item.get("metadata") or {}
        vt_results = check_email_artifacts(
            attachment_hashes=metadata.get("attachment_hashes", []),
            urls=metadata.get("urls_found", []),
            max_checks=8
        )
        item["virustotal"] = vt_results
        from web.auth import get_db
        conn = get_db()
        conn.execute(
            "UPDATE analysis_history SET full_json = ? WHERE id = ? AND user_id = ?",
            (json.dumps(item, default=str), db_id, session["user_id"])
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "virustotal": vt_results})

    @app.route("/api/stats/trend")
    @login_required
    def stats_trend():
        uid = session["user_id"]
        history = get_history(uid)
        today = datetime.now().date()
        daily = {}
        for i in range(30):
            day = today - timedelta(days=i)
            daily[day.isoformat()] = {"malicious": 0, "benign": 0}
        for item in history:
            ts = item.get("timestamp", "")
            day = ts[:10] if ts else ""
            if day in daily:
                pred = item.get("prediction", "")
                if pred == "MALICIOSO":
                    daily[day]["malicious"] += 1
                elif pred == "BENIGNO":
                    daily[day]["benign"] += 1
        labels = sorted(daily.keys())
        return jsonify({
            "labels": labels,
            "malicious": [daily[d]["malicious"] for d in labels],
            "benign": [daily[d]["benign"] for d in labels],
        })

    @app.route("/api/export/csv")
    @login_required
    def export_csv():
        uid = session["user_id"]
        history = get_history(uid)
        output = io.StringIO()
        writer = csv_module.writer(output)
        writer.writerow(["fecha", "archivo", "asunto", "remitente", "prediccion",
                         "riesgo", "nivel", "confianza", "urls", "adjuntos"])
        for item in history:
            writer.writerow([
                item.get("timestamp", ""),
                item.get("file", ""),
                item.get("subject", ""),
                item.get("from", ""),
                item.get("prediction", ""),
                item.get("risk_score", ""),
                item.get("risk_level", ""),
                item.get("ml_confidence", ""),
                len(item.get("metadata", {}).get("urls_found", [])),
                len(item.get("metadata", {}).get("attachments", [])),
            ])
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=email_detector_export.csv"}
        )
