from flask import render_template, request, jsonify

from web.services.decorators import login_required, admin_required, current_user
from updater import check_for_updates, get_update_state, start_update


def register_routes(app):

    @app.route("/update")
    @admin_required
    def update_page():
        return render_template("update.html", user=current_user(), active_page='update')

    @app.route("/api/update/check")
    @admin_required
    def api_update_check():
        return jsonify(check_for_updates())

    @app.route("/api/update/apply", methods=["POST"])
    @admin_required
    def api_update_apply():
        update_info = check_for_updates()
        if update_info.get("error"):
            return jsonify({"started": False, "error": update_info["error"]}), 400
        if not update_info.get("update_available"):
            return jsonify({"started": False, "error": "No hay actualización disponible."}), 400
        zip_url = update_info.get("zip_url", "")
        ok, err = start_update(zip_url)
        if not ok:
            return jsonify({"started": False, "error": err}), 409
        return jsonify({"started": True, "message": "Actualización iniciada en background."})

    @app.route("/api/update/status")
    @admin_required
    def api_update_status():
        return jsonify(get_update_state())
