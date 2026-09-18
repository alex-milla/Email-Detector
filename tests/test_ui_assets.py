#!/usr/bin/env python3
"""
Tests de estructura de la UI (Fase 0 del rediseno): assets y referencias.
"""

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("EMAIL_DETECTOR_RELAX_SCRIPT_CHECK", "1")

PROJECT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
STATIC = os.path.join(PROJECT_DIR, "web", "static")
TEMPLATES = os.path.join(PROJECT_DIR, "web", "templates")


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class TestAssets:
    def test_design_system_files_exist(self):
        for rel in ("css/app.css", "js/app.js", "theme.js", "vendor/chart.umd.min.js"):
            assert os.path.isfile(os.path.join(STATIC, *rel.split("/"))), rel

    def test_dashboard_has_clickfix_section(self):
        js = _read(os.path.join(STATIC, "js", "dashboard.js"))
        assert "renderClickfixSection" in js
        assert "payload_urls" in js
        assert "payload_domains" in js

    def test_dashboard_has_hidden_section(self):
        js = _read(os.path.join(STATIC, "js", "dashboard.js"))
        assert "renderHiddenSection" in js
        assert "hidden_text" in js

    def test_settings_has_hidden_lang_option(self):
        html = _read(os.path.join(TEMPLATES, "settings.html"))
        assert 'id="hidden-langs"' in html
        assert 'save-hidden-langs' in html
        js = _read(os.path.join(STATIC, "js", "settings.js"))
        assert "saveHiddenLangs" in js

    def test_app_css_has_tokens_and_components(self):
        css = _read(os.path.join(STATIC, "css", "app.css"))
        for token in ("--bg-body", "--accent", "--text-primary"):
            assert token in css
        for cls in (".btn", ".card", ".alert", ".modal", ".toast", ".auth-card"):
            assert cls in css


class TestLayout:
    def test_layout_links_external_assets(self):
        html = _read(os.path.join(TEMPLATES, "layout.html"))
        assert "/static/css/app.css" in html
        assert "/static/js/app.js" in html
        assert "/static/vendor/chart.umd.min.js" in html
        assert "/static/theme.js" in html

    def test_layout_has_no_inline_style_or_script(self):
        html = _read(os.path.join(TEMPLATES, "layout.html"))
        assert "<style" not in html
        assert "cdn.jsdelivr.net" not in html

    def test_login_uses_design_system(self):
        html = _read(os.path.join(TEMPLATES, "login.html"))
        assert "/static/css/app.css" in html
        assert "<style" not in html

    def test_error_uses_design_system(self):
        html = _read(os.path.join(TEMPLATES, "error.html"))
        assert "/static/css/app.css" in html
        assert "<style" not in html

    def test_users_page_migrated(self):
        html = _read(os.path.join(TEMPLATES, "users.html"))
        assert "/static/js/users.js" in html
        assert "<style" not in html
        assert "onclick=" not in html
        assert os.path.isfile(os.path.join(STATIC, "js", "users.js"))

    def test_update_page_migrated(self):
        html = _read(os.path.join(TEMPLATES, "update.html"))
        assert "/static/js/update.js" in html
        assert "<style" not in html
        assert "onclick=" not in html
        assert os.path.isfile(os.path.join(STATIC, "js", "update.js"))

    def test_training_page_migrated(self):
        html = _read(os.path.join(TEMPLATES, "training.html"))
        assert "/static/js/training.js" in html
        assert "<style" not in html
        assert "onclick=" not in html
        assert "onchange=" not in html
        assert os.path.isfile(os.path.join(STATIC, "js", "training.js"))

    def test_settings_page_migrated(self):
        html = _read(os.path.join(TEMPLATES, "settings.html"))
        assert "/static/js/settings.js" in html
        assert "<style" not in html
        assert "onclick=" not in html
        assert "onchange=" not in html
        assert os.path.isfile(os.path.join(STATIC, "js", "settings.js"))

    def test_settings_has_tabs_security_and_collapse(self):
        html = _read(os.path.join(TEMPLATES, "settings.html"))
        assert 'data-action="tab"' in html
        for tab in ("mail", "detection", "system"):
            assert 'data-tab-panel="' + tab + '"' in html
        assert 'data-action="change-password"' in html
        assert 'data-action="collapse"' in html
        assert "provider-card" in html

    def test_training_page_renders(self):
        from web.app import app
        with app.test_client() as client:
            with client.session_transaction() as sess:
                sess["user_id"] = 1
                sess["username"] = "tester"
                sess["user_role"] = "admin"
            resp = client.get("/training")
        assert resp.status_code == 200
        body = resp.get_data(as_text=True)
        assert 'id="trainingStatus"' in body
        assert 'data-tab-panel="maintenance"' in body

    def test_training_has_state_and_guided_tabs(self):
        html = _read(os.path.join(TEMPLATES, "training.html"))
        assert 'id="trainingStatus"' in html
        assert 'data-model-ready' in html
        assert 'data-action="tab"' in html
        for tab in ("setup", "maintenance", "models"):
            assert 'data-tab-panel="' + tab + '"' in html
        assert 'class="checklist"' in html
        assert "Puesta en marcha" in html
        assert "Mantenimiento" in html
        assert "advanced-block" in html

    def test_training_has_history_and_metrics(self):
        html = _read(os.path.join(TEMPLATES, "training.html"))
        assert 'id="modelComparison"' in html
        assert 'id="aucHistoryChart"' in html
        assert 'id="trainingHistoryTable"' in html
        assert "Evolución del ROC AUC" in html
        assert "Métricas detalladas" in html
        assert "Matriz de confusión" in html

    def test_dashboard_page_migrated(self):
        html = _read(os.path.join(TEMPLATES, "index.html"))
        assert "/static/js/dashboard.js" in html
        assert "<style" not in html
        assert "onclick=" not in html
        assert os.path.isfile(os.path.join(STATIC, "js", "dashboard.js"))

    def test_no_template_has_inline_scripts_or_handlers(self):
        import glob
        for path in glob.glob(os.path.join(TEMPLATES, "*.html")):
            name = os.path.basename(path)
            html = _read(path)
            assert "<style" not in html, name
            assert "onclick=" not in html, name
            assert "onchange=" not in html, name

    def test_theme_js_has_no_injected_styles(self):
        js = _read(os.path.join(STATIC, "theme.js"))
        assert "injectStyles" not in js
        assert "createElement('style')" not in js

    def test_app_css_has_light_theme_tokens(self):
        css = _read(os.path.join(STATIC, "css", "app.css"))
        assert '[data-theme="light"]' in css

    def test_csp_scripts_not_unsafe_inline(self):
        from web.app import app
        with app.test_client() as client:
            csp = client.get("/health").headers.get("Content-Security-Policy", "")
        assert "script-src 'self'" in csp
        assert "script-src 'self' 'unsafe-inline'" not in csp
