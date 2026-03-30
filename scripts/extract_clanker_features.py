"""extract_clanker_features.py — Motor de extracción de features Anti-Clanker.

Lee clanker_rules.yaml y genera un vector de features numérico a partir del
HTML raw de un correo. Se integra con extract_features.py del ensemble.
"""
import os
import re
import logging
import time
from typing import Dict, Any, Optional
from functools import lru_cache

logger = logging.getLogger(__name__)

# ── Constantes ────────────────────────────────────────────────────────────────
INSTALL_DIR  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_FILE   = os.path.join(INSTALL_DIR, "config", "clanker_rules.yaml")
_SEVERITY_MAP = {"low": 0.2, "medium": 0.5, "high": 0.8, "critical": 1.0}
_CACHE_TTL    = 300  # segundos entre recargas del YAML

_rules_cache: Optional[Dict] = None
_rules_mtime: float = 0.0
_rules_loaded: float = 0.0


# ── Carga y caché de reglas ───────────────────────────────────────────────────
def _load_rules() -> Dict:
    """Carga clanker_rules.yaml con hot-reload basado en mtime."""
    global _rules_cache, _rules_mtime, _rules_loaded
    now = time.time()
    try:
        mtime = os.path.getmtime(RULES_FILE)
    except OSError:
        logger.warning("clanker_rules.yaml no encontrado: %s", RULES_FILE)
        return {"meta": {}, "rules": []}

    if (_rules_cache is not None
            and mtime == _rules_mtime
            and now - _rules_loaded < _CACHE_TTL):
        return _rules_cache

    try:
        import yaml
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        _rules_cache = data
        _rules_mtime = mtime
        _rules_loaded = now
        logger.debug("clanker_rules.yaml cargado: %d reglas",
                     len(data.get("rules", [])))
    except Exception as e:
        logger.error("Error cargando clanker_rules.yaml: %s", e)
        _rules_cache = _rules_cache or {"meta": {}, "rules": []}
    return _rules_cache


def get_active_rules():
    """Devuelve las reglas activas con el regex compilado."""
    data = _load_rules()
    active = []
    for rule in data.get("rules", []):
        if not rule.get("enabled", True):
            continue
        try:
            compiled = re.compile(rule["pattern"], re.IGNORECASE | re.DOTALL)
            active.append({**rule, "_compiled": compiled})
        except re.error as e:
            logger.warning("Regex inválido en %s: %s", rule.get("id"), e)
    return active


# ── Extracción de zonas del HTML ─────────────────────────────────────────────
def _extract_zones(html_raw: str) -> Dict[str, str]:
    """Extrae zonas del HTML para aplicar cada regla en su target correcto."""
    zones: Dict[str, str] = {
        "html_comment": "",
        "html_body":    html_raw,
        "href_attr":    "",
        "src_attr":     "",
        "inline_style": "",
        "script_block": "",
    }
    # Comentarios HTML
    zones["html_comment"] = " ".join(re.findall(r'<!--(.*?)-->', html_raw,
                                                  re.DOTALL | re.IGNORECASE))
    # Atributos href
    zones["href_attr"] = " ".join(re.findall(r'href=["\']([^"\']*)["\']',
                                              html_raw, re.IGNORECASE))
    # Atributos src
    zones["src_attr"] = " ".join(re.findall(r'\bsrc=["\']([^"\']*)["\']',
                                             html_raw, re.IGNORECASE))
    # Estilos inline
    zones["inline_style"] = " ".join(re.findall(r'style=["\']([^"\']*)["\']',
                                                  html_raw, re.IGNORECASE))
    # Bloques <style> y <script>
    zones["script_block"] = " ".join(
        re.findall(r'<(?:style|script)[^>]*>(.*?)</(?:style|script)>',
                   html_raw, re.DOTALL | re.IGNORECASE))
    return zones


# ── Feature extraction principal ─────────────────────────────────────────────
def extract_clanker_features(html_raw: str) -> Dict[str, Any]:
    """
    Recibe el HTML raw de un correo y devuelve un diccionario de features
    compatible con el vector de features global del ensemble.

    Features generadas:
      clanker_total_matches        — total de reglas que hicieron match
      clanker_weighted_score       — suma ponderada por severidad
      clanker_score_<category>     — score por categoría
      clanker_has_placeholder      — binario: algún placeholder detectado
      clanker_has_yellow_highlight — binario: highlight amarillo detectado
      clanker_has_localhost_url    — binario: URL localhost/ejemplo detectada
      clanker_comment_ratio        — ratio comentarios sospechosos / total
      clanker_unique_categories    — número de categorías distintas con match
    """
    features: Dict[str, Any] = {
        "clanker_total_matches":        0,
        "clanker_weighted_score":       0.0,
        "clanker_has_placeholder":      0,
        "clanker_has_yellow_highlight": 0,
        "clanker_has_localhost_url":    0,
        "clanker_comment_ratio":        0.0,
        "clanker_unique_categories":    0,
    }
    # Scores por categoría
    categories = [
        "conversational_comment", "placeholder", "visual_slop",
        "yellow_highlight", "localhost_url", "verbose_code_comment",
        "overengineered_html",
    ]
    for cat in categories:
        features[f"clanker_score_{cat}"] = 0.0

    if not html_raw:
        return features

    rules = get_active_rules()
    zones = _extract_zones(html_raw)

    matched_categories = set()
    suspicious_comments = 0
    total_comments = max(1, len(re.findall(r'<!--', html_raw)))

    for rule in rules:
        target_text = zones.get(rule.get("target", "html_body"), html_raw)
        compiled: re.Pattern = rule["_compiled"]
        matches = compiled.findall(target_text)
        if not matches:
            continue

        n = len(matches)
        sev = _SEVERITY_MAP.get(rule.get("severity", "medium"), 0.5)
        cat = rule.get("category", "unknown")

        features["clanker_total_matches"] += n
        features["clanker_weighted_score"] += sev * n
        features[f"clanker_score_{cat}"] = (
            features.get(f"clanker_score_{cat}", 0.0) + sev * n
        )
        matched_categories.add(cat)

        # Binarios de alto nivel
        if cat == "placeholder":
            features["clanker_has_placeholder"] = 1
        if cat == "yellow_highlight":
            features["clanker_has_yellow_highlight"] = 1
        if cat == "localhost_url":
            features["clanker_has_localhost_url"] = 1
        if cat == "conversational_comment":
            suspicious_comments += n

    features["clanker_comment_ratio"] = round(
        suspicious_comments / total_comments, 4)
    features["clanker_unique_categories"] = len(matched_categories)

    # Normalizar weighted_score al rango [0, 1] (cap en 10 reglas críticas)
    features["clanker_weighted_score"] = round(
        min(features["clanker_weighted_score"] / 10.0, 1.0), 4)

    return features


# ── API pública para get_clanker_score() ─────────────────────────────────────
def get_clanker_score(html_raw: str) -> float:
    """Devuelve el score Anti-Clanker normalizado [0, 1]."""
    feats = extract_clanker_features(html_raw)
    return feats.get("clanker_weighted_score", 0.0)


# ── Metadata de reglas ────────────────────────────────────────────────────────
def get_rules_meta() -> Dict:
    """Devuelve los metadatos del fichero de reglas."""
    return _load_rules().get("meta", {})


def get_rules_list() -> list:
    """Devuelve la lista de reglas (con/sin habilitadas)."""
    return _load_rules().get("rules", [])


if __name__ == "__main__":
    import sys
    import json
    test_html = sys.argv[1] if len(sys.argv) > 1 else ""
    if not test_html:
        test_html = """
        <!-- Sure! Here is the email you requested. Remember to replace [Your Name] -->
        <html><body>
        <p style="background-color: yellow;">Hello [Customer],</p>
        <a href="http://localhost:8080/track">Click here</a>
        <!-- End of footer section -->
        </body></html>
        """
    feats = extract_clanker_features(test_html)
    print(json.dumps(feats, indent=2))