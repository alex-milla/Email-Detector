#!/usr/bin/env python3
"""
plugin_loader.py — Sistema de plugins para Email Malware Detector.

Los plugins son archivos .py en el directorio plugins/ que exportan
una función `analyze(features, metadata) -> dict`.

El diccionario devuelto puede contener:
  - Nuevas features (se añaden al vector del modelo)
  - "boost": ajuste del risk_score (+/-)
  - "tags": etiquetas para mostrar en la UI

Uso:
    from plugin_loader import run_plugins
    extra_feats, boost, tags = run_plugins(features, metadata)

Estructura de plugins/:
    plugins/
    ├── __init__.py
    ├── example_plugin.py      # plugin de ejemplo
    └── mis_reglas.py          # plugin personalizado
"""

import os
import sys
import importlib
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

PLUGINS_DIR = os.path.join(os.path.dirname(__file__), "..", "plugins")


def discover_plugins():
    """Encuentra todos los plugins disponibles en plugins/."""
    plugins_dir = Path(PLUGINS_DIR)
    if not plugins_dir.exists():
        return []
    plugins = []
    for f in plugins_dir.glob("*.py"):
        if f.name == "__init__.py":
            continue
        plugins.append(f.stem)
    return sorted(plugins)


def load_plugin(plugin_name):
    """Carga un plugin por nombre."""
    try:
        sys.path.insert(0, PLUGINS_DIR)
        module = importlib.import_module(plugin_name)
        if hasattr(module, "analyze") and callable(module.analyze):
            return module.analyze
        else:
            logger.warning("Plugin %s no exporta función analyze()", plugin_name)
            return None
    except Exception as e:
        logger.error("Error cargando plugin %s: %s", plugin_name, e)
        return None


def run_plugins(features, metadata):
    """Ejecuta todos los plugins y combina resultados."""
    extra_features = {}
    total_boost = 0.0
    all_tags = []

    for name in discover_plugins():
        try:
            analyze_fn = load_plugin(name)
            if analyze_fn is None:
                continue
            result = analyze_fn(features, metadata)
            if not isinstance(result, dict):
                continue

            if "features" in result and isinstance(result["features"], dict):
                extra_features.update(result["features"])

            boost = float(result.get("boost", 0.0))
            total_boost += boost

            tags = result.get("tags", [])
            if isinstance(tags, list):
                all_tags.extend(tags)

            logger.info("Plugin %s: boost=%.2f tags=%s", name, boost, tags)
        except Exception as e:
            logger.error("Plugin %s falló: %s", name, e)

    return extra_features, total_boost, all_tags


def create_example_plugin():
    """Crea un plugin de ejemplo si no existe."""
    example_path = os.path.join(PLUGINS_DIR, "ejemplo.py")
    if os.path.exists(example_path):
        return
    os.makedirs(PLUGINS_DIR, exist_ok=True)
    with open(os.path.join(PLUGINS_DIR, "__init__.py"), "w") as f:
        f.write("")
    with open(example_path, "w") as f:
        f.write('''"""
Plugin de ejemplo para Email Malware Detector.
Añade una feature personalizada y ajusta el riesgo si se detectan
ciertos patrones en el asunto o remitente.
"""

import re


def analyze(features, metadata):
    """
    Recibe el diccionario de features y metadata del correo.
    Devuelve dict con:
      - features: nuevas features para el modelo
      - boost: ajuste al risk_score (-1.0 a 1.0)
      - tags: etiquetas para la UI
    """
    result = {"features": {}, "boost": 0.0, "tags": []}

    subject = metadata.get("subject", "")
    from_addr = metadata.get("from", "")

    # Ejemplo: detectar dominios sospechosos en el remitente
    suspicious_domains = {"tempmail.com", "mailinator.com", "guerrillamail.com"}
    for domain in suspicious_domains:
        if domain in from_addr.lower():
            result["boost"] += 0.15
            result["tags"].append(f"dominio_temporal:{domain}")

    # Ejemplo: feature personalizada (longitud del asunto normalizada)
    result["features"]["custom_subject_ratio"] = round(
        len(subject) / max(len(metadata.get("body_html", "")
                            or metadata.get("body_text", "") or " "), 1), 4
    )

    return result
''')


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    create_example_plugin()
    print("Plugins disponibles:", discover_plugins())
    for name in discover_plugins():
        fn = load_plugin(name)
        if fn:
            print(f"  {name}: OK")
