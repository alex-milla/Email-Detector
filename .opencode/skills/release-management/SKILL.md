# Skill: Gestión de Releases para Email-Detector

## Alcance
Proceso completo de release para la versión v2.0 con QR detection, incluyendo validación, tagging y publicación en GitHub.

## Pre-requisitos
- `GITHUB_TOKEN` configurado en `config/.env` (usado por `bump_version.py`)
- Script `validate_release.py` funciona

## Flujo de release (5 fases)

### Fase 1: Módulos nuevos (sin features ML)
**Cambios**: `qr_decoder.py`, `url_resolver.py`, `requirements.txt`, `install.sh`
**Riesgo**: Cero — código nuevo, no toca flujo existente
**Reversible**: Sí (borrar 2 archivos y revertir requirements)
**Tests**: `python scripts/qr_decoder.py test.png`, `python scripts/url_resolver.py https://bit.ly/3xyZ`
**Commit**: `feat(qr): add qr_decoder and url_resolver modules`

### Fase 2: Extractor (metadata only)
**Cambios**: `extract_features.py` — solo añadir QR a `metadata`, NO a `features`
**Riesgo**: Bajo — el modelo sigue igual
**Reversible**: Sí
**Tests**: Verificar que `metadata["qr_codes_found"]` existe y `features` NO tiene `qr_*`
**Commit**: `feat(qr): expose QR metadata without ML features`

### Fase 3: Frontend
**Cambios**: `web/templates/index.html` — nueva sección QR
**Riesgo**: Cero — solo UI
**Reversible**: Sí
**Tests**: Verificar modal con correo que tenga QR
**Commit**: `feat(ui): display QR codes in analysis modal`

### Fase 4: Reentrenamiento
**Cambios**: Dataset + modelos entrenados
**Riesgo**: Medio — si el modelo empeora, rollback
**Reversible**: Sí (backup de `models/`)
**Tests**: Comparar AUC, validar con `validate_release.py`
**Commit**: `feat(ml): retrain models with QR features`

### Fase 5: Activar features ML
**Cambios**: `extract_features.py` — añadir `qr_*` al dict `features`
**Riesgo**: Medio — requiere modelo nuevo
**Reversible**: Sí (revertir extract_features.py + restaurar modelos antiguos)
**Tests**: Full E2E, todos los unit tests
**Commit**: `feat(qr): enable QR features for ML prediction`
**Tag**: `v2.0.0`

## Validación obligatoria
ANTES de cada release:
```bash
python3 scripts/validate_release.py
```
Esto verifica:
- Sintaxis de todos los `.py` y `.sh`
- `web.app` importa sin errores
- `train_model.py` no ejecuta side-effects al importar
- No hay referencias a variables antes de su definición

## Comandos de release
```bash
# 1. Validar
python3 scripts/validate_release.py

# 2. Bump version (preguntará nueva versión y changelog)
python3 scripts/bump_version.py

# 3. Si bump_version falla, manual:
git add -A
git commit -m "release: v2.0.0 - QR detection"
git tag v2.0.0
git push origin main --tags

# 4. Crear release en GitHub (requiere GITHUB_TOKEN)
# bump_version.py hace esto automáticamente
```

## Notas de release (template)
```markdown
## Email-Detector v2.0.0 — QR Detection

### Novedades
- Detección de códigos QR en imágenes adjuntas e inline
- Resolución de redirecciones HTTP, meta-refresh y JavaScript
- 9 nuevas features de ML para detección de quishing
- Nueva sección en la interfaz web para visualizar QRs

### Dependencias nuevas
- pyzbar, opencv-python-headless, Pillow
- beautifulsoup4, playwright

### Cambios de infraestructura
- Requiere `libzbar0` en el sistema
- Requiere navegador Chromium para Playwright

### Breaking changes
- Modelo reentrenado obligatorio (feature_names cambia)
- Backup de `models/` recomendado antes de actualizar

### Seguridad
- Protección SSRF en resolución de URLs
- Límites de tamaño de imagen (25MB) y hops (15)
```

## Rollback de emergencia
```bash
# Restaurar modelos antiguos
cp -r models-backup-YYYYMMDD/* models/

# Revertir código
git revert HEAD  # o git checkout main -- scripts/extract_features.py

# Reiniciar servicio
sudo systemctl restart email-detector
```
