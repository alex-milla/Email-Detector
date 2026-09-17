# Email Malware Detector - Checkpoint Sprint 3 (4.2)

**Fecha:** 2026-09-18  
**Versión:** 2.1.7 (sin release)  
**Último commit:** 310f1f6 (fix: instalar Playwright Chromium en Dockerfile)  
**Tag:** v2.1.6 (ultima publicada)  
**Release:** https://github.com/alex-milla/Email-Detector/releases/tag/v2.1.6 (ID: 391122802)  
**Branch:** main

---

## Cambios Implementados

### 4.2 Instalar Playwright Chromium en Dockerfile → ✅ COMPLETADO

**Problema:** `requirements.txt` incluye `playwright` y el README documenta `QR_USE_JS_RESOLVER=true` (default), pero el Dockerfile no instalaba el navegador Chromium. La deteccion de QR con redirecciones JS fallaba en Docker.

**Solucion:** Anadido `RUN python -m playwright install chromium --with-deps` despues del `pip install -r requirements.txt`.

**Archivo modificado:** `Dockerfile`

```dockerfile
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright: instalar navegador Chromium para deteccion de redirecciones JS
RUN python -m playwright install chromium --with-deps

COPY . .
```

El flag `--with-deps` instala automaticamente las dependencias de sistema que Chromium necesita (librerias graficas, fuentes, etc.).

---

## Verificacion

- `pytest tests/test_health.py` → 2/2 PASSED
- Dockerfile no se puede construir en este entorno (no Docker), pero la sintaxis es correcta

---

## Estado de Mejoras

### Sprint 1 (Critico) - ✅ COMPLETOS
| # | Cambio | Status |
|---|--------|--------|
| 1.1 | Fix CSRF protection invertida | ✅ v2.1.3 |
| 1.2 | Autenticar /metrics | ✅ v2.1.3 |
| 1.3 | Restringir SIEM webhook y monitoring_status | ✅ v2.1.3 |
| 2.1 | Fix version hardcoded "2.0.0" | ✅ v2.1.3 |

### Sprint 2 (Alto) - ✅ COMPLETOS
| # | Cambio | Status |
|---|--------|--------|
| 1.4 | Scoping feedback_stats por usuario | ✅ v2.1.3 |
| 1.5 | Eliminar fallback inseguro de SECRET_KEY | ✅ v2.1.3 |
| 2.2 | Fix calculo de recent_24h | ✅ v2.1.3 |
| 4.1 | Eliminar version key deprecado | ✅ v2.1.3 |

### Sprint 3 (Medio) - ✅ COMPLETOS (5/5)
| # | Cambio | Status |
|---|--------|--------|
| 2.3 | Anadir columnas totp_secret y theme al schema | ✅ v2.1.4 |
| 2.4 | Refactorizar mutacion de os.environ | ✅ v2.1.4 |
| 3.1 | Simplificar normalize_result (unicode) | ✅ v2.1.5 |
| 3.2 | Centralizar sys.path.insert | ✅ v2.1.6 |
| 4.2 | Instalar Playwright en Dockerfile | ✅ v2.1.7 (este commit) |

### Sprint 4 (Bajo) - PENDIENTES
| # | Cambio | Status |
|---|--------|--------|
| 3.3 | Migrar print() a logging | Pendiente |

---

## Historial de Commits

| Hash | Mensaje |
|------|---------|
| 310f1f6 | fix: instalar Playwright Chromium en Dockerfile (Sprint 3 - punto 4.2) |
| 60502a9 | docs: actualizar checkpoint con release v2.1.6 |
| 7d168c0 | fix: actualizar version.json con release_id 391122802 |
| 701be44 | docs: checkpoint Sprint 3 - punto 3.2 completado |
| a383852 | refactor: centralizar sys.path.insert en web/__init__.py |
| c318474 | docs: actualizar checkpoint con correccion de zip_url |
| bf48536 | fix: corregir zip_url en version.json |
| 56989b6 | docs: actualizar checkpoint con release v2.1.5 |
| fe9898c | feat: simplificar normalize_result con unicodedata |

---

## Resumen

| Metrica | Valor |
|---------|-------|
| **Version** | 2.1.7 (sin release) |
| **Commits nuevos** | 1 |
| **Archivos cambiados** | 3 |
| **Tests** | 2/2 PASSED |
| **Sprint 3** | ✅ COMPLETO (5/5) |
| **Pendientes** | 3.3 (print→logging) — Sprint 4 |

**Sprint 3 completado al 100%.** Solo queda el punto 3.3 (Sprint 4).

---

*Generado el: 2026-09-18*
*Anterior: md/CHECKPOINT_2026-09-18_V3.md*
