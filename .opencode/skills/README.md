# Skills del Proyecto Email-Detector v2.0 (QR Detection)

## Estructura de skills

| Skill | Directorio | Propósito | Cuándo usar |
|---|---|---|---|
| **qr-detection-dev** | `.opencode/skills/qr-detection-dev/` | Desarrollo de módulos QR | Fases 1-3 |
| **cybersecurity-qr** | `.opencode/skills/cybersecurity-qr/` | Seguridad SSRF/DoS | Fases 1, 5 |
| **qa-testing** | `.opencode/skills/qa-testing/` | Testing unitario/integración | Todas las fases |
| **ml-retraining** | `.opencode/skills/ml-retraining/` | Reentrenamiento de modelos | Fase 4 |
| **release-management** | `.opencode/skills/release-management/` | Releases y deployment | Fase 5 |

## Uso recomendado por modelo

### Kimi Code (desarrollo principal)
- Fases 1, 2, 3: Desarrollo de código Python y frontend
- Fase 5: Integración final y fixes

### Opencode/Deepseek API (análisis profundo)
- Fase 4: Análisis de features, tuning de hiperparámetros, evaluación de modelo
- Revisión de seguridad avanzada (análisis estático de vulnerabilidades)

## Fases del proyecto

1. **Fase 1 — Módulos nuevos**: `qr_decoder.py` + `url_resolver.py` + tests
2. **Fase 2 — Extractor metadata**: Modificar `extract_features.py` (solo metadata)
3. **Fase 3 — Frontend**: Añadir sección QR a `index.html`
4. **Fase 4 — Reentrenamiento**: Dataset + entrenamiento + validación
5. **Fase 5 — Activación ML + Release**: Features ML + release v2.0.0

## Tokens y acceso
- GitHub PAT: configurado en `config/.env` como `GITHUB_TOKEN`
- Repo: `https://github.com/alex-milla/Email-Detector`
