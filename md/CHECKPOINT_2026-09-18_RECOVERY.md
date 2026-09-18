# Email Malware Detector - Checkpoint Post-Incidente y Recovery

**Fecha:** 2026-09-18  
**Version del proyecto:** 2.2.2  
**Ultimo commit:** c274e8d (fix: actualizar VERSION y version.json a v2.2.2)  
**Tag:** v2.2.2  
**Release:** https://github.com/alex-milla/Email-Detector/releases/tag/v2.2.2 (ID: 391136161)  
**Branch:** main

---

## Resumen del Incidente

### Que paso

1. Se implemento Anti-Clanker v1.2.0 (11 reglas nuevas, 4 features DOM, bug fix html_comment)
2. Se creo release v2.2.1 en GitHub
3. **El archivo `config/clanker_rules.yaml` contenia caracteres Unicode (ÂÂ) en separadores de comentarios** que se corrompieron al pasar por el CDN de GitHub (raw.githubusercontent.com)
4. El YAML se volvio invalido en GitHub, causando que el updater descargara un archivo corrupto
5. El servicio en el LXC (ORO-LXC-03) cayo al intentar cargar el YAML corrupto
6. Al hacer rollback a v2.1.8, se descubrieron problemas preexistentes:
   - Directorio `logs/` con permisos incorrectos (root en vez de emaildetector)
   - `config/.env` faltante en el repo git (esta en .gitignore, solo existe en /opt/)

### Causa raiz

- **Bug de encoding:** El archivo `clanker_rules.yaml` usaba caracteres Unicode `ÂÂÂ` (U+2550, BOX DRAWINGS DOUBLE HORIZONTAL) en comentarios de separacion. Git los almacena bien en UTF-8, pero el CDN de GitHub (raw.githubusercontent.com) los sirve con encoding incorrecto, corrompiendo los bytes.
- **Bug preexistente de permisos:** El directorio `/opt/email-detector/logs/` fue creado como root en algun momento, pero el servicio corre como usuario `emaildetector`. Esto no tenia relacion con la actualizacion, pero se manifesto al reiniciar.

### Impacto

- Servicio caido ~30 minutos
- Sin perdida de datos ni modelos
- Los modelos en `/opt/email-detector/models/` nunca fueron tocados (el updater tiene lista blanca que excluye `models/`)

---

## Recovery

### Pasos realizados en el LXC (ORO-LXC-03)

1. **Rollback a v2.1.8** (estable, sin caracteres Unicode problematicos)
   ```bash
   cd ~/Email-Detector
   git stash
   git checkout v2.1.8
   ```

2. **Fix permisos de logs** (causa real del crash tras reinicio)
   ```bash
   mkdir -p /opt/email-detector/logs
   chown -R emaildetector:emaildetector /opt/email-detector/logs
   chmod 755 /opt/email-detector/logs
   ```

3. **Regenerar SECRET_KEY** (faltaba en el repo git, solo en /opt/)
   ```bash
   SECRET=$(python3 -c "import secrets; print(secrets.token_hex(32))")
   echo "SECRET_KEY=$SECRET" > ~/Email-Detector/config/.env
   ```

4. **Verificacion de modelos** (siempre estuvieron intactos en /opt/)
   ```bash
   ls -la /opt/email-detector/models/
   # email_classifier.joblib: 2.9MB (modelo real de mayo 2026)
   # anti_clanker.joblib: 340KB
   ```

5. **Pull a main** (con el fix del YAML ya aplicado)
   ```bash
   git checkout main
   git pull origin main
   ```

6. **Reiniciar servicio**
   ```bash
   systemctl restart email-detector
   systemctl status email-detector --no-pager
   # Active: active (running)
   ```

7. **Verificacion final**
   ```bash
   curl -sk https://localhost:5000/health
   # {"model_trained":true,"models_count":10,"status":"ok","version":"2.2.0"}
   ```

---

## Estado del LXC (ORO-LXC-03)

### Arquitectura de deployment

| Ruta | Funcion | Propietario |
|------|---------|-------------|
| `/root/Email-Detector/` | Repo git (clone) | root |
| `/opt/email-detector/` | Deployment activo (gunicorn) | emaildetector |
| `/opt/email-detector/models/` | Modelos entrenados (NO en git) | emaildetector |
| `/opt/email-detector/config/.env` | SECRET_KEY y config (NO en git) | emaildetector |
| `/opt/email-detector/config/ssl/` | Certificados SSL (NO en git) | emaildetector |
| `/opt/email-detector/logs/` | Logs del servicio | emaildetector |

### Servicio systemd

```
[Unit]
Description=Email Malware Detector

[Service]
ExecStart=/opt/email-detector/venv/bin/gunicorn --bind 0.0.0.0:5000 --workers 2 --timeout 300 --preload --certfile=/opt/email-detector/config/ssl/cert.pem --keyfile=/opt/email-detector/config/ssl/key.pem web.app:app
```

### Estado actual

| Elemento | Valor | Estado |
|----------|-------|--------|
| Servicio | active (running) | OK |
| Health | `{"status":"ok","model_trained":true}` | OK |
| Version en /opt/ | 2.2.0 | Pendiente de actualizar via web |
| Version en git (main) | 2.2.2 | OK |
| Modelos | Intactos (2.9MB classifier + 340KB clanker) | OK |
| SECRET_KEY | Configurada en /opt/email-detector/config/.env | OK |
| Logs | Permisos correctos (emaildetector) | OK |
| SSL | Certificados en /opt/email-detector/config/ssl/ | OK |

---

## Anti-Clanker v1.2.0 - Cambios Implementados

### Nuevas reglas (11 reglas, 3 categorias)

| ID | Categoria | Patron | Severidad |
|----|-----------|--------|-----------|
| CLK-025 | overengineered_css | `orphans\s*:\s*\d+` | Alta |
| CLK-026 | overengineered_css | `widows\s*:\s*\d+` | Alta |
| CLK-027 | overengineered_css | `font-variant-ligatures\s*:\s*normal` | Alta |
| CLK-027b | overengineered_css | `hyphens\s*:\s*(?:auto\|manual\|none)` | Media |
| CLK-027c | overengineered_css | `text-rendering\s*:\s*(?:optimizeSpeed\|...)` | Media |
| CLK-028 | clipboard_abuse | `navigator\.clipboard\.writeText\s*\(` | Critica |
| CLK-029 | clipboard_abuse | `navigator\.clipboard\.writeText\s*\([^)]*(?:powershell\|cmd\|...)` | Critica |
| CLK-030 | prompt_injection | `<!--\s*(?:IGNORE ALL PREVIOUS INSTRUCTIONS\|...)` | Alta |
| CLK-031 | prompt_injection | `<!--\s*(?:SYSTEM PROMPT\|USER PROMPT\|...)` | Alta |
| CLK-032 | prompt_injection | `<!--\s*(?:You are a\|Act as a\|...)` | Alta |

### Nuevas features DOM (4)

| Feature | Que mide |
|---------|----------|
| `clanker_css_property_count` | Numero de propiedades CSS unicas |
| `clanker_suspicious_css_count` | Propiedades CSS sospechosas (orphans, widows, etc.) |
| `clanker_script_block_count` | Numero de bloques `<script>` |
| `clanker_event_handler_count` | Event handlers inline (onclick, onload, etc.) |

### Nuevos bonus estructurales (3)

| Condicion | Bonus |
|-----------|-------|
| 3+ propiedades CSS sospechosas | +0.15 |
| 5+ event handlers inline | +0.10 |
| 1+ bloques `<script>` | +0.10 |

### Bug fix: zona html_comment

**Antes:** `re.findall(r'<!--(.*?)-->', html_raw, ...)` extraia solo el contenido sin delimitadores
**Despues:** `re.findall(r'(<!--.*?-->)', html_raw, ...)` incluye los delimitadores `<!-- -->`

Las reglas CLK-001 a CLK-024 con `target: html_comment` ahora funcionan correctamente.

### Bug fix: encoding Unicode

**Antes:** Comentarios con `ÂÂÂ` (U+2550) se corrompian en GitHub CDN
**Despues:** Comentarios con `===` (ASCII puro)

---

## Releases Generadas

| Version | Tag | Release ID | Fecha | Descripcion |
|---------|-----|------------|-------|-------------|
| 2.2.1 | v2.2.1 | 391131173 | 2026-09-18 | Anti-Clanker v1.2.0 (retirada por bug encoding) |
| 2.2.2 | v2.2.2 | 391136161 | 2026-09-18 | Fix encoding clanker_rules.yaml |

---

## Commits (este incidente)

| Hash | Mensaje |
|------|---------|
| c274e8d | fix: actualizar VERSION y version.json a v2.2.2 |
| 72f60ce | fix: corregir caracteres Unicode en clanker_rules.yaml |
| bc3a786 | fix: alinear VERSION y version.json a v2.2.1 |
| dc00a62 | fix: actualizar version.json con release_id 391131173 |
| 0ffb8e0 | feat: Anti-Clanker v1.2.0 - deteccion CSS, Clipboard, Prompt Injection |

---

## Lecciones Aprendidas

### 1. No usar caracteres Unicode en archivos YAML

Los separadores `ÂÂÂ` (BOX DRAWINGS) se corrompen al pasar por el CDN de GitHub. Usar solo ASCII en archivos de configuracion.

**Aplicado:** Todos los separadores cambiados a `===` (ASCII puro).

### 2. El updater es seguro (no borra modelos)

El updater tiene una lista blanca estricta (`ALLOWED_PATHS`) que solo permite:
- `web/`
- `scripts/`
- `config/clanker_rules.yaml`
- `VERSION`
- `version.json`
- `requirements.txt`

**No toca:** `models/`, `data/`, `config/.env`, `config/ssl/`, `logs/`, `*.db`, `*.joblib`

### 3. Permisos de logs

El directorio `/opt/email-detector/logs/` debe ser propiedad de `emaildetector:emaildetector`. Si se crea como root, el servicio crashea con `PermissionError` al intentar escribir `audit.log`.

### 4. Modelos no estan en git

Los archivos `*.joblib` estan en `.gitignore`. Los modelos solo existen en `/opt/email-detector/models/`. Un `git checkout` o `git pull` no los borra, pero tampoco los restaura si se pierden.

### 5. Probar el YAML antes de pushear

Antes de pushear cambios a `clanker_rules.yaml`, verificar que:
```bash
python3 -c "import yaml; yaml.safe_load(open('config/clanker_rules.yaml'))"
```
Y despues de pushear, verificar que GitHub lo sirve correctamente:
```bash
curl -s https://raw.githubusercontent.com/alex-milla/Email-Detector/main/config/clanker_rules.yaml | python3 -c "import yaml,sys; yaml.safe_load(sys.stdin)"
```

---

## Verificacion Final

| Check | Resultado |
|-------|----------|
| YAML local valido | 34 reglas, version 1.2.0 |
| YAML en GitHub API valido | 34 reglas, version 1.2.0 |
| Servicio LXC activo | active (running) |
| Health endpoint | `{"status":"ok","model_trained":true}` |
| Modelos intactos | 2.9MB + 340KB en /opt/ |
| SECRET_KEY configurada | En /opt/email-detector/config/.env |
| Permisos logs correctos | emaildetector:emaildetector |

---

## Historial de Versiones

| Version | Fecha | Cambios |
|---------|-------|---------|
| 2.1.8 | 2026-09-18 | Sprint 4: migrar print() a logging |
| 2.2.0 | 2026-09-18 | Anti-Clanker v1.2.0 (11 reglas nuevas) |
| 2.2.1 | 2026-09-18 | Release con bug de encoding (retirada) |
| **2.2.2** | **2026-09-18** | **Fix encoding + Anti-Clanker v1.2.0** |

---

## Proximos Pasos

1. **Actualizar LXC de 2.2.0 a 2.2.2 via web** (updater automatico)
   - El updater solo reemplazara codigo y reglas YAML
   - Los modelos, .env, certificados y logs no se tocan
2. **Hacer snapshot del LXC** despues de verificar que 2.2.2 funciona
3. **Reentrenar Anti-Clanker** con datos reales cuando sea posible
   - El modelo actual en /opt/ fue entrenado en mayo 2026 (pre-v1.2.0)
   - Las nuevas features (CSS, script, event) no estan en el modelo
   - El score heuristico funciona sin modelo, pero el modelo no las usa

---

*Generado el: 2026-09-18*  
*Anterior: md/CHECKPOINT_2026-09-18_FINAL.md*
