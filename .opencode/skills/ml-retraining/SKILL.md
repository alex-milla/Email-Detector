# Skill: Reentrenamiento de Modelos con Features QR

## Alcance
Guía completa para reentrenar el ensemble de Email-Detector tras añadir las 9 features QR.

## Contexto
- Se añaden 9 features nuevas: `qr_count`, `qr_url_count`, `qr_in_inline_image`, `qr_redirect_chain_max`, `qr_uses_shortener`, `qr_uses_js_redirect`, `qr_final_url_entropy_max`, `qr_domain_mismatch`, `qr_url_length_max`
- Los modelos antiguos NO son compatibles (feature_names cambia)
- `predict.py` usa `features.get(fn, 0)` con default 0, así que correos antiguos con modelo nuevo funcionan
- El modelo nuevo NO funciona con extractor antiguo (rompe)

## Fases del reentrenamiento

### Paso 1: Backup
```bash
cp -r models/ models-backup-$(date +%Y%m%d)/
cp models/model_metadata.json models-backup-$(date +%Y%m%d)/
```

### Paso 2: Dataset con QR
Necesitas correos con QR en ambas clases (benigno/malicioso). Opciones:

**Opción A: Dataset sintético**
```python
import qrcode, email.mime.multipart, email.mime.text, email.mime.image
import os

os.makedirs("data/synthetic_qr/phishing", exist_ok=True)
os.makedirs("data/synthetic_qr/benign", exist_ok=True)

# Phishing con QR malicioso
for i in range(50):
    msg = email.mime.multipart.MIMEMultipart()
    msg["Subject"] = f"Urgent invoice #{i}"
    msg.attach(email.mime.text.MIMEText("<p>Please scan to pay</p>", "html"))
    
    img = qrcode.make(f"https://bit.ly/malicious{i}")
    buf = io.BytesIO(); img.save(buf, format="PNG")
    img_part = email.mime.image.MIMEImage(buf.getvalue())
    img_part.add_header("Content-Disposition", "inline", filename="invoice.png")
    msg.attach(img_part)
    
    with open(f"data/synthetic_qr/phishing/qr_{i}.eml", "wb") as f:
        f.write(msg.as_bytes())

# Benigno con QR legítimo (ej: confirmación de evento)
for i in range(50):
    msg = email.mime.multipart.MIMEMultipart()
    msg["Subject"] = f"Event confirmation #{i}"
    msg.attach(email.mime.text.MIMEText("<p>Scan for details</p>", "html"))
    
    img = qrcode.make(f"https://legit-events.example.com/details/{i}")
    buf = io.BytesIO(); img.save(buf, format="PNG")
    img_part = email.mime.image.MIMEImage(buf.getvalue())
    img_part.add_header("Content-Disposition", "inline", filename="event.png")
    msg.attach(img_part)
    
    with open(f"data/synthetic_qr/benign/qr_{i}.eml", "wb") as f:
        f.write(msg.as_bytes())
```

**Opción B: Datasets públicos**
- PhishTank: muestras con QR desde 2023
- Enron + añadir QR benignos manualmente

**Opción C: Feedback histórico**
- Reprocesar correos ya etiquetados que tengan adjuntos imagen

### Paso 3: Re-extraer features
```bash
# Con el NUEVO extract_features.py (con features QR activadas)
python scripts/extract_features.py --batch data/phishing/ --output data/processed/phishing_v2.csv --label 1
python scripts/extract_features.py --batch data/benign/   --output data/processed/benign_v2.csv   --label 0

# Añadir dataset sintético si se generó
python scripts/extract_features.py --batch data/synthetic_qr/phishing --output data/processed/syn_phish.csv --label 1
python scripts/extract_features.py --batch data/synthetic_qr/benign   --output data/processed/syn_benign.csv --label 0
```

### Paso 4: Entrenar
```bash
cat data/processed/*_v2.csv data/processed/syn_*.csv > data/processed/full_v2.csv
python scripts/train_model.py --csv data/processed/full_v2.csv
```

### Paso 5: Verificar
```bash
# Verificar que feature_names incluye qr_*
cat models/model_metadata.json | python -m json.tool | grep qr_

# Verificar que el mejor modelo mejora (o al menos no empeora)
# Comparar AUC con backup anterior
```

### Paso 6: Validación cruzada
```bash
# Test con correos antiguos (deben seguir funcionando)
python scripts/predict.py data/test/old_email_without_qr.eml --skip-vt

# Test con correos nuevos con QR
python scripts/predict.py data/test/new_email_with_qr.eml --skip-vt
```

## Consideraciones importantes
1. **Balance de clases**: Si añades 100 correos con QR phishing y 0 benignos con QR, el modelo puede sobreajustar. Asegúrate de balancear.
2. **Features default**: `predict.py` ya hace `features.get(fn, 0)`, pero `train_model.py` usa pandas y rellena NaN con 0 automáticamente si todas las filas tienen las mismas columnas.
3. **Anti-Clanker**: Las features `clanker_*` se entrenan en modelo separado. No se ven afectadas.
4. **GPU**: Si usas GPU, asegúrate de que el entorno tiene CUDA disponible.

## Rollback
Si algo falla:
```bash
rm -rf models/
cp -r models-backup-YYYYMMDD/ models/
# Revertir código de extract_features.py a versión anterior
```

## Métricas de éxito
- AUC del mejor modelo >= AUC anterior (o dentro de ±0.02)
- Todos los tests de `validate_release.py` pasan
- `predict.py` funciona con correos con y sin QR
