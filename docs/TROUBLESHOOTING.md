# Troubleshooting — Email Malware Detector

## Índice

- [Despliegue falla en LXC sin privilegios](#despliegue-falla-en-lxc-sin-privilegios)
- [No puedo instalar dependencias del sistema](#no-puedo-instalar-dependencias-del-sistema)
- [El servicio no arranca](#el-servicio-no-arranca)
- [Puerto 5000 ocupado](#puerto-5000-ocupado)
- [xgboost/lightgbm/catboost fallan al instalar](#xgboostlightgbmcatboost-fallan-al-instalar)
- [El modelo no predice (Anti-Clanker)](#el-modelo-no-predice-anti-clanker)
- [Cómo actualizar sin perder datos](#cómo-actualizar-sin-perder-datos)

---

## Despliegue falla en LXC sin privilegios

**Síntoma**: `./deploy.sh` falla al crear usuarios de sistema o al intentar usar systemd.

**Causa**: Los contenedores LXC sin privilegios no permiten crear usuarios ni gestionar systemd.

**Solución**:
1. Ejecuta `./deploy.sh` sin `sudo`.
2. Cuando pregunte "Instalar servicio systemd?", responde `n`.
3. El script generará `run.sh` y `stop.sh` para arranque manual.
4. Inicia la app:
   ```bash
   nohup ./run.sh > logs/server.log 2>&1 &
   ```

---

## No puedo instalar dependencias del sistema

**Síntoma**: `apt-get` falla con permisos denegados.

**Solución**:
- Si tienes `sudo`, instala manualmente antes de ejecutar `deploy.sh`:
  ```bash
  sudo apt-get install -y python3 python3-venv git curl wget openssl
  ```
- Si no tienes `sudo` (LXC compartido), contacta al administrador del host.

---

## El servicio no arranca

**Síntoma**: `systemctl status email-detector` muestra `failed`.

**Pasos**:
1. Revisa los logs:
   ```bash
   journalctl -u email-detector -n 50 --no-pager
   ```
2. Verifica que `config/.env` existe y tiene `SECRET_KEY` configurado.
3. Asegúrate de que el puerto no está ocupado:
   ```bash
   ss -tlnp | grep 5000
   ```
4. Prueba arrancar manualmente para ver el error exacto:
   ```bash
   cd /opt/email-detector
   source venv/bin/activate
   gunicorn --bind 0.0.0.0:5000 web.app:app
   ```

---

## Puerto 5000 ocupado

**Solución**:
- Ejecuta `./deploy.sh` de nuevo y elige otro puerto.
- O edita `config/.env` y cambia `WEB_PORT`, luego reinicia.

---

## xgboost/lightgbm/catboost fallan al instalar

**Síntoma**: `pip install xgboost` falla con errores de compilación.

**Solución**:
- Estas librerías son **opcionales**. El ensemble funciona con scikit-learn puro.
- En Debian/Ubuntu, instala dependencias de compilación:
  ```bash
  sudo apt-get install -y build-essential cmake libopenmpi-dev
  ```
- En LXC sin `build-essential`, omítelas. El script continúa automáticamente.

---

## El modelo no predice (Anti-Clanker)

**Síntoma**: El resultado siempre muestra `"anti_clanker": {"available": false}`.

**Causas**:
1. `extract_clanker_features.py` no está en `scripts/`.
2. El correo no tiene contenido HTML.

**Solución**:
- Asegúrate de que `scripts/extract_clanker_features.py` existe.
- Revisa que `config/clanker_rules.yaml` existe y tiene reglas válidas.
- El modelo Anti-Clanker requiere que el correo tenga parte HTML (`text/html`).

---

## Cómo actualizar sin perder datos

**Sistema con systemd**:
```bash
cd /opt/email-detector
git pull origin main
./deploy.sh
```

**Standalone**:
```bash
cd ~/email-detector
./stop.sh
git pull origin main
./deploy.sh
./run.sh
```

`deploy.sh` es **idempotente**: no sobrescribe `.env`, `users.db`, modelos ni datos etiquetados.
