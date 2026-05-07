# Email Malware Detector — Docker (opcional)
# Método principal de instalación: ./deploy.sh
# Este Dockerfile es una alternativa para entornos containerizados.

FROM python:3.11-slim-bookworm AS base

RUN apt-get update && apt-get install -y --no-install-recommends \
    libzbar0 \
    openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/email-detector

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p config/ssl data/raw data/samples data/processed data/labeled results logs tmp

ENV PYTHONPATH=/opt/email-detector/scripts:/opt/email-detector/web
ENV WEB_HOST=0.0.0.0
ENV WEB_PORT=5000
ENV EMAIL_DETECTOR_RELAX_SCRIPT_CHECK=1

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "--access-logfile", "logs/access.log", "--error-logfile", "logs/error.log", "web.app:app"]
