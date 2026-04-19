#!/usr/bin/env python3
"""
http_redirect.py — Redirector HTTP→HTTPS para Email Malware Detector.

Escucha en el puerto 80 y redirige toda petición a https://host:HTTPS_PORT
con código 301. Sin dependencias externas.

Variables de entorno:
  HTTP_PORT   Puerto en el que escucha (por defecto 80)
  HTTPS_PORT  Puerto HTTPS destino (por defecto 5000)
"""
import http.server
import os

HTTP_PORT  = int(os.environ.get("HTTP_PORT",  80))
HTTPS_PORT = int(os.environ.get("HTTPS_PORT", 5000))


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):  self._redirect()
    def do_POST(self): self._redirect()
    def do_HEAD(self): self._redirect()
    def do_PUT(self):  self._redirect()

    def _redirect(self):
        host   = self.headers.get("Host", "").split(":")[0]
        target = f"https://{host}:{HTTPS_PORT}{self.path}"
        self.send_response(301)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, fmt, *args):
        pass  # silenciar logs — el servicio systemd ya los gestiona


if __name__ == "__main__":
    server = http.server.HTTPServer(("0.0.0.0", HTTP_PORT), RedirectHandler)
    print(f"Redirector HTTP:{HTTP_PORT} → HTTPS:{HTTPS_PORT} activo", flush=True)
    server.serve_forever()
