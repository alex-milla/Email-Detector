#!/usr/bin/env python3
"""
shannon_entropy.py — Calcula la entropía de Shannon de cualquier texto.

La entropía mide cuánto "desorden" hay en una cadena.
Cuanto más alta, más aleatoria/ofuscada parece.

Uso:
    from shannon_entropy import calculate_entropy
    entropy = calculate_entropy("texto a analizar")
"""

import math
from collections import Counter


def calculate_entropy(text):
    """
    Calcula la entropía de Shannon de un texto.

    Parámetros:
        text: cualquier cadena de texto

    Devuelve:
        Un número decimal (float):
        - 0.0   = sin variación (ej: "aaaaaaa")
        - 3.5-4.5 = texto normal en idioma humano
        - 5.5+  = contenido sospechoso (ofuscado/codificado)
        - 8.0   = máximo teórico (cada byte aparece igual)
    """
    if not text:
        return 0.0

    counter = Counter(text)
    length  = len(text)

    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


def calculate_entropy_bytes(data):
    """
    Calcula la entropía de datos binarios (bytes).
    Útil para analizar archivos adjuntos.

    Parámetros:
        data: bytes (contenido binario de un archivo)

    Devuelve:
        Entropía entre 0.0 y 8.0
    """
    if not data:
        return 0.0

    counter = Counter(data)
    length  = len(data)

    entropy = 0.0
    for count in counter.values():
        probability = count / length
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return round(entropy, 4)


# ── Prueba rápida (si ejecutas este archivo directamente) ──
if __name__ == "__main__":
    ejemplos = [
        ("Texto normal en español",    "Hola, te envío el informe adjunto del proyecto."),
        ("URL legítima",               "https://www.google.com/search?q=python+tutorial"),
        ("URL sospechosa (aleatoria)", "https://x7k9m2.xyz/a8f3e/d2c1?t=9xkL3mNpQr"),
        ("Base64 (contenido cod.)",    "aHR0cHM6Ly9tYWx3YXJlLmNvbS9wYXlsb2Fk"),
        ("Cadena repetitiva",          "aaaaaaaaaaaaaaaaaaaaaaaaa"),
        ("Máxima entropía (hex)",       "0123456789abcdef" * 10),
    ]

    print("=" * 60)
    print(" DEMOSTRACIÓN DE ENTROPÍA DE SHANNON")
    print("=" * 60)

    for nombre, texto in ejemplos:
        e     = calculate_entropy(texto)
        barra = "█" * int(e * 4) + "░" * (32 - int(e * 4))
        print(f"\n  {nombre}:")
        print(f"  Texto:    \"{texto[:50]}{'...' if len(texto) > 50 else ''}\"")
        print(f"  Entropía: {e:.4f} bits/carácter")
        print(f"  [{barra}]")
