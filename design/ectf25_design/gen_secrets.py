#!/usr/bin/env python3
"""
gen_secrets.py
--------------
Este script se encarga de la generación y gestión de la clave secreta compartida (16 bytes) que se utilizará para
calcular el MAC en las tramas y en las actualizaciones de suscripción. Además de generar la clave, incluye funciones
para guardarla y cargarla desde un archivo seguro.
"""

import os
import sys

# Constantes
KEY_LENGTH = 16
KEY_FILE = "shared_key.bin"

def generate_shared_key() -> bytes:
    """Genera una clave secreta de 16 bytes usando os.urandom."""
    return os.urandom(KEY_LENGTH)

def save_key(key: bytes, filename: str = KEY_FILE) -> None:
    """Guarda la clave en un archivo en formato binario."""
    try:
        with open(filename, "wb") as f:
            f.write(key)
        print(f"Clave guardada en '{filename}'")
    except IOError as e:
        print(f"Error al guardar la clave: {e}")
        sys.exit(1)

def load_key(filename: str = KEY_FILE) -> bytes:
    """Carga la clave desde un archivo en formato binario."""
    try:
        with open(filename, "rb") as f:
            key = f.read(KEY_LENGTH)
        if len(key) != KEY_LENGTH:
            raise ValueError("Clave incompleta")
        print(f"Clave cargada desde '{filename}'")
        return key
    except (IOError, ValueError) as e:
        print(f"Error al cargar la clave: {e}")
        sys.exit(1)

def print_key_hex(key: bytes) -> None:
    """Imprime la clave en formato hexadecimal."""
    print("Clave compartida (hex):", key.hex())

def main():
    """
    Función principal:
    - Si ya existe un archivo con la clave, se carga e imprime.
    - Si no existe, se genera, se guarda y se imprime.
    """
    if os.path.exists(KEY_FILE):
        key = load_key()
    else:
        key = generate_shared_key()
        save_key(key)
    print_key_hex(key)

if __name__ == "__main__":
    main()
