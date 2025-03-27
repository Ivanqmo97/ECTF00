#!/usr/bin/env python3
"""
encoder.py
----------
Este script construye tramas seguras para el envío, incluyendo un MAC calculado utilizando
una clave compartida que se carga desde un archivo seguro (por defecto, 'shared_key.bin').
La estructura de la trama es la siguiente:
  - channel (4 bytes, little endian)
  - timestamp (8 bytes, little endian)
  - data (FRAME_SIZE - MAC_SIZE bytes)
  - mac (MAC_SIZE bytes)

Se espera que la clave (de 16 bytes) se haya generado previamente (por ejemplo, usando gen_secrets.py)
y se encuentre almacenada en el archivo 'shared_key.bin'.
"""

import struct
import hashlib
import time
import sys
import os

# Constantes
FRAME_SIZE = 64
KEY_LENGTH = 16         # Longitud de la clave en bytes
HASH_SIZE = 16          # Se usará SHA-256 truncado a 16 bytes como MAC
MAC_SIZE = HASH_SIZE
KEY_FILE = "shared_key.bin"

def load_key(filename: str) -> bytes:
    """
    Carga la clave compartida desde un archivo en formato binario.
    
    Args:
        filename (str): Nombre del archivo que contiene la clave.
    
    Returns:
        bytes: La clave de KEY_LENGTH bytes.
    
    Termina la ejecución si ocurre algún error.
    """
    try:
        with open(filename, "rb") as f:
            key = f.read(KEY_LENGTH)
        if len(key) != KEY_LENGTH:
            raise ValueError("La clave cargada no tiene la longitud esperada.")
        return key
    except (IOError, ValueError) as e:
        print(f"Error al cargar la clave desde '{filename}': {e}", file=sys.stderr)
        sys.exit(1)

def compute_mac(key: bytes, message: bytes) -> bytes:
    """
    Calcula un MAC simple concatenando la clave y el mensaje, y aplicando SHA-256.
    Se trunca el resultado a MAC_SIZE bytes.
    
    Args:
        key (bytes): Clave compartida.
        message (bytes): Mensaje sobre el cual calcular el MAC.
    
    Returns:
        bytes: El MAC calculado (MAC_SIZE bytes).
    """
    buffer = key + message
    digest = hashlib.sha256(buffer).digest()
    return digest[:MAC_SIZE]

def build_secure_frame(key: bytes, channel: int, timestamp: int, data: bytes) -> bytes:
    """
    Construye una trama segura.
    
    La trama consta de:
      - channel: 4 bytes (uint32 little endian)
      - timestamp: 8 bytes (uint64 little endian)
      - data: FRAME_SIZE - MAC_SIZE bytes (rellenado o truncado según sea necesario)
      - mac: MAC_SIZE bytes, calculado sobre los campos anteriores utilizando la clave
    
    Args:
        key (bytes): Clave compartida para calcular el MAC.
        channel (int): Número del canal.
        timestamp (int): Timestamp (por ejemplo, tiempo actual).
        data (bytes): Payload a enviar.
    
    Returns:
        bytes: La trama completa lista para ser enviada.
    """
    # Ajustar el payload para que tenga el tamaño exacto
    data = data.ljust(FRAME_SIZE - MAC_SIZE, b'\x00')[:FRAME_SIZE - MAC_SIZE]
    header = struct.pack('<IQ', channel, timestamp)
    # Calcular el MAC sobre header + data
    mac = compute_mac(key, header + data)
    return header + data + mac

def print_key_hex(key: bytes) -> None:
    """Imprime la clave en formato hexadecimal (para debug o verificación)."""
    print("Clave compartida (hex):", key.hex())

def main():
    # Cargar la clave compartida desde el archivo seguro
    key = load_key(KEY_FILE)
    
    # Para este ejemplo, definimos valores fijos o basados en el tiempo
    channel = 1
    timestamp = int(time.time())
    payload = b'Hola, mundo seguro!'  # Ejemplo de payload

    frame = build_secure_frame(key, channel, timestamp, payload)
    
    print("Secure frame (hex):", frame.hex())
    # Aquí se podría enviar la trama a través de la interfaz correspondiente

if __name__ == "__main__":
    main()
