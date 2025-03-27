#!/usr/bin/env python3
"""
gen_subscription.py
-------------------
Este script genera un paquete de actualización de suscripción seguro que incluye un MAC.
La estructura del paquete es:
  - channel (4 bytes, little endian)
  - start_timestamp (8 bytes, little endian)
  - end_timestamp (8 bytes, little endian)
  - mac (MAC_SIZE bytes)

La clave para calcular el MAC se carga desde un archivo seguro (por defecto, 'shared_key.bin').
"""

import argparse
import struct
import hashlib
import time
import sys
import os

# Constantes
KEY_LENGTH = 16         # Longitud de la clave en bytes
HASH_SIZE = 16          # Se usará SHA-256 truncado a 16 bytes como MAC
MAC_SIZE = HASH_SIZE

def load_key(filename: str) -> bytes:
    """Carga la clave desde un archivo en formato binario."""
    try:
        with open(filename, "rb") as f:
            key = f.read(KEY_LENGTH)
        if len(key) != KEY_LENGTH:
            raise ValueError("La clave cargada no tiene la longitud esperada")
        return key
    except (IOError, ValueError) as e:
        print(f"Error al cargar la clave desde '{filename}': {e}", file=sys.stderr)
        sys.exit(1)

def compute_mac(key: bytes, message: bytes) -> bytes:
    """
    Calcula el MAC concatenando la clave cargada y el mensaje, y aplicando SHA-256.
    Se trunca el resultado a MAC_SIZE bytes.
    """
    buffer = key + message
    digest = hashlib.sha256(buffer).digest()
    return digest[:MAC_SIZE]

def build_subscription_update(key: bytes, channel: int, start_timestamp: int, end_timestamp: int) -> bytes:
    """
    Construye el paquete de actualización de suscripción seguro.
    
    Args:
        key (bytes): Clave cargada para el cálculo del MAC.
        channel (int): Número del canal (uint32).
        start_timestamp (int): Timestamp de inicio (uint64).
        end_timestamp (int): Timestamp de fin (uint64).
    
    Returns:
        bytes: Paquete de actualización de suscripción en formato binario.
    """
    header = struct.pack('<IQQ', channel, start_timestamp, end_timestamp)
    mac = compute_mac(key, header)
    return header + mac

def parse_args():
    parser = argparse.ArgumentParser(description="Genera un paquete de actualización de suscripción seguro con MAC.")
    parser.add_argument("-c", "--channel", type=int, default=1, help="Número de canal (default: 1)")
    parser.add_argument("-s", "--start", type=int, default=None, help="Timestamp de inicio. Por defecto se usa el tiempo actual.")
    parser.add_argument("-e", "--end", type=int, default=None, help="Timestamp de fin. Por defecto se usa una hora después del inicio.")
    parser.add_argument("-k", "--keyfile", type=str, default="shared_key.bin", help="Archivo desde donde cargar la clave (default: shared_key.bin)")
    parser.add_argument("-o", "--output", type=str, default=None, help="Archivo de salida para guardar el paquete (opcional).")
    return parser.parse_args()

def main():
    args = parse_args()
    
    # Cargar la clave segura desde el archivo especificado
    key = load_key(args.keyfile)
    
    channel = args.channel
    start_timestamp = args.start if args.start is not None else int(time.time())
    end_timestamp = args.end if args.end is not None else (start_timestamp + 3600)
    
    update_packet = build_subscription_update(key, channel, start_timestamp, end_timestamp)
    
    # Mostrar el paquete en formato hexadecimal
    print("Subscription update packet (hex):", update_packet.hex())
    
    # Si se especifica un archivo de salida, guardarlo
    if args.output:
        try:
            with open(args.output, "wb") as f:
                f.write(update_packet)
            print(f"Paquete guardado en '{args.output}'")
        except IOError as e:
            print(f"Error al guardar el paquete: {e}", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
