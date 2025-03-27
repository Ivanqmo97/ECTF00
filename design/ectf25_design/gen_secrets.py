#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Random import get_random_bytes
from secretsharing import PlaintextToHexSecretSharer
from loguru import logger

def generate_master_key() -> bytes:
    """
    Genera una clave maestra segura de 256 bits.
    Esta clave es inmutable y se utiliza para:
      - Derivar la clave intermedia (K1) mediante AES-CMAC.
      - Cifrar y firmar los códigos de suscripción.
    """
    return get_random_bytes(32)

def derive_intermediate_key(K_master: bytes) -> bytes:
    """
    Deriva la clave intermedia K1 a partir de la clave maestra (K_master)
    utilizando AES-CMAC. Esta clave se emplea para generar las claves parciales.
    """
    cobj = CMAC.new(K_master, ciphermod=AES)
    cobj.update(b'intermediate_key')
    return cobj.digest()

def generate_partial_keys(K1: bytes, total_keys: int = 100, threshold: int = 1) -> list:
    """
    Genera claves parciales (K00, K01, …, K99) usando un esquema de compartición
    de secretos (TSS) con el umbral establecido en 1.
    
    Args:
        K1 (bytes): Clave intermedia derivada de K_master.
        total_keys (int): Número total de claves parciales a generar (por defecto 100).
        threshold (int): Número mínimo de claves necesarias para reconstruir la clave original (por defecto 1).

    Returns:
        list: Lista de claves parciales en formato hexadecimal.
    """
    hex_key = K1.hex()
    partial_keys = PlaintextToHexSecretSharer.split_secret(hex_key, threshold, total_keys)
    return partial_keys

def gen_secrets(channels: list[int]) -> bytes:
    """
    Genera el contenido del archivo de secretos que se utilizará en el Encoder,
    en la generación de suscripciones y durante la compilación del Decoder.
    
    Este archivo contiene:
      - "channels": Lista de canales soportados (no se incluye el canal 0, que es de emergencia).
      - "K_master": Clave maestra en formato hexadecimal.
      - "partial_keys": Lista de 100 claves parciales generadas mediante TSS.
    
    Args:
        channels (list[int]): Lista de números de canales válidos en esta implementación.

    Returns:
        bytes: Datos JSON codificados que representan el archivo de secretos.
    """
    # Generación de la clave maestra (K_master) inmutable
    K_master = generate_master_key()
    # Derivación de la clave intermedia K1 a partir de K_master usando AES-CMAC
    K1 = derive_intermediate_key(K_master)
    # Generación de 100 claves parciales (K00...K99) mediante TSS con umbral de 1
    partial_keys = generate_partial_keys(K1)

    secrets = {
        "channels": channels,
        "K_master": K_master.hex(),
        "partial_keys": partial_keys
    }

    return json.dumps(secrets).encode()

def parse_args():
    """
    Define y analiza los argumentos de línea de comandos.
    
    NOTA: Esta función no debe ser modificada según los requerimientos del diseño.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--force",
        "-f",
        action="store_true",
        help="Forzar la creación del archivo de secretos, sobreescribiendo el existente",
    )
    parser.add_argument(
        "secrets_file",
        type=Path,
        help="Ruta del archivo de secretos a crear",
    )
    parser.add_argument(
        "channels",
        nargs="+",
        type=int,
        help="Canales soportados. El canal 0 (broadcast) es siempre válido y no se incluye en esta lista",
    )
    return parser.parse_args()

def main():
    """
    Función principal de gen_secrets.
    
    Se encarga de generar el archivo de secretos que contendrá K_master, la lista
    de canales soportados y las claves parciales derivadas. Este archivo será utilizado
    por el Encoder, el generador de suscripciones y el Decoder.
    """
    args = parse_args()

    secrets = gen_secrets(args.channels)

    logger.debug(f"Generated secrets: {secrets}")

    with open(args.secrets_file, "wb" if args.force else "xb") as f:
        f.write(secrets)

    logger.success(f"Wrote secrets to {str(args.secrets_file.absolute())}")

if __name__ == "__main__":
    main()
