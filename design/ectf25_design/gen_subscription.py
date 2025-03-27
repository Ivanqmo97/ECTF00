#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import struct
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from loguru import logger

def encrypt_subscription(K_master: bytes, subscription_data: bytes) -> bytes:
    """
    "Cifra" (firma) los datos de suscripción usando AES-CMAC.
    Esto protege la integridad del código de suscripción, de forma que cualquier modificación se detecte.
    """
    cobj = CMAC.new(K_master, ciphermod=AES)
    cobj.update(subscription_data)
    return cobj.digest()

def gen_subscription(
    secrets: bytes, device_id: int, start: int, end: int, channel: int, encoder_id: int
) -> bytes:
    """
    Genera el código de suscripción (C_SUBS) que se utilizará en el Decoder.
    
    La función empaqueta los siguientes campos:
      - DECODER_ID: Identificador único del decodificador.
      - T_inicio: Timestamp de inicio de la validez de la suscripción.
      - T_fin: Timestamp de expiración de la suscripción.
      - CH_ID: Identificador del canal autorizado.
      - K00: Clave parcial asignada al dispositivo, derivada mediante TSS.
      - ENCODER_ID: Identificador único del codificador.
      
    Posteriormente, se "cifra" (firma) el paquete utilizando AES-CMAC con la clave maestra (K_master)
    para garantizar su integridad.
    
    Args:
        secrets (bytes): Contenido del archivo de secretos generado por gen_secrets.py.
        device_id (int): Identificador del decodificador (DECODER_ID).
        start (int): Timestamp de inicio (T_inicio) de la suscripción.
        end (int): Timestamp de expiración (T_fin) de la suscripción.
        channel (int): Identificador del canal (CH_ID) al que se autoriza la suscripción.
        encoder_id (int): Identificador del codificador (ENCODER_ID).
        
    Returns:
        bytes: Código de suscripción (C_SUBS) firmado.
    """
    secrets = json.loads(secrets)
    K_master = bytes.fromhex(secrets["K_master"])
    partial_keys = secrets["partial_keys"]

    # Seleccionamos la clave parcial correspondiente al dispositivo
    partial_key = partial_keys[device_id % len(partial_keys)]

    # Empaquetamos la suscripción siguiendo el orden:
    # DECODER_ID, T_inicio, T_fin, CH_ID, [K00] (32 bytes) y ENCODER_ID.
    subscription_plain = struct.pack(
        "<IQQI32sI", 
        device_id,     # DECODER_ID
        start,         # T_inicio
        end,           # T_fin
        channel,       # CH_ID
        bytes.fromhex(partial_key),  # Clave parcial asignada (K00)
        encoder_id     # ENCODER_ID
    )

    # Firmamos el paquete de suscripción usando AES-CMAC con la clave maestra para proteger su integridad.
    encrypted_subscription = encrypt_subscription(K_master, subscription_plain)

    return encrypted_subscription

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
        help="Forzar la creación del archivo de suscripción, sobreescribiendo el existente",
    )
    parser.add_argument(
        "secrets_file",
        type=argparse.FileType("rb"),
        help="Ruta del archivo de secretos creado por ectf25_design.gen_secrets",
    )
    parser.add_argument("subscription_file", type=Path, help="Archivo de salida para la suscripción")
    parser.add_argument(
        "device_id", type=lambda x: int(x, 0), help="Identificador del dispositivo receptor (DECODER_ID)"
    )
    parser.add_argument(
        "start", type=lambda x: int(x, 0), help="Timestamp de inicio de la suscripción (T_inicio)"
    )
    parser.add_argument("end", type=int, help="Timestamp de expiración de la suscripción (T_fin)")
    parser.add_argument("channel", type=int, help="Canal al que se suscribe (CH_ID)")
    parser.add_argument("encoder_id", type=lambda x: int(x, 0), help="Identificador del codificador (ENCODER_ID)")
    return parser.parse_args()

def main():
    """
    Función principal de gen_subscription.
    
    Se encarga de generar el código de suscripción (C_SUBS) que incluye:
      - DECODER_ID, T_inicio, T_fin, CH_ID, la clave parcial (K00) y ENCODER_ID.
    El resultado se firma utilizando AES-CMAC con K_master y se escribe en el archivo de salida.
    """
    args = parse_args()

    subscription = gen_subscription(
        args.secrets_file.read(), args.device_id, args.start, args.end, args.channel, args.encoder_id
    )

    logger.debug(f"Generated subscription: {subscription}")

    with open(args.subscription_file, "wb" if args.force else "xb") as f:
        f.write(subscription)

    logger.success(f"Wrote subscription to {str(args.subscription_file.absolute())}")

if __name__ == "__main__":
    main()
