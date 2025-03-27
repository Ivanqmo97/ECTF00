#!/usr/bin/env python3
import argparse
import struct
import json
from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Hash import CMAC

class Encoder:
    def __init__(self, secrets: bytes):
        """
        Inicializa el Encoder cargando secretos, clave maestra y claves parciales.

        :param secrets: Contenido del archivo de secretos generado por gen_secrets.
        """
        secrets = json.loads(secrets)
        self.K_master = bytes.fromhex(secrets["K_master"])
        self.partial_keys = secrets["partial_keys"]
        self.sequence_number = 0

    def derive_intermediate_key(self) -> bytes:
        """
        Deriva la clave intermedia K1 usando AES-CMAC a partir de K_master.
        
        :returns: Clave intermedia K1.
        """
        cobj = CMAC.new(self.K_master, ciphermod=AES)
        cobj.update(b'intermediate_key')
        return cobj.digest()

    def encrypt_frame_aes_ctr(self, key: bytes, nonce: bytes, data: bytes) -> bytes:
        """
        Cifra los datos del frame usando AES-CTR.
        
        :param key: Clave a utilizar para el cifrado.
        :param nonce: Valor inicial del contador.
        :param data: Datos del frame a cifrar.
        :returns: Frame cifrado.
        """
        ctr = Counter.new(128, initial_value=int.from_bytes(nonce, 'big'))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher.encrypt(data)

    def generate_subscription_code(self, decoder_id: int, sub_start: int, sub_end: int, channel: int, encoder_id: int) -> bytes:
        """
        Genera el código de suscripción (C_SUBS) que se incluirá en el paquete final.
        
        Se empaqueta la siguiente información:
          - DECODER_ID: Identificador del decodificador.
          - T_inicio (sub_start): Timestamp de inicio de la suscripción.
          - T_fin (sub_end): Timestamp de expiración de la suscripción.
          - CH_ID (channel): Identificador del canal.
          - Clave parcial (32 bytes) asignada al dispositivo, derivada mediante TSS.
          - ENCODER_ID: Identificador del codificador.
        
        Luego se firma el paquete utilizando AES-CMAC con la clave maestra (K_master) para garantizar su integridad.
        
        :param decoder_id: Identificador del decodificador (DECODER_ID).
        :param sub_start: Timestamp de inicio de la suscripción.
        :param sub_end: Timestamp de expiración de la suscripción.
        :param channel: Identificador del canal (CH_ID).
        :param encoder_id: Identificador del codificador (ENCODER_ID).
        :returns: Código de suscripción firmado (C_SUBS).
        """
        # Seleccionar la clave parcial asignada al dispositivo
        partial_key_hex = self.partial_keys[decoder_id % len(self.partial_keys)]
        partial_key_bytes = bytes.fromhex(partial_key_hex)
        
        # Empaquetar la información de suscripción siguiendo el orden:
        # DECODER_ID, T_inicio, T_fin, CH_ID, [K00] (32 bytes) y ENCODER_ID.
        subscription_plain = struct.pack(
            "<IQQI32sI",
            decoder_id,  # DECODER_ID
            sub_start,   # T_inicio
            sub_end,     # T_fin
            channel,     # CH_ID
            partial_key_bytes,  # Clave parcial (K00)
            encoder_id   # ENCODER_ID
        )
        
        # Firmar el paquete de suscripción usando AES-CMAC con K_master.
        cobj = CMAC.new(self.K_master, ciphermod=AES)
        cobj.update(subscription_plain)
        subscription_code = cobj.digest()
        return subscription_code

    def encode(self, channel: int, frame: bytes, timestamp: int, decoder_id: int, sub_start: int, sub_end: int, encoder_id: int) -> bytes:
        """
        Codifica el frame y genera el paquete completo para la transmisión.
        
        El paquete final tiene la estructura:
          (#SEQ ∥ CH_ID ∥ ENCODER_ID) || [C_SUBS] || [FRAME cifrado ∥ TS ∥ #SEQ]
          
        Donde:
          - #SEQ: Número de secuencia.
          - CH_ID: Identificador del canal.
          - ENCODER_ID: Identificador del codificador.
          - C_SUBS: Código de suscripción generado.
          - FRAME cifrado: Contenido cifrado del frame (máximo 64 bytes).
          - TS: Timestamp utilizado.
          
        :param channel: Número del canal.
        :param frame: Contenido del frame a cifrar.
        :param timestamp: Timestamp actual.
        :param decoder_id: Identificador del decodificador (usado para la suscripción).
        :param sub_start: Timestamp de inicio de la suscripción (T_inicio).
        :param sub_end: Timestamp de expiración de la suscripción (T_fin).
        :param encoder_id: Identificador del codificador (ENCODER_ID).
        :returns: Paquete completo listo para transmisión.
        """
        # Derivar la clave intermedia K1
        K1 = self.derive_intermediate_key()

        # Incrementar el número de secuencia
        self.sequence_number += 1

        # Construir el nonce combinando el número de secuencia y el identificador del canal
        nonce = struct.pack("<QI", self.sequence_number, channel)

        # Cifrar el frame utilizando AES-CTR con K1 y el nonce
        encrypted_frame = self.encrypt_frame_aes_ctr(K1, nonce, frame)

        # Generar el código de suscripción (C_SUBS)
        subscription_code = self.generate_subscription_code(decoder_id, sub_start, sub_end, channel, encoder_id)

        # Construir el header: (#SEQ ∥ CH_ID ∥ ENCODER_ID)
        header = struct.pack("<I I I", self.sequence_number, channel, encoder_id)

        # Empaquetar la parte final: [FRAME cifrado ∥ TS ∥ #SEQ]
        frame_section = encrypted_frame + struct.pack("<Q I", timestamp, self.sequence_number)

        # Construir el paquete final concatenando header, C_SUBS y frame_section
        packet = header + subscription_code + frame_section

        return packet

def main():
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument("secrets_file", type=argparse.FileType("rb"), help="Ruta del archivo de secretos")
    parser.add_argument("channel", type=int, help="Canal para codificar")
    parser.add_argument("frame", help="Contenido del frame (máximo 64 bytes)")
    parser.add_argument("timestamp", type=int, help="Timestamp de 64 bits a utilizar")
    parser.add_argument("decoder_id", type=int, help="Identificador del decodificador (DECODER_ID)")
    parser.add_argument("sub_start", type=int, help="Timestamp de inicio de la suscripción (T_inicio)")
    parser.add_argument("sub_end", type=int, help="Timestamp de expiración de la suscripción (T_fin)")
    parser.add_argument("encoder_id", type=int, help="Identificador del codificador (ENCODER_ID)")
    args = parser.parse_args()

    encoder = Encoder(args.secrets_file.read())
    packet = encoder.encode(
        args.channel,
        args.frame.encode(),
        args.timestamp,
        args.decoder_id,
        args.sub_start,
        args.sub_end,
        args.encoder_id
    )
    print(repr(packet))

if __name__ == "__main__":
    main()
