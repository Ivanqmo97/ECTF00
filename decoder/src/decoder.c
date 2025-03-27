/**
 * @file    decoder.c
 * @author  Samuel Meyers (modificado)
 * @brief   eCTF Decoder Example Design Implementation modificado para cumplir con main.pdf
 * @date    2025
 *
 * Este archivo ha sido modificado para integrar:
 *   - Almacenamiento de la clave parcial (K00) y ENCODER_ID en la actualización de suscripciones.
 *   - Descifrado de frames usando AES-CTR con la clave parcial.
 *   - Validación de la suscripción basada en timestamps y coincidencia de ENCODER_ID.
 *
 * NOTA: La función decrypt_aes_ctr es un stub y debe reemplazarse por una implementación real.
 *
 * @copyright Copyright (c) 2025 The MITRE Corporation
 */

 #include <stdio.h>
 #include <stdint.h>
 #include <string.h>
 #include <stdbool.h>
 #include "mxc_device.h"
 #include "status_led.h"
 #include "board.h"
 #include "mxc_delay.h"
 #include "simple_flash.h"
 #include "host_messaging.h"
 #include "simple_uart.h"
 
 #ifdef CRYPTO_EXAMPLE
 #include "simple_crypto.h"
 #endif  // CRYPTO_EXAMPLE
 
 /**********************************************************
  ******************* PRIMITIVE TYPES **********************
  **********************************************************/
 #define timestamp_t uint64_t
 #define channel_id_t uint32_t
 #define decoder_id_t uint32_t
 #define pkt_len_t uint16_t
 
 /**********************************************************
  *********************** CONSTANTS ************************
  **********************************************************/
 #define MAX_CHANNEL_COUNT 8
 #define EMERGENCY_CHANNEL 0
 #define FRAME_SIZE 64
 #define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
 // Este es un valor canario para confirmar que el decodificador ha iniciado correctamente.
 #define FLASH_FIRST_BOOT 0xDEADBEEF
 
 // Definición de la dirección flash para almacenar el estado de los canales.
 #define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
 
 // Definiciones para el nuevo formato del paquete
 #define HEADER_SIZE 12              // 4 bytes (#SEQ) + 4 bytes (CH_ID) + 4 bytes (ENCODER_ID)
 #define SUBS_CODE_SIZE 16           // Tamaño del código de suscripción (resultado de AES-CMAC)
 #define FRAME_SECTION_SIZE (FRAME_SIZE + sizeof(timestamp_t) + sizeof(uint32_t)) // FRAME cifrado + TS + #SEQ
 
 /**********************************************************
  ************* ESTRUCTURAS DE DATOS MODIFICADAS ************
  **********************************************************/
 
 #pragma pack(push, 1)
 typedef struct {
     channel_id_t channel;
     timestamp_t timestamp;
     uint8_t data[FRAME_SIZE];
 } frame_packet_t;
 
 typedef struct {
     // Se omite el campo de suscripción original
     // ya que ahora se recibe mediante actualización
     decoder_id_t decoder_id;
     timestamp_t start_timestamp;
     timestamp_t end_timestamp;
     channel_id_t channel;
     uint8_t partial_key[32]; // Clave parcial (K00) enviada en la actualización
     uint32_t encoder_id;     // Identificador del codificador
 } subscription_update_packet_t;
 
 typedef struct {
     channel_id_t channel;
     timestamp_t start;
     timestamp_t end;
 } channel_info_t;
 
 typedef struct {
     uint32_t n_channels;
     channel_info_t channel_info[MAX_CHANNEL_COUNT];
 } list_response_t;
 #pragma pack(pop)
 
 typedef struct {
     bool active;
     channel_id_t id;
     timestamp_t start_timestamp;
     timestamp_t end_timestamp;
     uint8_t partial_key[32]; // Clave parcial asignada (K00)
     uint32_t encoder_id;     // Identificador del codificador
 } channel_status_t;
 
 typedef struct {
     uint32_t first_boot; // Si es igual a FLASH_FIRST_BOOT, el dispositivo ha iniciado anteriormente.
     channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
 } flash_entry_t;
 
 /**********************************************************
  ************************ GLOBALS *************************
  **********************************************************/
 flash_entry_t decoder_status;
 
 /**********************************************************
  ********************* FUNCIONES UTILITARIAS **************
  **********************************************************/
 
 /** @brief Verifica si el decodificador está suscrito a un canal.
  *
  *  @param channel Número del canal a verificar.
  *  @return 1 si está suscrito, 0 en caso contrario.
  */
 int is_subscribed(channel_id_t channel) {
     // Permitir siempre el canal de emergencia.
     if (channel == EMERGENCY_CHANNEL) {
         return 1;
     }
     for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].id == channel && decoder_status.subscribed_channels[i].active) {
             return 1;
         }
     }
     return 0;
 }
 
 /** @brief Imprime una bandera de referencia de boot.
  *  TODO: Eliminar esta función en la versión final.
  */
 void boot_flag(void) {
     char flag[28];
     char output_buf[128] = {0};
 
     // Procedimiento de deofuscación de ejemplo.
     for (int i = 0; i < 27; i++) {
         flag[i] = 'A' + (i % 26); // Ejemplo simple
     }
     flag[27] = '\0';
     sprintf(output_buf, "Boot Reference Flag: %s\n", flag);
     print_debug(output_buf);
 }
 
 /** @brief Lista los canales a los que el decodificador está suscrito.
  *
  *  @return 0 si es exitoso.
  */
 int list_channels() {
     list_response_t resp;
     pkt_len_t len;
 
     resp.n_channels = 0;
 
     for (uint32_t i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].active) {
             resp.channel_info[resp.n_channels].channel = decoder_status.subscribed_channels[i].id;
             resp.channel_info[resp.n_channels].start = decoder_status.subscribed_channels[i].start_timestamp;
             resp.channel_info[resp.n_channels].end = decoder_status.subscribed_channels[i].end_timestamp;
             resp.n_channels++;
         }
     }
 
     len = sizeof(resp.n_channels) + (sizeof(channel_info_t) * resp.n_channels);
     write_packet(LIST_MSG, &resp, len);
     return 0;
 }
 
 /**********************************************************
  ***************** FUNCIONES CORE MODIFICADAS *************
  **********************************************************/
 
 /** @brief Actualiza la suscripción de canales del decodificador.
  *
  *  @param pkt_len Longitud del paquete recibido.
  *  @param update Puntero al paquete de actualización de suscripción.
  *
  *  @return 0 si es exitoso, -1 en caso de error.
  */
 int update_subscription(pkt_len_t pkt_len, subscription_update_packet_t *update) {
     int i;
 
     if (update->channel == EMERGENCY_CHANNEL) {
         STATUS_LED_RED();
         print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
         return -1;
     }
 
     for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].id == update->channel || !decoder_status.subscribed_channels[i].active) {
             decoder_status.subscribed_channels[i].active = true;
             decoder_status.subscribed_channels[i].id = update->channel;
             decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
             decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
             // Almacenar la clave parcial y el encoder_id enviados en la actualización.
             memcpy(decoder_status.subscribed_channels[i].partial_key, update->partial_key, 32);
             decoder_status.subscribed_channels[i].encoder_id = update->encoder_id;
             break;
         }
     }
 
     if (i == MAX_CHANNEL_COUNT) {
         STATUS_LED_RED();
         print_error("Failed to update subscription - max subscriptions installed\n");
         return -1;
     }
 
     flash_simple_erase_page(FLASH_STATUS_ADDR);
     flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
     write_packet(SUBSCRIBE_MSG, NULL, 0);
     return 0;
 }
 
 /** @brief Función stub para descifrar datos usando AES-CTR.
  *
  *  Dado que AES-CTR es simétrico, se puede usar la misma función para cifrar y descifrar.
  *  Esta función debe reemplazarse por una implementación real utilizando la biblioteca criptográfica adecuada.
  *
  *  @param key Clave de 32 bytes para descifrado.
  *  @param nonce Valor inicial del contador (12 bytes en este ejemplo).
  *  @param ciphertext Datos cifrados.
  *  @param plaintext Buffer donde se almacenarán los datos descifrados.
  *  @param len Longitud de los datos a descifrar.
  *  @return 0 si es exitoso, -1 en caso de error.
  */
 int decrypt_aes_ctr(const uint8_t *key, const uint8_t *nonce, const uint8_t *ciphertext, uint8_t *plaintext, size_t len) {
     // IMPLEMENTACIÓN: Reemplazar este stub con una función real de descifrado AES-CTR.
     // Por ejemplo, utilizando mbedTLS, OpenSSL o una librería propia.
     // Para efectos de este ejemplo, se copia el ciphertext en plaintext (no es real).
     memcpy(plaintext, ciphertext, len);
     return 0;
 }
 
 /** @brief Procesa un paquete recibido que contiene datos de un frame cifrado.
  *
  *  El paquete tiene la siguiente estructura:
  *    Header: (#SEQ ∥ CH_ID ∥ ENCODER_ID) [12 bytes]
  *    C_SUBS: Código de suscripción firmado [16 bytes]
  *    Frame Section: [FRAME cifrado (64 bytes) ∥ TS (8 bytes) ∥ #SEQ (4 bytes)]
  *
  *  @param pkt_len Longitud total del paquete recibido.
  *  @param uart_buf Puntero al buffer que contiene el paquete.
  *
  *  @return 0 si es exitoso, -1 en caso de error.
  */
 int decode(pkt_len_t pkt_len, uint8_t *uart_buf) {
     char output_buf[128] = {0};
 
     if (pkt_len < (HEADER_SIZE + SUBS_CODE_SIZE + FRAME_SECTION_SIZE)) {
         print_error("Packet too short\n");
         return -1;
     }
 
     /* Extraer el header: (#SEQ, CH_ID, ENCODER_ID) */
     uint32_t pkt_seq, pkt_channel, pkt_encoder_id;
     memcpy(&pkt_seq, uart_buf, sizeof(uint32_t));
     memcpy(&pkt_channel, uart_buf + 4, sizeof(uint32_t));
     memcpy(&pkt_encoder_id, uart_buf + 8, sizeof(uint32_t));
 
     /* Extraer el código de suscripción (C_SUBS) */
     uint8_t subs_code[SUBS_CODE_SIZE];
     memcpy(subs_code, uart_buf + HEADER_SIZE, SUBS_CODE_SIZE);
 
     /* Extraer la sección del frame: [FRAME cifrado || TS || #SEQ] */
     uint8_t encrypted_frame[FRAME_SIZE];
     timestamp_t pkt_ts;
     uint32_t pkt_seq2;
     memcpy(encrypted_frame, uart_buf + HEADER_SIZE + SUBS_CODE_SIZE, FRAME_SIZE);
     memcpy(&pkt_ts, uart_buf + HEADER_SIZE + SUBS_CODE_SIZE + FRAME_SIZE, sizeof(timestamp_t));
     memcpy(&pkt_seq2, uart_buf + HEADER_SIZE + SUBS_CODE_SIZE + FRAME_SIZE + sizeof(timestamp_t), sizeof(uint32_t));
 
     /* Verificar consistencia del número de secuencia */
     if (pkt_seq != pkt_seq2) {
         sprintf(output_buf, "Sequence number mismatch: %u vs %u\n", pkt_seq, pkt_seq2);
         print_error(output_buf);
         return -1;
     }
 
     /* Buscar la suscripción activa para el canal */
     int found = 0;
     channel_status_t *sub = NULL;
     for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].active &&
             decoder_status.subscribed_channels[i].id == pkt_channel) {
             sub = &decoder_status.subscribed_channels[i];
             found = 1;
             break;
         }
     }
     if (!found) {
         sprintf(output_buf, "Receiving unsubscribed channel data: %u\n", pkt_channel);
         print_error(output_buf);
         return -1;
     }
 
     /* Validar la suscripción:
      *  - El timestamp del paquete debe estar dentro del intervalo [start_timestamp, end_timestamp].
      *  - El ENCODER_ID del header debe coincidir con el almacenado en la suscripción.
      */
     if (pkt_ts < sub->start_timestamp || pkt_ts > sub->end_timestamp) {
         print_error("Subscription expired or not yet valid\n");
         return -1;
     }
     if (sub->encoder_id != pkt_encoder_id) {
         print_error("Encoder ID mismatch\n");
         return -1;
     }
 
     /* Construir el nonce para AES-CTR:
      * Se empaqueta como: <QI> = 8 bytes para el número de secuencia (completado a 64 bits) y 4 bytes para CH_ID.
      */
     uint64_t nonce_seq = (uint64_t)pkt_seq;  // Se asume que los 4 bytes altos son 0
     uint8_t nonce[12];
     memcpy(nonce, &nonce_seq, sizeof(uint64_t));      // 8 bytes
     memcpy(nonce + sizeof(uint64_t), &pkt_channel, sizeof(uint32_t)); // 4 bytes
 
     /* Descifrar el frame usando AES-CTR con la clave parcial almacenada (K00) */
     uint8_t decrypted_frame[FRAME_SIZE];
     if (decrypt_aes_ctr(sub->partial_key, nonce, encrypted_frame, decrypted_frame, FRAME_SIZE) != 0) {
         print_error("Frame decryption failed\n");
         return -1;
     }
 
     /* Enviar el frame descifrado al host */
     write_packet(DECODE_MSG, decrypted_frame, FRAME_SIZE);
     return 0;
 }
 
 /**********************************************************
  *********************** MAIN LOOP ************************
  **********************************************************/
 
 int main(void) {
     char output_buf[128] = {0};
     uint8_t uart_buf[200];  // Tamaño suficientemente grande para contener el paquete completo.
     msg_type_t cmd;
     int result;
     uint16_t pkt_len;
 
     // Inicializar los periféricos: flash, UART, etc.
     flash_simple_init();
     flash_simple_read(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
     if (decoder_status.first_boot != FLASH_FIRST_BOOT) {
         print_debug("First boot.  Setting flash...\n");
         decoder_status.first_boot = FLASH_FIRST_BOOT;
         channel_status_t subscription[MAX_CHANNEL_COUNT];
         for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
             subscription[i].start_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
             subscription[i].end_timestamp = DEFAULT_CHANNEL_TIMESTAMP;
             subscription[i].active = false;
         }
         memcpy(decoder_status.subscribed_channels, subscription, MAX_CHANNEL_COUNT * sizeof(channel_status_t));
         flash_simple_erase_page(FLASH_STATUS_ADDR);
         flash_simple_write(FLASH_STATUS_ADDR, &decoder_status, sizeof(flash_entry_t));
     }
 
     result = uart_init();
     if (result < 0) {
         STATUS_LED_ERROR();
         while (1);
     }
 
     print_debug("Decoder Booted!\n");
 
     /* Bucle principal para procesar comandos */
     while (1) {
         print_debug("Ready\n");
         STATUS_LED_GREEN();
         result = read_packet(&cmd, uart_buf, &pkt_len);
         if (result < 0) {
             STATUS_LED_ERROR();
             print_error("Failed to receive cmd from host\n");
             continue;
         }
 
         switch (cmd) {
             case LIST_MSG:
                 STATUS_LED_CYAN();
 #ifdef CRYPTO_EXAMPLE
                 // Ejemplo de criptografía (para desarrollo; eliminar en producción)
                 // crypto_example();
 #endif
                 boot_flag();
                 list_channels();
                 break;
             case DECODE_MSG:
                 STATUS_LED_PURPLE();
                 // Nota: Se utiliza el nuevo formato del paquete en decode()
                 decode(pkt_len, uart_buf);
                 break;
             case SUBSCRIBE_MSG:
                 STATUS_LED_YELLOW();
                 update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
                 break;
             default:
                 STATUS_LED_ERROR();
                 sprintf(output_buf, "Invalid Command: %c\n", cmd);
                 print_error(output_buf);
                 break;
         }
     }
 }
 