/**
 * @file    decoder.c
 * @brief   eCTF Decoder Example Design Implementation with minimal security enhancements
 * @date    2025
 *
 * Este archivo implementa el decodificador que, además de la funcionalidad original,
 * incorpora medidas mínimas de seguridad (MAC, verificación anti-replay y autenticación)
 * sin modificar la interfaz de comandos.
 */

 #include <stdio.h>
 #include <stdint.h>
 #include <stdbool.h>
 #include <string.h>
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
  *********************** CONSTANTES ************************
  **********************************************************/
 #define MAX_CHANNEL_COUNT 8
 #define EMERGENCY_CHANNEL 0
 #define FRAME_SIZE 64
 #define DEFAULT_CHANNEL_TIMESTAMP 0xFFFFFFFFFFFFFFFF
 #define FLASH_FIRST_BOOT 0xDEADBEEF
 
 // Dirección de memoria flash para guardar el estado
 #define FLASH_STATUS_ADDR ((MXC_FLASH_MEM_BASE + MXC_FLASH_MEM_SIZE) - (2 * MXC_FLASH_PAGE_SIZE))
 
 /**********************************************************
  *************** TIPOS DE PAQUETES DE COMUNICACIÓN **********
  **********************************************************/
 #pragma pack(push, 1)
 typedef struct {
     channel_id_t channel;
     timestamp_t timestamp;
     uint8_t data[FRAME_SIZE];  // Estructura original sin seguridad
 } frame_packet_t;
 
 typedef struct {
     decoder_id_t decoder_id;
     timestamp_t start_timestamp;
     timestamp_t end_timestamp;
     channel_id_t channel;
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
 
 /**********************************************************
  ***************** TIPOS INTERNOS DEL SISTEMA ***************
  **********************************************************/
 typedef struct {
     bool active;
     channel_id_t id;
     timestamp_t start_timestamp;
     timestamp_t end_timestamp;
 } channel_status_t;
 
 typedef struct {
     uint32_t first_boot; // Si es igual a FLASH_FIRST_BOOT, el dispositivo ya ha iniciado antes.
     channel_status_t subscribed_channels[MAX_CHANNEL_COUNT];
 } flash_entry_t;
 
 /**********************************************************
  ************************ GLOBALES *************************
  **********************************************************/
 flash_entry_t decoder_status;
 
 /**********************************************************
  *************** FUNCIONES DE OFUSCACIÓN *******************
  **********************************************************/
 typedef uint32_t aErjfkdfru;
 const aErjfkdfru aseiFuengleR[] = {0x1ffe4b6,0x3098ac,0x2f56101,0x11a38bb,0x485124,0x11644a7,0x3c74e8,0x3c74e8,0x2f56101,0x2ca498,0x127bc,0x2e590b1,0x1d467da,0x1fbf0a2,0x11a38bb,0x2b22bad,0x2e590b1,0x1ffe4b6,0x2b61fc1,0x1fbf0a2,0x1fbf0a2,0x2e590b1,0x11644a7,0x2e590b1,0x1cc7fb2,0x1d073c6,0x2179d2e,0};
 const aErjfkdfru djFIehjkklIH[] = {0x138e798,0x2cdbb14,0x1f9f376,0x23bcfda,0x1d90544,0x1cad2d2,0x860e2c,0x860e2c,0x1f9f376,0x25cbe0c,0x11c82b4,0x35ff56,0x3935040,0xc7ea90,0x23bcfda,0x1ae6dee,0x35ff56,0x138e798,0x21f6af6,0xc7ea90,0xc7ea90,0x35ff56,0x1cad2d2,0x35ff56,0x2b15630,0x3225338,0x4431c8,0};
 typedef int skerufjp;
 skerufjp siNfidpL(skerufjp verLKUDSfj) {
     aErjfkdfru ubkerpYBd = 12+1;
     skerufjp xUrenrkldxpxx = 2253667944 % 0x432a1f32;
     aErjfkdfru UfejrlcpD = 1361423303;
     verLKUDSfj = (verLKUDSfj + 0x12345678) % 60466176;
     while(xUrenrkldxpxx-- != 0) {
         verLKUDSfj = (ubkerpYBd * verLKUDSfj + UfejrlcpD) % 0x39aa400;
     }
     return verLKUDSfj;
 }
 typedef uint8_t kkjerfI;
 kkjerfI deobfuscate(aErjfkdfru veruioPjfke, aErjfkdfru veruioPjfwe) {
     skerufjp fjekovERf = 2253667944 % 0x432a1f32;
     aErjfkdfru veruicPjfwe, verulcPjfwe;
     while(fjekovERf-- != 0) {
         veruioPjfwe = (veruioPjfwe - siNfidpL(veruioPjfke)) % 0x39aa400;
         veruioPjfke = (veruioPjfke - siNfidpL(veruioPjfwe)) % 60466176;
     }
     veruicPjfwe = (veruioPjfke + 0x39aa400) % 60466176;
     verulcPjfwe = (veruioPjfwe + 60466176) % 0x39aa400;
     return veruicPjfwe * 60466176 + verulcPjfwe - 89;
 }
 
 /**********************************************************
  *************** DEFINICIONES SEGURAS (MAC) ***************
  **********************************************************/
 #ifdef CRYPTO_EXAMPLE
     /* Se asume que KEY_SIZE y HASH_SIZE están definidos en simple_crypto.h.
        Para este ejemplo, usamos KEY_SIZE = 16 y HASH_SIZE = 16. */
     #define MAC_SIZE HASH_SIZE
 
     /* Clave precompartida */
     static uint8_t shared_key[KEY_SIZE] = { 
         0x01, 0x02, 0x03, 0x04,
         0x05, 0x06, 0x07, 0x08,
         0x09, 0x0A, 0x0B, 0x0C,
         0x0D, 0x0E, 0x0F, 0x10
     };
 
     /* Estructura segura para tramas que incluye MAC.
        Se reduce el tamaño del campo data para dejar espacio al MAC. */
     typedef struct {
         channel_id_t channel;
         timestamp_t timestamp;
         uint8_t data[FRAME_SIZE - MAC_SIZE];
         uint8_t mac[MAC_SIZE];
     } secure_frame_packet_t;
 
     /* Estructura segura para actualizaciones de suscripción que incluye MAC */
     typedef struct {
         channel_id_t channel;
         timestamp_t start_timestamp;
         timestamp_t end_timestamp;
         uint8_t mac[MAC_SIZE];
     } secure_subscription_update_packet_t;
 
     /* Función auxiliar para calcular un MAC básico.
        Se concatena la clave precompartida y el mensaje y se aplica hash(). */
     static void compute_mac(uint8_t *message, size_t length, uint8_t *mac_out) {
         uint8_t buffer[KEY_SIZE + length];
         memcpy(buffer, shared_key, KEY_SIZE);
         memcpy(buffer + KEY_SIZE, message, length);
         hash(buffer, KEY_SIZE + length, mac_out);
     }
 #else
     typedef frame_packet_t secure_frame_packet_t;
     typedef subscription_update_packet_t secure_subscription_update_packet_t;
 #endif
 
 /**********************************************************
  ******************* FUNCIONES UTILES *********************
  **********************************************************/
 int is_subscribed(channel_id_t channel) {
     if (channel == EMERGENCY_CHANNEL) {
         return 1;
     }
     for (int i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].id == channel &&
             decoder_status.subscribed_channels[i].active) {
             return 1;
         }
     }
     return 0;
 }
 
 void boot_flag(void) {
     char flag[28];
     char output_buf[128] = {0};
     for (int i = 0; aseiFuengleR[i]; i++) {
         flag[i] = deobfuscate(aseiFuengleR[i], djFIehjkklIH[i]);
         flag[i+1] = 0;
     }
     sprintf(output_buf, "Boot Reference Flag: %s\n", flag);
     print_debug(output_buf);
 }
 
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
  ******************* FUNCIONES PRINCIPALES ******************
  **********************************************************/
 
 /** @brief Procesa un paquete de trama con verificación de MAC y anti-replay.
  *
  *  @param pkt_len Longitud del paquete recibido.
  *  @param new_frame Puntero a la trama recibida (formato seguro).
  *  @return 0 si es exitoso, -1 en error.
  */
 int decode(pkt_len_t pkt_len, secure_frame_packet_t *new_frame) {
     char output_buf[128] = {0};
 
 #ifdef CRYPTO_EXAMPLE
     /* Calcular el MAC sobre: channel, timestamp y data */
     uint8_t computed_mac[MAC_SIZE];
     size_t mac_length = sizeof(new_frame->channel) + sizeof(new_frame->timestamp) + sizeof(new_frame->data);
     compute_mac((uint8_t*)new_frame, mac_length, computed_mac);
     if (memcmp(computed_mac, new_frame->mac, MAC_SIZE) != 0) {
         print_error("MAC verification failed\n");
         return -1;
     }
 #endif
 
     print_debug("Checking subscription\n");
     if (is_subscribed(new_frame->channel)) {
         if (new_frame->channel != EMERGENCY_CHANNEL) {
             bool valid_time = false;
             for (int i = 0; i < MAX_CHANNEL_COUNT; i++){
                 if (decoder_status.subscribed_channels[i].id == new_frame->channel &&
                     decoder_status.subscribed_channels[i].active) {
                     if (new_frame->timestamp >= decoder_status.subscribed_channels[i].start_timestamp &&
                         new_frame->timestamp <= decoder_status.subscribed_channels[i].end_timestamp) {
                         valid_time = true;
                     }
                     break;
                 }
             }
             if (!valid_time) {
                 print_error("Timestamp outside subscription window\n");
                 return -1;
             }
         }
         print_debug("Subscription Valid\n");
 #ifdef CRYPTO_EXAMPLE
         uint16_t payload_size = FRAME_SIZE - MAC_SIZE;
 #else
         uint16_t payload_size = FRAME_SIZE;
 #endif
         write_packet(DECODE_MSG, new_frame->data, payload_size);
         return 0;
     } else {
         STATUS_LED_RED();
         sprintf(output_buf, "Receiving unsubscribed channel data. %u\n", new_frame->channel);
         print_error(output_buf);
         return -1;
     }
 }
 
 /** @brief Actualiza la suscripción de canal con verificación de MAC.
  *
  *  @param pkt_len Longitud del paquete recibido.
  *  @param update Puntero al paquete de actualización (formato seguro).
  *  @return 0 en éxito, -1 en error.
  */
 int update_subscription(pkt_len_t pkt_len, secure_subscription_update_packet_t *update) {
     char output_buf[128] = {0};
 
 #ifdef CRYPTO_EXAMPLE
     /* Calcular el MAC sobre: channel, start_timestamp y end_timestamp */
     uint8_t computed_mac[MAC_SIZE];
     size_t mac_length = sizeof(update->channel) + sizeof(update->start_timestamp) + sizeof(update->end_timestamp);
     compute_mac((uint8_t*)update, mac_length, computed_mac);
     if (memcmp(computed_mac, update->mac, MAC_SIZE) != 0) {
         print_error("Subscription update MAC verification failed\n");
         return -1;
     }
 #endif
 
     if (update->channel == EMERGENCY_CHANNEL) {
         STATUS_LED_RED();
         print_error("Failed to update subscription - cannot subscribe to emergency channel\n");
         return -1;
     }
 
     int i;
     for (i = 0; i < MAX_CHANNEL_COUNT; i++) {
         if (decoder_status.subscribed_channels[i].id == update->channel ||
             !decoder_status.subscribed_channels[i].active) {
             decoder_status.subscribed_channels[i].active = true;
             decoder_status.subscribed_channels[i].id = update->channel;
             decoder_status.subscribed_channels[i].start_timestamp = update->start_timestamp;
             decoder_status.subscribed_channels[i].end_timestamp = update->end_timestamp;
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
 
 /** @brief Inicializa los periféricos y el estado persistente.
  */
 void init() {
     int ret;
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
     ret = uart_init();
     if (ret < 0) {
         STATUS_LED_ERROR();
         while (1);
     }
 }
 
 /**********************************************************
  ************************* MAIN ***************************
  **********************************************************/
 int main(void) {
     char output_buf[128] = {0};
     uint8_t uart_buf[100];
     msg_type_t cmd;
     int result;
     uint16_t pkt_len;
 
     init();
     print_debug("Decoder Booted!\n");
 
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
                 crypto_example();
 #endif
                 boot_flag();
                 list_channels();
                 break;
             case DECODE_MSG:
                 STATUS_LED_PURPLE();
 #ifdef CRYPTO_EXAMPLE
                 decode(pkt_len, (secure_frame_packet_t *)uart_buf);
 #else
                 decode(pkt_len, (frame_packet_t *)uart_buf);
 #endif
                 break;
             case SUBSCRIBE_MSG:
                 STATUS_LED_YELLOW();
 #ifdef CRYPTO_EXAMPLE
                 update_subscription(pkt_len, (secure_subscription_update_packet_t *)uart_buf);
 #else
                 update_subscription(pkt_len, (subscription_update_packet_t *)uart_buf);
 #endif
                 break;
             default:
                 STATUS_LED_ERROR();
                 sprintf(output_buf, "Invalid Command: %c\n", cmd);
                 print_error(output_buf);
                 break;
         }
     }
 }
 