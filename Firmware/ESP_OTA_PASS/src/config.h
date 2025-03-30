#ifndef CONFIG_H
#define CONFIG_H

#include <stddef.h>  // For size_t
#include <stdint.h>  // For uint32_t and other integer types

#define ENABLE_LCD

// Hardware pins
#define RGB_LED_PIN 48
#define NUM_PIXELS 1
#define I2C_SDA 35
#define I2C_SCL 36
#define SIM7600_PWR 21
#define MODEM_TX 16
#define MODEM_RX 17
#define LED_PIN 13
#define FACTORY_RESET_PIN 4

// UART configuration
#define UART_NUM UART_NUM_2
#define BAUD_RATE 115200
#define BUFFER_SIZE 1024

// Default credentials
#define DEFAULT_CLIENT_ID "ESP32_SIM7600_Client"
#define DEFAULT_USERNAME "ESP32"
#define DEFAULT_PASSWORD "12345"

// APN configuration
extern const char apn[];
extern const char gprsUser[];
extern const char gprsPass[];

// AES-256 Configuration
extern const unsigned char aes_key[32];
extern const unsigned char aes_iv[16];

// MQTT Configuration
extern const char *cert_name;
extern const char *mqtt_server;
#define PROVISION_TOPIC "dev_pass_req"
#define PROVISION_RESPONSE_TOPIC "dev_pass_res"
extern const char *mqtt_topic_send;
extern const char *mqtt_topic_recv;
extern const char *mqtt_topic_firmware;
extern const int mqtt_port;

// Timing and Limits
extern const int MAX_RETRIES;
extern const int RETRY_DELAY;
extern const size_t OTA_CHUNK_SIZE;
extern const size_t OTA_MAX_DATA_SIZE;
extern const int BATCH_SIZE;
extern const unsigned long MONITOR_INTERVAL;
extern const uint32_t WDT_TIMEOUT;
extern const size_t CHUNK_SIZE;

#endif