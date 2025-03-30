#include "config.h"

const char apn[] = "internet";
const char gprsUser[] = "";
const char gprsPass[] = "";

const unsigned char aes_key[32] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46
};

const unsigned char aes_iv[16] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46
};

const char *cert_name = "iot_inverter2.pem";
const char *mqtt_server = "u008dd8e.ala.dedicated.aws.emqxcloud.com";
const char *mqtt_topic_send = "esp32_status";
const char *mqtt_topic_recv = "server_cmd";
const char *mqtt_topic_firmware = "OTA_Update";
const int mqtt_port = 8883;

const int MAX_RETRIES = 10;
const int RETRY_DELAY = 2000;
const size_t OTA_CHUNK_SIZE = 1028;
const size_t OTA_MAX_DATA_SIZE = OTA_CHUNK_SIZE - 4;
const int BATCH_SIZE = 10;
const unsigned long MONITOR_INTERVAL = 5000;
const uint32_t WDT_TIMEOUT = 30;
const size_t CHUNK_SIZE = 1024;