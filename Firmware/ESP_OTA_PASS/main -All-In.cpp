#define ENABLE_LCD

#include <Wire.h>
#include <HardwareSerial.h>
#include <Adafruit_NeoPixel.h>
#ifdef ENABLE_LCD
#include <LCD_I2C.h>
#endif
#include <esp_task_wdt.h>
#include <driver/uart.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "certificates.h" // Ensure this contains your root_ca string
#include <esp_ota_ops.h>
#include <map>
#include <vector>
#include <Preferences.h>

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

// FreeRTOS queue for UART data
QueueHandle_t uartQueue;

// Default credentials
#define DEFAULT_CLIENT_ID "ESP32_SIM7600_Client"
#define DEFAULT_USERNAME "ESP32"
#define DEFAULT_PASSWORD "12345"

// APN configuration
const char apn[] = "internet";
const char gprsUser[] = "";
const char gprsPass[] = "";

// AES-256 Configuration
const unsigned char aes_key[32] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46,
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};
const unsigned char aes_iv[16] = {
    0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
    0x38, 0x39, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46};

// Serial interfaces
HardwareSerial sim7600(1);
#define SerialMon Serial
#define SerialAT sim7600

// State machine states
enum SetupState {
    STATE_INIT_MODEM,
    STATE_WAIT_NETWORK,
    STATE_CONNECT_GPRS,
    STATE_UPLOAD_CERTIFICATE,
    STATE_SETUP_SSL,
    STATE_SETUP_MQTT,
    STATE_CONNECT_MQTT,
    STATE_SUBSCRIBE_MQTT,
    STATE_RUNNING,
    STATE_WAIT_PROVISION,
    STATE_ERROR,
    STATE_STOPPED,
    STATE_RECOVER_NETWORK,
    STATE_RECOVER_GPRS,
    STATE_RECOVER_MQTT
};

struct MqttStatus {
    bool serviceStarted = false;
    bool clientAcquired = false;
    bool connected = false;
    bool subscribed = false;
    bool provisionSubscribed = false;
    int lastErrorCode = 0;
    unsigned long lastConnectTime = 0;

    void reset() {
        serviceStarted = false;
        clientAcquired = false;
        connected = false;
        subscribed = false;
        provisionSubscribed = false;
        lastErrorCode = 0;
        lastConnectTime = 0;
    }
};

// Configuration
const int MAX_RETRIES = 10;
const int RETRY_DELAY = 2000;
const size_t OTA_CHUNK_SIZE = 1028;
const size_t OTA_MAX_DATA_SIZE = OTA_CHUNK_SIZE - 4;
const int BATCH_SIZE = 10;
std::vector<unsigned long> batchChunks;
unsigned long expectedBatchEnd = 0;

const char *cert_name = "iot_inverter2.pem";
const char *mqtt_server = "u008dd8e.ala.dedicated.aws.emqxcloud.com";
#define PROVISION_TOPIC "dev_pass_req"
#define PROVISION_RESPONSE_TOPIC "dev_pass_res"
const char *mqtt_topic_send = "esp32_status";
const char *mqtt_topic_recv = "server_cmd";
const char *mqtt_topic_firmware = "OTA_Update";
const int mqtt_port = 8883;
const unsigned long MONITOR_INTERVAL = 5000;
const uint32_t WDT_TIMEOUT = 30;
const size_t CHUNK_SIZE = 1024;

// Global variables
SetupState currentState = STATE_INIT_MODEM;
int retryCount = 0;
uint8_t ledStatus = 0;
Adafruit_NeoPixel rgbLed(NUM_PIXELS, RGB_LED_PIN, NEO_GRB + NEO_KHZ800);
bool lcdAvailable = false;
#ifdef ENABLE_LCD
LCD_I2C lcd(0x27, 16, 2);
#else
void *lcd = nullptr;
#endif
String clientID = DEFAULT_CLIENT_ID;
String mqtt_user = DEFAULT_USERNAME;
String mqtt_pass = DEFAULT_PASSWORD;
MqttStatus mqttStatus;

String imei = "";
unsigned long lastMonitorTime = 0;
String pendingTopic = "";
String pendingPayload = "";
bool messageInProgress = false;
int pendingTopicLen = 0;
int pendingPayloadLen = 0;
int receivedPayloadSize = 0;
unsigned char decryptedBuffer[128];
unsigned char encryptedBuffer[128];
bool isProvisioned = false;
Preferences preferences;
bool factoryResetTriggered = false;
bool waitingForProvisionResponse = false;
unsigned long provisionTimeout = 1200000;
unsigned long provisionStartTime = 0;
const unsigned long PROVISION_REQUEST_INTERVAL = 10000;
unsigned long PROVISION_RESTART_TIMEOUT = 120000;
unsigned long lastRequestTime = 0;
static int publishRetryCount = 0;

bool otaInProgress = false;
unsigned long otaReceivedSize = 0;
unsigned long otaTotalSize = 0;
unsigned long chunkCount = 0;
std::vector<unsigned long> missingChunks;
std::map<unsigned long, bool> receivedChunks;
esp_ota_handle_t otaHandle = 0;
const esp_partition_t *updatePartition = NULL;
const esp_partition_t *previousPartition = NULL;
unsigned long bootTime = 0;
unsigned long validationDelay = 60000;
bool pendingValidation = false;
unsigned int mqttErrors = 0;

String otaHash = "";
mbedtls_sha256_context sha256_ctx;

// Base64 encoding/decoding tables
static const char base64_enc_map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char base64_dec_map[128] = {
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 62, 127, 127, 127, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 127, 127, 127, 64, 127, 127,
    127, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 127, 127, 127, 127, 127,
    127, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 127, 127, 127, 127, 127};

// Function declarations
String base64_encode(const unsigned char *input, size_t len);
size_t base64_decode(const char *input, unsigned char *output, size_t out_len);
void printHex(const char *label, const unsigned char *data, size_t len);
void pkcs7_pad(unsigned char *data, size_t data_len, size_t block_size);
size_t pkcs7_unpad(unsigned char *data, size_t data_len);
void check_firmware_partition();
String encryptMessage(const char *message);
String decryptMessage(const char *encryptedBase64);
void handleMessage(String topic, String payload);
bool tryStep(const String &stepMsg, bool success);
void nextState(SetupState next);
void retryState(const String &stepMsg);
void resetModem();
void resetState();
void monitorConnections();
void cleanupResources();
void processURC(String urc);
bool uploadCertificate();
bool setupSSL();
bool setupMQTT();
bool connectMQTT();
bool subscribeMQTT();
bool subscribeMQTT(const char *topic);
bool publishMQTT(const char *topic, const char *message);
bool disconnectMQTT();
bool stopMQTT();
void startOTA(uint32_t totalSize);
void processOTAFirmware(const String &topic, byte *payload, unsigned int dataLen);
void finishOTA();
void checkMissingChunks();
void revertToPreviousFirmware();
void loadCredentials();
void saveCredentials(String newPassword);
bool requestCredentialsFromServer();
bool republishProvisionRequest();
void performFactoryReset();
void resetCredentials();

// UART interrupt handler
static void IRAM_ATTR uart_isr(void *arg) {
    uint8_t buffer[BUFFER_SIZE];
    int len = uart_read_bytes(UART_NUM, buffer, BUFFER_SIZE - 1, 0);
    if (len > 0) {
        buffer[len] = '\0';
        xQueueSendFromISR(uartQueue, buffer, NULL);
    }
}

// Send AT command and wait for response
bool sendAT(const char* cmd, String& response, uint32_t timeout_ms = 1000, const char* expected = "OK") {
    uart_flush(UART_NUM);
    uart_write_bytes(UART_NUM, cmd, strlen(cmd));
    uart_write_bytes(UART_NUM, "\r\n", 2);

    response = "";
    uint32_t start = millis();
    while (millis() - start < timeout_ms) {
        char buffer[BUFFER_SIZE];
        if (xQueueReceive(uartQueue, buffer, pdMS_TO_TICKS(100)) == pdTRUE) {
            response += String(buffer);
            if (response.indexOf(expected) >= 0 || response.indexOf("ERROR") >= 0) {
                return response.indexOf(expected) >= 0;
            }
        }
    }
    return false;
}

// Modem task to process UART data
void modemTask(void *pvParameters) {
    char buffer[BUFFER_SIZE];
    while (1) {
        if (xQueueReceive(uartQueue, buffer, portMAX_DELAY) == pdTRUE) {
            String urc = String(buffer);
            processURC(urc);
        }
    }
}

// Base64 encode function
String base64_encode(const unsigned char *input, size_t len) {
    String output = "";
    int i = 0, j = 0;
    unsigned char char_array_3[3], char_array_4[4];
    while (i < len) {
        char_array_3[j++] = input[i++];
        if (j == 3 || i == len) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((j > 1 ? char_array_3[1] : 0) >> 4);
            char_array_4[2] = j > 1 ? ((char_array_3[1] & 0x0f) << 2) + ((j > 2 ? char_array_3[2] : 0) >> 6) : 0;
            char_array_4[3] = j > 2 ? (char_array_3[2] & 0x3f) : 0;
            for (int k = 0; k < (j + 1); k++) {
                output += base64_enc_map[char_array_4[k]];
            }
            while (j++ < 3) output += '=';
            j = 0;
        }
    }
    return output;
}

// Base64 decode function
size_t base64_decode(const char *input, unsigned char *output, size_t out_len) {
    size_t in_len = strlen(input);
    if (in_len % 4 != 0) return 0;
    size_t out_pos = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        uint32_t n = (base64_dec_map[(unsigned char)input[i]] << 18) +
                     (base64_dec_map[(unsigned char)input[i + 1]] << 12) +
                     (base64_dec_map[(unsigned char)input[i + 2]] << 6) +
                     base64_dec_map[(unsigned char)input[i + 3]];
        if (out_pos + 3 > out_len) return 0;
        output[out_pos++] = (n >> 16) & 0xFF;
        if (input[i + 2] != '=') output[out_pos++] = (n >> 8) & 0xFF;
        if (input[i + 3] != '=') output[out_pos++] = n & 0xFF;
    }
    return out_pos;
}

// Utility function to print hex
void printHex(const char *label, const unsigned char *data, size_t len) {
    SerialMon.print(label);
    for (size_t i = 0; i < len; i++) {
        if (data[i] < 0x10) SerialMon.print("0");
        SerialMon.print(data[i], HEX);
        if (i < len - 1) SerialMon.print(" ");
    }
    SerialMon.println();
}

// PKCS7 padding/unpadding functions
void pkcs7_pad(unsigned char *data, size_t data_len, size_t block_size) {
    unsigned char pad_value = block_size - (data_len % block_size);
    for (size_t i = data_len; i < data_len + pad_value; i++) {
        data[i] = pad_value;
    }
}

size_t pkcs7_unpad(unsigned char *data, size_t data_len) {
    unsigned char pad_value = data[data_len - 1];
    if (pad_value > 16 || pad_value > data_len) return data_len;
    return data_len - pad_value;
}

// Setup function
void setup() {
    esp_task_wdt_reset();
    SerialMon.begin(115200);
    delay(1000);
    SerialMon.println("Starting...");

    mqttStatus.reset();
    otaInProgress = false;
    otaReceivedSize = 0;
    otaTotalSize = 0;
    chunkCount = 0;
    receivedChunks.clear();
    missingChunks.clear();

    // UART configuration
    uart_config_t uart_config = {
        .baud_rate = BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 0,
        .source_clk = UART_SCLK_APB,
    };
    uart_param_config(UART_NUM, &uart_config);
    uart_set_pin(UART_NUM, MODEM_TX, MODEM_RX, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    uart_driver_install(UART_NUM, BUFFER_SIZE * 2, BUFFER_SIZE * 2, 20, NULL, 0);

    // Install ISR
    uartQueue = xQueueCreate(20, BUFFER_SIZE);
    uart_isr_register(UART_NUM, uart_isr, NULL, ESP_INTR_FLAG_IRAM, NULL);
    uart_enable_rx_intr(UART_NUM);

    // Start modem task
    xTaskCreate(modemTask, "modemTask", 4096, NULL, 5, NULL);

    esp_task_wdt_init(WDT_TIMEOUT * 1000, true);
    esp_task_wdt_add(NULL);

    pinMode(FACTORY_RESET_PIN, INPUT_PULLUP);
    check_firmware_partition();
    pinMode(SIM7600_PWR, OUTPUT);
    digitalWrite(SIM7600_PWR, LOW);
    delay(1500);
    digitalWrite(SIM7600_PWR, HIGH);
    delay(5000);

#ifdef ENABLE_LCD
    Wire.begin(I2C_SDA, I2C_SCL);
    lcd.begin();
    lcd.backlight();
    lcd.print("Connecting...");
    lcdAvailable = true;
#else
    lcdAvailable = false;
#endif

    rgbLed.begin();
    rgbLed.show();
    resetCredentials();
    bootTime = millis();

    String response;
    if (sendAT("AT", response, 1000)) {
        SerialMon.println("Modem initialized");
        sendAT("AT+CGSN", response, 1000);
        imei = response;
        imei.replace("\r", "");
        imei.replace("\n", "");
        int okIndex = imei.indexOf("OK");
        if (okIndex != -1) {
            imei = imei.substring(0, okIndex);
        }
        imei.trim();
        SerialMon.print("Cleaned IMEI: ");
        SerialMon.println(imei);
        sendAT("ATE0", response, 1000); // Echo off
        sendAT("AT+CMEE=2", response, 1000); // Verbose errors
        loadCredentials();
        bootTime = millis();
        nextState(STATE_WAIT_NETWORK);
    }
}

void loop() {
    esp_task_wdt_reset();
    if (digitalRead(FACTORY_RESET_PIN) == LOW) {
        delay(50);
        if (digitalRead(FACTORY_RESET_PIN) == LOW) {
            factoryResetTriggered = true;
            performFactoryReset();
        }
    }

    switch (currentState) {
        case STATE_INIT_MODEM: {
            String response;
            if (tryStep("Initializing modem", sendAT("AT", response, 1000))) {
                sendAT("AT+CGSN", response, 1000);
                imei = response;
                imei.replace("\r", "");
                imei.replace("\n", "");
                int okIndex = imei.indexOf("OK");
                if (okIndex != -1) imei = imei.substring(0, okIndex);
                imei.trim();
                nextState(STATE_WAIT_NETWORK);
            }
            break;
        }

        case STATE_WAIT_NETWORK: {
            String response;
            sendAT("AT+CSQ", response, 1000);
            if (tryStep("Waiting for network", response.indexOf("+CSQ:") >= 0 && response.indexOf("99,99") < 0)) {
                nextState(STATE_CONNECT_GPRS);
            }
            break;
        }

        case STATE_CONNECT_GPRS: {
            String response;
            String cmd = String("AT+CGDCONT=1,\"IP\",\"") + apn + "\"";
            sendAT(cmd.c_str(), response, 1000);
            if (tryStep("Connecting to " + String(apn), sendAT("AT+CGATT=1", response, 5000))) {
                nextState(STATE_UPLOAD_CERTIFICATE);
            }
            break;
        }

        case STATE_UPLOAD_CERTIFICATE:
            if (tryStep("Uploading certificate", uploadCertificate())) {
                nextState(STATE_SETUP_SSL);
            }
            break;

        case STATE_SETUP_SSL:
            if (tryStep("Setting up SSL", setupSSL())) {
                nextState(STATE_SETUP_MQTT);
            }
            break;

        case STATE_SETUP_MQTT:
            if (tryStep("Setting up MQTT", setupMQTT())) {
                if (!isProvisioned) {
                    if (requestCredentialsFromServer()) {
                        nextState(STATE_WAIT_PROVISION);
                    } else {
                        nextState(STATE_ERROR);
                    }
                } else {
                    nextState(STATE_CONNECT_MQTT);
                }
            }
            break;

        case STATE_WAIT_PROVISION:
            if (millis() - provisionStartTime >= provisionTimeout) {
                SerialMon.println("Provisioning timeout exceeded");
                waitingForProvisionResponse = false;
                stopMQTT();
                nextState(STATE_ERROR);
            } else if (millis() - lastRequestTime >= PROVISION_REQUEST_INTERVAL) {
                republishProvisionRequest();
            }
            break;

        case STATE_CONNECT_MQTT:
            if (tryStep("Connecting to MQTT", connectMQTT())) {
                nextState(STATE_SUBSCRIBE_MQTT);
            }
            break;

        case STATE_SUBSCRIBE_MQTT:
            if (tryStep("Subscribing to MQTT", subscribeMQTT())) {
                nextState(STATE_RUNNING);
            }
            break;

        case STATE_RUNNING:
            if (millis() - lastMonitorTime >= MONITOR_INTERVAL) {
                monitorConnections();
                lastMonitorTime = millis();
            }
            break;

        case STATE_ERROR:
            SerialMon.println("Setup failed, cleaning up...");
            cleanupResources();
            resetModem();
            nextState(STATE_INIT_MODEM);
            break;

        case STATE_RECOVER_MQTT:
            if (tryStep("Recovering MQTT", connectMQTT() && subscribeMQTT())) {
                nextState(STATE_RUNNING);
            }
            break;
    }
}

String encryptMessage(const char *message) {
    if (!message) return "";
    size_t input_len = strlen(message);
    if (input_len == 0) return "";
    size_t padded_len = ((input_len + 15) / 16) * 16;
    if (padded_len > 1024) {
        SerialMon.println("Message too long: " + String(input_len));
        return "";
    }
    unsigned char *padded_input = new unsigned char[padded_len]();
    if (!padded_input) return "";
    memcpy(padded_input, message, input_len);
    pkcs7_pad(padded_input, input_len, 16);
    unsigned char *output_buffer = new unsigned char[padded_len]();
    if (!output_buffer) {
        delete[] padded_input;
        return "";
    }
    mbedtls_aes_context aes;
    unsigned char iv[16];
    memcpy(iv, aes_iv, 16);
    mbedtls_aes_init(&aes);
    int key_ret = mbedtls_aes_setkey_enc(&aes, aes_key, 256);
    if (key_ret != 0) {
        delete[] padded_input;
        delete[] output_buffer;
        return "";
    }
    int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, padded_input, output_buffer);
    mbedtls_aes_free(&aes);
    String result;
    if (ret == 0) {
        result = base64_encode(output_buffer, padded_len);
    }
    delete[] padded_input;
    delete[] output_buffer;
    return result;
}

String decryptMessage(const char *encryptedBase64) {
    if (!encryptedBase64 || strlen(encryptedBase64) == 0) return "";
    size_t max_input_len = strlen(encryptedBase64);
    if (max_input_len > 1024) return "";
    unsigned char *encrypted_bytes = new unsigned char[max_input_len]();
    if (!encrypted_bytes) return "";
    size_t decoded_len = base64_decode(encryptedBase64, encrypted_bytes, max_input_len);
    if (decoded_len == 0 || decoded_len % 16 != 0) {
        delete[] encrypted_bytes;
        return "";
    }
    unsigned char *output_buffer = new unsigned char[decoded_len]();
    if (!output_buffer) {
        delete[] encrypted_bytes;
        return "";
    }
    mbedtls_aes_context aes;
    unsigned char iv[16];
    memcpy(iv, aes_iv, 16);
    mbedtls_aes_init(&aes);
    int key_ret = mbedtls_aes_setkey_dec(&aes, aes_key, 256);
    if (key_ret != 0) {
        delete[] encrypted_bytes;
        delete[] output_buffer;
        return "";
    }
    int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, decoded_len, iv, encrypted_bytes, output_buffer);
    mbedtls_aes_free(&aes);
    String result;
    if (ret == 0) {
        size_t unpadded_len = pkcs7_unpad(output_buffer, decoded_len);
        result = String((char *)output_buffer, unpadded_len);
    }
    delete[] encrypted_bytes;
    delete[] output_buffer;
    return result;
}

void handleMessage(String topic, String payload) {
    SerialMon.println("Received on topic: " + topic + ", Payload: " + payload);
    if (topic == "server_cmd") {
        String decrypted = decryptMessage(payload.c_str());
        if (decrypted.length() == 0) {
            SerialMon.println("Failed to decrypt message from " + topic);
            return;
        }
        if (decrypted == "RESET_PASSWORD") {
            resetCredentials();
            publishMQTT(PROVISION_TOPIC, "Password reset requested");
            return;
        }
        publishMQTT(mqtt_topic_send, decrypted.c_str());
        String prefixedMessage = imei + decrypted;
        String encryptedPrefixed = encryptMessage(prefixedMessage.c_str());
        if (encryptedPrefixed.length() > 0) {
            publishMQTT(mqtt_topic_send, encryptedPrefixed.c_str());
        }
        ledStatus = !ledStatus;
        digitalWrite(LED_PIN, ledStatus);
#ifdef ENABLE_LCD
        if (lcdAvailable) {
            lcd.clear();
            lcd.print("MQTT Msg:");
            lcd.setCursor(0, 1);
            lcd.print(decrypted.substring(0, 16));
        }
#endif
    } else if (topic == PROVISION_RESPONSE_TOPIC && !isProvisioned && waitingForProvisionResponse) {
        String decrypted = decryptMessage(payload.c_str());
        if (decrypted.startsWith("PASSWORD:")) {
            String newPassword = decrypted.substring(9);
            saveCredentials(newPassword);
            SerialMon.println("Received new password: " + newPassword);
            disconnectMQTT();
            if (!stopMQTT()) {
                SerialMon.println("Failed to stop MQTT, forcing full reset");
                resetState();
                nextState(STATE_INIT_MODEM);
                return;
            }
            waitingForProvisionResponse = false;
            mqttStatus.provisionSubscribed = false;
            if (currentState == STATE_WAIT_PROVISION) {
                nextState(STATE_CONNECT_MQTT);
            } else {
                SerialMon.println("Unexpected state during provisioning: " + String(currentState));
                nextState(STATE_SETUP_MQTT);
            }
        } else {
            SerialMon.println("Invalid provisioning response");
            nextState(STATE_ERROR);
        }
    } else if (topic == "OTA_Update") {
        if (payload == "reverse old firmware" && pendingValidation) {
            revertToPreviousFirmware();
        } else {
            SerialMon.println("OTA_Update matched, calling processOTAFirmware");
            byte *payloadBytes = (byte *)payload.c_str();
            unsigned int payloadLen = payload.length();
            processOTAFirmware(topic, payloadBytes, payloadLen);
        }
    }
}

bool tryStep(const String &stepMsg, bool success) {
    SerialMon.print(stepMsg + "... ");
    if (success) {
        SerialMon.println("success");
        retryCount = 0;
        return true;
    }
    SerialMon.println("fail");
    retryState(stepMsg);
    return false;
}

void nextState(SetupState next) {
    currentState = next;
    retryCount = 0;
}

void retryState(const String &stepMsg) {
    retryCount++;
    if (retryCount >= MAX_RETRIES) {
        SerialMon.println("Max retries reached for " + stepMsg);
        if (currentState >= STATE_CONNECT_MQTT) {
            disconnectMQTT();
            stopMQTT();
        }
        resetModem();
        resetState();
    } else {
        delay(RETRY_DELAY);
    }
}

void resetModem() {
    SerialMon.println("Resetting modem...");
    digitalWrite(SIM7600_PWR, LOW);
    delay(1500);
    digitalWrite(SIM7600_PWR, HIGH);
    delay(5000);
    mqttStatus.serviceStarted = false;
}

void resetState() {
    SerialMon.println("Resetting state data...");
    currentState = STATE_INIT_MODEM;
    retryCount = 0;
    if (otaInProgress) {
        cleanupResources();
    }
    ledStatus = 0;
    digitalWrite(LED_PIN, ledStatus);
    rgbLed.setPixelColor(0, 0, 0, 0);
    rgbLed.show();
#ifdef ENABLE_LCD
    if (lcdAvailable) {
        lcd.clear();
        lcd.print("Resetting...");
    }
#endif
}

void monitorConnections() {
    String response;
    sendAT("AT+CSQ", response, 1000);
    if (response.indexOf("+CSQ:") < 0 || response.indexOf("99,99") >= 0) {
        SerialMon.println("Network lost");
        if (otaInProgress) {
            SerialMon.println("OTA interrupted by network loss");
            cleanupResources();
            publishMQTT(mqtt_topic_send, "OTA:ERROR:Network lost");
        }
        nextState(STATE_RECOVER_NETWORK);
    } else {
        sendAT("AT+CGATT?", response, 1000);
        if (response.indexOf("+CGATT: 1") < 0) {
            SerialMon.println("GPRS disconnected");
            if (otaInProgress) {
                SerialMon.println("OTA interrupted by GPRS loss");
                cleanupResources();
                publishMQTT(mqtt_topic_send, "OTA:ERROR:GPRS lost");
            }
            nextState(STATE_RECOVER_GPRS);
        }
    }
}

void cleanupResources() {
    SerialMon.println("Cleaning up resources...");
    String response;
    sendAT("AT+CGATT=0", response, 5000);
    stopMQTT();
    if (otaInProgress) {
        esp_ota_end(otaHandle);
        otaInProgress = false;
        otaReceivedSize = 0;
        otaTotalSize = 0;
        chunkCount = 0;
        receivedChunks.clear();
        missingChunks.clear();
        SerialMon.println("OTA data cleared due to cleanup");
    }
    pendingTopic = "";
    pendingPayload = "";
    publishRetryCount = 0;
    waitingForProvisionResponse = false;
}

void processURC(String urc) {
    urc.trim();
    if (urc.length() > 0) {
        SerialMon.println("URC: " + urc);
    }
    if (urc.startsWith("+CMQTTCONNLOST: 0,")) {
        SerialMon.println("MQTT connection lost detected");
        mqttStatus.connected = false;
        mqttStatus.subscribed = false;
        if (currentState == STATE_RUNNING || currentState == STATE_WAIT_PROVISION) {
            nextState(STATE_RECOVER_MQTT);
        }
    } else if (urc.startsWith("+CMQTTSUB: 0,0")) {
        SerialMon.println("Subscription confirmed via URC");
        if (!mqttStatus.provisionSubscribed && waitingForProvisionResponse) {
            mqttStatus.provisionSubscribed = true;
        }
    } else if (urc.startsWith("+CMQTTRXPAYLOAD: 0,")) {
        pendingPayloadLen = urc.substring(urc.indexOf(",") + 1).toInt();
        pendingPayload = "";
        receivedPayloadSize = 0;
    } else if (urc.startsWith("+CMQTTACCQ: 0,0")) {
        SerialMon.println("MQTT client acquisition confirmed via URC");
        mqttStatus.clientAcquired = true;
    } else if (urc.startsWith("+CMQTTCONNECT: 0,0")) {
        SerialMon.println("MQTT connection confirmed via URC");
        mqttStatus.connected = true;
        mqttStatus.lastConnectTime = millis();
        if (currentState == STATE_CONNECT_MQTT) {
            nextState(STATE_SUBSCRIBE_MQTT);
        }
    } else if (urc.startsWith("+CMQTTRXSTART: 0,")) {
        messageInProgress = true;
        pendingTopic = "";
        pendingPayload = "";
        int commaIdx = urc.indexOf(',', 14);
        pendingTopicLen = urc.substring(14, commaIdx).toInt();
        pendingPayloadLen = urc.substring(commaIdx + 1).toInt();
    } else if (messageInProgress && !urc.startsWith("+") && pendingTopic == "") {
        pendingTopic = urc;
    } else if (messageInProgress && !urc.startsWith("+") && pendingTopic != "" && pendingPayload == "") {
        pendingPayload = urc;
    } else if (!urc.startsWith("+") && pendingPayloadLen > 0) {
        pendingPayload += urc;
        receivedPayloadSize += urc.length();
        SerialMon.println("Payload chunk received, total size so far: " + String(receivedPayloadSize));
    } else if (urc == "+CMQTTRXEND: 0") {
        if (receivedPayloadSize != pendingPayloadLen) {
            SerialMon.println("Warning: Received " + String(receivedPayloadSize) + " bytes, expected " + String(pendingPayloadLen));
        }
        handleMessage(pendingTopic, pendingPayload);
        pendingTopic = "";
        pendingPayload = "";
        pendingTopicLen = 0;
        pendingPayloadLen = 0;
        receivedPayloadSize = 0;
    }
}

bool uploadCertificate() {
    String response;
    sendAT("+CCERTLIST", response, 2000);
    if (response.indexOf(String("+CCERTLIST: \"") + cert_name + "\"") >= 0) {
        SerialMon.println("Certificate '" + String(cert_name) + "' exists");
        return true;
    }
    String cmd = String("+CCERTDOWN=\"") + cert_name + "\"," + String(strlen(root_ca));
    sendAT(cmd.c_str(), response, 2000, ">");
    if (response.indexOf(">") < 0) return false;
    uart_write_bytes(UART_NUM, root_ca, strlen(root_ca));
    return sendAT("", response, 5000);
}

bool setupSSL() {
    String response;
    if (!sendAT("+CSSLCFG=\"sslversion\",0,4", response, 1000)) return false;
    String cmd = String("+CSSLCFG=\"cacert\",0,\"") + cert_name + "\"";
    if (!sendAT(cmd.c_str(), response, 1000)) return false;
    return sendAT("+CSSLCFG=\"authmode\",0,1", response, 1000);
}

bool setupMQTT() {
    String response;
    if (!mqttStatus.serviceStarted) {
        if (!sendAT("AT+CMQTTSTART", response, 5000) || response.indexOf("+CMQTTSTART: 0") < 0) {
            SerialMon.println("MQTT start failed - Response: " + response);
            if (response.indexOf("+CMQTTSTART: 23") >= 0) {
                SerialMon.println("MQTT service already running (+CMQTTSTART: 23), proceeding");
                mqttStatus.serviceStarted = true;
            } else {
                return false;
            }
        } else {
            mqttStatus.serviceStarted = true;
            SerialMon.println("MQTT service started successfully");
        }
    } else {
        SerialMon.println("MQTT service already started, skipping AT+CMQTTSTART");
    }

    if (!mqttStatus.clientAcquired) {
        unsigned long timeVal = millis() & 0xFFF;
        clientID = "ESP32_" + String(timeVal);
        SerialMon.println("Generated clientID: " + clientID);
        String cmd = "AT+CMQTTACCQ=0,\"" + clientID + "\",1";
        if (!sendAT(cmd.c_str(), response, 10000)) {
            SerialMon.println("Failed to acquire MQTT client - Response: " + response);
            if (response.indexOf("+CMQTTACCQ: 0,19") >= 0) {
                SerialMon.println("Client index in use, resetting...");
                stopMQTT();
                resetModem();
                return false;
            }
            return false;
        }
        mqttStatus.clientAcquired = true;
        SerialMon.println("MQTT client acquired successfully");
    } else {
        SerialMon.println("MQTT client already acquired, skipping AT+CMQTTACCQ");
    }

    if (!sendAT("AT+CMQTTSSLCFG=0,1", response, 2000)) {
        SerialMon.println("Failed to configure SSL for MQTT");
        return false;
    }

    SerialMon.println("Setting up MQTT... success");
    return true;
}

bool connectMQTT() {
    if (mqttStatus.connected) {
        SerialMon.println("MQTT already connected, skipping connect");
        return true;
    }
    if (!mqttStatus.serviceStarted || !mqttStatus.clientAcquired) {
        SerialMon.println("MQTT service or client not ready, setting up...");
        if (!setupMQTT()) return false;
    }
    String cmd = "AT+CMQTTCONNECT=0,\"tcp://" + String(mqtt_server) + ":" + String(mqtt_port) + "\",60,1,\"" + mqtt_user + "\",\"" + mqtt_pass + "\"";
    SerialMon.println("Connecting - ClientID: " + clientID + ", User: " + mqtt_user + ", Pass: " + mqtt_pass);
    String response;
    if (!sendAT(cmd.c_str(), response, 30000)) {
        SerialMon.println("Connect failed: " + response);
        if (response.indexOf("+CMQTTCONNECT: 0,") >= 0) {
            mqttStatus.lastErrorCode = response.substring(response.indexOf(",") + 1).toInt();
            SerialMon.println("Error code: " + String(mqttStatus.lastErrorCode));
        }
        return false;
    }
    if (response.indexOf("+CMQTTCONNECT: 0,0") >= 0) {
        mqttStatus.connected = true;
        SerialMon.println("MQTT connected");
        return true;
    }
    SerialMon.println("No success URC: " + response);
    return false;
}

bool subscribeMQTT(const char *topic) {
    if (!topic || strlen(topic) == 0) {
        SerialMon.println("Invalid topic provided for subscription");
        return false;
    }
    if (!mqttStatus.connected) {
        SerialMon.println("MQTT not connected, cannot subscribe to: " + String(topic));
        return false;
    }
    int topicLen = strlen(topic);
    SerialMon.println("Subscribing to: " + String(topic));
    String cmd = "AT+CMQTTSUBTOPIC=0," + String(topicLen) + ",1";
    String response;
    if (!sendAT(cmd.c_str(), response, 2000, ">") || response.indexOf(">") < 0) {
        SerialMon.println("Failed to get '>' prompt for SUBTOPIC: " + response);
        return false;
    }
    uart_write_bytes(UART_NUM, topic, topicLen);
    if (!sendAT("", response, 2000)) {
        SerialMon.println("Failed to send topic: " + response);
        return false;
    }
    if (!sendAT("AT+CMQTTSUB=0", response, 10000) || response.indexOf("+CMQTTSUB: 0,0") < 0) {
        SerialMon.println("Subscription failed: " + response);
        return false;
    }
    SerialMon.println("Successfully subscribed to: " + String(topic));
    return true;
}

bool subscribeMQTT() {
    if (mqttStatus.subscribed) {
        SerialMon.println("Already subscribed to MQTT topics, skipping");
        return true;
    }
    bool success = true;
    success &= subscribeMQTT(mqtt_topic_recv);
    success &= subscribeMQTT(mqtt_topic_firmware);
    if (success) {
        mqttStatus.subscribed = true;
        SerialMon.println("MQTT subscriptions completed");
    }
    return success;
}

bool publishMQTT(const char *topic, const char *message) {
    if (!mqttStatus.serviceStarted || !connectMQTT()) {
        SerialMon.println("Cannot publish: MQTT not ready");
        return false;
    }
    if (!topic || !message) return false;
    String response;
    String cmd = "AT+CMQTTTOPIC=0," + String(strlen(topic));
    if (!sendAT(cmd.c_str(), response, 500, ">") || response.indexOf(">") < 0) {
        SerialMon.println("Failed to set topic: " + response);
        return false;
    }
    uart_write_bytes(UART_NUM, topic, strlen(topic));
    if (!sendAT("", response, 500)) {
        SerialMon.println("Topic write failed: " + response);
        return false;
    }
    cmd = "AT+CMQTTPAYLOAD=0," + String(strlen(message));
    if (!sendAT(cmd.c_str(), response, 500, ">") || response.indexOf(">") < 0) {
        SerialMon.println("Failed to set payload: " + response);
        return false;
    }
    uart_write_bytes(UART_NUM, message, strlen(message));
    if (!sendAT("", response, 500)) {
        SerialMon.println("Payload write failed: " + response);
        return false;
    }
    if (!sendAT("AT+CMQTTPUB=0,1,60", response, 2000) || (response.indexOf("OK") < 0 && response.indexOf("+CMQTTPUB: 0,0") < 0)) {
        SerialMon.println("Publish failed: " + response);
        return false;
    }
    SerialMon.println("Published to " + String(topic) + ": " + String(message));
    return true;
}

bool disconnectMQTT() {
    if (!mqttStatus.serviceStarted) {
        SerialMon.println("MQTT service not started, no need to disconnect");
        return true;
    }
    String response;
    if (!sendAT("AT+CMQTTDISC=0,120", response, 15000) || response.indexOf("+CMQTTDISC: 0,0") < 0) {
        SerialMon.println("Failed to disconnect MQTT: " + response);
        return false;
    }
    mqttStatus.connected = false;
    SerialMon.println("MQTT disconnected");
    return true;
}

bool stopMQTT() {
    if (!mqttStatus.serviceStarted) {
        SerialMon.println("MQTT service already stopped");
        return true;
    }
    String response;
    if (mqttStatus.connected) {
        if (!sendAT("AT+CMQTTDISC=0,120", response, 15000) || response.indexOf("+CMQTTDISC: 0,0") < 0) {
            SerialMon.println("Disconnect failed: " + response);
        }
        mqttStatus.connected = false;
    }
    if (mqttStatus.clientAcquired) {
        if (!sendAT("AT+CMQTTREL=0", response, 5000)) {
            SerialMon.println("Release failed: " + response);
        }
        mqttStatus.clientAcquired = false;
    }
    if (!sendAT("AT+CMQTTSTOP", response, 10000) || response.indexOf("+CMQTTSTOP: 0") < 0) {
        SerialMon.println("Stop failed: " + response);
        resetModem();
        mqttStatus.reset();
        return false;
    }
    mqttStatus.reset();
    SerialMon.println("MQTT service stopped successfully");
    return true;
}

void startOTA(uint32_t totalSize) {
    previousPartition = esp_ota_get_running_partition();
    updatePartition = esp_ota_get_next_update_partition(NULL);
    if (!updatePartition) {
        SerialMon.println("No valid OTA partition available");
        publishMQTT(mqtt_topic_send, "OTA:ERROR:No partition");
        return;
    }
    esp_err_t err = esp_ota_begin(updatePartition, totalSize, &otaHandle);
    if (err != ESP_OK) {
        SerialMon.printf("OTA begin failed: %s\n", esp_err_to_name(err));
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Begin failed");
        return;
    }
    otaInProgress = true;
    pendingValidation = false;
    otaTotalSize = totalSize;
    otaReceivedSize = 0;
    chunkCount = 0;
    receivedChunks.clear();
    missingChunks.clear();
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    SerialMon.println("OTA started from " + String(previousPartition->label) + " to " + String(updatePartition->label));
    publishMQTT(mqtt_topic_send, "OTA:STARTED");
}

void processOTAFirmware(const String &topic, byte *payload, unsigned int dataLen) {
    SerialMon.println("ENTER processOTAFirmware");
    SerialMon.print("Topic: ["); SerialMon.print(topic); SerialMon.print("], Length: "); SerialMon.println(dataLen);
    if (topic != mqtt_topic_firmware) {
        SerialMon.println("Ignoring OTA message: wrong topic");
        return;
    }
    String payloadStr((char *)payload, dataLen);
    if (payloadStr.startsWith("OTA:BEGIN:")) {
        if (otaInProgress || pendingValidation) {
            SerialMon.println("Previous OTA detected, cleaning up...");
            cleanupResources();
        }
        int colonIdx = payloadStr.indexOf(':', 10);
        uint32_t totalSize = payloadStr.substring(10, colonIdx).toInt();
        otaHash = payloadStr.substring(colonIdx + 1);
        SerialMon.println("Starting OTA with total size: " + String(totalSize) + ", hash: " + otaHash);
        startOTA(totalSize);
        publishMQTT(mqtt_topic_send, "OTA:STARTED");
        return;
    }
    if (!otaInProgress) {
        SerialMon.println("Ignoring OTA message: OTA not started");
        return;
    }
    if (pendingValidation) {
        SerialMon.println("Ignoring OTA message: OTA pending validation");
        return;
    }
    if (payloadStr == "OTA:END") {
        SerialMon.println("Received OTA:END");
        finishOTA();
        return;
    }
    if (payloadStr == "OTA:CANCEL") {
        if (otaInProgress) {
            SerialMon.println("Cancelling ongoing OTA update");
            cleanupResources();
            publishMQTT(mqtt_topic_firmware, "OTA:CANCELLED");
        } else {
            SerialMon.println("No OTA in progress to cancel");
        }
        return;
    }
    size_t maxDecodedLen = ((dataLen + 3) / 4) * 3;
    unsigned char *decodedPayload = new unsigned char[maxDecodedLen];
    size_t decodedLen = base64_decode((char *)payload, decodedPayload, maxDecodedLen);
    if (decodedLen < 4) {
        SerialMon.println("Invalid decoded chunk size: " + String(decodedLen));
        delete[] decodedPayload;
        return;
    }
    unsigned long chunkNum = ((unsigned long)decodedPayload[0] << 24) |
                             ((unsigned long)decodedPayload[1] << 16) |
                             ((unsigned long)decodedPayload[2] << 8) |
                             decodedPayload[3];
    size_t chunkSize = decodedLen - 4;
    if (chunkSize > OTA_MAX_DATA_SIZE) {
        SerialMon.println("Chunk too large: " + String(chunkSize) + " for chunk " + String(chunkNum));
        delete[] decodedPayload;
        return;
    }
    if (receivedChunks[chunkNum]) {
        SerialMon.println("Duplicate chunk " + String(chunkNum));
        delete[] decodedPayload;
        return;
    }
    esp_err_t err = esp_ota_write(otaHandle, decodedPayload + 4, chunkSize);
    if (err != ESP_OK) {
        SerialMon.printf("OTA write failed for chunk %lu: %s\n", chunkNum, esp_err_to_name(err));
        cleanupResources();
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Write failed");
        delete[] decodedPayload;
        return;
    }
    mbedtls_sha256_update(&sha256_ctx, decodedPayload + 4, chunkSize);
    receivedChunks[chunkNum] = true;
    otaReceivedSize += chunkSize;
    chunkCount++;
    SerialMon.println("Processed chunk " + String(chunkNum) + ", size=" + String(chunkSize));
    static int chunksSinceAck = 0;
    chunksSinceAck++;
    if (chunksSinceAck >= BATCH_SIZE) {
        String ackMsg = "OTA:PROGRESS:" + String(chunkNum) + ":" + String(otaReceivedSize) + "/" + String(otaTotalSize);
        publishMQTT(mqtt_topic_firmware, ackMsg.c_str());
        chunksSinceAck = 0;
    }
    delete[] decodedPayload;
}

void finishOTA() {
    if (!otaInProgress) {
        SerialMon.println("No OTA in progress to finish");
        return;
    }
    const int MAX_CHUNK_RETRIES = 3;
    int retryCount = 0;
    while (retryCount < MAX_CHUNK_RETRIES) {
        checkMissingChunks();
        if (otaReceivedSize == otaTotalSize) break;
        SerialMon.println("Missing chunks detected, retry " + String(retryCount + 1) + "/" + String(MAX_CHUNK_RETRIES));
        delay(5000);
        retryCount++;
    }
    if (otaReceivedSize != otaTotalSize) {
        SerialMon.println("OTA incomplete: Received " + String(otaReceivedSize) + "/" + String(otaTotalSize));
        cleanupResources();
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Incomplete");
        return;
    }
    unsigned char hash[32];
    mbedtls_sha256_finish(&sha256_ctx, hash);
    mbedtls_sha256_free(&sha256_ctx);
    String computedHash = "";
    for (int i = 0; i < 32; i++) {
        char hex[3];
        sprintf(hex, "%02x", hash[i]);
        computedHash += hex;
    }
    if (computedHash != otaHash) {
        SerialMon.println("Hash mismatch: " + computedHash + " vs " + otaHash);
        cleanupResources();
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Hash mismatch");
        publishMQTT(mqtt_topic_send, "OTA:REQUEST:RETRY");
        return;
    }
    esp_err_t err = esp_ota_end(otaHandle);
    if (err != ESP_OK) {
        SerialMon.printf("OTA end failed: %s\n", esp_err_to_name(err));
        cleanupResources();
        publishMQTT(mqtt_topic_send, "OTA:ERROR:End failed");
        return;
    }
    SerialMon.println("OTA update written, validating...");
    publishMQTT(mqtt_topic_send, "OTA:SUCCESS:PENDING_VALIDATION");
    pendingValidation = true;
    delay(10000);
    err = esp_ota_set_boot_partition(updatePartition);
    if (err != ESP_OK) {
        SerialMon.printf("OTA set boot partition failed: %s\n", esp_err_to_name(err));
        publishMQTT(mqtt_topic_firmware, "OTA:ERROR:Set boot failed");
        return;
    }
    SerialMon.println("OTA successful, restarting...");
    delay(1000);
    otaInProgress = false;
    ESP.restart();
}

void checkMissingChunks() {
    SerialMon.println("Checking for missing chunks...");
    unsigned long expectedChunks = (otaTotalSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
    String missingMsg = "OTA:REQUEST:";
    bool hasMissing = false;
    for (unsigned long i = 0; i < expectedChunks; i++) {
        if (!receivedChunks[i]) {
            missingMsg += String(i) + ",";
            hasMissing = true;
        }
    }
    if (hasMissing) {
        missingMsg.remove(missingMsg.length() - 1);
        SerialMon.println("Requesting missing chunks: " + missingMsg);
        publishMQTT(mqtt_topic_send, missingMsg.c_str());
    } else {
        SerialMon.println("No missing chunks detected");
    }
}

void revertToPreviousFirmware() {
    if (previousPartition == NULL) {
        SerialMon.println("No previous partition known");
        publishMQTT(mqtt_topic_send, "REVERT:ERROR:No previous partition");
        return;
    }
    const esp_partition_t *current = esp_ota_get_running_partition();
    if (current == previousPartition) {
        SerialMon.println("Already running previous firmware");
        publishMQTT(mqtt_topic_send, "REVERT:ERROR:Already on previous");
        return;
    }
    esp_err_t err = esp_ota_set_boot_partition(previousPartition);
    if (err != ESP_OK) {
        SerialMon.printf("Failed to set boot partition: %s\n", esp_err_to_name(err));
        publishMQTT(mqtt_topic_send, "REVERT:ERROR:Set failed");
        return;
    }
    SerialMon.println("Reverting to previous firmware: " + String(previousPartition->label));
    String revertMsg = String("REVERT:SUCCESS:") + String(previousPartition->label);
    publishMQTT(mqtt_topic_send, revertMsg.c_str());
#ifdef ENABLE_LCD
    if (lcdAvailable) {
        lcd.clear();
        lcd.print("Reverting...");
    }
#endif
    pendingValidation = false;
    delay(1000);
    ESP.restart();
}

void performFactoryReset() {
    const esp_partition_t *factoryPartition = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL);
    if (factoryPartition == NULL) {
        SerialMon.println("Factory partition not found");
        publishMQTT(mqtt_topic_send, "FACTORY_RESET:ERROR:No factory partition");
        return;
    }
    esp_err_t err = esp_ota_set_boot_partition(factoryPartition);
    if (err != ESP_OK) {
        SerialMon.printf("Failed to set factory partition: %s\n", esp_err_to_name(err));
        publishMQTT(mqtt_topic_send, "FACTORY_RESET:ERROR:Set failed");
        return;
    }
    preferences.begin("device-creds", false);
    preferences.clear();
    preferences.end();
    isProvisioned = false;
    clientID = DEFAULT_CLIENT_ID;
    mqtt_user = DEFAULT_USERNAME;
    mqtt_pass = DEFAULT_PASSWORD;
    SerialMon.println("Factory reset complete");
    publishMQTT(mqtt_topic_send, "FACTORY_RESET:SUCCESS");
#ifdef ENABLE_LCD
    if (lcdAvailable) {
        lcd.clear();
        lcd.print("Factory Reset");
    }
#endif
    delay(1000);
    ESP.restart();
}

void check_firmware_partition() {
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running->subtype == ESP_PARTITION_SUBTYPE_APP_FACTORY) {
        SerialMon.println("Running from factory partition");
#ifdef ENABLE_LCD
        if (lcdAvailable) {
            lcd.clear();
            lcd.print("Factory Mode");
        }
#endif
    } else if (running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0 || running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1) {
        SerialMon.printf("Running from OTA partition %d\n", running->subtype - ESP_PARTITION_SUBTYPE_APP_OTA_0);
#ifdef ENABLE_LCD
        if (lcdAvailable) {
            lcd.clear();
            lcd.print("OTA Mode");
        }
#endif
    }
}

void resetCredentials() {
    preferences.begin("device-creds", false);
    preferences.clear();
    preferences.end();
    isProvisioned = false;
    clientID = DEFAULT_CLIENT_ID;
    mqtt_user = DEFAULT_USERNAME;
    mqtt_pass = DEFAULT_PASSWORD;
    SerialMon.println("Credentials reset to defaults");
#ifdef ENABLE_LCD
    if (lcdAvailable) {
        lcd.clear();
        lcd.print("Creds Reset");
    }
#endif
}

void loadCredentials() {
    preferences.begin("device-creds", true);
    isProvisioned = preferences.getBool("provisioned", false);
    if (isProvisioned) {
        clientID = preferences.getString("client_id", "GESUS_" + String(millis()));
        mqtt_user = preferences.getString("username", "ESP32_" + imei);
        mqtt_pass = preferences.getString("password", "");
        if (mqtt_pass == "") {
            SerialMon.println("Warning: No saved password found, resetting to default");
            isProvisioned = false;
            clientID = DEFAULT_CLIENT_ID;
            mqtt_user = DEFAULT_USERNAME;
            mqtt_pass = DEFAULT_PASSWORD;
        }
    } else {
        clientID = DEFAULT_CLIENT_ID;
        mqtt_user = DEFAULT_USERNAME;
        mqtt_pass = DEFAULT_PASSWORD;
    }
    mqtt_user.replace("\r", "");
    mqtt_user.replace("\n", "");
    int okIndex = mqtt_user.indexOf("OK");
    if (okIndex != -1) mqtt_user = mqtt_user.substring(0, okIndex);
    mqtt_user.trim();
    mqtt_pass.replace("\r", "");
    mqtt_pass.replace("\n", "");
    mqtt_pass.trim();
    preferences.end();
    SerialMon.println("Loaded credentials:");
    SerialMon.println("Client ID: " + clientID);
    SerialMon.println("Username: " + mqtt_user);
    SerialMon.println("Provisioned: " + String(isProvisioned ? "Yes" : "No"));
}

void saveCredentials(String newPassword) {
    if (imei == "" || imei == "Unknown") {
        SerialMon.println("Cannot save credentials without valid IMEI");
        return;
    }
    mqtt_user = "ESP32_" + imei;
    mqtt_user.replace("\r", "");
    mqtt_user.replace("\n", "");
    int okIndex = mqtt_user.indexOf("OK");
    if (okIndex != -1) mqtt_user = mqtt_user.substring(0, okIndex);
    mqtt_user.trim();
    if (!isProvisioned) {
        clientID = "GESUS_" + String(millis());
    }
    mqtt_pass = newPassword;
    mqtt_pass.replace("\r", "");
    mqtt_pass.replace("\n", "");
    mqtt_pass.trim();
    preferences.begin("device-creds", false);
    preferences.putString("client_id", clientID);
    preferences.putString("username", mqtt_user);
    preferences.putString("password", mqtt_pass);
    preferences.putBool("provisioned", true);
    preferences.end();
    isProvisioned = true;
    SerialMon.println("Saved new credentials:");
    SerialMon.println("Client ID: " + clientID);
    SerialMon.println("Username: " + mqtt_user);
    SerialMon.println("Password length: " + String(mqtt_pass.length()));
}

bool republishProvisionRequest() {
    if (!mqttStatus.serviceStarted || !mqttStatus.provisionSubscribed) {
        SerialMon.println("Cannot republish: MQTT not fully set up");
        return false;
    }
    String requestMsg = "IMEI:" + imei;
    if (publishMQTT(PROVISION_TOPIC, requestMsg.c_str())) {
        SerialMon.println("Republished credentials request with IMEI: " + imei);
        lastRequestTime = millis();
        return true;
    } else {
        SerialMon.println("Failed to republish provisioning request");
        return false;
    }
}

bool requestCredentialsFromServer() {
    if (imei == "" || imei == "Unknown") {
        SerialMon.println("No IMEI available for provisioning");
        return false;
    }
    mqtt_user = DEFAULT_USERNAME;
    mqtt_pass = DEFAULT_PASSWORD;
    if (!mqttStatus.serviceStarted || !mqttStatus.clientAcquired) {
        if (!setupMQTT()) return false;
    }
    if (!mqttStatus.connected) {
        if (!connectMQTT()) return false;
    }
    if (!mqttStatus.provisionSubscribed) {
        if (subscribeMQTT(PROVISION_RESPONSE_TOPIC)) {
            mqttStatus.provisionSubscribed = true;
        } else {
            return false;
        }
    }
    String requestMsg = "IMEI:" + imei;
    if (publishMQTT(PROVISION_TOPIC, requestMsg.c_str())) {
        SerialMon.println("Credentials request sent with IMEI: " + imei);
        waitingForProvisionResponse = true;
        provisionStartTime = millis();
        lastRequestTime = millis();
        return true;
    }
    return false;
}