#define TINY_GSM_MODEM_SIM7600
#define ENABLE_LCD

#include <Wire.h>
#include <TinyGsmClient.h>
#include <HardwareSerial.h>
#include <Adafruit_NeoPixel.h>
#ifdef ENABLE_LCD
#include <LCD_I2C.h>
#endif
#include <esp_task_wdt.h>
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <esp_ota_ops.h>
#include <Preferences.h>
#include <esp_random.h>
#include <map> // Ensure std::map is included
#include <vector>
#include <certificates.h>


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

// Default credentials (randomized)
String generateRandomString(size_t length) {
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    String result;
    for (size_t i = 0; i < length; i++) {
        result += charset[esp_random() % (sizeof(charset) - 1)];
    }
    return result;
}
//String DEFAULT_CLIENT_ID = "ESP32_" + generateRandomString(8);
//String DEFAULT_USERNAME = generateRandomString(12);
//String DEFAULT_PASSWORD = generateRandomString(16);

String DEFAULT_CLIENT_ID = "ESP32_SIM7600";
String DEFAULT_USERNAME = "ESP32";
String DEFAULT_PASSWORD = "12345";

// APN configuration
const char apn[] = "internet";
const char gprsUser[] = "";
const char gprsPass[] = "";

// Serial interfaces
HardwareSerial sim7600(1);
#define SerialMon Serial
#define SerialAT sim7600
TinyGsm modem(SerialAT);

// Encryption and OTA settings
unsigned char aes_key[32]; // Dynamically generated
unsigned char device_key[32]; // For NVS encryption
const char* SERVER_PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\n"
                                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcUqag9hF6FwK6OCEPD1leoTZYjAH\n"
                                    "fMeNrht9Aiufk2jMGiQjIhnU22PM9Vt6XfdhNC7Qjd4xqBmCkFXsB0q2HA==\n"
                                    "-----END PUBLIC KEY-----\n"; // Replace with actual server public key
                                    

// State machine states
enum SetupState {
    STATE_INIT_MODEM, STATE_WAIT_NETWORK, STATE_CONNECT_GPRS, STATE_UPLOAD_CERTIFICATE,
    STATE_SETUP_SSL, STATE_SETUP_MQTT, STATE_CONNECT_MQTT, STATE_SUBSCRIBE_MQTT,
    STATE_RUNNING, STATE_WAIT_PROVISION, STATE_ERROR, STATE_RECOVER_MQTT
};

// MQTT status structure
struct MqttStatus {
    bool serviceStarted = false;
    bool clientAcquired = false;
    bool connected = false;
    bool subscribed = false;
    bool provisionSubscribed = false;
    int lastErrorCode = 0;
    unsigned long lastConnectTime = 0;
    void reset() {
        serviceStarted = clientAcquired = connected = subscribed = provisionSubscribed = false;
        lastErrorCode = 0;
        lastConnectTime = 0;
    }
};

// Configuration
const int MAX_RETRIES = 10;
const int RETRY_DELAY = 2000;
const size_t OTA_CHUNK_SIZE = 1028;
const size_t OTA_MAX_DATA_SIZE = OTA_CHUNK_SIZE - 4;
const char* cert_name = "iot_inverter2.pem";
const char* mqtt_server = "u008dd8e.ala.dedicated.aws.emqxcloud.com";
#define PROVISION_TOPIC "dev_pass_req"
#define PROVISION_RESPONSE_TOPIC "dev_pass_res"
const char* mqtt_topic_send = "esp32_status";
const char* mqtt_topic_recv = "server_cmd";
const char* mqtt_topic_firmware = "OTA_Update";
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
void* lcd = nullptr;
#endif
String clientID = DEFAULT_CLIENT_ID;
String mqtt_user = DEFAULT_USERNAME;
String mqtt_pass = DEFAULT_PASSWORD;
MqttStatus mqttStatus;
String deviceUUID;
unsigned long lastMonitorTime = 0;
String pendingTopic = "";
String pendingPayload = "";
bool messageInProgress = false;
int pendingTopicLen = 0;
int pendingPayloadLen = 0;
int receivedPayloadSize = 0;
bool isProvisioned = false;
Preferences preferences;
bool waitingForProvisionResponse = false;
unsigned long provisionTimeout = 300000;
unsigned long provisionStartTime = 0;
const unsigned long PROVISION_REQUEST_INTERVAL = 30000;
unsigned long lastRequestTime = 0;
bool otaInProgress = false;
String otaSignature; // Base64-encoded ECDSA signature from OTA:BEGIN
unsigned long otaReceivedSize = 0;
unsigned long otaTotalSize = 0;
unsigned long chunkCount = 0;
std::map<unsigned long, bool> receivedChunks;
esp_ota_handle_t otaHandle = 0;
const esp_partition_t *updatePartition = NULL;
const esp_partition_t *previousPartition = NULL;
String otaHash = "";
mbedtls_sha256_context sha256_ctx;

// Base64 encoding/decoding tables (unchanged)
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
String base64_encode(const unsigned char* input, size_t len);
size_t base64_decode(const char* input, unsigned char* output, size_t out_len);
void pkcs7_pad(unsigned char* data, size_t data_len, size_t block_size);
size_t pkcs7_unpad(unsigned char* data, size_t data_len);
void generateEncryptionKeys();
String encryptMessage(const char* message, unsigned char* iv_out);
String decryptMessage(const char* encryptedBase64, const unsigned char* iv);
void encryptNVSData(unsigned char* data, size_t len, unsigned char* out);
void decryptNVSData(unsigned char* data, size_t len, unsigned char* out);
bool verifyOTASignature(const unsigned char* firmware, size_t len, const unsigned char* signature, size_t sig_len);
void handleMessage(String topic, String payload);
bool tryStep(const String& stepMsg, bool success);
void nextState(SetupState next);
void retryState(const String& stepMsg);
void resetModem();
void monitorConnections();
void cleanupResources();
void processURC(String urc);
bool uploadCertificate();
bool setupSSL();
bool setupMQTT();
bool connectMQTT();
bool subscribeMQTT();
bool subscribeMQTT(const char* topic);
bool publishMQTT(const char* topic, const char* message);
bool disconnectMQTT();
bool stopMQTT();
void startOTA(uint32_t totalSize);
void processOTAFirmware(const String& topic, byte* payload, unsigned int dataLen);
void finishOTA();
void checkMissingChunks();
void revertToPreviousFirmware();
void loadCredentials();
void saveCredentials(String device_id, String username, String password); // Updated from two to three parameters
bool requestCredentialsFromServer();
void performFactoryReset();

// Base64 functions (unchanged)
String base64_encode(const unsigned char* input, size_t len) {
    String output = "";
    int i = 0, j = 0;
    unsigned char char_array_3[3], char_array_4[4];
    while (i < len) {
        char_array_3[j++] = input[i++];
        if (j == 3 || i == len) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((j > 1 ? (char_array_3[1] & 0xf0) : 0) >> 4); // Fixed
            char_array_4[2] = j > 1 ? ((char_array_3[1] & 0x0f) << 2) + ((j > 2 ? (char_array_3[2] & 0xc0) : 0) >> 6) : 0;
            char_array_4[3] = j > 2 ? (char_array_3[2] & 0x3f) : 0;
            for (int k = 0; k < (j + 1); k++) output += base64_enc_map[char_array_4[k]];
            while (j++ < 3) output += '=';
            j = 0;
        }
    }
    return output;
}

size_t base64_decode(const char* input, unsigned char* output, size_t out_len) {
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

// Padding functions (unchanged)
void pkcs7_pad(unsigned char* data, size_t data_len, size_t block_size) {
    unsigned char pad_value = block_size - (data_len % block_size);
    for (size_t i = data_len; i < data_len + pad_value; i++) data[i] = pad_value;
}

size_t pkcs7_unpad(unsigned char* data, size_t data_len) {
    unsigned char pad_value = data[data_len - 1];
    if (pad_value > 16 || pad_value > data_len) return data_len;
    return data_len - pad_value;
}

// Security functions
void generateEncryptionKeys() {
    esp_fill_random(aes_key, 32);
    esp_fill_random(device_key, 32);
}

String encryptMessage(const char* message, unsigned char* iv_out) {
    if (!message) return "";
    size_t input_len = strlen(message);
    size_t padded_len = ((input_len + 15) / 16) * 16;
    unsigned char* padded_input = new unsigned char[padded_len]();
    memcpy(padded_input, message, input_len);
    pkcs7_pad(padded_input, input_len, 16);

    unsigned char iv[16];
    esp_fill_random(iv, 16);
    memcpy(iv_out, iv, 16);

    unsigned char* output_buffer = new unsigned char[padded_len]();
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, aes_key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, padded_input, output_buffer);
    mbedtls_aes_free(&aes);

    String result = base64_encode(output_buffer, padded_len);
    delete[] padded_input;
    delete[] output_buffer;
    return result;
}

String decryptMessage(const char* encryptedBase64, const unsigned char* iv) {
    if (!encryptedBase64) return "";
    size_t max_input_len = strlen(encryptedBase64);
    unsigned char* encrypted_bytes = new unsigned char[max_input_len]();
    size_t decoded_len = base64_decode(encryptedBase64, encrypted_bytes, max_input_len);
    if (decoded_len < 16) {
        delete[] encrypted_bytes;
        return "";
    }
    unsigned char* output_buffer = new unsigned char[decoded_len - 16]();
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, aes_key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, decoded_len - 16, (unsigned char*)iv, encrypted_bytes + 16, output_buffer);
    mbedtls_aes_free(&aes);

    size_t unpadded_len = pkcs7_unpad(output_buffer, decoded_len - 16);
    String result = String((char*)output_buffer, unpadded_len);
    delete[] encrypted_bytes;
    delete[] output_buffer;
    return result;
}

void encryptNVSData(unsigned char* data, size_t len, unsigned char* out) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, device_key, 256);
    unsigned char iv[16] = {0}; // Fixed for simplicity; improve in production
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, iv, data, out);
    mbedtls_aes_free(&aes);
}

void decryptNVSData(unsigned char* data, size_t len, unsigned char* out) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, device_key, 256);
    unsigned char iv[16] = {0};
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv, data, out);
    mbedtls_aes_free(&aes);
}

bool verifyOTASignature(const unsigned char* firmware, size_t len, const unsigned char* signature, size_t sig_len) {
    mbedtls_ecdsa_context ecdsa;
    mbedtls_ecdsa_init(&ecdsa);

    // Load the elliptic curve group
    if (mbedtls_ecp_group_load(&ecdsa.grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        SerialMon.println("Failed to load curve");
        mbedtls_ecdsa_free(&ecdsa);
        return false;
    }

    // Load the server's public key (assuming uncompressed format: 0x04 | X | Y)
    const unsigned char* pubkey = (unsigned char*)SERVER_PUBLIC_KEY_PEM; // Adjust if necessary
    if (mbedtls_ecp_point_read_binary(&ecdsa.grp, &ecdsa.Q, pubkey, 65) != 0) {
        SerialMon.println("Failed to parse server public key");
        mbedtls_ecdsa_free(&ecdsa);
        return false;
    }

    // Compute SHA-256 hash of the firmware
    unsigned char hash[32];
    mbedtls_sha256(firmware, len, hash, 0);

    // Split signature into r and s (assuming sig_len = 64 for SECP256R1)
    if (sig_len != 64) { // 32 bytes for r + 32 bytes for s
        SerialMon.println("Invalid signature length");
        mbedtls_ecdsa_free(&ecdsa);
        return false;
    }
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    if (mbedtls_mpi_read_binary(&r, signature, 32) != 0 ||
        mbedtls_mpi_read_binary(&s, signature + 32, 32) != 0) {
        SerialMon.println("Failed to parse signature components");
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_ecdsa_free(&ecdsa);
        return false;
    }

    // Verify the signature
    int ret = mbedtls_ecdsa_verify(&ecdsa.grp, hash, 32, &ecdsa.Q, &r, &s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecdsa_free(&ecdsa);
    return ret == 0;
}

// Setup
void setup() {
    esp_task_wdt_reset();
    SerialMon.begin(115200);
    delay(1000);
    SerialMon.println("Starting...");

    generateEncryptionKeys();
    uint8_t uuid[16];
    esp_fill_random(uuid, 16);
    char uuid_str[37];
    snprintf(uuid_str, sizeof(uuid_str),
             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
             uuid[0], uuid[1], uuid[2], uuid[3], uuid[4], uuid[5], uuid[6], uuid[7],
             uuid[8], uuid[9], uuid[10], uuid[11], uuid[12], uuid[13], uuid[14], uuid[15]);
    deviceUUID = String(uuid_str);

    sim7600.begin(115200, SERIAL_8N1, MODEM_RX, MODEM_TX);
    esp_task_wdt_init(WDT_TIMEOUT * 1000, true);
    esp_task_wdt_add(NULL);

    pinMode(FACTORY_RESET_PIN, INPUT_PULLUP);
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
#endif

    rgbLed.begin();
    rgbLed.show();
    loadCredentials();
}

// Loop
void loop() {
    esp_task_wdt_reset();
    if (digitalRead(FACTORY_RESET_PIN) == LOW) {
        delay(50);
        if (digitalRead(FACTORY_RESET_PIN) == LOW) {
            performFactoryReset();
        }
    }

    while (SerialAT.available()) {
        String urc = SerialAT.readStringUntil('\n');
        processURC(urc);
    }

    switch (currentState) {
        case STATE_INIT_MODEM:
            if (tryStep("Initializing modem", modem.init())) nextState(STATE_WAIT_NETWORK);
            break;
        case STATE_WAIT_NETWORK:
            if (tryStep("Waiting for network", modem.waitForNetwork())) nextState(STATE_CONNECT_GPRS);
            break;
        case STATE_CONNECT_GPRS:
            if (tryStep("Connecting to " + String(apn), modem.gprsConnect(apn, gprsUser, gprsPass))) nextState(STATE_UPLOAD_CERTIFICATE);
            break;
        case STATE_UPLOAD_CERTIFICATE:
            if (tryStep("Uploading certificate", uploadCertificate())) nextState(STATE_SETUP_SSL);
            break;
        case STATE_SETUP_SSL:
            if (tryStep("Setting up SSL", setupSSL())) nextState(STATE_SETUP_MQTT);
            break;
        case STATE_SETUP_MQTT:
            if (tryStep("Setting up MQTT", setupMQTT())) {
                if (!isProvisioned) {
                    if (requestCredentialsFromServer()) nextState(STATE_WAIT_PROVISION);
                    else nextState(STATE_ERROR);
                } else {
                    nextState(STATE_CONNECT_MQTT);
                }
            }
            break;
        case STATE_WAIT_PROVISION:
            if (SerialAT.available()) { // Extra check within state
                String urc = SerialAT.readStringUntil('\n');
                processURC(urc);
            }
            if (millis() - provisionStartTime >= provisionTimeout) {
                SerialMon.println("Provisioning timeout");
                waitingForProvisionResponse = false;
                stopMQTT();
                nextState(STATE_ERROR);
            } else if (millis() - lastRequestTime >= PROVISION_REQUEST_INTERVAL) {
                requestCredentialsFromServer();
            }
            break;
        case STATE_CONNECT_MQTT:
            if (tryStep("Connecting to MQTT", connectMQTT())) nextState(STATE_SUBSCRIBE_MQTT);
            break;
        case STATE_SUBSCRIBE_MQTT:
            if (tryStep("Subscribing to MQTT", subscribeMQTT())) nextState(STATE_RUNNING);
            break;
        case STATE_RUNNING:
            if (millis() - lastMonitorTime >= MONITOR_INTERVAL) {
                monitorConnections();
                lastMonitorTime = millis();
            }
            break;
        case STATE_ERROR:
            SerialMon.println("Setup failed");
            cleanupResources();
            resetModem();
            nextState(STATE_INIT_MODEM);
            break;
        case STATE_RECOVER_MQTT:
            if (tryStep("Recovering MQTT", connectMQTT() && subscribeMQTT())) nextState(STATE_RUNNING);
            break;
    }
}

// MQTT and OTA functions (partial implementation; integrate with existing logic)
void handleMessage(String topic, String payload) {
    SerialMon.println("Received message on " + topic + ": " + payload);
    if (topic == PROVISION_RESPONSE_TOPIC && waitingForProvisionResponse) {
        if (payload.startsWith("CREDENTIALS:")) {
            String encrypted_b64 = payload.substring(11);
            unsigned char encrypted_bytes[1024];
            size_t enc_len = base64_decode(encrypted_b64.c_str(), encrypted_bytes, 1024);
            unsigned char iv[16], ecdh_priv[32];
            preferences.begin("device-creds", true);
            preferences.getBytes("nonce", iv, 16);
            preferences.getBytes("ecdh_priv", ecdh_priv, 32);
            preferences.end();

            mbedtls_ecdh_context ecdh;
            mbedtls_ecdh_init(&ecdh);
            if (mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
                SerialMon.println("Failed to load curve");
                return;
            }
            mbedtls_mpi_read_binary(&ecdh.d, ecdh_priv, 32);

            const unsigned char* server_pubkey = (unsigned char*)SERVER_PUBLIC_KEY_PEM;
            if (mbedtls_ecp_point_read_binary(&ecdh.grp, &ecdh.Qp, server_pubkey, 65) != 0) {
                SerialMon.println("Failed to load server public key");
                mbedtls_ecdh_free(&ecdh);
                return;
            }

            unsigned char shared_secret[32];
            size_t olen;
            if (mbedtls_ecdh_calc_secret(&ecdh, &olen, shared_secret, 32, NULL, NULL) != 0) {
                SerialMon.println("Failed to compute shared secret");
                mbedtls_ecdh_free(&ecdh);
                return;
            }
            unsigned char derived_key[32];
            mbedtls_sha256(shared_secret, 32, derived_key, 0);

            mbedtls_aes_context aes;
            mbedtls_aes_init(&aes);
            mbedtls_aes_setkey_dec(&aes, derived_key, 256);
            unsigned char decrypted[1024];
            mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, enc_len, iv, encrypted_bytes, decrypted);
            size_t unpadded_len = pkcs7_unpad(decrypted, enc_len);
            String creds = String((char*)decrypted, unpadded_len);

            // Parse DEVICE_ID, USERNAME, and PASSWORD
            int deviceIdStart = creds.indexOf("DEVICE_ID:") + 10;
            int usernameStart = creds.indexOf(":USERNAME:");
            int passwordStart = creds.indexOf(":PASSWORD:");
            String device_id = creds.substring(deviceIdStart, usernameStart);
            String username = creds.substring(usernameStart + 10, passwordStart);
            String password = creds.substring(passwordStart + 10);

            saveCredentials(device_id, username, password); // Updated to include device_id
            clientID = device_id; // Set MQTT client ID to the custom device ID
            waitingForProvisionResponse = false;
            nextState(STATE_CONNECT_MQTT);

            mbedtls_aes_free(&aes);
            mbedtls_ecdh_free(&ecdh);
        }
    } else if (topic == mqtt_topic_firmware) {
        processOTAFirmware(topic, (byte*)payload.c_str(), payload.length());
    }
}

bool tryStep(const String& stepMsg, bool success) {
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

void retryState(const String& stepMsg) {
    retryCount++;
    if (retryCount >= MAX_RETRIES) {
        SerialMon.println("Max retries for " + stepMsg);
        nextState(STATE_ERROR);
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
    mqttStatus.reset();
}

void monitorConnections() {
    if (!modem.isNetworkConnected()) {
        SerialMon.println("Network lost");
        nextState(STATE_ERROR);
    } else if (!modem.isGprsConnected()) {
        SerialMon.println("GPRS lost");
        nextState(STATE_ERROR);
    }
}

void cleanupResources() {
    modem.gprsDisconnect();
    stopMQTT();
    if (otaInProgress) {
        esp_ota_end(otaHandle);
        otaInProgress = false;
        otaReceivedSize = 0;
        otaTotalSize = 0;
        chunkCount = 0;
        receivedChunks.clear();
    }
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
            nextState(STATE_SUBSCRIBE_MQTT); // Proceed if still connecting
        }
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

bool uploadCertificate()
{
    modem.sendAT("+CCERTLIST");
    String response;
    if (modem.waitResponse(2000L, response) != 1)
        return false;
    if (response.indexOf(String("+CCERTLIST: \"") + cert_name + "\"") >= 0)
    {
        SerialMon.println("Certificate '" + String(cert_name) + "' exists");
        return true;
    }
    modem.sendAT("+CCERTDOWN=\"", cert_name, "\",", strlen(root_ca));
    if (modem.waitResponse(2000L, ">") != 1)
        return false;
    SerialAT.write(root_ca, strlen(root_ca));
    return modem.waitResponse(5000L) == 1;
}

bool setupSSL()
{
    modem.sendAT("+CSSLCFG=\"sslversion\",0,4");
    if (modem.waitResponse() != 1)
        return false;
    modem.sendAT("+CSSLCFG=\"cacert\",0,\"", cert_name, "\"");
    if (modem.waitResponse() != 1)
        return false;
    modem.sendAT("+CSSLCFG=\"authmode\",0,1");
    return modem.waitResponse() == 1;
}

bool setupMQTT() {
    if (!mqttStatus.serviceStarted) {
        SerialAT.println("AT+CMQTTSTART");
        String response;
        if (modem.waitResponse(5000L, response) != 1) {
            response.trim();
            SerialMon.println("MQTT start failed - Response: " + response);
            if (response.indexOf("+CMQTTSTART:") >= 0) {
                mqttStatus.lastErrorCode = response.substring(response.indexOf(":") + 2).toInt();
                if (mqttStatus.lastErrorCode == 23) {
                    SerialMon.println("MQTT service already running (+CMQTTSTART: 23), proceeding");
                    mqttStatus.serviceStarted = true;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        } else if (response.indexOf("+CMQTTSTART: 0") >= 0) {
            mqttStatus.serviceStarted = true;
            SerialMon.println("MQTT service started successfully");
        } else {
            SerialMon.println("Unexpected response to AT+CMQTTSTART: " + response);
            return false;
        }
    } else {
        SerialMon.println("MQTT service already started, skipping AT+CMQTTSTART");
    }

    if (!mqttStatus.clientAcquired) {
        unsigned long timeVal = millis() & 0xFFF;
        clientID = "ESP32_" + String(timeVal);
        SerialMon.println("Generated clientID: " + clientID);

        char accqCmd[64];
        snprintf(accqCmd, sizeof(accqCmd), "AT+CMQTTACCQ=0,\"%s\",1", clientID.c_str());
        SerialMon.println("Sending: " + String(accqCmd));
        SerialAT.println(accqCmd);

        if (modem.waitResponse(5000L) != 1) {
            SerialMon.println("Failed to acquire MQTT client - No OK response");
            return false;
        }
        // Assume success if OK is received; URC is optional per SIM7600 manual
        mqttStatus.clientAcquired = true;
        SerialMon.println("MQTT client acquired successfully (OK received)");
    } else {
        SerialMon.println("MQTT client already acquired, skipping AT+CMQTTACCQ");
    }

    if (!mqttStatus.connected) {
        SerialAT.println("AT+CMQTTSSLCFG=0,0");
        if (modem.waitResponse(2000L) != 1) {
            SerialMon.println("Failed to configure SSL for MQTT");
            return false;
        }
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
        if (!setupMQTT()) {
            return false;
        }
    }

    SerialMon.println("Connecting - ClientID: " + clientID + ", User: " + mqtt_user + ", Pass: " + mqtt_pass);

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "AT+CMQTTCONNECT=0,\"tcp://%s:%d\",60,1,\"%s\",\"%s\"",
             mqtt_server, mqtt_port, mqtt_user.c_str(), mqtt_pass.c_str());
    SerialMon.println("Sending: " + String(cmd));
    SerialAT.println(cmd);

    String fullResponse = "";
    unsigned long startTime = millis();
    bool gotOK = false;
    bool gotURC = false;

    // Wait up to 30 seconds, reading directly from SerialAT
    while (millis() - startTime < 30000L && !gotURC) {
        if (SerialAT.available()) {
            String line = SerialAT.readStringUntil('\n');
            line.trim();
            if (line.length() > 0) {
                SerialMon.println("Received line: " + line + " at " + String(millis() - startTime) + "ms");
                fullResponse += line + "\n";
                if (line.indexOf("OK") >= 0) {
                    gotOK = true;
                    SerialMon.println("OK detected");
                }
                if (line.indexOf("+CMQTTCONNECT: 0,0") >= 0) {
                    gotURC = true;
                    mqttStatus.connected = true;
                    mqttStatus.lastConnectTime = millis();
                    SerialMon.println("MQTT connected successfully");
                } else if (line.indexOf("+CMQTTCONNECT: 0,") >= 0) {
                    mqttStatus.lastErrorCode = line.substring(line.indexOf(",") + 1).toInt();
                    SerialMon.println("MQTT connection failed - Error code: " + String(mqttStatus.lastErrorCode));
                    return false;
                }
            }
        } else {
            SerialMon.println("No data available at " + String(millis() - startTime) + "ms");
            delay(100); // Small delay to avoid tight looping
        }
    }

    fullResponse.trim();
    SerialMon.println("Full response after wait: [" + fullResponse + "]");

    if (gotURC) {
        return true;
    } else if (gotOK) {
        SerialMon.println("OK received but no success URC within 30s - Assuming failure");
        return false;
    } else {
        SerialMon.println("No OK or URC received within 30s");
        return false;
    }
}


bool subscribeMQTT() {
    bool success = true;
    success &= subscribeMQTT(mqtt_topic_recv);
    success &= subscribeMQTT(mqtt_topic_firmware);
    success &= subscribeMQTT(PROVISION_RESPONSE_TOPIC);
    if (success) mqttStatus.subscribed = true;
    return success;
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

    // Send topic length and QoS
    char subTopicCmd[32];
    snprintf(subTopicCmd, sizeof(subTopicCmd), "AT+CMQTTSUBTOPIC=0,%d,1", topicLen);
    SerialMon.println("Sending: " + String(subTopicCmd));
    SerialAT.println(subTopicCmd);

    String response;
    // Wait for '>' prompt
    int waitResult = modem.waitResponse(2000L, response, ">");
    SerialMon.println("waitResponse result: " + String(waitResult) + ", Response: [" + response + "]");

    if (waitResult != 1 || response.indexOf(">") < 0) {
        response.trim();
        SerialMon.println("Initial wait failed to detect '>' prompt - Response: [" + response + "]");
        // Fallback to raw read
        unsigned long startTime = millis();
        while (millis() - startTime < 2000L) {
            if (SerialAT.available()) {
                String line = SerialAT.readStringUntil('\n');
                line.trim();
                if (line.length() > 0) {
                    SerialMon.println("Raw read line: " + line + " at " + String(millis() - startTime) + "ms");
                    if (line.indexOf(">") >= 0) {
                        SerialMon.println("'>' prompt detected via raw read");
                        response = line;
                        break;
                    }
                }
            }
            delay(100);
        }
        if (response.indexOf(">") < 0) {
            SerialMon.println("Failed to get '>' prompt for SUBTOPIC after fallback - Final response: [" + response + "]");
            return false;
        }
    } else {
        SerialMon.println("'>' prompt received successfully: " + response);
    }

    SerialMon.println("Sending topic: " + String(topic));
    SerialAT.print(topic);
    if (modem.waitResponse(2000L, response) != 1 || response.indexOf("OK") < 0) {
        SerialMon.println("Failed to send topic - Response: " + response);
        return false;
    }
    SerialMon.println("Topic sent successfully, response: " + response);

    // Confirm subscription
    SerialMon.println("Sending: AT+CMQTTSUB=0");
    SerialAT.println("AT+CMQTTSUB=0");

    String fullResponse = "";
    unsigned long startTime = millis();
    bool gotOK = false;
    bool gotURC = false;

    // Wait up to 10 seconds for OK and URC
    while (millis() - startTime < 10000L && !gotURC) {
        if (SerialAT.available()) {
            String line = SerialAT.readStringUntil('\n');
            line.trim();
            if (line.length() > 0) {
                SerialMon.println("Received line: " + line + " at " + String(millis() - startTime) + "ms");
                fullResponse += line + "\n";
                if (line.indexOf("OK") >= 0) {
                    gotOK = true;
                    SerialMon.println("OK detected");
                }
                if (line.indexOf("+CMQTTSUB: 0,0") >= 0) {
                    gotURC = true;
                    SerialMon.println("Subscription confirmed for: " + String(topic));
                } else if (line.indexOf("+CMQTTSUB: 0,") >= 0) {
                    int errorCode = line.substring(line.indexOf(",") + 1).toInt();
                    SerialMon.println("Subscription failed for " + String(topic) + " - Error code: " + String(errorCode));
                    return false;
                }
            }
        } else {
            SerialMon.println("No data available at " + String(millis() - startTime) + "ms");
            delay(100);
        }
    }

    fullResponse.trim();
    SerialMon.println("Full response after wait: [" + fullResponse + "]");

    if (gotURC) {
        SerialMon.println("Successfully subscribed to: " + String(topic));
        return true;
    } else if (gotOK) {
        SerialMon.println("OK received but no +CMQTTSUB: 0,0 within 10s for " + String(topic) + " - Assuming failure");
        return false;
    } else {
        SerialMon.println("No OK or URC received within 10s for " + String(topic));
        return false;
    }
}

bool publishMQTT(const char *topic, const char *message)
{
    if (!mqttStatus.serviceStarted || !connectMQTT())
    {
        SerialMon.println("Cannot publish: MQTT service not started or not connected");
        return false;
    }
    if (!topic || !message)
        return false;

    // Set topic
    modem.sendAT("+CMQTTTOPIC=0,", String(strlen(topic)).c_str());
    if (modem.waitResponse(500L, ">") != 1)
    {
        SerialMon.println("Failed to set topic: " + String(topic));
        return false;
    }
    SerialAT.print(topic);
    if (modem.waitResponse(500L) != 1)
    {
        SerialMon.println("Topic write failed");
        return false;
    }

    // Set payload
    int msgLen = strlen(message);
    modem.sendAT("+CMQTTPAYLOAD=0,", String(msgLen).c_str());
    if (modem.waitResponse(500L, ">") != 1)
    {
        SerialMon.println("Failed to set payload length");
        return false;
    }
    SerialAT.print(message);
    if (modem.waitResponse(500L) != 1)
    {
        SerialMon.println("Payload write failed");
        return false;
    }

    // Publish
    modem.sendAT("+CMQTTPUB=0,1,60");
    String response;
    bool success = false;
    // Wait for response with a longer timeout to catch asynchronous URCs
    if (modem.waitResponse(2000L, response) == 1)
    {
        response.trim();
        SerialMon.println("Publish response: " + response);
        // Check for either OK or +CMQTTPUB: 0,0
        if (response.indexOf("OK") >= 0 || response.indexOf("+CMQTTPUB: 0,0") >= 0)
        {
            success = true;
            SerialMon.println("Published to " + String(topic) + ": " + String(message));
        }
    }

    if (!success)
    {
        SerialMon.println("Failed to publish to " + String(topic) + " - Response: " + response);
        // Check for asynchronous +CMQTTPUB: 0,0 in URCs later
        SerialMon.println("Note: +CMQTTPUB: 0,0 may arrive asynchronously via URC");
    }
    return success;
}

bool disconnectMQTT()
{
    if (!mqttStatus.serviceStarted)
    {
        SerialMon.println("MQTT service not started, no need to disconnect");
        return true; // Not an error if already disconnected
    }
    SerialMon.println("Disconnecting MQTT...");
    modem.sendAT("+CMQTTDISC=0,120");
    bool success = modem.waitResponse(10000L, "+CMQTTDISC: 0,0") == 1;
    if (!success)
        SerialMon.println("Failed to disconnect MQTT");
    return success;
}

bool stopMQTT() {
    if (!mqttStatus.serviceStarted) {
        SerialMon.println("MQTT service already stopped");
        return true;
    }

    if (mqttStatus.connected) {
        SerialMon.println("Disconnecting MQTT...");
        SerialAT.println("AT+CMQTTDISC=0,120");

        String discResponse = "";
        unsigned long startTime = millis();
        bool gotOK = false;
        bool gotURC = false;

        // Wait up to 15 seconds for OK or URC
        while (millis() - startTime < 15000L && !(gotOK && gotURC)) {
            if (SerialAT.available()) {
                String line = SerialAT.readStringUntil('\n');
                line.trim();
                if (line.length() > 0) {
                    SerialMon.println("Received line: " + line + " at " + String(millis() - startTime) + "ms");
                    discResponse += line + "\n";
                    if (line.indexOf("OK") >= 0) {
                        gotOK = true;
                        SerialMon.println("OK detected");
                    }
                    if (line.indexOf("+CMQTTDISC: 0,0") >= 0) {
                        gotURC = true;
                        SerialMon.println("Disconnect confirmed");
                    }
                }
            } else {
                delay(100);
            }
        }

        discResponse.trim();
        SerialMon.println("Full disconnect response: [" + discResponse + "]");

        if (!gotURC || !gotOK) {
            SerialMon.println("Warning: Incomplete disconnect response - URC: " + String(gotURC) + ", OK: " + String(gotOK));
        }
        mqttStatus.connected = false; // Assume disconnected even if partial success
        delay(1000); // Allow modem to process
    }

    if (mqttStatus.clientAcquired) {
        SerialMon.println("Releasing MQTT client...");
        SerialAT.println("AT+CMQTTREL=0");
        String relResponse;
        if (modem.waitResponse(5000L, relResponse) != 1 || relResponse.indexOf("OK") < 0) {
            relResponse.trim();
            SerialMon.println("Warning: Failed to release MQTT client - Response: " + relResponse);
        }
        mqttStatus.clientAcquired = false;
        delay(1000); // Allow modem to process
    }

    SerialMon.println("Stopping MQTT service...");
    SerialAT.println("AT+CMQTTSTOP");
    String stopResponse;
    if (modem.waitResponse(10000L, stopResponse) != 1 || stopResponse.indexOf("+CMQTTSTOP: 0") < 0) {
        stopResponse.trim();
        SerialMon.println("MQTT stop failed - Response: " + stopResponse);
        SerialMon.println("Forcing modem reset due to stop failure...");
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
        SerialMon.println("No OTA partition");
        return;
    }
    esp_err_t err = esp_ota_begin(updatePartition, totalSize, &otaHandle);
    if (err != ESP_OK) {
        SerialMon.printf("OTA begin failed: %s\n", esp_err_to_name(err));
        return;
    }
    otaInProgress = true;
    otaTotalSize = totalSize;
    otaReceivedSize = 0;
    chunkCount = 0;
    receivedChunks.clear();
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    publishMQTT(mqtt_topic_send, "OTA:STARTED");
}

void processOTAFirmware(const String& topic, byte* payload, unsigned int dataLen) {
    String payloadStr((char*)payload, dataLen);
    if (payloadStr.startsWith("OTA:BEGIN:")) {
        if (otaInProgress) cleanupResources();
        int colonIdx = payloadStr.indexOf(':', 10);
        otaTotalSize = payloadStr.substring(10, colonIdx).toInt();
        int nextColon = payloadStr.indexOf(':', colonIdx + 1);
        otaHash = payloadStr.substring(colonIdx + 1, nextColon);        
        String sigBase64 = payloadStr.substring(nextColon + 1);
        unsigned char signature[128];
        size_t sig_len = base64_decode(sigBase64.c_str(), signature, 128);
        startOTA(otaTotalSize);
        return;
    }
    if (!otaInProgress) return;
    if (payloadStr == "OTA:END") {
        finishOTA();
        return;
    }
    size_t maxDecodedLen = ((dataLen + 3) / 4) * 3;
    unsigned char* decodedPayload = new unsigned char[maxDecodedLen];
    size_t decodedLen = base64_decode((char*)payload, decodedPayload, maxDecodedLen);
    if (decodedLen < 4) {
        delete[] decodedPayload;
        return;
    }
    unsigned long chunkNum = ((unsigned long)decodedPayload[0] << 24) |
                            ((unsigned long)decodedPayload[1] << 16) |
                            ((unsigned long)decodedPayload[2] << 8) |
                            decodedPayload[3];
    size_t chunkSize = decodedLen - 4;
    if (receivedChunks[chunkNum]) {
        delete[] decodedPayload;
        return;
    }
    esp_ota_write(otaHandle, decodedPayload + 4, chunkSize);
    mbedtls_sha256_update(&sha256_ctx, decodedPayload + 4, chunkSize);
    receivedChunks[chunkNum] = true;
    otaReceivedSize += chunkSize;
    chunkCount++;
    String ackMsg = "OTA:PROGRESS:" + String(chunkNum) + ":" + String(otaReceivedSize) + "/" + String(otaTotalSize);
    publishMQTT(mqtt_topic_send, ackMsg.c_str());
    delete[] decodedPayload;
}

void finishOTA() {
    if (!otaInProgress) return;
    if (otaReceivedSize != otaTotalSize) {
        checkMissingChunks();
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

    // Extract signature from OTA:BEGIN payload (stored in global otaSignature)
    extern String otaSignature; // Add this global to store signature from OTA:BEGIN
    unsigned char signature[64];
    size_t sig_len = base64_decode(otaSignature.c_str(), signature, 64);
    if (!verifyOTASignature(hash, 32, signature, sig_len)) {
        cleanupResources();
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Signature invalid");
        return;
    }

    if (computedHash != otaHash) {
        cleanupResources();
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Hash mismatch");
        return;
    }
    esp_ota_end(otaHandle);
    esp_ota_set_boot_partition(updatePartition);
    SerialMon.println("OTA successful, restarting...");
    otaInProgress = false;
    ESP.restart();
}

void checkMissingChunks() {
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
        publishMQTT(mqtt_topic_send, missingMsg.c_str());
    }
}

void revertToPreviousFirmware() {
    if (!previousPartition) return;
    esp_ota_set_boot_partition(previousPartition);
    SerialMon.println("Reverting to previous firmware");
    ESP.restart();
}

void performFactoryReset() {
    const esp_partition_t* factoryPartition = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL);
    if (!factoryPartition) return;
    esp_ota_set_boot_partition(factoryPartition);
    preferences.begin("device-creds", false);
    preferences.clear();
    preferences.end();
    isProvisioned = false;
    clientID = DEFAULT_CLIENT_ID;
    mqtt_user = DEFAULT_USERNAME;
    mqtt_pass = DEFAULT_PASSWORD;
    ESP.restart();
}

void loadCredentials() {
    preferences.begin("device-creds", true);
    isProvisioned = preferences.getBool("provisioned", false);
    if (isProvisioned) {
        clientID = preferences.getString("device_id", DEFAULT_CLIENT_ID); // Load custom device ID
        unsigned char enc_user[32], dec_user[32];
        unsigned char enc_pass[32], dec_pass[32];
        preferences.getBytes("username", enc_user, 32);
        preferences.getBytes("password", enc_pass, 32);
        decryptNVSData(enc_user, 32, dec_user);
        decryptNVSData(enc_pass, 32, dec_pass);
        mqtt_user = String((char*)dec_user);
        mqtt_pass = String((char*)dec_pass);
    } else {
        clientID = DEFAULT_CLIENT_ID;
        mqtt_user = DEFAULT_USERNAME;
        mqtt_pass = DEFAULT_PASSWORD;
    }
    preferences.end();
}

void saveCredentials(String device_id, String username, String password) {
    clientID = device_id; // Use server-assigned ID as MQTT client ID
    mqtt_user = username;
    mqtt_pass = password;

    preferences.begin("device-creds", false);
    preferences.putString("device_id", device_id); // Store the custom device ID

    unsigned char enc_user[32], dec_user[32];
    memset(dec_user, 0, 32);
    memcpy(dec_user, mqtt_user.c_str(), min(mqtt_user.length(), (size_t)32));
    encryptNVSData(dec_user, 32, enc_user);
    preferences.putBytes("username", enc_user, 32);

    unsigned char enc_pass[32], dec_pass[32];
    memset(dec_pass, 0, 32);
    memcpy(dec_pass, mqtt_pass.c_str(), min(mqtt_pass.length(), (size_t)32));
    encryptNVSData(dec_pass, 32, enc_pass);
    preferences.putBytes("password", enc_pass, 32);

    preferences.putBool("provisioned", true);
    preferences.end();
    isProvisioned = true;
}

bool requestCredentialsFromServer() {
    mbedtls_ecdh_context ecdh;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;

    // Initialize contexts
    mbedtls_ecdh_init(&ecdh);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Seed the DRBG
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) {
        SerialMon.println("Failed to seed DRBG");
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_ecdh_free(&ecdh);
        return false;
    }

    // Load the elliptic curve group
    if (mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_SECP256R1) != 0) {
        SerialMon.println("Failed to load curve");
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_ecdh_free(&ecdh);
        return false;
    }

    // Generate public key
    if (mbedtls_ecdh_gen_public(&ecdh.grp, &ecdh.d, &ecdh.Q, mbedtls_ctr_drbg_random, &ctr_drbg) != 0) {
        SerialMon.println("Failed to generate public key");
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_ecdh_free(&ecdh);
        return false;
    }

    // Export public key
    unsigned char pubkey[65];
    size_t pubkey_len = 65;
    pubkey[0] = 0x04; // Uncompressed point
    mbedtls_mpi_write_binary(&ecdh.Q.X, pubkey + 1, 32);
    mbedtls_mpi_write_binary(&ecdh.Q.Y, pubkey + 33, 32);
    String pubkey_b64 = base64_encode(pubkey, pubkey_len);

    // Generate nonce
    unsigned char nonce[16];
    esp_fill_random(nonce, 16);
    String nonceStr = base64_encode(nonce, 16);

    // Construct request message
    String requestMsg = "UUID:" + deviceUUID + ":NONCE:" + nonceStr + ":PUBKEY:" + pubkey_b64;

    // Publish and store private key/nonce
    if (publishMQTT(PROVISION_TOPIC, requestMsg.c_str())) {
        waitingForProvisionResponse = true;
        provisionStartTime = millis();
        lastRequestTime = millis();
        preferences.begin("device-creds", false);
        unsigned char priv_key[32];
        mbedtls_mpi_write_binary(&ecdh.d, priv_key, 32);
        preferences.putBytes("ecdh_priv", priv_key, 32);
        preferences.putBytes("nonce", nonce, 16);
        preferences.end();
        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_ecdh_free(&ecdh);
        return true;
    }

    // Cleanup on failure
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ecdh_free(&ecdh);
    return false;
}