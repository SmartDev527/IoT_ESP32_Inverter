#define TINY_GSM_MODEM_SIM7600
#define ENABLE_LCD
#define DUMP_AT_COMMANDS

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
#include <mbedtls/pk.h>
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
String generateRandomString(size_t length)
{
    const char charset[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    String result;
    for (size_t i = 0; i < length; i++)
    {
        result += charset[esp_random() % (sizeof(charset) - 1)];
    }
    return result;
}
// String DEFAULT_CLIENT_ID = "ESP32_" + generateRandomString(8);
// String DEFAULT_USERNAME = generateRandomString(12);
// String DEFAULT_PASSWORD = generateRandomString(16);

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

#ifdef DUMP_AT_COMMANDS
#include <StreamDebugger.h>
StreamDebugger debugger(SerialAT, SerialMon);
TinyGsm modem(debugger);
#else
TinyGsm modem(SerialAT);
#endif

// Encryption and OTA settings
unsigned char aes_key[32];    // Dynamically generated
unsigned char device_key[32]; // For NVS encryption
const char *SERVER_PUBLIC_KEY_PEM = "-----BEGIN PUBLIC KEY-----\n"
                                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcUqag9hF6FwK6OCEPD1leoTZYjAH\n"
                                    "fMeNrht9Aiufk2jMGiQjIhnU22PM9Vt6XfdhNC7Qjd4xqBmCkFXsB0q2HA==\n"
                                    "-----END PUBLIC KEY-----\n"; // Replace with actual server public key

const unsigned char SERVER_PUBLIC_KEY[] = {
    0x04, // Uncompressed point indicator
    0x71, 0x52, 0xAA, 0x83, 0xD8, 0x45, 0xE8, 0x5C, 0x0A, 0xE8, 0xE0, 0x84, 0x3C, 0x3D, 0x65, 0x7A,
    0x84, 0xD9, 0x62, 0x30, 0x07, 0xFC, 0xC7, 0x8D, 0xAE, 0x1B, 0x7D, 0x02, 0x2B, 0x9F, 0x93, 0x68,
    0xCC, 0x1A, 0x24, 0x23, 0x22, 0x19, 0xD4, 0xDB, 0x63, 0xCC, 0xF5, 0x5B, 0x7A, 0x5D, 0xF7, 0x61,
    0x34, 0x2E, 0xD0, 0x8D, 0xDE, 0x31, 0xA8, 0x19, 0x82, 0x90, 0x55, 0xEC, 0x07, 0x4A, 0xB6, 0x1C};

// State machine states
enum SetupState
{
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
    STATE_RECOVER_MQTT
};

// MQTT status structure
struct MqttStatus
{
    bool serviceStarted = false;
    bool clientAcquired = false;
    bool connected = false;
    bool subscribed = false;
    bool provisionSubscribed = false;
    int lastErrorCode = 0;
    unsigned long lastConnectTime = 0;
    void reset()
    {
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
unsigned long provisionTimeout = 1200000;
unsigned long provisionStartTime = 0;
const unsigned long PROVISION_REQUEST_INTERVAL = 60000;
unsigned long lastRequestTime = 0;
String otaSignature; // Base64-encoded ECDSA signature from OTA:BEGIN
bool otaInProgress = false;
unsigned long otaReceivedSize = 0;
unsigned long otaTotalSize = 0;
unsigned long chunkCount = 0;
std::map<unsigned long, bool> receivedChunks;
String lastAckMsg = "";                  // Stores the most recent OTA:PROGRESS message
unsigned long lastChunkNum = 0xFFFFFFFF; // Stores the chunk number of the last acknowledgment (invalid default)

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
String base64_encode(const unsigned char *input, size_t len);
size_t base64_decode(const char *input, unsigned char *output, size_t out_len);
void pkcs7_pad(unsigned char *data, size_t data_len, size_t block_size);
size_t pkcs7_unpad(unsigned char *data, size_t data_len);
void generateEncryptionKeys();
String encryptMessage(const char *message, unsigned char *iv_out);
String decryptMessage(const char *encryptedBase64, const unsigned char *iv);
void encryptNVSData(unsigned char *data, size_t len, unsigned char *out);
void decryptNVSData(unsigned char *data, size_t len, unsigned char *out);
bool verifyOTASignature(const unsigned char *firmware, size_t len, const unsigned char *signature, size_t sig_len);
void handleMessage(String topic, String payload);
bool tryStep(const String &stepMsg, bool success);
void nextState(SetupState next);
void retryState(const String &stepMsg);
void resetModem();
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
void saveCredentials(String device_id, String username, String password); // Updated from two to three parameters
bool requestCredentialsFromServer();
void resetCredentials();
void performFactoryReset();

void testECDH();
void generateTestServerKey();
String getIMEI();

void resetCredentials()
{
    SerialMon.println("Resetting credentials for testing...");

    // Open Preferences in read-write mode
    preferences.begin("device-creds", false);

    // Clear all stored data in the "device-creds" namespace
    preferences.clear();

    // Explicitly remove specific keys (redundant after clear, but ensures completeness)
    preferences.remove("provisioned");
    preferences.remove("device_id");
    preferences.remove("username");
    preferences.remove("password");
    preferences.remove("nonce");
    preferences.remove("ecdh_priv");

    // Close Preferences
    preferences.end();

    // Reset in-memory variables to default values
    isProvisioned = false;
    clientID = DEFAULT_CLIENT_ID;
    mqtt_user = DEFAULT_USERNAME;
    mqtt_pass = DEFAULT_PASSWORD;
    waitingForProvisionResponse = false;
    provisionStartTime = 0;
    lastRequestTime = 0;
    mqttStatus.reset();

    // Stop MQTT if running
    if (mqttStatus.serviceStarted)
    {
        stopMQTT();
    }

    SerialMon.println("Credentials reset complete. Device is now in unprovisioned state.");
    SerialMon.println("ClientID: " + clientID + ", Username: " + mqtt_user + ", Password: " + mqtt_pass);
}

String getIMEI()
{
    String imei = "";
    modem.sendAT("+CGSN"); // Send command to get IMEI
    String response;

    String rawImei;
    if (modem.waitResponse(1000L, rawImei) != 1)
    {
        SerialMon.println("Failed to retrieve IMEI");
        imei = "Unknown";
    }
    else
    {
        imei = rawImei;
        imei.replace("\r", "");
        imei.replace("\n", "");
        int okIndex = imei.indexOf("OK");
        if (okIndex != -1)
        {
            imei = imei.substring(0, okIndex);
        }
        imei.trim();
        SerialMon.print("Cleaned IMEI: ");
        SerialMon.println(imei);
    }
    return imei;
}

void testECDH()
{
    mbedtls_ecdh_context ecdh;
    mbedtls_pk_context pk;
    mbedtls_ecdh_init(&ecdh);
    mbedtls_pk_init(&pk);

    SerialMon.println("Test: Loading curve SECP256R1");
    if (mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
    {
        SerialMon.println("Test: Failed to load curve");
        mbedtls_pk_free(&pk);
        mbedtls_ecdh_free(&ecdh);
        return;
    }

    // Parse the PEM public key
    SerialMon.println("Test: Parsing server public key from PEM");
    if (mbedtls_pk_parse_public_key(&pk, (const unsigned char *)SERVER_PUBLIC_KEY_PEM, strlen(SERVER_PUBLIC_KEY_PEM) + 1) != 0)
    {
        SerialMon.println("Test: Failed to parse PEM server public key");
        mbedtls_pk_free(&pk);
        mbedtls_ecdh_free(&ecdh);
        return;
    }

    // Ensure it's an EC key
    if (mbedtls_pk_get_type(&pk) != MBEDTLS_PK_ECKEY)
    {
        SerialMon.println("Test: Parsed key is not an EC key");
        mbedtls_pk_free(&pk);
        mbedtls_ecdh_free(&ecdh);
        return;
    }

    mbedtls_ecp_keypair *ec_key = mbedtls_pk_ec(pk);
    if (!ec_key)
    {
        SerialMon.println("Test: Failed to get EC keypair from parsed key");
        mbedtls_pk_free(&pk);
        mbedtls_ecdh_free(&ecdh);
        return;
    }

    // Verify the curve matches SECP256R1
    if (ec_key->grp.id != MBEDTLS_ECP_DP_SECP256R1)
    {
        SerialMon.println("Test: Server public key curve does not match SECP256R1");
        mbedtls_pk_free(&pk);
        mbedtls_ecdh_free(&ecdh);
        return;
    }

    // Copy the public key point (Q) to ecdh.Qp
    if (mbedtls_ecp_copy(&ecdh.Qp, &ec_key->Q) != 0)
    {
        SerialMon.println("Test: Failed to copy server public key point");
        mbedtls_pk_free(&pk);
        mbedtls_ecdh_free(&ecdh);
        return;
    }

    // Validate the public key
    if (mbedtls_ecp_check_pubkey(&ecdh.grp, &ecdh.Qp) != 0)
    {
        SerialMon.println("Test: Server public key is invalid for SECP256R1");
        mbedtls_pk_free(&pk);
        mbedtls_ecdh_free(&ecdh);
        return;
    }
    SerialMon.println("Test: Server public key is valid");

    // Print the public key for debugging
    unsigned char pubkey[65];
    pubkey[0] = 0x04; // Uncompressed format
    if (mbedtls_mpi_write_binary(&ecdh.Qp.X, pubkey + 1, 32) != 0 ||
        mbedtls_mpi_write_binary(&ecdh.Qp.Y, pubkey + 33, 32) != 0)
    {
        SerialMon.println("Test: Failed to serialize public key");
        mbedtls_pk_free(&pk);
        mbedtls_ecdh_free(&ecdh);
        return;
    }
    SerialMon.print("Test: Server public key (binary): ");
    for (int i = 0; i < 65; i++)
        SerialMon.printf("%02x", pubkey[i]);
    SerialMon.println();

    // Load private key from NVS
    unsigned char ecdh_priv[32];
    preferences.begin("device-creds", true);
    preferences.getBytes("ecdh_priv", ecdh_priv, 32);
    preferences.end();

    SerialMon.print("Test: Private key from NVS: ");
    for (int i = 0; i < 32; i++)
        SerialMon.printf("%02x", ecdh_priv[i]);
    SerialMon.println();

    if (mbedtls_mpi_read_binary(&ecdh.d, ecdh_priv, 32) != 0)
    {
        SerialMon.println("Test: Failed to load private key");
        mbedtls_pk_free(&pk);
        mbedtls_ecdh_free(&ecdh);
        return;
    }

    if (mbedtls_ecp_check_privkey(&ecdh.grp, &ecdh.d) != 0)
    {
        SerialMon.println("Test: Private key is invalid for SECP256R1");
        mbedtls_pk_free(&pk);
        mbedtls_ecdh_free(&ecdh);
        return;
    }
    SerialMon.println("Test: Private key is valid");

    // Compute shared secret
    unsigned char shared_secret[32];
    size_t olen;
    int ret = mbedtls_ecdh_calc_secret(&ecdh, &olen, shared_secret, 32, NULL, NULL);
    if (ret != 0)
    {
        SerialMon.println("Test: Failed to compute shared secret, error code: " + String(ret));
    }
    else
    {
        SerialMon.print("Test: Shared secret: ");
        for (int i = 0; i < 32; i++)
            SerialMon.printf("%02x", shared_secret[i]);
        SerialMon.println();
        SerialMon.println("Test: Shared secret length: " + String(olen));
    }

    // Cleanup (automatically called when objects go out of scope, but explicit for clarity)
    mbedtls_pk_free(&pk);
    mbedtls_ecdh_free(&ecdh);
}

void generateTestServerKey()
{
    mbedtls_ecdh_context ecdh;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ecdh_init(&ecdh);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_SECP256R1);
    mbedtls_ecdh_gen_public(&ecdh.grp, &ecdh.d, &ecdh.Q, mbedtls_ctr_drbg_random, &ctr_drbg);

    unsigned char test_pubkey[65];
    test_pubkey[0] = 0x04;
    mbedtls_mpi_write_binary(&ecdh.Q.X, test_pubkey + 1, 32);
    mbedtls_mpi_write_binary(&ecdh.Q.Y, test_pubkey + 33, 32);
    SerialMon.print("Test server public key: ");
    for (int i = 0; i < 65; i++)
        SerialMon.printf("%02x", test_pubkey[i]);
    SerialMon.println();

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ecdh_free(&ecdh);
}

// Base64 functions (unchanged)
String base64_encode(const unsigned char *input, size_t len)
{
    String output = "";
    int i = 0, j = 0;
    unsigned char char_array_3[3], char_array_4[4];
    while (i < len)
    {
        char_array_3[j++] = input[i++];
        if (j == 3 || i == len)
        {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((j > 1 ? (char_array_3[1] & 0xf0) : 0) >> 4); // Fixed
            char_array_4[2] = j > 1 ? ((char_array_3[1] & 0x0f) << 2) + ((j > 2 ? (char_array_3[2] & 0xc0) : 0) >> 6) : 0;
            char_array_4[3] = j > 2 ? (char_array_3[2] & 0x3f) : 0;
            for (int k = 0; k < (j + 1); k++)
                output += base64_enc_map[char_array_4[k]];
            while (j++ < 3)
                output += '=';
            j = 0;
        }
    }
    return output;
}

size_t base64_decode(const char *input, unsigned char *output, size_t out_len)
{
    size_t in_len = strlen(input);
    if (in_len % 4 != 0)
        return 0;
    size_t out_pos = 0;
    for (size_t i = 0; i < in_len; i += 4)
    {
        uint32_t n = (base64_dec_map[(unsigned char)input[i]] << 18) +
                     (base64_dec_map[(unsigned char)input[i + 1]] << 12) +
                     (base64_dec_map[(unsigned char)input[i + 2]] << 6) +
                     base64_dec_map[(unsigned char)input[i + 3]];
        if (out_pos + 3 > out_len)
            return 0;
        output[out_pos++] = (n >> 16) & 0xFF;
        if (input[i + 2] != '=')
            output[out_pos++] = (n >> 8) & 0xFF;
        if (input[i + 3] != '=')
            output[out_pos++] = n & 0xFF;
    }
    return out_pos;
}

// Padding functions (unchanged)
void pkcs7_pad(unsigned char *data, size_t data_len, size_t block_size)
{
    unsigned char pad_value = block_size - (data_len % block_size);
    for (size_t i = data_len; i < data_len + pad_value; i++)
        data[i] = pad_value;
}

size_t pkcs7_unpad(unsigned char *data, size_t data_len)
{
    unsigned char pad_value = data[data_len - 1];
    if (pad_value > 16 || pad_value > data_len)
        return data_len;
    return data_len - pad_value;
}

// Security functions
void generateEncryptionKeys()
{
    esp_fill_random(aes_key, 32);
    esp_fill_random(device_key, 32);
}

String encryptMessage(const char *message, unsigned char *iv_out)
{
    if (!message)
        return "";
    size_t input_len = strlen(message);
    size_t padded_len = ((input_len + 15) / 16) * 16;
    unsigned char *padded_input = new unsigned char[padded_len]();
    memcpy(padded_input, message, input_len);
    pkcs7_pad(padded_input, input_len, 16);

    unsigned char iv[16];
    esp_fill_random(iv, 16);
    memcpy(iv_out, iv, 16);

    unsigned char *output_buffer = new unsigned char[padded_len]();
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

String decryptMessage(const char *encryptedBase64, const unsigned char *iv)
{
    if (!encryptedBase64)
        return "";
    size_t max_input_len = strlen(encryptedBase64);
    unsigned char *encrypted_bytes = new unsigned char[max_input_len]();
    size_t decoded_len = base64_decode(encryptedBase64, encrypted_bytes, max_input_len);
    if (decoded_len < 16)
    {
        delete[] encrypted_bytes;
        return "";
    }
    unsigned char *output_buffer = new unsigned char[decoded_len - 16]();
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, aes_key, 256);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, decoded_len - 16, (unsigned char *)iv, encrypted_bytes + 16, output_buffer);
    mbedtls_aes_free(&aes);

    size_t unpadded_len = pkcs7_unpad(output_buffer, decoded_len - 16);
    String result = String((char *)output_buffer, unpadded_len);
    delete[] encrypted_bytes;
    delete[] output_buffer;
    return result;
}

void encryptNVSData(unsigned char *data, size_t len, unsigned char *out)
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, device_key, 256);
    unsigned char iv[16];
    esp_fill_random(iv, 16);                    // Generate a random IV
    size_t padded_len = ((len + 15) / 16) * 16; // Ensure length is a multiple of 16
    unsigned char padded_data[32] = {0};
    memcpy(padded_data, data, len);
    pkcs7_pad(padded_data, len, 16);
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, padded_data, out);
    mbedtls_aes_free(&aes);
    // Store the IV in NVS alongside the encrypted data
    preferences.putBytes("user_iv", iv, 16); // Assuming called within a preferences.begin() block
}

void decryptNVSData(unsigned char *data, size_t len, unsigned char *out)
{
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, device_key, 256);
    unsigned char iv[16];
    preferences.getBytes("user_iv", iv, 16); // Retrieve the stored IV
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, len, iv, data, out);
    size_t unpadded_len = pkcs7_unpad(out, len); // Remove PKCS7 padding
    if (unpadded_len < len)
    {
        out[unpadded_len] = '\0'; // Null-terminate the string
    }
    mbedtls_aes_free(&aes);
}

bool verifyOTASignature(const unsigned char *firmware, size_t len, const unsigned char *signature, size_t sig_len)
{
    mbedtls_ecdsa_context ecdsa;
    mbedtls_pk_context pk;
    mbedtls_ecdsa_init(&ecdsa);
    mbedtls_pk_init(&pk);

    if (mbedtls_ecp_group_load(&ecdsa.grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
    {
        SerialMon.println("Failed to load curve");
        mbedtls_pk_free(&pk);
        mbedtls_ecdsa_free(&ecdsa);
        return false;
    }

    if (mbedtls_pk_parse_public_key(&pk, (const unsigned char *)SERVER_PUBLIC_KEY_PEM, strlen(SERVER_PUBLIC_KEY_PEM) + 1) != 0)
    {
        SerialMon.println("Failed to parse server public key PEM");
        mbedtls_pk_free(&pk);
        mbedtls_ecdsa_free(&ecdsa);
        return false;
    }

    mbedtls_ecp_keypair *ec_key = mbedtls_pk_ec(pk);
    if (!ec_key || mbedtls_ecp_copy(&ecdsa.Q, &ec_key->Q) != 0)
    {
        SerialMon.println("Failed to extract EC public key");
        mbedtls_pk_free(&pk);
        mbedtls_ecdsa_free(&ecdsa);
        return false;
    }

    unsigned char hash[32];
    mbedtls_sha256(firmware, len, hash, 0);

    if (sig_len != 64)
    {
        SerialMon.println("Invalid signature length");
        mbedtls_pk_free(&pk);
        mbedtls_ecdsa_free(&ecdsa);
        return false;
    }

    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    if (mbedtls_mpi_read_binary(&r, signature, 32) != 0 ||
        mbedtls_mpi_read_binary(&s, signature + 32, 32) != 0)
    {
        SerialMon.println("Failed to parse signature components");
        mbedtls_mpi_free(&r);
        mbedtls_mpi_free(&s);
        mbedtls_pk_free(&pk);
        mbedtls_ecdsa_free(&ecdsa);
        return false;
    }

    int ret = mbedtls_ecdsa_verify(&ecdsa.grp, hash, 32, &ecdsa.Q, &r, &s);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_pk_free(&pk);
    mbedtls_ecdsa_free(&ecdsa);
    return ret == 0;
}

// Setup
void setup()
{
    esp_task_wdt_reset();
    SerialMon.begin(115200);

    generateEncryptionKeys();
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

    // For debugging purpose
    // SerialMon.println("This is Updated OTA Firmware");
    resetCredentials();

    rgbLed.begin();
    rgbLed.show();
    loadCredentials();

    // generateTestServerKey();
    // testECDH();
}

// Loop
void loop()
{
    esp_task_wdt_reset();
    if (digitalRead(FACTORY_RESET_PIN) == LOW)
    {
        delay(50);
        if (digitalRead(FACTORY_RESET_PIN) == LOW)
        {
            performFactoryReset();
        }
    }

    while (SerialAT.available())
    {
        String urc = SerialAT.readStringUntil('\n');
        processURC(urc);
    }

    // SerialMon.println("Current state: " + String(currentState)); // Log current state
    switch (currentState)
    {
    case STATE_INIT_MODEM:
        if (tryStep("Initializing modem", modem.init()))

            if (getIMEI() != "Unknown")
            {
                deviceUUID = getIMEI();
                nextState(STATE_WAIT_NETWORK);
            }
        break;
    case STATE_WAIT_NETWORK:
        if (tryStep("Waiting for network", modem.waitForNetwork()))
            nextState(STATE_CONNECT_GPRS);
        break;
    case STATE_CONNECT_GPRS:
        if (tryStep("Connecting to " + String(apn), modem.gprsConnect(apn, gprsUser, gprsPass)))
            nextState(STATE_UPLOAD_CERTIFICATE);
        break;
    case STATE_UPLOAD_CERTIFICATE:
        if (tryStep("Uploading certificate", uploadCertificate()))
            nextState(STATE_SETUP_SSL);
        break;
    case STATE_SETUP_SSL:
        if (tryStep("Setting up SSL", setupSSL()))
            nextState(STATE_SETUP_MQTT);
        break;
    case STATE_SETUP_MQTT:
        SerialMon.println("Entering STATE_SETUP_MQTT, isProvisioned: " + String(isProvisioned));
        if (tryStep("Setting up MQTT", setupMQTT()))
            nextState(STATE_CONNECT_MQTT);
        break;
    case STATE_CONNECT_MQTT:
        SerialMon.println("Entering STATE_CONNECT_MQTT, attempting connection...");
        if (tryStep("Connecting to MQTT", connectMQTT()))
        {
            SerialMon.println("MQTT connection successful, isProvisioned: " + String(isProvisioned));
            nextState(STATE_SUBSCRIBE_MQTT);
        }
        break;
    case STATE_SUBSCRIBE_MQTT:
        SerialMon.println("Entering STATE_SUBSCRIBE_MQTT, isProvisioned: " + String(isProvisioned));
        if (!isProvisioned)
        {
            if (tryStep("Subscribing to provisioning topic", subscribeMQTT(PROVISION_RESPONSE_TOPIC)))
            {
                if (requestCredentialsFromServer())
                {
                    mqttStatus.provisionSubscribed = true;
                    nextState(STATE_WAIT_PROVISION);
                }
                else
                {
                    nextState(STATE_ERROR);
                }
            }
        }
        else
        {
            if (tryStep("Subscribing to MQTT", subscribeMQTT()))
                nextState(STATE_RUNNING);
        }
        break;
    case STATE_WAIT_PROVISION:
        if (SerialAT.available())
        {
            String urc = SerialAT.readStringUntil('\n');
            processURC(urc);
            SerialMon.println("Provision URC Called");
        }
        if (millis() - provisionStartTime >= provisionTimeout)
        {
            SerialMon.println("Provisioning timeout");
            waitingForProvisionResponse = false;
            preferences.begin("device-creds", false);
            preferences.remove("nonce"); // Clear on timeout
            preferences.remove("ecdh_priv");
            preferences.end();
            stopMQTT();
            nextState(STATE_ERROR);
        }
        else if (millis() - lastRequestTime >= PROVISION_REQUEST_INTERVAL)
        {
            if (requestCredentialsFromServer())
            {
                SerialMon.printf("Provision request resent successfully at %lu ms\n", millis());
            }
            else
            {
                SerialMon.printf("Provision request failed at %lu ms, will retry after interval\n", millis());
            }
            lastRequestTime = millis(); //
        }
        break;
    case STATE_RUNNING:
        if (millis() - lastMonitorTime >= MONITOR_INTERVAL)
        {
            monitorConnections();
            lastMonitorTime = millis();
            // SerialMon.println("This is Updated OTA Firmware");
        }
        break;
    case STATE_ERROR:
        SerialMon.println("Setup failed");
        cleanupResources();
        resetModem();
        nextState(STATE_INIT_MODEM);
        break;
    case STATE_RECOVER_MQTT:
        if (tryStep("Recovering MQTT", connectMQTT() && subscribeMQTT()))
            nextState(STATE_RUNNING);
        break;
    }
}

// MQTT and OTA functions (partial implementation; integrate with existing logic)
void handleMessage(String topic, String payload)
{
    SerialMon.println("Received message on " + topic + ": " + payload);
    if (topic == PROVISION_RESPONSE_TOPIC && waitingForProvisionResponse)
    {
        if (payload.startsWith("CREDENTIALS:"))
        {
            String encrypted_b64 = payload.substring(11);
            encrypted_b64.trim();
            if (encrypted_b64.startsWith(":"))
            {
                encrypted_b64 = encrypted_b64.substring(1);
            }
            SerialMon.println("Final Base64 to decode: [" + encrypted_b64 + "]");

            unsigned char encrypted_bytes[1024];
            size_t enc_len = base64_decode(encrypted_b64.c_str(), encrypted_bytes, 1024);
            SerialMon.println("Decoded length: " + String(enc_len));

            if (enc_len == 0)
            {
                SerialMon.println("Failed to decode Base64 data");
                return;
            }

            preferences.begin("device-creds", true);
            unsigned char iv[16], ecdh_priv[32];
            preferences.getBytes("nonce", iv, 16);
            preferences.getBytes("ecdh_priv", ecdh_priv, 32);
            preferences.end();

            SerialMon.print("Private key from NVS: ");
            for (int i = 0; i < 32; i++)
                SerialMon.printf("%02x", ecdh_priv[i]);
            SerialMon.println();

            mbedtls_ecdh_context ecdh;
            mbedtls_pk_context pk;
            mbedtls_ecdh_init(&ecdh);
            mbedtls_pk_init(&pk);

            if (mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
            {
                SerialMon.println("Failed to load curve");
                mbedtls_pk_free(&pk);
                mbedtls_ecdh_free(&ecdh);
                return;
            }

            if (mbedtls_mpi_read_binary(&ecdh.d, ecdh_priv, 32) != 0)
            {
                SerialMon.println("Failed to load private key");
                mbedtls_pk_free(&pk);
                mbedtls_ecdh_free(&ecdh);
                return;
            }

            if (mbedtls_pk_parse_public_key(&pk, (const unsigned char *)SERVER_PUBLIC_KEY_PEM, strlen(SERVER_PUBLIC_KEY_PEM) + 1) != 0)
            {
                SerialMon.println("Failed to parse server public key PEM");
                mbedtls_pk_free(&pk);
                mbedtls_ecdh_free(&ecdh);
                return;
            }

            mbedtls_ecp_keypair *ec_key = mbedtls_pk_ec(pk);
            if (!ec_key || mbedtls_ecp_copy(&ecdh.Qp, &ec_key->Q) != 0)
            {
                SerialMon.println("Failed to extract server public key");
                mbedtls_pk_free(&pk);
                mbedtls_ecdh_free(&ecdh);
                return;
            }

            unsigned char shared_secret[32];
            size_t olen;
            int ret = mbedtls_ecdh_calc_secret(&ecdh, &olen, shared_secret, 32, NULL, NULL);
            if (ret != 0)
            {
                SerialMon.println("Failed to compute shared secret, error code: " + String(ret));
                mbedtls_pk_free(&pk);
                mbedtls_ecdh_free(&ecdh);
                return;
            }
            SerialMon.print("Shared secret: ");
            for (int i = 0; i < 32; i++)
                SerialMon.printf("%02x", shared_secret[i]);
            SerialMon.println();

            unsigned char derived_key[32];
            mbedtls_sha256(shared_secret, 32, derived_key, 0);
            SerialMon.print("Derived key: ");
            for (int i = 0; i < 32; i++)
                SerialMon.printf("%02x", derived_key[i]);
            SerialMon.println();

            mbedtls_aes_context aes;
            mbedtls_aes_init(&aes);
            if (mbedtls_aes_setkey_dec(&aes, derived_key, 256) != 0)
            {
                SerialMon.println("Failed to set AES decryption key");
                mbedtls_aes_free(&aes);
                mbedtls_pk_free(&pk);
                mbedtls_ecdh_free(&ecdh);
                return;
            }

            unsigned char decrypted[1024];
            size_t padded_len = ((enc_len + 15) / 16) * 16;
            if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, padded_len, iv, encrypted_bytes, decrypted) != 0)
            {
                SerialMon.println("AES decryption failed");
                mbedtls_aes_free(&aes);
                mbedtls_pk_free(&pk);
                mbedtls_ecdh_free(&ecdh);
                return;
            }

            size_t unpadded_len = pkcs7_unpad(decrypted, padded_len);
            String creds = String((char *)decrypted, unpadded_len);
            SerialMon.println("Decrypted credentials: " + creds);

            int deviceIdStart = creds.indexOf("DEVICE_ID:") + 10;
            int usernameStart = creds.indexOf(":USERNAME:");
            int passwordStart = creds.indexOf(":PASSWORD:");
            if (deviceIdStart < 10 || usernameStart == -1 || passwordStart == -1)
            {
                SerialMon.println("Invalid credential format");
                mbedtls_aes_free(&aes);
                mbedtls_pk_free(&pk);
                mbedtls_ecdh_free(&ecdh);
                return;
            }

            String device_id = creds.substring(deviceIdStart, usernameStart);
            String username = creds.substring(usernameStart + 10, passwordStart);
            String password = creds.substring(passwordStart + 10);

            saveCredentials(device_id, username, password);
            clientID = device_id;
            waitingForProvisionResponse = false;
            preferences.begin("device-creds", false);
            preferences.remove("nonce");     // Clear nonce on success
            preferences.remove("ecdh_priv"); // Clear private key
            preferences.end();
            stopMQTT();
            nextState(STATE_SETUP_MQTT);

            mbedtls_aes_free(&aes);
            mbedtls_pk_free(&pk);
            mbedtls_ecdh_free(&ecdh);
            return;
        }
    }
    else if (topic == mqtt_topic_firmware)
    {
        processOTAFirmware(topic, (byte *)payload.c_str(), payload.length());
    }
}

bool tryStep(const String &stepMsg, bool success)
{
    SerialMon.print(stepMsg + "... ");
    if (success)
    {
        SerialMon.println("success");
        retryCount = 0;
        return true;
    }
    SerialMon.println("fail");
    retryState(stepMsg);
    return false;
}

void nextState(SetupState next)
{
    currentState = next;
    retryCount = 0;
}

void retryState(const String &stepMsg)
{
    retryCount++;
    if (retryCount >= MAX_RETRIES)
    {
        SerialMon.println("Max retries for " + stepMsg);
        nextState(STATE_ERROR);
    }
    else
    {
        delay(RETRY_DELAY * (retryCount + 1));
    }
}

void resetModem()
{
    SerialMon.println("Resetting modem...");
    digitalWrite(SIM7600_PWR, LOW);
    delay(1500);
    digitalWrite(SIM7600_PWR, HIGH);
    delay(5000);
    mqttStatus.reset();
}

void monitorConnections()
{
    if (!modem.isNetworkConnected())
    {
        SerialMon.println("Network lost");
        nextState(STATE_ERROR);
    }
    else if (!modem.isGprsConnected())
    {
        SerialMon.println("GPRS lost");
        nextState(STATE_ERROR);
    }
}

void cleanupResources()
{
    modem.gprsDisconnect();
    stopMQTT();
    if (otaInProgress)
    {
        esp_ota_end(otaHandle);
        otaInProgress = false;
        otaReceivedSize = 0;
        otaTotalSize = 0;
        chunkCount = 0;
        lastAckMsg = ""; // Clear last acknowledgment
        lastChunkNum = 0xFFFFFFFF;
        receivedChunks.clear();
    }
}

void processURC(String urc)
{
    urc.trim();
    if (urc.length() > 0)
    {
        SerialMon.println("URC: " + urc);
    }
    if (urc.startsWith("+CMQTTCONNLOST: 0,"))
    {
        SerialMon.println("MQTT connection lost detected");
        mqttStatus.connected = false;
        mqttStatus.subscribed = false;
        if (currentState == STATE_RUNNING || currentState == STATE_WAIT_PROVISION)
        {
            nextState(STATE_RECOVER_MQTT);
        }
    }
    else if (urc.startsWith("+CMQTTSUB: 0,0"))
    {
        SerialMon.println("Subscription confirmed via URC");
        if (!mqttStatus.provisionSubscribed && waitingForProvisionResponse)
        {
            mqttStatus.provisionSubscribed = true;
        }
    }
    else if (urc.startsWith("+CMQTTRXPAYLOAD: 0,"))
    {
        pendingPayloadLen = urc.substring(urc.indexOf(",") + 1).toInt();
        pendingPayload = "";
        receivedPayloadSize = 0;
    }
    else if (urc.startsWith("+CMQTTACCQ: 0,0"))
    {
        SerialMon.println("MQTT client acquisition confirmed via URC");
        mqttStatus.clientAcquired = true;
    }
    else if (urc.startsWith("+CMQTTCONNECT: 0,0"))
    {
        SerialMon.println("MQTT connection confirmed via URC");
        mqttStatus.connected = true;
        mqttStatus.lastConnectTime = millis();
        if (currentState == STATE_CONNECT_MQTT)
        {
            nextState(STATE_SUBSCRIBE_MQTT);
        }
    }
    else if (urc.startsWith("+CMQTTRXSTART: 0,"))
    {
        messageInProgress = true;
        pendingTopic = "";
        pendingPayload = "";
        int commaIdx = urc.indexOf(',', 14);
        pendingTopicLen = urc.substring(14, commaIdx).toInt();
        pendingPayloadLen = urc.substring(commaIdx + 1).toInt();
    }
    else if (messageInProgress && !urc.startsWith("+") && pendingTopic == "")
    {
        pendingTopic = urc;
    }
    else if (messageInProgress && !urc.startsWith("+") && pendingTopic != "" && pendingPayload == "")
    {
        pendingPayload = urc;
        receivedPayloadSize = urc.length(); // Initialize size here
    }
    else if (!urc.startsWith("+") && pendingPayloadLen > 0)
    {
        pendingPayload += urc;
        receivedPayloadSize += urc.length(); // Update size for each chunk
        SerialMon.println("Payload chunk received, total size so far: " + String(receivedPayloadSize));
    }
    else if (urc == "+CMQTTRXEND: 0")
    {
        if (receivedPayloadSize != pendingPayloadLen)
        {
            SerialMon.println("Warning: Received " + String(receivedPayloadSize) + " bytes, expected " + String(pendingPayloadLen));
        }
        handleMessage(pendingTopic, pendingPayload);
        pendingTopic = "";
        pendingPayload = "";
        pendingTopicLen = 0;
        pendingPayloadLen = 0;
        receivedPayloadSize = 0;
        messageInProgress = false;
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

bool setupMQTT()
{
    if (!mqttStatus.serviceStarted)
    {
        SerialAT.println("AT+CMQTTSTART");
        String response;
        if (modem.waitResponse(5000L, response) != 1)
        {
            response.trim();
            SerialMon.println("MQTT start failed - Response: " + response);
            if (response.indexOf("+CMQTTSTART:") >= 0)
            {
                mqttStatus.lastErrorCode = response.substring(response.indexOf(":") + 2).toInt();
                if (mqttStatus.lastErrorCode == 23)
                {
                    SerialMon.println("MQTT service already running (+CMQTTSTART: 23), proceeding");
                    mqttStatus.serviceStarted = true;
                }
                else
                {
                    return false;
                }
            }
            else
            {
                return false;
            }
        }
        else if (response.indexOf("+CMQTTSTART: 0") >= 0)
        {
            mqttStatus.serviceStarted = true;
            SerialMon.println("MQTT service started successfully");
        }
    }

    if (!mqttStatus.clientAcquired)
    {
        unsigned long timeVal = millis() & 0xFFF;
        clientID = "ESP32_" + String(timeVal);
        SerialMon.println("Generated clientID: " + clientID);

        char accqCmd[64];
        snprintf(accqCmd, sizeof(accqCmd), "AT+CMQTTACCQ=0,\"%s\",1", clientID.c_str());
        SerialMon.println("Sending: " + String(accqCmd));
        SerialAT.println(accqCmd);

        String response;
        if (modem.waitResponse(5000L, response) != 1)
        {
            response.trim();
            SerialMon.println("Failed to acquire MQTT client - Response: " + response);
            if (response.indexOf("+CMQTTACCQ: 0,19") >= 0)
            {
                SerialMon.println("Client index 0 already acquired, attempting to release...");
                SerialAT.println("AT+CMQTTREL=0");
                if (modem.waitResponse(5000L) != 1)
                {
                    SerialMon.println("Failed to release client, attempting full MQTT restart...");
                    if (!stopMQTT()) // Stop and reset MQTT service
                    {
                        SerialMon.println("MQTT stop failed, resetting modem...");
                        resetModem();
                        mqttStatus.reset();
                        // Restart MQTT service after reset
                        SerialAT.println("AT+CMQTTSTART");
                        if (modem.waitResponse(5000L) != 1)
                        {
                            SerialMon.println("Failed to restart MQTT service after modem reset");
                            return false;
                        }
                        mqttStatus.serviceStarted = true;
                    }
                    // Retry acquiring client after cleanup
                    SerialMon.println("Retrying: " + String(accqCmd));
                    SerialAT.println(accqCmd);
                    if (modem.waitResponse(5000L, response) != 1 || response.indexOf("+CMQTTACCQ: 0,0") < 0)
                    {
                        SerialMon.println("Failed to acquire client after cleanup - Response: " + response);
                        return false;
                    }
                }
                else
                {
                    // Successfully released, retry acquiring
                    SerialMon.println("Client released, retrying: " + String(accqCmd));
                    SerialAT.println(accqCmd);
                    if (modem.waitResponse(5000L, response) != 1 || response.indexOf("+CMQTTACCQ: 0,0") < 0)
                    {
                        SerialMon.println("Failed to acquire client after release - Response: " + response);
                        return false;
                    }
                }
            }
            else
            {
                return false; // Other errors
            }
        }
        mqttStatus.clientAcquired = true;
        SerialMon.println("MQTT client acquired successfully");
    }

    if (!mqttStatus.connected)
    {
        SerialAT.println("AT+CMQTTSSLCFG=0,0");
        if (modem.waitResponse(2000L) != 1)
        {
            SerialMon.println("Failed to configure SSL for MQTT");
            return false;
        }
    }

    SerialMon.println("Setting up MQTT... success");
    return true;
}

bool connectMQTT()
{
    SerialMon.println("Entering connectMQTT - mqttStatus.connected: " + String(mqttStatus.connected));
    if (mqttStatus.connected)
    {
        SerialMon.println("MQTT already connected, skipping connect");
        return true;
    }

    if (!mqttStatus.serviceStarted || !mqttStatus.clientAcquired)
    {
        SerialMon.println("MQTT service or client not ready, setting up...");
        if (!setupMQTT())
        {
            SerialMon.println("setupMQTT failed in connectMQTT");
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

    while (millis() - startTime < 30000L && !gotURC)
    {
        if (SerialAT.available())
        {
            String line = SerialAT.readStringUntil('\n');
            line.trim();
            if (line.length() > 0)
            {
                SerialMon.println("Received: " + line + " at " + String(millis() - startTime) + "ms");
                fullResponse += line + "\n";
                if (line.indexOf("OK") >= 0)
                {
                    gotOK = true;
                    SerialMon.println("OK detected");
                }
                if (line.indexOf("+CMQTTCONNECT: 0,0") >= 0)
                {
                    gotURC = true;
                    mqttStatus.connected = true;
                    mqttStatus.lastConnectTime = millis();
                    SerialMon.println("MQTT connected successfully");
                }
                else if (line.indexOf("+CMQTTCONNECT: 0,") >= 0)
                {
                    mqttStatus.lastErrorCode = line.substring(line.indexOf(",") + 1).toInt();
                    SerialMon.println("MQTT connection failed - Error code: " + String(mqttStatus.lastErrorCode));
                    return false;
                }
            }
        }
    }

    SerialMon.println("Full response: [" + fullResponse + "]");
    if (gotURC)
    {
        SerialMon.println("connectMQTT returning true");
        return true;
    }
    else if (gotOK)
    {
        SerialMon.println("OK received but no URC, assuming failure");
        return false;
    }
    else
    {
        SerialMon.println("No OK or URC, connectMQTT failed");
        return false;
    }
}

bool subscribeMQTT()
{
    bool success = true;
    success &= subscribeMQTT(mqtt_topic_recv);
    success &= subscribeMQTT(mqtt_topic_firmware);
    success &= subscribeMQTT(PROVISION_RESPONSE_TOPIC);
    if (success)
        mqttStatus.subscribed = true;
    return success;
}

bool subscribeMQTT(const char *topic)
{
    if (!topic || strlen(topic) == 0)
    {
        SerialMon.println("Invalid topic provided for subscription");
        return false;
    }

    if (!mqttStatus.connected)
    {
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

    if (waitResult != 1 || response.indexOf(">") < 0)
    {
        response.trim();
        SerialMon.println("Initial wait failed to detect '>' prompt - Response: [" + response + "]");
        // Fallback to raw read
        unsigned long startTime = millis();
        while (millis() - startTime < 2000L)
        {
            if (SerialAT.available())
            {
                String line = SerialAT.readStringUntil('\n');
                line.trim();
                if (line.length() > 0)
                {
                    SerialMon.println("Raw read line: " + line + " at " + String(millis() - startTime) + "ms");
                    if (line.indexOf(">") >= 0)
                    {
                        SerialMon.println("'>' prompt detected via raw read");
                        response = line;
                        break;
                    }
                }
            }
            delay(100);
        }
        if (response.indexOf(">") < 0)
        {
            SerialMon.println("Failed to get '>' prompt for SUBTOPIC after fallback - Final response: [" + response + "]");
            return false;
        }
    }
    else
    {
        SerialMon.println("'>' prompt received successfully: " + response);
    }

    SerialMon.println("Sending topic: " + String(topic));
    SerialAT.print(topic);
    if (modem.waitResponse(2000L, response) != 1 || response.indexOf("OK") < 0)
    {
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
    while (millis() - startTime < 10000L && !gotURC)
    {
        if (SerialAT.available())
        {
            String line = SerialAT.readStringUntil('\n');
            line.trim();
            if (line.length() > 0)
            {
                SerialMon.println("Received line: " + line + " at " + String(millis() - startTime) + "ms");
                fullResponse += line + "\n";
                if (line.indexOf("OK") >= 0)
                {
                    gotOK = true;
                    SerialMon.println("OK detected");
                }
                if (line.indexOf("+CMQTTSUB: 0,0") >= 0)
                {
                    gotURC = true;
                    SerialMon.println("Subscription confirmed for: " + String(topic));
                }
                else if (line.indexOf("+CMQTTSUB: 0,") >= 0)
                {
                    int errorCode = line.substring(line.indexOf(",") + 1).toInt();
                    SerialMon.println("Subscription failed for " + String(topic) + " - Error code: " + String(errorCode));
                    return false;
                }
            }
        }
        else
        {
            SerialMon.println("No data available at " + String(millis() - startTime) + "ms");
            delay(100);
        }
    }

    fullResponse.trim();
    SerialMon.println("Full response after wait: [" + fullResponse + "]");

    if (gotURC)
    {
        SerialMon.println("Successfully subscribed to: " + String(topic));
        return true;
    }
    else if (gotOK)
    {
        SerialMon.println("OK received but no +CMQTTSUB: 0,0 within 10s for " + String(topic) + " - Assuming failure");
        return false;
    }
    else
    {
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

bool stopMQTT()
{
    if (!mqttStatus.serviceStarted)
    {
        SerialMon.println("MQTT service already stopped");
        return true;
    }

    if (mqttStatus.connected)
    {
        SerialMon.println("Disconnecting MQTT...");
        SerialAT.println("AT+CMQTTDISC=0,120");

        String discResponse = "";
        unsigned long startTime = millis();
        bool gotOK = false;
        bool gotURC = false;

        // Wait up to 15 seconds for OK or URC
        while (millis() - startTime < 15000L && !(gotOK && gotURC))
        {
            if (SerialAT.available())
            {
                String line = SerialAT.readStringUntil('\n');
                line.trim();
                if (line.length() > 0)
                {
                    SerialMon.println("Received line: " + line + " at " + String(millis() - startTime) + "ms");
                    discResponse += line + "\n";
                    if (line.indexOf("OK") >= 0)
                    {
                        gotOK = true;
                        SerialMon.println("OK detected");
                    }
                    if (line.indexOf("+CMQTTDISC: 0,0") >= 0)
                    {
                        gotURC = true;
                        SerialMon.println("Disconnect confirmed");
                    }
                }
            }
            else
            {
                delay(100);
            }
        }

        discResponse.trim();
        SerialMon.println("Full disconnect response: [" + discResponse + "]");

        if (!gotURC || !gotOK)
        {
            SerialMon.println("Warning: Incomplete disconnect response - URC: " + String(gotURC) + ", OK: " + String(gotOK));
        }
        mqttStatus.connected = false; // Assume disconnected even if partial success
        delay(1000);                  // Allow modem to process
    }

    if (mqttStatus.clientAcquired)
    {
        SerialMon.println("Releasing MQTT client...");
        SerialAT.println("AT+CMQTTREL=0");
        String relResponse;
        if (modem.waitResponse(5000L, relResponse) != 1 || relResponse.indexOf("OK") < 0)
        {
            relResponse.trim();
            SerialMon.println("Warning: Failed to release MQTT client - Response: " + relResponse);
        }
        mqttStatus.clientAcquired = false;
        delay(1000); // Allow modem to process
    }

    SerialMon.println("Stopping MQTT service...");
    SerialAT.println("AT+CMQTTSTOP");
    String stopResponse;
    if (modem.waitResponse(10000L, stopResponse) != 1 || stopResponse.indexOf("+CMQTTSTOP: 0") < 0)
    {
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

void startOTA(uint32_t totalSize)
{
    previousPartition = esp_ota_get_running_partition();
    updatePartition = esp_ota_get_next_update_partition(NULL);
    if (!updatePartition)
    {
        SerialMon.println("No OTA partition");
        return;
    }
    esp_err_t err = esp_ota_begin(updatePartition, totalSize, &otaHandle);
    if (err != ESP_OK)
    {
        SerialMon.printf("OTA begin failed: %s\n", esp_err_to_name(err));
        return;
    }
    otaInProgress = true;
    otaTotalSize = totalSize;
    otaReceivedSize = 0;
    chunkCount = 0;
    receivedChunks.clear();
    lastAckMsg = ""; // Reset last acknowledgment
    lastChunkNum = 0xFFFFFFFF;
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    publishMQTT(mqtt_topic_send, "OTA:STARTED");
}

void processOTAFirmware(const String &topic, byte *payload, unsigned int dataLen)
{
    String payloadStr((char *)payload, dataLen);
    SerialMon.println("Processing OTA message: " + payloadStr);
    if (payloadStr.startsWith("OTA:BEGIN:"))
    {
        if (otaInProgress)
            cleanupResources();
        int colonIdx = payloadStr.indexOf(':', 10);
        otaTotalSize = payloadStr.substring(10, colonIdx).toInt();
        int nextColon = payloadStr.indexOf(':', colonIdx + 1);
        otaHash = payloadStr.substring(colonIdx + 1, nextColon);
        otaSignature = payloadStr.substring(nextColon + 1); // Store the signature
        SerialMon.println("OTA Begin - Size: " + String(otaTotalSize) + ", Hash: " + otaHash + ", Signature: " + otaSignature);
        startOTA(otaTotalSize);
        return;
    }
    if (!otaInProgress)
    {
        SerialMon.println("Ignoring OTA message: OTA not in progress");
        return;
    }
    if (payloadStr == "OTA:END")
    {
        SerialMon.println("Received OTA:END");
        finishOTA();
        return;
    }
    size_t maxDecodedLen = ((dataLen + 3) / 4) * 3;
    unsigned char *decodedPayload = new unsigned char[maxDecodedLen];
    size_t decodedLen = base64_decode((char *)payload, decodedPayload, maxDecodedLen);
    if (decodedLen < 4)
    {
        SerialMon.println("Invalid chunk size: " + String(decodedLen));
        delete[] decodedPayload;
        return;
    }
    unsigned long chunkNum = ((unsigned long)decodedPayload[0] << 24) |
                             ((unsigned long)decodedPayload[1] << 16) |
                             ((unsigned long)decodedPayload[2] << 8) |
                             decodedPayload[3];
    size_t chunkSize = decodedLen - 4;

    if (receivedChunks[chunkNum])
    {
        SerialMon.println("Duplicate chunk: " + String(chunkNum));
        if (chunkNum == lastChunkNum && lastAckMsg != "")
        {
            // Resend the last acknowledgment if it matches the duplicate chunk
            publishMQTT(mqtt_topic_send, lastAckMsg.c_str());
            SerialMon.println("Resent last ack: " + lastAckMsg);
        }
        else
        {
            SerialMon.println("Duplicate chunk " + String(chunkNum) + " does not match last chunk " + String(lastChunkNum) + "; no ack resent");
        }
        delete[] decodedPayload;
        return;
    }

    // Process new chunk
    esp_ota_write(otaHandle, decodedPayload + 4, chunkSize);
    mbedtls_sha256_update(&sha256_ctx, decodedPayload + 4, chunkSize);
    receivedChunks[chunkNum] = true;
    otaReceivedSize += chunkSize;
    chunkCount++;

    // Construct and store the acknowledgment message
    lastAckMsg = "OTA:PROGRESS:" + String(chunkNum) + ":" + String(otaReceivedSize) + "/" + String(otaTotalSize) + ":DEVICE:" + clientID;
    lastChunkNum = chunkNum; // Update the last chunk number
    publishMQTT(mqtt_topic_send, lastAckMsg.c_str());
    SerialMon.println("Sent ack: " + lastAckMsg);

    delete[] decodedPayload;
}

void finishOTA()
{
    if (!otaInProgress)
    {
        SerialMon.println("No OTA in progress to finish");
        return;
    }
    if (otaReceivedSize != otaTotalSize)
    {
        SerialMon.println("OTA incomplete: Received " + String(otaReceivedSize) + " of " + String(otaTotalSize));
        checkMissingChunks();
        cleanupResources();
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Incomplete");
        return;
    }

    // Compute SHA-256 hash
    unsigned char hash[32];
    mbedtls_sha256_finish(&sha256_ctx, hash);
    mbedtls_sha256_free(&sha256_ctx);
    String computedHash = "";
    for (int i = 0; i < 32; i++)
    {
        char hex[3];
        sprintf(hex, "%02x", hash[i]);
        computedHash += hex;
    }
    SerialMon.println("Computed Hash: " + computedHash + ", Expected Hash: " + otaHash);

    // Verify hash
    if (computedHash != otaHash)
    {
        SerialMon.println("Hash mismatch detected");
        cleanupResources();
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Hash mismatch");
        return;
    }

    // Verify ECDSA signature
    unsigned char signature[128]; // Buffer large enough for base64-decoded signature
    size_t sig_len = base64_decode(otaSignature.c_str(), signature, 128);
    if (sig_len == 0 || !verifyOTASignature(hash, 32, signature, sig_len))
    {
        SerialMon.println("OTA signature verification failed");
        cleanupResources();
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Signature invalid");
        return;
    }
    SerialMon.println("OTA signature verified successfully");

    // Apply the update
    esp_err_t err = esp_ota_end(otaHandle);
    if (err != ESP_OK)
    {
        SerialMon.printf("OTA end failed: %s\n", esp_err_to_name(err));
        cleanupResources();
        publishMQTT(mqtt_topic_send, "OTA:ERROR:End failed");
        return;
    }
    err = esp_ota_set_boot_partition(updatePartition);
    if (err != ESP_OK)
    {
        SerialMon.printf("OTA set boot partition failed: %s\n", esp_err_to_name(err));
        cleanupResources();
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Boot partition set failed");
        return;
    }

    SerialMon.println("OTA successful, restarting...");
    otaInProgress = false;
    publishMQTT(mqtt_topic_send, "OTA:SUCCESS:PENDING_VALIDATION");
    delay(1000); // Brief delay to ensure message is sent
    ESP.restart();
}

void checkMissingChunks()
{
    unsigned long expectedChunks = (otaTotalSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
    String missingMsg = "OTA:REQUEST:";
    bool hasMissing = false;
    for (unsigned long i = 0; i < expectedChunks; i++)
    {
        if (!receivedChunks[i])
        {
            missingMsg += String(i) + ",";
            hasMissing = true;
        }
    }
    if (hasMissing)
    {
        missingMsg.remove(missingMsg.length() - 1);
        publishMQTT(mqtt_topic_send, missingMsg.c_str());
    }
}

void revertToPreviousFirmware()
{
    if (!previousPartition)
        return;
    esp_ota_set_boot_partition(previousPartition);
    SerialMon.println("Reverting to previous firmware");
    ESP.restart();
}

void performFactoryReset()
{
    const esp_partition_t *factoryPartition = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL);
    if (!factoryPartition)
    {
        SerialMon.println("No factory partition found");
        return;
    }

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

void loadCredentials()
{
    preferences.begin("device-creds", true);
    isProvisioned = preferences.getBool("provisioned", false);
    if (isProvisioned)
    {
        clientID = preferences.getString("device_id", DEFAULT_CLIENT_ID);
        unsigned char enc_user[32], dec_user[32];
        unsigned char enc_pass[32], dec_pass[32];
        preferences.getBytes("username", enc_user, 32);
        preferences.getBytes("password", enc_pass, 32);
        decryptNVSData(enc_user, 32, dec_user);
        decryptNVSData(enc_pass, 32, dec_pass);

        // Debug the decrypted data
        SerialMon.print("Decrypted username: ");
        for (int i = 0; i < 32 && dec_user[i] != '\0'; i++)
        {
            SerialMon.print((char)dec_user[i]);
        }
        SerialMon.println();
        SerialMon.print("Decrypted password: ");
        for (int i = 0; i < 32 && dec_pass[i] != '\0'; i++)
        {
            SerialMon.print((char)dec_pass[i]);
        }
        SerialMon.println();

        mqtt_user = String((char *)dec_user);
        mqtt_pass = String((char *)dec_pass);
    }
    else
    {
        clientID = DEFAULT_CLIENT_ID;
        mqtt_user = DEFAULT_USERNAME;
        mqtt_pass = DEFAULT_PASSWORD;
    }
    preferences.end();
}

void saveCredentials(String device_id, String username, String password)
{
    clientID = device_id;
    mqtt_user = username;
    mqtt_pass = password;

    preferences.begin("device-creds", false);
    preferences.putString("device_id", device_id);

    unsigned char enc_user[32], dec_user[32] = {0};
    memcpy(dec_user, mqtt_user.c_str(), min(mqtt_user.length(), (size_t)32));
    encryptNVSData(dec_user, mqtt_user.length(), enc_user);
    preferences.putBytes("username", enc_user, 32);

    unsigned char enc_pass[32], dec_pass[32] = {0};
    memcpy(dec_pass, mqtt_pass.c_str(), min(mqtt_pass.length(), (size_t)32));
    encryptNVSData(dec_pass, mqtt_pass.length(), enc_pass);
    preferences.putBytes("password", enc_pass, 32);

    preferences.putBool("provisioned", true);
    preferences.end();
    isProvisioned = true;
}

bool requestCredentialsFromServer()
{
    preferences.begin("device-creds", false);
    bool hasPendingNonce = preferences.isKey("nonce");
    bool sentRequest = false;

    // Try reusing existing nonce and keys if available
    if (hasPendingNonce && waitingForProvisionResponse)
    {
        unsigned char nonce[16];
        unsigned char priv_key[32];
        preferences.getBytes("nonce", nonce, 16);
        preferences.getBytes("ecdh_priv", priv_key, 32);
        String nonceStr = base64_encode(nonce, 16);

        // Log stored private key for debugging
        SerialMon.print("Loaded private key from NVS: ");
        for (int i = 0; i < 32; i++)
            SerialMon.printf("%02x", priv_key[i]);
        SerialMon.println();

        mbedtls_ecdh_context ecdh;
        mbedtls_ctr_drbg_context ctr_drbg;
        mbedtls_entropy_context entropy;
        mbedtls_ecdh_init(&ecdh);
        mbedtls_ctr_drbg_init(&ctr_drbg);
        mbedtls_entropy_init(&entropy);

        // Attempt to regenerate public key
        bool regenerationSuccess = true;
        if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0)
        {
            SerialMon.println("Failed to seed DRBG");
            regenerationSuccess = false;
        }
        else if (mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
        {
            SerialMon.println("Failed to load curve");
            regenerationSuccess = false;
        }
        else if (mbedtls_mpi_read_binary(&ecdh.d, priv_key, 32) != 0)
        {
            SerialMon.println("Failed to load private key from NVS");
            regenerationSuccess = false;
        }
        else
        {
            unsigned char pubkey_buf[65];
            size_t olen;
            int ret = mbedtls_ecdh_make_public(&ecdh, &olen, pubkey_buf, sizeof(pubkey_buf),
                                               mbedtls_ctr_drbg_random, &ctr_drbg);
            if (ret != 0)
            {
                SerialMon.println("Failed to regenerate public key from stored private key, error code: " + String(ret));
                regenerationSuccess = false;
            }
            else if (olen != 65 || pubkey_buf[0] != 0x04)
            {
                SerialMon.println("Invalid public key format");
                regenerationSuccess = false;
            }
            else
            {
                String pubkey_b64 = base64_encode(pubkey_buf, 65);
                String requestMsg = "UUID:" + deviceUUID + ":NONCE:" + nonceStr + ":PUBKEY:" + pubkey_b64;

                if (publishMQTT(PROVISION_TOPIC, requestMsg.c_str()))
                {
                    SerialMon.println("Resent provision request with stored nonce");
                    sentRequest = true;
                }
                else
                {
                    SerialMon.println("Failed to resend provision request with stored nonce");
                }
            }
        }

        mbedtls_entropy_free(&entropy);
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_ecdh_free(&ecdh);

        if (sentRequest)
        {
            preferences.end();
            lastRequestTime = millis(); // Update only on success
            return true;
        }
        else if (!regenerationSuccess)
        {
            SerialMon.println("Regeneration failed, falling back to new key generation");
            // Proceed to generate new keys below
        }
        else
        {
            preferences.end();
            return false; // Failed to send but no regeneration error
        }
    }

    // Generate new nonce and keys if no pending request or regeneration failed
    mbedtls_ecdh_context ecdh;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_context entropy;
    mbedtls_ecdh_init(&ecdh);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0)
    {
        SerialMon.println("Failed to seed DRBG");
    }
    else if (mbedtls_ecp_group_load(&ecdh.grp, MBEDTLS_ECP_DP_SECP256R1) != 0)
    {
        SerialMon.println("Failed to load curve");
    }
    else if (mbedtls_ecdh_gen_public(&ecdh.grp, &ecdh.d, &ecdh.Q, mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    {
        SerialMon.println("Failed to generate public key");
    }
    else
    {
        unsigned char pubkey[65];
        pubkey[0] = 0x04;
        if (mbedtls_mpi_write_binary(&ecdh.Q.X, pubkey + 1, 32) != 0 ||
            mbedtls_mpi_write_binary(&ecdh.Q.Y, pubkey + 33, 32) != 0)
        {
            SerialMon.println("Failed to serialize public key");
        }
        else
        {
            String pubkey_b64 = base64_encode(pubkey, 65);

            unsigned char priv_key[32];
            if (mbedtls_mpi_write_binary(&ecdh.d, priv_key, 32) != 0)
            {
                SerialMon.println("Failed to serialize private key");
            }
            else
            {
                unsigned char nonce[16];
                esp_fill_random(nonce, 16);
                String nonceStr = base64_encode(nonce, 16);

                String requestMsg = "UUID:" + deviceUUID + ":NONCE:" + nonceStr + ":PUBKEY:" + pubkey_b64;

                if (publishMQTT(PROVISION_TOPIC, requestMsg.c_str()))
                {
                    waitingForProvisionResponse = true;
                    provisionStartTime = millis();
                    lastRequestTime = millis();
                    preferences.putBytes("ecdh_priv", priv_key, 32);
                    preferences.putBytes("nonce", nonce, 16);
                    SerialMon.println("Private key and nonce stored in NVS");
                    sentRequest = true;
                }
                else
                {
                    SerialMon.println("Failed to send new provision request");
                }
            }
        }
    }

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ecdh_free(&ecdh);
    preferences.end();
    return sentRequest;
}

/*


provisioning okay
password
1234567890abcdef
Full erase ESP32
esptool.exe --chip esp32s3 --port COM3 erase_flash


*/