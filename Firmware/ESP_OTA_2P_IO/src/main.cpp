#define TINY_GSM_MODEM_SIM7600
#define DUMP_AT_COMMANDS
#define ENABLE_LCD

#include <Wire.h>
#include <TinyGsmClient.h>
#include <HardwareSerial.h>
#include <Adafruit_NeoPixel.h>
#ifdef ENABLE_LCD
#include <LCD_I2C.h>
#endif
#include <esp_task_wdt.h>
#include "mbedtls/aes.h"
#include "certificates.h"
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

// Default credentials for initial provisioning
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

#ifdef DUMP_AT_COMMANDS
#include <StreamDebugger.h>
StreamDebugger debugger(SerialAT, SerialMon);
TinyGsm modem(debugger);
#else
TinyGsm modem(SerialAT);
#endif

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
    STATE_ERROR,
    STATE_STOPPED,
    STATE_RECOVER_NETWORK,
    STATE_RECOVER_GPRS,
    STATE_RECOVER_MQTT
};

// Configuration
const int MAX_RETRIES = 3;
const int RETRY_DELAY = 2000;
const size_t OTA_CHUNK_SIZE = 512;
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
const size_t CHUNK_SIZE = 508;

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
String imei = "";
String incomingBuffer = "";
unsigned long lastMonitorTime = 0;
String pendingTopic = "";
String pendingPayload = "";
bool messageInProgress = false;
int pendingTopicLen = 0;
int pendingPayloadLen = 0;
unsigned char decryptedBuffer[128];
unsigned char encryptedBuffer[128];
bool isProvisioned = false;
Preferences preferences;
bool factoryResetTriggered = false;
bool waitingForProvisionResponse = false; // New flag to track provisioning wait
unsigned long provisionTimeout = 30000;   // Timeout for provisioning response

// OTA variables
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
bool mqttServiceStarted = false;

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
bool publishMQTT(const char *message);
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
void performFactoryReset();
void resetCredentials();

// Base64 encode function
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
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((j > 1 ? char_array_3[1] : 0) >> 4);
            char_array_4[2] = j > 1 ? ((char_array_3[1] & 0x0f) << 2) + ((j > 2 ? char_array_3[2] : 0) >> 6) : 0;
            char_array_4[3] = j > 2 ? (char_array_3[2] & 0x3f) : 0;
            for (int k = 0; k < (j + 1); k++)
            {
                output += base64_enc_map[char_array_4[k]];
            }
            while (j++ < 3)
                output += '=';
            j = 0;
        }
    }
    return output;
}

// Base64 decode function
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

// Utility function to print hex
void printHex(const char *label, const unsigned char *data, size_t len)
{
    SerialMon.print(label);
    for (size_t i = 0; i < len; i++)
    {
        if (data[i] < 0x10)
            SerialMon.print("0");
        SerialMon.print(data[i], HEX);
        if (i < len - 1)
            SerialMon.print(" ");
    }
    SerialMon.println();
}

// PKCS7 padding/unpadding functions
void pkcs7_pad(unsigned char *data, size_t data_len, size_t block_size)
{
    unsigned char pad_value = block_size - (data_len % block_size);
    for (size_t i = data_len; i < data_len + pad_value; i++)
    {
        data[i] = pad_value;
    }
}

size_t pkcs7_unpad(unsigned char *data, size_t data_len)
{
    unsigned char pad_value = data[data_len - 1];
    if (pad_value > 16 || pad_value > data_len)
        return data_len;
    return data_len - pad_value;
}

// Check running partition
void check_firmware_partition()
{
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running->subtype == ESP_PARTITION_SUBTYPE_APP_FACTORY)
    {
        SerialMon.println("Running from factory partition");
#ifdef ENABLE_LCD
        if (lcdAvailable)
        {
            lcd.clear();
            lcd.print("Factory Mode");
        }
#endif
    }
    else if (running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0 ||
             running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1)
    {
        SerialMon.printf("Running from OTA partition %d\n", running->subtype - ESP_PARTITION_SUBTYPE_APP_OTA_0);
#ifdef ENABLE_LCD
        if (lcdAvailable)
        {
            lcd.clear();
            lcd.print("OTA Mode");
        }
#endif
    }
}

void resetCredentials()
{
    preferences.begin("device-creds", false); // Open in read-write mode
    preferences.clear();                      // Clear all key-value pairs in "device-creds"
    preferences.end();

    // Reset global variables to defaults
    isProvisioned = false;
    clientID = DEFAULT_CLIENT_ID;
    mqtt_user = DEFAULT_USERNAME;
    mqtt_pass = DEFAULT_PASSWORD;

    SerialMon.println("Credentials reset to defaults");
#ifdef ENABLE_LCD
    if (lcdAvailable)
    {
        lcd.clear();
        lcd.print("Creds Reset");
    }
#endif
}

// Load credentials from NVS
void loadCredentials()
{
    preferences.begin("device-creds", true);
    isProvisioned = preferences.getBool("provisioned", false);

    if (isProvisioned)
    {
        clientID = preferences.getString("client_id", "ESP32_" + imei);
        mqtt_user = preferences.getString("username", "ESP32_" + imei);
        mqtt_pass = preferences.getString("password", "");
        if (mqtt_pass == "")
        {
            SerialMon.println("Warning: No saved password found, resetting to default");
            isProvisioned = false;
            clientID = DEFAULT_CLIENT_ID;
            mqtt_user = DEFAULT_USERNAME;
            mqtt_pass = DEFAULT_PASSWORD;
        }
    }
    else
    {
        clientID = DEFAULT_CLIENT_ID;
        mqtt_user = DEFAULT_USERNAME;
        mqtt_pass = DEFAULT_PASSWORD;
    }
    preferences.end();
    SerialMon.println("Loaded credentials:");
    SerialMon.println("Client ID: " + clientID);
    SerialMon.println("Username: " + mqtt_user);
    SerialMon.println("Provisioned: " + String(isProvisioned ? "Yes" : "No"));
}

// Save credentials to NVS
void saveCredentials(String newPassword)
{
    if (imei == "" || imei == "Unknown")
    {
        SerialMon.println("Cannot save credentials without valid IMEI");
        return;
    }

    clientID = "ESP32_" + imei;
    mqtt_user = clientID; // Username matches clientID
    mqtt_pass = newPassword;

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
}

// Request credentials from server
bool requestCredentialsFromServer()
{
    if (imei == "" || imei == "Unknown")
    {
        SerialMon.println("No IMEI available for provisioning");
        return false;
    }

    clientID = DEFAULT_CLIENT_ID;
    mqtt_user = DEFAULT_USERNAME;
    mqtt_pass = DEFAULT_PASSWORD;
    SerialMon.println("Set provisioning credentials - ClientID: " + clientID + ", User: " + mqtt_user + ", Pass: " + mqtt_pass);

    if (!connectMQTT())
    {
        SerialMon.println("Failed to connect with default credentials");
        return false;
    }

    // Subscribe to PROVISION_RESPONSE_TOPIC
    modem.sendAT("+CMQTTSUBTOPIC=0,", String(strlen(PROVISION_RESPONSE_TOPIC)).c_str(), ",1");
    if (modem.waitResponse(1000L, ">") != 1)
    {
        SerialMon.println("Failed to get prompt for SUBTOPIC");
        disconnectMQTT();
        return false;
    }
    SerialAT.print(PROVISION_RESPONSE_TOPIC);
    if (modem.waitResponse(2000L) != 1)
    {
        SerialMon.println("Failed to send provision response topic");
        disconnectMQTT();
        return false;
    }
    modem.sendAT("+CMQTTSUB=0");
    if (modem.waitResponse(2000L, "+CMQTTSUB: 0,0") != 1)
    {
        SerialMon.println("Failed to subscribe to " + String(PROVISION_RESPONSE_TOPIC));
        disconnectMQTT();
        return false;
    }
    SerialMon.println("Subscribed to " + String(PROVISION_RESPONSE_TOPIC));

    // Publish provisioning request
    String requestMsg = "IMEI:" + imei;
    modem.sendAT("+CMQTTTOPIC=0,", String(strlen(PROVISION_TOPIC)).c_str());
    if (modem.waitResponse(1000L, ">") != 1)
    {
        SerialMon.println("Failed to get prompt for TOPIC");
        disconnectMQTT();
        return false;
    }
    SerialAT.print(PROVISION_TOPIC);
    if (modem.waitResponse(1000L) != 1)
    {
        SerialMon.println("Failed to send provision topic");
        disconnectMQTT();
        return false;
    }
    modem.sendAT("+CMQTTPAYLOAD=0,", String(requestMsg.length()).c_str());
    if (modem.waitResponse(1000L, ">") != 1)
    {
        SerialMon.println("Failed to get prompt for PAYLOAD");
        disconnectMQTT();
        return false;
    }
    SerialAT.print(requestMsg);
    if (modem.waitResponse(1000L) != 1)
    {
        SerialMon.println("Failed to send payload");
        disconnectMQTT();
        return false;
    }
    modem.sendAT("+CMQTTPUB=0,1,60");
    if (modem.waitResponse(2000L, "+CMQTTPUB: 0,0") != 1)
    {
        SerialMon.println("Failed to publish credential request");
        disconnectMQTT();
        return false;
    }

    SerialMon.println("Requested credentials with IMEI: " + imei);
#ifdef ENABLE_LCD
    if (lcdAvailable)
    {
        lcd.clear();
        lcd.print("Requesting Creds");
    }
#endif
    waitingForProvisionResponse = true;
    provisionTimeout = millis() + 30000; // Increase timeout to 30 seconds
    return true;                         // Stay in STATE_SETUP_MQTT
}

void setup()
{
    esp_task_wdt_reset(); // Reset immediately on boot
    SerialMon.begin(115200);
    delay(1000);
    SerialMon.println("Starting...");

    resetCredentials();
    mqttServiceStarted = false; // Initialize flag

    otaInProgress = false;
    otaReceivedSize = 0;
    otaTotalSize = 0;
    chunkCount = 0;
    receivedChunks.clear();
    missingChunks.clear();

    sim7600.begin(115200, SERIAL_8N1, MODEM_RX, MODEM_TX);
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

    loadCredentials();
    bootTime = millis();

    if (tryStep("Initializing modem", modem.init()))
    {
        SerialMon.println("Modem initialized: " + modem.getModemInfo());
        modem.sendAT("+CGSN");
        if (modem.waitResponse(1000L, imei) != 1)
        {
            SerialMon.println("Failed to retrieve IMEI");
            imei = "Unknown";
        }
        else
        {
            imei.trim();
            SerialMon.println("Retrieved IMEI: " + imei);
        }
        loadCredentials(); // Moved here after IMEI is retrieved
        bootTime = millis();
        nextState(STATE_WAIT_NETWORK);
    }
}

void loop()
{
    esp_task_wdt_reset();
    if (digitalRead(FACTORY_RESET_PIN) == LOW)
    {
        delay(50);
        if (digitalRead(FACTORY_RESET_PIN) == LOW)
        {
            factoryResetTriggered = true;
            performFactoryReset();
        }
    }

    while (SerialAT.available())
    {
        char c = SerialAT.read();
        incomingBuffer += c;
        if (c == '\n')
        {
            processURC(incomingBuffer);
            incomingBuffer = "";
        }
    }

    switch (currentState)
    {
    case STATE_INIT_MODEM:
        if (tryStep("Initializing modem", modem.init()))
        {
            SerialMon.println("Modem initialized: " + modem.getModemInfo());
            modem.sendAT("+CGSN");
            if (modem.waitResponse(1000L, imei) != 1)
            {
                SerialMon.println("Failed to retrieve IMEI");
                imei = "Unknown";
            }
            else
            {
                imei.trim();
                SerialMon.println("Retrieved IMEI: " + imei);
            }
            nextState(STATE_WAIT_NETWORK);
        }
        break;

    case STATE_WAIT_NETWORK:
        if (tryStep("Waiting for network", modem.waitForNetwork()))
        {
            nextState(STATE_CONNECT_GPRS);
        }
        break;

    case STATE_CONNECT_GPRS:
        if (tryStep("Connecting to " + String(apn), modem.gprsConnect(apn, gprsUser, gprsPass)))
        {
            nextState(STATE_UPLOAD_CERTIFICATE);
        }
        break;

    case STATE_UPLOAD_CERTIFICATE:
        if (tryStep("Uploading certificate", uploadCertificate()))
        {
            nextState(STATE_SETUP_SSL);
        }
        break;

    case STATE_SETUP_SSL:
        if (tryStep("Setting up SSL", setupSSL()))
        {
            nextState(STATE_SETUP_MQTT);
        }
        break;

    case STATE_SETUP_MQTT:
      if (!isProvisioned)
        {
            if (!waitingForProvisionResponse)
            {
                if (tryStep("Setting up MQTT", setupMQTT()))
                {
                    if (requestCredentialsFromServer())
                    {
                        SerialMon.println("Waiting for provisioning response...");
                    }
                    else
                    {
                        nextState(STATE_ERROR);
                    }
                }
            }
            else
            {
                SerialMon.println("Still waiting for provisioning response...");
            }
        }
        else
        {
            if (tryStep("Setting up MQTT", setupMQTT()))
            {
                nextState(STATE_CONNECT_MQTT);
            }
        }
        break;      
    case STATE_CONNECT_MQTT:
        SerialMon.println("Before connect - ClientID: " + clientID + ", User: " + mqtt_user + ", Pass: " + mqtt_pass);
        if (tryStep("Connecting to MQTT", connectMQTT()))
        {
            nextState(STATE_SUBSCRIBE_MQTT);
        }
        break;

    case STATE_SUBSCRIBE_MQTT:
        if (tryStep("Subscribing to MQTT", subscribeMQTT()))
        {
            nextState(STATE_RUNNING);
        }
        break;

    case STATE_RUNNING:
        if (millis() - lastMonitorTime >= MONITOR_INTERVAL)
        {
            monitorConnections();
            lastMonitorTime = millis();
        }
        break;

    case STATE_ERROR:
        SerialMon.println("Setup failed, cleaning up...");
        cleanupResources();
#ifdef ENABLE_LCD
        if (lcdAvailable)
        {
            lcd.clear();
            lcd.print("Error - Resetting");
        }
#endif
        delay(2000);
        ESP.restart();
        break;

    case STATE_STOPPED:
        SerialMon.println("Device stopped by server command");
#ifdef ENABLE_LCD
        if (lcdAvailable)
        {
            lcd.clear();
            lcd.print("Device Stopped");
        }
#endif
        while (true)
            delay(1000);
        break;

    case STATE_RECOVER_NETWORK:
        if (tryStep("Recovering network", modem.waitForNetwork()))
        {
            nextState(STATE_RECOVER_GPRS);
        }
        break;

    case STATE_RECOVER_GPRS:
        if (tryStep("Recovering GPRS", modem.gprsConnect(apn, gprsUser, gprsPass)))
        {
            nextState(STATE_RECOVER_MQTT);
        }
        break;

    case STATE_RECOVER_MQTT:
        if (tryStep("Recovering MQTT", connectMQTT() && subscribeMQTT()))
        {
            nextState(STATE_RUNNING);
        }
        break;
    }

    // Check provisioning timeout
    if (waitingForProvisionResponse && millis() >= provisionTimeout)
    {
        SerialMon.println("Timeout waiting for provisioning response");
        waitingForProvisionResponse = false;
        disconnectMQTT();
        stopMQTT();
        nextState(STATE_ERROR);
    }
}

String encryptMessage(const char *message)
{
    if (!message)
        return "";
    size_t input_len = strlen(message);
    if (input_len == 0)
        return "";
    size_t padded_len = ((input_len + 15) / 16) * 16;
    if (padded_len > 1024)
    {
        SerialMon.println("Message too long: " + String(input_len));
        return "";
    }
    unsigned char *padded_input = new unsigned char[padded_len]();
    if (!padded_input)
        return "";
    memcpy(padded_input, message, input_len);
    pkcs7_pad(padded_input, input_len, 16);
    unsigned char *output_buffer = new unsigned char[padded_len]();
    if (!output_buffer)
    {
        delete[] padded_input;
        return "";
    }
    mbedtls_aes_context aes;
    unsigned char iv[16];
    memcpy(iv, aes_iv, 16);
    mbedtls_aes_init(&aes);
    int key_ret = mbedtls_aes_setkey_enc(&aes, aes_key, 256);
    if (key_ret != 0)
    {
        delete[] padded_input;
        delete[] output_buffer;
        return "";
    }
    int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv,
                                    padded_input, output_buffer);
    mbedtls_aes_free(&aes);
    String result;
    if (ret == 0)
    {
        result = base64_encode(output_buffer, padded_len);
    }
    delete[] padded_input;
    delete[] output_buffer;
    return result;
}

String decryptMessage(const char *encryptedBase64)
{
    if (!encryptedBase64 || strlen(encryptedBase64) == 0)
        return "";
    size_t max_input_len = strlen(encryptedBase64);
    if (max_input_len > 1024)
        return "";
    unsigned char *encrypted_bytes = new unsigned char[max_input_len]();
    if (!encrypted_bytes)
        return "";
    size_t decoded_len = base64_decode(encryptedBase64, encrypted_bytes, max_input_len);
    if (decoded_len == 0 || decoded_len % 16 != 0)
    {
        delete[] encrypted_bytes;
        return "";
    }
    unsigned char *output_buffer = new unsigned char[decoded_len]();
    if (!output_buffer)
    {
        delete[] encrypted_bytes;
        return "";
    }
    mbedtls_aes_context aes;
    unsigned char iv[16];
    memcpy(iv, aes_iv, 16);
    mbedtls_aes_init(&aes);
    int key_ret = mbedtls_aes_setkey_dec(&aes, aes_key, 256);
    if (key_ret != 0)
    {
        delete[] encrypted_bytes;
        delete[] output_buffer;
        return "";
    }
    int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, decoded_len, iv,
                                    encrypted_bytes, output_buffer);
    mbedtls_aes_free(&aes);
    String result;
    if (ret == 0)
    {
        size_t unpadded_len = pkcs7_unpad(output_buffer, decoded_len);
        result = String((char *)output_buffer, unpadded_len);
    }
    delete[] encrypted_bytes;
    delete[] output_buffer;
    return result;
}

void handleMessage(String topic, String payload)
{
    SerialMon.println("Received on topic: " + topic + ", Payload: " + payload);

    if (topic == "server_cmd")
    {
        String decrypted = decryptMessage(payload.c_str());
        if (decrypted.length() == 0)
        {
            SerialMon.println("Failed to decrypt message from " + topic);
            return;
        }
        if (decrypted == "RESET_PASSWORD")
        {
            resetCredentials();
            publishMQTT("Password reset requested");
            return;
        }
        publishMQTT(decrypted.c_str());
        String prefixedMessage = imei + decrypted;
        String encryptedPrefixed = encryptMessage(prefixedMessage.c_str());
        if (encryptedPrefixed.length() > 0)
        {
            publishMQTT(encryptedPrefixed.c_str());
        }
        ledStatus = !ledStatus;
        digitalWrite(LED_PIN, ledStatus);
#ifdef ENABLE_LCD
        if (lcdAvailable)
        {
            lcd.clear();
            lcd.print("MQTT Msg:");
            lcd.setCursor(0, 1);
            lcd.print(decrypted.substring(0, 16));
        }
#endif
    }
    else if (topic == PROVISION_RESPONSE_TOPIC && !isProvisioned && waitingForProvisionResponse)
    {
        String decrypted = decryptMessage(payload.c_str());
        if (decrypted.startsWith("PASSWORD:"))
        {
            String newPassword = decrypted.substring(9);
            saveCredentials(newPassword);
            SerialMon.println("Received new password: " + newPassword);

            disconnectMQTT();
            if (!stopMQTT())
            {
                SerialMon.println("Failed to stop MQTT, forcing full reset");
                resetState();
                nextState(STATE_INIT_MODEM);
                return;
            }

            waitingForProvisionResponse = false;
            nextState(STATE_SETUP_MQTT); // Re-run setup with new credentials
        }
        else
        {
            SerialMon.println("Invalid provisioning response");
            waitingForProvisionResponse = false;
            nextState(STATE_ERROR);
        }
    }
    else if (topic == "OTA_Update")
    {
        if (payload == "reverse old firmware" && pendingValidation)
        {
            revertToPreviousFirmware();
        }
        else
        {
            byte *payloadBytes = (byte *)payload.c_str();
            unsigned int payloadLen = payload.length();
            processOTAFirmware(topic, payloadBytes, payloadLen);
        }
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
        SerialMon.println("Max retries reached for " + stepMsg);
        if (currentState >= STATE_CONNECT_MQTT)
        {
            disconnectMQTT();
            stopMQTT();
        }
        resetModem();
        resetState();
    }
    else
    {
        delay(RETRY_DELAY);
    }
}

void resetModem()
{
    SerialMon.println("Resetting modem...");
    digitalWrite(SIM7600_PWR, LOW);
    delay(1500);
    digitalWrite(SIM7600_PWR, HIGH);
    delay(5000);
}

void resetState()
{
    SerialMon.println("Resetting state data...");
    currentState = STATE_INIT_MODEM;
    retryCount = 0;
    if (otaInProgress)
    {
        cleanupResources();
    }
    ledStatus = 0;
    digitalWrite(LED_PIN, ledStatus);
    rgbLed.setPixelColor(0, 0, 0, 0);
    rgbLed.show();
#ifdef ENABLE_LCD
    if (lcdAvailable)
    {
        lcd.clear();
        lcd.print("Resetting...");
    }
#endif
}

void monitorConnections()
{
    if (!modem.isNetworkConnected())
    {
        SerialMon.println("Network lost");
        if (otaInProgress)
        {
            SerialMon.println("OTA interrupted by network loss");
            cleanupResources();
            publishMQTT("OTA:ERROR:Network lost");
        }
        nextState(STATE_RECOVER_NETWORK);
    }
    else if (!modem.isGprsConnected())
    {
        SerialMon.println("GPRS disconnected");
        if (otaInProgress)
        {
            SerialMon.println("OTA interrupted by GPRS loss");
            cleanupResources();
            publishMQTT("OTA:ERROR:GPRS lost");
        }
        nextState(STATE_RECOVER_GPRS);
    }
}

void cleanupResources()
{
    SerialMon.println("Cleaning up resources...");
    modem.gprsDisconnect();
    stopMQTT();
    if (otaInProgress)
    {
        esp_ota_end(otaHandle);
        otaInProgress = false;
        otaReceivedSize = 0;
        otaTotalSize = 0;
        chunkCount = 0;
        receivedChunks.clear();
        missingChunks.clear();
        SerialMon.println("OTA data cleared due to cleanup");
    }
    incomingBuffer = "";
    pendingTopic = "";
    pendingPayload = "";
    waitingForProvisionResponse = false; // Reset provisioning flag
}

void processURC(String urc)
{
    urc.trim();
    SerialMon.println("URC: " + urc); // Debug URCs

    if (urc.startsWith("+CMQTTRXSTART: 0,"))
    {
        messageInProgress = true;
        pendingTopic = "";
        pendingPayload = "";
        int commaIdx = urc.indexOf(',', 14);
        pendingTopicLen = urc.substring(14, commaIdx).toInt();
        pendingPayloadLen = urc.substring(commaIdx + 1).toInt();
    }
    else if (urc.startsWith("+CMQTTRXTOPIC: 0,"))
    {
        // Topic length already set, wait for topic content
    }
    else if (messageInProgress && !urc.startsWith("+") && pendingTopic == "")
    {
        pendingTopic = urc;
        if (waitingForProvisionResponse && pendingTopic == PROVISION_RESPONSE_TOPIC)
        {
            // Waiting for provisioning response, proceed to payload
        }
    }
    else if (urc.startsWith("+CMQTTRXPAYLOAD: 0,"))
    {
        // Payload length already set, wait for payload content
    }
    else if (messageInProgress && !urc.startsWith("+") && pendingTopic != "" && pendingPayload == "")
    {
        pendingPayload = urc;
        if (waitingForProvisionResponse && pendingTopic == PROVISION_RESPONSE_TOPIC)
        {
            SerialMon.println("Received provisioning payload: " + pendingPayload);
            handleMessage(pendingTopic, pendingPayload);
            pendingTopic = "";
            pendingPayload = "";
            messageInProgress = false;
        }
    }
    else if (urc == "+CMQTTRXEND: 0")
    {
        if (messageInProgress && pendingTopic != "" && pendingPayload != "")
        {
            handleMessage(pendingTopic, pendingPayload);
        }
        messageInProgress = false;
        pendingTopic = "";
        pendingPayload = "";
        pendingTopicLen = 0;
        pendingPayloadLen = 0;
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
    if (mqttServiceStarted)
    {
        SerialMon.println("MQTT service already started, skipping AT+CMQTTSTART");
        return true; // Already set up
    }

    modem.sendAT("+CMQTTSTART");
    if (modem.waitResponse(5000L, "+CMQTTSTART: 0") != 1)
    {
        SerialMon.println("MQTT start failed");
        return false;
    }
    mqttServiceStarted = true;

    modem.sendAT("+CMQTTACCQ=0,\"", clientID.c_str(), "\",1");
    if (modem.waitResponse() != 1)
        return false;
    modem.sendAT("+CMQTTSSLCFG=0,0");
    return modem.waitResponse() == 1;
}

bool connectMQTT()
{
    String cmd = "+CMQTTCONNECT=0,\"tcp://";
    cmd += mqtt_server;
    cmd += ":";
    cmd += mqtt_port;
    cmd += "\",60,1,\"";
    cmd += mqtt_user;
    cmd += "\",\"";
    cmd += mqtt_pass;
    cmd += "\"";
    modem.sendAT(cmd);
    if (modem.waitResponse(10000L, "+CMQTTCONNECT: 0,0") != 1)
    {
        SerialMon.println("MQTT connection failed");
        return false;
    }
    SerialMon.println("MQTT connected");
    return true;
}

bool subscribeMQTT()
{
    modem.sendAT("+CMQTTSUBTOPIC=0,", String(strlen(mqtt_topic_recv)).c_str(), ",1");
    if (modem.waitResponse(500L, ">") != 1)
        return false;
    SerialAT.print(mqtt_topic_recv);
    if (modem.waitResponse(500L) != 1)
        return false;
    modem.sendAT("+CMQTTSUB=0");
    if (modem.waitResponse(1000L, "+CMQTTSUB: 0,0") != 1)
        return false;
    SerialMon.println("Subscribed to: " + String(mqtt_topic_recv));

    modem.sendAT("+CMQTTSUBTOPIC=0,", String(strlen(mqtt_topic_firmware)).c_str(), ",1");
    if (modem.waitResponse(500L, ">") != 1)
        return false;
    SerialAT.print(mqtt_topic_firmware);
    if (modem.waitResponse(500L) != 1)
        return false;
    modem.sendAT("+CMQTTSUB=0");
    if (modem.waitResponse(1000L, "+CMQTTSUB: 0,0") != 1)
        return false;
    SerialMon.println("Subscribed to: " + String(mqtt_topic_firmware));

    return true;
}

bool publishMQTT(const char *message)
{
    modem.sendAT("+CMQTTTOPIC=0,", String(strlen(mqtt_topic_send)).c_str());
    if (modem.waitResponse(500L, ">") != 1)
        return false;
    SerialAT.print(mqtt_topic_send);
    if (modem.waitResponse(500L) != 1)
        return false;
    int msgLen = strlen(message);
    modem.sendAT("+CMQTTPAYLOAD=0,", String(msgLen).c_str());
    if (modem.waitResponse(500L, ">") != 1)
        return false;
    SerialAT.print(message);
    if (modem.waitResponse(500L) != 1)
        return false;
    modem.sendAT("+CMQTTPUB=0,1,60");
    return modem.waitResponse(1000L, "+CMQTTPUB: 0,0") == 1;
}

bool disconnectMQTT()
{
    SerialMon.println("Disconnecting MQTT...");
    modem.sendAT("+CMQTTDISC=0,120");
    return modem.waitResponse(10000L, "+CMQTTDISC: 0,0") == 1;
}

bool stopMQTT()
{
    modem.sendAT("+CMQTTSTOP");
    if (modem.waitResponse(10000L, "+CMQTTSTOP: 0") != 1)
    {
        SerialMon.println("MQTT stop returned error, continuing cleanup");
        return false;
    }
    mqttServiceStarted = false; // Reset flag
    SerialMon.println("MQTT service stopped");
    return true;
}

void startOTA(uint32_t totalSize)
{
    previousPartition = esp_ota_get_running_partition();
    updatePartition = esp_ota_get_next_update_partition(NULL);
    if (!updatePartition)
    {
        SerialMon.println("No valid OTA partition available");
        publishMQTT("OTA:ERROR:No partition");
        return;
    }
    esp_err_t err = esp_ota_begin(updatePartition, totalSize, &otaHandle);
    if (err != ESP_OK)
    {
        SerialMon.printf("OTA begin failed: %s\n", esp_err_to_name(err));
        publishMQTT("OTA:ERROR:Begin failed");
        return;
    }
    otaInProgress = true;
    pendingValidation = true;
    otaTotalSize = totalSize;
    otaReceivedSize = 0;
    chunkCount = 0;
    receivedChunks.clear();
    missingChunks.clear();
    SerialMon.println("OTA started from " + String(previousPartition->label) +
                      " to " + String(updatePartition->label));
    publishMQTT("OTA:STARTED");
}

void processOTAFirmware(const String &topic, byte *payload, unsigned int dataLen)
{
    if (topic != mqtt_topic_firmware || pendingValidation)
        return;

    SerialMon.println("Processing OTA message, length=" + String(dataLen));
    String encodedPayload = String((char *)payload);
    size_t maxDecodedLen = (encodedPayload.length() / 4) * 3;
    unsigned char *decodedPayload = new unsigned char[maxDecodedLen];
    if (!decodedPayload)
    {
        SerialMon.println("Memory allocation failed for OTA payload");
        publishMQTT("OTA:ERROR:Memory");
        return;
    }
    size_t decodedLen = base64_decode(encodedPayload.c_str(), decodedPayload, maxDecodedLen);
    if (decodedLen == 0)
    {
        SerialMon.println("Base64 decode failed");
        delete[] decodedPayload;
        return;
    }
    String decodedStr = String((char *)decodedPayload, decodedLen);
    if (decodedStr.startsWith("OTA:BEGIN:"))
    {
        if (otaInProgress)
        {
            cleanupResources();
            otaInProgress = false;
        }
        uint32_t totalSize = decodedStr.substring(10).toInt();
        startOTA(totalSize);
        delete[] decodedPayload;
        return;
    }
    if (decodedStr == "OTA:END")
    {
        if (otaInProgress)
        {
            finishOTA();
        }
        delete[] decodedPayload;
        return;
    }
    if (!otaInProgress)
    {
        SerialMon.println("OTA not started, ignoring message");
        delete[] decodedPayload;
        return;
    }
    if (decodedLen < 4)
    {
        SerialMon.println("Invalid decoded chunk size: " + String(decodedLen));
        cleanupResources();
        otaInProgress = false;
        publishMQTT("OTA:ERROR:Invalid chunk");
        delete[] decodedPayload;
        return;
    }
    unsigned long chunkNum = ((unsigned long)decodedPayload[0] << 24) |
                             ((unsigned long)decodedPayload[1] << 16) |
                             ((unsigned long)decodedPayload[2] << 8) |
                             decodedPayload[3];
    if (receivedChunks[chunkNum])
    {
        String progress = "OTA:PROGRESS:" + String(otaReceivedSize) + "/" + String(otaTotalSize) +
                          ":CHUNK:" + String(chunkNum);
        publishMQTT(progress.c_str());
        delete[] decodedPayload;
        return;
    }
    size_t chunkSize = decodedLen - 4;
    if (chunkSize > OTA_MAX_DATA_SIZE)
    {
        SerialMon.println("Chunk too large: " + String(chunkSize));
        cleanupResources();
        otaInProgress = false;
        publishMQTT("OTA:ERROR:Chunk too large");
        delete[] decodedPayload;
        return;
    }
    esp_err_t err = esp_ota_write(otaHandle, decodedPayload + 4, chunkSize);
    if (err != ESP_OK)
    {
        SerialMon.printf("OTA write failed for chunk %lu: %s\n", chunkNum, esp_err_to_name(err));
        cleanupResources();
        otaInProgress = false;
        publishMQTT("OTA:ERROR:Write failed");
        delete[] decodedPayload;
        return;
    }
    receivedChunks[chunkNum] = true;
    otaReceivedSize += chunkSize;
    chunkCount++;
    String progress = "OTA:PROGRESS:" + String(otaReceivedSize) + "/" + String(otaTotalSize) +
                      ":CHUNK:" + String(chunkNum);
    if (publishMQTT(progress.c_str()) && chunkCount % 10 == 0)
    {
        checkMissingChunks();
    }
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
        SerialMon.println("OTA incomplete: Received " + String(otaReceivedSize) + "/" + String(otaTotalSize));
        cleanupResources();
        publishMQTT("OTA:ERROR:Incomplete");
        return;
    }
    esp_err_t err = esp_ota_end(otaHandle);
    if (err != ESP_OK)
    {
        SerialMon.printf("OTA end failed: %s\n", esp_err_to_name(err));
        cleanupResources();
        publishMQTT("OTA:ERROR:End failed");
        return;
    }
    err = esp_ota_set_boot_partition(updatePartition);
    if (err != ESP_OK)
    {
        SerialMon.printf("OTA set boot partition failed: %s\n", esp_err_to_name(err));
        cleanupResources();
        publishMQTT("OTA:ERROR:Set boot failed");
        return;
    }
    SerialMon.println("OTA update successful, restarting to " + String(updatePartition->label));
    publishMQTT("OTA:SUCCESS:PENDING_VALIDATION");
#ifdef ENABLE_LCD
    if (lcdAvailable)
    {
        lcd.clear();
        lcd.print("OTA Complete");
    }
#endif
    delay(1000);
    otaInProgress = false;
    ESP.restart();
}

void checkMissingChunks()
{
    missingChunks.clear();
    unsigned long expectedChunks = (otaTotalSize + OTA_MAX_DATA_SIZE - 1) / OTA_MAX_DATA_SIZE;
    for (unsigned long i = 0; i < expectedChunks; i++)
    {
        if (!receivedChunks[i])
        {
            missingChunks.push_back(i);
            String req = "OTA:REQUEST:" + String(i);
            publishMQTT(req.c_str());
        }
    }
}

void revertToPreviousFirmware()
{
    if (previousPartition == NULL)
    {
        SerialMon.println("No previous partition known");
        publishMQTT("REVERT:ERROR:No previous partition");
        return;
    }
    const esp_partition_t *current = esp_ota_get_running_partition();
    if (current == previousPartition)
    {
        SerialMon.println("Already running previous firmware");
        publishMQTT("REVERT:ERROR:Already on previous");
        return;
    }
    esp_err_t err = esp_ota_set_boot_partition(previousPartition);
    if (err != ESP_OK)
    {
        SerialMon.printf("Failed to set boot partition: %s\n", esp_err_to_name(err));
        publishMQTT("REVERT:ERROR:Set failed");
        return;
    }
    SerialMon.println("Reverting to previous firmware: " + String(previousPartition->label));
    String revertMsg = String("REVERT:SUCCESS:") + String(previousPartition->label);
    publishMQTT(revertMsg.c_str());
#ifdef ENABLE_LCD
    if (lcdAvailable)
    {
        lcd.clear();
        lcd.print("Reverting...");
    }
#endif
    pendingValidation = false;
    delay(1000);
    ESP.restart();
}

void performFactoryReset()
{
    const esp_partition_t *factoryPartition = esp_partition_find_first(ESP_PARTITION_TYPE_APP,
                                                                       ESP_PARTITION_SUBTYPE_APP_FACTORY,
                                                                       NULL);
    if (factoryPartition == NULL)
    {
        SerialMon.println("Factory partition not found");
        publishMQTT("FACTORY_RESET:ERROR:No factory partition");
        return;
    }

    esp_err_t err = esp_ota_set_boot_partition(factoryPartition);
    if (err != ESP_OK)
    {
        SerialMon.printf("Failed to set factory partition: %s\n", esp_err_to_name(err));
        publishMQTT("FACTORY_RESET:ERROR:Set failed");
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
    publishMQTT("FACTORY_RESET:SUCCESS");
#ifdef ENABLE_LCD
    if (lcdAvailable)
    {
        lcd.clear();
        lcd.print("Factory Reset");
    }
#endif
    delay(1000);
    ESP.restart();
}