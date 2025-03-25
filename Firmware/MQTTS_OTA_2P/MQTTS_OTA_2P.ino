#define TINY_GSM_MODEM_SIM7600
#define DUMP_AT_COMMANDS

#include <Wire.h>
#include <TinyGsmClient.h>
#include <HardwareSerial.h>
#include <Adafruit_NeoPixel.h>
#include <LCD_I2C.h>
#include <esp_task_wdt.h>
#include "mbedtls/aes.h"
#include "certificates.h"
#include <esp_ota_ops.h> // Replaced Update.h with esp_ota_ops.h for OTA partition management
#include <map>
#include <vector>

// Hardware pins
#define RGB_LED_PIN 48

#define NUM_PIXELS 1
#define I2C_SDA 35
#define I2C_SCL 36
#define SIM7600_PWR 21
#define MODEM_TX 16
#define MODEM_RX 17
#define LED_PIN 13

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
  STATE_ERROR,
  STATE_STOPPED,
  STATE_RECOVER_NETWORK,
  STATE_RECOVER_GPRS,
  STATE_RECOVER_MQTT
};

// Configuration
const int MAX_RETRIES = 3;
const int RETRY_DELAY = 2000;
const size_t OTA_CHUNK_SIZE = 512;              // Base chunk size
const size_t OTA_MAX_DATA_SIZE = OTA_CHUNK_SIZE - 4;  // Chunk size minus 4 bytes for chunk number

const char *cert_name = "iot_inverter2.pem";
const char *mqtt_server = "u008dd8e.ala.dedicated.aws.emqxcloud.com";
const char *mqtt_user = "ESP32";
const char *mqtt_pass = "12345";
const char *mqtt_topic_send = "esp32_status";
const char *mqtt_topic_recv = "server_cmd";
const char *mqtt_topic_firmware = "firmware/update";
const int mqtt_port = 8883;
const unsigned long MONITOR_INTERVAL = 5000;
const uint32_t WDT_TIMEOUT = 30;
const size_t CHUNK_SIZE = 508; // Configurable chunk size (e.g., 1024 bytes)

// Global variables
SetupState currentState = STATE_INIT_MODEM;
int retryCount = 0;
uint8_t ledStatus = 0;
Adafruit_NeoPixel rgbLed(NUM_PIXELS, RGB_LED_PIN, NEO_GRB + NEO_KHZ800);
LCD_I2C lcd(0x27, 16, 2);
String clientID = "ESP32_SIM7600_" + String(millis());
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

// OTA variables
bool otaInProgress = false;
unsigned long otaReceivedSize = 0;
unsigned long otaTotalSize = 0;
unsigned long chunkCount = 0;
std::vector<unsigned long> missingChunks;
std::map<unsigned long, bool> receivedChunks;
esp_ota_handle_t otaHandle = 0; // Handle for OTA operations
const esp_partition_t* updatePartition = NULL; // Target OTA partition

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

// Check running partition
void check_firmware_partition() {
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running->subtype == ESP_PARTITION_SUBTYPE_APP_FACTORY) {
        SerialMon.println("Running from factory partition");
        lcd.clear();
        lcd.print("Factory Mode");
    } else if (running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0 || 
               running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1) {
        SerialMon.printf("Running from OTA partition %d\n", running->subtype - ESP_PARTITION_SUBTYPE_APP_OTA_0);
        lcd.clear();
        lcd.print("OTA Mode");
    }
}

void setup() {
  SerialMon.begin(115200);
  delay(1000);
  SerialMon.println("Starting...");

  // Clear OTA state on startup
  otaInProgress = false;
  otaReceivedSize = 0;
  otaTotalSize = 0;
  chunkCount = 0;
  receivedChunks.clear();
  missingChunks.clear();

  sim7600.begin(115200, SERIAL_8N1, MODEM_RX, MODEM_TX);

  esp_task_wdt_config_t wdt_config = {
      .timeout_ms = 30000,
      .idle_core_mask = 0,
      .trigger_panic = true};
  esp_task_wdt_reconfigure(&wdt_config);
  esp_task_wdt_add(NULL);

  check_firmware_partition();
  
  delay(1000);

  pinMode(SIM7600_PWR, OUTPUT);
  digitalWrite(SIM7600_PWR, LOW);
  delay(1500);
  digitalWrite(SIM7600_PWR, HIGH);
  delay(5000);

  Wire.begin(I2C_SDA, I2C_SCL);
  lcd.begin();
  lcd.backlight();
  lcd.print("Connecting...");
  rgbLed.begin();
  rgbLed.show();
}

void loop() {
  esp_task_wdt_reset();

  while (SerialAT.available()) {
    char c = SerialAT.read();
    incomingBuffer += c;
    if (c == '\n') {
      processURC(incomingBuffer);
      incomingBuffer = "";
    }
  }

  switch (currentState) {
    case STATE_INIT_MODEM:
      if (tryStep("Initializing modem", modem.init())) {
        SerialMon.println("Modem initialized: " + modem.getModemInfo());
        modem.sendAT("+CGSN");
        if (modem.waitResponse(1000L, imei) != 1) {
          SerialMon.println("Failed to retrieve IMEI, proceeding anyway");
          imei = "Unknown";
        } else {
          imei.trim();
          SerialMon.println("Retrieved IMEI: " + imei);
        }
        nextState(STATE_WAIT_NETWORK);
      }
      break;

    case STATE_WAIT_NETWORK:
      if (tryStep("Waiting for network", modem.waitForNetwork())) {
        nextState(STATE_CONNECT_GPRS);
      }
      break;

    case STATE_CONNECT_GPRS:
      if (tryStep("Connecting to " + String(apn), modem.gprsConnect(apn, gprsUser, gprsPass))) {
        nextState(STATE_UPLOAD_CERTIFICATE);
      }
      break;

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
        nextState(STATE_CONNECT_MQTT);
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
        esp_ota_mark_app_valid_cancel_rollback(); // Mark firmware valid after successful MQTT setup
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
      lcd.clear();
      lcd.print("Error - Resetting");
      delay(2000);
      ESP.restart();
      break;

    case STATE_STOPPED:
      SerialMon.println("Device stopped by server command");
      lcd.clear();
      lcd.print("Device Stopped");
      while (true) delay(1000);
      break;

    case STATE_RECOVER_NETWORK:
      if (tryStep("Recovering network", modem.waitForNetwork())) {
        nextState(STATE_RECOVER_GPRS);
      }
      break;

    case STATE_RECOVER_GPRS:
      if (tryStep("Recovering GPRS", modem.gprsConnect(apn, gprsUser, gprsPass))) {
        nextState(STATE_RECOVER_MQTT);
      }
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
  if (!padded_input) {
    SerialMon.println("Memory allocation failed");
    return "";
  }

  memcpy(padded_input, message, input_len);
  pkcs7_pad(padded_input, input_len, 16);

  unsigned char *output_buffer = new unsigned char[padded_len]();
  if (!output_buffer) {
    delete[] padded_input;
    SerialMon.println("Memory allocation failed");
    return "";
  }

  mbedtls_aes_context aes;
  unsigned char iv[16];
  memcpy(iv, aes_iv, 16);

  mbedtls_aes_init(&aes);
  int key_ret = mbedtls_aes_setkey_enc(&aes, aes_key, 256);
  if (key_ret != 0) {
    SerialMon.println("Setkey failed: " + String(key_ret));
    delete[] padded_input;
    delete[] output_buffer;
    return "";
  }

  int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv,
                                  padded_input, output_buffer);
  mbedtls_aes_free(&aes);

  String result;
  if (ret == 0) {
    result = base64_encode(output_buffer, padded_len);
  } else {
    SerialMon.println("Encryption failed: " + String(ret));
  }

  delete[] padded_input;
  delete[] output_buffer;
  return result;
}

String decryptMessage(const char *encryptedBase64) {
  if (!encryptedBase64 || strlen(encryptedBase64) == 0) return "";
  size_t max_input_len = strlen(encryptedBase64);
  if (max_input_len > 1024) {
    SerialMon.println("Input too long: " + String(max_input_len));
    return "";
  }

  unsigned char *encrypted_bytes = new unsigned char[max_input_len]();
  if (!encrypted_bytes) {
    SerialMon.println("Memory allocation failed");
    return "";
  }

  size_t decoded_len = base64_decode(encryptedBase64, encrypted_bytes, max_input_len);
  if (decoded_len == 0 || decoded_len % 16 != 0) {
    SerialMon.println("Invalid decode length: " + String(decoded_len));
    delete[] encrypted_bytes;
    return "";
  }

  unsigned char *output_buffer = new unsigned char[decoded_len]();
  if (!output_buffer) {
    delete[] encrypted_bytes;
    SerialMon.println("Memory allocation failed");
    return "";
  }

  mbedtls_aes_context aes;
  unsigned char iv[16];
  memcpy(iv, aes_iv, 16);

  mbedtls_aes_init(&aes);
  int key_ret = mbedtls_aes_setkey_dec(&aes, aes_key, 256);
  if (key_ret != 0) {
    SerialMon.println("Setkey failed: " + String(key_ret));
    delete[] encrypted_bytes;
    delete[] output_buffer;
    return "";
  }

  int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, decoded_len, iv,
                                  encrypted_bytes, output_buffer);
  mbedtls_aes_free(&aes);

  String result;
  if (ret == 0) {
    size_t unpadded_len = pkcs7_unpad(output_buffer, decoded_len);
    result = String((char *)output_buffer, unpadded_len);
  } else {
    SerialMon.println("Decryption failed: " + String(ret));
  }

  delete[] encrypted_bytes;
  delete[] output_buffer;
  return result;
}

void handleMessage(String topic, String payload) {
  SerialMon.println("Received on topic: " + topic + ", Raw payload len: " + String(payload.length()));

  if (topic == "server_cmd") {
    String decrypted = decryptMessage(payload.c_str());
    if (decrypted.length() == 0) {
      SerialMon.println("Failed to decrypt message from " + topic);
      return;
    }
    publishMQTT(decrypted.c_str());
    SerialMon.println("Sent decrypted message: " + decrypted);

    String prefixedMessage = imei + decrypted;
    String encryptedPrefixed = encryptMessage(prefixedMessage.c_str());
    if (encryptedPrefixed.length() > 0) {
      publishMQTT(encryptedPrefixed.c_str());
      SerialMon.println("Sent encrypted 'IMEI' prefixed message (Base64): " + encryptedPrefixed);
    } else {
      SerialMon.println("Failed to encrypt prefixed message");
    }

    ledStatus = !ledStatus;
    digitalWrite(LED_PIN, ledStatus);

    lcd.clear();
    lcd.print("MQTT Msg:");
    lcd.setCursor(0, 1);
    lcd.print(decrypted.substring(0, 16));
  } else if (topic == "firmware/update") {
    byte *payloadBytes = (byte *)payload.c_str();
    unsigned int payloadLen = payload.length();
    processOTAFirmware(topic, payloadBytes, payloadLen);
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

  lcd.clear();
  lcd.print("Resetting...");
}

void monitorConnections() {
  if (!modem.isNetworkConnected()) {
    SerialMon.println("Network lost");
    if (otaInProgress) {
      SerialMon.println("OTA interrupted by network loss");
      cleanupResources();
      publishMQTT("OTA:ERROR:Network lost");
    }
    nextState(STATE_RECOVER_NETWORK);
  } else if (!modem.isGprsConnected()) {
    SerialMon.println("GPRS disconnected");
    if (otaInProgress) {
      SerialMon.println("OTA interrupted by GPRS loss");
      cleanupResources();
      publishMQTT("OTA:ERROR:GPRS lost");
    }
    nextState(STATE_RECOVER_GPRS);
  }
}

void cleanupResources() {
  SerialMon.println("Cleaning up resources...");
  modem.gprsDisconnect();
  stopMQTT();

  incomingBuffer = "";
  pendingTopic = "";
  pendingPayload = "";

  if (otaInProgress) {
    esp_ota_end(otaHandle); // Clean up OTA handle
    otaInProgress = false;
    otaReceivedSize = 0;
    otaTotalSize = 0;
    chunkCount = 0;
    receivedChunks.clear();
    missingChunks.clear();
    SerialMon.println("OTA data cleared due to cleanup");
  }
}

void processURC(String urc) {
  urc.trim();
  if (urc.startsWith("+CMQTTRXSTART: 0,")) {
    messageInProgress = true;
    pendingTopic = "";
    pendingPayload = "";
    int commaIdx = urc.indexOf(',', 14);
    pendingTopicLen = urc.substring(14, commaIdx).toInt();
    pendingPayloadLen = urc.substring(commaIdx + 1).toInt();
  } else if (urc.startsWith("+CMQTTRXTOPIC: 0,")) {
    // Topic length already set
  } else if (messageInProgress && !urc.startsWith("+") && pendingTopic == "") {
    pendingTopic = urc;
  } else if (urc.startsWith("+CMQTTRXPAYLOAD: 0,")) {
    // Payload length already set
  } else if (messageInProgress && !urc.startsWith("+") && pendingTopic != "" && pendingPayload == "") {
    pendingPayload = urc;
  } else if (urc == "+CMQTTRXEND: 0") {
    if (messageInProgress && pendingTopic != "" && pendingPayload != "") {
      byte *payloadBytes = (byte *)pendingPayload.c_str();
      handleMessage(pendingTopic, pendingPayload);
    }
    messageInProgress = false;
    pendingTopic = "";
    pendingPayload = "";
    pendingTopicLen = 0;
    pendingPayloadLen = 0;
  } else if (urc == "GPRS disconnected" && otaInProgress) {
    SerialMon.println("GPRS disconnect detected during OTA");
    cleanupResources();
    nextState(STATE_RECOVER_GPRS);
  }
}

bool uploadCertificate() {
  modem.sendAT("+CCERTLIST");
  String response;
  if (modem.waitResponse(2000L, response) != 1) return false;

  if (response.indexOf(String("+CCERTLIST: \"") + cert_name + "\"") >= 0) {
    SerialMon.println("Certificate '" + String(cert_name) + "' exists");
    return true;
  }

  modem.sendAT("+CCERTDOWN=\"", cert_name, "\",", strlen(root_ca));
  if (modem.waitResponse(2000L, ">") != 1) return false;

  SerialAT.write(root_ca, strlen(root_ca));
  return modem.waitResponse(5000L) == 1;
}

bool setupSSL() {
  modem.sendAT("+CSSLCFG=\"sslversion\",0,4");
  if (modem.waitResponse() != 1) return false;

  modem.sendAT("+CSSLCFG=\"cacert\",0,\"", cert_name, "\"");
  if (modem.waitResponse() != 1) return false;

  modem.sendAT("+CSSLCFG=\"authmode\",0,1");
  return modem.waitResponse() == 1;
}

bool setupMQTT() {
  modem.sendAT("+CMQTTSTART");
  if (modem.waitResponse(5000L, "+CMQTTSTART: 0") != 1) return false;

  modem.sendAT("+CMQTTACCQ=0,\"", clientID.c_str(), "\",1");
  if (modem.waitResponse() != 1) return false;

  modem.sendAT("+CMQTTSSLCFG=0,0");
  return modem.waitResponse() == 1;
}

bool connectMQTT() {
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
  return modem.waitResponse(10000L, "+CMQTTCONNECT: 0,0") == 1;
}

bool subscribeMQTT() {
  modem.sendAT("+CMQTTSUBTOPIC=0,", String(strlen(mqtt_topic_recv)).c_str(), ",1");
  if (modem.waitResponse(500L, ">") != 1) {
    SerialMon.println("Failed to get '>' for SUBTOPIC (server_cmd)");
    return false;
  }
  SerialAT.print(mqtt_topic_recv);
  if (modem.waitResponse(500L) != 1) {
    SerialMon.println("SUBTOPIC send failed (server_cmd)");
    return false;
  }

  modem.sendAT("+CMQTTSUB=0");
  if (modem.waitResponse(1000L, "+CMQTTSUB: 0,0") != 1) {
    SerialMon.println("SUBSCRIBE failed (server_cmd)");
    return false;
  }
  SerialMon.println("Subscribed to: " + String(mqtt_topic_recv));

  modem.sendAT("+CMQTTSUBTOPIC=0,", String(strlen(mqtt_topic_firmware)).c_str(), ",1");
  if (modem.waitResponse(500L, ">") != 1) {
    SerialMon.println("Failed to get '>' for SUBTOPIC (firmware/update)");
    return false;
  }
  SerialAT.print(mqtt_topic_firmware);
  if (modem.waitResponse(500L) != 1) {
    SerialMon.println("SUBTOPIC send failed (firmware/update)");
    return false;
  }

  modem.sendAT("+CMQTTSUB=0");
  if (modem.waitResponse(1000L, "+CMQTTSUB: 0,0") != 1) {
    SerialMon.println("SUBSCRIBE failed (firmware/update)");
    return false;
  }
  SerialMon.println("Subscribed to: " + String(mqtt_topic_firmware));

  return true;
}

bool publishMQTT(const char *message) {
  modem.sendAT("+CMQTTTOPIC=0,", String(strlen(mqtt_topic_send)).c_str());
  if (modem.waitResponse(500L, ">") != 1) {
    SerialMon.println("publishMQTT: Failed to get '>' for topic");
    return false;
  }
  SerialAT.print(mqtt_topic_send);
  if (modem.waitResponse(500L) != 1) {
    SerialMon.println("publishMQTT: Topic send failed");
    return false;
  }

  int msgLen = strlen(message);
  modem.sendAT("+CMQTTPAYLOAD=0,", String(msgLen).c_str());
  if (modem.waitResponse(500L, ">") != 1) {
    SerialMon.println("publishMQTT: Failed to get '>' for payload");
    return false;
  }
  SerialAT.print(message);
  if (modem.waitResponse(500L) != 1) {
    SerialMon.println("publishMQTT: Payload send failed");
    return false;
  }

  modem.sendAT("+CMQTTPUB=0,1,60");
  if (modem.waitResponse(1000L, "+CMQTTPUB: 0,0") == 1) {
    return true;
  } else {
    SerialMon.println("publishMQTT: Publish failed");
    return false;
  }
}

bool disconnectMQTT() {
  SerialMon.println("Disconnecting MQTT...");
  modem.sendAT("+CMQTTDISC=0,120");
  return modem.waitResponse(10000L, "+CMQTTDISC: 0,0") == 1;
}

bool stopMQTT() {
  SerialMon.println("Stopping MQTT service...");
  modem.sendAT("+CMQTTSTOP");
  return modem.waitResponse(10000L, "+CMQTTSTOP: 0") == 1;
}

void startOTA(uint32_t totalSize) {
  if (otaInProgress) {
    SerialMon.println("OTA already in progress");
    return;
  }

  updatePartition = esp_ota_get_next_update_partition(NULL); // Select next OTA slot (ota_0 or ota_1)
  if (!updatePartition) {
    SerialMon.println("No valid OTA partition available");
    publishMQTT("OTA:ERROR:No partition");
    return;
  }

  esp_err_t err = esp_ota_begin(updatePartition, totalSize, &otaHandle);
  if (err != ESP_OK) {
    SerialMon.printf("OTA begin failed: %s\n", esp_err_to_name(err));
    publishMQTT("OTA:ERROR:Begin failed");
    return;
  }

  otaInProgress = true;
  otaTotalSize = totalSize;
  otaReceivedSize = 0;
  chunkCount = 0;
  receivedChunks.clear();
  missingChunks.clear();

  SerialMon.println("OTA started: Total size=" + String(totalSize) + ", Chunk size=" + String(CHUNK_SIZE));
  publishMQTT("OTA:STARTED");
}

void processOTAFirmware(const String& topic, byte* payload, unsigned int dataLen) {
  if (topic != mqtt_topic_firmware) return;

  SerialMon.println("Processing OTA message, length=" + String(dataLen));
  String encodedPayload = String((char*)payload);

  size_t maxDecodedLen = (encodedPayload.length() / 4) * 3;
  unsigned char* decodedPayload = new unsigned char[maxDecodedLen];
  if (!decodedPayload) {
    SerialMon.println("Memory allocation failed for OTA payload");
    publishMQTT("OTA:ERROR:Memory");
    return;
  }

  size_t decodedLen = base64_decode(encodedPayload.c_str(), decodedPayload, maxDecodedLen);
  if (decodedLen == 0) {
    SerialMon.println("Base64 decode failed");
    delete[] decodedPayload;
    return;
  }

  String decodedStr = String((char*)decodedPayload, decodedLen);
  if (decodedStr.startsWith("OTA:BEGIN:")) {
    if (otaInProgress) {
      cleanupResources();
      otaInProgress = false;
    }
    uint32_t totalSize = decodedStr.substring(10).toInt();
    startOTA(totalSize);
    delete[] decodedPayload;
    return;
  }

  if (decodedStr == "OTA:END") {
    if (otaInProgress) {
      finishOTA();
    }
    delete[] decodedPayload;
    return;
  }

  if (!otaInProgress) {
    SerialMon.println("OTA not started, ignoring message");
    delete[] decodedPayload;
    return;
  }

  if (decodedLen < 4) {
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

  if (receivedChunks[chunkNum]) {
    String progress = "OTA:PROGRESS:" + String(otaReceivedSize) + "/" + String(otaTotalSize) + 
                     ":CHUNK:" + String(chunkNum);
    publishMQTT(progress.c_str());
    delete[] decodedPayload;
    return;
  }

  size_t chunkSize = decodedLen - 4; // Subtract 4 bytes for chunk number
  if (chunkSize > OTA_MAX_DATA_SIZE) {
    SerialMon.println("Chunk too large: " + String(chunkSize) + " exceeds " + String(CHUNK_SIZE));
    cleanupResources();
    otaInProgress = false;
    publishMQTT("OTA:ERROR:Chunk too large");
    delete[] decodedPayload;
    return;
  }

  esp_err_t err = esp_ota_write(otaHandle, decodedPayload + 4, chunkSize);
  if (err != ESP_OK) {
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
  if (publishMQTT(progress.c_str())) {
    if (chunkCount % 10 == 0) {
      checkMissingChunks();
    }
  } else {
    SerialMon.println("Failed to report OTA progress, retrying...");
  }

  delete[] decodedPayload;
}

void finishOTA() {
  if (!otaInProgress) {
    SerialMon.println("No OTA in progress to finish");
    return;
  }

  if (otaReceivedSize != otaTotalSize) {
    SerialMon.println("OTA incomplete: Received " + String(otaReceivedSize) + "/" + String(otaTotalSize));
    cleanupResources();
    publishMQTT("OTA:ERROR:Incomplete");
    return;
  }

  esp_err_t err = esp_ota_end(otaHandle);
  if (err != ESP_OK) {
    SerialMon.printf("OTA end failed: %s\n", esp_err_to_name(err));
    cleanupResources();
    publishMQTT("OTA:ERROR:End failed");
    return;
  }

  err = esp_ota_set_boot_partition(updatePartition);
  if (err != ESP_OK) {
    SerialMon.printf("OTA set boot partition failed: %s\n", esp_err_to_name(err));
    cleanupResources();
    publishMQTT("OTA:ERROR:Set boot failed");
    return;
  }

  SerialMon.println("OTA update successful, restarting...");
  publishMQTT("OTA:SUCCESS");
  lcd.clear();
  lcd.print("OTA Complete");
  delay(1000);

  otaInProgress = false;
  otaReceivedSize = 0;
  otaTotalSize = 0;
  chunkCount = 0;
  receivedChunks.clear();
  missingChunks.clear();

  ESP.restart();
}

void checkMissingChunks() {
  missingChunks.clear();
  unsigned long expectedChunks = (otaTotalSize + OTA_MAX_DATA_SIZE - 1) / OTA_MAX_DATA_SIZE; // Ceiling division
  for (unsigned long i = 0; i < expectedChunks; i++) {
    if (!receivedChunks[i]) {
      missingChunks.push_back(i);
      String req = "OTA:REQUEST:" + String(i);
      publishMQTT(req.c_str());
    }
  }
}