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

// Hardware pins (unchanged)
#define RGB_LED_PIN 48
#define NUM_PIXELS 1
#define I2C_SDA 35
#define I2C_SCL 36
#define SIM7600_PWR 21
#define MODEM_TX 16
#define MODEM_RX 17
#define LED_PIN 13

// APN configuration (unchanged)
const char apn[] = "internet";
const char gprsUser[] = "";
const char gprsPass[] = "";

// AES-256 Configuration (from working code)
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

// Serial interfaces (unchanged)
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

// State machine states (unchanged)
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
  STATE_STOPPED
};

// Configuration (unchanged)
const int MAX_RETRIES = 3;
const int RETRY_DELAY = 2000;
const char *cert_name = "iot_inverter2.pem";
const char *mqtt_server = "u008dd8e.ala.dedicated.aws.emqxcloud.com";
const char *mqtt_user = "ESP32";
const char *mqtt_pass = "12345";
const char *mqtt_topic_send = "esp32_status";
const char *mqtt_topic_recv = "server_cmd";
const int mqtt_port = 8883;
const unsigned long MONITOR_INTERVAL = 5000;
const uint32_t WDT_TIMEOUT = 30;

// Global variables (unchanged)
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
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 127, 127, 127, 127, 127
};


// Base64 encode function
String base64_encode(const unsigned char* input, size_t len) {
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

// Utility function to print hex
void printHex(const char* label, const unsigned char* data, size_t len) {
  SerialMon.print(label);
  for (size_t i = 0; i < len; i++) {
    if (data[i] < 0x10) SerialMon.print("0");
    SerialMon.print(data[i], HEX);
    if (i < len - 1) SerialMon.print(" ");
  }
  SerialMon.println();
}

// PKCS7 padding function
void pkcs7_pad(unsigned char* data, size_t data_len, size_t block_size) {
  unsigned char pad_value = block_size - (data_len % block_size);
  for (size_t i = data_len; i < data_len + pad_value; i++) {
    data[i] = pad_value;
  }
}

// PKCS7 unpadding function
size_t pkcs7_unpad(unsigned char* data, size_t data_len) {
  unsigned char pad_value = data[data_len - 1];
  if (pad_value > 16 || pad_value > data_len) return data_len;  // Invalid padding
  return data_len - pad_value;
}

void setup() {
  SerialMon.begin(115200);
  delay(1000);  // Give serial monitor time to connect

  // Minimal encryption test
  SerialMon.println("Minimal encryption test of 'TEST'...");
  unsigned char plaintext[16] = { 'T', 'E', 'S', 'T' };
  pkcs7_pad(plaintext, 4, 16);
  unsigned char test_output[16] = {0};
  unsigned char iv[16];
  memcpy(iv, aes_iv, 16);

  printHex("Padded input: ", plaintext, 16);
  printHex("Key: ", aes_key, 32);
  printHex("IV: ", iv, 16);

  mbedtls_aes_context aes;
  mbedtls_aes_init(&aes);
  int key_ret = mbedtls_aes_setkey_enc(&aes, aes_key, 256);
  if (key_ret != 0) SerialMon.println("Setkey failed: " + String(key_ret));
  int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, 16, iv, plaintext, test_output);
  mbedtls_aes_free(&aes);

  if (ret == 0) {
    printHex("Encrypted: ", test_output, 16);
  } else {
    SerialMon.println("Encryption failed: " + String(ret));
  }

  sim7600.begin(115200, SERIAL_8N1, MODEM_RX, MODEM_TX);

  esp_task_wdt_config_t wdt_config = {
    .timeout_ms = WDT_TIMEOUT * 1000,
    .idle_core_mask = 0,
    .trigger_panic = true
  };
  esp_task_wdt_reconfigure(&wdt_config);
  esp_task_wdt_add(NULL);

  pinMode(LED_PIN, OUTPUT);
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
        // Fetch IMEI for response, but keep static clientID
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
      }
      break;

    case STATE_RUNNING:
      if (millis() - lastMonitorTime >= MONITOR_INTERVAL) {
        monitorConnections();
        lastMonitorTime = millis();
      }
      break;

    case STATE_ERROR:
      SerialMon.println("Setup failed, halting...");
      lcd.clear();
      lcd.print("Setup Failed");
      while (true) delay(1000);
      break;

    case STATE_STOPPED:  // Added from latest
      SerialMon.println("Device stopped by server command");
      lcd.clear();
      lcd.print("Device Stopped");
      while (true) delay(1000);
      break;
  }
}

// AES-256 encryption (output as Base64)
String encryptMessage(const char* message) {
  mbedtls_aes_context aes;
  unsigned char iv[16];
  memcpy(iv, aes_iv, 16);

  size_t input_len = strlen(message);
  size_t padded_len = ((input_len + 15) / 16) * 16;
  if (padded_len > 128) {
    SerialMon.println("Message too long for buffer: " + String(input_len));
    return "";
  }
  unsigned char padded_input[128] = {0};
  memcpy(padded_input, message, input_len);
  pkcs7_pad(padded_input, input_len, 16);

  printHex("Padded input: ", padded_input, padded_len);
  printHex("Key: ", aes_key, 32);
  printHex("IV: ", iv, 16);

  mbedtls_aes_init(&aes);
  int key_ret = mbedtls_aes_setkey_enc(&aes, aes_key, 256);
  if (key_ret != 0) {
    SerialMon.println("Setkey failed with code: " + String(key_ret));
    return "";
  }
  int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, padded_input, encryptedBuffer);
  mbedtls_aes_free(&aes);

  if (ret != 0) {
    SerialMon.println("Encryption failed with code: " + String(ret));
    return "";
  }

  printHex("Encrypted: ", encryptedBuffer, padded_len);
  String base64Output = base64_encode(encryptedBuffer, padded_len);
  SerialMon.println("Base64 encoded: " + base64Output);
  return base64Output;
}

// AES-256 decryption (output as plaintext string)
String decryptMessage(const char* encryptedBase64) {
  unsigned char encryptedBytes[128];
  size_t decoded_len = base64_decode(encryptedBase64, encryptedBytes, 128);
  if (decoded_len == 0 || decoded_len % 16 != 0) {
    SerialMon.println("Base64 decode failed or invalid length: " + String(decoded_len));
    return "";
  }

  printHex("Decoded encrypted bytes: ", encryptedBytes, decoded_len);

  mbedtls_aes_context aes;
  unsigned char iv[16];
  memcpy(iv, aes_iv, 16);

  mbedtls_aes_init(&aes);
  int key_ret = mbedtls_aes_setkey_dec(&aes, aes_key, 256);
  if (key_ret != 0) {
    SerialMon.println("Setkey failed with code: " + String(key_ret));
    return "";
  }
  int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, decoded_len, iv, encryptedBytes, decryptedBuffer);
  mbedtls_aes_free(&aes);

  if (ret != 0) {
    SerialMon.println("Decryption failed with code: " + String(ret));
    return "";
  }

  size_t unpadded_len = pkcs7_unpad(decryptedBuffer, decoded_len);
  printHex("Decrypted with padding: ", decryptedBuffer, decoded_len);
  SerialMon.print("Decrypted text: ");
  SerialMon.write(decryptedBuffer, unpadded_len);
  SerialMon.println();

  return String((char*)decryptedBuffer, unpadded_len);
}

void handleMessage(String topic, String payload) {
  if (topic != "server_cmd") return;

  SerialMon.println("Raw received payload (Base64): " + payload);

  // Decrypt the incoming Base64-encoded message
  String decrypted = decryptMessage(payload.c_str());
  if (decrypted.length() == 0) {
    SerialMon.println("Failed to decrypt message");
    return;
  }

  // Send the decrypted message
  publishMQTT(decrypted.c_str());
  SerialMon.println("Sent decrypted message: " + decrypted);

  // Create and encrypt "ESP32_" + decrypted message
  String prefixedMessage = "ESP32_" + decrypted;
  String encryptedPrefixed = encryptMessage(prefixedMessage.c_str());
  if (encryptedPrefixed.length() > 0) {
    publishMQTT(encryptedPrefixed.c_str());
    SerialMon.println("Sent encrypted 'ESP32_' prefixed message (Base64): " + encryptedPrefixed);
  } else {
    SerialMon.println("Failed to encrypt prefixed message");
  }

  // Toggle LED for visual feedback
  ledStatus = !ledStatus;
  digitalWrite(LED_PIN, ledStatus);

  // Update LCD with decrypted message
  lcd.clear();
  lcd.print("MQTT Msg:");
  lcd.setCursor(0, 1);
  lcd.print(decrypted.substring(0, 16));
}

// Rest of the functions remain unchanged...
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
    SerialMon.println("Max retries reached for " + stepMsg);
    if (currentState >= STATE_CONNECT_MQTT) {
      disconnectMQTT();
      stopMQTT();
    }
    resetModem();
    resetState();
  } else {
    delay(RETRY_DELAY);  // Reverted to working code’s simple delay
  }
}

void resetModem() {
  SerialMon.println("Resetting modem...");
  digitalWrite(SIM7600_PWR, LOW);
  delay(1500);  // Reverted to working code’s timing
  digitalWrite(SIM7600_PWR, HIGH);
  delay(5000);
}

void resetState() {
  SerialMon.println("Resetting state data...");
  currentState = STATE_INIT_MODEM;
  retryCount = 0;
  ledStatus = 0;
  digitalWrite(LED_PIN, ledStatus);
  lcd.clear();
  lcd.print("Connecting...");
  rgbLed.setPixelColor(0, 0, 0, 0);
  rgbLed.show();
}

void monitorConnections() {
  if (!modem.isNetworkConnected()) {
    SerialMon.println("Network disconnected");
    nextState(STATE_WAIT_NETWORK);
  } else if (!modem.isGprsConnected()) {
    SerialMon.println("GPRS disconnected");
    nextState(STATE_CONNECT_GPRS);
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
  } else if (messageInProgress && !urc.startsWith("+") && pendingTopic == "") {
    pendingTopic = urc;
  } else if (urc.startsWith("+CMQTTRXPAYLOAD: 0,")) {
  } else if (messageInProgress && !urc.startsWith("+") && pendingTopic != "" && pendingPayload == "") {
    pendingPayload = urc;
  } else if (urc == "+CMQTTRXEND: 0") {
    if (messageInProgress && pendingTopic != "" && pendingPayload != "") {
      handleMessage(pendingTopic, pendingPayload);
    }
    messageInProgress = false;
    pendingTopic = "";
    pendingPayload = "";
    pendingTopicLen = 0;
    pendingPayloadLen = 0;
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
  // Reverted to working code’s simplicity
  modem.sendAT("+CMQTTSTART");
  if (modem.waitResponse(5000L, "+CMQTTSTART: 0") != 1) return false;

  modem.sendAT("+CMQTTACCQ=0,\"", clientID.c_str(), "\",1");
  if (modem.waitResponse() != 1) return false;

  modem.sendAT("+CMQTTSSLCFG=0,0");
  return modem.waitResponse() == 1;
}

bool connectMQTT() {
  // Reverted to working code’s simplicity
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
    SerialMon.println("Failed to get '>' for SUBTOPIC");
    return false;
  }
  SerialAT.print(mqtt_topic_recv);
  if (modem.waitResponse(500L) != 1) {
    SerialMon.println("SUBTOPIC send failed");
    return false;
  }

  modem.sendAT("+CMQTTSUB=0");
  if (modem.waitResponse(1000L, "+CMQTTSUB: 0,0") != 1) {
    SerialMon.println("SUBSCRIBE failed");
    return false;
  }
  SerialMon.println("Subscribed to: " + String(mqtt_topic_recv));
  return true;
}

bool publishMQTT(const char* message) {
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