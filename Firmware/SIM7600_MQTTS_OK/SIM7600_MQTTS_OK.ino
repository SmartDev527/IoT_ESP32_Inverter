#define TINY_GSM_MODEM_SIM7600
#define DUMP_AT_COMMANDS

#include <Wire.h>
#include <TinyGsmClient.h>
#include <HardwareSerial.h>
#include <Adafruit_NeoPixel.h>
#include <LCD_I2C.h>
#include <esp_task_wdt.h>
#include "certificates.h"

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
  STATE_STOPPED
};

// Configuration
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
const uint32_t WDT_TIMEOUT = 10;

// Global variables
SetupState currentState = STATE_INIT_MODEM;
int retryCount = 0;
uint8_t ledStatus = 0;
Adafruit_NeoPixel rgbLed(NUM_PIXELS, RGB_LED_PIN, NEO_GRB + NEO_KHZ800);
LCD_I2C lcd(0x27, 16, 2);
String clientID = "";  // Will be set with IMEI + "_" + truncated timestamp
String imei = "";      // Store IMEI globally for use in responses
String incomingBuffer = "";
unsigned long lastMonitorTime = 0;
String pendingTopic = "";
String pendingPayload = "";
bool messageInProgress = false;
int pendingTopicLen = 0;
int pendingPayloadLen = 0;

void setup() {
  SerialMon.begin(115200);
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
  unsigned long start = millis();
  while (millis() - start < 1500) {
    esp_task_wdt_reset();
    delay(100);
  }
  digitalWrite(SIM7600_PWR, HIGH);
  start = millis();
  while (millis() - start < 5000) {
    esp_task_wdt_reset();
    delay(100);
  }

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
        if (setClientIDWithIMEI()) {
          nextState(STATE_WAIT_NETWORK);
        } else {
          nextState(STATE_ERROR);
        }
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

    case STATE_STOPPED:
      SerialMon.println("Device stopped by server command");
      lcd.clear();
      lcd.print("Device Stopped");
      while (true) delay(1000);
      break;
  }
}

bool setClientIDWithIMEI() {
  modem.sendAT("+CGSN");
  if (modem.waitResponse(1000L, imei) != 1) {
    SerialMon.println("Failed to retrieve IMEI");
    return false;
  }
  imei.trim();
  SerialMon.println("Retrieved IMEI: " + imei);
  String timestamp = String(millis());
  if (timestamp.length() > 5) {
    timestamp = timestamp.substring(0, 5);  // Truncate to 5 digits
  }
  clientID = imei + "_" + timestamp;  // Client ID = IMEI + "_" + truncated timestamp
  SerialMon.println("Client ID set to: " + clientID);
  return true;
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
    SerialMon.println("Max retries reached for " + stepMsg);
    if (currentState >= STATE_CONNECT_MQTT) {
      disconnectMQTT();
      stopMQTT();
    }
    resetModem();
    resetState();
  } else {
    unsigned long start = millis();
    while (millis() - start < RETRY_DELAY) {
      esp_task_wdt_reset();
      delay(100);
    }
  }
}

void resetModem() {
  SerialMon.println("Resetting modem...");
  digitalWrite(SIM7600_PWR, LOW);
  unsigned long start = millis();
  while (millis() - start < 1500) {
    esp_task_wdt_reset();
    delay(100);
  }
  digitalWrite(SIM7600_PWR, HIGH);
  start = millis();
  while (millis() - start < 5000) {
    esp_task_wdt_reset();
    delay(100);
  }
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

void handleMessage(String topic, String payload) {
  if (topic != "server_cmd") return;

  if (payload == "STOP_DEVICE") {
    SerialMon.println("Received stop command from server");
    nextState(STATE_STOPPED);
    return;
  }

  ledStatus = !ledStatus;
  digitalWrite(LED_PIN, ledStatus);

  String reply = imei + ": " + payload;  // Replace "I got your message" with IMEI
  if (publishMQTT(reply.c_str())) {
    if (payload.length() >= 3) {
      rgbLed.setPixelColor(0, rgbLed.Color(payload[0], payload[1], payload[2]));
      rgbLed.show();
    }
    lcd.clear();
    lcd.print("MQTT Msg:");
    lcd.setCursor(0, 1);
    lcd.print(payload.substring(0, 16));
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
  bool result = modem.waitResponse(5000L) == 1;
  esp_task_wdt_reset();
  return result;
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
  esp_task_wdt_reset();

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
  bool result = modem.waitResponse(10000L, "+CMQTTCONNECT: 0,0") == 1;
  esp_task_wdt_reset();
  return result;
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
  bool result = modem.waitResponse(10000L, "+CMQTTDISC: 0,0") == 1;
  esp_task_wdt_reset();
  return result;
}

bool stopMQTT() {
  SerialMon.println("Stopping MQTT service...");
  modem.sendAT("+CMQTTSTOP");
  bool result = modem.waitResponse(10000L, "+CMQTTSTOP: 0") == 1;
  esp_task_wdt_reset();
  return result;
}