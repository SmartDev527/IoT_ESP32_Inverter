#define TINY_GSM_MODEM_SIM7600
#define DUMP_AT_COMMANDS

#include <Wire.h>
#include <TinyGsmClient.h>
#include <HardwareSerial.h>
#include <Adafruit_NeoPixel.h>
#include <LCD_I2C.h>
#include <esp_task_wdt.h>  // Include ESP32 Watchdog Timer library
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
  STATE_ERROR
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
const uint32_t WDT_TIMEOUT = 10;  // Watchdog timeout in seconds

// Global variables
SetupState currentState = STATE_INIT_MODEM;
int retryCount = 0;
uint8_t ledStatus = 0;
Adafruit_NeoPixel rgbLed(NUM_PIXELS, RGB_LED_PIN, NEO_GRB + NEO_KHZ800);
LCD_I2C lcd(0x27, 16, 2);
String clientID = "ESP32_SIM7600_" + String(millis());
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
  
  // Configure existing WDT instead of re-initializing
  esp_task_wdt_config_t wdt_config = {
    .timeout_ms = WDT_TIMEOUT * 1000,  // Convert to milliseconds
    .idle_core_mask = 0,               // Watch all cores
    .trigger_panic = true              // Reset on timeout
  };
  esp_task_wdt_reconfigure(&wdt_config);  // Reconfigure existing WDT
  esp_task_wdt_add(NULL);                 // Add main task to WDT

  pinMode(LED_PIN, OUTPUT);
  pinMode(SIM7600_PWR, OUTPUT);
  digitalWrite(SIM7600_PWR, LOW);
  
  // Replace delay with WDT-friendly wait
  unsigned long start = millis();
  while (millis() - start < 1500) {
    esp_task_wdt_reset();
    delay(100);  // Short delay with periodic reset
  }
  
  digitalWrite(SIM7600_PWR, HIGH);
  start = millis();
  while (millis() - start < 5000) {
    esp_task_wdt_reset();
    delay(100);  // Short delay with periodic reset
  }

  Wire.begin(I2C_SDA, I2C_SCL);
  lcd.begin();
  lcd.backlight();
  lcd.print("Connecting...");

  rgbLed.begin();
  rgbLed.show();
}

void loop() {
  // Feed the Watchdog Timer
  esp_task_wdt_reset();

  // Process incoming data
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
      while (true) delay(1000);  // WDT will reset here
      break;
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
      delay(100);  // Short delay with periodic reset
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
  // SerialMon.println("URC: " + urc);

  if (urc.startsWith("+CMQTTRXSTART: 0,")) {
    messageInProgress = true;
    pendingTopic = "";
    pendingPayload = "";
    int commaIdx = urc.indexOf(',', 14);
    pendingTopicLen = urc.substring(14, commaIdx).toInt();
    pendingPayloadLen = urc.substring(commaIdx + 1).toInt();
    // SerialMon.println("RXSTART: Topic Len=" + String(pendingTopicLen) + ", Payload Len=" + String(pendingPayloadLen));
  } else if (urc.startsWith("+CMQTTRXTOPIC: 0,")) {
    // int expectedLen = urc.substring(13).toInt();
    // SerialMon.println("RXTOPIC: Expected Topic Len=" + String(expectedLen));
  } else if (messageInProgress && !urc.startsWith("+") && pendingTopic == "") {
    pendingTopic = urc;
    // SerialMon.println("Topic Received: " + pendingTopic + " (Len=" + String(pendingTopic.length()) + ")");
  } else if (urc.startsWith("+CMQTTRXPAYLOAD: 0,")) {
    // int expectedLen = urc.substring(18).toInt();
    // SerialMon.println("RXPAYLOAD: Expected Payload Len=" + String(expectedLen));
  } else if (messageInProgress && !urc.startsWith("+") && pendingTopic != "" && pendingPayload == "") {
    pendingPayload = urc;
    // SerialMon.println("Payload Received: " + pendingPayload + " (Len=" + String(pendingPayload.length()) + ")");
  } else if (urc == "+CMQTTRXEND: 0") {
    // SerialMon.println("RXEND: Topic=" + pendingTopic + ", Payload=" + pendingPayload);
    if (messageInProgress && pendingTopic != "" && pendingPayload != "") {
      // SerialMon.println("Calling handleMessage...");
      handleMessage(pendingTopic, pendingPayload);
    } else {
      // SerialMon.println("Message incomplete: Topic=" + pendingTopic + ", Payload=" + pendingPayload);
    }
    messageInProgress = false;
    pendingTopic = "";
    pendingPayload = "";
    pendingTopicLen = 0;
    pendingPayloadLen = 0;
  }
}

void handleMessage(String topic, String payload) {
  // SerialMon.printf("Message arrived [%s]: %s\n", topic.c_str(), payload.c_str());

  if (topic != "server_cmd") {
    // SerialMon.println("Ignoring message from non-server_cmd topic: " + topic);
    return;
  }

  ledStatus = !ledStatus;
  digitalWrite(LED_PIN, ledStatus);

  String reply = "I got your message: " + payload;
  // SerialMon.println("Attempting to publish: " + reply);
  if (publishMQTT(reply.c_str())) {
    // SerialMon.println("Published response: " + reply);
    if (payload.length() >= 3) {
      rgbLed.setPixelColor(0, rgbLed.Color(payload[0], payload[1], payload[2]));
      rgbLed.show();
    }
    lcd.clear();
    lcd.print("MQTT Msg:");
    lcd.setCursor(0, 1);
    lcd.print(payload.substring(0, 16));
  } else {
    // SerialMon.println("Failed to publish response");
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
  esp_task_wdt_reset();  // Feed WDT during long operation
  return result;
}

bool setupSSL() {
  modem.sendAT("+CSSLCFG=\"sslversion\",0,4"); // TLS 1.2
  if (modem.waitResponse() != 1) return false;

  modem.sendAT("+CSSLCFG=\"cacert\",0,\"", cert_name, "\"");
  if (modem.waitResponse() != 1) return false;

  modem.sendAT("+CSSLCFG=\"authmode\",0,1"); // Verify server only
  return modem.waitResponse() == 1;
}

bool setupMQTT() {
  modem.sendAT("+CMQTTSTART");
  if (modem.waitResponse(5000L, "+CMQTTSTART: 0") != 1) return false;
  esp_task_wdt_reset();  // Feed WDT during long operation

  modem.sendAT("+CMQTTACCQ=0,\"", clientID.c_str(), "\",1"); // SSL enabled
  if (modem.waitResponse() != 1) return false;

  modem.sendAT("+CMQTTSSLCFG=0,0"); // Use SSL context 0
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
  esp_task_wdt_reset();  // Feed WDT during long operation
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
  // SerialMon.println("publishMQTT: Setting topic...");
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

  // SerialMon.println("publishMQTT: Setting payload...");
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

  // SerialMon.println("publishMQTT: Publishing...");
  modem.sendAT("+CMQTTPUB=0,1,60");
  if (modem.waitResponse(1000L, "+CMQTTPUB: 0,0") == 1) {
    // SerialMon.println("publishMQTT: Success");
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
  esp_task_wdt_reset();  // Feed WDT during long operation
  return result;
}

bool stopMQTT() {
  SerialMon.println("Stopping MQTT service...");
  modem.sendAT("+CMQTTSTOP");
  bool result = modem.waitResponse(10000L, "+CMQTTSTOP: 0") == 1;
  esp_task_wdt_reset();  // Feed WDT during long operation
  return result;
}