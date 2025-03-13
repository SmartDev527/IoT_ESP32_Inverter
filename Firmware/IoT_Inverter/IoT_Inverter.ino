#define TINY_GSM_MODEM_SIM7600

#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <TinyGsmClient.h>
#include <WiFiClientSecure.h>
#include <PubSubClient.h>
#include <ArduinoJson.h>
#include <ModbusMaster.h>
#include <HardwareSerial.h>
#include "certificates.h"

// LCD1602 I2C Setup
#define I2C_SDA 21  // Set custom SDA pin
#define I2C_SCL 22  // Set custom SCL pin
Wire.begin(I2C_SDA, I2C_SCL);
LiquidCrystal_I2C lcd(0x27, 16, 2);  // Change 0x27 if needed

// SIM7600 Serial Configuration
#define MODEM_TX 17
#define MODEM_RX 16
#define RS485_RX 27
#define RS485_TX 26
#define RS485_EN 25  // RS485 Enable Pin

// MQTT Configuration with TLS
const char* mqtt_server = "your_mqtt_broker";  // Replace with EMQX server URL
const char* mqtt_topic_control = "inverter/control";
const char* mqtt_topic_status = "inverter/status";
const int mqtt_port = 8883; // MQTT over TLS port

// APN Configuration
const char apn[] = "your_apn";
const char user[] = "";
const char pass[] = "";

HardwareSerial sim7600(1);
HardwareSerial rs485(2);
ModbusMaster node;
TinyGsm modem(sim7600);
TinyGsmClientSecure client(modem);
PubSubClient mqtt(client);

void writeRegister(uint16_t reg, uint16_t value) {
    digitalWrite(RS485_EN, HIGH);
    delay(10);
    node.writeSingleRegister(reg, value);
    digitalWrite(RS485_EN, LOW);
}

void callback(char* topic, byte* payload, unsigned int length) {
    StaticJsonDocument<256> doc;
    deserializeJson(doc, payload, length);
    int registerAddress = doc["register"];
    int value = doc["value"];
    writeRegister(registerAddress, value);
    
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("CMD:");
    lcd.setCursor(0, 1);
    lcd.print("Reg:");
    lcd.print(registerAddress);
    lcd.print(" Val:");
    lcd.print(value);
}

void connectMQTT() {
    while (!mqtt.connected()) {
        Serial.print("Connecting to MQTT over TLS...");
        if (mqtt.connect("ESP32_SIM7600_Client")) {
            Serial.println("Connected!");
            mqtt.subscribe(mqtt_topic_control);
        } else {
            Serial.print("Failed, retrying in 5 seconds...");
            delay(5000);
        }
    }
}

void setup() {
    Serial.begin(115200);
    lcd.init();
    lcd.backlight();
    lcd.setCursor(0, 0);
    lcd.print("Connecting...");
    
    rs485.begin(9600, SERIAL_8N1, RS485_RX, RS485_TX);
    pinMode(RS485_EN, OUTPUT);
    digitalWrite(RS485_EN, LOW);
    node.begin(1, rs485);
    
    sim7600.begin(115200, SERIAL_8N1, MODEM_RX, MODEM_TX);
    modem.gprsConnect(apn, user, pass);
    client.setCACert(root_ca);  // Load CA certificate from certificates.h
    mqtt.setServer(mqtt_server, mqtt_port);
    mqtt.setCallback(callback);
}

void loop() {
    if (!mqtt.connected()) {
        connectMQTT();
    }
    mqtt.loop();
}
