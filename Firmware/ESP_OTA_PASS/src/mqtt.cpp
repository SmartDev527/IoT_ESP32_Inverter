#include "mqtt.h"
#include "modem.h"
#include "encrypt.h"
#include "ota.h"
#include "utils.h"
#include <String.h>


MqttStatus mqttStatus;
String clientID = DEFAULT_CLIENT_ID;
String mqtt_user = DEFAULT_USERNAME;
String mqtt_pass = DEFAULT_PASSWORD;



void MqttStatus::reset() {
    serviceStarted = false;
    clientAcquired = false;
    connected = false;
    subscribed = false;
    provisionSubscribed = false;
    lastErrorCode = 0;
    lastConnectTime = 0;
}

bool setupMQTT() {
    String response;
    if (!mqttStatus.serviceStarted) {
        if (!sendAT("AT+CMQTTSTART", response, 5000) || response.indexOf("+CMQTTSTART: 0") < 0) {
            Serial.println("MQTT start failed - Response: " + response);
            if (response.indexOf("+CMQTTSTART: 23") >= 0) {
                Serial.println("MQTT service already running (+CMQTTSTART: 23), proceeding");
                mqttStatus.serviceStarted = true;
            } else {
                return false;
            }
        } else {
            mqttStatus.serviceStarted = true;
            Serial.println("MQTT service started successfully");
        }
    }
    if (!mqttStatus.clientAcquired) {
        unsigned long timeVal = millis() & 0xFFF;
        clientID = "ESP32_" + String(timeVal);
        String cmd = "AT+CMQTTACCQ=0,\"" + clientID + "\",1";
        if (!sendAT(cmd.c_str(), response, 10000)) return false;
        mqttStatus.clientAcquired = true;
    }
    return sendAT("AT+CMQTTSSLCFG=0,1", response, 2000);
}

bool connectMQTT() {
    if (mqttStatus.connected) return true;
    if (!mqttStatus.serviceStarted || !mqttStatus.clientAcquired) {
        if (!setupMQTT()) return false;
    }
    String cmd = "AT+CMQTTCONNECT=0,\"tcp://" + String(mqtt_server) + ":" + String(mqtt_port) + "\",60,1,\"" + mqtt_user + "\",\"" + mqtt_pass + "\"";
    String response;
    if (!sendAT(cmd.c_str(), response, 30000)) return false;
    if (response.indexOf("+CMQTTCONNECT: 0,0") >= 0) {
        mqttStatus.connected = true;
        return true;
    }
    return false;
}

bool subscribeMQTT(const char *topic) {
    if (!mqttStatus.connected) return false;
    int topicLen = strlen(topic);
    String cmd = "AT+CMQTTSUBTOPIC=0," + String(topicLen) + ",1";
    String response;
    if (!sendAT(cmd.c_str(), response, 2000, ">") || response.indexOf(">") < 0) return false;
    uart_write_bytes(UART_NUM, topic, topicLen);
    if (!sendAT("", response, 2000)) return false;
    if (!sendAT("AT+CMQTTSUB=0", response, 10000) || response.indexOf("+CMQTTSUB: 0,0") < 0) return false;
    return true;
}

bool subscribeMQTT() {
    if (mqttStatus.subscribed) return true;
    bool success = subscribeMQTT(mqtt_topic_recv) && subscribeMQTT(mqtt_topic_firmware);
    if (success) mqttStatus.subscribed = true;
    return success;
}

bool publishMQTT(const char *topic, const char *message) {
    if (!mqttStatus.serviceStarted || !connectMQTT()) return false;
    String response;
    String cmd = "AT+CMQTTTOPIC=0," + String(strlen(topic));
    if (!sendAT(cmd.c_str(), response, 500, ">") || response.indexOf(">") < 0) return false;
    uart_write_bytes(UART_NUM, topic, strlen(topic));
    if (!sendAT("", response, 500)) return false;
    cmd = "AT+CMQTTPAYLOAD=0," + String(strlen(message));
    if (!sendAT(cmd.c_str(), response, 500, ">") || response.indexOf(">") < 0) return false;
    uart_write_bytes(UART_NUM, message, strlen(message));
    if (!sendAT("", response, 500)) return false;
    if (!sendAT("AT+CMQTTPUB=0,1,60", response, 2000) || (response.indexOf("OK") < 0 && response.indexOf("+CMQTTPUB: 0,0") < 0)) return false;
    return true;
}

bool disconnectMQTT() {
    if (!mqttStatus.serviceStarted) return true;
    String response;
    if (!sendAT("AT+CMQTTDISC=0,120", response, 15000) || response.indexOf("+CMQTTDISC: 0,0") < 0) return false;
    mqttStatus.connected = false;
    return true;
}

bool stopMQTT() {
    if (!mqttStatus.serviceStarted) return true;
    String response;
    if (mqttStatus.connected) disconnectMQTT();
    if (mqttStatus.clientAcquired) sendAT("AT+CMQTTREL=0", response, 5000);
    if (!sendAT("AT+CMQTTSTOP", response, 10000) || response.indexOf("+CMQTTSTOP: 0") < 0) {
        resetModem();
        mqttStatus.reset();
        return false;
    }
    mqttStatus.reset();
    return true;
}


bool requestCredentialsFromServer() {
    if (imei == "" || imei == "Unknown") return false;
    mqtt_user = DEFAULT_USERNAME;
    mqtt_pass = DEFAULT_PASSWORD;
    if (!mqttStatus.serviceStarted || !mqttStatus.clientAcquired) {
        if (!setupMQTT()) return false;
    }
    if (!mqttStatus.connected) {
        if (!connectMQTT()) return false;
    }
    if (!mqttStatus.provisionSubscribed) {
        if (subscribeMQTT(PROVISION_RESPONSE_TOPIC)) mqttStatus.provisionSubscribed = true;
        else return false;
    }
    String requestMsg = "IMEI:" + imei;
    if (publishMQTT(PROVISION_TOPIC, requestMsg.c_str())) {
        waitingForProvisionResponse = true;
        provisionStartTime = millis();
        lastRequestTime = millis();
        return true;
    }
    return false;
}

