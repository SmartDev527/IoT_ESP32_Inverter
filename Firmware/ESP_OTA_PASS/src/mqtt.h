#ifndef MQTT_H
#define MQTT_H

#include <Arduino.h> // Include for String and Serial
#include "config.h"

struct MqttStatus {
    bool serviceStarted = false;
    bool clientAcquired = false;
    bool connected = false;
    bool subscribed = false;
    bool provisionSubscribed = false;
    int lastErrorCode = 0;
    unsigned long lastConnectTime = 0;

    void reset();
};

extern MqttStatus mqttStatus;
extern String clientID;
extern String mqtt_user;
extern String mqtt_pass;

bool setupMQTT();
bool connectMQTT();
bool subscribeMQTT();
bool subscribeMQTT(const char *topic);
bool publishMQTT(const char *topic, const char *message);
bool disconnectMQTT();
bool stopMQTT();

#endif