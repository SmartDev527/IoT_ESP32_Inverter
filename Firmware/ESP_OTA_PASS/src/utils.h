#ifndef UTILS_H
#define UTILS_H

#include <Arduino.h>
#include <Preferences.h>
#include <ArduinoJson.h> // Explicitly include if needed
#include <Adafruit_NeoPixel.h> // For rgbLed
#include "config.h"
#ifdef ENABLE_LCD
#include <LCD_I2C.h>
extern LCD_I2C lcd;
#endif

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
    STATE_WAIT_PROVISION,
    STATE_ERROR,
    STATE_STOPPED,
    STATE_RECOVER_NETWORK,
    STATE_RECOVER_GPRS,
    STATE_RECOVER_MQTT
};

extern SetupState currentState;
extern int retryCount;
extern String imei;
extern unsigned long lastMonitorTime;
extern String pendingTopic;
extern String pendingPayload;
extern bool messageInProgress;
extern int pendingTopicLen;
extern int pendingPayloadLen;
extern int receivedPayloadSize;
extern bool isProvisioned;
extern Preferences preferences;
extern bool factoryResetTriggered;
extern bool waitingForProvisionResponse;
extern unsigned long provisionTimeout;
extern unsigned long provisionStartTime;
extern const unsigned long PROVISION_REQUEST_INTERVAL;
extern unsigned long PROVISION_RESTART_TIMEOUT;
extern unsigned long lastRequestTime;
extern unsigned long bootTime;
extern unsigned long validationDelay;

extern Adafruit_NeoPixel rgbLed; // Already present
#ifdef ENABLE_LCD
extern bool lcdAvailable;
extern LCD_I2C lcd;
#endif

void printHex(const char *label, const unsigned char *data, size_t len);
bool tryStep(const String &stepMsg, bool success);
void nextState(SetupState next);
void retryState(const String &stepMsg);
void resetState();
void monitorConnections();
void cleanupResources();
void handleMessage(String topic, String payload);
bool requestCredentialsFromServer();
bool republishProvisionRequest();

void performFactoryReset();
void check_firmware_partition();
void resetCredentials();
void loadCredentials();
void saveCredentials(String newPassword);


#endif