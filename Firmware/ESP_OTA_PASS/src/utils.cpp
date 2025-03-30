#include "utils.h"
#include "mqtt.h"
#include "ota.h"
#include "modem.h"
#include "encrypt.h"

SetupState currentState = STATE_INIT_MODEM;
int retryCount = 0;
String imei = "";
unsigned long lastMonitorTime = 0;
String pendingTopic = "";
String pendingPayload = "";
bool messageInProgress = false;
int pendingTopicLen = 0;
int pendingPayloadLen = 0;
int receivedPayloadSize = 0;
bool isProvisioned = false;
Preferences preferences;
bool factoryResetTriggered = false;
bool waitingForProvisionResponse = false;
unsigned long provisionTimeout = 1200000;
unsigned long provisionStartTime = 0;
const unsigned long PROVISION_REQUEST_INTERVAL = 10000;
unsigned long PROVISION_RESTART_TIMEOUT = 120000;
unsigned long lastRequestTime = 0;
unsigned long bootTime = 0;
unsigned long validationDelay = 60000;

void printHex(const char *label, const unsigned char *data, size_t len) {
    Serial.print(label);
    for (size_t i = 0; i < len; i++) {
        if (data[i] < 0x10) Serial.print("0");
        Serial.print(data[i], HEX);
        if (i < len - 1) Serial.print(" ");
    }
    Serial.println();
}

bool tryStep(const String &stepMsg, bool success) {
    Serial.print(stepMsg + "... ");
    if (success) {
        Serial.println("success");
        retryCount = 0;
        return true;
    }
    Serial.println("fail");
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
        Serial.println("Max retries reached for " + stepMsg);
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

void resetState() {
    Serial.println("Resetting state data...");
    currentState = STATE_INIT_MODEM;
    retryCount = 0;
    if (otaInProgress) {
        cleanupResources();
    }
    digitalWrite(LED_PIN, LOW);
    rgbLed.setPixelColor(0, 0, 0, 0);
    rgbLed.show();
#ifdef ENABLE_LCD
    if (lcdAvailable) {
        lcd.clear();
        lcd.print("Resetting...");
    }
#endif
}

void monitorConnections() {
    String response;
    sendAT("AT+CSQ", response, 1000);
    if (response.indexOf("+CSQ:") < 0 || response.indexOf("99,99") >= 0) {
        Serial.println("Network lost");
        if (otaInProgress) {
            Serial.println("OTA interrupted by network loss");
            cleanupResources();
            publishMQTT(mqtt_topic_send, "OTA:ERROR:Network lost");
        }
        nextState(STATE_RECOVER_NETWORK);
    } else {
        sendAT("AT+CGATT?", response, 1000);
        if (response.indexOf("+CGATT: 1") < 0) {
            Serial.println("GPRS disconnected");
            if (otaInProgress) {
                Serial.println("OTA interrupted by GPRS loss");
                cleanupResources();
                publishMQTT(mqtt_topic_send, "OTA:ERROR:GPRS lost");
            }
            nextState(STATE_RECOVER_GPRS);
        }
    }
}

void cleanupResources() {
    Serial.println("Cleaning up resources...");
    String response;
    sendAT("AT+CGATT=0", response, 5000);
    stopMQTT();
    if (otaInProgress) {
        esp_ota_end(otaHandle);
        otaInProgress = false;
        otaReceivedSize = 0;
        otaTotalSize = 0;
        chunkCount = 0;
        receivedChunks.clear();
        missingChunks.clear();
        Serial.println("OTA data cleared due to cleanup");
    }
    pendingTopic = "";
    pendingPayload = "";
}

void handleMessage(String topic, String payload) {
    Serial.println("Received topic: " + topic + ", payload: " + payload);
    if (topic == PROVISION_RESPONSE_TOPIC) {
        StaticJsonDocument<200> doc;
        deserializeJson(doc, payload);
        if (doc.containsKey("password")) {
            String newPassword = doc["password"];
            saveCredentials(newPassword);
            nextState(STATE_CONNECT_MQTT);
            waitingForProvisionResponse = false;
#ifdef ENABLE_LCD
            if (lcdAvailable) {
                lcd.clear();
                lcd.print("Provisioned");
            }
#endif
        }
    } else if (topic == mqtt_topic_firmware) {
        processOTAFirmware(topic, (byte*)payload.c_str(), payload.length());
    } else {
        Serial.println("Unhandled topic: " + topic);
    }
}
void performFactoryReset() {
    const esp_partition_t *factoryPartition = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_FACTORY, NULL);
    if (factoryPartition == NULL) {
        Serial.println("Factory partition not found");
        publishMQTT(mqtt_topic_send, "FACTORY_RESET:ERROR:No factory partition");
        return;
    }
    esp_err_t err = esp_ota_set_boot_partition(factoryPartition);
    if (err != ESP_OK) {
        Serial.printf("Failed to set factory partition: %s\n", esp_err_to_name(err));
        publishMQTT(mqtt_topic_send, "FACTORY_RESET:ERROR:Set failed");
        return;
    }
    preferences.begin("device-creds", false);
    preferences.clear();
    preferences.end();
    isProvisioned = false;
    clientID = DEFAULT_CLIENT_ID;
    mqtt_user = DEFAULT_USERNAME;
    mqtt_pass = DEFAULT_PASSWORD;
    Serial.println("Factory reset complete");
    publishMQTT(mqtt_topic_send, "FACTORY_RESET:SUCCESS");
#ifdef ENABLE_LCD
    if (lcdAvailable) {
        lcd.clear();
        lcd.print("Factory Reset");
    }
#endif
    delay(1000);
    ESP.restart();
}

void check_firmware_partition() {
    const esp_partition_t *running = esp_ota_get_running_partition();
    if (running->subtype == ESP_PARTITION_SUBTYPE_APP_FACTORY) {
        Serial.println("Running from factory partition");
#ifdef ENABLE_LCD
        if (lcdAvailable) {
            lcd.clear();
            lcd.print("Factory Mode");
        }
#endif
    } else if (running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_0 || running->subtype == ESP_PARTITION_SUBTYPE_APP_OTA_1) {
        Serial.printf("Running from OTA partition %d\n", running->subtype - ESP_PARTITION_SUBTYPE_APP_OTA_0);
#ifdef ENABLE_LCD
        if (lcdAvailable) {
            lcd.clear();
            lcd.print("OTA Mode");
        }
#endif
    }
}

void resetCredentials() {
    preferences.begin("device-creds", false);
    preferences.clear();
    preferences.end();
    isProvisioned = false;
    clientID = DEFAULT_CLIENT_ID;
    mqtt_user = DEFAULT_USERNAME;
    mqtt_pass = DEFAULT_PASSWORD;
    Serial.println("Credentials reset to defaults");
#ifdef ENABLE_LCD
    if (lcdAvailable) {
        lcd.clear();
        lcd.print("Creds Reset");
    }
#endif
}

void loadCredentials() {
    preferences.begin("device-creds", true);
    isProvisioned = preferences.getBool("provisioned", false);
    if (isProvisioned) {
        clientID = preferences.getString("client_id", "GESUS_" + String(millis()));
        mqtt_user = preferences.getString("username", "ESP32_" + imei);
        mqtt_pass = preferences.getString("password", "");
        if (mqtt_pass == "") {
            Serial.println("Warning: No saved password found, resetting to default");
            isProvisioned = false;
            clientID = DEFAULT_CLIENT_ID;
            mqtt_user = DEFAULT_USERNAME;
            mqtt_pass = DEFAULT_PASSWORD;
        }
    } else {
        clientID = DEFAULT_CLIENT_ID;
        mqtt_user = DEFAULT_USERNAME;
        mqtt_pass = DEFAULT_PASSWORD;
    }
    mqtt_user.replace("\r", "");
    mqtt_user.replace("\n", "");
    int okIndex = mqtt_user.indexOf("OK");
    if (okIndex != -1) mqtt_user = mqtt_user.substring(0, okIndex);
    mqtt_user.trim();
    mqtt_pass.replace("\r", "");
    mqtt_pass.replace("\n", "");
    mqtt_pass.trim();
    preferences.end();
    Serial.println("Loaded credentials:");
    Serial.println("Client ID: " + clientID);
    Serial.println("Username: " + mqtt_user);
    Serial.println("Provisioned: " + String(isProvisioned ? "Yes" : "No"));
}

void saveCredentials(String newPassword) {
    if (imei == "" || imei == "Unknown") {
        Serial.println("Cannot save credentials without valid IMEI");
        return;
    }
    mqtt_user = "ESP32_" + imei;
    mqtt_user.replace("\r", "");
    mqtt_user.replace("\n", "");
    int okIndex = mqtt_user.indexOf("OK");
    if (okIndex != -1) mqtt_user = mqtt_user.substring(0, okIndex);
    mqtt_user.trim();
    if (!isProvisioned) {
        clientID = "GESUS_" + String(millis());
    }
    mqtt_pass = newPassword;
    mqtt_pass.replace("\r", "");
    mqtt_pass.replace("\n", "");
    mqtt_pass.trim();
    preferences.begin("device-creds", false);
    preferences.putString("client_id", clientID);
    preferences.putString("username", mqtt_user);
    preferences.putString("password", mqtt_pass);
    preferences.putBool("provisioned", true);
    preferences.end();
    isProvisioned = true;
    Serial.println("Saved new credentials:");
    Serial.println("Client ID: " + clientID);
    Serial.println("Username: " + mqtt_user);
    Serial.println("Password length: " + String(mqtt_pass.length()));
}

bool republishProvisionRequest() {
    if (waitingForProvisionResponse && (millis() - lastRequestTime >= PROVISION_REQUEST_INTERVAL)) {
        StaticJsonDocument<200> doc;
        doc["device_id"] = clientID;
        doc["imei"] = imei;
        String request;
        serializeJson(doc, request);
        lastRequestTime = millis();
        return publishMQTT(PROVISION_TOPIC, request.c_str());
    }
    return false;
}


