#include <Wire.h>
#include <HardwareSerial.h>
#include <Adafruit_NeoPixel.h>
#ifdef ENABLE_LCD
#include <LCD_I2C.h>
#endif
#include <esp_task_wdt.h>
#include "config.h"
#include "mqtt.h"
#include "ota.h"
#include "modem.h"
#include "utils.h"

// HardwareSerial sim7600(1);
#define SerialMon Serial

Adafruit_NeoPixel rgbLed(NUM_PIXELS, RGB_LED_PIN, NEO_GRB + NEO_KHZ800);
bool lcdAvailable = false;
#ifdef ENABLE_LCD
LCD_I2C lcd(0x27, 16, 2);
#endif

void setup() {
    esp_task_wdt_reset();
    SerialMon.begin(115200);
    delay(1000);
    SerialMon.println("Starting...");

    mqttStatus.reset();
    otaInProgress = false;
    otaReceivedSize = 0;
    otaTotalSize = 0;
    chunkCount = 0;
    receivedChunks.clear();
    missingChunks.clear();

    esp_task_wdt_init(WDT_TIMEOUT * 1000, true);
    esp_task_wdt_add(NULL);

    pinMode(FACTORY_RESET_PIN, INPUT_PULLUP);
    check_firmware_partition();
    setupModem();

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
    resetCredentials();
    bootTime = millis();

    String response;
    if (sendAT("AT", response, 1000)) {
        SerialMon.println("Modem initialized");
        sendAT("AT+CGSN", response, 1000);
        imei = response;
        imei.replace("\r", "");
        imei.replace("\n", "");
        int okIndex = imei.indexOf("OK");
        if (okIndex != -1) {
            imei = imei.substring(0, okIndex);
        }
        imei.trim();
        SerialMon.print("Cleaned IMEI: ");
        SerialMon.println(imei);
        sendAT("ATE0", response, 1000); // Echo off
        sendAT("AT+CMEE=2", response, 1000); // Verbose errors
        loadCredentials();
        bootTime = millis();
        nextState(STATE_WAIT_NETWORK);
    }
}

void loop() {
    esp_task_wdt_reset();
    if (digitalRead(FACTORY_RESET_PIN) == LOW) {
        delay(50);
        if (digitalRead(FACTORY_RESET_PIN) == LOW) {
            factoryResetTriggered = true;
            performFactoryReset();
        }
    }

    switch (currentState) {
        case STATE_INIT_MODEM: {
            String response;
            if (tryStep("Initializing modem", sendAT("AT", response, 1000))) {
                sendAT("AT+CGSN", response, 1000);
                imei = response;
                imei.replace("\r", "");
                imei.replace("\n", "");
                int okIndex = imei.indexOf("OK");
                if (okIndex != -1) imei = imei.substring(0, okIndex);
                imei.trim();
                nextState(STATE_WAIT_NETWORK);
            }
            break;
        }

        case STATE_WAIT_NETWORK: {
            String response;
            sendAT("AT+CSQ", response, 1000);
            if (tryStep("Waiting for network", response.indexOf("+CSQ:") >= 0 && response.indexOf("99,99") < 0)) {
                nextState(STATE_CONNECT_GPRS);
            }
            break;
        }

        case STATE_CONNECT_GPRS: {
            String response;
            String cmd = String("AT+CGDCONT=1,\"IP\",\"") + apn + "\"";
            sendAT(cmd.c_str(), response, 1000);
            if (tryStep("Connecting to " + String(apn), sendAT("AT+CGATT=1", response, 5000))) {
                nextState(STATE_UPLOAD_CERTIFICATE);
            }
            break;
        }

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
                if (!isProvisioned) {
                    if (requestCredentialsFromServer()) {
                        nextState(STATE_WAIT_PROVISION);
                    } else {
                        nextState(STATE_ERROR);
                    }
                } else {
                    nextState(STATE_CONNECT_MQTT);
                }
            }
            break;

        case STATE_WAIT_PROVISION:
            if (millis() - provisionStartTime >= provisionTimeout) {
                SerialMon.println("Provisioning timeout exceeded");
                waitingForProvisionResponse = false;
                stopMQTT();
                nextState(STATE_ERROR);
            } else if (millis() - lastRequestTime >= PROVISION_REQUEST_INTERVAL) {
                republishProvisionRequest();
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
            SerialMon.println("Setup failed, cleaning up...");
            cleanupResources();
            resetModem();
            nextState(STATE_INIT_MODEM);
            break;

        case STATE_RECOVER_MQTT:
            if (tryStep("Recovering MQTT", connectMQTT() && subscribeMQTT())) {
                nextState(STATE_RUNNING);
            }
            break;
    }
}