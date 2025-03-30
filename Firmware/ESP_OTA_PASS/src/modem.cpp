#include "modem.h"
#include "mqtt.h"
#include "utils.h" // Include for waitingForProvisionResponse and other utils variables
#include "config.h"

QueueHandle_t uartQueue;

static void IRAM_ATTR uart_isr(void *arg) {
    uint8_t buffer[BUFFER_SIZE];
    int len = uart_read_bytes(UART_NUM, buffer, BUFFER_SIZE - 1, 0);
    if (len > 0) {
        buffer[len] = '\0';
        xQueueSendFromISR(uartQueue, buffer, NULL);
    }
}

void modemTask(void *pvParameters) {
    char buffer[BUFFER_SIZE];
    while (1) {
        if (xQueueReceive(uartQueue, buffer, portMAX_DELAY) == pdTRUE) {
            String urc = String(buffer);
            processURC(urc);
        }
    }
}

void setupModem() {
    uart_config_t uart_config = {
        .baud_rate = BAUD_RATE,
        .data_bits = UART_DATA_8_BITS,
        .parity = UART_PARITY_DISABLE,
        .stop_bits = UART_STOP_BITS_1,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE,
        .rx_flow_ctrl_thresh = 0,
        .source_clk = UART_SCLK_APB,
    };
    uart_param_config(UART_NUM, &uart_config);
    uart_set_pin(UART_NUM, MODEM_TX, MODEM_RX, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    uart_driver_install(UART_NUM, BUFFER_SIZE * 2, BUFFER_SIZE * 2, 20, NULL, 0);

    uartQueue = xQueueCreate(20, BUFFER_SIZE);
    uart_isr_register(UART_NUM, uart_isr, NULL, ESP_INTR_FLAG_IRAM, NULL);
    uart_enable_rx_intr(UART_NUM);

    xTaskCreate(modemTask, "modemTask", 4096, NULL, 5, NULL);

    pinMode(SIM7600_PWR, OUTPUT);
    digitalWrite(SIM7600_PWR, LOW);
    delay(1500);
    digitalWrite(SIM7600_PWR, HIGH);
    delay(5000);
}

bool sendAT(const char* cmd, String& response, uint32_t timeout_ms, const char* expected) {
    uart_flush(UART_NUM);
    uart_write_bytes(UART_NUM, cmd, strlen(cmd));
    uart_write_bytes(UART_NUM, "\r\n", 2);

    response = "";
    uint32_t start = millis();
    while (millis() - start < timeout_ms) {
        char buffer[BUFFER_SIZE];
        if (xQueueReceive(uartQueue, buffer, pdMS_TO_TICKS(100)) == pdTRUE) {
            response += String(buffer);
            if (response.indexOf(expected) >= 0 || response.indexOf("ERROR") >= 0) {
                return response.indexOf(expected) >= 0;
            }
        }
    }
    return false;
}

void resetModem() {
    Serial.println("Resetting modem...");
    digitalWrite(SIM7600_PWR, LOW);
    delay(1500);
    digitalWrite(SIM7600_PWR, HIGH);
    delay(5000);
    mqttStatus.serviceStarted = false;
}

void processURC(String urc) {
    urc.trim();
    if (urc.length() > 0) {
        Serial.println("URC: " + urc);
    }
    if (urc.startsWith("+CMQTTCONNLOST: 0,")) {
        Serial.println("MQTT connection lost detected");
        mqttStatus.connected = false;
        mqttStatus.subscribed = false;
    } else if (urc.startsWith("+CMQTTSUB: 0,0")) {
        Serial.println("Subscription confirmed via URC");
        if (!mqttStatus.provisionSubscribed && waitingForProvisionResponse) {
            mqttStatus.provisionSubscribed = true;
        }
    } else if (urc.startsWith("+CMQTTRXPAYLOAD: 0,")) {
        pendingPayloadLen = urc.substring(urc.indexOf(",") + 1).toInt();
        pendingPayload = "";
        receivedPayloadSize = 0;
    } else if (urc.startsWith("+CMQTTACCQ: 0,0")) {
        Serial.println("MQTT client acquisition confirmed via URC");
        mqttStatus.clientAcquired = true;
    } else if (urc.startsWith("+CMQTTCONNECT: 0,0")) {
        Serial.println("MQTT connection confirmed via URC");
        mqttStatus.connected = true;
        mqttStatus.lastConnectTime = millis();
    } else if (urc.startsWith("+CMQTTRXSTART: 0,")) {
        messageInProgress = true;
        pendingTopic = "";
        pendingPayload = "";
        int commaIdx = urc.indexOf(',', 14);
        pendingTopicLen = urc.substring(14, commaIdx).toInt();
        pendingPayloadLen = urc.substring(commaIdx + 1).toInt();
    } else if (messageInProgress && !urc.startsWith("+") && pendingTopic == "") {
        pendingTopic = urc;
    } else if (messageInProgress && !urc.startsWith("+") && pendingTopic != "" && pendingPayload == "") {
        pendingPayload = urc;
    } else if (!urc.startsWith("+") && pendingPayloadLen > 0) {
        pendingPayload += urc;
        receivedPayloadSize += urc.length();
        Serial.println("Payload chunk received, total size so far: " + String(receivedPayloadSize));
    } else if (urc == "+CMQTTRXEND: 0") {
        if (receivedPayloadSize != pendingPayloadLen) {
            Serial.println("Warning: Received " + String(receivedPayloadSize) + " bytes, expected " + String(pendingPayloadLen));
        }
        handleMessage(pendingTopic, pendingPayload);
        pendingTopic = "";
        pendingPayload = "";
        pendingTopicLen = 0;
        pendingPayloadLen = 0;
        receivedPayloadSize = 0;
    }
}

bool uploadCertificate() {
    String response;
    sendAT("+CCERTLIST", response, 2000);
    if (response.indexOf(String("+CCERTLIST: \"") + cert_name + "\"") >= 0) {
        Serial.println("Certificate '" + String(cert_name) + "' exists");
        return true;
    }
    String cmd = String("+CCERTDOWN=\"") + cert_name + "\"," + String(strlen(root_ca));
    sendAT(cmd.c_str(), response, 2000, ">");
    if (response.indexOf(">") < 0) return false;
    uart_write_bytes(UART_NUM, root_ca, strlen(root_ca));
    return sendAT("", response, 5000);
}

bool setupSSL() {
    String response;
    if (!sendAT("+CSSLCFG=\"sslversion\",0,4", response, 1000)) return false;
    String cmd = String("+CSSLCFG=\"cacert\",0,\"") + cert_name + "\"";
    if (!sendAT(cmd.c_str(), response, 1000)) return false;
    return sendAT("+CSSLCFG=\"authmode\",0,1", response, 1000);
}