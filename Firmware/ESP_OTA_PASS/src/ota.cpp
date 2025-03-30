#include "ota.h"
#include "config.h"
#include "mqtt.h"
#include "encrypt.h"
#include "utils.h" // Added for lcd and lcdAvailable

bool otaInProgress = false;
unsigned long otaReceivedSize = 0;
unsigned long otaTotalSize = 0;
unsigned long chunkCount = 0;
std::vector<unsigned long> missingChunks;
std::map<unsigned long, bool> receivedChunks;
esp_ota_handle_t otaHandle = 0;
const esp_partition_t *updatePartition = NULL;
const esp_partition_t *previousPartition = NULL;
bool pendingValidation = false;
String otaHash = "";
mbedtls_sha256_context sha256_ctx;

void startOTA(uint32_t totalSize) {
    previousPartition = esp_ota_get_running_partition();
    updatePartition = esp_ota_get_next_update_partition(NULL);
    if (!updatePartition) {
        Serial.println("No valid OTA partition available");
        publishMQTT(mqtt_topic_send, "OTA:ERROR:No partition");
        return;
    }
    esp_err_t err = esp_ota_begin(updatePartition, totalSize, &otaHandle);
    if (err != ESP_OK) {
        Serial.printf("OTA begin failed: %s\n", esp_err_to_name(err));
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Begin failed");
        return;
    }
    otaInProgress = true;
    pendingValidation = false;
    otaTotalSize = totalSize;
    otaReceivedSize = 0;
    chunkCount = 0;
    receivedChunks.clear();
    missingChunks.clear();
    mbedtls_sha256_init(&sha256_ctx);
    mbedtls_sha256_starts(&sha256_ctx, 0);
    Serial.println("OTA started from " + String(previousPartition->label) + " to " + String(updatePartition->label));
    publishMQTT(mqtt_topic_send, "OTA:STARTED");
}

void processOTAFirmware(const String &topic, byte *payload, unsigned int dataLen) {
    Serial.println("ENTER processOTAFirmware");
    Serial.print("Topic: ["); Serial.print(topic); Serial.print("], Length: "); Serial.println(dataLen);
    if (topic != mqtt_topic_firmware) {
        Serial.println("Ignoring OTA message: wrong topic");
        return;
    }
    String payloadStr((char *)payload, dataLen);
    if (payloadStr.startsWith("OTA:BEGIN:")) {
        if (otaInProgress || pendingValidation) {
            Serial.println("Previous OTA detected, cleaning up...");
            esp_ota_end(otaHandle);
            otaInProgress = false;
        }
        int colonIdx = payloadStr.indexOf(':', 10);
        uint32_t totalSize = payloadStr.substring(10, colonIdx).toInt();
        otaHash = payloadStr.substring(colonIdx + 1);
        Serial.println("Starting OTA with total size: " + String(totalSize) + ", hash: " + otaHash);
        startOTA(totalSize);
        publishMQTT(mqtt_topic_send, "OTA:STARTED");
        return;
    }
    if (!otaInProgress) {
        Serial.println("Ignoring OTA message: OTA not started");
        return;
    }
    if (pendingValidation) {
        Serial.println("Ignoring OTA message: OTA pending validation");
        return;
    }
    if (payloadStr == "OTA:END") {
        Serial.println("Received OTA:END");
        finishOTA();
        return;
    }
    if (payloadStr == "OTA:CANCEL") {
        if (otaInProgress) {
            Serial.println("Cancelling ongoing OTA update");
            esp_ota_end(otaHandle);
            otaInProgress = false;
            publishMQTT(mqtt_topic_firmware, "OTA:CANCELLED");
        } else {
            Serial.println("No OTA in progress to cancel");
        }
        return;
    }
    size_t maxDecodedLen = ((dataLen + 3) / 4) * 3;
    unsigned char *decodedPayload = new unsigned char[maxDecodedLen];
    size_t decodedLen = base64_decode((char *)payload, decodedPayload, maxDecodedLen);
    if (decodedLen < 4) {
        Serial.println("Invalid decoded chunk size: " + String(decodedLen));
        delete[] decodedPayload;
        return;
    }
    unsigned long chunkNum = ((unsigned long)decodedPayload[0] << 24) |
                             ((unsigned long)decodedPayload[1] << 16) |
                             ((unsigned long)decodedPayload[2] << 8) |
                             decodedPayload[3];
    size_t chunkSize = decodedLen - 4;
    if (chunkSize > OTA_MAX_DATA_SIZE) {
        Serial.println("Chunk too large: " + String(chunkSize) + " for chunk " + String(chunkNum));
        delete[] decodedPayload;
        return;
    }
    if (receivedChunks[chunkNum]) {
        Serial.println("Duplicate chunk " + String(chunkNum));
        delete[] decodedPayload;
        return;
    }
    esp_err_t err = esp_ota_write(otaHandle, decodedPayload + 4, chunkSize);
    if (err != ESP_OK) {
        Serial.printf("OTA write failed for chunk %lu: %s\n", chunkNum, esp_err_to_name(err));
        esp_ota_end(otaHandle);
        otaInProgress = false;
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Write failed");
        delete[] decodedPayload;
        return;
    }
    mbedtls_sha256_update(&sha256_ctx, decodedPayload + 4, chunkSize);
    receivedChunks[chunkNum] = true;
    otaReceivedSize += chunkSize;
    chunkCount++;
    Serial.println("Processed chunk " + String(chunkNum) + ", size=" + String(chunkSize));
    static int chunksSinceAck = 0;
    chunksSinceAck++;
    if (chunksSinceAck >= BATCH_SIZE) {
        String ackMsg = "OTA:PROGRESS:" + String(chunkNum) + ":" + String(otaReceivedSize) + "/" + String(otaTotalSize);
        publishMQTT(mqtt_topic_firmware, ackMsg.c_str());
        chunksSinceAck = 0;
    }
    delete[] decodedPayload;
}

void finishOTA() {
    if (!otaInProgress) {
        Serial.println("No OTA in progress to finish");
        return;
    }
    const int MAX_CHUNK_RETRIES = 3;
    int retryCount = 0;
    while (retryCount < MAX_CHUNK_RETRIES) {
        checkMissingChunks();
        if (otaReceivedSize == otaTotalSize) break;
        Serial.println("Missing chunks detected, retry " + String(retryCount + 1) + "/" + String(MAX_CHUNK_RETRIES));
        delay(5000);
        retryCount++;
    }
    if (otaReceivedSize != otaTotalSize) {
        Serial.println("OTA incomplete: Received " + String(otaReceivedSize) + "/" + String(otaTotalSize));
        esp_ota_end(otaHandle);
        otaInProgress = false;
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Incomplete");
        return;
    }
    unsigned char hash[32];
    mbedtls_sha256_finish(&sha256_ctx, hash);
    mbedtls_sha256_free(&sha256_ctx);
    String computedHash = "";
    for (int i = 0; i < 32; i++) {
        char hex[3];
        sprintf(hex, "%02x", hash[i]);
        computedHash += hex;
    }
    if (computedHash != otaHash) {
        Serial.println("Hash mismatch: " + computedHash + " vs " + otaHash);
        esp_ota_end(otaHandle);
        otaInProgress = false;
        publishMQTT(mqtt_topic_send, "OTA:ERROR:Hash mismatch");
        publishMQTT(mqtt_topic_send, "OTA:REQUEST:RETRY");
        return;
    }
    esp_err_t err = esp_ota_end(otaHandle);
    if (err != ESP_OK) {
        Serial.printf("OTA end failed: %s\n", esp_err_to_name(err));
        otaInProgress = false;
        publishMQTT(mqtt_topic_send, "OTA:ERROR:End failed");
        return;
    }
    Serial.println("OTA update written, validating...");
    publishMQTT(mqtt_topic_send, "OTA:SUCCESS:PENDING_VALIDATION");
    pendingValidation = true;
    delay(10000);
    err = esp_ota_set_boot_partition(updatePartition);
    if (err != ESP_OK) {
        Serial.printf("OTA set boot partition failed: %s\n", esp_err_to_name(err));
        publishMQTT(mqtt_topic_firmware, "OTA:ERROR:Set boot failed");
        return;
    }
    Serial.println("OTA successful, restarting...");
    delay(1000);
    otaInProgress = false;
    ESP.restart();
}

void checkMissingChunks() {
    Serial.println("Checking for missing chunks...");
    unsigned long expectedChunks = (otaTotalSize + CHUNK_SIZE - 1) / CHUNK_SIZE;
    String missingMsg = "OTA:REQUEST:";
    bool hasMissing = false;
    for (unsigned long i = 0; i < expectedChunks; i++) {
        if (!receivedChunks[i]) {
            missingMsg += String(i) + ",";
            hasMissing = true;
        }
    }
    if (hasMissing) {
        missingMsg.remove(missingMsg.length() - 1);
        Serial.println("Requesting missing chunks: " + missingMsg);
        publishMQTT(mqtt_topic_send, missingMsg.c_str());
    } else {
        Serial.println("No missing chunks detected");
    }
}

void revertToPreviousFirmware() {
    if (previousPartition == NULL) {
        Serial.println("No previous partition known");
        publishMQTT(mqtt_topic_send, "REVERT:ERROR:No previous partition");
        return;
    }
    const esp_partition_t *current = esp_ota_get_running_partition();
    if (current == previousPartition) {
        Serial.println("Already running previous firmware");
        publishMQTT(mqtt_topic_send, "REVERT:ERROR:Already on previous");
        return;
    }
    esp_err_t err = esp_ota_set_boot_partition(previousPartition);
    if (err != ESP_OK) {
        Serial.printf("Failed to set boot partition: %s\n", esp_err_to_name(err));
        publishMQTT(mqtt_topic_send, "REVERT:ERROR:Set failed");
        return;
    }
    Serial.println("Reverting to previous firmware: " + String(previousPartition->label));
    String revertMsg = String("REVERT:SUCCESS:") + String(previousPartition->label);
    publishMQTT(mqtt_topic_send, revertMsg.c_str());
#ifdef ENABLE_LCD
  
    extern bool lcdAvailable;
    if (lcdAvailable) {
        lcd.clear();
        lcd.print("Reverting...");
    }
#endif
    pendingValidation = false;
    delay(1000);
    ESP.restart();
}