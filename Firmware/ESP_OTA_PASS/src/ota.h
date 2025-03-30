#ifndef OTA_H
#define OTA_H

#include <Arduino.h>
#include <esp_ota_ops.h>
#include <vector>       // For std::vector
#include <map>          // For std::map
#include "mbedtls/sha256.h"

extern bool otaInProgress;
extern unsigned long otaReceivedSize;
extern unsigned long otaTotalSize;
extern unsigned long chunkCount;
extern std::vector<unsigned long> missingChunks;
extern std::map<unsigned long, bool> receivedChunks;
extern esp_ota_handle_t otaHandle;
extern const esp_partition_t *updatePartition;
extern const esp_partition_t *previousPartition;
extern bool pendingValidation;
extern String otaHash;
extern mbedtls_sha256_context sha256_ctx;

void startOTA(uint32_t totalSize);
void processOTAFirmware(const String &topic, byte *payload, unsigned int dataLen);
void finishOTA();
void checkMissingChunks();
void revertToPreviousFirmware();

#endif