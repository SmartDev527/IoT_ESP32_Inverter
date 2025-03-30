#ifndef MODEM_H
#define MODEM_H

#include <Arduino.h>
#include <driver/uart.h>
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <freertos/queue.h>
#include "config.h"
#include "certificates.h" // Include for root_ca

extern QueueHandle_t uartQueue;

void setupModem();
bool sendAT(const char* cmd, String& response, uint32_t timeout_ms = 1000, const char* expected = "OK");
void resetModem();
void processURC(String urc);
bool uploadCertificate();
bool setupSSL();

#endif