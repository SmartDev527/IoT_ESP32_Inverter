#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <Arduino.h>
#include "mbedtls/aes.h"

String base64_encode(const unsigned char *input, size_t len);
size_t base64_decode(const char *input, unsigned char *output, size_t out_len);
void pkcs7_pad(unsigned char *data, size_t data_len, size_t block_size);
size_t pkcs7_unpad(unsigned char *data, size_t data_len);
String encryptMessage(const char *message);
String decryptMessage(const char *encryptedBase64);

#endif