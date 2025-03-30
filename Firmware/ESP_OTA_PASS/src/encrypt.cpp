#include "encrypt.h"
#include "config.h"

static const char base64_enc_map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char base64_dec_map[128] = {
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127,
    127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 127, 62, 127, 127, 127, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 127, 127, 127, 64, 127, 127,
    127, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 127, 127, 127, 127, 127,
    127, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 127, 127, 127, 127, 127};

String base64_encode(const unsigned char *input, size_t len) {
    String output = "";
    int i = 0, j = 0;
    unsigned char char_array_3[3], char_array_4[4];
    while (i < len) {
        char_array_3[j++] = input[i++];
        if (j == 3 || i == len) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((j > 1 ? char_array_3[1] : 0) >> 4);
            char_array_4[2] = j > 1 ? ((char_array_3[1] & 0x0f) << 2) + ((j > 2 ? char_array_3[2] : 0) >> 6) : 0;
            char_array_4[3] = j > 2 ? (char_array_3[2] & 0x3f) : 0;
            for (int k = 0; k < (j + 1); k++) {
                output += base64_enc_map[char_array_4[k]];
            }
            while (j++ < 3) output += '=';
            j = 0;
        }
    }
    return output;
}

size_t base64_decode(const char *input, unsigned char *output, size_t out_len) {
    size_t in_len = strlen(input);
    if (in_len % 4 != 0) return 0;
    size_t out_pos = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        uint32_t n = (base64_dec_map[(unsigned char)input[i]] << 18) +
                     (base64_dec_map[(unsigned char)input[i + 1]] << 12) +
                     (base64_dec_map[(unsigned char)input[i + 2]] << 6) +
                     base64_dec_map[(unsigned char)input[i + 3]];
        if (out_pos + 3 > out_len) return 0;
        output[out_pos++] = (n >> 16) & 0xFF;
        if (input[i + 2] != '=') output[out_pos++] = (n >> 8) & 0xFF;
        if (input[i + 3] != '=') output[out_pos++] = n & 0xFF;
    }
    return out_pos;
}

void pkcs7_pad(unsigned char *data, size_t data_len, size_t block_size) {
    unsigned char pad_value = block_size - (data_len % block_size);
    for (size_t i = data_len; i < data_len + pad_value; i++) {
        data[i] = pad_value;
    }
}

size_t pkcs7_unpad(unsigned char *data, size_t data_len) {
    unsigned char pad_value = data[data_len - 1];
    if (pad_value > 16 || pad_value > data_len) return data_len;
    return data_len - pad_value;
}

String encryptMessage(const char *message) {
    if (!message) return "";
    size_t input_len = strlen(message);
    if (input_len == 0) return "";
    size_t padded_len = ((input_len + 15) / 16) * 16;
    if (padded_len > 1024) {
        Serial.println("Message too long: " + String(input_len));
        return "";
    }
    unsigned char *padded_input = new unsigned char[padded_len]();
    if (!padded_input) return "";
    memcpy(padded_input, message, input_len);
    pkcs7_pad(padded_input, input_len, 16);
    unsigned char *output_buffer = new unsigned char[padded_len]();
    if (!output_buffer) {
        delete[] padded_input;
        return "";
    }
    mbedtls_aes_context aes;
    unsigned char iv[16];
    memcpy(iv, aes_iv, 16);
    mbedtls_aes_init(&aes);
    int key_ret = mbedtls_aes_setkey_enc(&aes, aes_key, 256);
    if (key_ret != 0) {
        delete[] padded_input;
        delete[] output_buffer;
        return "";
    }
    int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, padded_len, iv, padded_input, output_buffer);
    mbedtls_aes_free(&aes);
    String result;
    if (ret == 0) {
        result = base64_encode(output_buffer, padded_len);
    }
    delete[] padded_input;
    delete[] output_buffer;
    return result;
}

String decryptMessage(const char *encryptedBase64) {
    if (!encryptedBase64 || strlen(encryptedBase64) == 0) return "";
    size_t max_input_len = strlen(encryptedBase64);
    if (max_input_len > 1024) return "";
    unsigned char *encrypted_bytes = new unsigned char[max_input_len]();
    if (!encrypted_bytes) return "";
    size_t decoded_len = base64_decode(encryptedBase64, encrypted_bytes, max_input_len);
    if (decoded_len == 0 || decoded_len % 16 != 0) {
        delete[] encrypted_bytes;
        return "";
    }
    unsigned char *output_buffer = new unsigned char[decoded_len]();
    if (!output_buffer) {
        delete[] encrypted_bytes;
        return "";
    }
    mbedtls_aes_context aes;
    unsigned char iv[16];
    memcpy(iv, aes_iv, 16);
    mbedtls_aes_init(&aes);
    int key_ret = mbedtls_aes_setkey_dec(&aes, aes_key, 256);
    if (key_ret != 0) {
        delete[] encrypted_bytes;
        delete[] output_buffer;
        return "";
    }
    int ret = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, decoded_len, iv, encrypted_bytes, output_buffer);
    mbedtls_aes_free(&aes);
    String result;
    if (ret == 0) {
        size_t unpadded_len = pkcs7_unpad(output_buffer, decoded_len);
        result = String((char *)output_buffer, unpadded_len);
    }
    delete[] encrypted_bytes;
    delete[] output_buffer;
    return result;
}