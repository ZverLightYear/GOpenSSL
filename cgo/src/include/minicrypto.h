#ifndef MINICRYPTO_H
#define MINICRYPTO_H

#include <stdint.h>
#include <openssl/aes.h>

int aes_ecb_encrypt(const uint8_t *in, uint8_t *out, const uint8_t *key, int key_len);
int aes_ecb_decrypt(const uint8_t *in, uint8_t *out, const uint8_t *key, int key_len);
int aes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len, const uint8_t *key, int key_len, const uint8_t *iv);
int aes_cbc_decrypt(const uint8_t *in, uint8_t *out, size_t len, const uint8_t *key, int key_len, const uint8_t *iv);

#endif
