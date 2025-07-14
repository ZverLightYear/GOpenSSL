#include "include/minicrypto.h"

int aes_ecb_encrypt(const uint8_t *in, uint8_t *out, const uint8_t *key, int key_len) {
    AES_KEY enc_key;
    if (AES_set_encrypt_key(key, key_len * 8, &enc_key) != 0) return -1;
    AES_ecb_encrypt(in, out, &enc_key, AES_ENCRYPT);
    return 0;
}

int aes_ecb_decrypt(const uint8_t *in, uint8_t *out, const uint8_t *key, int key_len) {
    AES_KEY dec_key;
    if (AES_set_decrypt_key(key, key_len * 8, &dec_key) != 0) return -1;
    AES_ecb_encrypt(in, out, &dec_key, AES_DECRYPT);
    return 0;
}

int aes_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len, const uint8_t *key, int key_len, const uint8_t *iv) {
    AES_KEY enc_key;
    if (AES_set_encrypt_key(key, key_len * 8, &enc_key) != 0) return -1;
    AES_cbc_encrypt(in, out, len, &enc_key, (uint8_t *)iv, AES_ENCRYPT);
    return 0;
}

int aes_cbc_decrypt(const uint8_t *in, uint8_t *out, size_t len, const uint8_t *key, int key_len, const uint8_t *iv) {
    AES_KEY dec_key;
    if (AES_set_decrypt_key(key, key_len * 8, &dec_key) != 0) return -1;
    AES_cbc_encrypt(in, out, len, &dec_key, (uint8_t *)iv, AES_DECRYPT);
    return 0;
}
