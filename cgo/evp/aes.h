#ifndef OPENSSL_CGO_EVP_AES_H
#define OPENSSL_CGO_EVP_AES_H

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

int aes_init(
    unsigned char *key_data,
    int key_data_len,
    unsigned char *salt,
    EVP_CIPHER_CTX *e_ctx,
    EVP_CIPHER_CTX *d_ctx,
);

unsigned char *aes_encrypt(
    EVP_CIPHER_CTX *e,
    unsigned char *plaintext,
    int *len,
);

unsigned char *aes_decrypt(
    EVP_CIPHER_CTX *e,
    unsigned char *ciphertext,
    int *len,
);

#endif // OPENSSL_CGO_EVP_AES_H
