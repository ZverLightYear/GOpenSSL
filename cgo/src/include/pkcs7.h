#ifndef PKCS7_H
#define PKCS7_H

#include <stdint.h>
#include <openssl/objects.h>
#include <openssl/pkcs7.h>

int pkcs7_pad_len(size_t len, int block_size);
int pkcs7_pad(uint8_t *data, size_t len, int block_size);
int pkcs7_unpad(const uint8_t *data, size_t len, int *out_len);

#endif
