#include "include/pkcs7.h"


/* PKCS7 padding: return new size (len + pad) */
int pkcs7_pad_len(size_t len, int block_size) {
    int pad = block_size - (len % block_size);
    return (int)(len + pad);
}

/* in-place PKCS7 padding */
int pkcs7_pad(uint8_t *data, size_t len, int block_size) {
    int pad = block_size - (len % block_size);
    if (pad == 0) pad = block_size;
    for (int i = 0; i < pad; ++i)
        data[len + i] = (uint8_t)pad;
    return 0;
}

/* PKCS7 unpad: return new length (original len) */
int pkcs7_unpad(const uint8_t *data, size_t len, int *out_len) {
    if (len == 0 || len % 16 != 0) return -1;
    uint8_t pad = data[len - 1];
    if (pad == 0 || pad > 16) return -1;
    for (size_t i = len - pad; i < len; ++i)
        if (data[i] != pad) return -1;
    *out_len = (int)(len - pad);
    return 0;
}