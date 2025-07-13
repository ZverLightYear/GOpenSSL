#include "base.h"

// Получить список EVP-шифров (заглушка)
int go_list_ciphers(char **out, int max) {
    if (max >= 1) {
        out[0] = strdup("AES-256-CBC");
    }
    if (max >= 2) {
        out[1] = strdup("AES-128-CBC");
    }
    if (max >= 3) {
        out[2] = strdup("DES-CBC");
    }
    return max >= 3 ? 3 : max;
}

// Получить список EVP-хэш функций (заглушка)
int go_list_hashes(char **out, int max) {
    if (max >= 1) {
        out[0] = strdup("SHA256");
    }
    if (max >= 2) {
        out[1] = strdup("SHA1");
    }
    if (max >= 3) {
        out[2] = strdup("MD5");
    }
    return max >= 3 ? 3 : max;
}