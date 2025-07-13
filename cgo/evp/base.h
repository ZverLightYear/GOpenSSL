#ifndef OPENSSL_EVP_BASE_H
#define OPENSSL_EVP_BASE_H

#include <stdlib.h>
#include <string.h>

// Получить список EVP-шифров
int go_list_ciphers(char **out, int max);

// Получить список EVP-хэшей
int go_list_hashes(char **out, int max);

#endif // OPENSSL_EVP_BASE_H
