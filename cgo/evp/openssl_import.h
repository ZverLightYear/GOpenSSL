#ifndef OPENSSL_IMPORT_H
#define OPENSSL_IMPORT_H

// Реальные OpenSSL заголовки
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/engine.h>
#include <openssl/provider.h>
#include <openssl/core_names.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Структура для хранения контекста шифра
typedef struct {
    EVP_CIPHER_CTX *ctx;
    int is_encrypt;
    char *cipher_name;
} go_cipher_ctx_t;

// Структура для хранения контекста хэша
typedef struct {
    EVP_MD_CTX *ctx;
    char *hash_name;
} go_hash_ctx_t;

// Функции для работы с шифрами
go_cipher_ctx_t* go_cipher_new(const char* cipher_name, int is_encrypt, const unsigned char* key, const unsigned char* iv);
int go_cipher_get_block_size(const char* cipher_name);
int go_cipher_update(go_cipher_ctx_t* ctx, const unsigned char* in, int in_len, unsigned char* out, int* out_len);
int go_cipher_final(go_cipher_ctx_t* ctx, unsigned char* out, int* out_len);
void go_cipher_free(go_cipher_ctx_t* ctx);
int go_cipher_reset(go_cipher_ctx_t* ctx);
int go_cipher_block_size(go_cipher_ctx_t* ctx);
int go_cipher_key_length(go_cipher_ctx_t* ctx);

// Функции для работы с хэшами
go_hash_ctx_t* go_hash_new(const char* hash_name);
int go_hash_update(go_hash_ctx_t* ctx, const unsigned char* data, int data_len);
int go_hash_final(go_hash_ctx_t* ctx, unsigned char* out, unsigned int* out_len);
int go_hash_get_size(const char* hash_name);
void go_hash_free(go_hash_ctx_t* ctx);
int go_hash_reset(go_hash_ctx_t* ctx);
int go_hash_size(go_hash_ctx_t* ctx);

// Функции для получения списков алгоритмов
char** go_get_cipher_list(int* count);
char** go_get_hash_list(int* count);
void go_free_string_list(char** list, int count);

#endif // OPENSSL_IMPORT_H 