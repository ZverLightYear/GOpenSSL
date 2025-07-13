#ifndef OPENSSL_IMPORT_H
#define OPENSSL_IMPORT_H

// Минимальная заглушка для OpenSSL API
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Заглушки для OpenSSL типов
typedef struct evp_cipher_st EVP_CIPHER;
typedef struct evp_md_st EVP_MD;
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
typedef struct evp_md_ctx_st EVP_MD_CTX;
typedef struct engine_st ENGINE;
typedef struct ossl_provider_st OSSL_PROVIDER;

// Структура для хранения контекста шифра
typedef struct {
    void *ctx;
    int is_encrypt;
    char *cipher_name;
} go_cipher_ctx_t;

// Создать контекст шифра (заглушка)
go_cipher_ctx_t* go_cipher_new(const char* cipher_name, int is_encrypt, const unsigned char* key, const unsigned char* iv);

// Получить размер блока по имени шифра (заглушка)
int go_cipher_get_block_size(const char* cipher_name);

// Шифровать/дешифровать данные (заглушка)
int go_cipher_update(go_cipher_ctx_t* ctx, const unsigned char* in, int in_len, unsigned char* out, int* out_len);

// Завершить шифрование/дешифрование (заглушка)
int go_cipher_final(go_cipher_ctx_t* ctx, unsigned char* out, int* out_len);

// Сбросить контекст (заглушка)
int go_cipher_reset(go_cipher_ctx_t* ctx);

// Освободить контекст (заглушка)
void go_cipher_free(go_cipher_ctx_t* ctx);

// Получить размер блока (заглушка)
int go_cipher_block_size(go_cipher_ctx_t* ctx);

// Получить размер ключа (заглушка)
int go_cipher_key_length(go_cipher_ctx_t* ctx);

// Структура для хранения контекста хэша
typedef struct {
    void *ctx;
    char *digest_name;
} go_hash_ctx_t;

// Создать контекст хэша (заглушка)
go_hash_ctx_t* go_hash_new(const char* digest_name);

// Обновить хэш (заглушка)
int go_hash_update(go_hash_ctx_t* ctx, const unsigned char* data, int len);

// Завершить хэш (заглушка)
int go_hash_final(go_hash_ctx_t* ctx, unsigned char* out, unsigned int* out_len);

// Сбросить контекст (заглушка)
int go_hash_reset(go_hash_ctx_t* ctx);

// Освободить контекст (заглушка)
void go_hash_free(go_hash_ctx_t* ctx);

// Получить размер хэша (заглушка)
int go_hash_size(go_hash_ctx_t* ctx);

// Получить размер хэша по имени (заглушка)
int go_hash_get_size(const char* digest_name);
// Освободить память
void go_free(void* ptr);

#endif // OPENSSL_IMPORT_C 