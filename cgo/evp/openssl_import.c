#include "openssl_import.h"
#include <time.h>


// Коллектор для имён EVP-шифров (заглушка)
static void cipher_collector(const EVP_CIPHER *ciph, const char *from, const char *to, void *arg) {
    // Заглушка - не делаем ничего
}

// Коллектор для имён EVP-хэш функций (заглушка)
static void digest_collector(const EVP_MD *md, const char *from, const char *to, void *arg) {
    // Заглушка - не делаем ничего
}

// Создать контекст шифра (заглушка)
go_cipher_ctx_t* go_cipher_new(const char* cipher_name, int is_encrypt, const unsigned char* key, const unsigned char* iv) {
    go_cipher_ctx_t* ctx = (go_cipher_ctx_t*)malloc(sizeof(go_cipher_ctx_t));
    if (!ctx) return NULL;

    ctx->ctx = malloc(1); // Просто указатель для совместимости
    ctx->is_encrypt = is_encrypt;
    ctx->cipher_name = strdup(cipher_name);

    fprintf(stderr, "Created cipher context for: %s\n", cipher_name);
    return ctx;
}

// Получить размер блока по имени шифра (заглушка)
int go_cipher_get_block_size(const char* cipher_name) {
    if (strstr(cipher_name, "AES")) {
        return 16;
    } else if (strstr(cipher_name, "DES")) {
        return 8;
    }
    return 16; // По умолчанию
}

// Шифровать/дешифровать данные (заглушка)
int go_cipher_update(go_cipher_ctx_t* ctx, const unsigned char* in, int in_len, unsigned char* out, int* out_len) {
    if (!ctx || !ctx->ctx) return 0;

    // Просто копируем данные без шифрования
    memcpy(out, in, in_len);
    *out_len = in_len;
    return 1;
}

// Завершить шифрование/дешифрование (заглушка)
int go_cipher_final(go_cipher_ctx_t* ctx, unsigned char* out, int* out_len) {
    if (!ctx || !ctx->ctx) return 0;

    *out_len = 0;
    return 1;
}

// Сбросить контекст (заглушка)
int go_cipher_reset(go_cipher_ctx_t* ctx) {
    if (!ctx || !ctx->ctx) return 0;
    return 1;
}

// Освободить контекст (заглушка)
void go_cipher_free(go_cipher_ctx_t* ctx) {
    if (ctx) {
        if (ctx->ctx) {
            free(ctx->ctx);
        }
        if (ctx->cipher_name) {
            free(ctx->cipher_name);
        }
        free(ctx);
    }
}

// Получить размер блока (заглушка)
int go_cipher_block_size(go_cipher_ctx_t* ctx) {
    if (!ctx || !ctx->ctx) return 0;
    return 16; // По умолчанию AES размер
}

// Получить размер ключа (заглушка)
int go_cipher_key_length(go_cipher_ctx_t* ctx) {
    if (!ctx || !ctx->ctx) return 0;
    return 32; // По умолчанию 256 бит
}

// Создать контекст хэша (заглушка)
go_hash_ctx_t* go_hash_new(const char* digest_name) {
    go_hash_ctx_t* ctx = (go_hash_ctx_t*)malloc(sizeof(go_hash_ctx_t));
    if (!ctx) return NULL;

    ctx->ctx = malloc(1); // Просто указатель для совместимости
    ctx->digest_name = strdup(digest_name);

    fprintf(stderr, "Created hash context for: %s\n", digest_name);
    return ctx;
}

// Обновить хэш (заглушка)
int go_hash_update(go_hash_ctx_t* ctx, const unsigned char* data, int len) {
    if (!ctx || !ctx->ctx) return 0;
    return 1;
}

// Завершить хэш (заглушка)
int go_hash_final(go_hash_ctx_t* ctx, unsigned char* out, unsigned int* out_len) {
    if (!ctx || !ctx->ctx) return 0;

    // Возвращаем фиктивный хэш
    if (strstr(ctx->digest_name, "SHA256")) {
        *out_len = 32;
        memset(out, 0xAA, 32);
    } else if (strstr(ctx->digest_name, "SHA1")) {
        *out_len = 20;
        memset(out, 0xBB, 20);
    } else if (strstr(ctx->digest_name, "MD5")) {
        *out_len = 16;
        memset(out, 0xCC, 16);
    } else {
        *out_len = 32;
        memset(out, 0xDD, 32);
    }
    return 1;
}

// Сбросить контекст (заглушка)
int go_hash_reset(go_hash_ctx_t* ctx) {
    if (!ctx || !ctx->ctx) return 0;
    return 1;
}

// Освободить контекст (заглушка)
void go_hash_free(go_hash_ctx_t* ctx) {
    if (ctx) {
        if (ctx->ctx) {
            free(ctx->ctx);
        }
        if (ctx->digest_name) {
            free(ctx->digest_name);
        }
        free(ctx);
    }
}

// Получить размер хэша (заглушка)
int go_hash_size(go_hash_ctx_t* ctx) {
    if (!ctx || !ctx->ctx) return 0;
    
    if (strstr(ctx->digest_name, "SHA256")) {
        return 32;
    } else if (strstr(ctx->digest_name, "SHA1")) {
        return 20;
    } else if (strstr(ctx->digest_name, "MD5")) {
        return 16;
    }
    return 32; // По умолчанию
}

// Получить размер хэша по имени (заглушка)
int go_hash_get_size(const char* digest_name) {
    if (strstr(digest_name, "SHA256")) {
        return 32;
    } else if (strstr(digest_name, "SHA1")) {
        return 20;
    } else if (strstr(digest_name, "MD5")) {
        return 16;
    }
    return 32; // По умолчанию
}

// Освободить память
void go_free(void* ptr) {
    free(ptr);
}
