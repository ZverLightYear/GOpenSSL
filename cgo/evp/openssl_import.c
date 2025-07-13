#include "openssl_import.h"
#include <time.h>

// Инициализация OpenSSL
static int openssl_initialized = 0;

static void init_openssl() {
    if (!openssl_initialized) {
        OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
        openssl_initialized = 1;
    }
}

// Создать контекст шифра
go_cipher_ctx_t* go_cipher_new(const char* cipher_name, int is_encrypt, const unsigned char* key, const unsigned char* iv) {
    init_openssl();
    
    go_cipher_ctx_t* ctx = (go_cipher_ctx_t*)malloc(sizeof(go_cipher_ctx_t));
    if (!ctx) return NULL;

    ctx->ctx = EVP_CIPHER_CTX_new();
    if (!ctx->ctx) {
        free(ctx);
        return NULL;
    }

    ctx->is_encrypt = is_encrypt;
    ctx->cipher_name = strdup(cipher_name);

    // Получаем EVP_CIPHER по имени
    const EVP_CIPHER* cipher = EVP_CIPHER_fetch(NULL, cipher_name, NULL);
    if (!cipher) {
        EVP_CIPHER_CTX_free(ctx->ctx);
        free(ctx->cipher_name);
        free(ctx);
        return NULL;
    }

    // Инициализируем контекст
    int key_len = EVP_CIPHER_get_key_length(cipher);
    int iv_len = EVP_CIPHER_get_iv_length(cipher);
    
    if (EVP_CipherInit_ex2(ctx->ctx, cipher, key, iv, is_encrypt, NULL) != 1) {
        EVP_CIPHER_free((EVP_CIPHER*)cipher);
        EVP_CIPHER_CTX_free(ctx->ctx);
        free(ctx->cipher_name);
        free(ctx);
        return NULL;
    }

    EVP_CIPHER_free((EVP_CIPHER*)cipher);
    return ctx;
}

// Получить размер блока по имени шифра
int go_cipher_get_block_size(const char* cipher_name) {
    init_openssl();
    
    const EVP_CIPHER* cipher = EVP_CIPHER_fetch(NULL, cipher_name, NULL);
    if (!cipher) return -1;
    
    int block_size = EVP_CIPHER_get_block_size(cipher);
    EVP_CIPHER_free((EVP_CIPHER*)cipher);
    return block_size;
}

// Шифровать/дешифровать данные
int go_cipher_update(go_cipher_ctx_t* ctx, const unsigned char* in, int in_len, unsigned char* out, int* out_len) {
    if (!ctx || !ctx->ctx) return -1;
    
    return EVP_CipherUpdate(ctx->ctx, out, out_len, in, in_len);
}

// Завершить шифрование/дешифрование
int go_cipher_final(go_cipher_ctx_t* ctx, unsigned char* out, int* out_len) {
    if (!ctx || !ctx->ctx) return -1;
    
    return EVP_CipherFinal_ex(ctx->ctx, out, out_len);
}

// Сбросить контекст
int go_cipher_reset(go_cipher_ctx_t* ctx) {
    if (!ctx || !ctx->ctx) return 0;
    
    return EVP_CIPHER_CTX_reset(ctx->ctx);
}

// Освободить контекст шифра
void go_cipher_free(go_cipher_ctx_t* ctx) {
    if (ctx) {
        if (ctx->ctx) {
            EVP_CIPHER_CTX_free(ctx->ctx);
        }
        if (ctx->cipher_name) {
            free(ctx->cipher_name);
        }
        free(ctx);
    }
}

// Получить размер блока
int go_cipher_block_size(go_cipher_ctx_t* ctx) {
    if (!ctx || !ctx->ctx) return 0;
    
    return EVP_CIPHER_CTX_get_block_size(ctx->ctx);
}

// Получить размер ключа
int go_cipher_key_length(go_cipher_ctx_t* ctx) {
    if (!ctx || !ctx->ctx) return 0;
    
    return EVP_CIPHER_CTX_get_key_length(ctx->ctx);
}

// Структура для хранения контекста хэша
typedef struct {
    EVP_MD_CTX *ctx;
    char *hash_name;
} go_hash_ctx_t;

// Создать контекст хэша
go_hash_ctx_t* go_hash_new(const char* hash_name) {
    init_openssl();
    
    go_hash_ctx_t* ctx = (go_hash_ctx_t*)malloc(sizeof(go_hash_ctx_t));
    if (!ctx) return NULL;

    ctx->ctx = EVP_MD_CTX_new();
    if (!ctx->ctx) {
        free(ctx);
        return NULL;
    }

    ctx->hash_name = strdup(hash_name);

    // Получаем EVP_MD по имени
    const EVP_MD* md = EVP_MD_fetch(NULL, hash_name, NULL);
    if (!md) {
        EVP_MD_CTX_free(ctx->ctx);
        free(ctx->hash_name);
        free(ctx);
        return NULL;
    }

    // Инициализируем контекст
    if (EVP_DigestInit_ex2(ctx->ctx, md, NULL) != 1) {
        EVP_MD_free((EVP_MD*)md);
        EVP_MD_CTX_free(ctx->ctx);
        free(ctx->hash_name);
        free(ctx);
        return NULL;
    }

    EVP_MD_free((EVP_MD*)md);
    return ctx;
}

// Обновить хэш данными
int go_hash_update(go_hash_ctx_t* ctx, const unsigned char* data, int data_len) {
    if (!ctx || !ctx->ctx) return -1;
    
    return EVP_DigestUpdate(ctx->ctx, data, data_len);
}

// Завершить хэширование
int go_hash_final(go_hash_ctx_t* ctx, unsigned char* out, unsigned int* out_len) {
    if (!ctx || !ctx->ctx) return -1;
    
    return EVP_DigestFinal_ex(ctx->ctx, out, out_len);
}

// Сбросить контекст
int go_hash_reset(go_hash_ctx_t* ctx) {
    if (!ctx || !ctx->ctx) return 0;
    
    return EVP_MD_CTX_reset(ctx->ctx);
}

// Освободить контекст хэша
void go_hash_free(go_hash_ctx_t* ctx) {
    if (ctx) {
        if (ctx->ctx) {
            EVP_MD_CTX_free(ctx->ctx);
        }
        if (ctx->hash_name) {
            free(ctx->hash_name);
        }
        free(ctx);
    }
}

// Получить размер хэша
int go_hash_size(go_hash_ctx_t* ctx) {
    if (!ctx || !ctx->ctx) return 0;
    
    return EVP_MD_CTX_get_size(ctx->ctx);
}

// Получить размер хэша по имени
int go_hash_get_size(const char* hash_name) {
    init_openssl();
    
    const EVP_MD* md = EVP_MD_fetch(NULL, hash_name, NULL);
    if (!md) return -1;
    
    int size = EVP_MD_get_size(md);
    EVP_MD_free((EVP_MD*)md);
    return size;
}

// Освободить память
void go_free(void* ptr) {
    free(ptr);
}

// Упрощенная функция для получения списка шифров
char** go_get_cipher_list(int* count) {
    init_openssl();
    
    *count = 0;
    char** list = (char**)malloc(10 * sizeof(char*));
    if (!list) return NULL;
    
    // Добавляем основные шифры
    list[0] = strdup("AES-128-ECB");
    list[1] = strdup("AES-192-ECB");
    list[2] = strdup("AES-256-ECB");
    list[3] = strdup("AES-128-CBC");
    list[4] = strdup("AES-192-CBC");
    list[5] = strdup("AES-256-CBC");
    list[6] = strdup("AES-128-GCM");
    list[7] = strdup("AES-256-GCM");
    list[8] = strdup("DES-ECB");
    list[9] = strdup("DES-CBC");
    
    *count = 10;
    return list;
}

// Упрощенная функция для получения списка хэш-функций
char** go_get_hash_list(int* count) {
    init_openssl();
    
    *count = 0;
    char** list = (char**)malloc(8 * sizeof(char*));
    if (!list) return NULL;
    
    // Добавляем основные хэш-функции
    list[0] = strdup("MD5");
    list[1] = strdup("SHA1");
    list[2] = strdup("SHA256");
    list[3] = strdup("SHA384");
    list[4] = strdup("SHA512");
    list[5] = strdup("SHA3-256");
    list[6] = strdup("SHA3-512");
    list[7] = strdup("BLAKE2b512");
    
    *count = 8;
    return list;
}

// Освободить список строк
void go_free_string_list(char** list, int count) {
    if (list) {
        for (int i = 0; i < count; i++) {
            if (list[i]) {
                free(list[i]);
            }
        }
        free(list);
    }
}
