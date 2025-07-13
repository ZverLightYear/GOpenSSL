#include "base.h"
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include <openssl/core_names.h>
#include <openssl/types.h>
#include <stdlib.h>
#include <string.h>

// Инициализация OpenSSL
static int openssl_initialized = 0;

static void init_openssl() {
    if (!openssl_initialized) {
        OPENSSL_init_crypto(OPENSSL_INIT_ADD_ALL_CIPHERS | OPENSSL_INIT_ADD_ALL_DIGESTS, NULL);
        openssl_initialized = 1;
    }
}

// Структура для сбора имен шифров
typedef struct {
    char** names;
    int count;
    int capacity;
} cipher_collector_t;

// Callback функция для EVP_CIPHER_do_all_provided
static void collect_cipher_name(EVP_CIPHER* cipher, void* arg) {
    cipher_collector_t* collector = (cipher_collector_t*)arg;
    
    // Получаем имена шифра
    STACK_OF(OPENSSL_CSTRING)* names = sk_OPENSSL_CSTRING_new_null();
    if (names == NULL) return;
    
    EVP_CIPHER_names_do_all(cipher, collect_names, names);
        int num_names = sk_OPENSSL_CSTRING_num(names);
        for (int i = 0; i < num_names; i++) {
            const char* name = sk_OPENSSL_CSTRING_value(names, i);
            if (name != NULL) {
                // Проверяем, нужно ли расширить массив
                if (collector->count >= collector->capacity) {
                    int new_capacity = collector->capacity * 2;
                    if (new_capacity == 0) new_capacity = 10;
                    
                    char** new_names = realloc(collector->names, new_capacity * sizeof(char*));
                    if (new_names == NULL) {
                        sk_OPENSSL_CSTRING_free(names);
                        return;
                    }
                    collector->names = new_names;
                    collector->capacity = new_capacity;
                }
                
                collector->names[collector->count] = strdup(name);
                collector->count++;
            }
        }
    }
    
    sk_OPENSSL_CSTRING_free(names);
}

// Callback функция для сбора имен
static void collect_names(const char* name, void* arg) {
    STACK_OF(OPENSSL_CSTRING)* names = (STACK_OF(OPENSSL_CSTRING)*)arg;
    sk_OPENSSL_CSTRING_push(names, name);
}

// Получить список доступных шифров
char** get_available_ciphers(int* count) {
    init_openssl();
    
    cipher_collector_t collector = {NULL, 0, 0};
    
    // Перечисляем все доступные шифры
    EVP_CIPHER_do_all_provided(NULL, collect_cipher_name, &collector);
    
    *count = collector.count;
    return collector.names;
}

// Структура для сбора имен хэш-функций
typedef struct {
    char** names;
    int count;
    int capacity;
} digest_collector_t;

// Callback функция для EVP_MD_do_all_provided
static void collect_digest_name(EVP_MD* md, void* arg) {
    digest_collector_t* collector = (digest_collector_t*)arg;
    
    // Получаем имена хэш-функции
    STACK_OF(OPENSSL_CSTRING)* names = sk_OPENSSL_CSTRING_new_null();
    if (names == NULL) return;
    
    EVP_MD_names_do_all(md, collect_names, names);
        int num_names = sk_OPENSSL_CSTRING_num(names);
        for (int i = 0; i < num_names; i++) {
            const char* name = sk_OPENSSL_CSTRING_value(names, i);
            if (name != NULL) {
                // Проверяем, нужно ли расширить массив
                if (collector->count >= collector->capacity) {
                    int new_capacity = collector->capacity * 2;
                    if (new_capacity == 0) new_capacity = 10;
                    
                    char** new_names = realloc(collector->names, new_capacity * sizeof(char*));
                    if (new_names == NULL) {
                        sk_OPENSSL_CSTRING_free(names);
                        return;
                    }
                    collector->names = new_names;
                    collector->capacity = new_capacity;
                }
                
                collector->names[collector->count] = strdup(name);
                collector->count++;
            }
        }
    }
    
    sk_OPENSSL_CSTRING_free(names);
}

// Получить список доступных хэш-функций
char** get_available_digests(int* count) {
    init_openssl();
    
    digest_collector_t collector = {NULL, 0, 0};
    
    // Перечисляем все доступные хэш-функции
    EVP_MD_do_all_provided(NULL, collect_digest_name, &collector);
    
    *count = collector.count;
    return collector.names;
}

// Освободить список строк
void free_string_list(char** list, int count) {
    if (list) {
        for (int i = 0; i < count; i++) {
            if (list[i]) {
                free(list[i]);
            }
        }
        free(list);
    }
}

// Получить версию OpenSSL
const char* get_openssl_version() {
    return OpenSSL_version(OPENSSL_VERSION);
}

// Получить информацию о сборке OpenSSL
const char* get_openssl_build_info() {
    return OpenSSL_version(OPENSSL_BUILT_ON);
}

// Получить информацию о компиляторе
const char* get_openssl_compiler_info() {
    return OpenSSL_version(OPENSSL_CFLAGS);
}