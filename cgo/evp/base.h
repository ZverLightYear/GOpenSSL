#ifndef BASE_H
#define BASE_H

// Функции для получения списков алгоритмов
char** get_available_ciphers(int* count);
char** get_available_digests(int* count);
void free_string_list(char** list, int count);

// Функции для получения информации о OpenSSL
const char* get_openssl_version();
const char* get_openssl_build_info();
const char* get_openssl_compiler_info();

#endif // BASE_H
