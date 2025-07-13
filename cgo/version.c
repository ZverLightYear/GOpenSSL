#include "version.h"

// Версия OpenSSL
const char* go_openssl_version() {
    return OPENSSL_VERSION_STR;
}
