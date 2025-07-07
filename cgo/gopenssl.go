package gopenssl

/*
#cgo CFLAGS: -I${SRCDIR}/../submodules/build/include
#cgo LDFLAGS: -L${SRCDIR}/../submodules/build/lib -lssl -lcrypto -ldl
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

// Обёртка для получения версии OpenSSL
const char* go_openssl_version() {
    return OpenSSL_version(OPENSSL_VERSION);
}

// Получить список SSL ciphersuites (аналог openssl ciphers)
int go_list_ssl_ciphers(char **out, int max) {
    SSL_CTX *ctx = SSL_CTX_new(TLS_method());
    if (!ctx) return 0;
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return 0;
    }
    STACK_OF(SSL_CIPHER) *ciphers = SSL_get_ciphers(ssl);
    int n = sk_SSL_CIPHER_num(ciphers);
    int count = n < max ? n : max;
    for (int i = 0; i < count; i++) {
        const SSL_CIPHER *cipher = sk_SSL_CIPHER_value(ciphers, i);
        const char *name = SSL_CIPHER_get_name(cipher);
        size_t len = strlen(name);
        char *copy = (char*)malloc(len+1);
        strcpy(copy, name);
        out[i] = copy;
    }
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    return count;
}
*/
import "C"
import (
	"unsafe"
)

func OpenSSLVersion() string {
	return C.GoString(C.go_openssl_version())
}

func ListSSLCiphers() []string {
	max := 256
	out := make([]*C.char, max)
	count := int(C.go_list_ssl_ciphers((**C.char)(unsafe.Pointer(&out[0])), C.int(max)))
	ciphers := make([]string, 0, count)
	for i := 0; i < count && out[i] != nil; i++ {
		ciphers = append(ciphers, C.GoString(out[i]))
		C.free(unsafe.Pointer(out[i]))
	}
	return ciphers
}
