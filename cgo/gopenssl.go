package gopenssl

/*
#cgo CFLAGS: -I${SRCDIR}/../submodules/build/include
#cgo LDFLAGS: -L${SRCDIR}/../submodules/build/lib -lssl -lcrypto -ldl
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <stdlib.h>

// Обёртка для получения версии OpenSSL
const char* go_openssl_version() {
    return OpenSSL_version(OPENSSL_VERSION);
}

// Коллектор для имён шифров
static void cipher_collector(const EVP_CIPHER *ciph, const char *from, const char *to, void *arg) {
    if (ciph == NULL) return;
    char ***list = (char ***)arg;
    const char *name = EVP_CIPHER_name(ciph);
    if (name) {
        size_t len = strlen(name);
        char *copy = (char*)malloc(len+1);
        strcpy(copy, name);
        (*list)[0] = copy;
        (*list)++;
    }
}

// Получить список шифров
int go_list_ciphers(char **out, int max) {
    char **ptr = out;
    int count = 0;
    void *arg = &ptr;
    EVP_CIPHER_do_all_sorted(cipher_collector, &ptr);
    return (int)(ptr - out);
}
*/
import "C"
import (
	"unsafe"
)

func OpenSSLVersion() string {
	return C.GoString(C.go_openssl_version())
}

func ListCiphers() []string {
	max := 256
	out := make([]*C.char, max)
	count := int(C.go_list_ciphers((**C.char)(unsafe.Pointer(&out[0])), C.int(max)))
	ciphers := make([]string, 0, count)
	for i := 0; i < count && out[i] != nil; i++ {
		ciphers = append(ciphers, C.GoString(out[i]))
		C.free(unsafe.Pointer(out[i]))
	}
	return ciphers
}
