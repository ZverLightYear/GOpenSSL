package cgopenssl

/*
#cgo CFLAGS: -I${SRCDIR}/../../submodules/build/include -Wno-deprecated-declarations
#cgo LDFLAGS: -L${SRCDIR}/../../submodules/build/lib -lssl -lcrypto -ldl
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>

// Коллектор для имён EVP-шифров
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

// Получить список EVP-шифров
int go_list_ciphers(char **out, int max) {
    int count = 0;
    char **ptr = out;
    EVP_CIPHER_do_all_sorted(cipher_collector, &ptr);
    count = ptr - out;
    return count < max ? count : max;
}
*/
import "C"
import (
	"unsafe"
)

// ListCiphers возвращает список доступных шифров
func ListCiphers() []string {
	const max = 256
	var arr [max]*C.char
	n := C.go_list_ciphers((**C.char)(unsafe.Pointer(&arr[0])), C.int(max))
	out := make([]string, 0, int(n))
	for i := 0; i < int(n); i++ {
		if arr[i] != nil {
			out = append(out, C.GoString(arr[i]))
			C.free(unsafe.Pointer(arr[i]))
		}
	}
	return out
}
