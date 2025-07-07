package gopenssl

/*
#cgo CFLAGS: -I${SRCDIR}/../submodules/build/include -Wno-deprecated-declarations
#cgo LDFLAGS: -L${SRCDIR}/../submodules/build/lib -lssl -lcrypto -ldl
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <openssl/engine.h>
#include <stdlib.h>
#include <string.h>

// Глобальная переменная для отслеживания инициализации
static int go_openssl_initialized = 0;

// Принудительная загрузка legacy provider при инициализации
__attribute__((constructor))
static void go_force_legacy_provider() {
    OSSL_PROVIDER_load(NULL, "legacy");
}

// Инициализация legacy provider и gost-engine (только один раз)
static void go_init_legacy_provider_once() {
    if (go_openssl_initialized) {
        return; // Уже инициализировано
    }

    // Загружаем legacy provider
    OSSL_PROVIDER* legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy) {
        // Если не удалось загрузить, попробуем загрузить по пути
        legacy = OSSL_PROVIDER_load(NULL, "${SRCDIR}/../submodules/build/lib/ossl-modules/legacy.dylib");
    }

    // Загружаем gost-engine
    ENGINE_load_builtin_engines();
    ENGINE* gost_engine = ENGINE_by_id("gost");
    if (gost_engine) {
        if (ENGINE_init(gost_engine)) {
            ENGINE_set_default(gost_engine, ENGINE_METHOD_ALL);
        }
        ENGINE_free(gost_engine);
    }

    go_openssl_initialized = 1;
}

// Получить версию OpenSSL
const char* go_openssl_version() {
    return OpenSSL_version(OPENSSL_VERSION);
}

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
    go_init_legacy_provider_once(); // Инициализируем только один раз
    int count = 0;
    char **ptr = out;
    EVP_CIPHER_do_all_sorted(cipher_collector, &ptr);
    count = ptr - out;
    return count < max ? count : max;
}

// Коллектор для имён EVP-хэш функций
static void digest_collector(const EVP_MD *md, const char *from, const char *to, void *arg) {
    if (md == NULL) return;
    char ***list = (char ***)arg;
    const char *name = EVP_MD_name(md);
    if (name) {
        size_t len = strlen(name);
        char *copy = (char*)malloc(len+1);
        strcpy(copy, name);
        (*list)[0] = copy;
        (*list)++;
    }
}

// Получить список EVP-хэш функций
int go_list_hashes(char **out, int max) {
    go_init_legacy_provider_once(); // Инициализируем только один раз
    int count = 0;
    char **ptr = out;
    EVP_MD_do_all_sorted(digest_collector, &ptr);
    count = ptr - out;
    return count < max ? count : max;
}
*/
import "C"
import (
	"os"
	"path/filepath"
	"unsafe"
)

func init() {
	// Устанавливаем переменную окружения для модулей OpenSSL
	// Получаем абсолютный путь к текущей директории
	currentDir, err := os.Getwd()
	if err == nil {
		modulesPath := filepath.Join(currentDir, "submodules", "build", "lib", "ossl-modules")
		os.Setenv("OPENSSL_MODULES", modulesPath)
	}
}

func OpenSSLVersion() string {
	return C.GoString(C.go_openssl_version())
}

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

func ListHashes() []string {
	const max = 256
	var arr [max]*C.char
	n := C.go_list_hashes((**C.char)(unsafe.Pointer(&arr[0])), C.int(max))
	out := make([]string, 0, int(n))
	for i := 0; i < int(n); i++ {
		if arr[i] != nil {
			out = append(out, C.GoString(arr[i]))
			C.free(unsafe.Pointer(arr[i]))
		}
	}
	return out
}
