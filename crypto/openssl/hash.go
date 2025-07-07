package openssl

/*
#cgo CFLAGS: -I${SRCDIR}/../../submodules/build/include
#cgo LDFLAGS: -L${SRCDIR}/../../submodules/build/lib -lssl -lcrypto -ldl
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <stdlib.h>
#include <string.h>

// Принудительная загрузка legacy provider при инициализации
__attribute__((constructor))
static void go_force_legacy_provider() {
    OSSL_PROVIDER_load(NULL, "legacy");
}

// Инициализация legacy provider
static void go_init_legacy_provider() {
    // Устанавливаем путь к модулям
    setenv("OPENSSL_MODULES", "${SRCDIR}/../../submodules/build/lib/ossl-modules", 1);

    // Загружаем legacy provider
    OSSL_PROVIDER* legacy = OSSL_PROVIDER_load(NULL, "legacy");
    if (!legacy) {
        // Если не удалось загрузить, попробуем загрузить по пути
        legacy = OSSL_PROVIDER_load(NULL, "${SRCDIR}/../../submodules/build/lib/ossl-modules/legacy.dylib");
    }
}

// Структура для хранения контекста хэша
typedef struct {
    EVP_MD_CTX *ctx;
    char *digest_name;
} go_hash_ctx_t;

// Создать контекст хэша
go_hash_ctx_t* go_hash_new(const char* digest_name) {
    go_init_legacy_provider();

    go_hash_ctx_t* ctx = (go_hash_ctx_t*)malloc(sizeof(go_hash_ctx_t));
    if (!ctx) return NULL;

    ctx->ctx = EVP_MD_CTX_new();
    if (!ctx->ctx) {
        free(ctx);
        return NULL;
    }

    ctx->digest_name = strdup(digest_name);

    const EVP_MD* md = EVP_get_digestbyname(digest_name);
    if (!md) {
        EVP_MD_CTX_free(ctx->ctx);
        free(ctx->digest_name);
        free(ctx);
        return NULL;
    }

    int result = EVP_DigestInit_ex2(ctx->ctx, (EVP_MD*)md, NULL);
    EVP_MD_free((EVP_MD*)md);

    if (result != 1) {
        EVP_MD_CTX_free(ctx->ctx);
        free(ctx->digest_name);
        free(ctx);
        return NULL;
    }

    return ctx;
}

// Обновить хэш
int go_hash_update(go_hash_ctx_t* ctx, const unsigned char* data, int len) {
    if (!ctx || !ctx->ctx) return 0;
    return EVP_DigestUpdate(ctx->ctx, data, len);
}

// Завершить хэш
int go_hash_final(go_hash_ctx_t* ctx, unsigned char* out, unsigned int* out_len) {
    if (!ctx || !ctx->ctx) return 0;
    return EVP_DigestFinal_ex(ctx->ctx, out, out_len);
}

// Сбросить контекст
int go_hash_reset(go_hash_ctx_t* ctx) {
    if (!ctx || !ctx->ctx) return 0;

    const EVP_MD* md = EVP_get_digestbyname(ctx->digest_name);
    if (!md) return 0;

    int result = EVP_MD_CTX_reset(ctx->ctx);
    if (result == 1) {
        result = EVP_DigestInit_ex(ctx->ctx, (EVP_MD*)md, NULL);
    }

    return result;
}

// Освободить контекст
void go_hash_free(go_hash_ctx_t* ctx) {
    if (ctx) {
        if (ctx->ctx) {
            EVP_MD_CTX_free(ctx->ctx);
        }
        if (ctx->digest_name) {
            free(ctx->digest_name);
        }
        free(ctx);
    }
}

// Получить размер хэша
int go_hash_size(go_hash_ctx_t* ctx) {
    if (!ctx || !ctx->ctx) return 0;
    return EVP_MD_CTX_size(ctx->ctx);
}

// Получить размер хэша по имени
int go_hash_get_size(const char* digest_name) {
    go_init_legacy_provider();

    const EVP_MD* md = EVP_get_digestbyname(digest_name);
    if (!md) return 0;

    int size = EVP_MD_size(md);

    return size;
}
*/
import "C"
import (
	"fmt"
	"unsafe"

	"gopenssl/crypto"
)

// OpenSSLHasher реализует интерфейс Hasher для OpenSSL
type OpenSSLHasher struct {
	algorithm  crypto.HashAlgorithm
	digestName string
	ctx        *C.go_hash_ctx_t
}

// NewOpenSSLHasher создает новый OpenSSL хэшер
func NewOpenSSLHasher(algorithm crypto.HashAlgorithm, digestName string) (*OpenSSLHasher, error) {
	hasher := &OpenSSLHasher{
		algorithm:  algorithm,
		digestName: digestName,
	}

	// Создаем контекст
	ctx := C.go_hash_new(C.CString(digestName))
	if ctx == nil {
		return nil, fmt.Errorf("failed to create hash context for %s", digestName)
	}

	hasher.ctx = ctx
	return hasher, nil
}

// Write добавляет данные для хэширования
func (h *OpenSSLHasher) Write(data []byte) (int, error) {
	if h.ctx == nil {
		return 0, fmt.Errorf("hash context is nil")
	}

	if len(data) == 0 {
		return 0, nil
	}

	result := C.go_hash_update(h.ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.int(len(data)))
	if result != 1 {
		return 0, fmt.Errorf("hash update failed for %s", h.digestName)
	}

	return len(data), nil
}

// Sum возвращает хэш от добавленных данных
func (h *OpenSSLHasher) Sum() []byte {
	if h.ctx == nil {
		return nil
	}

	// Получаем размер хэша
	size := int(C.go_hash_size(h.ctx))
	if size <= 0 {
		return nil
	}

	// Выделяем буфер для результата
	out := make([]byte, size)
	var outLen C.uint

	// Завершаем хэширование
	result := C.go_hash_final(h.ctx, (*C.uchar)(unsafe.Pointer(&out[0])), &outLen)
	if result != 1 {
		return nil
	}

	return out[:int(outLen)]
}

// Reset сбрасывает состояние хэшера
func (h *OpenSSLHasher) Reset() {
	if h.ctx != nil {
		C.go_hash_reset(h.ctx)
	}
}

// Size возвращает размер хэша в байтах
func (h *OpenSSLHasher) Size() int {
	return int(C.go_hash_get_size(C.CString(h.digestName)))
}

// Algorithm возвращает алгоритм хэширования
func (h *OpenSSLHasher) Algorithm() crypto.HashAlgorithm {
	return h.algorithm
}

// Close освобождает ресурсы
func (h *OpenSSLHasher) Close() error {
	if h.ctx != nil {
		C.go_hash_free(h.ctx)
		h.ctx = nil
	}
	return nil
}
