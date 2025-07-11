package cgopenssl

/*
#cgo CFLAGS: -I${SRCDIR}/../../submodules/build/include
#cgo LDFLAGS: -L${SRCDIR}/../../submodules/build/lib -lssl -lcrypto -ldl
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include <openssl/provider.h>
#include <stdlib.h>
#include <string.h>

// Структура для хранения контекста хэша
typedef struct {
    EVP_MD_CTX *ctx;
    char *digest_name;
} go_hash_ctx_t;

// Создать контекст хэша
go_hash_ctx_t* go_hash_new(const char* digest_name) {
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
    const EVP_MD* md = EVP_get_digestbyname(digest_name);
    if (!md) return 0;

    int size = EVP_MD_size(md);

    return size;
}
*/
import "C"
import (
	"unsafe"
)

// HashContext представляет CGO контекст хэша
type HashContext struct {
	ctx *C.go_hash_ctx_t
}

// NewHashContext создает новый контекст хэша
func NewHashContext(digestName string) (*HashContext, error) {
	ctx := C.go_hash_new(C.CString(digestName))
	if ctx == nil {
		return nil, nil
	}
	return &HashContext{ctx: ctx}, nil
}

// Update обновляет хэш
func (h *HashContext) Update(data []byte) error {
	if len(data) == 0 {
		return nil
	}

	result := C.go_hash_update(h.ctx, (*C.uchar)(unsafe.Pointer(&data[0])), C.int(len(data)))
	if result != 1 {
		return nil
	}
	return nil
}

// Final завершает хэширование
func (h *HashContext) Final() ([]byte, error) {
	size := int(C.go_hash_size(h.ctx))
	if size <= 0 {
		return nil, nil
	}

	out := make([]byte, size)
	var outLen C.uint

	result := C.go_hash_final(h.ctx, (*C.uchar)(unsafe.Pointer(&out[0])), &outLen)
	if result != 1 {
		return nil, nil
	}

	return out[:outLen], nil
}

// Reset сбрасывает контекст
func (h *HashContext) Reset() error {
	result := C.go_hash_reset(h.ctx)
	if result != 1 {
		return nil
	}
	return nil
}

// Free освобождает контекст
func (h *HashContext) Free() {
	if h.ctx != nil {
		C.go_hash_free(h.ctx)
		h.ctx = nil
	}
}

// GetSize возвращает размер хэша
func (h *HashContext) GetSize() int {
	return int(C.go_hash_size(h.ctx))
}

// GetSizeByName возвращает размер хэша по имени
func GetSizeByName(digestName string) int {
	return int(C.go_hash_get_size(C.CString(digestName)))
}
