//go:build cgo && !windows
// +build cgo,!windows

package cgo

/*
#cgo CFLAGS: -I${SRCDIR}/../submodules/openssl/include
#cgo LDFLAGS: -L${SRCDIR}/../submodules/openssl -lcrypto -lssl
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include <string.h>
#include <stdlib.h>

// Константы для алгоритмов
#define AES_BLOCK_SIZE 16
#define GOST_BLOCK_SIZE 8
#define GRASSHOPPER_BLOCK_SIZE 16

// Структура для хранения контекста шифрования
typedef struct {
    EVP_CIPHER_CTX *ctx;
    int encrypt;
} cipher_ctx_t;

// Структура для хранения контекста хэширования
typedef struct {
    EVP_MD_CTX *ctx;
} hash_ctx_t;

// Инициализация OpenSSL
void init_openssl() {
    OpenSSL_add_all_algorithms();
    OpenSSL_add_all_ciphers();
    OpenSSL_add_all_digests();
    ENGINE_load_builtin_engines();
    ENGINE_register_all_complete();
}

// Очистка OpenSSL
void cleanup_openssl() {
    EVP_cleanup();
    ENGINE_cleanup();
}

// Получение последней ошибки OpenSSL
const char* get_openssl_error() {
    return ERR_error_string(ERR_get_error(), NULL);
}

// Создание контекста шифрования
cipher_ctx_t* create_cipher_ctx() {
    cipher_ctx_t *ctx = (cipher_ctx_t*)malloc(sizeof(cipher_ctx_t));
    if (ctx) {
        ctx->ctx = EVP_CIPHER_CTX_new();
        ctx->encrypt = 0;
    }
    return ctx;
}

// Уничтожение контекста шифрования
void destroy_cipher_ctx(cipher_ctx_t *ctx) {
    if (ctx) {
        if (ctx->ctx) {
            EVP_CIPHER_CTX_free(ctx->ctx);
        }
        free(ctx);
    }
}

// Создание контекста хэширования
hash_ctx_t* create_hash_ctx() {
    hash_ctx_t *ctx = (hash_ctx_t*)malloc(sizeof(hash_ctx_t));
    if (ctx) {
        ctx->ctx = EVP_MD_CTX_new();
    }
    return ctx;
}

// Уничтожение контекста хэширования
void destroy_hash_ctx(hash_ctx_t *ctx) {
    if (ctx) {
        if (ctx->ctx) {
            EVP_MD_CTX_free(ctx->ctx);
        }
        free(ctx);
    }
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Инициализация OpenSSL
func InitOpenSSL() {
	C.init_openssl()
}

// Очистка OpenSSL
func CleanupOpenSSL() {
	C.cleanup_openssl()
}

// Получение последней ошибки OpenSSL
func GetOpenSSLError() string {
	return C.GoString(C.get_openssl_error())
}

// Константы для размеров блоков
const (
	AESBlockSize         = C.AES_BLOCK_SIZE
	GOSTBlockSize        = C.GOST_BLOCK_SIZE
	GrasshopperBlockSize = C.GRASSHOPPER_BLOCK_SIZE
)

// CipherContext представляет контекст шифрования
type CipherContext struct {
	ctx *C.cipher_ctx_t
}

// HashContext представляет контекст хэширования
type HashContext struct {
	ctx *C.hash_ctx_t
}

// NewCipherContext создает новый контекст шифрования
func NewCipherContext() *CipherContext {
	ctx := C.create_cipher_ctx()
	if ctx == nil {
		return nil
	}
	return &CipherContext{ctx: ctx}
}

// Free освобождает контекст шифрования
func (c *CipherContext) Free() {
	if c.ctx != nil {
		C.destroy_cipher_ctx(c.ctx)
		c.ctx = nil
	}
}

// NewHashContext создает новый контекст хэширования
func NewHashContext() *HashContext {
	ctx := C.create_hash_ctx()
	if ctx == nil {
		return nil
	}
	return &HashContext{ctx: ctx}
}

// Free освобождает контекст хэширования
func (h *HashContext) Free() {
	if h.ctx != nil {
		C.destroy_hash_ctx(h.ctx)
		h.ctx = nil
	}
}

// OpenSSLError представляет ошибку OpenSSL
type OpenSSLError struct {
	Message string
}

func (e *OpenSSLError) Error() string {
	return fmt.Sprintf("OpenSSL error: %s", e.Message)
}

// Проверка ошибки OpenSSL
func checkOpenSSLError() error {
	err := GetOpenSSLError()
	if err != "" {
		return &OpenSSLError{Message: err}
	}
	return nil
}

// Безопасное преобразование Go строки в C строку
func goStringToCString(s string) *C.char {
	return C.CString(s)
}

// Безопасное освобождение C строки
func freeCString(s *C.char) {
	C.free(unsafe.Pointer(s))
}

// Безопасное преобразование Go байтов в C байты
func goBytesToCBytes(b []byte) *C.uchar {
	if len(b) == 0 {
		return nil
	}
	return (*C.uchar)(unsafe.Pointer(&b[0]))
}
