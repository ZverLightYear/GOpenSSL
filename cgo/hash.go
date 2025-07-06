//go:build cgo
// +build cgo

package cgo

/*
#cgo CFLAGS: -I${SRCDIR}/../submodules/openssl/include
#cgo LDFLAGS: -L${SRCDIR}/../submodules/openssl -lcrypto -lssl
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <string.h>
#include <stdlib.h>

// Хэширование
int hash_data(hash_ctx_t *ctx, const unsigned char *data, int datalen,
              unsigned char *digest, int *digestlen, const char *hash_name) {
    const EVP_MD *md = EVP_get_digestbyname(hash_name);
    if (!md) {
        return 0;
    }

    if (!EVP_DigestInit_ex(ctx->ctx, md, NULL)) {
        return 0;
    }

    if (!EVP_DigestUpdate(ctx->ctx, data, datalen)) {
        return 0;
    }

    if (!EVP_DigestFinal_ex(ctx->ctx, digest, digestlen)) {
        return 0;
    }

    return 1;
}

// Получение размера хэша
int hash_size(const char *hash_name) {
    const EVP_MD *md = EVP_get_digestbyname(hash_name);
    if (!md) {
        return 0;
    }
    return EVP_MD_size(md);
}

// Инициализация GOST engine для хэширования
int init_gost_hash_engine() {
    ENGINE *e = ENGINE_by_id("gost");
    if (!e) {
        return 0;
    }

    if (!ENGINE_init(e)) {
        ENGINE_free(e);
        return 0;
    }

    if (!ENGINE_set_default(e, ENGINE_METHOD_ALL)) {
        ENGINE_finish(e);
        ENGINE_free(e);
        return 0;
    }

    ENGINE_free(e);
    return 1;
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Алгоритмы хэширования
const (
	// SHA алгоритмы
	SHA1     = "sha1"
	SHA224   = "sha224"
	SHA256   = "sha256"
	SHA384   = "sha384"
	SHA512   = "sha512"
	SHA3_224 = "sha3-224"
	SHA3_256 = "sha3-256"
	SHA3_384 = "sha3-384"
	SHA3_512 = "sha3-512"

	// MD алгоритмы
	MD4 = "md4"
	MD5 = "md5"

	// GOST алгоритмы
	GOSTR341194      = "gostr341194"      // ГОСТ Р 34.11-94
	GOSTR34112012256 = "gostr34112012256" // ГОСТ Р 34.11-2012 256 бит
	GOSTR34112012512 = "gostr34112012512" // ГОСТ Р 34.11-2012 512 бит
)

// Hash представляет хэшер
type Hash struct {
	ctx      *HashContext
	hashName string
}

// NewHash создает новый хэшер
func NewHash(algorithm string) (*Hash, error) {
	ctx := NewHashContext()
	if ctx == nil {
		return nil, fmt.Errorf("failed to create hash context")
	}

	// Для GOST алгоритмов инициализируем engine
	if algorithm == GOSTR341194 || algorithm == GOSTR34112012256 || algorithm == GOSTR34112012512 {
		if C.init_gost_hash_engine() == 0 {
			ctx.Free()
			return nil, fmt.Errorf("failed to initialize GOST hash engine")
		}
	}

	// Проверяем, что алгоритм поддерживается
	if C.hash_size(C.CString(algorithm)) == 0 {
		ctx.Free()
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	return &Hash{
		ctx:      ctx,
		hashName: algorithm,
	}, nil
}

// Free освобождает ресурсы хэшера
func (h *Hash) Free() {
	if h.ctx != nil {
		h.ctx.Free()
		h.ctx = nil
	}
}

// Size возвращает размер хэша в байтах
func (h *Hash) Size() int {
	hashName := C.CString(h.hashName)
	defer C.free(unsafe.Pointer(hashName))
	return int(C.hash_size(hashName))
}

// Sum вычисляет хэш от данных
func (h *Hash) Sum(data []byte) ([]byte, error) {
	if h.ctx == nil {
		return nil, fmt.Errorf("hash context is nil")
	}

	// Выделяем память для результата
	digestSize := h.Size()
	digest := make([]byte, digestSize)

	hashName := C.CString(h.hashName)
	defer C.free(unsafe.Pointer(hashName))

	dataPtr := goBytesToCBytes(data)
	digestPtr := goBytesToCBytes(digest)

	var actualDigestLen C.int

	if C.hash_data(h.ctx.ctx, dataPtr, C.int(len(data)),
		digestPtr, &actualDigestLen, hashName) == 0 {
		return nil, checkOpenSSLError()
	}

	return digest[:actualDigestLen], nil
}

// NewSHA1 создает SHA-1 хэшер
func NewSHA1() (*Hash, error) {
	return NewHash(SHA1)
}

// NewSHA256 создает SHA-256 хэшер
func NewSHA256() (*Hash, error) {
	return NewHash(SHA256)
}

// NewSHA512 создает SHA-512 хэшер
func NewSHA512() (*Hash, error) {
	return NewHash(SHA512)
}

// NewMD5 создает MD5 хэшер
func NewMD5() (*Hash, error) {
	return NewHash(MD5)
}

// NewGOSTR34112012256 создает GOST Р 34.11-2012 (256 бит) хэшер
func NewGOSTR34112012256() (*Hash, error) {
	return NewHash(GOSTR34112012256)
}

// NewGOSTR34112012512 создает GOST Р 34.11-2012 (512 бит) хэшер
func NewGOSTR34112012512() (*Hash, error) {
	return NewHash(GOSTR34112012512)
}
