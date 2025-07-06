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

// GOST шифрование
int gost_encrypt(cipher_ctx_t *ctx, const unsigned char *key, const unsigned char *iv,
                 const unsigned char *in, int inlen, unsigned char *out, int *outlen,
                 const char *cipher_name) {
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        return 0;
    }

    if (!EVP_EncryptInit_ex(ctx->ctx, cipher, NULL, key, iv)) {
        return 0;
    }

    ctx->encrypt = 1;

    if (!EVP_EncryptUpdate(ctx->ctx, out, outlen, in, inlen)) {
        return 0;
    }

    int tmplen;
    if (!EVP_EncryptFinal_ex(ctx->ctx, out + *outlen, &tmplen)) {
        return 0;
    }

    *outlen += tmplen;
    return 1;
}

// GOST расшифрование
int gost_decrypt(cipher_ctx_t *ctx, const unsigned char *key, const unsigned char *iv,
                 const unsigned char *in, int inlen, unsigned char *out, int *outlen,
                 const char *cipher_name) {
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        return 0;
    }

    if (!EVP_DecryptInit_ex(ctx->ctx, cipher, NULL, key, iv)) {
        return 0;
    }

    ctx->encrypt = 0;

    if (!EVP_DecryptUpdate(ctx->ctx, out, outlen, in, inlen)) {
        return 0;
    }

    int tmplen;
    if (!EVP_DecryptFinal_ex(ctx->ctx, out + *outlen, &tmplen)) {
        return 0;
    }

    *outlen += tmplen;
    return 1;
}

// Получение размера блока для GOST
int gost_block_size(const char *cipher_name) {
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        return 0;
    }
    return EVP_CIPHER_block_size(cipher);
}

// Получение размера ключа для GOST
int gost_key_size(const char *cipher_name) {
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        return 0;
    }
    return EVP_CIPHER_key_length(cipher);
}

// Получение размера IV для GOST
int gost_iv_size(const char *cipher_name) {
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        return 0;
    }
    return EVP_CIPHER_iv_length(cipher);
}

// Инициализация GOST engine
int init_gost_engine() {
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

// GOST режимы шифрования
const (
	GOSTCFB   = "gost89"        // ГОСТ 28147-89 CFB (Cipher Feedback)
	GOSTCBC   = "gost89-cbc"    // ГОСТ 28147-89 CBC (Cipher Block Chaining)
	GOSTCTR   = "gost89-cnt"    // ГОСТ 28147-89 CTR (Counter)
	GOSTCTR12 = "gost89-cnt-12" // ГОСТ 28147-89 CTR (Counter) 12 bytes (96 bits) IV
)

// GOST представляет GOST шифратор
type GOST struct {
	ctx        *CipherContext
	cipherName string
}

// NewGOST создает новый GOST шифратор
func NewGOST(mode string) (*GOST, error) {
	// Инициализируем GOST engine
	if C.init_gost_engine() == 0 {
		return nil, fmt.Errorf("failed to initialize GOST engine")
	}

	ctx := NewCipherContext()
	if ctx == nil {
		return nil, fmt.Errorf("failed to create cipher context")
	}

	// Проверяем, что алгоритм поддерживается
	if C.gost_block_size(C.CString(mode)) == 0 {
		ctx.Free()
		return nil, fmt.Errorf("unsupported GOST cipher: %s", mode)
	}

	return &GOST{
		ctx:        ctx,
		cipherName: mode,
	}, nil
}

// Free освобождает ресурсы GOST шифратора
func (g *GOST) Free() {
	if g.ctx != nil {
		g.ctx.Free()
		g.ctx = nil
	}
}

// BlockSize возвращает размер блока
func (g *GOST) BlockSize() int {
	cipherName := C.CString(g.cipherName)
	defer C.free(unsafe.Pointer(cipherName))
	return int(C.gost_block_size(cipherName))
}

// KeySize возвращает размер ключа
func (g *GOST) KeySize() int {
	cipherName := C.CString(g.cipherName)
	defer C.free(unsafe.Pointer(cipherName))
	return int(C.gost_key_size(cipherName))
}

// IVSize возвращает размер IV
func (g *GOST) IVSize() int {
	cipherName := C.CString(g.cipherName)
	defer C.free(unsafe.Pointer(cipherName))
	return int(C.gost_iv_size(cipherName))
}

// Encrypt шифрует данные
func (g *GOST) Encrypt(plaintext, key, iv []byte) ([]byte, error) {
	if g.ctx == nil {
		return nil, fmt.Errorf("GOST context is nil")
	}

	// Проверяем размеры
	if len(key) != g.KeySize() {
		return nil, fmt.Errorf("invalid key size: got %d, want %d", len(key), g.KeySize())
	}

	if len(iv) != g.IVSize() {
		return nil, fmt.Errorf("invalid IV size: got %d, want %d", len(iv), g.IVSize())
	}

	// Выделяем память для результата
	outlen := len(plaintext) + g.BlockSize()
	out := make([]byte, outlen)

	cipherName := C.CString(g.cipherName)
	defer C.free(unsafe.Pointer(cipherName))

	keyPtr := goBytesToCBytes(key)
	ivPtr := goBytesToCBytes(iv)
	inPtr := goBytesToCBytes(plaintext)
	outPtr := goBytesToCBytes(out)

	var actualOutlen C.int

	if C.gost_encrypt(g.ctx.ctx, keyPtr, ivPtr, inPtr, C.int(len(plaintext)),
		outPtr, &actualOutlen, cipherName) == 0 {
		return nil, checkOpenSSLError()
	}

	return out[:actualOutlen], nil
}

// Decrypt расшифровывает данные
func (g *GOST) Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	if g.ctx == nil {
		return nil, fmt.Errorf("GOST context is nil")
	}

	// Проверяем размеры
	if len(key) != g.KeySize() {
		return nil, fmt.Errorf("invalid key size: got %d, want %d", len(key), g.KeySize())
	}

	if len(iv) != g.IVSize() {
		return nil, fmt.Errorf("invalid IV size: got %d, want %d", len(iv), g.IVSize())
	}

	// Выделяем память для результата
	outlen := len(ciphertext)
	out := make([]byte, outlen)

	cipherName := C.CString(g.cipherName)
	defer C.free(unsafe.Pointer(cipherName))

	keyPtr := goBytesToCBytes(key)
	ivPtr := goBytesToCBytes(iv)
	inPtr := goBytesToCBytes(ciphertext)
	outPtr := goBytesToCBytes(out)

	var actualOutlen C.int

	if C.gost_decrypt(g.ctx.ctx, keyPtr, ivPtr, inPtr, C.int(len(ciphertext)),
		outPtr, &actualOutlen, cipherName) == 0 {
		return nil, checkOpenSSLError()
	}

	return out[:actualOutlen], nil
}
