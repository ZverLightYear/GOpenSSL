//go:build cgo
// +build cgo

package cgo

/*
#cgo CFLAGS: -I${SRCDIR}/../submodules/openssl/include
#cgo LDFLAGS: -L${SRCDIR}/../submodules/openssl -lcrypto -lssl
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <stdlib.h>

// AES шифрование
int aes_encrypt(cipher_ctx_t *ctx, const unsigned char *key, const unsigned char *iv,
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

// AES расшифрование
int aes_decrypt(cipher_ctx_t *ctx, const unsigned char *key, const unsigned char *iv,
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

// Получение размера блока для AES
int aes_block_size(const char *cipher_name) {
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        return 0;
    }
    return EVP_CIPHER_block_size(cipher);
}

// Получение размера ключа для AES
int aes_key_size(const char *cipher_name) {
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        return 0;
    }
    return EVP_CIPHER_key_length(cipher);
}

// Получение размера IV для AES
int aes_iv_size(const char *cipher_name) {
    const EVP_CIPHER *cipher = EVP_get_cipherbyname(cipher_name);
    if (!cipher) {
        return 0;
    }
    return EVP_CIPHER_iv_length(cipher);
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// AES режимы шифрования
const (
	AES128 = "aes-128"
	AES192 = "aes-192"
	AES256 = "aes-256"
)

// Режимы работы AES
const (
	AESECB = "ecb"
	AESCBC = "cbc"
	AESCFB = "cfb"
	AESOFB = "ofb"
	AESCTR = "ctr"
	AESGCM = "gcm"
	AESXTS = "xts"
	AESCCM = "ccm"
	AESOCB = "ocb"
)

// AES представляет AES шифратор
type AES struct {
	ctx        *CipherContext
	cipherName string
}

// NewAES создает новый AES шифратор
func NewAES(keySize, mode string) (*AES, error) {
	ctx := NewCipherContext()
	if ctx == nil {
		return nil, fmt.Errorf("failed to create cipher context")
	}

	cipherName := fmt.Sprintf("%s-%s", keySize, mode)

	// Проверяем, что алгоритм поддерживается
	if C.aes_block_size(C.CString(cipherName)) == 0 {
		ctx.Free()
		return nil, fmt.Errorf("unsupported AES cipher: %s", cipherName)
	}

	return &AES{
		ctx:        ctx,
		cipherName: cipherName,
	}, nil
}

// Free освобождает ресурсы AES шифратора
func (a *AES) Free() {
	if a.ctx != nil {
		a.ctx.Free()
		a.ctx = nil
	}
}

// BlockSize возвращает размер блока
func (a *AES) BlockSize() int {
	cipherName := C.CString(a.cipherName)
	defer C.free(unsafe.Pointer(cipherName))
	return int(C.aes_block_size(cipherName))
}

// KeySize возвращает размер ключа
func (a *AES) KeySize() int {
	cipherName := C.CString(a.cipherName)
	defer C.free(unsafe.Pointer(cipherName))
	return int(C.aes_key_size(cipherName))
}

// IVSize возвращает размер IV
func (a *AES) IVSize() int {
	cipherName := C.CString(a.cipherName)
	defer C.free(unsafe.Pointer(cipherName))
	return int(C.aes_iv_size(cipherName))
}

// Encrypt шифрует данные
func (a *AES) Encrypt(plaintext, key, iv []byte) ([]byte, error) {
	if a.ctx == nil {
		return nil, fmt.Errorf("AES context is nil")
	}

	// Проверяем размеры
	if len(key) != a.KeySize() {
		return nil, fmt.Errorf("invalid key size: got %d, want %d", len(key), a.KeySize())
	}

	if len(iv) != a.IVSize() {
		return nil, fmt.Errorf("invalid IV size: got %d, want %d", len(iv), a.IVSize())
	}

	// Выделяем память для результата
	outlen := len(plaintext) + a.BlockSize()
	out := make([]byte, outlen)

	cipherName := C.CString(a.cipherName)
	defer C.free(unsafe.Pointer(cipherName))

	keyPtr := goBytesToCBytes(key)
	ivPtr := goBytesToCBytes(iv)
	inPtr := goBytesToCBytes(plaintext)
	outPtr := goBytesToCBytes(out)

	var actualOutlen C.int

	if C.aes_encrypt(a.ctx.ctx, keyPtr, ivPtr, inPtr, C.int(len(plaintext)),
		outPtr, &actualOutlen, cipherName) == 0 {
		return nil, checkOpenSSLError()
	}

	return out[:actualOutlen], nil
}

// Decrypt расшифровывает данные
func (a *AES) Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	if a.ctx == nil {
		return nil, fmt.Errorf("AES context is nil")
	}

	// Проверяем размеры
	if len(key) != a.KeySize() {
		return nil, fmt.Errorf("invalid key size: got %d, want %d", len(key), a.KeySize())
	}

	if len(iv) != a.IVSize() {
		return nil, fmt.Errorf("invalid IV size: got %d, want %d", len(iv), a.IVSize())
	}

	// Выделяем память для результата
	outlen := len(ciphertext)
	out := make([]byte, outlen)

	cipherName := C.CString(a.cipherName)
	defer C.free(unsafe.Pointer(cipherName))

	keyPtr := goBytesToCBytes(key)
	ivPtr := goBytesToCBytes(iv)
	inPtr := goBytesToCBytes(ciphertext)
	outPtr := goBytesToCBytes(out)

	var actualOutlen C.int

	if C.aes_decrypt(a.ctx.ctx, keyPtr, ivPtr, inPtr, C.int(len(ciphertext)),
		outPtr, &actualOutlen, cipherName) == 0 {
		return nil, checkOpenSSLError()
	}

	return out[:actualOutlen], nil
}
