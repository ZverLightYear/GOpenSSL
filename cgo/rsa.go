//go:build cgo
// +build cgo

package cgo

/*
#cgo CFLAGS: -I${SRCDIR}/../submodules/openssl/include
#cgo LDFLAGS: -L${SRCDIR}/../submodules/openssl -lcrypto -lssl
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <string.h>
#include <stdlib.h>

// RSA шифрование
int rsa_encrypt(RSA *rsa, const unsigned char *in, int inlen,
                unsigned char *out, int *outlen, int padding) {
    return RSA_encrypt(rsa, in, inlen, out, outlen, padding);
}

// RSA расшифрование
int rsa_decrypt(RSA *rsa, const unsigned char *in, int inlen,
                unsigned char *out, int *outlen, int padding) {
    return RSA_decrypt(rsa, in, inlen, out, outlen, padding);
}

// RSA подпись
int rsa_sign(RSA *rsa, const unsigned char *m, int mlen,
             unsigned char *sig, int *siglen, const EVP_MD *md) {
    return RSA_sign(EVP_MD_type(md), m, mlen, sig, siglen, rsa);
}

// RSA проверка подписи
int rsa_verify(RSA *rsa, const unsigned char *m, int mlen,
               const unsigned char *sig, int siglen, const EVP_MD *md) {
    return RSA_verify(EVP_MD_type(md), m, mlen, sig, siglen, rsa);
}

// Генерация RSA ключей
RSA* generate_rsa_key(int bits) {
    BIGNUM *e = BN_new();
    if (!e) {
        return NULL;
    }

    if (!BN_set_word(e, RSA_F4)) {
        BN_free(e);
        return NULL;
    }

    RSA *rsa = RSA_new();
    if (!rsa) {
        BN_free(e);
        return NULL;
    }

    if (!RSA_generate_key_ex(rsa, bits, e, NULL)) {
        RSA_free(rsa);
        BN_free(e);
        return NULL;
    }

    BN_free(e);
    return rsa;
}

// Получение размера RSA ключа
int rsa_size(RSA *rsa) {
    return RSA_size(rsa);
}

// Получение размера блока RSA
int rsa_block_size(RSA *rsa) {
    return RSA_size(rsa);
}

// Сохранение RSA ключа в PEM формате
int save_rsa_key(RSA *rsa, const char *filename, int is_private) {
    BIO *bio = BIO_new_file(filename, "w");
    if (!bio) {
        return 0;
    }

    int result;
    if (is_private) {
        result = PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, NULL, NULL);
    } else {
        result = PEM_write_bio_RSA_PUBKEY(bio, rsa);
    }

    BIO_free(bio);
    return result;
}

// Загрузка RSA ключа из PEM формата
RSA* load_rsa_key(const char *filename, int is_private) {
    BIO *bio = BIO_new_file(filename, "r");
    if (!bio) {
        return NULL;
    }

    RSA *rsa;
    if (is_private) {
        rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
    } else {
        rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
    }

    BIO_free(bio);
    return rsa;
}

// Освобождение RSA ключа
void free_rsa_key(RSA *rsa) {
    if (rsa) {
        RSA_free(rsa);
    }
}
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// RSA константы
const (
	RSA_PKCS1_PADDING      = C.RSA_PKCS1_PADDING
	RSA_PKCS1_OAEP_PADDING = C.RSA_PKCS1_OAEP_PADDING
	RSA_PKCS1_PSS_PADDING  = C.RSA_PKCS1_PSS_PADDING
	RSA_NO_PADDING         = C.RSA_NO_PADDING
)

// RSA представляет RSA криптографию
type RSA struct {
	rsa *C.RSA
}

// NewRSA создает новый RSA объект
func NewRSA() *RSA {
	return &RSA{}
}

// GenerateKey генерирует новую пару RSA ключей
func (r *RSA) GenerateKey(bits int) error {
	if r.rsa != nil {
		C.free_rsa_key(r.rsa)
	}

	r.rsa = C.generate_rsa_key(C.int(bits))
	if r.rsa == nil {
		return checkOpenSSLError()
	}

	return nil
}

// LoadPrivateKey загружает приватный ключ из файла
func (r *RSA) LoadPrivateKey(filename string) error {
	if r.rsa != nil {
		C.free_rsa_key(r.rsa)
	}

	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	r.rsa = C.load_rsa_key(cFilename, 1)
	if r.rsa == nil {
		return checkOpenSSLError()
	}

	return nil
}

// LoadPublicKey загружает публичный ключ из файла
func (r *RSA) LoadPublicKey(filename string) error {
	if r.rsa != nil {
		C.free_rsa_key(r.rsa)
	}

	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	r.rsa = C.load_rsa_key(cFilename, 0)
	if r.rsa == nil {
		return checkOpenSSLError()
	}

	return nil
}

// SavePrivateKey сохраняет приватный ключ в файл
func (r *RSA) SavePrivateKey(filename string) error {
	if r.rsa == nil {
		return fmt.Errorf("RSA key is nil")
	}

	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	if C.save_rsa_key(r.rsa, cFilename, 1) == 0 {
		return checkOpenSSLError()
	}

	return nil
}

// SavePublicKey сохраняет публичный ключ в файл
func (r *RSA) SavePublicKey(filename string) error {
	if r.rsa == nil {
		return fmt.Errorf("RSA key is nil")
	}

	cFilename := C.CString(filename)
	defer C.free(unsafe.Pointer(cFilename))

	if C.save_rsa_key(r.rsa, cFilename, 0) == 0 {
		return checkOpenSSLError()
	}

	return nil
}

// Size возвращает размер RSA ключа в байтах
func (r *RSA) Size() int {
	if r.rsa == nil {
		return 0
	}
	return int(C.rsa_size(r.rsa))
}

// BlockSize возвращает размер блока RSA
func (r *RSA) BlockSize() int {
	if r.rsa == nil {
		return 0
	}
	return int(C.rsa_block_size(r.rsa))
}

// Encrypt шифрует данные
func (r *RSA) Encrypt(plaintext []byte, padding int) ([]byte, error) {
	if r.rsa == nil {
		return nil, fmt.Errorf("RSA key is nil")
	}

	if len(plaintext) > r.BlockSize() {
		return nil, fmt.Errorf("plaintext too large for RSA key size")
	}

	// Выделяем память для результата
	outlen := r.Size()
	out := make([]byte, outlen)

	inPtr := goBytesToCBytes(plaintext)
	outPtr := goBytesToCBytes(out)

	var actualOutlen C.int

	if C.rsa_encrypt(r.rsa, inPtr, C.int(len(plaintext)),
		outPtr, &actualOutlen, C.int(padding)) == 0 {
		return nil, checkOpenSSLError()
	}

	return out[:actualOutlen], nil
}

// Decrypt расшифровывает данные
func (r *RSA) Decrypt(ciphertext []byte, padding int) ([]byte, error) {
	if r.rsa == nil {
		return nil, fmt.Errorf("RSA key is nil")
	}

	// Выделяем память для результата
	outlen := r.Size()
	out := make([]byte, outlen)

	inPtr := goBytesToCBytes(ciphertext)
	outPtr := goBytesToCBytes(out)

	var actualOutlen C.int

	if C.rsa_decrypt(r.rsa, inPtr, C.int(len(ciphertext)),
		outPtr, &actualOutlen, C.int(padding)) == 0 {
		return nil, checkOpenSSLError()
	}

	return out[:actualOutlen], nil
}

// Sign подписывает данные
func (r *RSA) Sign(data []byte, hashAlgorithm string) ([]byte, error) {
	if r.rsa == nil {
		return nil, fmt.Errorf("RSA key is nil")
	}

	// Получаем хэш алгоритм
	hashName := C.CString(hashAlgorithm)
	defer C.free(unsafe.Pointer(hashName))

	md := C.EVP_get_digestbyname(hashName)
	if md == nil {
		return nil, fmt.Errorf("unsupported hash algorithm: %s", hashAlgorithm)
	}

	// Выделяем память для подписи
	siglen := r.Size()
	sig := make([]byte, siglen)

	dataPtr := goBytesToCBytes(data)
	sigPtr := goBytesToCBytes(sig)

	var actualSiglen C.int

	if C.rsa_sign(r.rsa, dataPtr, C.int(len(data)),
		sigPtr, &actualSiglen, md) == 0 {
		return nil, checkOpenSSLError()
	}

	return sig[:actualSiglen], nil
}

// Verify проверяет подпись
func (r *RSA) Verify(data, signature []byte, hashAlgorithm string) error {
	if r.rsa == nil {
		return fmt.Errorf("RSA key is nil")
	}

	// Получаем хэш алгоритм
	hashName := C.CString(hashAlgorithm)
	defer C.free(unsafe.Pointer(hashName))

	md := C.EVP_get_digestbyname(hashName)
	if md == nil {
		return fmt.Errorf("unsupported hash algorithm: %s", hashAlgorithm)
	}

	dataPtr := goBytesToCBytes(data)
	sigPtr := goBytesToCBytes(signature)

	if C.rsa_verify(r.rsa, dataPtr, C.int(len(data)),
		sigPtr, C.int(len(signature)), md) == 0 {
		return checkOpenSSLError()
	}

	return nil
}

// Free освобождает ресурсы RSA
func (r *RSA) Free() {
	if r.rsa != nil {
		C.free_rsa_key(r.rsa)
		r.rsa = nil
	}
}
