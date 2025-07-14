package cgo

/*
#cgo CFLAGS: -Isrc/include
#cgo CFLAGS: -I${SRCDIR}/../submodules/openssl/include
#cgo LDFLAGS: /Users/sergey.zverev/Projects/own/GOpenSSL/build/libminicrypto.a
#include "minicrypto.h"
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

const blockSize = 16 // AES block size

type CryptoInstance struct{}

func New() *CryptoInstance {
	fmt.Printf("New\n")

	return &CryptoInstance{}
}

func (c *CryptoInstance) EncryptCBC(plain, key, iv []byte) ([]byte, error) {
	if len(iv) != blockSize {
		return nil, errors.New("invalid IV length")
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("invalid key length")
	}

	// PKCS7 padding
	data := pkcs7PadOpenSSL(plain, blockSize)

	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)

	out := make([]byte, len(data))
	res := C.aes_cbc_encrypt(
		(*C.uint8_t)(unsafe.Pointer(&data[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		C.size_t(len(data)),
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		C.int(len(key)),
		(*C.uint8_t)(unsafe.Pointer(&ivCopy[0])),
	)
	if res != 0 {
		return nil, errors.New("encryption failed")
	}
	return out, nil
}

func (c *CryptoInstance) DecryptCBC(cipher, key, iv []byte) ([]byte, error) {
	if len(iv) != blockSize {
		return nil, errors.New("invalid IV length")
	}
	if len(cipher)%blockSize != 0 {
		return nil, errors.New("cipher length not multiple of block size")
	}
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("invalid key length")
	}

	ivCopy := make([]byte, len(iv))
	copy(ivCopy, iv)

	out := make([]byte, len(cipher))
	res := C.aes_cbc_decrypt(
		(*C.uint8_t)(unsafe.Pointer(&cipher[0])),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
		C.size_t(len(cipher)),
		(*C.uint8_t)(unsafe.Pointer(&key[0])),
		C.int(len(key)),
		(*C.uint8_t)(unsafe.Pointer(&ivCopy[0])),
	)
	if res != 0 {
		return nil, errors.New("decryption failed")
	}

	// PKCS7 unpad
	return pkcs7UnpadOpenSSL(out, blockSize)
}
