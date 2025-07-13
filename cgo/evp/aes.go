package cgo_evp

/*
#cgo CFLAGS: -I${SRCDIR}submodules/openssl/include -Wno-deprecated-declarations
#include "aes.h"
*/
import "C"
import "unsafe"

type AES struct {
	ctx c.
}

func Init(key string) []string {
	init := C.aes_init(
		unsigned char *key_data,
		int key_data_len,
		unsigned char *salt,
		EVP_CIPHER_CTX *e_ctx,
		EVP_CIPHER_CTX *d_ctx,
	)
	if ciphers == nil {
		return []string{}
	}
	defer C.free_string_list(ciphers, count)

	result := make([]string, int(count))
	// Преобразуем C массив в Go слайс
	cipherArray := (*[1 << 30]*C.char)(unsafe.Pointer(ciphers))[:count:count]
	for i := 0; i < int(count); i++ {
		if cipherArray[i] != nil {
			result[i] = C.GoString(cipherArray[i])
		}
	}
	return result
}

// GetAvailableDigests возвращает список доступных хэш-функций
func Encrypt(plaintext string) []string {
	//unsigned char *aes_encrypt(
	//	EVP_CIPHER_CTX *e,
	//	unsigned char *plaintext,
	//	int *len,
	//);
}

// GetOpenSSLVersion возвращает версию OpenSSL
func Decrypt() string {
	//unsigned char *aes_decrypt(
	//	EVP_CIPHER_CTX *e,
	//	unsigned char *ciphertext,
	//	int *len,
	//);
}

// GetOpenSSLBuildInfo возвращает информацию о сборке OpenSSL
func GetOpenSSLBuildInfo() string {
	info := C.get_openssl_build_info()
	if info == nil {
		return ""
	}
	return C.GoString(info)
}

// GetOpenSSLCompilerInfo возвращает информацию о компиляторе OpenSSL
func GetOpenSSLCompilerInfo() string {
	info := C.get_openssl_compiler_info()
	if info == nil {
		return ""
	}
	return C.GoString(info)
}
