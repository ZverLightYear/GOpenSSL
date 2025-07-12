package cgopenssl

/*
#cgo CFLAGS: -I${SRCDIR}/../submodules/openssl/include -I${SRCDIR}/../submodules/openssl/crypto -Wno-deprecated-declarations
#include "openssl_import.c"
*/
import "C"
import (
	"fmt"
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

// ListCiphers возвращает список доступных шифров
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

// ListHashes возвращает список доступных хэш-алгоритмов
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

// CipherContext представляет CGO контекст шифра
type CipherContext struct {
	ctx *C.go_cipher_ctx_t
}

// NewCipherContext создает новый контекст шифра
func NewCipherContext(cipherName string, isEncrypt bool, key, iv []byte) (*CipherContext, error) {
	var keyPtr *C.uchar
	var ivPtr *C.uchar

	if len(key) > 0 {
		keyPtr = (*C.uchar)(unsafe.Pointer(&key[0]))
	}
	if len(iv) > 0 {
		ivPtr = (*C.uchar)(unsafe.Pointer(&iv[0]))
	}

	ctx := C.go_cipher_new(C.CString(cipherName), C.int(btoi(isEncrypt)), keyPtr, ivPtr)
	if ctx == nil {
		return nil, fmt.Errorf("failed to create cipher context for %s", cipherName)
	}
	return &CipherContext{ctx: ctx}, nil
}

// Update обновляет шифрование/дешифрование
func (c *CipherContext) Update(in []byte) ([]byte, error) {
	if c == nil || c.ctx == nil {
		return nil, fmt.Errorf("cipher context is nil")
	}
	if len(in) == 0 {
		return []byte{}, nil
	}

	outLen := C.int(len(in) + int(C.go_cipher_get_block_size(C.CString("AES-256-CBC"))))
	out := make([]byte, outLen)

	var updateLen C.int
	result := C.go_cipher_update(c.ctx, (*C.uchar)(unsafe.Pointer(&in[0])), C.int(len(in)), (*C.uchar)(unsafe.Pointer(&out[0])), &updateLen)
	if result != 1 {
		return nil, nil
	}

	return out[:updateLen], nil
}

// Final завершает шифрование/дешифрование
func (c *CipherContext) Final() ([]byte, error) {
	if c == nil || c.ctx == nil {
		return nil, fmt.Errorf("cipher context is nil")
	}
	outLen := C.int(int(C.go_cipher_get_block_size(C.CString("AES-256-CBC"))))
	out := make([]byte, outLen)

	var finalLen C.int
	result := C.go_cipher_final(c.ctx, (*C.uchar)(unsafe.Pointer(&out[0])), &finalLen)
	if result != 1 {
		return nil, nil
	}

	return out[:finalLen], nil
}

// Reset сбрасывает контекст
func (c *CipherContext) Reset() error {
	if c == nil || c.ctx == nil {
		return fmt.Errorf("cipher context is nil")
	}
	result := C.go_cipher_reset(c.ctx)
	if result != 1 {
		return fmt.Errorf("failed to reset cipher context")
	}
	return nil
}

// Free освобождает контекст
func (c *CipherContext) Free() {
	if c != nil && c.ctx != nil {
		C.go_cipher_free(c.ctx)
		c.ctx = nil
	}
}

// GetBlockSize возвращает размер блока
func (c *CipherContext) GetBlockSize() int {
	return int(C.go_cipher_block_size(c.ctx))
}

// GetKeyLength возвращает размер ключа
func (c *CipherContext) GetKeyLength() int {
	return int(C.go_cipher_key_length(c.ctx))
}

// GetBlockSizeByName возвращает размер блока по имени шифра
func GetBlockSizeByName(cipherName string) int {
	return int(C.go_cipher_get_block_size(C.CString(cipherName)))
}

// HashContext представляет CGO контекст хэша
type HashContext struct {
	ctx *C.go_hash_ctx_t
}

// NewHashContext создает новый контекст хэша
func NewHashContext(digestName string) (*HashContext, error) {
	ctx := C.go_hash_new(C.CString(digestName))
	if ctx == nil {
		return nil, fmt.Errorf("failed to create hash context for %s", digestName)
	}
	return &HashContext{ctx: ctx}, nil
}

// Update обновляет хэш
func (h *HashContext) Update(data []byte) error {
	if h == nil || h.ctx == nil {
		return fmt.Errorf("hash context is nil")
	}
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
	if h == nil || h.ctx == nil {
		return nil, fmt.Errorf("hash context is nil")
	}
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
	if h == nil || h.ctx == nil {
		return fmt.Errorf("hash context is nil")
	}
	result := C.go_hash_reset(h.ctx)
	if result != 1 {
		return fmt.Errorf("failed to reset hash context")
	}
	return nil
}

// Free освобождает контекст
func (h *HashContext) Free() {
	if h != nil && h.ctx != nil {
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

// btoi конвертирует bool в int
func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}
