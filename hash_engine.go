// Package gopenssl предоставляет Go интерфейсы для OpenSSL хэширования
package gopenssl

import (
	"fmt"

	"gopenssl/cgo"
)

// ===== ХЭШИРОВАНИЕ =====

// Hash представляет хэшер
type Hash struct {
	hash *cgo.Hash
}

// NewHash создает новый хэшер
func NewHash(algorithm string) (*Hash, error) {
	hash, err := cgo.NewHash(algorithm)
	if err != nil {
		return nil, fmt.Errorf("failed to create hash: %w", err)
	}

	return &Hash{hash: hash}, nil
}

// Size возвращает размер хэша в байтах
func (h *Hash) Size() int {
	return h.hash.Size()
}

// Sum вычисляет хэш от данных
func (h *Hash) Sum(data []byte) ([]byte, error) {
	return h.hash.Sum(data)
}

// Free освобождает ресурсы хэшера
func (h *Hash) Free() {
	if h.hash != nil {
		h.hash.Free()
		h.hash = nil
	}
}

// Константы для хэширования
const (
	// SHA алгоритмы
	SHA1     = cgo.SHA1
	SHA224   = cgo.SHA224
	SHA256   = cgo.SHA256
	SHA384   = cgo.SHA384
	SHA512   = cgo.SHA512
	SHA3_224 = cgo.SHA3_224
	SHA3_256 = cgo.SHA3_256
	SHA3_384 = cgo.SHA3_384
	SHA3_512 = cgo.SHA3_512

	// MD алгоритмы
	MD4 = cgo.MD4
	MD5 = cgo.MD5

	// GOST алгоритмы
	GOSTR341194      = cgo.GOSTR341194
	GOSTR34112012256 = cgo.GOSTR34112012256
	GOSTR34112012512 = cgo.GOSTR34112012512
)
