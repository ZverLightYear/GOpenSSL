package hashes

import (
	"fmt"
	cgopenssl "gopenssl/cgo"

	"gopenssl/internal/common"
)

// OpenSSLHasher реализует интерфейс Hasher для OpenSSL
type OpenSSLHasher struct {
	algorithm  common.HashAlgorithm
	digestName string
	ctx        *cgopenssl.HashContext
}

// NewOpenSSLHasher создает новый OpenSSL хэшер
func NewOpenSSLHasher(algorithm common.HashAlgorithm, digestName string) (*OpenSSLHasher, error) {
	hasher := &OpenSSLHasher{
		algorithm:  algorithm,
		digestName: digestName,
	}

	// Создаем контекст
	ctx, err := cgopenssl.NewHashContext(digestName)
	if err != nil {
		return nil, fmt.Errorf("failed to create hash context: %v", err)
	}
	if ctx == nil {
		return nil, fmt.Errorf("failed to create hash context for %s", digestName)
	}

	hasher.ctx = ctx
	return hasher, nil
}

// Write добавляет данные для хэширования
func (h *OpenSSLHasher) Write(data []byte) (int, error) {
	if h.ctx == nil {
		return 0, fmt.Errorf("hash context is nil")
	}

	if len(data) == 0 {
		return 0, nil
	}

	err := h.ctx.Update(data)
	if err != nil {
		return 0, fmt.Errorf("hash update failed for %s: %v", h.digestName, err)
	}

	return len(data), nil
}

// Sum возвращает хэш от добавленных данных
func (h *OpenSSLHasher) Sum() []byte {
	if h.ctx == nil {
		return nil
	}

	// Завершаем хэширование
	result, err := h.ctx.Final()
	if err != nil {
		return nil
	}

	return result
}

// Reset сбрасывает состояние хэшера
func (h *OpenSSLHasher) Reset() {
	if h.ctx != nil {
		h.ctx.Reset()
	}
}

// Size возвращает размер хэша в байтах
func (h *OpenSSLHasher) Size() int {
	if h.ctx != nil {
		return h.ctx.GetSize()
	}
	return cgopenssl.GetSizeByName(h.digestName)
}

// Algorithm возвращает алгоритм хэширования
func (h *OpenSSLHasher) Algorithm() common.HashAlgorithm {
	return h.algorithm
}

// Close освобождает ресурсы
func (h *OpenSSLHasher) Close() error {
	if h.ctx != nil {
		h.ctx.Free()
		h.ctx = nil
	}
	return nil
}
