package ciphers

import (
	"fmt"
	cgopenssl "gopenssl/cgo"

	"gopenssl/internal/common"
)

// OpenSSLCipher реализует интерфейс Cipher для OpenSSL
type OpenSSLCipher struct {
	algorithm  common.CipherAlgorithm
	mode       common.CipherMode
	cipherName string
	key        []byte
	iv         []byte
}

// NewOpenSSLCipher создает новый OpenSSL шифр
func NewOpenSSLCipher(algorithm common.CipherAlgorithm, mode common.CipherMode, cipherName string, key []byte, iv []byte) (*OpenSSLCipher, error) {
	return &OpenSSLCipher{
		algorithm:  algorithm,
		mode:       mode,
		cipherName: cipherName,
		key:        key,
		iv:         iv,
	}, nil
}

// Encrypt шифрует данные
func (c *OpenSSLCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return []byte{}, nil
	}

	// Создаем новый контекст для шифрования
	ctx, err := cgopenssl.NewCipherContext(c.cipherName, true, c.key, c.iv)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption context: %v", err)
	}
	if ctx == nil {
		return nil, fmt.Errorf("failed to create encryption context")
	}
	defer ctx.Free()

	// Шифруем данные
	updateResult, err := ctx.Update(plaintext)
	if err != nil {
		return nil, fmt.Errorf("encryption update failed: %v", err)
	}

	// Завершаем шифрование
	finalResult, err := ctx.Final()
	if err != nil {
		return nil, fmt.Errorf("encryption final failed: %v", err)
	}

	// Объединяем результаты
	result := make([]byte, 0, len(updateResult)+len(finalResult))
	result = append(result, updateResult...)
	result = append(result, finalResult...)

	return result, nil
}

// Decrypt расшифровывает данные
func (c *OpenSSLCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return []byte{}, nil
	}

	// Создаем новый контекст для дешифрования
	ctx, err := cgopenssl.NewCipherContext(c.cipherName, false, c.key, c.iv)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryption context: %v", err)
	}
	if ctx == nil {
		return nil, fmt.Errorf("failed to create decryption context")
	}
	defer ctx.Free()

	// Дешифруем данные
	updateResult, err := ctx.Update(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decryption update failed: %v", err)
	}

	// Завершаем дешифрование
	finalResult, err := ctx.Final()
	if err != nil {
		return nil, fmt.Errorf("decryption final failed: %v", err)
	}

	// Объединяем результаты
	result := make([]byte, 0, len(updateResult)+len(finalResult))
	result = append(result, updateResult...)
	result = append(result, finalResult...)

	return result, nil
}

// EncryptStream создает потоковый шифратор
func (c *OpenSSLCipher) EncryptStream() (common.CipherStream, error) {
	ctx, err := cgopenssl.NewCipherContext(c.cipherName, true, c.key, c.iv)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryption stream context: %v", err)
	}
	if ctx == nil {
		return nil, fmt.Errorf("failed to create encryption stream context")
	}

	return &OpenSSLCipherStream{
		ctx:       ctx,
		isEncrypt: true,
		buffer:    make([]byte, 0),
	}, nil
}

// DecryptStream создает потоковый дешифратор
func (c *OpenSSLCipher) DecryptStream() (common.CipherStream, error) {
	ctx, err := cgopenssl.NewCipherContext(c.cipherName, false, c.key, c.iv)
	if err != nil {
		return nil, fmt.Errorf("failed to create decryption stream context: %v", err)
	}
	if ctx == nil {
		return nil, fmt.Errorf("failed to create decryption stream context")
	}

	return &OpenSSLCipherStream{
		ctx:       ctx,
		isEncrypt: false,
		buffer:    make([]byte, 0),
	}, nil
}

// Algorithm возвращает алгоритм шифра
func (c *OpenSSLCipher) Algorithm() common.CipherAlgorithm {
	return c.algorithm
}

// Mode возвращает режим работы
func (c *OpenSSLCipher) Mode() common.CipherMode {
	return c.mode
}

// KeySize возвращает размер ключа в байтах
func (c *OpenSSLCipher) KeySize() int {
	return len(c.key)
}

// BlockSize возвращает размер блока в байтах
func (c *OpenSSLCipher) BlockSize() int {
	return cgopenssl.GetBlockSizeByName(c.cipherName)
}

// OpenSSLCipherStream представляет потоковый интерфейс для шифрования/дешифрования
type OpenSSLCipherStream struct {
	ctx       *cgopenssl.CipherContext
	isEncrypt bool
	buffer    []byte
}

// Write шифрует/дешифрует данные
func (s *OpenSSLCipherStream) Write(data []byte) (int, error) {
	s.buffer = append(s.buffer, data...)
	return len(data), nil
}

// Final завершает операцию и возвращает финальные данные
func (s *OpenSSLCipherStream) Final() ([]byte, error) {
	if len(s.buffer) == 0 {
		return []byte{}, nil
	}

	// Обрабатываем данные
	updateResult, err := s.ctx.Update(s.buffer)
	if err != nil {
		return nil, fmt.Errorf("stream update failed: %v", err)
	}

	// Завершаем операцию
	finalResult, err := s.ctx.Final()
	if err != nil {
		return nil, fmt.Errorf("stream final failed: %v", err)
	}

	// Объединяем результаты
	result := make([]byte, 0, len(updateResult)+len(finalResult))
	result = append(result, updateResult...)
	result = append(result, finalResult...)

	return result, nil
}

// Reset сбрасывает состояние потока
func (s *OpenSSLCipherStream) Reset() error {
	if s.ctx != nil {
		err := s.ctx.Reset()
		if err != nil {
			return fmt.Errorf("failed to reset stream: %v", err)
		}
	}
	s.buffer = s.buffer[:0]
	return nil
}

// Close освобождает ресурсы
func (s *OpenSSLCipherStream) Close() error {
	if s.ctx != nil {
		s.ctx.Free()
		s.ctx = nil
	}
	return nil
}
