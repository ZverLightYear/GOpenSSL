package openssl

import (
	"fmt"
	"strings"
	"sync"

	gopenssl "gopenssl/cgo"
	"gopenssl/crypto"
)

// Глобальный синглтон провайдера
var (
	globalProvider *Provider
	providerOnce   sync.Once
)

// GetProvider возвращает глобальный синглтон провайдера
func GetProvider() *Provider {
	providerOnce.Do(func() {
		globalProvider = &Provider{
			cipherFactory: NewCipherFactory(),
			hashFactory:   NewHashFactory(),
		}
	})
	return globalProvider
}

// Provider реализует интерфейс CryptoProvider для OpenSSL
type Provider struct {
	cipherFactory *CipherFactory
	hashFactory   *HashFactory

	// Кэш для списков шифров и хэшей
	ciphersCache []string
	hashesCache  []string
	cacheOnce    sync.Once
}

// NewProvider создает новый OpenSSL провайдер
func NewProvider() *Provider {
	return &Provider{
		cipherFactory: NewCipherFactory(),
		hashFactory:   NewHashFactory(),
	}
}

// OpenSSLVersion возвращает версию OpenSSL
func (p *Provider) OpenSSLVersion() string {
	return gopenssl.OpenSSLVersion()
}

// ListCiphers возвращает список доступных шифров (кэшированный)
func (p *Provider) ListCiphers() []string {
	p.cacheOnce.Do(func() {
		p.ciphersCache = gopenssl.ListCiphers()
		p.hashesCache = gopenssl.ListHashes()
	})
	return p.ciphersCache
}

// ListHashes возвращает список доступных хэш-алгоритмов (кэшированный)
func (p *Provider) ListHashes() []string {
	p.cacheOnce.Do(func() {
		p.ciphersCache = gopenssl.ListCiphers()
		p.hashesCache = gopenssl.ListHashes()
	})
	return p.hashesCache
}

// NewCipher создает новый шифр
func (p *Provider) NewCipher(algorithm crypto.CipherAlgorithm, mode crypto.CipherMode, key []byte, iv []byte) (crypto.Cipher, error) {
	return p.cipherFactory.NewCipher(algorithm, mode, key, iv)
}

// SupportedAlgorithms возвращает список поддерживаемых алгоритмов шифрования
func (p *Provider) SupportedAlgorithms() []crypto.CipherAlgorithm {
	return p.cipherFactory.SupportedAlgorithms()
}

// SupportedModes возвращает список поддерживаемых режимов для алгоритма
func (p *Provider) SupportedModes(algorithm crypto.CipherAlgorithm) []crypto.CipherMode {
	return p.cipherFactory.SupportedModes(algorithm)
}

// NewHasher создает новый хэшер
func (p *Provider) NewHasher(algorithm crypto.HashAlgorithm) (crypto.Hasher, error) {
	return p.hashFactory.NewHasher(algorithm)
}

// SupportedHashAlgorithms возвращает список поддерживаемых алгоритмов хэширования
func (p *Provider) SupportedHashAlgorithms() []crypto.HashAlgorithm {
	return p.hashFactory.SupportedHashAlgorithms()
}

// ValidateCipherParams проверяет параметры шифра
func (p *Provider) ValidateCipherParams(algorithm crypto.CipherAlgorithm, mode crypto.CipherMode, key []byte, iv []byte) error {
	// Проверяем поддержку алгоритма
	supported := p.SupportedAlgorithms()
	found := false
	for _, alg := range supported {
		if alg == algorithm {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("unsupported cipher algorithm: %s", algorithm)
	}

	// Проверяем поддержку режима
	supportedModes := p.SupportedModes(algorithm)
	found = false
	for _, m := range supportedModes {
		if m == mode {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("unsupported mode %s for algorithm %s", mode, algorithm)
	}

	// Проверяем размер ключа
	expectedKeySize := p.getExpectedKeySize(algorithm)
	if len(key) != expectedKeySize {
		return fmt.Errorf("invalid key size: got %d, expected %d", len(key), expectedKeySize)
	}

	// Проверяем IV для режимов, которые его требуют
	if p.requiresIV(mode) {
		expectedIVSize := p.getExpectedIVSize(algorithm)
		if len(iv) != expectedIVSize {
			return fmt.Errorf("invalid IV size: got %d, expected %d", len(iv), expectedIVSize)
		}
	}

	return nil
}

// getExpectedKeySize возвращает ожидаемый размер ключа для алгоритма
func (p *Provider) getExpectedKeySize(algorithm crypto.CipherAlgorithm) int {
	switch algorithm {
	case crypto.AES:
		return 32 // AES-256
	case crypto.GOST:
		return 32 // GOST 28147-89
	case crypto.GrassHopper:
		return 32 // GrassHopper
	default:
		return 0
	}
}

// getExpectedIVSize возвращает ожидаемый размер IV для алгоритма
func (p *Provider) getExpectedIVSize(algorithm crypto.CipherAlgorithm) int {
	switch algorithm {
	case crypto.AES:
		return 16 // 128 bits
	case crypto.GOST:
		return 8 // 64 bits
	case crypto.GrassHopper:
		return 16 // 128 bits
	default:
		return 0
	}
}

// requiresIV проверяет, требует ли режим IV
func (p *Provider) requiresIV(mode crypto.CipherMode) bool {
	switch mode {
	case crypto.ModeECB:
		return false
	case crypto.ModeCBC, crypto.ModeCFB, crypto.ModeOFB, crypto.ModeCTR, crypto.ModeGCM, crypto.ModeCCM:
		return true
	default:
		return true
	}
}

// IsGOSTSupported проверяет поддержку GOST алгоритмов
func (p *Provider) IsGOSTSupported() bool {
	ciphers := p.ListCiphers()
	for _, cipher := range ciphers {
		if strings.Contains(strings.ToLower(cipher), "gost") {
			return true
		}
	}
	return false
}

// IsGrassHopperSupported проверяет поддержку GrassHopper алгоритмов
func (p *Provider) IsGrassHopperSupported() bool {
	ciphers := p.ListCiphers()
	for _, cipher := range ciphers {
		if strings.Contains(strings.ToLower(cipher), "grasshopper") ||
			strings.Contains(strings.ToLower(cipher), "magma") {
			return true
		}
	}
	return false
}
