package providers

import (
	"fmt"
	cgopenssl "gopenssl/cgo"
	"strings"
	"sync"

	"gopenssl/internal/common"
	"gopenssl/internal/factories"
)

// Глобальный синглтон провайдера
var (
	globalProvider *OpenSSLProvider
	providerOnce   sync.Once
)

// GetProvider возвращает глобальный синглтон провайдера
func GetProvider() *OpenSSLProvider {
	providerOnce.Do(func() {
		globalProvider = &OpenSSLProvider{
			cipherFactory: factories.NewCipherFactory(),
			hashFactory:   factories.NewHashFactory(),
		}
	})
	return globalProvider
}

// OpenSSLProvider реализует интерфейс CryptoProvider для OpenSSL
type OpenSSLProvider struct {
	cipherFactory *factories.CipherFactory
	hashFactory   *factories.HashFactory

	// Кэш для списков шифров и хэшей
	ciphersCache []string
	hashesCache  []string
	cacheOnce    sync.Once
}

// NewProvider создает новый OpenSSL провайдер
func NewProvider() *OpenSSLProvider {
	return &OpenSSLProvider{
		cipherFactory: factories.NewCipherFactory(),
		hashFactory:   factories.NewHashFactory(),
	}
}

// OpenSSLVersion возвращает версию OpenSSL
func (p *OpenSSLProvider) OpenSSLVersion() string {
	return cgopenssl.OpenSSLVersion()
}

// ListCiphers возвращает список доступных шифров (кэшированный)
func (p *OpenSSLProvider) ListCiphers() []string {
	p.cacheOnce.Do(func() {
		// Получаем реальный список из OpenSSL через cgo
		p.ciphersCache = cgopenssl.ListCiphers()
		p.hashesCache = cgopenssl.ListHashes()
	})
	return p.ciphersCache
}

// ListHashes возвращает список доступных хэш-алгоритмов (кэшированный)
func (p *OpenSSLProvider) ListHashes() []string {
	p.cacheOnce.Do(func() {
		// TODO: Реализовать через cgo
		p.ciphersCache = []string{"AES-256-CBC", "AES-256-GCM", "gost89", "gost89-cbc"}
		p.hashesCache = []string{"SHA256", "SHA512", "MD5", "md_gost94"}
	})
	return p.hashesCache
}

// NewCipher создает новый шифр
func (p *OpenSSLProvider) NewCipher(algorithm common.CipherAlgorithm, mode common.CipherMode, key []byte, iv []byte) (common.Cipher, error) {
	return p.cipherFactory.NewCipher(algorithm, mode, key, iv)
}

// SupportedAlgorithms возвращает список поддерживаемых алгоритмов шифрования
func (p *OpenSSLProvider) SupportedAlgorithms() []common.CipherAlgorithm {
	return p.cipherFactory.SupportedAlgorithms()
}

// SupportedModes возвращает список поддерживаемых режимов для алгоритма
func (p *OpenSSLProvider) SupportedModes(algorithm common.CipherAlgorithm) []common.CipherMode {
	return p.cipherFactory.SupportedModes(algorithm)
}

// NewHasher создает новый хэшер
func (p *OpenSSLProvider) NewHasher(algorithm common.HashAlgorithm) (common.Hasher, error) {
	return p.hashFactory.NewHasher(algorithm)
}

// SupportedHashAlgorithms возвращает список поддерживаемых алгоритмов хэширования
func (p *OpenSSLProvider) SupportedHashAlgorithms() []common.HashAlgorithm {
	return p.hashFactory.SupportedHashAlgorithms()
}

// ValidateCipherParams проверяет параметры шифра
func (p *OpenSSLProvider) ValidateCipherParams(algorithm common.CipherAlgorithm, mode common.CipherMode, key []byte, iv []byte) error {
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
func (p *OpenSSLProvider) getExpectedKeySize(algorithm common.CipherAlgorithm) int {
	switch algorithm {
	case common.AES:
		return 32 // AES-256
	case common.GOST:
		return 32 // GOST 28147-89
	case common.GrassHopper:
		return 32 // GrassHopper
	default:
		return 0
	}
}

// getExpectedIVSize возвращает ожидаемый размер IV для алгоритма
func (p *OpenSSLProvider) getExpectedIVSize(algorithm common.CipherAlgorithm) int {
	switch algorithm {
	case common.AES:
		return 16 // 128 bits
	case common.GOST:
		return 8 // 64 bits
	case common.GrassHopper:
		return 16 // 128 bits
	default:
		return 0
	}
}

// requiresIV проверяет, требует ли режим IV
func (p *OpenSSLProvider) requiresIV(mode common.CipherMode) bool {
	switch mode {
	case common.ModeECB:
		return false
	case common.ModeCBC, common.ModeCFB, common.ModeOFB, common.ModeCTR, common.ModeGCM, common.ModeCCM:
		return true
	default:
		return true
	}
}

// IsGOSTSupported проверяет поддержку GOST алгоритмов
func (p *OpenSSLProvider) IsGOSTSupported() bool {
	ciphers := p.ListCiphers()
	for _, cipher := range ciphers {
		if strings.Contains(strings.ToLower(cipher), "gost") {
			return true
		}
	}
	return false
}

// IsGrassHopperSupported проверяет поддержку GrassHopper алгоритмов
func (p *OpenSSLProvider) IsGrassHopperSupported() bool {
	ciphers := p.ListCiphers()
	for _, cipher := range ciphers {
		if strings.Contains(strings.ToLower(cipher), "grasshopper") ||
			strings.Contains(strings.ToLower(cipher), "magma") ||
			strings.Contains(strings.ToLower(cipher), "kuznyechik") {
			return true
		}
	}
	return false
}
