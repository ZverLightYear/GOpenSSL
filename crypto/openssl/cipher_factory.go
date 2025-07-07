package openssl

import (
	"fmt"
	"strings"

	"gopenssl/crypto"
)

// CipherFactory создает экземпляры шифров
type CipherFactory struct {
	// Кэш поддерживаемых алгоритмов и режимов
	supportedAlgorithms []crypto.CipherAlgorithm
	supportedModes      map[crypto.CipherAlgorithm][]crypto.CipherMode
}

// NewCipherFactory создает новую фабрику шифров
func NewCipherFactory() *CipherFactory {
	factory := &CipherFactory{
		supportedModes: make(map[crypto.CipherAlgorithm][]crypto.CipherMode),
	}

	// Инициализируем поддерживаемые алгоритмы
	factory.supportedAlgorithms = []crypto.CipherAlgorithm{
		crypto.AES,
		crypto.GOST,
		crypto.GrassHopper,
	}

	// Инициализируем поддерживаемые режимы для каждого алгоритма
	factory.supportedModes[crypto.AES] = []crypto.CipherMode{
		crypto.ModeECB,
		crypto.ModeCBC,
		crypto.ModeCFB,
		crypto.ModeOFB,
		crypto.ModeCTR,
		crypto.ModeGCM,
		crypto.ModeCCM,
	}

	factory.supportedModes[crypto.GOST] = []crypto.CipherMode{
		crypto.ModeECB,
		crypto.ModeCBC,
		crypto.ModeCTR, // gost-engine поддерживает только ECB, CBC, CTR
	}

	factory.supportedModes[crypto.GrassHopper] = []crypto.CipherMode{
		crypto.ModeECB,
		crypto.ModeCBC,
		crypto.ModeCFB,
		crypto.ModeOFB,
		crypto.ModeCTR,
	}

	return factory
}

// NewCipher создает новый шифр
func (f *CipherFactory) NewCipher(algorithm crypto.CipherAlgorithm, mode crypto.CipherMode, key []byte, iv []byte) (crypto.Cipher, error) {
	// Проверяем поддержку алгоритма
	if !f.isAlgorithmSupported(algorithm) {
		return nil, fmt.Errorf("unsupported cipher algorithm: %s", algorithm)
	}

	// Проверяем поддержку режима для алгоритма
	if !f.isModeSupported(algorithm, mode) {
		return nil, fmt.Errorf("unsupported mode %s for algorithm %s", mode, algorithm)
	}

	// Для AES не проверяем размер ключа здесь, а только внутри newAESCipher
	if algorithm != crypto.AES {
		expectedKeySize := f.getExpectedKeySize(algorithm)
		if expectedKeySize > 0 && len(key) != expectedKeySize {
			return nil, fmt.Errorf("invalid key size: got %d, expected %d", len(key), expectedKeySize)
		}
	}

	// Проверяем IV для режимов, которые его требуют
	if f.requiresIV(mode) {
		expectedIVSize := f.getExpectedIVSize(algorithm)
		if len(iv) != expectedIVSize {
			return nil, fmt.Errorf("invalid IV size: got %d, expected %d", len(iv), expectedIVSize)
		}
	}

	// Создаем соответствующий шифр
	switch algorithm {
	case crypto.AES:
		return f.newAESCipher(mode, key, iv)
	case crypto.GOST:
		return f.newGOSTCipher(mode, key, iv)
	case crypto.GrassHopper:
		return f.newGrassHopperCipher(mode, key, iv)
	default:
		return nil, fmt.Errorf("unsupported cipher algorithm: %s", algorithm)
	}
}

// SupportedAlgorithms возвращает список поддерживаемых алгоритмов
func (f *CipherFactory) SupportedAlgorithms() []crypto.CipherAlgorithm {
	return f.supportedAlgorithms
}

// SupportedModes возвращает список поддерживаемых режимов для алгоритма
func (f *CipherFactory) SupportedModes(algorithm crypto.CipherAlgorithm) []crypto.CipherMode {
	return f.supportedModes[algorithm]
}

// isAlgorithmSupported проверяет поддержку алгоритма
func (f *CipherFactory) isAlgorithmSupported(algorithm crypto.CipherAlgorithm) bool {
	for _, alg := range f.supportedAlgorithms {
		if alg == algorithm {
			return true
		}
	}
	return false
}

// isModeSupported проверяет поддержку режима для алгоритма
func (f *CipherFactory) isModeSupported(algorithm crypto.CipherAlgorithm, mode crypto.CipherMode) bool {
	modes, exists := f.supportedModes[algorithm]
	if !exists {
		return false
	}

	for _, m := range modes {
		if m == mode {
			return true
		}
	}
	return false
}

// getExpectedKeySize возвращает ожидаемый размер ключа для алгоритма
func (f *CipherFactory) getExpectedKeySize(algorithm crypto.CipherAlgorithm) int {
	switch algorithm {
	case crypto.AES:
		// Для AES поддерживаем 16, 24, 32 байта
		return 0 // специальная обработка ниже
	case crypto.GOST:
		return 32 // GOST 28147-89
	case crypto.GrassHopper:
		return 32 // GrassHopper
	default:
		return 0
	}
}

// getExpectedIVSize возвращает ожидаемый размер IV для алгоритма
func (f *CipherFactory) getExpectedIVSize(algorithm crypto.CipherAlgorithm) int {
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
func (f *CipherFactory) requiresIV(mode crypto.CipherMode) bool {
	switch mode {
	case crypto.ModeECB:
		return false
	case crypto.ModeCBC, crypto.ModeCFB, crypto.ModeOFB, crypto.ModeCTR, crypto.ModeGCM, crypto.ModeCCM:
		return true
	default:
		return true
	}
}

// newAESCipher создает AES шифр
func (f *CipherFactory) newAESCipher(mode crypto.CipherMode, key []byte, iv []byte) (crypto.Cipher, error) {
	// Определяем OpenSSL имя шифра по размеру ключа
	var cipherName string
	switch len(key) {
	case 16:
		switch mode {
		case crypto.ModeECB:
			cipherName = "AES-128-ECB"
		case crypto.ModeCBC:
			cipherName = "AES-128-CBC"
		case crypto.ModeCFB:
			cipherName = "AES-128-CFB"
		case crypto.ModeOFB:
			cipherName = "AES-128-OFB"
		case crypto.ModeCTR:
			cipherName = "AES-128-CTR"
		case crypto.ModeGCM:
			cipherName = "id-aes128-GCM"
		case crypto.ModeCCM:
			cipherName = "id-aes128-CCM"
		default:
			return nil, fmt.Errorf("unsupported AES mode: %s", mode)
		}
	case 24:
		switch mode {
		case crypto.ModeECB:
			cipherName = "AES-192-ECB"
		case crypto.ModeCBC:
			cipherName = "AES-192-CBC"
		case crypto.ModeCFB:
			cipherName = "AES-192-CFB"
		case crypto.ModeOFB:
			cipherName = "AES-192-OFB"
		case crypto.ModeCTR:
			cipherName = "AES-192-CTR"
		case crypto.ModeGCM:
			cipherName = "id-aes192-GCM"
		case crypto.ModeCCM:
			cipherName = "id-aes192-CCM"
		default:
			return nil, fmt.Errorf("unsupported AES mode: %s", mode)
		}
	case 32:
		switch mode {
		case crypto.ModeECB:
			cipherName = "AES-256-ECB"
		case crypto.ModeCBC:
			cipherName = "AES-256-CBC"
		case crypto.ModeCFB:
			cipherName = "AES-256-CFB"
		case crypto.ModeOFB:
			cipherName = "AES-256-OFB"
		case crypto.ModeCTR:
			cipherName = "AES-256-CTR"
		case crypto.ModeGCM:
			cipherName = "id-aes256-GCM"
		case crypto.ModeCCM:
			cipherName = "id-aes256-CCM"
		default:
			return nil, fmt.Errorf("unsupported AES mode: %s", mode)
		}
	default:
		return nil, fmt.Errorf("invalid AES key size: got %d, expected 16, 24, or 32", len(key))
	}

	return NewOpenSSLCipher(crypto.AES, mode, cipherName, key, iv)
}

// newGOSTCipher создает GOST шифр
func (f *CipherFactory) newGOSTCipher(mode crypto.CipherMode, key []byte, iv []byte) (crypto.Cipher, error) {
	// Определяем OpenSSL имя шифра
	var cipherName string
	switch mode {
	case crypto.ModeECB:
		cipherName = "gost89"
	case crypto.ModeCBC:
		cipherName = "gost89-cbc"
	case crypto.ModeCFB:
		cipherName = "gost89-cfb"
	case crypto.ModeOFB:
		cipherName = "gost89-ofb"
	case crypto.ModeCTR:
		cipherName = "gost89-cnt" // В gost-engine используется cnt вместо ctr
	default:
		return nil, fmt.Errorf("unsupported GOST mode: %s", mode)
	}

	return NewOpenSSLCipher(crypto.GOST, mode, cipherName, key, iv)
}

// newGrassHopperCipher создает GrassHopper шифр
func (f *CipherFactory) newGrassHopperCipher(mode crypto.CipherMode, key []byte, iv []byte) (crypto.Cipher, error) {
	// Определяем OpenSSL имя шифра
	var cipherName string
	switch mode {
	case crypto.ModeECB:
		cipherName = "kuznyechik-ecb" // В gost-engine используется kuznyechik
	case crypto.ModeCBC:
		cipherName = "kuznyechik-cbc"
	case crypto.ModeCFB:
		cipherName = "kuznyechik-cfb"
	case crypto.ModeOFB:
		cipherName = "kuznyechik-ofb"
	case crypto.ModeCTR:
		cipherName = "kuznyechik-ctr"
	default:
		return nil, fmt.Errorf("unsupported GrassHopper mode: %s", mode)
	}

	return NewOpenSSLCipher(crypto.GrassHopper, mode, cipherName, key, iv)
}

// IsCipherAvailable проверяет доступность шифра в OpenSSL
func (f *CipherFactory) IsCipherAvailable(cipherName string) bool {
	// TODO: Реализовать проверку через cgo
	// Пока возвращаем true для базовых шифров
	availableCiphers := []string{
		"aes-256-ecb", "aes-256-cbc", "aes-256-cfb", "aes-256-ofb", "aes-256-ctr", "aes-256-gcm",
		"gost89", "gost89-cbc", "gost89-cfb", "gost89-ofb", "gost89-cnt",
		"kuznyechik-ecb", "kuznyechik-cbc", "kuznyechik-cfb", "kuznyechik-ofb", "kuznyechik-ctr",
	}

	for _, cipher := range availableCiphers {
		if strings.EqualFold(cipher, cipherName) {
			return true
		}
	}
	return false
}
