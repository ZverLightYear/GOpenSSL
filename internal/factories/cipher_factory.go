package factories

import (
	"fmt"
	"strings"

	"gopenssl/internal/ciphers"
	"gopenssl/internal/common"
)

// CipherFactory создает экземпляры шифров
type CipherFactory struct {
	// Кэш поддерживаемых алгоритмов и режимов
	supportedAlgorithms []common.CipherAlgorithm
	supportedModes      map[common.CipherAlgorithm][]common.CipherMode
}

// NewCipherFactory создает новую фабрику шифров
func NewCipherFactory() *CipherFactory {
	factory := &CipherFactory{
		supportedModes: make(map[common.CipherAlgorithm][]common.CipherMode),
	}

	// Инициализируем поддерживаемые алгоритмы
	factory.supportedAlgorithms = []common.CipherAlgorithm{
		common.AES,
		common.GOST,
		common.GrassHopper,
	}

	// Инициализируем поддерживаемые режимы для каждого алгоритма
	factory.supportedModes[common.AES] = []common.CipherMode{
		common.ModeECB,
		common.ModeCBC,
		common.ModeCFB,
		common.ModeOFB,
		common.ModeCTR,
		common.ModeGCM,
		common.ModeCCM,
	}

	factory.supportedModes[common.GOST] = []common.CipherMode{
		common.ModeECB,
		common.ModeCBC,
		common.ModeCTR, // gost-engine поддерживает только ECB, CBC, CTR
	}

	factory.supportedModes[common.GrassHopper] = []common.CipherMode{
		common.ModeECB,
		common.ModeCBC,
		common.ModeCFB,
		common.ModeOFB,
		common.ModeCTR,
	}

	return factory
}

// NewCipher создает новый шифр
func (f *CipherFactory) NewCipher(algorithm common.CipherAlgorithm, mode common.CipherMode, key []byte, iv []byte) (common.Cipher, error) {
	// Проверяем поддержку алгоритма
	if !f.isAlgorithmSupported(algorithm) {
		return nil, fmt.Errorf("unsupported cipher algorithm: %s", algorithm)
	}

	// Проверяем поддержку режима для алгоритма
	if !f.isModeSupported(algorithm, mode) {
		return nil, fmt.Errorf("unsupported mode %s for algorithm %s", mode, algorithm)
	}

	// Для AES не проверяем размер ключа здесь, а только внутри newAESCipher
	if algorithm != common.AES {
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
	case common.AES:
		return f.newAESCipher(mode, key, iv)
	case common.GOST:
		return f.newGOSTCipher(mode, key, iv)
	case common.GrassHopper:
		return f.newGrassHopperCipher(mode, key, iv)
	default:
		return nil, fmt.Errorf("unsupported cipher algorithm: %s", algorithm)
	}
}

// SupportedAlgorithms возвращает список поддерживаемых алгоритмов
func (f *CipherFactory) SupportedAlgorithms() []common.CipherAlgorithm {
	return f.supportedAlgorithms
}

// SupportedModes возвращает список поддерживаемых режимов для алгоритма
func (f *CipherFactory) SupportedModes(algorithm common.CipherAlgorithm) []common.CipherMode {
	return f.supportedModes[algorithm]
}

// isAlgorithmSupported проверяет поддержку алгоритма
func (f *CipherFactory) isAlgorithmSupported(algorithm common.CipherAlgorithm) bool {
	for _, alg := range f.supportedAlgorithms {
		if alg == algorithm {
			return true
		}
	}
	return false
}

// isModeSupported проверяет поддержку режима для алгоритма
func (f *CipherFactory) isModeSupported(algorithm common.CipherAlgorithm, mode common.CipherMode) bool {
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
func (f *CipherFactory) getExpectedKeySize(algorithm common.CipherAlgorithm) int {
	switch algorithm {
	case common.AES:
		// Для AES поддерживаем 16, 24, 32 байта
		return 0 // специальная обработка ниже
	case common.GOST:
		return 32 // GOST 28147-89
	case common.GrassHopper:
		return 32 // GrassHopper
	default:
		return 0
	}
}

// getExpectedIVSize возвращает ожидаемый размер IV для алгоритма
func (f *CipherFactory) getExpectedIVSize(algorithm common.CipherAlgorithm) int {
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
func (f *CipherFactory) requiresIV(mode common.CipherMode) bool {
	switch mode {
	case common.ModeECB:
		return false
	case common.ModeCBC, common.ModeCFB, common.ModeOFB, common.ModeCTR, common.ModeGCM, common.ModeCCM:
		return true
	default:
		return true
	}
}

// newAESCipher создает AES шифр
func (f *CipherFactory) newAESCipher(mode common.CipherMode, key []byte, iv []byte) (common.Cipher, error) {
	// Явная проверка размера ключа
	switch len(key) {
	case 16, 24, 32:
		// ok
	default:
		return nil, fmt.Errorf("invalid key size for AES: got %d, expected 16, 24, or 32", len(key))
	}

	// Определяем OpenSSL имя шифра по размеру ключа
	var cipherName string
	switch len(key) {
	case 16:
		switch mode {
		case common.ModeECB:
			cipherName = "AES-128-ECB"
		case common.ModeCBC:
			cipherName = "AES-128-CBC"
		case common.ModeCFB:
			cipherName = "AES-128-CFB"
		case common.ModeOFB:
			cipherName = "AES-128-OFB"
		case common.ModeCTR:
			cipherName = "AES-128-CTR"
		case common.ModeGCM:
			cipherName = "AES-128-GCM"
		case common.ModeCCM:
			cipherName = "AES-128-CCM"
		default:
			return nil, fmt.Errorf("unsupported mode %s for AES", mode)
		}
	case 24:
		switch mode {
		case common.ModeECB:
			cipherName = "AES-192-ECB"
		case common.ModeCBC:
			cipherName = "AES-192-CBC"
		case common.ModeCFB:
			cipherName = "AES-192-CFB"
		case common.ModeOFB:
			cipherName = "AES-192-OFB"
		case common.ModeCTR:
			cipherName = "AES-192-CTR"
		case common.ModeGCM:
			cipherName = "AES-192-GCM"
		case common.ModeCCM:
			cipherName = "AES-192-CCM"
		default:
			return nil, fmt.Errorf("unsupported mode %s for AES", mode)
		}
	case 32:
		switch mode {
		case common.ModeECB:
			cipherName = "AES-256-ECB"
		case common.ModeCBC:
			cipherName = "AES-256-CBC"
		case common.ModeCFB:
			cipherName = "AES-256-CFB"
		case common.ModeOFB:
			cipherName = "AES-256-OFB"
		case common.ModeCTR:
			cipherName = "AES-256-CTR"
		case common.ModeGCM:
			cipherName = "AES-256-GCM"
		case common.ModeCCM:
			cipherName = "AES-256-CCM"
		default:
			return nil, fmt.Errorf("unsupported mode %s for AES", mode)
		}
	}

	return ciphers.NewOpenSSLCipher(common.AES, mode, cipherName, key, iv)
}

// newGOSTCipher создает GOST шифр
func (f *CipherFactory) newGOSTCipher(mode common.CipherMode, key []byte, iv []byte) (common.Cipher, error) {
	var cipherName string
	switch mode {
	case common.ModeECB:
		cipherName = "gost89"
	case common.ModeCBC:
		cipherName = "gost89-cbc"
	case common.ModeCTR:
		cipherName = "gost89-cnt"
	default:
		return nil, fmt.Errorf("unsupported mode %s for GOST", mode)
	}

	return ciphers.NewOpenSSLCipher(common.GOST, mode, cipherName, key, iv)
}

// newGrassHopperCipher создает GrassHopper шифр
func (f *CipherFactory) newGrassHopperCipher(mode common.CipherMode, key []byte, iv []byte) (common.Cipher, error) {
	var cipherName string
	switch mode {
	case common.ModeECB:
		cipherName = "grasshopper-ecb"
	case common.ModeCBC:
		cipherName = "grasshopper-cbc"
	case common.ModeCFB:
		cipherName = "grasshopper-cfb"
	case common.ModeOFB:
		cipherName = "grasshopper-ofb"
	case common.ModeCTR:
		cipherName = "grasshopper-ctr"
	default:
		return nil, fmt.Errorf("unsupported mode %s for GrassHopper", mode)
	}

	return ciphers.NewOpenSSLCipher(common.GrassHopper, mode, cipherName, key, iv)
}

// IsCipherAvailable проверяет доступность шифра
func (f *CipherFactory) IsCipherAvailable(cipherName string) bool {
	// Проверяем, содержит ли имя шифра поддерживаемые алгоритмы
	cipherNameLower := strings.ToLower(cipherName)
	return strings.Contains(cipherNameLower, "aes") ||
		strings.Contains(cipherNameLower, "gost") ||
		strings.Contains(cipherNameLower, "grasshopper") ||
		strings.Contains(cipherNameLower, "magma")
}
