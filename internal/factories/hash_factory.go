package factories

import (
	"fmt"
	"strings"

	"gopenssl/internal/common"
	"gopenssl/internal/hashes"
)

// HashFactory создает экземпляры хэшеров
type HashFactory struct {
	// Кэш поддерживаемых алгоритмов
	supportedAlgorithms []common.HashAlgorithm
}

// NewHashFactory создает новую фабрику хэшеров
func NewHashFactory() *HashFactory {
	factory := &HashFactory{}

	// Инициализируем поддерживаемые алгоритмы
	factory.supportedAlgorithms = []common.HashAlgorithm{
		common.SHA1,
		common.SHA224,
		common.SHA256,
		common.SHA384,
		common.SHA512,
		common.MD5,
		common.MD4,
		common.GOST34_11,
	}

	return factory
}

// NewHasher создает новый хэшер
func (f *HashFactory) NewHasher(algorithm common.HashAlgorithm) (common.Hasher, error) {
	// Проверяем поддержку алгоритма
	if !f.isAlgorithmSupported(algorithm) {
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	// Создаем соответствующий хэшер
	switch algorithm {
	case common.SHA1:
		return f.newSHA1Hasher()
	case common.SHA224:
		return f.newSHA224Hasher()
	case common.SHA256:
		return f.newSHA256Hasher()
	case common.SHA384:
		return f.newSHA384Hasher()
	case common.SHA512:
		return f.newSHA512Hasher()
	case common.MD5:
		return f.newMD5Hasher()
	case common.MD4:
		return f.newMD4Hasher()
	case common.GOST34_11:
		return f.newGOST34_11Hasher()
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// SupportedHashAlgorithms возвращает список поддерживаемых алгоритмов хэширования
func (f *HashFactory) SupportedHashAlgorithms() []common.HashAlgorithm {
	return f.supportedAlgorithms
}

// isAlgorithmSupported проверяет поддержку алгоритма
func (f *HashFactory) isAlgorithmSupported(algorithm common.HashAlgorithm) bool {
	for _, alg := range f.supportedAlgorithms {
		if alg == algorithm {
			return true
		}
	}
	return false
}

// newSHA1Hasher создает SHA1 хэшер
func (f *HashFactory) newSHA1Hasher() (common.Hasher, error) {
	return hashes.NewOpenSSLHasher(common.SHA1, "SHA1")
}

// newSHA224Hasher создает SHA224 хэшер
func (f *HashFactory) newSHA224Hasher() (common.Hasher, error) {
	return hashes.NewOpenSSLHasher(common.SHA224, "SHA224")
}

// newSHA256Hasher создает SHA256 хэшер
func (f *HashFactory) newSHA256Hasher() (common.Hasher, error) {
	return hashes.NewOpenSSLHasher(common.SHA256, "SHA256")
}

// newSHA384Hasher создает SHA384 хэшер
func (f *HashFactory) newSHA384Hasher() (common.Hasher, error) {
	return hashes.NewOpenSSLHasher(common.SHA384, "SHA384")
}

// newSHA512Hasher создает SHA512 хэшер
func (f *HashFactory) newSHA512Hasher() (common.Hasher, error) {
	return hashes.NewOpenSSLHasher(common.SHA512, "SHA512")
}

// newMD5Hasher создает MD5 хэшер
func (f *HashFactory) newMD5Hasher() (common.Hasher, error) {
	return hashes.NewOpenSSLHasher(common.MD5, "MD5")
}

// newMD4Hasher создает MD4 хэшер
func (f *HashFactory) newMD4Hasher() (common.Hasher, error) {
	return hashes.NewOpenSSLHasher(common.MD4, "MD4")
}

// newGOST34_11Hasher создает GOST 34.11 хэшер
func (f *HashFactory) newGOST34_11Hasher() (common.Hasher, error) {
	return hashes.NewOpenSSLHasher(common.GOST34_11, "md_gost94")
}

// IsHashAvailable проверяет доступность хэш-алгоритма в OpenSSL
func (f *HashFactory) IsHashAvailable(hashName string) bool {
	// TODO: Реализовать проверку через cgo
	// Пока возвращаем true для базовых алгоритмов
	availableHashes := []string{
		"sha1", "sha224", "sha256", "sha384", "sha512",
		"md5", "md4", "gost34.11",
	}

	for _, hash := range availableHashes {
		if strings.EqualFold(hash, hashName) {
			return true
		}
	}
	return false
}

// GetHashSize возвращает размер хэша для алгоритма
func (f *HashFactory) GetHashSize(algorithm common.HashAlgorithm) int {
	switch algorithm {
	case common.SHA1:
		return 20 // 160 bits
	case common.SHA224:
		return 28 // 224 bits
	case common.SHA256:
		return 32 // 256 bits
	case common.SHA384:
		return 48 // 384 bits
	case common.SHA512:
		return 64 // 512 bits
	case common.MD5:
		return 16 // 128 bits
	case common.MD4:
		return 16 // 128 bits
	case common.GOST34_11:
		return 32 // 256 bits
	default:
		return 0
	}
}
