package openssl

import (
	"fmt"
	"strings"

	"gopenssl/crypto"
)

// HashFactory создает экземпляры хэшеров
type HashFactory struct {
	// Кэш поддерживаемых алгоритмов
	supportedAlgorithms []crypto.HashAlgorithm
}

// NewHashFactory создает новую фабрику хэшеров
func NewHashFactory() *HashFactory {
	factory := &HashFactory{}

	// Инициализируем поддерживаемые алгоритмы
	factory.supportedAlgorithms = []crypto.HashAlgorithm{
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
		crypto.MD5,
		crypto.MD4,
		crypto.GOST34_11,
	}

	return factory
}

// NewHasher создает новый хэшер
func (f *HashFactory) NewHasher(algorithm crypto.HashAlgorithm) (crypto.Hasher, error) {
	// Проверяем поддержку алгоритма
	if !f.isAlgorithmSupported(algorithm) {
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}

	// Создаем соответствующий хэшер
	switch algorithm {
	case crypto.SHA1:
		return f.newSHA1Hasher()
	case crypto.SHA224:
		return f.newSHA224Hasher()
	case crypto.SHA256:
		return f.newSHA256Hasher()
	case crypto.SHA384:
		return f.newSHA384Hasher()
	case crypto.SHA512:
		return f.newSHA512Hasher()
	case crypto.MD5:
		return f.newMD5Hasher()
	case crypto.MD4:
		return f.newMD4Hasher()
	case crypto.GOST34_11:
		return f.newGOST34_11Hasher()
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// SupportedHashAlgorithms возвращает список поддерживаемых алгоритмов хэширования
func (f *HashFactory) SupportedHashAlgorithms() []crypto.HashAlgorithm {
	return f.supportedAlgorithms
}

// isAlgorithmSupported проверяет поддержку алгоритма
func (f *HashFactory) isAlgorithmSupported(algorithm crypto.HashAlgorithm) bool {
	for _, alg := range f.supportedAlgorithms {
		if alg == algorithm {
			return true
		}
	}
	return false
}

// newSHA1Hasher создает SHA1 хэшер
func (f *HashFactory) newSHA1Hasher() (crypto.Hasher, error) {
	return NewOpenSSLHasher(crypto.SHA1, "SHA1")
}

// newSHA224Hasher создает SHA224 хэшер
func (f *HashFactory) newSHA224Hasher() (crypto.Hasher, error) {
	return NewOpenSSLHasher(crypto.SHA224, "SHA224")
}

// newSHA256Hasher создает SHA256 хэшер
func (f *HashFactory) newSHA256Hasher() (crypto.Hasher, error) {
	return NewOpenSSLHasher(crypto.SHA256, "SHA256")
}

// newSHA384Hasher создает SHA384 хэшер
func (f *HashFactory) newSHA384Hasher() (crypto.Hasher, error) {
	return NewOpenSSLHasher(crypto.SHA384, "SHA384")
}

// newSHA512Hasher создает SHA512 хэшер
func (f *HashFactory) newSHA512Hasher() (crypto.Hasher, error) {
	return NewOpenSSLHasher(crypto.SHA512, "SHA512")
}

// newMD5Hasher создает MD5 хэшер
func (f *HashFactory) newMD5Hasher() (crypto.Hasher, error) {
	return NewOpenSSLHasher(crypto.MD5, "MD5")
}

// newMD4Hasher создает MD4 хэшер
func (f *HashFactory) newMD4Hasher() (crypto.Hasher, error) {
	return NewOpenSSLHasher(crypto.MD4, "MD4")
}

// newGOST34_11Hasher создает GOST 34.11 хэшер
func (f *HashFactory) newGOST34_11Hasher() (crypto.Hasher, error) {
	return NewOpenSSLHasher(crypto.GOST34_11, "md_gost94")
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
func (f *HashFactory) GetHashSize(algorithm crypto.HashAlgorithm) int {
	switch algorithm {
	case crypto.SHA1:
		return 20 // 160 bits
	case crypto.SHA224:
		return 28 // 224 bits
	case crypto.SHA256:
		return 32 // 256 bits
	case crypto.SHA384:
		return 48 // 384 bits
	case crypto.SHA512:
		return 64 // 512 bits
	case crypto.MD5:
		return 16 // 128 bits
	case crypto.MD4:
		return 16 // 128 bits
	case crypto.GOST34_11:
		return 32 // 256 bits
	default:
		return 0
	}
}
