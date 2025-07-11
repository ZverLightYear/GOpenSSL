package common

// CipherMode представляет режим работы блочного шифра
type CipherMode string

const (
	ModeECB CipherMode = "ECB"
	ModeCBC CipherMode = "CBC"
	ModeCFB CipherMode = "CFB"
	ModeOFB CipherMode = "OFB"
	ModeCTR CipherMode = "CTR"
	ModeGCM CipherMode = "GCM"
	ModeCCM CipherMode = "CCM"
	ModeXTS CipherMode = "XTS"
)

// CipherAlgorithm представляет алгоритм блочного шифра
type CipherAlgorithm string

const (
	AES         CipherAlgorithm = "AES"
	GOST        CipherAlgorithm = "GOST"
	GrassHopper CipherAlgorithm = "GrassHopper"
)

// HashAlgorithm представляет алгоритм хэширования
type HashAlgorithm string

const (
	SHA1      HashAlgorithm = "SHA1"
	SHA224    HashAlgorithm = "SHA224"
	SHA256    HashAlgorithm = "SHA256"
	SHA384    HashAlgorithm = "SHA384"
	SHA512    HashAlgorithm = "SHA512"
	MD5       HashAlgorithm = "MD5"
	MD4       HashAlgorithm = "MD4"
	GOST34_11 HashAlgorithm = "GOST34_11"
)

// Cipher представляет интерфейс для блочного шифра
type Cipher interface {
	// Encrypt шифрует данные
	Encrypt(plaintext []byte) ([]byte, error)

	// Decrypt расшифровывает данные
	Decrypt(ciphertext []byte) ([]byte, error)

	// EncryptStream создает потоковый шифратор
	EncryptStream() (CipherStream, error)

	// DecryptStream создает потоковый дешифратор
	DecryptStream() (CipherStream, error)

	// Algorithm возвращает алгоритм шифра
	Algorithm() CipherAlgorithm

	// Mode возвращает режим работы
	Mode() CipherMode

	// KeySize возвращает размер ключа в байтах
	KeySize() int

	// BlockSize возвращает размер блока в байтах
	BlockSize() int
}

// CipherStream представляет потоковый интерфейс для шифрования/дешифрования
type CipherStream interface {
	// Write шифрует/дешифрует данные
	Write(data []byte) (int, error)

	// Final завершает операцию и возвращает финальные данные
	Final() ([]byte, error)

	// Reset сбрасывает состояние потока
	Reset() error

	// Close освобождает ресурсы
	Close() error
}

// Hasher представляет интерфейс для хэширования
type Hasher interface {
	// Write добавляет данные для хэширования
	Write(data []byte) (int, error)

	// Sum возвращает хэш от добавленных данных
	Sum() []byte

	// Reset сбрасывает состояние хэшера
	Reset()

	// Size возвращает размер хэша в байтах
	Size() int

	// Algorithm возвращает алгоритм хэширования
	Algorithm() HashAlgorithm
}

// MAC представляет интерфейс для Message Authentication Code
type MAC interface {
	// Write добавляет данные для MAC
	Write(data []byte) (int, error)

	// Sum возвращает MAC от добавленных данных
	Sum() []byte

	// Reset сбрасывает состояние MAC
	Reset()

	// Size возвращает размер MAC в байтах
	Size() int
}

// CipherFactory создает экземпляры шифров
type CipherFactory interface {
	// NewCipher создает новый шифр
	NewCipher(algorithm CipherAlgorithm, mode CipherMode, key []byte, iv []byte) (Cipher, error)

	// SupportedAlgorithms возвращает список поддерживаемых алгоритмов
	SupportedAlgorithms() []CipherAlgorithm

	// SupportedModes возвращает список поддерживаемых режимов для алгоритма
	SupportedModes(algorithm CipherAlgorithm) []CipherMode
}

// HashFactory создает экземпляры хэшеров
type HashFactory interface {
	// NewHasher создает новый хэшер
	NewHasher(algorithm HashAlgorithm) (Hasher, error)

	// SupportedHashAlgorithms возвращает список поддерживаемых алгоритмов хэширования
	SupportedHashAlgorithms() []HashAlgorithm
}

// CryptoProvider представляет основной интерфейс для криптографических операций
type CryptoProvider interface {
	CipherFactory
	HashFactory

	// OpenSSLVersion возвращает версию OpenSSL
	OpenSSLVersion() string

	// ListCiphers возвращает список доступных шифров
	ListCiphers() []string

	// ListHashes возвращает список доступных хэш-алгоритмов
	ListHashes() []string
}
