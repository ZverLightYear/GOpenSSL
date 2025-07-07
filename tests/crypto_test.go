package tests

import (
	"bytes"
	"crypto/rand"
	"testing"

	"gopenssl/crypto"
	"gopenssl/crypto/openssl"
)

// TestCryptoProvider создает и тестирует основной провайдер
func TestCryptoProvider(t *testing.T) {
	provider := openssl.NewProvider()

	// Проверяем версию OpenSSL
	version := provider.OpenSSLVersion()
	if version == "" {
		t.Error("OpenSSL version should not be empty")
	}
	t.Logf("OpenSSL version: %s", version)

	// Проверяем список шифров
	ciphers := provider.ListCiphers()
	if len(ciphers) == 0 {
		t.Error("Cipher list should not be empty")
	}
	t.Logf("Found %d ciphers", len(ciphers))

	// Проверяем список хэш-алгоритмов
	hashes := provider.ListHashes()
	if len(hashes) == 0 {
		t.Error("Hash list should not be empty")
	}
	t.Logf("Found %d hashes", len(hashes))
}

// TestSupportedAlgorithms проверяет поддерживаемые алгоритмы
func TestSupportedAlgorithms(t *testing.T) {
	provider := openssl.NewProvider()

	// Проверяем поддерживаемые алгоритмы шифрования
	cipherAlgs := provider.SupportedAlgorithms()
	expectedCipherAlgs := []crypto.CipherAlgorithm{
		crypto.AES,
		crypto.GOST,
		crypto.GrassHopper,
	}

	for _, expected := range expectedCipherAlgs {
		found := false
		for _, alg := range cipherAlgs {
			if alg == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected cipher algorithm %s not found in supported algorithms", expected)
		}
	}

	// Проверяем поддерживаемые алгоритмы хэширования
	hashAlgs := provider.SupportedHashAlgorithms()
	expectedHashAlgs := []crypto.HashAlgorithm{
		crypto.SHA1,
		crypto.SHA224,
		crypto.SHA256,
		crypto.SHA384,
		crypto.SHA512,
		crypto.MD5,
		crypto.MD4,
		crypto.GOST34_11,
	}

	for _, expected := range expectedHashAlgs {
		found := false
		for _, alg := range hashAlgs {
			if alg == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected hash algorithm %s not found in supported algorithms", expected)
		}
	}
}

// TestSupportedModes проверяет поддерживаемые режимы
func TestSupportedModes(t *testing.T) {
	provider := openssl.NewProvider()

	// Проверяем режимы для AES
	aesModes := provider.SupportedModes(crypto.AES)
	expectedAESModes := []crypto.CipherMode{
		crypto.ModeECB,
		crypto.ModeCBC,
		crypto.ModeCFB,
		crypto.ModeOFB,
		crypto.ModeCTR,
		crypto.ModeGCM,
		crypto.ModeCCM,
	}

	for _, expected := range expectedAESModes {
		found := false
		for _, mode := range aesModes {
			if mode == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected AES mode %s not found in supported modes", expected)
		}
	}

	// Проверяем режимы для GOST
	gostModes := provider.SupportedModes(crypto.GOST)
	expectedGOSTModes := []crypto.CipherMode{
		crypto.ModeECB,
		crypto.ModeCBC,
		crypto.ModeCFB,
		crypto.ModeOFB,
		crypto.ModeCTR,
	}

	for _, expected := range expectedGOSTModes {
		found := false
		for _, mode := range gostModes {
			if mode == expected {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Expected GOST mode %s not found in supported modes", expected)
		}
	}
}

// TestCipherValidation проверяет валидацию параметров шифра
func TestCipherValidation(t *testing.T) {
	provider := openssl.NewProvider()

	// Генерируем тестовые ключи и IV
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	// Тестируем валидные параметры
	err := provider.ValidateCipherParams(crypto.AES, crypto.ModeCBC, key, iv)
	if err != nil {
		t.Errorf("Valid cipher params should not return error: %v", err)
	}

	// Тестируем неверный размер ключа
	invalidKey := make([]byte, 16)
	err = provider.ValidateCipherParams(crypto.AES, crypto.ModeCBC, invalidKey, iv)
	if err == nil {
		t.Error("Invalid key size should return error")
	}

	// Тестируем неверный размер IV
	invalidIV := make([]byte, 8)
	err = provider.ValidateCipherParams(crypto.AES, crypto.ModeCBC, key, invalidIV)
	if err == nil {
		t.Error("Invalid IV size should return error")
	}

	// Тестируем режим, который не требует IV
	err = provider.ValidateCipherParams(crypto.AES, crypto.ModeECB, key, nil)
	if err != nil {
		t.Errorf("ECB mode should not require IV: %v", err)
	}
}

// TestHashFactory проверяет фабрику хэшеров
func TestHashFactory(t *testing.T) {
	provider := openssl.NewProvider()

	// Тестируем создание SHA256 хэшера
	hasher, err := provider.NewHasher(crypto.SHA256)
	if err != nil {
		t.Fatalf("Failed to create SHA256 hasher: %v", err)
	}

	// Проверяем свойства хэшера
	if hasher.Algorithm() != crypto.SHA256 {
		t.Errorf("Expected algorithm SHA256, got %s", hasher.Algorithm())
	}

	expectedSize := 32 // SHA256 produces 256-bit (32-byte) hash
	if hasher.Size() != expectedSize {
		t.Errorf("Expected hash size %d, got %d", expectedSize, hasher.Size())
	}

	// Тестируем хэширование
	testData := []byte("Hello, World!")
	_, err = hasher.Write(testData)
	if err != nil {
		t.Errorf("Failed to write data to hasher: %v", err)
	}

	hash := hasher.Sum()
	if len(hash) != expectedSize {
		t.Errorf("Expected hash length %d, got %d", expectedSize, len(hash))
	}

	// Проверяем, что хэш не пустой
	if bytes.Equal(hash, make([]byte, expectedSize)) {
		t.Error("Hash should not be all zeros")
	}

	// Тестируем сброс
	hasher.Reset()
	hasher.Write(testData)
	hash2 := hasher.Sum()

	// Хэши должны быть одинаковыми для одинаковых данных
	if !bytes.Equal(hash, hash2) {
		t.Error("Hashes should be identical for same data after reset")
	}
}

// TestCipherFactory проверяет фабрику шифров
func TestCipherFactory(t *testing.T) {
	provider := openssl.NewProvider()

	// Генерируем тестовые ключи и IV
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	// Тестируем создание AES шифра
	cipher, err := provider.NewCipher(crypto.AES, crypto.ModeCBC, key, iv)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	// Проверяем свойства шифра
	if cipher.Algorithm() != crypto.AES {
		t.Errorf("Expected algorithm AES, got %s", cipher.Algorithm())
	}

	if cipher.Mode() != crypto.ModeCBC {
		t.Errorf("Expected mode CBC, got %s", cipher.Mode())
	}

	if cipher.KeySize() != 32 {
		t.Errorf("Expected key size 32, got %d", cipher.KeySize())
	}

	blockSize := cipher.BlockSize()
	if blockSize == 0 {
		t.Error("Block size should not be zero")
	}

	// Тестируем шифрование и дешифрование
	testData := []byte("Hello, World! This is a test message for encryption.")

	// Шифруем
	encrypted, err := cipher.Encrypt(testData)
	if err != nil {
		t.Fatalf("Failed to encrypt data: %v", err)
	}

	// Проверяем, что зашифрованные данные отличаются от исходных
	if bytes.Equal(testData, encrypted) {
		t.Error("Encrypted data should not be identical to plaintext")
	}

	// Дешифруем
	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt data: %v", err)
	}

	// Проверяем, что дешифрованные данные совпадают с исходными
	if !bytes.Equal(testData, decrypted) {
		t.Error("Decrypted data should be identical to original plaintext")
	}
}

// TestGOSTSupport проверяет поддержку GOST алгоритмов
func TestGOSTSupport(t *testing.T) {
	provider := openssl.NewProvider()

	// Проверяем поддержку GOST
	if !provider.IsGOSTSupported() {
		t.Skip("GOST algorithms not supported, skipping GOST tests")
	}

	t.Log("GOST algorithms are supported")

	// Проверяем поддержку GrassHopper
	if !provider.IsGrassHopperSupported() {
		t.Skip("GrassHopper algorithms not supported, skipping GrassHopper tests")
	}

	t.Log("GrassHopper algorithms are supported")
}

// BenchmarkHashCreation измеряет производительность создания хэшеров
func BenchmarkHashCreation(b *testing.B) {
	provider := openssl.NewProvider()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher, err := provider.NewHasher(crypto.SHA256)
		if err != nil {
			b.Fatalf("Failed to create hasher: %v", err)
		}
		_ = hasher
	}
}

// BenchmarkCipherCreation измеряет производительность создания шифров
func BenchmarkCipherCreation(b *testing.B) {
	provider := openssl.NewProvider()

	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cipher, err := provider.NewCipher(crypto.AES, crypto.ModeCBC, key, iv)
		if err != nil {
			b.Fatalf("Failed to create cipher: %v", err)
		}
		_ = cipher
	}
}
