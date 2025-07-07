package tests

import (
	"bytes"
	"crypto/rand"
	"testing"

	"gopenssl/crypto"
	"gopenssl/crypto/openssl"
)

// TestMockProvider тестирует mock провайдер
func TestMockProvider(t *testing.T) {
	provider := openssl.NewMockProvider()

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

// TestMockAESEncryption тестирует AES шифрование через mock провайдер
func TestMockAESEncryption(t *testing.T) {
	provider := openssl.NewMockProvider()

	// Генерируем тестовые ключи и IV
	key := make([]byte, 32) // AES-256
	iv := make([]byte, 16)  // 128-bit IV
	rand.Read(key)
	rand.Read(iv)

	testData := []byte("Hello, World! This is a test message for AES encryption.")

	// Тестируем поддерживаемые режимы AES
	aesModes := []crypto.CipherMode{
		crypto.ModeCBC,
		crypto.ModeCTR,
	}

	for _, mode := range aesModes {
		t.Run(string(mode), func(t *testing.T) {
			// Создаем шифр
			cipher, err := provider.NewCipher(crypto.AES, mode, key, iv)
			if err != nil {
				t.Fatalf("Failed to create AES-%s cipher: %v", mode, err)
			}

			// Проверяем свойства шифра
			if cipher.Algorithm() != crypto.AES {
				t.Errorf("Expected algorithm AES, got %s", cipher.Algorithm())
			}

			if cipher.Mode() != mode {
				t.Errorf("Expected mode %s, got %s", mode, cipher.Mode())
			}

			if cipher.KeySize() != 32 {
				t.Errorf("Expected key size 32, got %d", cipher.KeySize())
			}

			blockSize := cipher.BlockSize()
			if blockSize != 16 {
				t.Errorf("Expected block size 16, got %d", blockSize)
			}

			// Шифруем данные
			encrypted, err := cipher.Encrypt(testData)
			if err != nil {
				t.Fatalf("Failed to encrypt with AES-%s: %v", mode, err)
			}

			// Проверяем, что зашифрованные данные отличаются от исходных
			if bytes.Equal(testData, encrypted) {
				t.Error("Encrypted data should not be identical to plaintext")
			}

			// Дешифруем данные
			decrypted, err := cipher.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Failed to decrypt with AES-%s: %v", mode, err)
			}

			// Проверяем, что дешифрованные данные совпадают с исходными
			if !bytes.Equal(testData, decrypted) {
				t.Error("Decrypted data should be identical to original plaintext")
			}
		})
	}
}

// TestMockHashAlgorithms тестирует хэш-алгоритмы через mock провайдер
func TestMockHashAlgorithms(t *testing.T) {
	provider := openssl.NewMockProvider()

	testData := []byte("Hello, World! This is a test message for hashing.")

	// Тестируем поддерживаемые алгоритмы
	hashAlgorithms := []crypto.HashAlgorithm{
		crypto.SHA1,
		crypto.SHA256,
		crypto.SHA512,
		crypto.MD5,
		crypto.GOST34_11,
	}

	for _, algorithm := range hashAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			// Создаем хэшер
			hasher, err := provider.NewHasher(algorithm)
			if err != nil {
				t.Fatalf("Failed to create %s hasher: %v", algorithm, err)
			}

			// Проверяем свойства хэшера
			if hasher.Algorithm() != algorithm {
				t.Errorf("Expected algorithm %s, got %s", algorithm, hasher.Algorithm())
			}

			// Проверяем размер хэша
			hashSize := hasher.Size()
			if hashSize == 0 {
				t.Error("Hash size should not be zero")
			}

			// Хэшируем данные
			_, err = hasher.Write(testData)
			if err != nil {
				t.Fatalf("Failed to write data to %s hasher: %v", algorithm, err)
			}

			hash := hasher.Sum()
			if len(hash) != hashSize {
				t.Errorf("Expected hash length %d, got %d", hashSize, len(hash))
			}

			// Проверяем, что хэш не пустой
			if bytes.Equal(hash, make([]byte, hashSize)) {
				t.Error("Hash should not be all zeros")
			}

			// Проверяем детерминированность
			hasher2, _ := provider.NewHasher(algorithm)
			hasher2.Write(testData)
			hash2 := hasher2.Sum()

			if !bytes.Equal(hash, hash2) {
				t.Error("Hashes should be identical for same data")
			}

			// Проверяем сброс
			hasher.Reset()
			hasher.Write(testData)
			hash3 := hasher.Sum()

			if !bytes.Equal(hash, hash3) {
				t.Error("Hashes should be identical after reset")
			}
		})
	}
}

// TestMockGOSTEncryption тестирует GOST шифрование через mock провайдер
func TestMockGOSTEncryption(t *testing.T) {
	provider := openssl.NewMockProvider()

	// Генерируем тестовые ключи и IV
	key := make([]byte, 32) // GOST 28147-89
	iv := make([]byte, 8)   // 64-bit IV
	rand.Read(key)
	rand.Read(iv)

	testData := []byte("Hello, World! This is a test message for GOST encryption.")

	// Тестируем поддерживаемые режимы GOST
	gostModes := []crypto.CipherMode{
		crypto.ModeECB,
		crypto.ModeCBC,
		crypto.ModeCFB,
		crypto.ModeOFB,
		crypto.ModeCTR,
	}

	for _, mode := range gostModes {
		t.Run(string(mode), func(t *testing.T) {
			// Создаем шифр
			var cipher crypto.Cipher
			var err error

			if mode == crypto.ModeECB {
				// ECB не требует IV
				cipher, err = provider.NewCipher(crypto.GOST, mode, key, nil)
			} else {
				cipher, err = provider.NewCipher(crypto.GOST, mode, key, iv)
			}

			if err != nil {
				t.Fatalf("Failed to create GOST-%s cipher: %v", mode, err)
			}

			// Проверяем свойства шифра
			if cipher.Algorithm() != crypto.GOST {
				t.Errorf("Expected algorithm GOST, got %s", cipher.Algorithm())
			}

			if cipher.Mode() != mode {
				t.Errorf("Expected mode %s, got %s", mode, cipher.Mode())
			}

			if cipher.KeySize() != 32 {
				t.Errorf("Expected key size 32, got %d", cipher.KeySize())
			}

			blockSize := cipher.BlockSize()
			if blockSize != 8 {
				t.Errorf("Expected block size 8, got %d", blockSize)
			}

			// Шифруем данные
			encrypted, err := cipher.Encrypt(testData)
			if err != nil {
				t.Fatalf("Failed to encrypt with GOST-%s: %v", mode, err)
			}

			// Проверяем, что зашифрованные данные отличаются от исходных
			if bytes.Equal(testData, encrypted) {
				t.Error("Encrypted data should not be identical to plaintext")
			}

			// Дешифруем данные
			decrypted, err := cipher.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Failed to decrypt with GOST-%s: %v", mode, err)
			}

			// Проверяем, что дешифрованные данные совпадают с исходными
			if !bytes.Equal(testData, decrypted) {
				t.Error("Decrypted data should be identical to original plaintext")
			}
		})
	}
}

// TestMockGrassHopperEncryption тестирует GrassHopper шифрование через mock провайдер
func TestMockGrassHopperEncryption(t *testing.T) {
	provider := openssl.NewMockProvider()

	// Генерируем тестовые ключи и IV
	key := make([]byte, 32) // GrassHopper
	iv := make([]byte, 16)  // 128-bit IV
	rand.Read(key)
	rand.Read(iv)

	testData := []byte("Hello, World! This is a test message for GrassHopper encryption.")

	// Тестируем поддерживаемые режимы GrassHopper
	grassHopperModes := []crypto.CipherMode{
		crypto.ModeECB,
		crypto.ModeCBC,
		crypto.ModeCFB,
		crypto.ModeOFB,
		crypto.ModeCTR,
	}

	for _, mode := range grassHopperModes {
		t.Run(string(mode), func(t *testing.T) {
			// Создаем шифр
			var cipher crypto.Cipher
			var err error

			if mode == crypto.ModeECB {
				// ECB не требует IV
				cipher, err = provider.NewCipher(crypto.GrassHopper, mode, key, nil)
			} else {
				cipher, err = provider.NewCipher(crypto.GrassHopper, mode, key, iv)
			}

			if err != nil {
				t.Fatalf("Failed to create GrassHopper-%s cipher: %v", mode, err)
			}

			// Проверяем свойства шифра
			if cipher.Algorithm() != crypto.GrassHopper {
				t.Errorf("Expected algorithm GrassHopper, got %s", cipher.Algorithm())
			}

			if cipher.Mode() != mode {
				t.Errorf("Expected mode %s, got %s", mode, cipher.Mode())
			}

			if cipher.KeySize() != 32 {
				t.Errorf("Expected key size 32, got %d", cipher.KeySize())
			}

			blockSize := cipher.BlockSize()
			if blockSize != 16 {
				t.Errorf("Expected block size 16, got %d", blockSize)
			}

			// Шифруем данные
			encrypted, err := cipher.Encrypt(testData)
			if err != nil {
				t.Fatalf("Failed to encrypt with GrassHopper-%s: %v", mode, err)
			}

			// Проверяем, что зашифрованные данные отличаются от исходных
			if bytes.Equal(testData, encrypted) {
				t.Error("Encrypted data should not be identical to plaintext")
			}

			// Дешифруем данные
			decrypted, err := cipher.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Failed to decrypt with GrassHopper-%s: %v", mode, err)
			}

			// Проверяем, что дешифрованные данные совпадают с исходными
			if !bytes.Equal(testData, decrypted) {
				t.Error("Decrypted data should be identical to original plaintext")
			}
		})
	}
}

// TestMockStreaming тестирует потоковое шифрование через mock провайдер
func TestMockStreaming(t *testing.T) {
	provider := openssl.NewMockProvider()

	// Генерируем тестовые ключи и IV
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	testData := []byte("Hello, World! This is a test message for streaming encryption.")

	// Тестируем потоковое шифрование для CBC режима
	cipher, err := provider.NewCipher(crypto.AES, crypto.ModeCBC, key, iv)
	if err != nil {
		t.Fatalf("Failed to create AES-CBC cipher: %v", err)
	}

	// Создаем потоковый шифратор
	encryptStream, err := cipher.EncryptStream()
	if err != nil {
		t.Fatalf("Failed to create encryption stream: %v", err)
	}
	defer encryptStream.Close()

	// Разбиваем данные на части и шифруем
	chunkSize := 8
	var encrypted []byte

	for i := 0; i < len(testData); i += chunkSize {
		end := i + chunkSize
		if end > len(testData) {
			end = len(testData)
		}

		chunk := testData[i:end]
		_, err := encryptStream.Write(chunk)
		if err != nil {
			t.Fatalf("Failed to write to encryption stream: %v", err)
		}
	}

	// Завершаем шифрование
	final, err := encryptStream.Final()
	if err != nil {
		t.Fatalf("Failed to finalize encryption: %v", err)
	}

	encrypted = final

	// Проверяем, что зашифрованные данные отличаются от исходных
	if bytes.Equal(testData, encrypted) {
		t.Error("Stream encrypted data should not be identical to plaintext")
	}

	// Создаем потоковый дешифратор
	decryptStream, err := cipher.DecryptStream()
	if err != nil {
		t.Fatalf("Failed to create decryption stream: %v", err)
	}
	defer decryptStream.Close()

	// Разбиваем зашифрованные данные на части и дешифруем
	var decrypted []byte

	for i := 0; i < len(encrypted); i += chunkSize {
		end := i + chunkSize
		if end > len(encrypted) {
			end = len(encrypted)
		}

		chunk := encrypted[i:end]
		_, err := decryptStream.Write(chunk)
		if err != nil {
			t.Fatalf("Failed to write to decryption stream: %v", err)
		}
	}

	// Завершаем дешифрование
	final, err = decryptStream.Final()
	if err != nil {
		t.Fatalf("Failed to finalize decryption: %v", err)
	}

	decrypted = final

	// Проверяем, что дешифрованные данные совпадают с исходными
	if !bytes.Equal(testData, decrypted) {
		t.Error("Stream decrypted data should be identical to original plaintext")
	}
}

// BenchmarkMockAESEncryption измеряет производительность mock AES шифрования
func BenchmarkMockAESEncryption(b *testing.B) {
	provider := openssl.NewMockProvider()

	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	cipher, err := provider.NewCipher(crypto.AES, crypto.ModeCBC, key, iv)
	if err != nil {
		b.Fatalf("Failed to create AES cipher: %v", err)
	}

	testData := make([]byte, 1024)
	rand.Read(testData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.Encrypt(testData)
		if err != nil {
			b.Fatalf("Encryption failed: %v", err)
		}
	}
}

// BenchmarkMockHashAlgorithms измеряет производительность mock хэш-алгоритмов
func BenchmarkMockHashAlgorithms(b *testing.B) {
	provider := openssl.NewMockProvider()

	testData := make([]byte, 1024)
	rand.Read(testData)

	algorithms := []crypto.HashAlgorithm{
		crypto.SHA1,
		crypto.SHA256,
		crypto.SHA512,
		crypto.MD5,
		crypto.GOST34_11,
	}

	for _, algorithm := range algorithms {
		b.Run(string(algorithm), func(b *testing.B) {
			hasher, err := provider.NewHasher(algorithm)
			if err != nil {
				b.Fatalf("Failed to create %s hasher: %v", algorithm, err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				hasher.Reset()
				hasher.Write(testData)
				_ = hasher.Sum()
			}
		})
	}
}
