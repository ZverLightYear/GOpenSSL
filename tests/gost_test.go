package tests

import (
	"bytes"
	"crypto/rand"
	"testing"

	"gopenssl/crypto"
	"gopenssl/crypto/openssl"
)

// TestGOSTSupportCheck проверяет поддержку GOST алгоритмов
func TestGOSTSupportCheck(t *testing.T) {
	provider := openssl.NewProvider()

	// Проверяем поддержку GOST шифрования
	if !provider.IsGOSTSupported() {
		t.Skip("GOST algorithms not supported, skipping GOST tests")
	}

	t.Log("GOST algorithms are supported")

	// Проверяем поддержку GrassHopper
	if !provider.IsGrassHopperSupported() {
		t.Log("GrassHopper algorithms not supported")
	} else {
		t.Log("GrassHopper algorithms are supported")
	}
}

// TestGOSTEncryptionDecryption тестирует GOST шифрование и дешифрование
func TestGOSTEncryptionDecryption(t *testing.T) {
	provider := openssl.NewProvider()

	if !provider.IsGOSTSupported() {
		t.Skip("GOST algorithms not supported")
	}

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

// TestGOSTStreaming тестирует потоковое GOST шифрование
func TestGOSTStreaming(t *testing.T) {
	provider := openssl.NewProvider()

	if !provider.IsGOSTSupported() {
		t.Skip("GOST algorithms not supported")
	}

	// Генерируем тестовые ключи и IV
	key := make([]byte, 32)
	iv := make([]byte, 8)
	rand.Read(key)
	rand.Read(iv)

	testData := []byte("Hello, World! This is a test message for GOST streaming encryption.")

	// Тестируем потоковое шифрование для CBC режима
	cipher, err := provider.NewCipher(crypto.GOST, crypto.ModeCBC, key, iv)
	if err != nil {
		t.Fatalf("Failed to create GOST-CBC cipher: %v", err)
	}

	// Создаем потоковый шифратор
	encryptStream, err := cipher.EncryptStream()
	if err != nil {
		t.Fatalf("Failed to create encryption stream: %v", err)
	}
	defer encryptStream.Close()

	// Разбиваем данные на части и шифруем
	chunkSize := 4 // Меньший размер для 64-битного блока
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

// TestGOSTHash тестирует GOST 34.11 хэширование
func TestGOSTHash(t *testing.T) {
	provider := openssl.NewProvider()

	// Создаем GOST 34.11 хэшер
	hasher, err := provider.NewHasher(crypto.GOST34_11)
	if err != nil {
		t.Skipf("GOST 34.11 not supported: %v", err)
	}

	// Проверяем свойства хэшера
	if hasher.Algorithm() != crypto.GOST34_11 {
		t.Errorf("Expected algorithm GOST34_11, got %s", hasher.Algorithm())
	}

	expectedSize := 32 // GOST 34.11 produces 256-bit (32-byte) hash
	if hasher.Size() != expectedSize {
		t.Errorf("Expected hash size %d, got %d", expectedSize, hasher.Size())
	}

	// Тестируем хэширование
	testData := []byte("Hello, World! This is a test message for GOST 34.11 hashing.")

	_, err = hasher.Write(testData)
	if err != nil {
		t.Fatalf("Failed to write data to GOST 34.11 hasher: %v", err)
	}

	hash := hasher.Sum()
	if len(hash) != expectedSize {
		t.Errorf("Expected hash length %d, got %d", expectedSize, len(hash))
	}

	// Проверяем, что хэш не пустой
	if bytes.Equal(hash, make([]byte, expectedSize)) {
		t.Error("GOST 34.11 hash should not be all zeros")
	}

	// Проверяем детерминированность
	hasher2, _ := provider.NewHasher(crypto.GOST34_11)
	hasher2.Write(testData)
	hash2 := hasher2.Sum()

	if !bytes.Equal(hash, hash2) {
		t.Error("GOST 34.11 hashes should be identical for same data")
	}

	// Проверяем сброс
	hasher.Reset()
	hasher.Write(testData)
	hash3 := hasher.Sum()

	if !bytes.Equal(hash, hash3) {
		t.Error("GOST 34.11 hash should be identical after reset")
	}
}

// TestGOSTEmptyData тестирует GOST с пустыми данными
func TestGOSTEmptyData(t *testing.T) {
	provider := openssl.NewProvider()

	if !provider.IsGOSTSupported() {
		t.Skip("GOST algorithms not supported")
	}

	key := make([]byte, 32)
	iv := make([]byte, 8)
	rand.Read(key)
	rand.Read(iv)

	cipher, err := provider.NewCipher(crypto.GOST, crypto.ModeCBC, key, iv)
	if err != nil {
		t.Fatalf("Failed to create GOST cipher: %v", err)
	}

	// Тестируем с пустыми данными
	emptyData := []byte{}

	encrypted, err := cipher.Encrypt(emptyData)
	if err != nil {
		t.Fatalf("Failed to encrypt empty data: %v", err)
	}

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt empty data: %v", err)
	}

	if !bytes.Equal(emptyData, decrypted) {
		t.Error("Empty data GOST encryption/decryption failed")
	}
}

// TestGOSTLargeData тестирует GOST с большими данными
func TestGOSTLargeData(t *testing.T) {
	provider := openssl.NewProvider()

	if !provider.IsGOSTSupported() {
		t.Skip("GOST algorithms not supported")
	}

	key := make([]byte, 32)
	iv := make([]byte, 8)
	rand.Read(key)
	rand.Read(iv)

	cipher, err := provider.NewCipher(crypto.GOST, crypto.ModeCBC, key, iv)
	if err != nil {
		t.Fatalf("Failed to create GOST cipher: %v", err)
	}

	// Создаем большие данные (100KB)
	largeData := make([]byte, 100*1024)
	rand.Read(largeData)

	// Шифруем большие данные
	encrypted, err := cipher.Encrypt(largeData)
	if err != nil {
		t.Fatalf("Failed to encrypt large data: %v", err)
	}

	// Проверяем, что зашифрованные данные отличаются от исходных
	if bytes.Equal(largeData, encrypted) {
		t.Error("Large encrypted data should not be identical to plaintext")
	}

	// Дешифруем большие данные
	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt large data: %v", err)
	}

	// Проверяем, что дешифрованные данные совпадают с исходными
	if !bytes.Equal(largeData, decrypted) {
		t.Error("Large data GOST decryption failed")
	}
}

// TestGrassHopperEncryption тестирует GrassHopper шифрование (если поддерживается)
func TestGrassHopperEncryption(t *testing.T) {
	provider := openssl.NewProvider()

	if !provider.IsGrassHopperSupported() {
		t.Skip("GrassHopper algorithms not supported")
	}

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

// BenchmarkGOSTEncryption измеряет производительность GOST шифрования
func BenchmarkGOSTEncryption(b *testing.B) {
	provider := openssl.NewProvider()

	if !provider.IsGOSTSupported() {
		b.Skip("GOST algorithms not supported")
	}

	key := make([]byte, 32)
	iv := make([]byte, 8)
	rand.Read(key)
	rand.Read(iv)

	cipher, err := provider.NewCipher(crypto.GOST, crypto.ModeCBC, key, iv)
	if err != nil {
		b.Fatalf("Failed to create GOST cipher: %v", err)
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

// BenchmarkGOSTDecryption измеряет производительность GOST дешифрования
func BenchmarkGOSTDecryption(b *testing.B) {
	provider := openssl.NewProvider()

	if !provider.IsGOSTSupported() {
		b.Skip("GOST algorithms not supported")
	}

	key := make([]byte, 32)
	iv := make([]byte, 8)
	rand.Read(key)
	rand.Read(iv)

	cipher, err := provider.NewCipher(crypto.GOST, crypto.ModeCBC, key, iv)
	if err != nil {
		b.Fatalf("Failed to create GOST cipher: %v", err)
	}

	testData := make([]byte, 1024)
	rand.Read(testData)

	encrypted, err := cipher.Encrypt(testData)
	if err != nil {
		b.Fatalf("Failed to encrypt test data: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cipher.Decrypt(encrypted)
		if err != nil {
			b.Fatalf("Decryption failed: %v", err)
		}
	}
}

// BenchmarkGOSTHash измеряет производительность GOST 34.11 хэширования
func BenchmarkGOSTHash(b *testing.B) {
	provider := openssl.NewProvider()

	hasher, err := provider.NewHasher(crypto.GOST34_11)
	if err != nil {
		b.Skipf("GOST 34.11 not supported: %v", err)
	}

	testData := make([]byte, 1024)
	rand.Read(testData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hasher.Reset()
		hasher.Write(testData)
		_ = hasher.Sum()
	}
}
