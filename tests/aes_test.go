package tests

import (
	"bytes"
	"crypto/rand"
	"testing"

	"gopenssl"
	"gopenssl/internal/common"
)

// TestAESEncryptionDecryption тестирует AES шифрование и дешифрование
func TestAESEncryptionDecryption(t *testing.T) {
	provider := gopenssl.NewProvider()

	// Генерируем тестовые ключи и IV
	key := make([]byte, 32) // AES-256
	iv := make([]byte, 16)  // 128-bit IV
	rand.Read(key)
	rand.Read(iv)

	testData := []byte("Hello, World! This is a test message for AES encryption.")

	// Тестируем основные поддерживаемые режимы AES (GCM и CCM требуют специальной обработки)
	aesModes := []common.CipherMode{
		common.ModeECB,
		common.ModeCBC,
		common.ModeCFB,
		common.ModeOFB,
		common.ModeCTR,
		// common.ModeGCM,  // Требует специальной обработки для аутентификации
		// common.ModeCCM,  // Требует специальной обработки для аутентификации
	}

	for _, mode := range aesModes {
		t.Run(string(mode), func(t *testing.T) {
			// Создаем шифр
			var cipher common.Cipher
			var err error

			if mode == common.ModeECB {
				// ECB не требует IV
				cipher, err = provider.NewCipher(common.AES, mode, key, nil)
			} else {
				cipher, err = provider.NewCipher(common.AES, mode, key, iv)
			}

			if err != nil {
				t.Fatalf("Failed to create AES-%s cipher: %v", mode, err)
			}

			// Проверяем свойства шифра
			if cipher.Algorithm() != common.AES {
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

// TestAESStreaming тестирует потоковое AES шифрование
func TestAESStreaming(t *testing.T) {
	provider := gopenssl.NewProvider()

	// Генерируем тестовые ключи и IV
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	testData := []byte("Hello, World! This is a test message for AES streaming encryption.")

	// Тестируем потоковое шифрование для CBC режима
	cipher, err := provider.NewCipher(common.AES, common.ModeCBC, key, iv)
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

// TestAESDifferentKeySizes тестирует AES с разными размерами ключей
func TestAESDifferentKeySizes(t *testing.T) {
	provider := gopenssl.NewProvider()

	// Тестируем AES-128 (16 байт ключа)
	key128 := make([]byte, 16)
	iv := make([]byte, 16)
	rand.Read(key128)
	rand.Read(iv)

	testData := []byte("Test message for AES-128")

	// Создаем шифр с 16-байтным ключом
	cipher, err := provider.NewCipher(common.AES, common.ModeCBC, key128, iv)
	if err != nil {
		t.Fatalf("Failed to create AES cipher with 16-byte key: %v", err)
	}

	// Проверяем размер ключа
	if cipher.KeySize() != 16 {
		t.Errorf("Expected key size 16, got %d", cipher.KeySize())
	}

	// Тестируем шифрование/дешифрование
	encrypted, err := cipher.Encrypt(testData)
	if err != nil {
		t.Fatalf("Failed to encrypt with AES-128: %v", err)
	}

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt with AES-128: %v", err)
	}

	if !bytes.Equal(testData, decrypted) {
		t.Error("AES-128 decryption failed")
	}
}

// TestAESEmptyData тестирует AES с пустыми данными
func TestAESEmptyData(t *testing.T) {
	provider := gopenssl.NewProvider()

	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	cipher, err := provider.NewCipher(common.AES, common.ModeCBC, key, iv)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
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
		t.Error("Empty data encryption/decryption failed")
	}
}

// TestAESLargeData тестирует AES с большими данными
func TestAESLargeData(t *testing.T) {
	provider := gopenssl.NewProvider()

	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	cipher, err := provider.NewCipher(common.AES, common.ModeCBC, key, iv)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}

	// Создаем большие данные (1MB)
	largeData := make([]byte, 1024*1024)
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
		t.Error("Large data decryption failed")
	}
}

// BenchmarkAESEncryption измеряет производительность AES шифрования
func BenchmarkAESEncryption(b *testing.B) {
	provider := gopenssl.NewProvider()

	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	cipher, err := provider.NewCipher(common.AES, common.ModeCBC, key, iv)
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

// BenchmarkAESDecryption измеряет производительность AES дешифрования
func BenchmarkAESDecryption(b *testing.B) {
	provider := gopenssl.NewProvider()

	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	cipher, err := provider.NewCipher(common.AES, common.ModeCBC, key, iv)
	if err != nil {
		b.Fatalf("Failed to create AES cipher: %v", err)
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
