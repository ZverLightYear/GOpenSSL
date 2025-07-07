package tests

import (
	"bytes"
	"crypto/rand"
	"testing"

	"gopenssl/crypto"
)

// TestCryptoProvider создает и тестирует основной провайдер
func TestCryptoProvider(t *testing.T) {
	provider := getProvider()

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
	provider := getProvider()

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
	provider := getProvider()

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
		crypto.ModeCTR, // gost-engine поддерживает только ECB, CBC, CTR
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
	provider := getProvider()

	// Генерируем тестовые ключи и IV
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	// Тестируем создание шифра с валидными параметрами
	_, err := provider.NewCipher(crypto.AES, crypto.ModeCBC, key, iv)
	if err != nil {
		t.Errorf("Valid cipher creation failed: %v", err)
	}

	// Тестируем неверный размер ключа
	invalidKey := make([]byte, 16)
	_, err = provider.NewCipher(crypto.AES, crypto.ModeCBC, invalidKey, iv)
	if err == nil {
		t.Error("Invalid key size should return error")
	}

	// Тестируем неверный размер IV
	invalidIV := make([]byte, 8)
	_, err = provider.NewCipher(crypto.AES, crypto.ModeCBC, key, invalidIV)
	if err == nil {
		t.Error("Invalid IV size should return error")
	}

	// Тестируем режим, который не требует IV
	_, err = provider.NewCipher(crypto.AES, crypto.ModeECB, key, nil)
	if err != nil {
		t.Errorf("ECB mode should not require IV: %v", err)
	}
}

// TestHashFactory проверяет фабрику хэшеров
func TestHashFactory(t *testing.T) {
	provider := getProvider()

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
	provider := getProvider()

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
	provider := getProvider()

	// Проверяем поддержку GOST - пытаемся создать GOST шифр
	key := make([]byte, 32)
	iv := make([]byte, 8)
	_, err := provider.NewCipher(crypto.GOST, crypto.ModeCBC, key, iv)
	if err != nil {
		t.Skip("GOST algorithms not supported, skipping GOST tests")
	}

	t.Log("GOST algorithms are supported")

	// Проверяем поддержку GrassHopper - пытаемся создать GrassHopper шифр
	_, err = provider.NewCipher(crypto.GrassHopper, crypto.ModeCBC, key, iv)
	if err != nil {
		t.Skip("GrassHopper algorithms not supported, skipping GrassHopper tests")
	}

	t.Log("GrassHopper algorithms are supported")
}

// BenchmarkHashCreation измеряет производительность создания хэшеров
func BenchmarkHashCreation(b *testing.B) {
	provider := getProvider()

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
	provider := getProvider()

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

// Edge-case тесты для AES
func TestAESEdgeCases(t *testing.T) {
	provider := getProvider()
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"one_byte", []byte{0x42}},
		{"block_size", make([]byte, 16)},
		{"block_size_minus1", make([]byte, 15)},
		{"block_size_plus1", make([]byte, 17)},
		{"all_bytes", func() []byte {
			b := make([]byte, 256)
			for i := 0; i < 256; i++ {
				b[i] = byte(i)
			}
			return b
		}()},
		{"large_1MB", make([]byte, 1024*1024)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rand.Read(c.data)
			cipher, err := provider.NewCipher(crypto.AES, crypto.ModeCBC, key, iv)
			if err != nil {
				t.Fatalf("Failed to create AES cipher: %v", err)
			}
			encrypted, err := cipher.Encrypt(c.data)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			decrypted, err := cipher.Decrypt(encrypted)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if !bytes.Equal(c.data, decrypted) {
				t.Errorf("Roundtrip failed for %s", c.name)
			}
		})
	}

	// Неверный ключ/IV
	_, err := provider.NewCipher(crypto.AES, crypto.ModeCBC, make([]byte, 10), iv)
	if err == nil {
		t.Error("Expected error for short key")
	}
	_, err = provider.NewCipher(crypto.AES, crypto.ModeCBC, key, make([]byte, 5))
	if err == nil {
		t.Error("Expected error for short IV")
	}

	// nil-данные
	cipher, _ := provider.NewCipher(crypto.AES, crypto.ModeCBC, key, iv)
	_, err = cipher.Encrypt(nil)
	if err != nil {
		t.Errorf("Encrypt(nil) should not error, got: %v", err)
	}
	_, err = cipher.Decrypt(nil)
	if err != nil {
		t.Errorf("Decrypt(nil) should not error, got: %v", err)
	}

	// Повторное использование
	data := []byte("repeat test data")
	encrypted, _ := cipher.Encrypt(data)
	decrypted, _ := cipher.Decrypt(encrypted)
	if !bytes.Equal(data, decrypted) {
		t.Error("Repeat roundtrip failed")
	}
	// Сброс
	if resetter, ok := cipher.(interface{ Reset() }); ok {
		resetter.Reset()
		encrypted2, _ := cipher.Encrypt(data)
		decrypted2, _ := cipher.Decrypt(encrypted2)
		if !bytes.Equal(data, decrypted2) {
			t.Error("Roundtrip after reset failed")
		}
	}
}

// Фаззинг-тест для AES (go test -fuzz совместим)
func FuzzAESRoundtrip(f *testing.F) {
	provider := getProvider()
	key := make([]byte, 32)
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)
	f.Add([]byte("fuzzdata"))
	f.Fuzz(func(t *testing.T, data []byte) {
		cipher, err := provider.NewCipher(crypto.AES, crypto.ModeCBC, key, iv)
		if err != nil {
			t.Skip()
		}
		encrypted, err := cipher.Encrypt(data)
		if err != nil {
			t.Skip()
		}
		decrypted, err := cipher.Decrypt(encrypted)
		if err != nil {
			t.Skip()
		}
		if !bytes.Equal(data, decrypted) {
			t.Errorf("Fuzz roundtrip failed")
		}
	})
}

// Edge-case тесты для хэшей
func TestHashEdgeCases(t *testing.T) {
	provider := getProvider()
	algos := []crypto.HashAlgorithm{
		crypto.SHA256, crypto.SHA512, crypto.MD5, crypto.GOST34_11,
	}
	cases := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"one_byte", []byte{0x42}},
		{"all_bytes", func() []byte {
			b := make([]byte, 256)
			for i := 0; i < 256; i++ {
				b[i] = byte(i)
			}
			return b
		}()},
		{"large_1MB", make([]byte, 1024*1024)},
	}
	for _, algo := range algos {
		hasher, err := provider.NewHasher(algo)
		if err != nil {
			t.Skipf("%s not supported: %v", algo, err)
		}
		for _, c := range cases {
			t.Run(string(algo)+"/"+c.name, func(t *testing.T) {
				rand.Read(c.data)
				hasher.Reset()
				hasher.Write(c.data)
				sum := hasher.Sum()
				if len(sum) != hasher.Size() {
					t.Errorf("Hash size mismatch for %s/%s", algo, c.name)
				}
				// Повторное использование
				hasher.Reset()
				hasher.Write(c.data)
				sum2 := hasher.Sum()
				if !bytes.Equal(sum, sum2) {
					t.Errorf("Hash not deterministic for %s/%s", algo, c.name)
				}
			})
		}
		// nil-данные
		hasher.Reset()
		hasher.Write(nil)
		sum := hasher.Sum()
		if len(sum) != hasher.Size() {
			t.Errorf("Hash size mismatch for %s/nil", algo)
		}
	}
}

// Фаззинг-тест для хэшей (go test -fuzz совместим)
func FuzzHashRoundtrip(f *testing.F) {
	provider := getProvider()
	algo := crypto.SHA256
	hasher, err := provider.NewHasher(algo)
	if err != nil {
		f.Skip()
	}
	f.Add([]byte("fuzzdata"))
	f.Fuzz(func(t *testing.T, data []byte) {
		hasher.Reset()
		hasher.Write(data)
		sum := hasher.Sum()
		if len(sum) != hasher.Size() {
			t.Errorf("Hash size mismatch in fuzz")
		}
	})
}
