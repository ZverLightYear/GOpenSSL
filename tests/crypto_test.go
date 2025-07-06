package tests

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"testing"

	"gopenssl"
)

func TestAESEncryption(t *testing.T) {
	// Тестируем различные режимы AES
	modes := []struct {
		keySize string
		mode    string
	}{
		{gopenssl.AES128, gopenssl.AESCBC},
		{gopenssl.AES192, gopenssl.AESCBC},
		{gopenssl.AES256, gopenssl.AESCBC},
		{gopenssl.AES128, gopenssl.AESCFB},
		{gopenssl.AES256, gopenssl.AESCFB},
	}

	for _, test := range modes {
		t.Run(fmt.Sprintf("%s-%s", test.keySize, test.mode), func(t *testing.T) {
			// Создаем AES шифратор
			aes, err := gopenssl.NewAES(test.keySize, test.mode)
			if err != nil {
				t.Fatalf("Failed to create AES cipher: %v", err)
			}
			defer aes.Free()

			// Генерируем ключ и IV
			key := make([]byte, aes.KeySize())
			iv := make([]byte, aes.IVSize())

			if _, err := rand.Read(key); err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			if _, err := rand.Read(iv); err != nil {
				t.Fatalf("Failed to generate IV: %v", err)
			}

			// Тестовые данные
			plaintext := []byte("Hello, GOpenSSL! This is a test message for AES encryption.")

			// Шифруем
			ciphertext, err := aes.Encrypt(plaintext, key, iv)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Расшифровываем
			decrypted, err := aes.Decrypt(ciphertext, key, iv)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Проверяем результат
			if string(plaintext) != string(decrypted) {
				t.Errorf("Encryption/decryption failed: got %s, want %s",
					string(decrypted), string(plaintext))
			}
		})
	}
}

func TestGOSTEncryption(t *testing.T) {
	// Тестируем различные режимы GOST
	modes := []string{
		gopenssl.GOSTCFB,
		gopenssl.GOSTCBC,
		gopenssl.GOSTCTR,
	}

	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			// Создаем GOST шифратор
			gost, err := gopenssl.NewGOST(mode)
			if err != nil {
				t.Skipf("GOST %s not available: %v", mode, err)
			}
			defer gost.Free()

			// Генерируем ключ и IV
			key := make([]byte, gost.KeySize())
			iv := make([]byte, gost.IVSize())

			if _, err := rand.Read(key); err != nil {
				t.Fatalf("Failed to generate key: %v", err)
			}
			if _, err := rand.Read(iv); err != nil {
				t.Fatalf("Failed to generate IV: %v", err)
			}

			// Тестовые данные
			plaintext := []byte("Hello, GOST! This is a test message for GOST encryption.")

			// Шифруем
			ciphertext, err := gost.Encrypt(plaintext, key, iv)
			if err != nil {
				t.Fatalf("Encryption failed: %v", err)
			}

			// Расшифровываем
			decrypted, err := gost.Decrypt(ciphertext, key, iv)
			if err != nil {
				t.Fatalf("Decryption failed: %v", err)
			}

			// Проверяем результат
			if string(plaintext) != string(decrypted) {
				t.Errorf("Encryption/decryption failed: got %s, want %s",
					string(decrypted), string(plaintext))
			}
		})
	}
}

func TestRSAEncryption(t *testing.T) {
	// Создаем RSA объект
	rsa := gopenssl.NewRSA()
	defer rsa.Free()

	// Генерируем RSA ключи
	if err := rsa.GenerateKey(2048); err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Тестовые данные
	plaintext := []byte("Hello, RSA!")

	// Шифруем с PKCS1 padding
	ciphertext, err := rsa.Encrypt(plaintext, gopenssl.RSA_PKCS1_PADDING)
	if err != nil {
		t.Fatalf("RSA encryption failed: %v", err)
	}

	// Расшифровываем
	decrypted, err := rsa.Decrypt(ciphertext, gopenssl.RSA_PKCS1_PADDING)
	if err != nil {
		t.Fatalf("RSA decryption failed: %v", err)
	}

	// Проверяем результат
	if string(plaintext) != string(decrypted) {
		t.Errorf("RSA encryption/decryption failed: got %s, want %s",
			string(decrypted), string(plaintext))
	}
}

func TestRSASignature(t *testing.T) {
	// Создаем RSA объект
	rsa := gopenssl.NewRSA()
	defer rsa.Free()

	// Генерируем RSA ключи
	if err := rsa.GenerateKey(2048); err != nil {
		t.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Тестовые данные
	data := []byte("Hello, RSA signature!")

	// Подписываем
	signature, err := rsa.Sign(data, gopenssl.SHA256)
	if err != nil {
		t.Fatalf("RSA signing failed: %v", err)
	}

	// Проверяем подпись
	if err := rsa.Verify(data, signature, gopenssl.SHA256); err != nil {
		t.Fatalf("RSA signature verification failed: %v", err)
	}
}

func TestKeySizes(t *testing.T) {
	// Тестируем размеры ключей для AES
	aes, err := gopenssl.NewAES(gopenssl.AES256, gopenssl.AESCBC)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}
	defer aes.Free()

	if aes.KeySize() != 32 { // 256 bits = 32 bytes
		t.Errorf("AES-256 key size: got %d, want 32", aes.KeySize())
	}

	if aes.IVSize() != 16 { // AES block size
		t.Errorf("AES IV size: got %d, want 16", aes.IVSize())
	}

	if aes.BlockSize() != 16 { // AES block size
		t.Errorf("AES block size: got %d, want 16", aes.BlockSize())
	}
}

func TestHashAlgorithms(t *testing.T) {
	// Тестируем различные алгоритмы хэширования
	algorithms := []struct {
		name string
		size int
	}{
		{gopenssl.SHA1, 20},
		{gopenssl.SHA256, 32},
		{gopenssl.SHA512, 64},
		{gopenssl.MD5, 16},
	}

	for _, alg := range algorithms {
		t.Run(alg.name, func(t *testing.T) {
			hash, err := gopenssl.NewHash(alg.name)
			if err != nil {
				t.Fatalf("Failed to create %s hash: %v", alg.name, err)
			}
			defer hash.Free()

			// Проверяем размер хэша
			if hash.Size() != alg.size {
				t.Errorf("%s hash size: got %d, want %d", alg.name, hash.Size(), alg.size)
			}

			// Тестовые данные
			data := []byte("Hello, GOpenSSL! This is a test message for hashing.")

			// Вычисляем хэш
			digest, err := hash.Sum(data)
			if err != nil {
				t.Fatalf("%s hashing failed: %v", alg.name, err)
			}

			// Проверяем размер результата
			if len(digest) != alg.size {
				t.Errorf("%s digest size: got %d, want %d", alg.name, len(digest), alg.size)
			}

			// Проверяем, что хэш не пустой
			if len(digest) == 0 {
				t.Errorf("%s digest is empty", alg.name)
			}

			t.Logf("%s digest: %s", alg.name, hex.EncodeToString(digest))
		})
	}
}

func TestGOSTHashAlgorithms(t *testing.T) {
	// Тестируем GOST алгоритмы хэширования
	algorithms := []struct {
		name string
		size int
	}{
		{gopenssl.GOSTR34112012256, 32},
		{gopenssl.GOSTR34112012512, 64},
	}

	for _, alg := range algorithms {
		t.Run(alg.name, func(t *testing.T) {
			hash, err := gopenssl.NewHash(alg.name)
			if err != nil {
				t.Skipf("GOST hash %s not available: %v", alg.name, err)
			}
			defer hash.Free()

			// Проверяем размер хэша
			if hash.Size() != alg.size {
				t.Errorf("%s hash size: got %d, want %d", alg.name, hash.Size(), alg.size)
			}

			// Тестовые данные
			data := []byte("Hello, GOST! This is a test message for GOST hashing.")

			// Вычисляем хэш
			digest, err := hash.Sum(data)
			if err != nil {
				t.Fatalf("%s hashing failed: %v", alg.name, err)
			}

			// Проверяем размер результата
			if len(digest) != alg.size {
				t.Errorf("%s digest size: got %d, want %d", alg.name, len(digest), alg.size)
			}

			t.Logf("%s digest: %s", alg.name, hex.EncodeToString(digest))
		})
	}
}

func TestRandomBytes(t *testing.T) {
	// Тестируем генерацию случайных байтов
	sizes := []int{16, 32, 64, 128}

	for _, size := range sizes {
		t.Run(fmt.Sprintf("size_%d", size), func(t *testing.T) {
			bytes, err := gopenssl.GenerateRandomBytes(size)
			if err != nil {
				t.Fatalf("Failed to generate random bytes: %v", err)
			}

			if len(bytes) != size {
				t.Errorf("Random bytes size: got %d, want %d", len(bytes), size)
			}

			// Проверяем, что байты не все нули
			allZero := true
			for _, b := range bytes {
				if b != 0 {
					allZero = false
					break
				}
			}

			if allZero {
				t.Error("Generated bytes are all zero")
			}
		})
	}
}
