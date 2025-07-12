package tests

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"gopenssl"
	"gopenssl/internal/common"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestAESGoCLICrossDecrypt(t *testing.T) {
	opensslPath := "../submodules/build/bin/openssl"
	if _, err := os.Stat(opensslPath); os.IsNotExist(err) {
		t.Skipf("OpenSSL CLI not found at %s", opensslPath)
	}

	provider := gopenssl.NewProvider()
	key := make([]byte, 32) // AES-256
	iv := make([]byte, 16)
	plaintext := []byte("The quick brown fox jumps over the lazy dog. This is a test string of arbitrary length!")
	rand.Read(key)
	rand.Read(iv)

	// Go encrypt → CLI decrypt
	t.Run("GoEncrypt_CliDecrypt", func(t *testing.T) {
		cipher, err := provider.NewCipher(common.AES, common.ModeCBC, key, iv)
		if err != nil {
			t.Fatalf("Go: failed to create cipher: %v", err)
		}
		ciphertext, err := cipher.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Go: failed to encrypt: %v", err)
		}
		decrypted, err := decryptWithOpenSSLNoPad(opensslPath, "AES-256-CBC", ciphertext, key, iv)
		if err != nil {
			t.Fatalf("CLI: failed to decrypt Go ciphertext: %v", err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("Go->CLI roundtrip failed\nOriginal: %x\nDecrypted: %x", plaintext, decrypted)
		}
	})

	// CLI encrypt → Go decrypt
	t.Run("CliEncrypt_GoDecrypt", func(t *testing.T) {
		ciphertext, err := encryptWithOpenSSLNoPad(opensslPath, "AES-256-CBC", plaintext, key, iv)
		if err != nil {
			t.Fatalf("CLI: failed to encrypt: %v", err)
		}
		cipher, err := provider.NewCipher(common.AES, common.ModeCBC, key, iv)
		if err != nil {
			t.Fatalf("Go: failed to create cipher: %v", err)
		}
		decrypted, err := cipher.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Go: failed to decrypt CLI ciphertext: %v", err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("CLI->Go roundtrip failed\nOriginal: %x\nDecrypted: %x", plaintext, decrypted)
		}
	})
}

func TestGOSTGoCLICrossDecrypt(t *testing.T) {
	// Проверяем, что openssl CLI доступен
	opensslPath := "../submodules/build/bin/openssl"
	if _, err := os.Stat(opensslPath); os.IsNotExist(err) {
		t.Skipf("OpenSSL CLI not found at %s", opensslPath)
	}

	// Создаем провайдер и проверяем доступные шифры
	provider := gopenssl.NewProvider()
	ciphers := provider.ListCiphers()
	t.Logf("Available ciphers in Go: %v", ciphers)

	// Проверяем поддержку GOST
	gostSupported := provider.IsGOSTSupported()
	t.Logf("GOST supported in Go: %v", gostSupported)

	// Тестовые данные (кратны размеру блока GOST - 8 байт)
	testData := []byte("Hello, World! This is a test message for GOST encryption comparison. It must be multiple of 8 bytes.")

	// Генерируем ключ и IV для GOST
	key := make([]byte, 32) // GOST 256-bit key
	iv := make([]byte, 8)   // GOST 64-bit block size

	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	_, err = rand.Read(iv)
	if err != nil {
		t.Fatalf("Failed to generate IV: %v", err)
	}

	// Тестируем cross-decrypt для GOST
	t.Run("GoEncrypt_CliDecrypt", func(t *testing.T) {
		t.Logf("Test data size: %d bytes", len(testData))
		t.Logf("Key size: %d bytes", len(key))
		t.Logf("IV size: %d bytes", len(iv))

		// Go шифрует
		cipher, err := provider.NewCipher(common.GOST, common.ModeCBC, key, iv)
		if err != nil {
			// Вывести список доступных шифров для отладки
			t.Fatalf("Go: failed to encrypt with GOST: %v\nAvailable ciphers: %v", err, ciphers)
		}
		ciphertext, err := cipher.Encrypt(testData)
		if err != nil {
			t.Fatalf("Go: failed to encrypt: %v", err)
		}
		t.Logf("Go ciphertext size: %d bytes", len(ciphertext))

		// CLI расшифровывает
		plaintext, err := decryptWithOpenSSLGOST(opensslPath, "GOST-256-CBC", ciphertext, key, iv)
		if err != nil {
			t.Fatalf("CLI: failed to decrypt Go GOST ciphertext: %v", err)
		}
		t.Logf("CLI decrypted size: %d bytes", len(plaintext))

		// Сравниваем результаты
		if !bytes.Equal(plaintext, testData) {
			t.Errorf("Go encrypt -> CLI decrypt failed:\nOriginal: %x\nDecrypted: %x", testData, plaintext)
		}
	})

	t.Run("CliEncrypt_GoDecrypt", func(t *testing.T) {
		t.Logf("Test data size: %d bytes", len(testData))
		t.Logf("Key size: %d bytes", len(key))
		t.Logf("IV size: %d bytes", len(iv))

		// CLI шифрует
		ciphertext, err := encryptWithOpenSSLGOST(opensslPath, "GOST-256-CBC", testData, key, iv)
		if err != nil {
			t.Fatalf("CLI: failed to encrypt with GOST: %v", err)
		}
		t.Logf("CLI ciphertext size: %d bytes", len(ciphertext))

		// Go расшифровывает
		cipher, err := provider.NewCipher(common.GOST, common.ModeCBC, key, iv)
		if err != nil {
			t.Fatalf("Go: failed to create GOST cipher: %v", err)
		}
		plaintext, err := cipher.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Go: failed to decrypt CLI GOST ciphertext: %v", err)
		}
		t.Logf("Go decrypted size: %d bytes", len(plaintext))

		// Сравниваем результаты
		if !bytes.Equal(plaintext, testData) {
			t.Errorf("CLI encrypt -> Go decrypt failed:\nOriginal: %x\nDecrypted: %x", testData, plaintext)
		}
	})
}

func testCipherComparison(t *testing.T, provider common.CryptoProvider, cipherName string, data, key, iv []byte, opensslPath string) {
	// Определяем алгоритм и режим из имени шифра
	var algorithm common.CipherAlgorithm
	var mode common.CipherMode

	switch cipherName {
	case "AES-256-CBC":
		algorithm = common.AES
		mode = common.ModeCBC
	case "AES-256-ECB":
		algorithm = common.AES
		mode = common.ModeECB
	case "GOST-256-CBC":
		algorithm = common.GOST
		mode = common.ModeCBC
	case "GOST-256-ECB":
		algorithm = common.GOST
		mode = common.ModeECB
	default:
		t.Fatalf("Unsupported cipher name: %s", cipherName)
	}

	// 1. Шифруем с помощью Go wrapper
	goStart := time.Now()

	cipher, err := provider.NewCipher(algorithm, mode, key, iv)
	if err != nil {
		t.Fatalf("Failed to create cipher %s: %v", cipherName, err)
	}

	encrypted, err := cipher.Encrypt(data)
	if err != nil {
		t.Fatalf("Failed to encrypt with Go: %v", err)
	}

	goEncryptTime := time.Since(goStart)

	// 2. Расшифровываем с помощью Go wrapper
	goStart = time.Now()

	decrypted, err := cipher.Decrypt(encrypted)
	if err != nil {
		t.Fatalf("Failed to decrypt with Go: %v", err)
	}

	goDecryptTime := time.Since(goStart)

	// Проверяем, что расшифрованные данные совпадают с исходными
	if !bytes.Equal(data, decrypted) {
		t.Errorf("Go decrypt result doesn't match original data")
		t.Errorf("Original: %x", data)
		t.Errorf("Decrypted: %x", decrypted)
	}

	// 3. Шифруем с помощью OpenSSL CLI
	cliStart := time.Now()

	cliEncrypted, err := encryptWithOpenSSL(opensslPath, cipherName, data, key, iv)
	if err != nil {
		t.Fatalf("Failed to encrypt with OpenSSL CLI: %v", err)
	}

	cliEncryptTime := time.Since(cliStart)

	// 4. Расшифровываем с помощью OpenSSL CLI
	cliStart = time.Now()

	cliDecrypted, err := decryptWithOpenSSL(opensslPath, cipherName, cliEncrypted, key, iv)
	if err != nil {
		t.Fatalf("Failed to decrypt with OpenSSL CLI: %v", err)
	}

	cliDecryptTime := time.Since(cliStart)

	// Проверяем, что CLI расшифрованные данные совпадают с исходными
	if !bytes.Equal(data, cliDecrypted) {
		t.Errorf("OpenSSL CLI decrypt result doesn't match original data")
		t.Errorf("Original: %x", data)
		t.Errorf("CLI Decrypted: %x", cliDecrypted)
	}

	// 5. Сравниваем результаты шифрования
	// Примечание: результаты могут отличаться из-за разных способов обработки padding
	// Поэтому сравниваем только расшифрованные результаты

	// Выводим статистику
	t.Logf("Cipher: %s", cipherName)
	t.Logf("Data size: %d bytes", len(data))
	t.Logf("Go encrypt time: %v", goEncryptTime)
	t.Logf("Go decrypt time: %v", goDecryptTime)
	t.Logf("CLI encrypt time: %v", cliEncryptTime)
	t.Logf("CLI decrypt time: %v", cliDecryptTime)
	t.Logf("Go encrypted size: %d bytes", len(encrypted))
	t.Logf("CLI encrypted size: %d bytes", len(cliEncrypted))

	// Проверяем, что размеры зашифрованных данных разумные
	if len(encrypted) == 0 {
		t.Errorf("Go encrypted data is empty")
	}
	if len(cliEncrypted) == 0 {
		t.Errorf("CLI encrypted data is empty")
	}
}

func encryptWithOpenSSL(opensslPath, cipherName string, data, key, iv []byte) ([]byte, error) {
	// Преобразуем имена алгоритмов для OpenSSL CLI
	opensslCipherName := getOpenSSLCipherName(cipherName)

	args := []string{
		"enc",
		"-" + opensslCipherName,
		"-K", fmt.Sprintf("%x", key),
		"-nopad", // Без padding для точного сравнения
	}

	if iv != nil {
		args = append(args, "-iv", fmt.Sprintf("%x", iv))
	}

	// Для GOST алгоритмов нужно загрузить engine
	if isGOSTAlgorithm(cipherName) {
		args = append([]string{"-engine", "gost"}, args...)
	}

	cmd := exec.Command(opensslPath, args...)
	cmd.Stdin = bytes.NewReader(data)
	// Устанавливаем переменные окружения для загрузки модулей
	cmd.Env = append(os.Environ(),
		"OPENSSL_MODULES=../submodules/build/lib/ossl-modules",
		"OPENSSL_ENGINES=../submodules/build/lib/engines-3",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("openssl enc failed: %v, stderr: %s", err, output)
	}

	return output, nil
}

func decryptWithOpenSSL(opensslPath, cipherName string, data, key, iv []byte) ([]byte, error) {
	// Преобразуем имена алгоритмов для OpenSSL CLI
	opensslCipherName := getOpenSSLCipherName(cipherName)

	args := []string{
		"enc",
		"-" + opensslCipherName,
		"-d", // decrypt
		"-K", fmt.Sprintf("%x", key),
		"-nopad", // Без padding для точного сравнения
	}

	if iv != nil {
		args = append(args, "-iv", fmt.Sprintf("%x", iv))
	}

	// Для GOST алгоритмов нужно загрузить engine
	if isGOSTAlgorithm(cipherName) {
		args = append([]string{"-engine", "gost"}, args...)
	}

	cmd := exec.Command(opensslPath, args...)
	cmd.Stdin = bytes.NewReader(data)
	// Устанавливаем переменные окружения для загрузки модулей
	cmd.Env = append(os.Environ(),
		"OPENSSL_MODULES=../submodules/build/lib/ossl-modules",
		"OPENSSL_ENGINES=../submodules/build/lib/engines-3",
	)

	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("openssl dec failed: %v, stderr: %s", err, output)
	}

	return output, nil
}

// getOpenSSLCipherName преобразует имена алгоритмов для OpenSSL CLI
func getOpenSSLCipherName(cipherName string) string {
	switch cipherName {
	case "AES-256-CBC":
		return "aes-256-cbc"
	case "AES-256-ECB":
		return "aes-256-ecb"
	case "GOST-256-CBC":
		return "gost89-cbc" // Используем gost89-cbc для GOST 28147-89
	case "GOST-256-ECB":
		return "gost89" // Используем gost89 для ECB режима
	default:
		return cipherName
	}
}

// isGOSTAlgorithm проверяет, является ли алгоритм GOST
func isGOSTAlgorithm(cipherName string) bool {
	return len(cipherName) >= 4 && cipherName[:4] == "GOST"
}

// encryptWithOpenSSLNoPad и decryptWithOpenSSLNoPad — версии без -nopad (используется padding по умолчанию)
func encryptWithOpenSSLNoPad(opensslPath, cipherName string, data, key, iv []byte) ([]byte, error) {
	opensslCipherName := getOpenSSLCipherName(cipherName)
	args := []string{
		"enc",
		"-" + opensslCipherName,
		"-K", fmt.Sprintf("%x", key),
	}
	if iv != nil {
		args = append(args, "-iv", fmt.Sprintf("%x", iv))
	}
	cmd := exec.Command(opensslPath, args...)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Env = append(os.Environ(),
		"OPENSSL_MODULES=../submodules/build/lib/ossl-modules",
		"OPENSSL_ENGINES=../submodules/build/lib/engines-3",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("openssl enc failed: %v, stderr: %s", err, output)
	}
	return output, nil
}

func decryptWithOpenSSLNoPad(opensslPath, cipherName string, data, key, iv []byte) ([]byte, error) {
	opensslCipherName := getOpenSSLCipherName(cipherName)
	args := []string{
		"enc",
		"-" + opensslCipherName,
		"-d",
		"-K", fmt.Sprintf("%x", key),
	}
	if iv != nil {
		args = append(args, "-iv", fmt.Sprintf("%x", iv))
	}
	cmd := exec.Command(opensslPath, args...)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Env = append(os.Environ(),
		"OPENSSL_MODULES=../submodules/build/lib/ossl-modules",
		"OPENSSL_ENGINES=../submodules/build/lib/engines-3",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("openssl dec failed: %v, stderr: %s", err, output)
	}
	return output, nil
}

// Специальные функции для GOST с engine
func encryptWithOpenSSLGOST(opensslPath, cipherName string, data, key, iv []byte) ([]byte, error) {
	opensslCipherName := getOpenSSLCipherName(cipherName)
	args := []string{
		"enc",
		"-" + opensslCipherName,
		"-K", fmt.Sprintf("%x", key),
		"-engine", "gost",
	}
	if iv != nil {
		args = append(args, "-iv", fmt.Sprintf("%x", iv))
	}
	// Для ECB режима добавляем -nopad (CBC использует стандартный padding)
	if strings.Contains(opensslCipherName, "ecb") {
		args = append(args, "-nopad")
	}

	cmd := exec.Command(opensslPath, args...)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Env = append(os.Environ(),
		"OPENSSL_MODULES=../submodules/build/lib/ossl-modules",
		"OPENSSL_ENGINES=../submodules/build/lib/engines-3",
		"DYLD_LIBRARY_PATH=../submodules/build/lib",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("openssl GOST enc failed: %v, stderr: %s\nENV: %v", err, output, cmd.Env)
	}

	// Убираем "Engine 'gost' set." из начала вывода
	output = bytes.TrimPrefix(output, []byte("Engine \"gost\" set.\n"))

	return output, nil
}

func decryptWithOpenSSLGOST(opensslPath, cipherName string, data, key, iv []byte) ([]byte, error) {
	opensslCipherName := getOpenSSLCipherName(cipherName)
	args := []string{
		"enc",
		"-" + opensslCipherName,
		"-d",
		"-K", fmt.Sprintf("%x", key),
		"-engine", "gost",
	}
	if iv != nil {
		args = append(args, "-iv", fmt.Sprintf("%x", iv))
	}
	// Для ECB режима добавляем -nopad (CBC использует стандартный padding)
	if strings.Contains(opensslCipherName, "ecb") {
		args = append(args, "-nopad")
	}

	cmd := exec.Command(opensslPath, args...)
	cmd.Stdin = bytes.NewReader(data)
	cmd.Env = append(os.Environ(),
		"OPENSSL_MODULES=../submodules/build/lib/ossl-modules",
		"OPENSSL_ENGINES=../submodules/build/lib/engines-3",
		"DYLD_LIBRARY_PATH=../submodules/build/lib",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("openssl GOST dec failed: %v, stderr: %s\nENV: %v", err, output, cmd.Env)
	}

	// Убираем "Engine 'gost' set." из начала вывода
	output = bytes.TrimPrefix(output, []byte("Engine \"gost\" set.\n"))

	return output, nil
}
