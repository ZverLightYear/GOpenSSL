package tests

import (
	"testing"

	"gopenssl/crypto"
	"gopenssl/crypto/openssl"
)

// TestSingletonProvider проверяет что синглтон провайдера работает правильно
func TestSingletonProvider(t *testing.T) {
	// Получаем провайдер несколько раз
	provider1 := getProvider()
	provider2 := getProvider()
	provider3 := openssl.GetProvider()

	// Проверяем что это один и тот же экземпляр
	if provider1 != provider2 {
		t.Error("getProvider() должен возвращать один и тот же экземпляр")
	}

	if provider1 != provider3 {
		t.Error("openssl.GetProvider() должен возвращать тот же экземпляр")
	}

	// Проверяем что провайдер работает
	version := provider1.OpenSSLVersion()
	if version == "" {
		t.Error("Версия OpenSSL не должна быть пустой")
	}

	ciphers := provider1.ListCiphers()
	if len(ciphers) == 0 {
		t.Error("Список шифров не должен быть пустым")
	}

	hashes := provider1.ListHashes()
	if len(hashes) == 0 {
		t.Error("Список хэшей не должен быть пустым")
	}

	t.Logf("OpenSSL version: %s", version)
	t.Logf("Found %d ciphers", len(ciphers))
	t.Logf("Found %d hashes", len(hashes))
}

// TestMultipleCalls проверяет что множественные вызовы не создают новые экземпляры
func TestMultipleCalls(t *testing.T) {
	// Вызываем getProvider много раз
	providers := make([]crypto.CryptoProvider, 10)
	for i := 0; i < 10; i++ {
		providers[i] = getProvider()
	}

	// Проверяем что все экземпляры одинаковые
	first := providers[0]
	for i := 1; i < 10; i++ {
		if providers[i] != first {
			t.Errorf("Провайдер %d должен быть тем же экземпляром", i)
		}
	}

	// Проверяем что провайдер работает после множественных вызовов
	cipher, err := first.NewCipher(crypto.AES, crypto.ModeCBC, make([]byte, 32), make([]byte, 16))
	if err != nil {
		t.Errorf("Не удалось создать шифр после множественных вызовов: %v", err)
	}

	if cipher == nil {
		t.Error("Шифр не должен быть nil")
	}
}
