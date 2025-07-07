package tests

import (
	"crypto/rand"
	"testing"
	"time"

	"gopenssl/crypto"
	"gopenssl/crypto/openssl"
)

func TestQuickBenchmark(t *testing.T) {
	// Используем глобальный синглтон провайдер
	provider := openssl.GetProvider()
	if provider == nil {
		t.Fatal("Failed to get OpenSSL provider")
	}

	// Генерируем тестовые данные
	key := make([]byte, 32)    // 256 bits
	iv := make([]byte, 16)     // 128 bits
	data := make([]byte, 1024) // 1KB данных

	rand.Read(key)
	rand.Read(iv)
	rand.Read(data)

	// Тестируем только AES-256-CBC
	cipher, err := provider.NewCipher(crypto.AES, crypto.ModeCBC, key, iv)
	if err != nil {
		t.Fatalf("Failed to create AES-256-CBC cipher: %v", err)
	}

	// Быстрый бенчмарк - 1000 операций
	iterations := 1000
	start := time.Now()

	for i := 0; i < iterations; i++ {
		encrypted, err := cipher.Encrypt(data)
		if err != nil {
			t.Fatalf("Encryption failed: %v", err)
		}
		if len(encrypted) == 0 {
			t.Fatal("Encrypted data is empty")
		}
	}

	duration := time.Since(start)
	opsPerSec := float64(iterations) / duration.Seconds()
	mbPerSec := (float64(iterations) * float64(len(data)) / 1024 / 1024) / duration.Seconds()

	t.Logf("AES-256-CBC Performance:")
	t.Logf("  Iterations: %d", iterations)
	t.Logf("  Duration: %v", duration)
	t.Logf("  Operations/sec: %.2f", opsPerSec)
	t.Logf("  Throughput: %.2f MB/s", mbPerSec)
	t.Logf("  Data size: %d bytes per operation", len(data))

	// Проверяем что производительность разумная (больше 100 ops/sec)
	if opsPerSec < 100 {
		t.Errorf("Performance too low: %.2f ops/sec", opsPerSec)
	}
}
