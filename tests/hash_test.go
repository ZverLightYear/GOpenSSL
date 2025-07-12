package tests

import (
	"bytes"
	"crypto/rand"
	"testing"

	"gopenssl"
	"gopenssl/internal/common"
)

// TestHashAlgorithms тестирует все поддерживаемые алгоритмы хэширования
func TestHashAlgorithms(t *testing.T) {
	provider := gopenssl.NewProvider()

	testData := []byte("Hello, World! This is a test message for hashing.")

	// Тестируем все поддерживаемые алгоритмы
	hashAlgorithms := []common.HashAlgorithm{
		common.SHA1,
		common.SHA224,
		common.SHA256,
		common.SHA384,
		common.SHA512,
		common.MD5,
		common.MD4,
		common.GOST34_11,
	}

	for _, algorithm := range hashAlgorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			// Создаем хэшер
			hasher, err := provider.NewHasher(algorithm)
			if err != nil {
				// MD4 должен поддерживаться
				if algorithm == common.MD4 {
					t.Fatalf("MD4 not supported - this should work!: %v", err)
				}
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

// TestHashSizes проверяет размеры хэшей для разных алгоритмов
func TestHashSizes(t *testing.T) {
	provider := gopenssl.NewProvider()

	expectedSizes := map[common.HashAlgorithm]int{
		common.SHA1:      20, // 160 bits
		common.SHA224:    28, // 224 bits
		common.SHA256:    32, // 256 bits
		common.SHA384:    48, // 384 bits
		common.SHA512:    64, // 512 bits
		common.MD5:       16, // 128 bits
		common.MD4:       16, // 128 bits
		common.GOST34_11: 32, // 256 bits
	}

	for algorithm, expectedSize := range expectedSizes {
		t.Run(string(algorithm), func(t *testing.T) {
			hasher, err := provider.NewHasher(algorithm)
			if err != nil {
				// MD4 должен поддерживаться
				if algorithm == common.MD4 {
					t.Fatalf("MD4 not supported - this should work!: %v", err)
				}
				t.Fatalf("Failed to create %s hasher: %v", algorithm, err)
			}

			actualSize := hasher.Size()
			if actualSize != expectedSize {
				t.Errorf("Expected %s hash size %d, got %d", algorithm, expectedSize, actualSize)
			}
		})
	}
}

// TestHashEmptyData тестирует хэширование пустых данных
func TestHashEmptyData(t *testing.T) {
	provider := gopenssl.NewProvider()

	algorithms := []common.HashAlgorithm{
		common.SHA256,
		common.MD5,
		common.GOST34_11,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			hasher, err := provider.NewHasher(algorithm)
			if err != nil {
				t.Fatalf("Failed to create %s hasher: %v", algorithm, err)
			}

			// Хэшируем пустые данные
			emptyData := []byte{}
			_, err = hasher.Write(emptyData)
			if err != nil {
				t.Fatalf("Failed to write empty data to %s hasher: %v", algorithm, err)
			}

			hash := hasher.Sum()
			expectedSize := hasher.Size()

			if len(hash) != expectedSize {
				t.Errorf("Empty data hash should have size %d, got %d", expectedSize, len(hash))
			}

			// Проверяем, что хэш не пустой (даже для пустых данных)
			if bytes.Equal(hash, make([]byte, expectedSize)) {
				t.Error("Empty data hash should not be all zeros")
			}
		})
	}
}

// TestHashLargeData тестирует хэширование больших данных
func TestHashLargeData(t *testing.T) {
	provider := gopenssl.NewProvider()

	// Создаем большие данные (1MB)
	largeData := make([]byte, 1024*1024)
	rand.Read(largeData)

	algorithms := []common.HashAlgorithm{
		common.SHA256,
		common.SHA512,
		common.GOST34_11,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			hasher, err := provider.NewHasher(algorithm)
			if err != nil {
				t.Fatalf("Failed to create %s hasher: %v", algorithm, err)
			}

			// Хэшируем большие данные
			_, err = hasher.Write(largeData)
			if err != nil {
				t.Fatalf("Failed to write large data to %s hasher: %v", algorithm, err)
			}

			hash := hasher.Sum()
			expectedSize := hasher.Size()

			if len(hash) != expectedSize {
				t.Errorf("Large data hash should have size %d, got %d", expectedSize, len(hash))
			}

			// Проверяем, что хэш не пустой
			if bytes.Equal(hash, make([]byte, expectedSize)) {
				t.Error("Large data hash should not be all zeros")
			}
		})
	}
}

// TestHashStreaming тестирует потоковое хэширование
func TestHashStreaming(t *testing.T) {
	provider := gopenssl.NewProvider()

	testData := []byte("Hello, World! This is a test message for streaming hashing.")

	algorithms := []common.HashAlgorithm{
		common.SHA256,
		common.SHA512,
		common.GOST34_11,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			// Создаем хэшер для обычного хэширования
			hasher1, err := provider.NewHasher(algorithm)
			if err != nil {
				t.Fatalf("Failed to create %s hasher: %v", algorithm, err)
			}

			// Хэшируем данные целиком
			hasher1.Write(testData)
			expectedHash := hasher1.Sum()

			// Создаем хэшер для потокового хэширования
			hasher2, err := provider.NewHasher(algorithm)
			if err != nil {
				t.Fatalf("Failed to create %s hasher for streaming: %v", algorithm, err)
			}

			// Разбиваем данные на части и хэшируем
			chunkSize := 8
			for i := 0; i < len(testData); i += chunkSize {
				end := i + chunkSize
				if end > len(testData) {
					end = len(testData)
				}

				chunk := testData[i:end]
				_, err := hasher2.Write(chunk)
				if err != nil {
					t.Fatalf("Failed to write chunk to %s hasher: %v", algorithm, err)
				}
			}

			streamingHash := hasher2.Sum()

			// Проверяем, что результаты одинаковые
			if !bytes.Equal(expectedHash, streamingHash) {
				t.Error("Streaming hash should be identical to regular hash")
			}
		})
	}
}

// TestHashReset тестирует сброс хэшера
func TestHashReset(t *testing.T) {
	provider := gopenssl.NewProvider()

	testData1 := []byte("First message")
	testData2 := []byte("Second message")

	algorithms := []common.HashAlgorithm{
		common.SHA256,
		common.SHA512,
		common.GOST34_11,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			hasher, err := provider.NewHasher(algorithm)
			if err != nil {
				t.Fatalf("Failed to create %s hasher: %v", algorithm, err)
			}

			// Хэшируем первое сообщение
			hasher.Write(testData1)
			hash1 := hasher.Sum()

			// Сбрасываем хэшер
			hasher.Reset()

			// Хэшируем второе сообщение
			hasher.Write(testData2)
			hash2 := hasher.Sum()

			// Проверяем, что хэши разные
			if bytes.Equal(hash1, hash2) {
				t.Error("Hashes for different data should be different after reset")
			}

			// Снова сбрасываем и хэшируем первое сообщение
			hasher.Reset()
			hasher.Write(testData1)
			hash3 := hasher.Sum()

			// Проверяем, что хэш совпадает с первым
			if !bytes.Equal(hash1, hash3) {
				t.Error("Hash should be identical after reset and same data")
			}
		})
	}
}

// TestHashConsistency тестирует консистентность хэшей
func TestHashConsistency(t *testing.T) {
	provider := gopenssl.NewProvider()

	testData := []byte("Consistency test message")

	algorithms := []common.HashAlgorithm{
		common.SHA1,
		common.SHA256,
		common.SHA512,
		common.MD5,
		common.GOST34_11,
	}

	for _, algorithm := range algorithms {
		t.Run(string(algorithm), func(t *testing.T) {
			// Создаем несколько хэшеров и проверяем консистентность
			var hashes [][]byte

			for i := 0; i < 5; i++ {
				hasher, err := provider.NewHasher(algorithm)
				if err != nil {
					t.Fatalf("Failed to create %s hasher: %v", algorithm, err)
				}

				hasher.Write(testData)
				hash := hasher.Sum()
				hashes = append(hashes, hash)
			}

			// Проверяем, что все хэши одинаковые
			firstHash := hashes[0]
			for i := 1; i < len(hashes); i++ {
				if !bytes.Equal(firstHash, hashes[i]) {
					t.Errorf("Hash %d should be identical to first hash", i)
				}
			}
		})
	}
}

// BenchmarkHashAlgorithms измеряет производительность хэш-алгоритмов
func BenchmarkHashAlgorithms(b *testing.B) {
	provider := gopenssl.NewProvider()

	testData := make([]byte, 1024)
	rand.Read(testData)

	algorithms := []common.HashAlgorithm{
		common.SHA1,
		common.SHA256,
		common.SHA512,
		common.MD5,
		common.GOST34_11,
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

// BenchmarkHashCreationPerAlgorithm измеряет производительность создания хэшеров по алгоритмам
func BenchmarkHashCreationPerAlgorithm(b *testing.B) {
	provider := gopenssl.NewProvider()

	algorithms := []common.HashAlgorithm{
		common.SHA256,
		common.SHA512,
		common.GOST34_11,
	}

	for _, algorithm := range algorithms {
		b.Run(string(algorithm), func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				hasher, err := provider.NewHasher(algorithm)
				if err != nil {
					b.Fatalf("Failed to create %s hasher: %v", algorithm, err)
				}
				_ = hasher
			}
		})
	}
}
