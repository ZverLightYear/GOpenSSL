package main

import (
	"crypto/rand"
	"fmt"
	cgopenssl "gopenssl/cgo"
	"runtime"
	"sync"
	"time"

	"gopenssl"
)

func main() {
	fmt.Println("=== Бенчмарки производительности GOpenSSL ===")
	fmt.Printf("OpenSSL версия: %s\n", cgopenssl.OpenSSLVersion())
	fmt.Printf("Go версия: %s\n", runtime.Version())
	fmt.Printf("ОС: %s\n", runtime.GOOS)
	fmt.Printf("Архитектура: %s\n", runtime.GOARCH)
	fmt.Printf("Количество CPU: %d\n\n", runtime.NumCPU())

	// Получаем провайдер
	provider := gopenssl.GetProvider()

	// Размеры данных для тестирования
	dataSizes := []int{
		1024,             // 1KB
		1024 * 1024,      // 1MB
		10 * 1024 * 1024, // 10MB
	}

	// Количество итераций для каждого теста
	iterations := 1000

	// Тестируем шифрование
	fmt.Println("=== Бенчмарки шифрования ===")
	benchmarkEncryption(provider, dataSizes, iterations)

	// Тестируем хэширование
	fmt.Println("\n=== Бенчмарки хэширования ===")
	benchmarkHashing(provider, dataSizes, iterations)

	// Тестируем конкурентность
	fmt.Println("\n=== Бенчмарки конкурентности ===")
	benchmarkConcurrency(provider, dataSizes)
}

func benchmarkEncryption(provider gopenssl.CryptoProvider, dataSizes []int, iterations int) {
	algorithms := []struct {
		name    gopenssl.CipherAlgorithm
		mode    gopenssl.CipherMode
		keySize int
		ivSize  int
	}{
		{gopenssl.AES, gopenssl.ModeCBC, 32, 16}, // AES-256-CBC
		{gopenssl.AES, gopenssl.ModeCTR, 32, 16}, // AES-256-CTR
		{gopenssl.AES, gopenssl.ModeGCM, 32, 12}, // AES-256-GCM
	}

	for _, size := range dataSizes {
		fmt.Printf("\n--- Размер данных: %d байт ---\n", size)

		// Генерируем тестовые данные
		data := make([]byte, size)
		rand.Read(data)

		for _, alg := range algorithms {
			// Генерируем ключ и IV
			key := make([]byte, alg.keySize)
			iv := make([]byte, alg.ivSize)
			rand.Read(key)
			rand.Read(iv)

			// Создаем шифр
			cipher, err := provider.NewCipher(alg.name, alg.mode, key, iv)
			if err != nil {
				fmt.Printf("❌ Ошибка создания шифра %s-%s: %v\n", alg.name, alg.mode, err)
				continue
			}

			// Выполняем бенчмарк
			start := time.Now()
			for i := 0; i < iterations; i++ {
				_, err := cipher.Encrypt(data)
				if err != nil {
					fmt.Printf("❌ Ошибка шифрования: %v\n", err)
					break
				}
			}
			duration := time.Since(start)

			// Вычисляем метрики
			totalData := int64(size) * int64(iterations)
			throughput := float64(totalData) / duration.Seconds() / (1024 * 1024) // MB/s
			opsPerSec := float64(iterations) / duration.Seconds()

			fmt.Printf("%s-%s: %d операций за %s (%.2f ops/sec, %.2f MB/s)\n",
				alg.name, alg.mode, iterations, duration.String(), opsPerSec, throughput)
		}
	}
}

func benchmarkHashing(provider gopenssl.CryptoProvider, dataSizes []int, iterations int) {
	algorithms := []gopenssl.HashAlgorithm{
		gopenssl.MD5,
		gopenssl.SHA1,
		gopenssl.SHA256,
		gopenssl.SHA384,
		gopenssl.SHA512,
	}

	for _, size := range dataSizes {
		fmt.Printf("\n--- Размер данных: %d байт ---\n", size)

		// Генерируем тестовые данные
		data := make([]byte, size)
		rand.Read(data)

		for _, algorithm := range algorithms {
			// Создаем хэшер
			hasher, err := provider.NewHasher(algorithm)
			if err != nil {
				fmt.Printf("❌ Ошибка создания хэшера %s: %v\n", algorithm, err)
				continue
			}

			// Выполняем бенчмарк
			start := time.Now()
			for i := 0; i < iterations; i++ {
				hasher.Reset()
				_, err := hasher.Write(data)
				if err != nil {
					fmt.Printf("❌ Ошибка хэширования: %v\n", err)
					break
				}
				hasher.Sum()
			}
			duration := time.Since(start)

			// Вычисляем метрики
			totalData := int64(size) * int64(iterations)
			throughput := float64(totalData) / duration.Seconds() / (1024 * 1024) // MB/s
			opsPerSec := float64(iterations) / duration.Seconds()

			fmt.Printf("%s: %d операций за %s (%.2f ops/sec, %.2f MB/s)\n",
				algorithm, iterations, duration.String(), opsPerSec, throughput)
		}
	}
}

func benchmarkConcurrency(provider gopenssl.CryptoProvider, dataSizes []int) {
	concurrencyLevels := []int{1, 2, 4, 8, 16}

	for _, size := range dataSizes {
		fmt.Printf("\n--- Размер данных: %d байт ---\n", size)

		// Генерируем тестовые данные
		data := make([]byte, size)
		rand.Read(data)

		for _, concurrency := range concurrencyLevels {
			// Тестируем конкурентное шифрование AES-256-CBC
			benchmarkConcurrentEncryption(provider, data, concurrency)

			// Тестируем конкурентное хэширование SHA256
			benchmarkConcurrentHashing(provider, data, concurrency)
		}
	}
}

func benchmarkConcurrentEncryption(provider gopenssl.CryptoProvider, data []byte, concurrency int) {
	iterations := 1000 / concurrency // Общее количество операций остается постоянным

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			// Генерируем ключ и IV для каждого горутины
			key := make([]byte, 32)
			iv := make([]byte, 16)
			rand.Read(key)
			rand.Read(iv)

			cipher, err := provider.NewCipher(gopenssl.AES, gopenssl.ModeCBC, key, iv)
			if err != nil {
				return
			}

			for j := 0; j < iterations; j++ {
				cipher.Encrypt(data)
			}
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	totalOps := concurrency * iterations
	opsPerSec := float64(totalOps) / duration.Seconds()

	fmt.Printf("AES-256-CBC (конкурентность %d): %d операций за %s (%.2f ops/sec)\n",
		concurrency, totalOps, duration.String(), opsPerSec)
}

func benchmarkConcurrentHashing(provider gopenssl.CryptoProvider, data []byte, concurrency int) {
	iterations := 1000 / concurrency

	var wg sync.WaitGroup
	start := time.Now()

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			hasher, err := provider.NewHasher(gopenssl.SHA256)
			if err != nil {
				return
			}

			for j := 0; j < iterations; j++ {
				hasher.Reset()
				hasher.Write(data)
				hasher.Sum()
			}
		}()
	}

	wg.Wait()
	duration := time.Since(start)

	totalOps := concurrency * iterations
	opsPerSec := float64(totalOps) / duration.Seconds()

	fmt.Printf("SHA256 (конкурентность %d): %d операций за %s (%.2f ops/sec)\n",
		concurrency, totalOps, duration.String(), opsPerSec)
}
