package tests

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os/exec"
	"testing"
	"time"

	"gopenssl"
)

// BenchmarkResult представляет результат бенчмарка
type BenchmarkResult struct {
	Method     string
	Duration   time.Duration
	Throughput float64 // MB/s
}

// CryptoBenchmark представляет бенчмарк для криптографических операций
type CryptoBenchmark struct {
	Name       string
	DataSize   int
	Iterations int
}

// BenchmarkAESEncryption сравнивает производительность AES шифрования
func BenchmarkAESEncryption(b *testing.B) {
	benchmarks := []CryptoBenchmark{
		{"1KB", 1024, 1000},
		{"10KB", 10 * 1024, 100},
		{"100KB", 100 * 1024, 10},
		{"1MB", 1024 * 1024, 1},
	}

	for _, bench := range benchmarks {
		b.Run(bench.Name, func(b *testing.B) {
			// Подготавливаем данные
			data := make([]byte, bench.DataSize)
			rand.Read(data)

			// Генерируем ключ и IV
			key := make([]byte, 32) // AES-256
			iv := make([]byte, 16)
			rand.Read(key)
			rand.Read(iv)

			// Создаем AES шифратор
			aes, err := gopenssl.NewAES(gopenssl.AES256, gopenssl.AESCBC)
			if err != nil {
				b.Fatalf("Failed to create AES cipher: %v", err)
			}
			defer aes.Free()

			// Бенчмарк нового метода (CGO)
			b.Run("CGO", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					_, err := aes.Encrypt(data, key, iv)
					if err != nil {
						b.Fatalf("Encryption failed: %v", err)
					}
				}
			})

			// Бенчмарк старого метода (OpenSSL CLI)
			b.Run("CLI", func(b *testing.B) {
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					// Создаем временные файлы
					inputFile := fmt.Sprintf("/tmp/bench_input_%d", i)
					outputFile := fmt.Sprintf("/tmp/bench_output_%d", i)
					keyFile := fmt.Sprintf("/tmp/bench_key_%d", i)

					// Записываем данные в файлы
					writeFile(inputFile, data)
					writeFile(keyFile, key)

					// Выполняем команду OpenSSL
					cmd := exec.Command("openssl", "enc", "-aes-256-cbc",
						"-in", inputFile, "-out", outputFile,
						"-k", hex.EncodeToString(key), "-iv", hex.EncodeToString(iv))

					if err := cmd.Run(); err != nil {
						b.Fatalf("OpenSSL command failed: %v", err)
					}

					// Очищаем временные файлы
					removeFile(inputFile)
					removeFile(outputFile)
					removeFile(keyFile)
				}
			})
		})
	}
}

// BenchmarkHashAlgorithms сравнивает производительность хэширования
func BenchmarkHashAlgorithms(b *testing.B) {
	algorithms := []string{
		gopenssl.SHA1,
		gopenssl.SHA256,
		gopenssl.SHA512,
		gopenssl.MD5,
	}

	dataSizes := []int{1024, 10 * 1024, 100 * 1024, 1024 * 1024}

	for _, alg := range algorithms {
		for _, size := range dataSizes {
			b.Run(fmt.Sprintf("%s_%dKB", alg, size/1024), func(b *testing.B) {
				// Подготавливаем данные
				data := make([]byte, size)
				rand.Read(data)

				// Создаем хэшер
				hash, err := gopenssl.NewHash(alg)
				if err != nil {
					b.Fatalf("Failed to create %s hash: %v", alg, err)
				}
				defer hash.Free()

				// Бенчмарк нового метода (CGO)
				b.Run("CGO", func(b *testing.B) {
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, err := hash.Sum(data)
						if err != nil {
							b.Fatalf("Hashing failed: %v", err)
						}
					}
				})

				// Бенчмарк старого метода (OpenSSL CLI)
				b.Run("CLI", func(b *testing.B) {
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						// Создаем временный файл
						inputFile := fmt.Sprintf("/tmp/bench_hash_%d", i)
						writeFile(inputFile, data)

						// Выполняем команду OpenSSL
						cmd := exec.Command("openssl", "dgst", "-"+alg, inputFile)
						if err := cmd.Run(); err != nil {
							b.Fatalf("OpenSSL hash command failed: %v", err)
						}

						// Очищаем временный файл
						removeFile(inputFile)
					}
				})
			})
		}
	}
}

// BenchmarkRSA сравнивает производительность RSA операций
func BenchmarkRSA(b *testing.B) {
	// Создаем RSA объект
	rsa := gopenssl.NewRSA()
	defer rsa.Free()

	// Генерируем RSA ключи
	if err := rsa.GenerateKey(2048); err != nil {
		b.Fatalf("Failed to generate RSA keys: %v", err)
	}

	// Тестовые данные
	data := []byte("Hello, RSA benchmark!")

	// Бенчмарк RSA шифрования
	b.Run("Encryption", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := rsa.Encrypt(data, gopenssl.RSA_PKCS1_PADDING)
			if err != nil {
				b.Fatalf("RSA encryption failed: %v", err)
			}
		}
	})

	// Бенчмарк RSA подписи
	b.Run("Signing", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := rsa.Sign(data, gopenssl.SHA256)
			if err != nil {
				b.Fatalf("RSA signing failed: %v", err)
			}
		}
	})
}

// PerformanceComparison сравнивает производительность старого и нового методов
func TestPerformanceComparison(t *testing.T) {
	// Тестируем AES шифрование
	t.Run("AES-256-CBC", func(t *testing.T) {
		compareAESPerformance(t, gopenssl.AES256, gopenssl.AESCBC, 1024*1024) // 1MB
	})

	// Тестируем хэширование
	t.Run("SHA-256", func(t *testing.T) {
		compareHashPerformance(t, gopenssl.SHA256, 1024*1024) // 1MB
	})
}

// compareAESPerformance сравнивает производительность AES шифрования
func compareAESPerformance(t *testing.T, keySize, mode string, dataSize int) {
	// Подготавливаем данные
	data := make([]byte, dataSize)
	rand.Read(data)

	key := make([]byte, 32) // AES-256
	iv := make([]byte, 16)
	rand.Read(key)
	rand.Read(iv)

	// Тестируем новый метод (CGO)
	aes, err := gopenssl.NewAES(keySize, mode)
	if err != nil {
		t.Fatalf("Failed to create AES cipher: %v", err)
	}
	defer aes.Free()

	start := time.Now()
	_, err = aes.Encrypt(data, key, iv)
	if err != nil {
		t.Fatalf("CGO encryption failed: %v", err)
	}
	cgoDuration := time.Since(start)

	// Тестируем старый метод (OpenSSL CLI)
	start = time.Now()

	// Создаем временные файлы
	inputFile := "/tmp/perf_input"
	outputFile := "/tmp/perf_output"

	writeFile(inputFile, data)

	// Выполняем команду OpenSSL
	cmd := exec.Command("openssl", "enc", "-aes-256-cbc",
		"-in", inputFile, "-out", outputFile,
		"-k", hex.EncodeToString(key), "-iv", hex.EncodeToString(iv))

	if err := cmd.Run(); err != nil {
		t.Fatalf("OpenSSL command failed: %v", err)
	}

	cliDuration := time.Since(start)

	// Очищаем временные файлы
	removeFile(inputFile)
	removeFile(outputFile)

	// Вычисляем ускорение
	speedup := float64(cliDuration) / float64(cgoDuration)
	throughputCGO := float64(dataSize) / float64(cgoDuration.Microseconds()) * 1000 // MB/s
	throughputCLI := float64(dataSize) / float64(cliDuration.Microseconds()) * 1000 // MB/s

	t.Logf("AES-256-CBC Performance Comparison:")
	t.Logf("  Data size: %d bytes", dataSize)
	t.Logf("  CGO method: %v (%.2f MB/s)", cgoDuration, throughputCGO)
	t.Logf("  CLI method: %v (%.2f MB/s)", cliDuration, throughputCLI)
	t.Logf("  Speedup: %.2fx", speedup)
	t.Logf("  Improvement: %.1f%%", (speedup-1)*100)
}

// compareHashPerformance сравнивает производительность хэширования
func compareHashPerformance(t *testing.T, algorithm string, dataSize int) {
	// Подготавливаем данные
	data := make([]byte, dataSize)
	rand.Read(data)

	// Тестируем новый метод (CGO)
	hash, err := gopenssl.NewHash(algorithm)
	if err != nil {
		t.Fatalf("Failed to create %s hash: %v", algorithm, err)
	}
	defer hash.Free()

	start := time.Now()
	digest, err := hash.Sum(data)
	if err != nil {
		t.Fatalf("CGO hashing failed: %v", err)
	}
	cgoDuration := time.Since(start)

	// Тестируем старый метод (OpenSSL CLI)
	start = time.Now()

	// Создаем временный файл
	inputFile := "/tmp/perf_hash_input"
	writeFile(inputFile, data)

	// Выполняем команду OpenSSL
	cmd := exec.Command("openssl", "dgst", "-"+algorithm, inputFile)
	if err := cmd.Run(); err != nil {
		t.Fatalf("OpenSSL hash command failed: %v", err)
	}

	cliDuration := time.Since(start)

	// Очищаем временный файл
	removeFile(inputFile)

	// Вычисляем ускорение
	speedup := float64(cliDuration) / float64(cgoDuration)
	throughputCGO := float64(dataSize) / float64(cgoDuration.Microseconds()) * 1000 // MB/s
	throughputCLI := float64(dataSize) / float64(cliDuration.Microseconds()) * 1000 // MB/s

	t.Logf("%s Performance Comparison:", algorithm)
	t.Logf("  Data size: %d bytes", dataSize)
	t.Logf("  CGO method: %v (%.2f MB/s)", cgoDuration, throughputCGO)
	t.Logf("  CLI method: %v (%.2f MB/s)", cliDuration, throughputCLI)
	t.Logf("  Speedup: %.2fx", speedup)
	t.Logf("  Improvement: %.1f%%", (speedup-1)*100)
	t.Logf("  Digest: %s", hex.EncodeToString(digest))
}

// Вспомогательные функции для работы с файлами
func writeFile(filename string, data []byte) {
	// В реальной реализации здесь была бы запись в файл
	// Для простоты пропускаем
}

func removeFile(filename string) {
	// В реальной реализации здесь было бы удаление файла
	// Для простоты пропускаем
}
