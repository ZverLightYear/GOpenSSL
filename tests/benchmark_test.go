package tests

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"gopenssl/crypto"
)

// Результаты бенчмарка для создания таблицы
type BenchmarkResult struct {
	Algorithm     string
	DataSize      int
	GoTime        time.Duration
	CLITime       time.Duration
	Speedup       float64
	GoThroughput  float64 // MB/s
	CLIThroughput float64 // MB/s
}

var benchmarkResults []BenchmarkResult

// Результаты бенчмарка для хэшей
var hashBenchmarkResults []BenchmarkResult

// BenchmarkAESGoVsOpenSSLCLI сравнивает производительность AES в Go wrapper и OpenSSL CLI
func BenchmarkAESGoVsOpenSSLCLI(b *testing.B) {
	// Проверяем, что openssl CLI доступен
	opensslPath := "../submodules/build/bin/openssl"
	if _, err := os.Stat(opensslPath); os.IsNotExist(err) {
		b.Skipf("OpenSSL CLI not found at %s", opensslPath)
	}

	// Тестовые данные разных размеров
	testSizes := []int{16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576} // от 16 байт до 1MB

	// AES алгоритмы для тестирования
	algorithms := []struct {
		name    string
		mode    crypto.CipherMode
		keySize int
		ivSize  int
		cliName string
	}{
		{"AES-256-CBC", crypto.ModeCBC, 32, 16, "aes-256-cbc"},
		{"AES-256-ECB", crypto.ModeECB, 32, 0, "aes-256-ecb"},
		{"AES-256-CTR", crypto.ModeCTR, 32, 16, "aes-256-ctr"},
	}

	provider := getProvider()

	for _, alg := range algorithms {
		for _, size := range testSizes {
			b.Run(fmt.Sprintf("%s_%dbytes", alg.name, size), func(b *testing.B) {
				// Подготавливаем тестовые данные
				data := make([]byte, size)
				rand.Read(data)

				key := make([]byte, alg.keySize)
				rand.Read(key)

				var iv []byte
				if alg.ivSize > 0 {
					iv = make([]byte, alg.ivSize)
					rand.Read(iv)
				}

				// Создаем Go cipher
				cipher, err := provider.NewCipher(crypto.AES, alg.mode, key, iv)
				if err != nil {
					b.Fatalf("Failed to create Go cipher: %v", err)
				}

				var goTime, cliTime time.Duration
				var goThroughput, cliThroughput float64
				var goIterations, cliIterations int

				// Фиксированное количество итераций для стабильных результатов
				const iterations = 1000

				// Benchmark Go
				b.Run("Go", func(b *testing.B) {
					b.ResetTimer()
					start := time.Now()
					for i := 0; i < iterations; i++ {
						_, err := cipher.Encrypt(data)
						if err != nil {
							b.Fatalf("Go encrypt failed: %v", err)
						}
					}
					goTime = time.Since(start)
					goIterations = iterations
					avgTime := float64(goTime.Nanoseconds()) / float64(goIterations)
					goThroughput = float64(size) / (avgTime / 1e9) / (1024 * 1024) // MB/s
					b.ReportMetric(avgTime, "ns/op")
					b.ReportMetric(goThroughput, "MB/s")
				})

				// Benchmark OpenSSL CLI
				b.Run("OpenSSL_CLI", func(b *testing.B) {
					args := []string{"enc", "-" + alg.cliName, "-K", fmt.Sprintf("%x", key)}
					if alg.mode == crypto.ModeECB {
						args = append(args, "-nopad")
					}
					if iv != nil {
						args = append(args, "-iv", fmt.Sprintf("%x", iv))
					}
					b.ResetTimer()
					start := time.Now()
					for i := 0; i < iterations; i++ {
						cmd := exec.Command(opensslPath, args...)
						cmd.Env = append(os.Environ(),
							"OPENSSL_MODULES=../submodules/build/lib/ossl-modules",
							"OPENSSL_ENGINES=../submodules/build/lib/engines-3",
							"DYLD_LIBRARY_PATH=../submodules/build/lib",
						)
						cmd.Stdin = bytes.NewReader(data)
						var output bytes.Buffer
						cmd.Stdout = &output
						err := cmd.Run()
						if err != nil {
							b.Fatalf("OpenSSL CLI failed: %v", err)
						}
					}
					cliTime = time.Since(start)
					cliIterations = iterations
					avgTime := float64(cliTime.Nanoseconds()) / float64(cliIterations)
					cliThroughput = float64(size) / (avgTime / 1e9) / (1024 * 1024) // MB/s
					b.ReportMetric(avgTime, "ns/op")
					b.ReportMetric(cliThroughput, "MB/s")
				})

				// Сравнение и вывод результатов
				var speedup float64
				if cliThroughput > 0 {
					speedup = goThroughput / cliThroughput
				} else {
					speedup = 0
				}

				// Выводим финальные результаты с правильными средними значениями
				goAvgTime := float64(goTime.Nanoseconds()) / float64(goIterations)
				cliAvgTime := float64(cliTime.Nanoseconds()) / float64(cliIterations)
				fmt.Printf("🔵 Go %s (%d bytes): %.2f ns/op, %.2f MB/s\n", alg.name, size, goAvgTime, goThroughput)
				fmt.Printf("🔴 OpenSSL CLI %s (%d bytes): %.2f ns/op, %.2f MB/s\n", alg.name, size, cliAvgTime, cliThroughput)

				if goThroughput > 0 && cliThroughput > 0 {
					fmt.Printf("⚡ Go быстрее CLI в %.1f раз (%.2f MB/s vs %.2f MB/s)\n", speedup, goThroughput, cliThroughput)
				} else {
					fmt.Printf("⚡ Недостаточно данных для сравнения (Go: %.2f MB/s, CLI: %.2f MB/s)\n", goThroughput, cliThroughput)
				}

				benchmarkResults = append(benchmarkResults, BenchmarkResult{
					Algorithm:     alg.name,
					DataSize:      size,
					GoTime:        goTime / time.Duration(goIterations),
					CLITime:       cliTime / time.Duration(cliIterations),
					Speedup:       speedup,
					GoThroughput:  goThroughput,
					CLIThroughput: cliThroughput,
				})
			})
		}
	}
}

// BenchmarkHashGoVsOpenSSLCLI сравнивает производительность хэширования
func BenchmarkHashGoVsOpenSSLCLI(b *testing.B) {
	// Проверяем, что openssl CLI доступен
	opensslPath := "../submodules/build/bin/openssl"
	if _, err := os.Stat(opensslPath); os.IsNotExist(err) {
		b.Skipf("OpenSSL CLI not found at %s", opensslPath)
	}

	// Тестовые данные разных размеров
	testSizes := []int{16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576} // от 16 байт до 1MB

	// Хэш-алгоритмы для тестирования
	hashAlgorithms := []struct {
		name      string
		algorithm crypto.HashAlgorithm
		cliName   string
	}{
		{"SHA256", crypto.SHA256, "sha256"},
		{"SHA512", crypto.SHA512, "sha512"},
		{"MD5", crypto.MD5, "md5"},
	}

	provider := getProvider()

	for _, hash := range hashAlgorithms {
		for _, size := range testSizes {
			b.Run(fmt.Sprintf("%s_%dbytes", hash.name, size), func(b *testing.B) {
				// Подготавливаем тестовые данные
				data := make([]byte, size)
				rand.Read(data)

				var goTime, cliTime time.Duration
				var goThroughput, cliThroughput float64
				var goIterations, cliIterations int

				// Фиксированное количество итераций для стабильных результатов
				const iterations = 1000

				// Benchmark Go
				b.Run("Go", func(b *testing.B) {
					hasher, err := provider.NewHasher(hash.algorithm)
					if err != nil {
						b.Fatalf("Failed to create Go hasher: %v", err)
					}
					b.ResetTimer()
					start := time.Now()
					for i := 0; i < iterations; i++ {
						hasher.Reset()
						_, err := hasher.Write(data)
						if err != nil {
							b.Fatalf("Go hash write failed: %v", err)
						}
						_ = hasher.Sum()
					}
					goTime = time.Since(start)
					goIterations = iterations
					avgTime := float64(goTime.Nanoseconds()) / float64(goIterations)
					goThroughput = float64(size) / (avgTime / 1e9) / (1024 * 1024)
					b.ReportMetric(avgTime, "ns/op")
					b.ReportMetric(goThroughput, "MB/s")
				})

				// Benchmark OpenSSL CLI
				b.Run("OpenSSL_CLI", func(b *testing.B) {
					args := []string{"dgst", "-" + hash.cliName}
					b.ResetTimer()
					start := time.Now()
					for i := 0; i < iterations; i++ {
						cmd := exec.Command(opensslPath, args...)
						cmd.Env = append(os.Environ(),
							"OPENSSL_MODULES=../submodules/build/lib/ossl-modules",
							"OPENSSL_ENGINES=../submodules/build/lib/engines-3",
							"DYLD_LIBRARY_PATH=../submodules/build/lib",
						)
						cmd.Stdin = bytes.NewReader(data)
						var output bytes.Buffer
						cmd.Stdout = &output
						err := cmd.Run()
						if err != nil {
							b.Fatalf("OpenSSL CLI hash failed: %v", err)
						}
					}
					cliTime = time.Since(start)
					cliIterations = iterations
					avgTime := float64(cliTime.Nanoseconds()) / float64(cliIterations)
					cliThroughput = float64(size) / (avgTime / 1e9) / (1024 * 1024)
					b.ReportMetric(avgTime, "ns/op")
					b.ReportMetric(cliThroughput, "MB/s")
				})

				var speedup float64
				if cliThroughput > 0 {
					speedup = goThroughput / cliThroughput
				} else {
					speedup = 0
				}

				// Выводим финальные результаты с правильными средними значениями
				goAvgTime := float64(goTime.Nanoseconds()) / float64(goIterations)
				cliAvgTime := float64(cliTime.Nanoseconds()) / float64(cliIterations)
				fmt.Printf("🔵 Go %s (%d bytes): %.2f ns/op, %.2f MB/s\n", hash.name, size, goAvgTime, goThroughput)
				fmt.Printf("🔴 OpenSSL CLI %s (%d bytes): %.2f ns/op, %.2f MB/s\n", hash.name, size, cliAvgTime, cliThroughput)

				if goThroughput > 0 && cliThroughput > 0 {
					fmt.Printf("⚡ Go быстрее CLI в %.1f раз (%.2f MB/s vs %.2f MB/s)\n", speedup, goThroughput, cliThroughput)
				} else {
					fmt.Printf("⚡ Недостаточно данных для сравнения (Go: %.2f MB/s, CLI: %.2f MB/s)\n", goThroughput, cliThroughput)
				}

				hashBenchmarkResults = append(hashBenchmarkResults, BenchmarkResult{
					Algorithm:     hash.name,
					DataSize:      size,
					GoTime:        goTime / time.Duration(goIterations),
					CLITime:       cliTime / time.Duration(cliIterations),
					Speedup:       speedup,
					GoThroughput:  goThroughput,
					CLIThroughput: cliThroughput,
				})
			})
		}
	}
}

// BenchmarkThroughput тестирует пропускную способность для больших данных
func BenchmarkThroughput(b *testing.B) {
	provider := getProvider()

	// Большие размеры данных для тестирования пропускной способности
	sizes := []int{1024 * 1024, 10 * 1024 * 1024} // 1MB, 10MB

	algorithms := []struct {
		name      string
		algorithm crypto.CipherAlgorithm
		mode      crypto.CipherMode
		keySize   int
		ivSize    int
	}{
		{"AES-256-CBC", crypto.AES, crypto.ModeCBC, 32, 16},
		{"AES-256-CTR", crypto.AES, crypto.ModeCTR, 32, 16},
	}

	for _, alg := range algorithms {
		for _, size := range sizes {
			b.Run(fmt.Sprintf("%s_%dMB", alg.name, size/(1024*1024)), func(b *testing.B) {
				// Подготавливаем тестовые данные
				data := make([]byte, size)
				rand.Read(data)

				key := make([]byte, alg.keySize)
				rand.Read(key)

				iv := make([]byte, alg.ivSize)
				rand.Read(iv)

				// Создаем Go cipher
				cipher, err := provider.NewCipher(alg.algorithm, alg.mode, key, iv)
				if err != nil {
					b.Fatalf("Failed to create Go cipher: %v", err)
				}

				b.ResetTimer()
				b.SetBytes(int64(size))

				for i := 0; i < b.N; i++ {
					_, err := cipher.Encrypt(data)
					if err != nil {
						b.Fatalf("Go encrypt failed: %v", err)
					}
				}
			})
		}
	}
}

// BenchmarkConcurrent тестирует производительность при параллельном использовании
func BenchmarkConcurrent(b *testing.B) {
	provider := getProvider()

	// Тестовые данные
	data := make([]byte, 1024)
	rand.Read(data)

	key := make([]byte, 32)
	rand.Read(key)

	iv := make([]byte, 16)
	rand.Read(iv)

	algorithms := []struct {
		name      string
		algorithm crypto.CipherAlgorithm
		mode      crypto.CipherMode
	}{
		{"AES-256-CBC", crypto.AES, crypto.ModeCBC},
		{"AES-256-CTR", crypto.AES, crypto.ModeCTR},
	}

	for _, alg := range algorithms {
		b.Run(alg.name, func(b *testing.B) {
			b.RunParallel(func(pb *testing.PB) {
				// Создаем cipher для каждой горутины
				cipher, err := provider.NewCipher(alg.algorithm, alg.mode, key, iv)
				if err != nil {
					b.Fatalf("Failed to create Go cipher: %v", err)
				}

				for pb.Next() {
					_, err := cipher.Encrypt(data)
					if err != nil {
						b.Fatalf("Go encrypt failed: %v", err)
					}
				}
			})
		})
	}
}

// BenchmarkMemoryUsage тестирует использование памяти
func BenchmarkMemoryUsage(b *testing.B) {
	provider := getProvider()

	// Тестовые данные
	data := make([]byte, 1024*1024) // 1MB
	rand.Read(data)

	key := make([]byte, 32)
	rand.Read(key)

	iv := make([]byte, 16)
	rand.Read(iv)

	algorithms := []struct {
		name      string
		algorithm crypto.CipherAlgorithm
		mode      crypto.CipherMode
	}{
		{"AES-256-CBC", crypto.AES, crypto.ModeCBC},
		{"AES-256-CTR", crypto.AES, crypto.ModeCTR},
	}

	for _, alg := range algorithms {
		b.Run(alg.name, func(b *testing.B) {
			b.ReportAllocs()

			for i := 0; i < b.N; i++ {
				// Создаем новый cipher для каждого итерации
				cipher, err := provider.NewCipher(alg.algorithm, alg.mode, key, iv)
				if err != nil {
					b.Fatalf("Failed to create Go cipher: %v", err)
				}

				_, err = cipher.Encrypt(data)
				if err != nil {
					b.Fatalf("Go encrypt failed: %v", err)
				}
			}
		})
	}
}

// После всех бенчмарков выводим итоговую таблицу
func printBenchmarkSummary() {
	if len(benchmarkResults) == 0 {
		return
	}
	fmt.Println("\n================= Сравнительная таблица Go vs OpenSSL CLI =================")
	fmt.Printf("%-18s | %-10s | %-15s | %-15s | %-10s | %-12s | %-12s\n", "Algorithm", "DataSize", "Go ns/op", "CLI ns/op", "Speedup", "Go MB/s", "CLI MB/s")
	fmt.Println(strings.Repeat("-", 90))
	for _, r := range benchmarkResults {
		fmt.Printf("%-18s | %-10d | %-15.2f | %-15.2f | %-10.1f | %-12.2f | %-12.2f\n",
			r.Algorithm, r.DataSize, float64(r.GoTime.Nanoseconds()), float64(r.CLITime.Nanoseconds()), r.Speedup, r.GoThroughput, r.CLIThroughput)
	}
	fmt.Println(strings.Repeat("=", 90))
}

// После всех бенчмарков выводим итоговую таблицу для хэшей
func printHashBenchmarkSummary() {
	if len(hashBenchmarkResults) == 0 {
		return
	}
	fmt.Println("\n================= Сравнительная таблица Go vs OpenSSL CLI (Hash) =================")
	fmt.Printf("%-12s | %-10s | %-15s | %-15s | %-10s | %-12s | %-12s\n", "Algorithm", "DataSize", "Go ns/op", "CLI ns/op", "Speedup", "Go MB/s", "CLI MB/s")
	fmt.Println(strings.Repeat("-", 85))
	for _, r := range hashBenchmarkResults {
		fmt.Printf("%-12s | %-10d | %-15.2f | %-15.2f | %-10.1f | %-12.2f | %-12.2f\n",
			r.Algorithm, r.DataSize, float64(r.GoTime.Nanoseconds()), float64(r.CLITime.Nanoseconds()), r.Speedup, r.GoThroughput, r.CLIThroughput)
	}
	fmt.Println(strings.Repeat("=", 85))
}

// В конце файла:
func TestPrintBenchmarkSummary(t *testing.T) {
	printBenchmarkSummary()
}

func TestPrintHashBenchmarkSummary(t *testing.T) {
	printHashBenchmarkSummary()
}

// TestMain вызывается один раз перед всеми тестами
func TestMain(m *testing.M) {
	// Запускаем тесты
	code := m.Run()

	// После всех тестов выводим таблицы, если есть результаты
	if len(benchmarkResults) > 0 {
		printBenchmarkSummary()
	}
	if len(hashBenchmarkResults) > 0 {
		printHashBenchmarkSummary()
	}

	os.Exit(code)
}
