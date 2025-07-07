package tests

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"gopenssl/crypto"
)

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

				// Benchmark Go
				b.Run("Go", func(b *testing.B) {
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						_, err := cipher.Encrypt(data)
						if err != nil {
							b.Fatalf("Go encrypt failed: %v", err)
						}
					}
				})

				// Benchmark OpenSSL CLI
				b.Run("OpenSSL_CLI", func(b *testing.B) {
					// Подготавливаем аргументы CLI
					args := []string{"enc", "-" + alg.cliName, "-K", fmt.Sprintf("%x", key)}

					// Для ECB добавляем -nopad
					if alg.mode == crypto.ModeECB {
						args = append(args, "-nopad")
					}

					if iv != nil {
						args = append(args, "-iv", fmt.Sprintf("%x", iv))
					}

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						// Создаем новую команду для каждой итерации
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

				// Benchmark Go
				b.Run("Go", func(b *testing.B) {
					hasher, err := provider.NewHasher(hash.algorithm)
					if err != nil {
						b.Fatalf("Failed to create Go hasher: %v", err)
					}

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						hasher.Reset()
						_, err := hasher.Write(data)
						if err != nil {
							b.Fatalf("Go hash write failed: %v", err)
						}
						_ = hasher.Sum()
					}
				})

				// Benchmark OpenSSL CLI
				b.Run("OpenSSL_CLI", func(b *testing.B) {
					args := []string{"dgst", "-" + hash.cliName}

					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						// Создаем новую команду для каждой итерации
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
