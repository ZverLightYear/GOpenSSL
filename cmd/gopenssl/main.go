package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"

	"gopenssl/crypto"
	"gopenssl/hash"
	"gopenssl/internal/openssl"
)

func main() {
	// Инициализируем OpenSSL
	openssl.InitOpenSSL()
	defer openssl.CleanupOpenSSL()

	// Парсим аргументы командной строки
	var (
		operation = flag.String("op", "", "Operation: encrypt, decrypt, hash")
		algorithm = flag.String("alg", "", "Algorithm: aes-256-cbc, gost89, sha256, etc.")
		input     = flag.String("in", "", "Input file (default: stdin)")
		output    = flag.String("out", "", "Output file (default: stdout)")
		key       = flag.String("key", "", "Encryption key (hex)")
		iv        = flag.String("iv", "", "Initialization vector (hex)")
		help      = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	if *help {
		showHelp()
		return
	}

	if *operation == "" {
		log.Fatal("Operation is required. Use -op encrypt, decrypt, or hash")
	}

	switch *operation {
	case "encrypt":
		if err := encryptOperation(*algorithm, *input, *output, *key, *iv); err != nil {
			log.Fatalf("Encryption failed: %v", err)
		}
	case "decrypt":
		if err := decryptOperation(*algorithm, *input, *output, *key, *iv); err != nil {
			log.Fatalf("Decryption failed: %v", err)
		}
	case "hash":
		if err := hashOperation(*algorithm, *input, *output); err != nil {
			log.Fatalf("Hashing failed: %v", err)
		}
	default:
		log.Fatalf("Unknown operation: %s", *operation)
	}
}

func encryptOperation(algorithm, inputFile, outputFile, keyHex, ivHex string) error {
	// Читаем входные данные
	data, err := readInput(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	// Парсим ключ и IV
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("invalid key format: %w", err)
	}

	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return fmt.Errorf("invalid IV format: %w", err)
	}

	// Создаем шифратор
	var cipher crypto.Cipher
	var err2 error

	if isAES(algorithm) {
		keySize, mode := parseAESAlgorithm(algorithm)
		cipher, err2 = crypto.NewAES(crypto.KeySize(keySize), crypto.Mode(mode))
	} else if isGOST(algorithm) {
		cipher, err2 = crypto.NewGOST(crypto.Mode(algorithm))
	} else {
		return fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if err2 != nil {
		return fmt.Errorf("failed to create cipher: %w", err2)
	}
	defer cipher.Free()

	// Шифруем
	encrypted, err := cipher.Encrypt(data, key, iv)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Записываем результат
	return writeOutput(outputFile, encrypted)
}

func decryptOperation(algorithm, inputFile, outputFile, keyHex, ivHex string) error {
	// Читаем входные данные
	data, err := readInput(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	// Парсим ключ и IV
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return fmt.Errorf("invalid key format: %w", err)
	}

	iv, err := hex.DecodeString(ivHex)
	if err != nil {
		return fmt.Errorf("invalid IV format: %w", err)
	}

	// Создаем шифратор
	var cipher crypto.Cipher
	var err2 error

	if isAES(algorithm) {
		keySize, mode := parseAESAlgorithm(algorithm)
		cipher, err2 = crypto.NewAES(crypto.KeySize(keySize), crypto.Mode(mode))
	} else if isGOST(algorithm) {
		cipher, err2 = crypto.NewGOST(crypto.Mode(algorithm))
	} else {
		return fmt.Errorf("unsupported algorithm: %s", algorithm)
	}

	if err2 != nil {
		return fmt.Errorf("failed to create cipher: %w", err2)
	}
	defer cipher.Free()

	// Расшифровываем
	decrypted, err := cipher.Decrypt(data, key, iv)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Записываем результат
	return writeOutput(outputFile, decrypted)
}

func hashOperation(algorithm, inputFile, outputFile string) error {
	// Читаем входные данные
	data, err := readInput(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	// Создаем хэшер
	hasher, err := hash.NewHash(hash.Algorithm(algorithm))
	if err != nil {
		return fmt.Errorf("failed to create hasher: %w", err)
	}
	defer hasher.Free()

	// Вычисляем хэш
	digest, err := hasher.Sum(data)
	if err != nil {
		return fmt.Errorf("hashing failed: %w", err)
	}

	// Записываем результат
	return writeOutput(outputFile, digest)
}

func readInput(filename string) ([]byte, error) {
	if filename == "" {
		// Читаем из stdin
		return os.ReadAll(os.Stdin)
	}
	return os.ReadFile(filename)
}

func writeOutput(filename string, data []byte) error {
	if filename == "" {
		// Записываем в stdout
		_, err := os.Stdout.Write(data)
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func isAES(algorithm string) bool {
	return len(algorithm) >= 3 && algorithm[:3] == "aes"
}

func isGOST(algorithm string) bool {
	return len(algorithm) >= 4 && algorithm[:4] == "gost"
}

func parseAESAlgorithm(algorithm string) (string, string) {
	// Пример: aes-256-cbc -> aes-256, cbc
	// Упрощенная логика, в реальном коде нужно более тщательно парсить
	if len(algorithm) < 8 {
		return "aes-256", "cbc"
	}

	// Ищем последний дефис
	lastDash := -1
	for i := len(algorithm) - 1; i >= 0; i-- {
		if algorithm[i] == '-' {
			lastDash = i
			break
		}
	}

	if lastDash == -1 {
		return "aes-256", "cbc"
	}

	keySize := algorithm[:lastDash]
	mode := algorithm[lastDash+1:]

	return keySize, mode
}

func showHelp() {
	fmt.Println("GOpenSSL - Go OpenSSL wrapper")
	fmt.Println()
	fmt.Println("Usage: gopenssl -op <operation> -alg <algorithm> [options]")
	fmt.Println()
	fmt.Println("Operations:")
	fmt.Println("  encrypt  - Encrypt data")
	fmt.Println("  decrypt  - Decrypt data")
	fmt.Println("  hash     - Calculate hash")
	fmt.Println()
	fmt.Println("Algorithms:")
	fmt.Println("  AES:     aes-128-cbc, aes-192-cbc, aes-256-cbc, aes-128-gcm, etc.")
	fmt.Println("  GOST:    gost89, gost89-cbc, gost89-cnt, gost89-cnt-12")
	fmt.Println("  Hash:    sha256, sha512, md5, gostr34112012256, etc.")
	fmt.Println()
	fmt.Println("Options:")
	fmt.Println("  -in <file>   Input file (default: stdin)")
	fmt.Println("  -out <file>  Output file (default: stdout)")
	fmt.Println("  -key <hex>   Encryption key (hex format)")
	fmt.Println("  -iv <hex>    Initialization vector (hex format)")
	fmt.Println("  -help        Show this help")
	fmt.Println()
	fmt.Println("Examples:")
	fmt.Println("  # Encrypt file with AES-256-CBC")
	fmt.Println("  gopenssl -op encrypt -alg aes-256-cbc -in data.txt -out encrypted.bin -key 0123456789abcdef0123456789abcdef -iv 0123456789abcdef")
	fmt.Println()
	fmt.Println("  # Decrypt file")
	fmt.Println("  gopenssl -op decrypt -alg aes-256-cbc -in encrypted.bin -out decrypted.txt -key 0123456789abcdef0123456789abcdef -iv 0123456789abcdef")
	fmt.Println()
	fmt.Println("  # Calculate SHA-256 hash")
	fmt.Println("  gopenssl -op hash -alg sha256 -in data.txt -out hash.txt")
}
