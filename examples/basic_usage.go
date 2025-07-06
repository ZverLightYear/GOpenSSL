package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	"gopenssl"
)

func main() {
	// Инициализация OpenSSL происходит автоматически при импорте пакета
	defer gopenssl.Cleanup()

	fmt.Println("=== GOpenSSL Basic Usage Example ===")

	// Пример AES шифрования
	fmt.Println("\n--- AES Encryption ---")
	if err := aesExample(); err != nil {
		log.Printf("AES example error: %v", err)
	}

	// Пример GOST шифрования
	fmt.Println("\n--- GOST Encryption ---")
	if err := gostExample(); err != nil {
		log.Printf("GOST example error: %v", err)
	}

	// Пример хэширования
	fmt.Println("\n--- Hashing ---")
	if err := hashExample(); err != nil {
		log.Printf("Hash example error: %v", err)
	}

	// Пример RSA
	fmt.Println("\n--- RSA ---")
	if err := rsaExample(); err != nil {
		log.Printf("RSA example error: %v", err)
	}
}

func aesExample() error {
	// Создаем AES-256-CBC шифратор
	aes, err := gopenssl.NewAES(gopenssl.AES256, gopenssl.AESCBC)
	if err != nil {
		return fmt.Errorf("failed to create AES cipher: %w", err)
	}
	defer aes.Free()

	// Генерируем ключ и IV
	key := make([]byte, aes.KeySize())
	iv := make([]byte, aes.IVSize())

	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	// Данные для шифрования
	plaintext := []byte("Hello, GOpenSSL! This is a test message for AES encryption.")

	fmt.Printf("Plaintext: %s\n", string(plaintext))
	fmt.Printf("Key (hex): %s\n", hex.EncodeToString(key))
	fmt.Printf("IV (hex): %s\n", hex.EncodeToString(iv))

	// Шифруем
	ciphertext, err := aes.Encrypt(plaintext, key, iv)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	fmt.Printf("Ciphertext (hex): %s\n", hex.EncodeToString(ciphertext))

	// Расшифровываем
	decrypted, err := aes.Decrypt(ciphertext, key, iv)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	fmt.Printf("Decrypted: %s\n", string(decrypted))

	if string(plaintext) == string(decrypted) {
		fmt.Println("✓ AES encryption/decryption successful!")
	} else {
		fmt.Println("✗ AES encryption/decryption failed!")
	}

	return nil
}

func gostExample() error {
	// Создаем GOST шифратор
	gost, err := gopenssl.NewGOST(gopenssl.GOSTCFB)
	if err != nil {
		return fmt.Errorf("failed to create GOST cipher: %w", err)
	}
	defer gost.Free()

	// Генерируем ключ и IV
	key := make([]byte, gost.KeySize())
	iv := make([]byte, gost.IVSize())

	if _, err := rand.Read(key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}
	if _, err := rand.Read(iv); err != nil {
		return fmt.Errorf("failed to generate IV: %w", err)
	}

	// Данные для шифрования
	plaintext := []byte("Hello, GOST! This is a test message for GOST encryption.")

	fmt.Printf("Plaintext: %s\n", string(plaintext))
	fmt.Printf("Key (hex): %s\n", hex.EncodeToString(key))
	fmt.Printf("IV (hex): %s\n", hex.EncodeToString(iv))

	// Шифруем
	ciphertext, err := gost.Encrypt(plaintext, key, iv)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	fmt.Printf("Ciphertext (hex): %s\n", hex.EncodeToString(ciphertext))

	// Расшифровываем
	decrypted, err := gost.Decrypt(ciphertext, key, iv)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	fmt.Printf("Decrypted: %s\n", string(decrypted))

	if string(plaintext) == string(decrypted) {
		fmt.Println("✓ GOST encryption/decryption successful!")
	} else {
		fmt.Println("✗ GOST encryption/decryption failed!")
	}

	return nil
}

func hashExample() error {
	// Создаем SHA-256 хэшер
	hash, err := gopenssl.NewHash(gopenssl.SHA256)
	if err != nil {
		return fmt.Errorf("failed to create hash: %w", err)
	}
	defer hash.Free()

	// Данные для хэширования
	data := []byte("Hello, GOpenSSL! This is a test message for hashing.")

	fmt.Printf("Data: %s\n", string(data))

	// Вычисляем хэш
	digest, err := hash.Sum(data)
	if err != nil {
		return fmt.Errorf("hashing failed: %w", err)
	}

	fmt.Printf("SHA-256 digest (hex): %s\n", hex.EncodeToString(digest))
	fmt.Printf("Hash size: %d bytes\n", hash.Size())

	// Тестируем GOST хэш
	gostHash, err := gopenssl.NewHash(gopenssl.GOSTR34112012256)
	if err != nil {
		fmt.Printf("GOST hash not available: %v\n", err)
	} else {
		defer gostHash.Free()

		gostDigest, err := gostHash.Sum(data)
		if err != nil {
			fmt.Printf("GOST hashing failed: %v\n", err)
		} else {
			fmt.Printf("GOST R 34.11-2012 (256) digest (hex): %s\n", hex.EncodeToString(gostDigest))
			fmt.Printf("GOST hash size: %d bytes\n", gostHash.Size())
		}
	}

	return nil
}

func rsaExample() error {
	// Создаем RSA объект
	rsa := gopenssl.NewRSA()
	defer rsa.Free()

	// Генерируем RSA ключи (2048 бит)
	fmt.Println("Generating RSA keys...")
	if err := rsa.GenerateKey(2048); err != nil {
		return fmt.Errorf("failed to generate RSA keys: %w", err)
	}

	fmt.Printf("RSA key size: %d bits\n", rsa.Size()*8)

	// Данные для шифрования
	plaintext := []byte("Hello, RSA!")

	fmt.Printf("Plaintext: %s\n", string(plaintext))

	// Шифруем с PKCS1 padding
	ciphertext, err := rsa.Encrypt(plaintext, gopenssl.RSA_PKCS1_PADDING)
	if err != nil {
		return fmt.Errorf("RSA encryption failed: %w", err)
	}

	fmt.Printf("RSA ciphertext (hex): %s\n", hex.EncodeToString(ciphertext))

	// Расшифровываем
	decrypted, err := rsa.Decrypt(ciphertext, gopenssl.RSA_PKCS1_PADDING)
	if err != nil {
		return fmt.Errorf("RSA decryption failed: %w", err)
	}

	fmt.Printf("RSA decrypted: %s\n", string(decrypted))

	if string(plaintext) == string(decrypted) {
		fmt.Println("✓ RSA encryption/decryption successful!")
	} else {
		fmt.Println("✗ RSA encryption/decryption failed!")
	}

	// Тестируем подписи
	signature, err := rsa.Sign(plaintext, gopenssl.SHA256)
	if err != nil {
		return fmt.Errorf("RSA signing failed: %w", err)
	}

	fmt.Printf("RSA signature (hex): %s\n", hex.EncodeToString(signature))

	// Проверяем подпись
	if err := rsa.Verify(plaintext, signature, gopenssl.SHA256); err != nil {
		return fmt.Errorf("RSA signature verification failed: %w", err)
	}

	fmt.Println("✓ RSA signature verification successful!")

	return nil
}
