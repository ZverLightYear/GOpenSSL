package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	cgopenssl "gopenssl/cgo"
	"log"

	"gopenssl"
)

func main() {
	fmt.Println("=== Базовый пример шифрования ===")
	fmt.Printf("OpenSSL версия: %s\n\n", cgopenssl.OpenSSLVersion())

	// Получаем провайдер
	provider := gopenssl.GetProvider()

	// Подготавливаем данные для шифрования
	plaintext := []byte("Hello, GOpenSSL! Это тестовое сообщение для шифрования.")
	fmt.Printf("Исходный текст: %s\n", string(plaintext))

	// Генерируем ключ и IV для AES-256-CBC
	key := make([]byte, 32) // 256 bits
	iv := make([]byte, 16)  // 128 bits
	rand.Read(key)
	rand.Read(iv)

	fmt.Printf("Ключ (hex): %s\n", hex.EncodeToString(key))
	fmt.Printf("IV (hex): %s\n", hex.EncodeToString(iv))

	// Создаем шифр
	cipher, err := provider.NewCipher(gopenssl.AES, gopenssl.ModeCBC, key, iv)
	if err != nil {
		log.Fatalf("Ошибка создания шифра: %v", err)
	}

	// Шифруем данные
	ciphertext, err := cipher.Encrypt(plaintext)
	if err != nil {
		log.Fatalf("Ошибка шифрования: %v", err)
	}

	fmt.Printf("Зашифрованный текст (hex): %s\n", hex.EncodeToString(ciphertext))

	// Расшифровываем данные
	decrypted, err := cipher.Decrypt(ciphertext)
	if err != nil {
		log.Fatalf("Ошибка расшифрования: %v", err)
	}

	fmt.Printf("Расшифрованный текст: %s\n", string(decrypted))

	// Проверяем, что данные совпадают
	if string(decrypted) == string(plaintext) {
		fmt.Println("✅ Шифрование/расшифрование работает корректно!")
	} else {
		fmt.Println("❌ Ошибка: данные не совпадают!")
	}
}
