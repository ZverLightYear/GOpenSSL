package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"gopenssl"
	"log"

	"gopenssl/cgo"
)

func main() {
	fmt.Println("=== Пример потокового шифрования ===")
	fmt.Printf("OpenSSL версия: %s\n\n", cgopenssl.OpenSSLVersion())

	// Получаем провайдер
	provider := gopenssl.GetProvider()

	// Подготавливаем данные
	plaintext := []byte("Это большое сообщение для демонстрации потокового шифрования. " +
		"Данные будут обрабатываться по частям, что позволяет эффективно работать " +
		"с большими объемами данных без загрузки всего содержимого в память.")

	fmt.Printf("Исходный текст (%d байт): %s\n\n", len(plaintext), string(plaintext))

	// Генерируем ключ и IV для AES-256-CTR
	key := make([]byte, 32) // 256 bits
	iv := make([]byte, 16)  // 128 bits
	rand.Read(key)
	rand.Read(iv)

	fmt.Printf("Ключ (hex): %s\n", hex.EncodeToString(key))
	fmt.Printf("IV (hex): %s\n\n", hex.EncodeToString(iv))

	// Создаем шифр
	cipher, err := provider.NewCipher(gopenssl.AES, gopenssl.ModeCTR, key, iv)
	if err != nil {
		log.Fatalf("Ошибка создания шифра: %v", err)
	}

	// Создаем потоковый шифратор
	encryptStream, err := cipher.EncryptStream()
	if err != nil {
		log.Fatalf("Ошибка создания потокового шифратора: %v", err)
	}
	defer encryptStream.Close()

	// Шифруем данные по частям
	chunkSize := 32 // Размер блока для обработки
	var ciphertext []byte

	for i := 0; i < len(plaintext); i += chunkSize {
		end := i + chunkSize
		if end > len(plaintext) {
			end = len(plaintext)
		}

		chunk := plaintext[i:end]
		fmt.Printf("Обрабатываем блок %d-%d (%d байт): %s\n", i, end-1, len(chunk), string(chunk))

		_, err := encryptStream.Write(chunk)
		if err != nil {
			log.Fatalf("Ошибка записи в потоковый шифратор: %v", err)
		}
	}

	// Получаем финальные данные
	final, err := encryptStream.Final()
	if err != nil {
		log.Fatalf("Ошибка завершения шифрования: %v", err)
	}

	ciphertext = append(ciphertext, final...)
	fmt.Printf("Зашифрованный текст (hex): %s\n\n", hex.EncodeToString(ciphertext))

	// Создаем потоковый дешифратор
	decryptStream, err := cipher.DecryptStream()
	if err != nil {
		log.Fatalf("Ошибка создания потокового дешифратора: %v", err)
	}
	defer decryptStream.Close()

	// Расшифровываем данные по частям
	var decrypted []byte

	for i := 0; i < len(ciphertext); i += chunkSize {
		end := i + chunkSize
		if end > len(ciphertext) {
			end = len(ciphertext)
		}

		chunk := ciphertext[i:end]
		fmt.Printf("Расшифровываем блок %d-%d (%d байт)\n", i, end-1, len(chunk))

		_, err := decryptStream.Write(chunk)
		if err != nil {
			log.Fatalf("Ошибка записи в потоковый дешифратор: %v", err)
		}
	}

	// Получаем финальные данные
	finalDecrypted, err := decryptStream.Final()
	if err != nil {
		log.Fatalf("Ошибка завершения расшифрования: %v", err)
	}

	decrypted = append(decrypted, finalDecrypted...)
	fmt.Printf("Расшифрованный текст: %s\n", string(decrypted))

	// Проверяем результат
	if string(decrypted) == string(plaintext) {
		fmt.Println("✅ Потоковое шифрование/расшифрование работает корректно!")
	} else {
		fmt.Println("❌ Ошибка: данные не совпадают!")
	}
}
