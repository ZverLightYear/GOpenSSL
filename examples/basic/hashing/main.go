package main

import (
	"encoding/hex"
	"fmt"
	cgopenssl "gopenssl/cgo"
	"log"

	"gopenssl"
)

func main() {
	fmt.Println("=== Базовый пример хэширования ===")
	fmt.Printf("OpenSSL версия: %s\n\n", cgopenssl.OpenSSLVersion())

	// Получаем провайдер
	provider := gopenssl.GetProvider()

	// Данные для хэширования
	data := []byte("Hello, GOpenSSL! Это тестовое сообщение для хэширования.")
	fmt.Printf("Исходные данные: %s\n\n", string(data))

	// Тестируем различные алгоритмы хэширования
	algorithms := []gopenssl.HashAlgorithm{
		gopenssl.SHA256,
		gopenssl.SHA512,
		gopenssl.MD5,
	}

	for _, algorithm := range algorithms {
		// Создаем хэшер
		hasher, err := provider.NewHasher(algorithm)
		if err != nil {
			log.Printf("Ошибка создания хэшера для %s: %v", algorithm, err)
			continue
		}

		// Хэшируем данные
		_, err = hasher.Write(data)
		if err != nil {
			log.Printf("Ошибка записи данных в хэшер %s: %v", algorithm, err)
			continue
		}

		// Получаем хэш
		hash := hasher.Sum()
		fmt.Printf("%s: %s\n", algorithm, hex.EncodeToString(hash))
		fmt.Printf("Размер хэша: %d байт\n", hasher.Size())
		fmt.Println()
	}

	// Демонстрация потокового хэширования
	fmt.Println("=== Потоковое хэширование ===")
	hasher, err := provider.NewHasher(gopenssl.SHA256)
	if err != nil {
		log.Fatalf("Ошибка создания хэшера: %v", err)
	}

	// Хэшируем данные по частям
	parts := [][]byte{
		[]byte("Hello, "),
		[]byte("GOpenSSL! "),
		[]byte("Это тестовое сообщение для хэширования."),
	}

	for i, part := range parts {
		_, err := hasher.Write(part)
		if err != nil {
			log.Fatalf("Ошибка записи части %d: %v", i, err)
		}
		fmt.Printf("Добавлена часть %d: %s\n", i+1, string(part))
	}

	// Получаем финальный хэш
	finalHash := hasher.Sum()
	fmt.Printf("Финальный хэш SHA256: %s\n", hex.EncodeToString(finalHash))
}
