# GOpenSSL

Go библиотека для криптографических операций, основанная на исходном коде OpenSSL.

## Возможности

### Алгоритмы шифрования
- **AES**: CBC, CFB, CTR, GCM, XTS режимы
- **RSA**: шифрование, подписи, генерация ключей
- **GOST**: ГОСТ 28147-89 (CFB, CBC, CTR режимы)
- **Grasshopper**: российский стандарт ГОСТ Р 34.12-2015

### Алгоритмы хэширования
- **SHA**: SHA-1, SHA-256, SHA-512 и другие
- **MD**: MD5, MD4
- **GOST**: ГОСТ Р 34.11-2012 (Streebog)

## Установка

```bash
go get github.com/yourusername/gopenssl
```

## Использование

### Шифрование AES

```go
package main

import (
    "bytes"
    "fmt"
    "github.com/yourusername/gopenssl/crypto"
)

func main() {
    // Создание AES шифратора
    aes, err := crypto.NewAES(crypto.AES256, crypto.CBC)
    if err != nil {
        panic(err)
    }
    
    // Шифрование
    plaintext := []byte("Hello, World!")
    key := []byte("0123456789abcdef0123456789abcdef")
    iv := []byte("0123456789abcdef")
    
    encrypted, err := aes.Encrypt(plaintext, key, iv)
    if err != nil {
        panic(err)
    }
    
    // Расшифрование
    decrypted, err := aes.Decrypt(encrypted, key, iv)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("Decrypted: %s\n", string(decrypted))
}
```

### Хэширование

```go
package main

import (
    "fmt"
    "github.com/yourusername/gopenssl/hash"
)

func main() {
    // Создание SHA-256 хэшера
    hasher, err := hash.NewSHA256()
    if err != nil {
        panic(err)
    }
    
    data := []byte("Hello, World!")
    digest := hasher.Sum(data)
    
    fmt.Printf("SHA-256: %x\n", digest)
}
```

### GOST шифрование

```go
package main

import (
    "fmt"
    "github.com/yourusername/gopenssl/crypto"
)

func main() {
    // Создание GOST шифратора
    gost, err := crypto.NewGOST(crypto.GOSTCFB)
    if err != nil {
        panic(err)
    }
    
    plaintext := []byte("Hello, GOST!")
    key := make([]byte, 32) // 256 бит ключ
    iv := make([]byte, 8)   // 64 бит IV
    
    encrypted, err := gost.Encrypt(plaintext, key, iv)
    if err != nil {
        panic(err)
    }
    
    fmt.Printf("GOST encrypted: %x\n", encrypted)
}
```

## Архитектура

Библиотека использует CGO для интеграции с исходным кодом OpenSSL:

- `cgo/` - CGO обертки для OpenSSL функций
- `submodules/openssl/` - OpenSSL исходный код (git submodule)
- `examples/` - примеры использования
- `cmd/` - утилиты командной строки
- `tests/` - тесты и бенчмарки

## Варианты использования OpenSSL

Проект поддерживает два способа использования OpenSSL:

### 1. OpenSSL Submodule (рекомендуется для разработки)
- Использует исходный код OpenSSL из git submodule
- Требует сборки OpenSSL из исходников
- Полный контроль над версией OpenSSL

### 2. Системный OpenSSL (рекомендуется для продакшена)
- Использует установленный в системе OpenSSL
- Проще в настройке
- Использует стабильную версию от дистрибутива

## Сборка

Для сборки требуется:
- Go 1.22+
- C компилятор (GCC/MinGW-w64 на Windows)
- OpenSSL (см. SETUP.md для подробностей)

### Быстрая настройка

```bash
# Клонирование и инициализация
git clone <your-repo-url>
cd gopenssl
git submodule update --init --recursive

# Установка OpenSSL (Windows)
make install-openssl-windows

# Сборка проекта
make build

# Запуск тестов
make test
```

### Ручная настройка

См. файл `SETUP.md` для подробных инструкций по установке зависимостей.

## Лицензия

Apache License 2.0 