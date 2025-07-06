# Настройка GOpenSSL

## Требования

- Go 1.22+
- C компилятор (GCC/MinGW-w64 на Windows)
- OpenSSL

## Установка зависимостей

### 1. Установка Go
Скачайте и установите Go с официального сайта: https://golang.org/dl/

### 2. Установка C компилятора

#### Windows
Установите MinGW-w64:
1. Скачайте с https://www.mingw-w64.org/downloads/
2. Установите в `C:\mingw-w64\mingw64\`
3. Добавьте `C:\mingw-w64\mingw64\bin` в переменную PATH

#### Linux
```bash
sudo apt-get install gcc
# или
sudo yum install gcc
```

#### macOS
```bash
xcode-select --install
```

### 3. Установка OpenSSL

#### Автоматическая установка (Windows)
```bash
make install-openssl-windows
```

#### Ручная установка (Windows)
1. Скачайте OpenSSL с https://slproweb.com/products/Win32OpenSSL.html
2. Установите в `C:\OpenSSL-Win64`
3. Добавьте `C:\OpenSSL-Win64\bin` в переменную PATH

#### Linux
```bash
sudo apt-get install libssl-dev
# или
sudo yum install openssl-devel
```

#### macOS
```bash
brew install openssl
```

## Настройка проекта

### 1. Клонирование и инициализация
```bash
git clone <your-repo-url>
cd gopenssl
git submodule update --init --recursive
```

### 2. Проверка зависимостей
```bash
# Проверка Go
go version

# Проверка C компилятора
gcc --version

# Проверка OpenSSL
openssl version
```

### 3. Сборка проекта
```bash
# Сборка библиотеки
make build

# Запуск тестов
make test

# Сборка примеров
make examples
```

## Устранение проблем

### Ошибка "C compiler not found"
Установите C компилятор (см. выше).

### Ошибка "openssl/configuration.h: No such file or directory"
Установите OpenSSL (см. выше).

### Ошибка "CGO disabled"
Убедитесь, что CGO включен:
```bash
set CGO_ENABLED=1  # Windows
export CGO_ENABLED=1  # Linux/macOS
```

### Ошибка "pkg-config: openssl not found"
Установите pkg-config и OpenSSL development пакеты:
```bash
# Ubuntu/Debian
sudo apt-get install pkg-config libssl-dev

# CentOS/RHEL
sudo yum install pkgconfig openssl-devel

# macOS
brew install pkg-config openssl
```

## Проверка установки

После установки всех зависимостей запустите:

```bash
go test -v ./tests/
```

Должны пройти все тесты без ошибок.

## Использование

```go
package main

import "gopenssl"

func main() {
    // AES шифрование
    aes, err := gopenssl.NewAES(gopenssl.AES256, gopenssl.AESCBC)
    if err != nil {
        panic(err)
    }
    defer aes.Free()
    
    // Хэширование
    hash, err := gopenssl.NewHash(gopenssl.SHA256)
    if err != nil {
        panic(err)
    }
    defer hash.Free()
} 