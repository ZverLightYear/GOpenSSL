# Dev Startup Guide

Этот документ описывает, как настроить и запустить проект GOpenSSL на локальной машине.

## Предварительные требования

- **Go 1.20+** (проект использует Go 1.20.14)
- **CMake 3.10+** (для сборки gost-engine)
- **C компилятор** (gcc/clang)
- **Git** (для работы с репозиторием)

### macOS (M1/M2)
```bash
# Установка через Homebrew
brew install go cmake

# Проверка версий
go version
cmake --version
```

### Linux (Ubuntu/Debian)
```bash
# Установка зависимостей
sudo apt update
sudo apt install build-essential cmake git golang-go

# Проверка версий
go version
cmake --version
```

## Настройка проекта

### 1. Клонирование репозитория
```bash
git clone <repository-url>
cd GOpenSSL
```

### 2. Инициализация подмодулей
```bash
# Инициализация и обновление подмодулей
git submodule update --init --recursive
```

### 3. Сборка зависимостей

Проект автоматически собирает OpenSSL и gost-engine из исходников:

```bash
# Очистка предыдущих сборок (если есть)
make clean

# Сборка OpenSSL и gost-engine
make all
```

**Что происходит:**
- OpenSSL 3.5.1 собирается с поддержкой `shared`, `enable-legacy`, `enable-engine`
- gost-engine собирается через CMake и устанавливается как engine
- Все артефакты помещаются в `submodules/build/`

### 4. Проверка сборки

Убедитесь, что все компоненты собрались корректно:

```bash
# Проверка наличия библиотек
ls submodules/build/lib/
ls submodules/build/lib/engines-3/
ls submodules/build/lib/ossl-modules/

# Проверка CLI
submodules/build/bin/openssl version
```

## Запуск тестов

### Структура тестов

Тесты находятся в `cgo/gopenssl_test.go` и являются частью пакета `gopenssl`. Это обеспечивает корректную работу cgo и видимость всех зависимостей.

### Запуск тестов

```bash
# Запуск всех тестов пакета cgo
go test ./cgo -v

# Ожидаемый вывод:
# === RUN   TestOpenSSLVersion
#     gopenssl_test.go:13: OpenSSL version: OpenSSL 3.5.1 1 Jul 2025
# --- PASS: TestOpenSSLVersion (0.00s)
# === RUN   TestListCiphers
#     gopenssl_test.go:22: Cipher: gost89
#     gopenssl_test.go:22: Cipher: AES-128-CBC
#     ... (много других шифров)
# --- PASS: TestListCiphers (0.29s)
# === RUN   TestCipherGOSTPresent
#     gopenssl_test.go:32: Found GOST cipher: gost89
#     gopenssl_test.go:32: Found GOST cipher: gost89-cbc
#     ... (другие GOST шифры)
# --- PASS: TestCipherGOSTPresent (0.00s)
# PASS
# ok      gopenssl/cgo    0.589s
```

## Архитектура решения

### Проблема
Изначально тесты не работали из-за:
1. **Отсутствия провайдеров OpenSSL** - `default.dylib`, `base.dylib` не собирались на macOS
2. **Неправильной структуры тестов** - тесты в отдельной директории `tests/` не видели cgo зависимости
3. **Отсутствия инициализации GOST** - engine не активировался автоматически

### Решение

#### 1. Автоматическая сборка зависимостей
- **Makefile** автоматически собирает OpenSSL с нужными флагами
- **CMake** собирает gost-engine и устанавливает его как engine
- Все пути и зависимости настраиваются автоматически

#### 2. Правильная структура тестов
```go
// cgo/gopenssl_test.go
package gopenssl  // Тесты в том же пакете, что и исходники

import (
    "strings"
    "testing"
)

func TestCipherGOSTPresent(t *testing.T) {
    ciphers := ListCiphers()  // Прямой вызов функции из того же пакета
    // ...
}
```

#### 3. Автоматическая инициализация GOST
```c
// В cgo/gopenssl.go
static void go_init_legacy_and_gost() {
    OSSL_PROVIDER_load(NULL, "legacy");  // Загружаем legacy provider
    ENGINE_load_builtin_engines();       // Загружаем все engines
    ENGINE *e = ENGINE_by_id("gost");    // Находим GOST engine
    if (e) {
        ENGINE_init(e);                  // Инициализируем
        ENGINE_set_default(e, ENGINE_METHOD_ALL);  // Делаем по умолчанию
        ENGINE_free(e);
    }
}
```

## Использование в других проектах

После успешной сборки библиотеку можно использовать в других Go-проектах:

```go
package main

import (
    "fmt"
    "gopenssl/cgo/gopenssl"
)

func main() {
    // Получение версии OpenSSL
    version := gopenssl.OpenSSLVersion()
    fmt.Printf("OpenSSL version: %s\n", version)
    
    // Получение списка доступных шифров
    ciphers := gopenssl.ListCiphers()
    for _, cipher := range ciphers {
        fmt.Printf("Available cipher: %s\n", cipher)
    }
}
```

## Устранение неполадок

### Ошибка: "No GOST cipher found"
**Причина:** GOST engine не загрузился или не активировался
**Решение:** 
1. Убедитесь, что `make all` выполнился успешно
2. Проверьте наличие `gost.dylib` в `submodules/build/lib/engines-3/`
3. Перезапустите тесты

### Ошибка: "No ciphers found"
**Причина:** OpenSSL не видит провайдеры
**Решение:**
1. Проверьте, что `legacy.dylib` есть в `submodules/build/lib/ossl-modules/`
2. Пересоберите OpenSSL: `make clean && make all`

### Ошибка: "package gopenssl/cgo/gopenssl is not in std"
**Причина:** Неправильная структура импортов
**Решение:** Запускайте тесты из корня проекта: `go test ./cgo -v`

### Предупреждения о deprecated ENGINE API
**Причина:** OpenSSL 3.x помечает ENGINE API как устаревший
**Решение:** Это нормально, функциональность работает корректно. В будущих версиях планируется переход на Provider API.

## Дополнительные команды

```bash
# Очистка всех собранных файлов
make clean

# Пересборка только OpenSSL
make openssl

# Пересборка только gost-engine
make gost-engine

# Проверка структуры проекта
tree -I 'submodules/build|.git'
``` 