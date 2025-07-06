# Инструкции по сборке GOpenSSL

## Требования

### Системные зависимости

- **Go 1.22+** - для компиляции Go кода
- **GCC/Clang** - для компиляции C кода через CGO
- **Git** - для скачивания OpenSSL
- **Make** - для автоматизации сборки
- **Perl** - для сборки OpenSSL (на некоторых системах)

### Операционные системы

- **Linux** (Ubuntu, CentOS, RHEL, etc.)
- **macOS** (с установленным Xcode Command Line Tools)
- **Windows** (с MinGW или WSL)

## Быстрая сборка

### 1. Клонирование репозитория

```bash
git clone https://github.com/yourusername/gopenssl.git
cd gopenssl
```

### 2. Автоматическая сборка

```bash
# Проверка зависимостей
make check-deps

# Полная сборка (OpenSSL + GOpenSSL)
make all

# Запуск примеров
make run-example
```

## Пошаговая сборка

### Шаг 1: Подготовка OpenSSL

```bash
# Скачать и собрать OpenSSL
make openssl
```

Это автоматически:
- Клонирует OpenSSL из GitHub
- Настраивает сборку
- Компилирует библиотеки
- Устанавливает в локальную директорию

### Шаг 2: Сборка GOpenSSL

```bash
# Собрать основную библиотеку
make build

# Или собрать с явным указанием путей
CGO_ENABLED=1 \
CGO_CFLAGS="-I../openssl/include" \
CGO_LDFLAGS="-L../openssl -lcrypto -lssl" \
go build ./...
```

### Шаг 3: Тестирование

```bash
# Запустить тесты
make test

# Собрать и запустить примеры
make examples
make run-example
```

## Сборка для разных платформ

### Linux

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install build-essential git

# CentOS/RHEL
sudo yum groupinstall "Development Tools"
sudo yum install git

# Сборка
make all
```

### macOS

```bash
# Установка Xcode Command Line Tools
xcode-select --install

# Сборка
make all
```

### Windows

#### Вариант 1: WSL (рекомендуется)

```bash
# Установка WSL
wsl --install

# В WSL
sudo apt-get update
sudo apt-get install build-essential git
make all
```

#### Вариант 2: MinGW

```bash
# Установка MinGW
# Скачайте и установите MinGW-w64

# Настройка переменных окружения
set CGO_ENABLED=1
set CGO_CFLAGS=-I../openssl/include
set CGO_LDFLAGS=-L../openssl -lcrypto -lssl

# Сборка
go build ./...
```

## Настройка переменных окружения

### Основные переменные

```bash
# Включить CGO
export CGO_ENABLED=1

# Путь к заголовочным файлам OpenSSL
export CGO_CFLAGS="-I../openssl/include"

# Путь к библиотекам OpenSSL
export CGO_LDFLAGS="-L../openssl -lcrypto -lssl"

# Путь к OpenSSL (опционально)
export OPENSSL_DIR="../openssl"
```

### Для Windows (PowerShell)

```powershell
$env:CGO_ENABLED = "1"
$env:CGO_CFLAGS = "-I../openssl/include"
$env:CGO_LDFLAGS = "-L../openssl -lcrypto -lssl"
```

## Устранение проблем

### Ошибка: "openssl/evp.h: No such file or directory"

```bash
# Убедитесь, что OpenSSL собран
ls -la ../openssl/include/openssl/

# Если файлов нет, пересоберите OpenSSL
make clean
make openssl
```

### Ошибка: "cannot find -lcrypto"

```bash
# Проверьте, что библиотеки существуют
ls -la ../openssl/libcrypto.a
ls -la ../openssl/libssl.a

# Если файлов нет, пересоберите OpenSSL
make clean
make openssl
```

### Ошибка: "gcc: command not found"

```bash
# Ubuntu/Debian
sudo apt-get install build-essential

# CentOS/RHEL
sudo yum groupinstall "Development Tools"

# macOS
xcode-select --install
```

### Ошибка: "CGO_ENABLED=0"

```bash
# Убедитесь, что CGO включен
export CGO_ENABLED=1
echo $CGO_ENABLED
```

## Сборка для продакшена

### Оптимизированная сборка

```bash
# Сборка с оптимизациями
CGO_ENABLED=1 \
CGO_CFLAGS="-I../openssl/include -O2" \
CGO_LDFLAGS="-L../openssl -lcrypto -lssl" \
go build -ldflags="-s -w" ./...
```

### Статическая сборка

```bash
# Сборка статической библиотеки
CGO_ENABLED=1 \
CGO_CFLAGS="-I../openssl/include" \
CGO_LDFLAGS="-L../openssl -lcrypto -lssl -static" \
go build -ldflags="-s -w" ./...
```

## Интеграция с CI/CD

### GitHub Actions

```yaml
name: Build GOpenSSL

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.22'
    
    - name: Install dependencies
      run: |
        sudo apt-get update
        sudo apt-get install build-essential git
    
    - name: Build OpenSSL
      run: make openssl
    
    - name: Build GOpenSSL
      run: make build
    
    - name: Run tests
      run: make test
```

### Docker

```dockerfile
FROM golang:1.22-bullseye

# Установка зависимостей
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# Клонирование и сборка OpenSSL
RUN git clone --depth 1 --branch OpenSSL_3_5_1 \
    https://github.com/openssl/openssl.git /tmp/openssl && \
    cd /tmp/openssl && \
    ./config --prefix=/usr/local/openssl && \
    make -j$(nproc) && \
    make install

# Настройка переменных окружения
ENV CGO_ENABLED=1
ENV CGO_CFLAGS="-I/usr/local/openssl/include"
ENV CGO_LDFLAGS="-L/usr/local/openssl/lib -lcrypto -lssl"

# Копирование кода
COPY . /app
WORKDIR /app

# Сборка
RUN go build ./...
```

## Проверка сборки

### Тест функциональности

```bash
# Запуск примеров
make run-example

# Ожидаемый вывод:
# === GOpenSSL Basic Usage Example ===
# 
# --- AES Encryption ---
# Plaintext: Hello, GOpenSSL! This is a test message for AES encryption.
# Key (hex): [32 bytes hex]
# IV (hex): [16 bytes hex]
# Encrypted (hex): [encrypted data]
# Decrypted: Hello, GOpenSSL! This is a test message for AES encryption.
# ✓ AES encryption/decryption successful!
```

### Проверка библиотек

```bash
# Проверка наличия OpenSSL библиотек
ls -la ../openssl/libcrypto.a
ls -la ../openssl/libssl.a

# Проверка заголовочных файлов
ls -la ../openssl/include/openssl/evp.h
ls -la ../openssl/include/openssl/err.h
```

## Обновление OpenSSL

```bash
# Очистка старой версии
make clean-all

# Сборка новой версии
make openssl

# Пересборка GOpenSSL
make build
```

## Полезные команды

```bash
# Показать информацию о системе
make info

# Показать справку
make help

# Очистка
make clean          # Очистить только сборку
make clean-all      # Очистить все (включая OpenSSL)

# Проверка зависимостей
make check-deps
``` 