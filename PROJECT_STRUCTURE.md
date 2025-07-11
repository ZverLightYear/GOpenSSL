# Структура проекта GOpenSSL

## Обзор
Проект реорганизован для лучшей модульности и разделения ответственности. Все компоненты разделены по функциональности и типу.

## Структура директорий

### CGO обертки (`cgo/`)
```
cgo/
├── gopenssl.go              # Основной файл для инициализации
├── providers/
│   └── openssl_provider.go  # Инициализация OpenSSL провайдеров
├── ciphers/
│   └── cipher_list.go       # Список доступных шифров
└── hashes/
    └── hash_list.go         # Список доступных хэш-функций
```

### Внутренняя логика (`internal/`)
```
internal/
├── interfaces.go            # Основные интерфейсы
├── providers/
│   └── openssl_provider.go  # OpenSSL провайдер
├── ciphers/                 # Реализации шифров (TODO)
├── hashes/                  # Реализации хэшеров (TODO)
└── factories/
    ├── cipher_factory.go    # Фабрика шифров
    └── hash_factory.go      # Фабрика хэшеров
```

### Тесты (`tests/`)
```
tests/
├── provider.go              # Общий провайдер для тестов
├── unit/                    # Модульные тесты
│   ├── crypto_test.go
│   ├── gopenssl_test.go
│   ├── hash_test.go
│   └── aes_test.go
├── integration/             # Интеграционные тесты
│   ├── gost_test.go
│   ├── openssl_comparison_test.go
│   └── singleton_test.go
├── benchmarks/              # Бенчмарки производительности
│   ├── benchmark_test.go
│   └── quick_benchmark_test.go
└── performance/             # Тесты производительности
    └── provider.go
```

### Подмодули (`submodules/`)
```
submodules/
├── openssl/                 # OpenSSL исходный код
└── gost-engine/             # GOST engine исходный код
```

## Принципы организации

### 1. Разделение CGO оберток
- **providers**: Инициализация и управление провайдерами
- **ciphers**: Операции со списком шифров
- **hashes**: Операции со списком хэш-функций

### 2. Внутренняя архитектура (internal)
- **interfaces**: Определение всех интерфейсов
- **providers**: Реализация провайдеров
- **ciphers**: Конкретные реализации шифров
- **hashes**: Конкретные реализации хэшеров
- **factories**: Фабрики для создания объектов

### 3. Организация тестов
- **unit**: Модульные тесты отдельных компонентов
- **integration**: Тесты взаимодействия компонентов
- **benchmarks**: Бенчмарки производительности
- **performance**: Тесты производительности

## API

### Основной пакет (`crypto.go`)
Экспортирует все публичные интерфейсы и функции:

```go
// Основные интерфейсы
type CryptoProvider interface { ... }
type Cipher interface { ... }
type Hasher interface { ... }

// Константы
const (
    AES = internal.AES
    GOST = internal.GOST
    // ...
)

// Функции
func GetProvider() CryptoProvider
func NewProvider() CryptoProvider
func OpenSSLVersion() string
func ListCiphers() []string
func ListHashes() []string
```

## Преимущества новой структуры

1. **Модульность**: Каждый компонент имеет четкую ответственность
2. **Тестируемость**: Тесты разделены по типам и назначению
3. **Расширяемость**: Легко добавлять новые алгоритмы и провайдеры
4. **Читаемость**: Понятная структура для новых разработчиков
5. **Изоляция**: Internal пакет скрывает детали реализации

## Следующие шаги

1. Перенести реализации шифров из `crypto/openssl/` в `internal/ciphers/`
2. Перенести реализации хэшеров из `crypto/openssl/` в `internal/hashes/`
3. Обновить импорты в тестах
4. Добавить документацию для каждого пакета
5. Создать примеры использования 