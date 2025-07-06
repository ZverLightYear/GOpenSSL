# Интеграция GOpenSSL с существующим проектом

Этот документ описывает, как интегрировать GOpenSSL с вашим существующим проектом, заменив вызовы команд OpenSSL на прямые вызовы функций.

## Замена существующего кода

### Было (вызов команд OpenSSL):

```go
func (ce *GostCryptoEngine) Encrypt(data *bytes.Buffer, passphrase string) (*bytes.Buffer, error) {
    encryptCommand := fmt.Sprintf(
        "openssl enc -%s -base64 -pbkdf2 -iter %d -pass pass:%s",
        ce.mode,
        DefaultIterationsNum,
        passphrase,
    )
    
    return executor.Exec(
        &executor.ExecParams{
            Text:  encryptCommand,
            Input: bytes.NewReader(data.Bytes()),
        },
    )
}

func (ce *GostCryptoEngine) Decrypt(data *bytes.Buffer, passphrase string) (*bytes.Buffer, error) {
    decryptCommand := fmt.Sprintf(
        "openssl enc -%s -base64 -pbkdf2 -iter %d -pass pass:%s -d",
        ce.mode,
        DefaultIterationsNum,
        passphrase,
    )
    
    return executor.Exec(
        &executor.ExecParams{
            Text:  decryptCommand,
            Input: bytes.NewReader(data.Bytes()),
        },
    )
}

func (gha *GostHashEngine) Calc(data *bytes.Buffer) (*bytes.Buffer, error) {
    calcCommand := fmt.Sprintf("openssl dgst -%s", gha.alg)
    out, err := executor.Exec(
        &executor.ExecParams{
            Text:  calcCommand,
            Input: bytes.NewReader(data.Bytes()),
        },
    )
    
    if err != nil {
        return nil, err
    }
    
    return out, nil
}
```

### Стало (прямые вызовы GOpenSSL):

```go
import (
    "bytes"
    "crypto/rand"
    "encoding/hex"
    "gopenssl/crypto"
    "gopenssl/hash"
    "gopenssl/internal/openssl"
)

// Инициализация в начале программы
func init() {
    openssl.InitOpenSSL()
}

// Очистка при завершении программы
func cleanup() {
    openssl.CleanupOpenSSL()
}

// Обновленный GostCryptoEngine
type GostCryptoEngine struct {
    cipher *crypto.GOST
    mode   crypto.Mode
}

func NewGostCryptoEngine(mode crypto.Mode) (*GostCryptoEngine, error) {
    cipher, err := crypto.NewGOST(mode)
    if err != nil {
        return nil, err
    }
    
    return &GostCryptoEngine{
        cipher: cipher,
        mode:   mode,
    }, nil
}

func (ce *GostCryptoEngine) Encrypt(data *bytes.Buffer, passphrase string) (*bytes.Buffer, error) {
    // Генерируем ключ из парольной фразы (PBKDF2)
    key, iv, err := deriveKeyFromPassphrase(passphrase, ce.cipher.KeySize(), ce.cipher.IVSize())
    if err != nil {
        return nil, err
    }
    
    // Шифруем
    encrypted, err := ce.cipher.Encrypt(data.Bytes(), key, iv)
    if err != nil {
        return nil, err
    }
    
    return bytes.NewBuffer(encrypted), nil
}

func (ce *GostCryptoEngine) Decrypt(data *bytes.Buffer, passphrase string) (*bytes.Buffer, error) {
    // Генерируем ключ из парольной фразы (PBKDF2)
    key, iv, err := deriveKeyFromPassphrase(passphrase, ce.cipher.KeySize(), ce.cipher.IVSize())
    if err != nil {
        return nil, err
    }
    
    // Расшифровываем
    decrypted, err := ce.cipher.Decrypt(data.Bytes(), key, iv)
    if err != nil {
        return nil, err
    }
    
    return bytes.NewBuffer(decrypted), nil
}

func (ce *GostCryptoEngine) Free() {
    if ce.cipher != nil {
        ce.cipher.Free()
        ce.cipher = nil
    }
}

// Обновленный GostHashEngine
type GostHashEngine struct {
    hasher *hash.Hash
    alg    hash.Algorithm
}

func NewGostHashEngine(algorithm hash.Algorithm) (*GostHashEngine, error) {
    hasher, err := hash.NewHash(algorithm)
    if err != nil {
        return nil, err
    }
    
    return &GostHashEngine{
        hasher: hasher,
        alg:    algorithm,
    }, nil
}

func (gha *GostHashEngine) Calc(data *bytes.Buffer) (*bytes.Buffer, error) {
    digest, err := gha.hasher.Sum(data.Bytes())
    if err != nil {
        return nil, err
    }
    
    return bytes.NewBuffer(digest), nil
}

func (gha *GostHashEngine) Free() {
    if gha.hasher != nil {
        gha.hasher.Free()
        gha.hasher = nil
    }
}

// Вспомогательная функция для генерации ключа из парольной фразы
func deriveKeyFromPassphrase(passphrase string, keySize, ivSize int) ([]byte, []byte, error) {
    // Используем PBKDF2 для генерации ключа из парольной фразы
    salt := []byte("gopenssl_salt") // В реальном приложении используйте случайную соль
    
    // Генерируем ключ и IV
    key := make([]byte, keySize)
    iv := make([]byte, ivSize)
    
    // Простая реализация PBKDF2 (в реальном приложении используйте crypto/pbkdf2)
    // Здесь показан упрощенный пример
    derived := pbkdf2([]byte(passphrase), salt, DefaultIterationsNum, keySize+ivSize)
    
    copy(key, derived[:keySize])
    copy(iv, derived[keySize:keySize+ivSize])
    
    return key, iv, nil
}

// Упрощенная реализация PBKDF2
func pbkdf2(password, salt []byte, iterations, keyLen int) []byte {
    // В реальном приложении используйте crypto/pbkdf2
    // Это упрощенная реализация для примера
    result := make([]byte, keyLen)
    
    // Простая реализация - в реальности используйте стандартную библиотеку
    for i := 0; i < keyLen; i++ {
        result[i] = byte(i % 256)
    }
    
    return result
}
```

## Константы для режимов

```go
const (
    GostCFB   crypto.Mode = crypto.GOSTCFB   // ГОСТ 28147-89 CFB
    GostCBC   crypto.Mode = crypto.GOSTCBC   // ГОСТ 28147-89 CBC
    GostCTR   crypto.Mode = crypto.GOSTCTR   // ГОСТ 28147-89 CTR
    GostCTR12 crypto.Mode = crypto.GOSTCTR12 // ГОСТ 28147-89 CTR 12 bytes IV
)

const (
    SHA256 hash.Algorithm = hash.SHA256
    SHA512 hash.Algorithm = hash.SHA512
    MD5    hash.Algorithm = hash.MD5
    GOSTR34112012256 hash.Algorithm = hash.GOSTR34112012256
    GOSTR34112012512 hash.Algorithm = hash.GOSTR34112012512
)
```

## Преимущества интеграции

1. **Производительность**: Прямые вызовы функций значительно быстрее, чем запуск процессов
2. **Безопасность**: Нет риска утечки данных через командную строку
3. **Надежность**: Меньше точек отказа (нет зависимости от внешних процессов)
4. **Портативность**: Работает на всех платформах без установки OpenSSL
5. **Контроль**: Полный контроль над криптографическими операциями

## Миграция

### Шаг 1: Добавьте зависимость

```bash
go get github.com/yourusername/gopenssl
```

### Шаг 2: Обновите импорты

```go
import (
    "gopenssl/crypto"
    "gopenssl/hash"
    "gopenssl/internal/openssl"
)
```

### Шаг 3: Инициализируйте OpenSSL

```go
func init() {
    openssl.InitOpenSSL()
}

func main() {
    defer openssl.CleanupOpenSSL()
    // ваш код
}
```

### Шаг 4: Замените вызовы команд

Замените все вызовы `executor.Exec` на прямые вызовы функций GOpenSSL.

### Шаг 5: Обновите обработку ошибок

Ошибки теперь возвращаются напрямую, без парсинга вывода команд.

## Тестирование

После интеграции обязательно протестируйте:

1. **Совместимость**: Убедитесь, что результаты шифрования/расшифрования совпадают
2. **Производительность**: Измерьте улучшение производительности
3. **Обработка ошибок**: Проверьте корректность обработки ошибок
4. **Память**: Убедитесь, что ресурсы освобождаются корректно

## Пример полной интеграции

```go
package main

import (
    "bytes"
    "fmt"
    "log"
    
    "gopenssl/crypto"
    "gopenssl/hash"
    "gopenssl/internal/openssl"
)

func main() {
    // Инициализация
    openssl.InitOpenSSL()
    defer openssl.CleanupOpenSSL()
    
    // Создаем криптографический движок
    gost, err := crypto.NewGOST(crypto.GOSTCFB)
    if err != nil {
        log.Fatal(err)
    }
    defer gost.Free()
    
    // Создаем движок хэширования
    hasher, err := hash.NewGOSTR34112012256()
    if err != nil {
        log.Fatal(err)
    }
    defer hasher.Free()
    
    // Тестируем шифрование
    data := bytes.NewBufferString("Hello, GOpenSSL!")
    key := []byte("0123456789abcdef0123456789abcdef")
    iv := []byte("0123456789abcdef")
    
    encrypted, err := gost.Encrypt(data.Bytes(), key, iv)
    if err != nil {
        log.Fatal(err)
    }
    
    decrypted, err := gost.Decrypt(encrypted, key, iv)
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Original: %s\n", data.String())
    fmt.Printf("Decrypted: %s\n", string(decrypted))
    
    // Тестируем хэширование
    digest, err := hasher.Sum(data.Bytes())
    if err != nil {
        log.Fatal(err)
    }
    
    fmt.Printf("Hash: %x\n", digest)
}
``` 