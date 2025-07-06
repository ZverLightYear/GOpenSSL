# Тесты GOpenSSL

Этот каталог содержит тесты для библиотеки GOpenSSL.

## Структура тестов

### `crypto_test.go`
Содержит unit-тесты для криптографических функций:
- AES шифрование (различные режимы и размеры ключей)
- GOST шифрование (различные режимы)
- RSA шифрование и подписи
- Проверка размеров ключей и блоков
- Тестирование хэш-алгоритмов
- Генерация случайных байтов

### `benchmark_test.go`
Содержит тесты производительности для сравнения старого и нового методов:
- Бенчмарки AES шифрования
- Бенчмарки хэш-алгоритмов
- Бенчмарки RSA операций
- Сравнение производительности CGO vs CLI методов

## Запуск тестов

### Unit-тесты
```bash
go test -v ./tests/
```

### Бенчмарки
```bash
go test -bench=. ./tests/
```

### Тесты производительности
```bash
go test -v -run TestPerformanceComparison ./tests/
```

## Примеры вывода

### Unit-тесты
```
=== RUN   TestAESEncryption
--- PASS: TestAESEncryption (0.05s)
=== RUN   TestGOSTEncryption
--- PASS: TestGOSTEncryption (0.03s)
=== RUN   TestRSAEncryption
--- PASS: TestRSAEncryption (0.12s)
PASS
```

### Бенчмарки
```
BenchmarkAESEncryption/1KB/CGO-8         1000           1234567 ns/op
BenchmarkAESEncryption/1KB/CLI-8          100           12345678 ns/op
```

### Тесты производительности
```
AES-256-CBC Performance Comparison:
  Data size: 1048576 bytes
  CGO method: 15.2ms (67.5 MB/s)
  CLI method: 125.3ms (8.2 MB/s)
  Speedup: 8.24x
  Improvement: 724.3%
```

## Требования

- Go 1.22+
- CGO_ENABLED=1
- OpenSSL (для CLI тестов)
- Доступ к файловой системе (для временных файлов)

## Примечания

1. **CLI тесты**: Некоторые тесты сравнивают производительность с вызовом OpenSSL через командную строку. Эти тесты требуют установленного OpenSSL.

2. **Временные файлы**: Бенчмарки создают временные файлы в `/tmp/`. Убедитесь, что у процесса есть права на запись.

3. **GOST тесты**: Тесты GOST могут быть пропущены, если GOST engine не доступен в OpenSSL.

4. **Производительность**: Результаты бенчмарков зависят от оборудования и нагрузки системы.

## Добавление новых тестов

### Unit-тест
```go
func TestNewFeature(t *testing.T) {
    // Подготовка
    // Выполнение
    // Проверка
}
```

### Бенчмарк
```go
func BenchmarkNewFeature(b *testing.B) {
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        // Тестируемый код
    }
}
```

### Тест производительности
```go
func TestPerformanceComparison(t *testing.T) {
    // Сравнение методов
    // Вывод результатов
}
``` 