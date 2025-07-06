# Устранение проблем

## Ошибка "pkg-config: openssl not found"

Эта ошибка возникает, когда Go пытается найти OpenSSL через pkg-config, но не может его найти.

### Решение 1: Установить OpenSSL для Windows

1. Скачайте OpenSSL для Windows с https://slproweb.com/products/Win32OpenSSL.html
2. Установите в `C:\OpenSSL-Win64`
3. Добавьте `C:\OpenSSL-Win64\bin` в переменную PATH

### Решение 2: Использовать submodule (рекомендуется)

1. Убедитесь, что submodule инициализирован:
   ```bash
   git submodule update --init --recursive
   ```

2. Соберите OpenSSL из исходников:
   ```bash
   cd submodules/openssl
   ./Configure mingw64 --prefix=. --openssldir=.
   make
   cd ../..
   ```

### Решение 3: Отключить CGO (для тестирования)

Если вы хотите протестировать код без OpenSSL:

```bash
set CGO_ENABLED=0
go test ./...
```

## Ошибка "C compiler not found"

Установите MinGW-w64:
1. Скачайте с https://www.mingw-w64.org/downloads/
2. Установите в `C:\mingw-w64\mingw64\`
3. Добавьте `C:\mingw-w64\mingw64\bin` в переменную PATH

## Ошибка "openssl/configuration.h: No such file or directory"

OpenSSL не собран. Соберите его:

```bash
cd submodules/openssl
./Configure mingw64 --prefix=. --openssldir=.
make
cd ../..
```

## Проверка установки

После установки всех зависимостей:

```bash
# Проверка Go
go version

# Проверка C компилятора
gcc --version

# Проверка OpenSSL
openssl version

# Проверка CGO
echo $env:CGO_ENABLED

# Запуск тестов
go test -v ./tests/
```

## Частые проблемы

### Проблема: "executable file not found in %PATH%"
**Решение:** Добавьте путь к исполняемому файлу в переменную PATH.

### Проблема: "No such file or directory"
**Решение:** Убедитесь, что файлы существуют по указанному пути.

### Проблема: "build failed"
**Решение:** Проверьте, что все зависимости установлены и CGO включен.

## Получение помощи

Если проблема не решается:

1. Проверьте все зависимости: `powershell -ExecutionPolicy Bypass -File scripts/check_deps.ps1`
2. Убедитесь, что CGO включен: `set CGO_ENABLED=1`
3. Проверьте, что пути в PATH корректны
4. Попробуйте перезапустить терминал после изменения PATH 