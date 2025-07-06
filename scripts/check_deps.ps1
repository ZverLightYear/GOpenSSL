# Скрипт для проверки зависимостей GOpenSSL

Write-Host "Проверка зависимостей для GOpenSSL..." -ForegroundColor Green

$errors = @()

# Проверка Go
Write-Host "Проверка Go..." -ForegroundColor Yellow
try {
    $goVersion = go version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Go найден: $goVersion" -ForegroundColor Green
    } else {
        $errors += "Go не найден. Установите Go с https://golang.org/dl/"
    }
} catch {
    $errors += "Go не найден. Установите Go с https://golang.org/dl/"
}

# Проверка C компилятора
Write-Host "Проверка C компилятора..." -ForegroundColor Yellow
try {
    $gccVersion = gcc --version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ GCC найден: $($gccVersion[0])" -ForegroundColor Green
    } else {
        $errors += "GCC не найден. Установите MinGW-w64 с https://www.mingw-w64.org/downloads/"
    }
} catch {
    $errors += "GCC не найден. Установите MinGW-w64 с https://www.mingw-w64.org/downloads/"
}

# Проверка OpenSSL
Write-Host "Проверка OpenSSL..." -ForegroundColor Yellow
try {
    $opensslVersion = openssl version 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ OpenSSL найден: $opensslVersion" -ForegroundColor Green
    } else {
        $errors += "OpenSSL не найден. Запустите: make install-openssl-windows"
    }
} catch {
    $errors += "OpenSSL не найден. Запустите: make install-openssl-windows"
}

# Проверка CGO
Write-Host "Проверка CGO..." -ForegroundColor Yellow
$cgoEnabled = $env:CGO_ENABLED
if ($cgoEnabled -eq "1") {
    Write-Host "✓ CGO включен" -ForegroundColor Green
} else {
    Write-Host "⚠ CGO отключен. Установите: set CGO_ENABLED=1" -ForegroundColor Yellow
}

# Проверка git submodules
Write-Host "Проверка git submodules..." -ForegroundColor Yellow
if (Test-Path "submodules/openssl") {
    Write-Host "✓ OpenSSL submodule найден" -ForegroundColor Green
} else {
    Write-Host "⚠ OpenSSL submodule не найден. Запустите: git submodule update --init --recursive" -ForegroundColor Yellow
}

# Вывод результатов
Write-Host ""
if ($errors.Count -eq 0) {
    Write-Host "✓ Все зависимости установлены!" -ForegroundColor Green
    Write-Host "Можете запускать: make build" -ForegroundColor Cyan
} else {
    Write-Host "✗ Найдены проблемы:" -ForegroundColor Red
    foreach ($err in $errors) {
        Write-Host "  - $err" -ForegroundColor Red
    }
    Write-Host ""
    Write-Host "Для установки OpenSSL запустите:" -ForegroundColor Cyan
    Write-Host "  make install-openssl-windows" -ForegroundColor White
} 