# Скрипт для установки OpenSSL на Windows
# Автоматически скачивает и устанавливает OpenSSL

param(
    [string]$Version = "3.2.4",
    [string]$Architecture = "x64",
    [string]$InstallPath = "C:\OpenSSL-Win64"
)

Write-Host "Установка OpenSSL $Version для Windows..." -ForegroundColor Green

# URL для скачивания OpenSSL
$OpenSSLUrl = "https://github.com/openssl/openssl/releases/download/openssl-$Version/Win64OpenSSL-$Version.exe"

# Временная директория для скачивания
$TempDir = "$env:TEMP\openssl_install"
$InstallerPath = "$TempDir\Win64OpenSSL-$Version.exe"

# Создаем временную директорию
if (!(Test-Path $TempDir)) {
    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
}

Write-Host "Скачивание OpenSSL..." -ForegroundColor Yellow
try {
    Invoke-WebRequest -Uri $OpenSSLUrl -OutFile $InstallerPath
} catch {
    Write-Host "Ошибка при скачивании OpenSSL: $_" -ForegroundColor Red
    exit 1
}

Write-Host "Установка OpenSSL..." -ForegroundColor Yellow
try {
    # Запускаем установщик в тихом режиме
    Start-Process -FilePath $InstallerPath -ArgumentList "/S", "/D=$InstallPath" -Wait
} catch {
    Write-Host "Ошибка при установке OpenSSL: $_" -ForegroundColor Red
    exit 1
}

# Проверяем, что OpenSSL установлен
$OpenSSLExe = "$InstallPath\bin\openssl.exe"
if (Test-Path $OpenSSLExe) {
    Write-Host "OpenSSL успешно установлен в $InstallPath" -ForegroundColor Green
    
    # Добавляем путь к OpenSSL в переменную окружения PATH
    $CurrentPath = [Environment]::GetEnvironmentVariable("PATH", "Machine")
    $OpenSSLBinPath = "$InstallPath\bin"
    
    if ($CurrentPath -notlike "*$OpenSSLBinPath*") {
        $NewPath = "$CurrentPath;$OpenSSLBinPath"
        [Environment]::SetEnvironmentVariable("PATH", $NewPath, "Machine")
        Write-Host "Путь к OpenSSL добавлен в переменную PATH" -ForegroundColor Green
    }
    
    # Показываем версию OpenSSL
    $VersionOutput = & $OpenSSLExe version
    Write-Host "Установленная версия OpenSSL: $VersionOutput" -ForegroundColor Green
    
} else {
    Write-Host "Ошибка: OpenSSL не найден после установки" -ForegroundColor Red
    exit 1
}

# Очищаем временные файлы
if (Test-Path $TempDir) {
    Remove-Item -Path $TempDir -Recurse -Force
}

Write-Host "Установка завершена!" -ForegroundColor Green
Write-Host "Теперь вы можете использовать OpenSSL в вашем проекте." -ForegroundColor Cyan 