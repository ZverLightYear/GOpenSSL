module gopenssl

go 1.22

// GOpenSSL - Go библиотека для криптографических операций
// основанная на исходном коде OpenSSL
//
// Основные возможности:
// - AES шифрование (CBC, CFB, CTR, GCM, XTS режимы)
// - GOST шифрование (CFB, CBC, CTR режимы)
// - RSA шифрование и подписи
// - Grasshopper шифрование
// - SHA, MD, GOST хэширование
//
// Требования для сборки:
// - CGO_ENABLED=1
// - OpenSSL исходный код
// - C компилятор (GCC/Clang)
