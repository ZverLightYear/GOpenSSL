package tests

import (
	"gopenssl/crypto"
	"gopenssl/crypto/openssl"
)

// getProvider возвращает глобальный синглтон провайдера
func getProvider() crypto.CryptoProvider {
	return openssl.GetProvider()
}
