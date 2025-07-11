package tests

import (
	"gopenssl"
)

// getProvider возвращает глобальный синглтон провайдера
func getProvider() gopenssl.CryptoProvider {
	return gopenssl.GetProvider()
}
