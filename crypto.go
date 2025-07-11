package gopenssl

import (
	"gopenssl/internal/common"
	"gopenssl/internal/providers"
)

// GetProvider возвращает глобальный синглтон провайдера
func GetProvider() common.CryptoProvider {
	return providers.GetProvider()
}

// NewProvider создает новый провайдер
func NewProvider() common.CryptoProvider {
	return providers.NewProvider()
}

// Re-export common types for backward compatibility
type CipherMode = common.CipherMode
type CipherAlgorithm = common.CipherAlgorithm
type HashAlgorithm = common.HashAlgorithm
type Cipher = common.Cipher
type CipherStream = common.CipherStream
type Hasher = common.Hasher
type MAC = common.MAC
type CipherFactory = common.CipherFactory
type HashFactory = common.HashFactory
type CryptoProvider = common.CryptoProvider

// Re-export constants for backward compatibility
const (
	ModeECB = common.ModeECB
	ModeCBC = common.ModeCBC
	ModeCFB = common.ModeCFB
	ModeOFB = common.ModeOFB
	ModeCTR = common.ModeCTR
	ModeGCM = common.ModeGCM
	ModeCCM = common.ModeCCM
	ModeXTS = common.ModeXTS

	AES         = common.AES
	GOST        = common.GOST
	GrassHopper = common.GrassHopper

	SHA1      = common.SHA1
	SHA224    = common.SHA224
	SHA256    = common.SHA256
	SHA384    = common.SHA384
	SHA512    = common.SHA512
	MD5       = common.MD5
	MD4       = common.MD4
	GOST34_11 = common.GOST34_11
)
