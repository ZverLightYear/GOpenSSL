// Package gopenssl предоставляет Go интерфейсы для OpenSSL криптографических функций
package gopenssl

import (
	"crypto/rand"
	"fmt"

	"gopenssl/cgo"
)

// Инициализация OpenSSL при импорте пакета
func init() {
	cgo.InitOpenSSL()
}

// Cleanup освобождает ресурсы OpenSSL
func Cleanup() {
	cgo.CleanupOpenSSL()
}

// ===== AES ШИФРОВАНИЕ =====

// AES представляет AES шифратор
type AES struct {
	aes *cgo.AES
}

// NewAES создает новый AES шифратор
func NewAES(keySize, mode string) (*AES, error) {
	aes, err := cgo.NewAES(keySize, mode)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	return &AES{aes: aes}, nil
}

// BlockSize возвращает размер блока
func (a *AES) BlockSize() int {
	return a.aes.BlockSize()
}

// KeySize возвращает размер ключа
func (a *AES) KeySize() int {
	return a.aes.KeySize()
}

// IVSize возвращает размер IV
func (a *AES) IVSize() int {
	return a.aes.IVSize()
}

// Encrypt шифрует данные
func (a *AES) Encrypt(plaintext, key, iv []byte) ([]byte, error) {
	return a.aes.Encrypt(plaintext, key, iv)
}

// Decrypt расшифровывает данные
func (a *AES) Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	return a.aes.Decrypt(ciphertext, key, iv)
}

// Free освобождает ресурсы AES шифратора
func (a *AES) Free() {
	if a.aes != nil {
		a.aes.Free()
		a.aes = nil
	}
}

// ===== GOST ШИФРОВАНИЕ =====

// GOST представляет GOST шифратор
type GOST struct {
	gost *cgo.GOST
}

// NewGOST создает новый GOST шифратор
func NewGOST(mode string) (*GOST, error) {
	gost, err := cgo.NewGOST(mode)
	if err != nil {
		return nil, fmt.Errorf("failed to create GOST cipher: %w", err)
	}

	return &GOST{gost: gost}, nil
}

// BlockSize возвращает размер блока
func (g *GOST) BlockSize() int {
	return g.gost.BlockSize()
}

// KeySize возвращает размер ключа
func (g *GOST) KeySize() int {
	return g.gost.KeySize()
}

// IVSize возвращает размер IV
func (g *GOST) IVSize() int {
	return g.gost.IVSize()
}

// Encrypt шифрует данные
func (g *GOST) Encrypt(plaintext, key, iv []byte) ([]byte, error) {
	return g.gost.Encrypt(plaintext, key, iv)
}

// Decrypt расшифровывает данные
func (g *GOST) Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	return g.gost.Decrypt(ciphertext, key, iv)
}

// Free освобождает ресурсы GOST шифратора
func (g *GOST) Free() {
	if g.gost != nil {
		g.gost.Free()
		g.gost = nil
	}
}

// ===== RSA =====

// RSA представляет RSA криптографию
type RSA struct {
	rsa *cgo.RSA
}

// NewRSA создает новый RSA объект
func NewRSA() *RSA {
	return &RSA{rsa: cgo.NewRSA()}
}

// GenerateKey генерирует новую пару RSA ключей
func (r *RSA) GenerateKey(bits int) error {
	return r.rsa.GenerateKey(bits)
}

// LoadPrivateKey загружает приватный ключ из файла
func (r *RSA) LoadPrivateKey(filename string) error {
	return r.rsa.LoadPrivateKey(filename)
}

// LoadPublicKey загружает публичный ключ из файла
func (r *RSA) LoadPublicKey(filename string) error {
	return r.rsa.LoadPublicKey(filename)
}

// SavePrivateKey сохраняет приватный ключ в файл
func (r *RSA) SavePrivateKey(filename string) error {
	return r.rsa.SavePrivateKey(filename)
}

// SavePublicKey сохраняет публичный ключ в файл
func (r *RSA) SavePublicKey(filename string) error {
	return r.rsa.SavePublicKey(filename)
}

// Size возвращает размер RSA ключа в байтах
func (r *RSA) Size() int {
	return r.rsa.Size()
}

// BlockSize возвращает размер блока RSA
func (r *RSA) BlockSize() int {
	return r.rsa.BlockSize()
}

// Encrypt шифрует данные
func (r *RSA) Encrypt(plaintext []byte, padding int) ([]byte, error) {
	return r.rsa.Encrypt(plaintext, padding)
}

// Decrypt расшифровывает данные
func (r *RSA) Decrypt(ciphertext []byte, padding int) ([]byte, error) {
	return r.rsa.Decrypt(ciphertext, padding)
}

// Sign подписывает данные
func (r *RSA) Sign(data []byte, hashAlgorithm string) ([]byte, error) {
	return r.rsa.Sign(data, hashAlgorithm)
}

// Verify проверяет подпись
func (r *RSA) Verify(data, signature []byte, hashAlgorithm string) error {
	return r.rsa.Verify(data, signature, hashAlgorithm)
}

// Free освобождает ресурсы RSA
func (r *RSA) Free() {
	if r.rsa != nil {
		r.rsa.Free()
		r.rsa = nil
	}
}

// ===== УТИЛИТЫ =====

// GenerateRandomBytes генерирует случайные байты
func GenerateRandomBytes(length int) ([]byte, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	return bytes, err
}

// Константы для AES
const (
	AES128 = cgo.AES128
	AES192 = cgo.AES192
	AES256 = cgo.AES256
)

// Константы для режимов AES
const (
	AESECB = cgo.AESECB
	AESCBC = cgo.AESCBC
	AESCFB = cgo.AESCFB
	AESOFB = cgo.AESOFB
	AESCTR = cgo.AESCTR
	AESGCM = cgo.AESGCM
	AESXTS = cgo.AESXTS
	AESCCM = cgo.AESCCM
	AESOCB = cgo.AESOCB
)

// Константы для GOST
const (
	GOSTCFB   = cgo.GOSTCFB
	GOSTCBC   = cgo.GOSTCBC
	GOSTCTR   = cgo.GOSTCTR
	GOSTCTR12 = cgo.GOSTCTR12
)

// Константы для RSA
const (
	RSA_PKCS1_PADDING      = cgo.RSA_PKCS1_PADDING
	RSA_PKCS1_OAEP_PADDING = cgo.RSA_PKCS1_OAEP_PADDING
	RSA_PKCS1_PSS_PADDING  = cgo.RSA_PKCS1_PSS_PADDING
	RSA_NO_PADDING         = cgo.RSA_NO_PADDING
)
