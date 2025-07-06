//go:build !cgo
// +build !cgo

package cgo

import "fmt"

// InitOpenSSL инициализирует OpenSSL (заглушка для !cgo)
func InitOpenSSL() {
	// Заглушка для случаев когда CGO не включен
}

// CleanupOpenSSL очищает ресурсы OpenSSL (заглушка для !cgo)
func CleanupOpenSSL() {
	// Заглушка для случаев когда CGO не включен
}

// GetOpenSSLError возвращает ошибку OpenSSL (заглушка для !cgo)
func GetOpenSSLError() string {
	return "OpenSSL not available (CGO disabled)"
}

// Константы для размеров блоков
const (
	AESBlockSize         = 16
	GOSTBlockSize        = 8
	GrasshopperBlockSize = 16
)

// CipherContext представляет контекст шифрования
type CipherContext struct{}

// HashContext представляет контекст хэширования
type HashContext struct{}

// NewCipherContext создает новый контекст шифрования
func NewCipherContext() *CipherContext {
	return &CipherContext{}
}

// Free освобождает контекст шифрования
func (c *CipherContext) Free() {
	// Заглушка для случаев когда CGO не включен
}

// NewHashContext создает новый контекст хэширования
func NewHashContext() *HashContext {
	return &HashContext{}
}

// Free освобождает контекст хэширования
func (h *HashContext) Free() {
	// Заглушка для случаев когда CGO не включен
}

// OpenSSLError представляет ошибку OpenSSL
type OpenSSLError struct {
	Message string
}

func (e *OpenSSLError) Error() string {
	return fmt.Sprintf("OpenSSL error: %s", e.Message)
}

// AES представляет AES шифратор
type AES struct {
	ctx        *CipherContext
	cipherName string
}

// NewAES создает новый AES шифратор
func NewAES(keySize, mode string) (*AES, error) {
	return nil, fmt.Errorf("AES not available (CGO disabled)")
}

// Free освобождает ресурсы AES шифратора
func (a *AES) Free() {
	// Заглушка для случаев когда CGO не включен
}

// BlockSize возвращает размер блока
func (a *AES) BlockSize() int {
	return 0
}

// KeySize возвращает размер ключа
func (a *AES) KeySize() int {
	return 0
}

// IVSize возвращает размер IV
func (a *AES) IVSize() int {
	return 0
}

// Encrypt шифрует данные
func (a *AES) Encrypt(plaintext, key, iv []byte) ([]byte, error) {
	return nil, fmt.Errorf("AES encryption not available (CGO disabled)")
}

// Decrypt расшифровывает данные
func (a *AES) Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	return nil, fmt.Errorf("AES decryption not available (CGO disabled)")
}

// GOST представляет GOST шифратор
type GOST struct {
	ctx        *CipherContext
	cipherName string
}

// NewGOST создает новый GOST шифратор
func NewGOST(mode string) (*GOST, error) {
	return nil, fmt.Errorf("GOST not available (CGO disabled)")
}

// Free освобождает ресурсы GOST шифратора
func (g *GOST) Free() {
	// Заглушка для случаев когда CGO не включен
}

// BlockSize возвращает размер блока
func (g *GOST) BlockSize() int {
	return 0
}

// KeySize возвращает размер ключа
func (g *GOST) KeySize() int {
	return 0
}

// IVSize возвращает размер IV
func (g *GOST) IVSize() int {
	return 0
}

// Encrypt шифрует данные
func (g *GOST) Encrypt(plaintext, key, iv []byte) ([]byte, error) {
	return nil, fmt.Errorf("GOST encryption not available (CGO disabled)")
}

// Decrypt расшифровывает данные
func (g *GOST) Decrypt(ciphertext, key, iv []byte) ([]byte, error) {
	return nil, fmt.Errorf("GOST decryption not available (CGO disabled)")
}

// Hash представляет хэшер
type Hash struct {
	ctx      *HashContext
	hashName string
}

// NewHash создает новый хэшер
func NewHash(algorithm string) (*Hash, error) {
	return nil, fmt.Errorf("Hash not available (CGO disabled)")
}

// Free освобождает ресурсы хэшера
func (h *Hash) Free() {
	// Заглушка для случаев когда CGO не включен
}

// Size возвращает размер хэша в байтах
func (h *Hash) Size() int {
	return 0
}

// Sum вычисляет хэш от данных
func (h *Hash) Sum(data []byte) ([]byte, error) {
	return nil, fmt.Errorf("Hash not available (CGO disabled)")
}

// RSA представляет RSA криптографию
type RSA struct {
	rsa interface{}
}

// NewRSA создает новый RSA объект
func NewRSA() *RSA {
	return &RSA{}
}

// GenerateKey генерирует новую пару RSA ключей
func (r *RSA) GenerateKey(bits int) error {
	return fmt.Errorf("RSA not available (CGO disabled)")
}

// LoadPrivateKey загружает приватный ключ из файла
func (r *RSA) LoadPrivateKey(filename string) error {
	return fmt.Errorf("RSA not available (CGO disabled)")
}

// LoadPublicKey загружает публичный ключ из файла
func (r *RSA) LoadPublicKey(filename string) error {
	return fmt.Errorf("RSA not available (CGO disabled)")
}

// SavePrivateKey сохраняет приватный ключ в файл
func (r *RSA) SavePrivateKey(filename string) error {
	return fmt.Errorf("RSA not available (CGO disabled)")
}

// SavePublicKey сохраняет публичный ключ в файл
func (r *RSA) SavePublicKey(filename string) error {
	return fmt.Errorf("RSA not available (CGO disabled)")
}

// Size возвращает размер RSA ключа в байтах
func (r *RSA) Size() int {
	return 0
}

// BlockSize возвращает размер блока RSA
func (r *RSA) BlockSize() int {
	return 0
}

// Encrypt шифрует данные
func (r *RSA) Encrypt(plaintext []byte, padding int) ([]byte, error) {
	return nil, fmt.Errorf("RSA not available (CGO disabled)")
}

// Decrypt расшифровывает данные
func (r *RSA) Decrypt(ciphertext []byte, padding int) ([]byte, error) {
	return nil, fmt.Errorf("RSA not available (CGO disabled)")
}

// Sign подписывает данные
func (r *RSA) Sign(data []byte, hashAlgorithm string) ([]byte, error) {
	return nil, fmt.Errorf("RSA not available (CGO disabled)")
}

// Verify проверяет подпись
func (r *RSA) Verify(data, signature []byte, hashAlgorithm string) error {
	return fmt.Errorf("RSA not available (CGO disabled)")
}

// Free освобождает ресурсы RSA
func (r *RSA) Free() {
	// Заглушка для случаев когда CGO не включен
}

// Константы для AES
const (
	AES128 = "aes-128"
	AES192 = "aes-192"
	AES256 = "aes-256"
)

// Константы для режимов AES
const (
	AESECB = "ecb"
	AESCBC = "cbc"
	AESCFB = "cfb"
	AESOFB = "ofb"
	AESCTR = "ctr"
	AESGCM = "gcm"
	AESXTS = "xts"
	AESCCM = "ccm"
	AESOCB = "ocb"
)

// Константы для GOST
const (
	GOSTCFB   = "gost89"
	GOSTCBC   = "gost89-cbc"
	GOSTCTR   = "gost89-cnt"
	GOSTCTR12 = "gost89-cnt-12"
)

// Константы для хэширования
const (
	SHA1             = "sha1"
	SHA224           = "sha224"
	SHA256           = "sha256"
	SHA384           = "sha384"
	SHA512           = "sha512"
	SHA3_224         = "sha3-224"
	SHA3_256         = "sha3-256"
	SHA3_384         = "sha3-384"
	SHA3_512         = "sha3-512"
	MD4              = "md4"
	MD5              = "md5"
	GOSTR341194      = "gostr341194"
	GOSTR34112012256 = "gostr34112012256"
	GOSTR34112012512 = "gostr34112012512"
)

// Константы для RSA
const (
	RSA_PKCS1_PADDING      = 1
	RSA_PKCS1_OAEP_PADDING = 4
	RSA_PKCS1_PSS_PADDING  = 6
	RSA_NO_PADDING         = 3
)
