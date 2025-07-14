package main

import (
	"fmt"
	"github.com/ZverLightYear/gopenssl/cgo"
)

func main() {
	fmt.Printf("START\n")

	plain := []byte("hello")
	key := []byte("0123456789abcdef")
	iv := []byte("1234567890abcdef")

	ci := cgo.New()

	cipher, err := ci.EncryptCBC(plain, key, iv)
	if err != nil {
		fmt.Printf("encrypt error: %v\n", err)
		return
	}
	fmt.Printf("cipher: %x\n", cipher)

	out, err := ci.DecryptCBC(cipher, key, iv)
	if err != nil {
		fmt.Printf("decrypt error: %v\n", err)
		return
	}
	fmt.Printf("plain: %s\n", out)
}
