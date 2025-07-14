package cgo

/*
#cgo CFLAGS: -Isrc/include
#cgo CFLAGS: -I${SRCDIR}/../submodules/openssl/include
#cgo LDFLAGS: /Users/sergey.zverev/Projects/own/GOpenSSL/build/libminicrypto.a
#include "pkcs7.h"
*/
import "C"
import (
	"errors"
	"unsafe"
)

func pkcs7PadOpenSSL(src []byte, block int) []byte {
	paddedLen := int(C.pkcs7_pad_len(C.size_t(len(src)), C.int(block)))
	out := make([]byte, paddedLen)
	copy(out, src)
	C.pkcs7_pad((*C.uint8_t)(unsafe.Pointer(&out[0])), C.size_t(len(src)), C.int(block))
	return out
}

func pkcs7UnpadOpenSSL(src []byte, block int) ([]byte, error) {
	var outLen C.int
	rc := C.pkcs7_unpad(
		(*C.uint8_t)(unsafe.Pointer(&src[0])),
		C.size_t(len(src)),
		&outLen,
	)
	if rc != 0 {
		return nil, errors.New("invalid PKCS7 padding")
	}
	return src[:outLen], nil
}
