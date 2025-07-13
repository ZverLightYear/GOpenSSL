package cgo_evp

/*
#cgo CFLAGS: -I${SRCDIR}/../submodules/openssl/include -Wno-deprecated-declarations
#include "base.h"
*/
import "C"
import "unsafe"

// ListCiphers возвращает список доступных шифров
func ListCiphers() []string {
	const max = 256
	var arr [max]*C.char
	n := C.go_list_ciphers((**C.char)(unsafe.Pointer(&arr[0])), C.int(max))
	out := make([]string, 0, int(n))
	for i := 0; i < int(n); i++ {
		if arr[i] != nil {
			out = append(out, C.GoString(arr[i]))
			C.free(unsafe.Pointer(arr[i]))
		}
	}
	return out
}

// ListHashes возвращает список доступных хэш-алгоритмов
func ListHashes() []string {
	const max = 256
	var arr [max]*C.char
	n := C.go_list_hashes((**C.char)(unsafe.Pointer(&arr[0])), C.int(max))
	out := make([]string, 0, int(n))
	for i := 0; i < int(n); i++ {
		if arr[i] != nil {
			out = append(out, C.GoString(arr[i]))
			C.free(unsafe.Pointer(arr[i]))
		}
	}
	return out
}
