package cgo

/*
#cgo CFLAGS: -I${SRCDIR}/../submodules/openssl/include -Wno-deprecated-declarations
#include "version.h"
*/
import "C"

func OpenSSLVersion() string {
	return C.GoString(C.go_openssl_version())
}
