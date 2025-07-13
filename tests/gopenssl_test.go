package tests

import (
	"gopenssl/cgo"
	cgo_evp "gopenssl/cgo/evp"
	"strings"
	"testing"
)

func TestOpenSSLVersion(t *testing.T) {
	ver := cgo.OpenSSLVersion()
	if ver == "" {
		t.Fatal("OpenSSL version is empty")
	}
	t.Logf("OpenSSL version: %s", ver)
}

func TestListCiphers(t *testing.T) {
	ciphers := cgo_evp.ListCiphers()
	if len(ciphers) == 0 {
		t.Fatal("No ciphers found")
	}
	for _, c := range ciphers {
		t.Logf("Cipher: %s", c)
	}
}

func TestCipherGOSTPresent(t *testing.T) {
	ciphers := cgo_evp.ListCiphers()
	found := false
	for _, c := range ciphers {
		if strings.Contains(strings.ToUpper(c), "GOST") {
			found = true
			t.Logf("Found GOST cipher: %s", c)
		}
	}
	if !found {
		t.Fatal("No GOST cipher found in EVP ciphers list")
	}
}
