package tests

import (
	gopenssl "gopenssl/cgo"
	"strings"
	"testing"
)

func TestOpenSSLVersion(t *testing.T) {
	ver := gopenssl.OpenSSLVersion()
	if ver == "" {
		t.Fatal("OpenSSL version is empty")
	}
	t.Logf("OpenSSL version: %s", ver)
}

func TestListCiphers(t *testing.T) {
	ciphers := gopenssl.ListCiphers()
	if len(ciphers) == 0 {
		t.Fatal("No ciphers found")
	}
	for _, c := range ciphers {
		t.Logf("Cipher: %s", c)
	}
}

func TestCipherGOSTPresent(t *testing.T) {
	ciphers := gopenssl.ListCiphers()
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
