package gopenssl_test

import (
	gopenssl "gopenssl/cgo"
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
