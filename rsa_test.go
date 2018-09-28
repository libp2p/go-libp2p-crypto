package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestTestBasicEncryptAndDecrypt(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		t.Fatal(err)
	}
	pk := &priv.PublicKey
	rsaPrivateKey := &RsaPrivateKey{sk: priv, pk: pk}
	rsaPublicKey := &RsaPublicKey{pk}

	data := []byte("hello! and welcome to some awesome crypto primitives")

	encry, err := rsaPublicKey.Encrypt(data)
	if err != nil {
		t.Fatal(err)
	}
	decry, err := rsaPrivateKey.Decrypt(encry)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(decry) {
		t.Fatal("decrypt result didn`t match")
	}
}
