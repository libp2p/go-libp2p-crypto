package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"

	pb "github.com/libp2p/go-libp2p-crypto/pb"

	"bytes"
	"github.com/minio/sha256-simd"
)

type RsaPrivateKey struct {
	sk *rsa.PrivateKey
	pk *rsa.PublicKey
}

type RsaPublicKey struct {
	k *rsa.PublicKey
}

func (pk *RsaPublicKey) Verify(data, sig []byte) (bool, error) {
	hashed := sha256.Sum256(data)
	err := rsa.VerifyPKCS1v15(pk.k, crypto.SHA256, hashed[:], sig)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (pk *RsaPublicKey) Type() pb.KeyType {
	return pb.KeyType_RSA
}

func (pk *RsaPublicKey) Bytes() ([]byte, error) {
	return MarshalPublicKey(pk)
}

func (pk *RsaPublicKey) Raw() ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pk.k)
}

func (pk *RsaPublicKey) Encrypt(b []byte) ([]byte, error) {
	partLen := pk.k.N.BitLen()/8 - 11
	chunks := split([]byte(b), partLen)
	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		bytes, err := rsa.EncryptPKCS1v15(rand.Reader, pk.k, chunk)
		if err != nil {
			return nil, err
		}
		buffer.Write(bytes)
	}
	return buffer.Bytes(), nil
}

// Equals checks whether this key is equal to another
func (pk *RsaPublicKey) Equals(k Key) bool {
	return KeyEqual(pk, k)
}

func (sk *RsaPrivateKey) Sign(message []byte) ([]byte, error) {
	hashed := sha256.Sum256(message)
	return rsa.SignPKCS1v15(rand.Reader, sk.sk, crypto.SHA256, hashed[:])
}

func (sk *RsaPrivateKey) GetPublic() PubKey {
	if sk.pk == nil {
		sk.pk = &sk.sk.PublicKey
	}
	return &RsaPublicKey{sk.pk}
}

func (sk *RsaPrivateKey) Decrypt(b []byte) ([]byte, error) {
	partLen := sk.pk.N.BitLen() / 8
	chunks := split([]byte(b), partLen)
	buffer := bytes.NewBufferString("")
	for _, chunk := range chunks {
		decrypted, err := rsa.DecryptPKCS1v15(rand.Reader, sk.sk, chunk)
		if err != nil {
			return nil, err
		}
		buffer.Write(decrypted)
	}
	return rsa.DecryptPKCS1v15(rand.Reader, sk.sk, b)
}

func (sk *RsaPrivateKey) Type() pb.KeyType {
	return pb.KeyType_RSA
}

func (sk *RsaPrivateKey) Bytes() ([]byte, error) {
	return MarshalPrivateKey(sk)
}

func (sk *RsaPrivateKey) Raw() ([]byte, error) {
	b := x509.MarshalPKCS1PrivateKey(sk.sk)
	return b, nil
}

// Equals checks whether this key is equal to another
func (sk *RsaPrivateKey) Equals(k Key) bool {
	return KeyEqual(sk, k)
}

func UnmarshalRsaPrivateKey(b []byte) (PrivKey, error) {
	sk, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return &RsaPrivateKey{sk: sk}, nil
}

func MarshalRsaPrivateKey(k *RsaPrivateKey) []byte {
	return x509.MarshalPKCS1PrivateKey(k.sk)
}

func UnmarshalRsaPublicKey(b []byte) (PubKey, error) {
	pub, err := x509.ParsePKIXPublicKey(b)
	if err != nil {
		return nil, err
	}
	pk, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("Not actually an rsa public key.")
	}
	return &RsaPublicKey{pk}, nil
}

func MarshalRsaPublicKey(k *RsaPublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(k.k)
}

func split(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}
