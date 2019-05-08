package testutil

import (
	ci "github.com/libp2p/go-libp2p-crypto"
	"github.com/libp2p/go-libp2p-testing/crypto"
)

func RandTestKeyPair(typ, bits int) (ci.PrivKey, ci.PubKey, error) {
	return tcrypto.RandTestKeyPair(typ, bits)
}

func SeededTestKeyPair(typ, bits int, seed int64) (ci.PrivKey, ci.PubKey, error) {
	return tcrypto.SeededTestKeyPair(typ, bits, seed)
}
