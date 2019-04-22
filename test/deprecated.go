package testutil

import (
	"github.com/libp2p/go-libp2p-core/crypto/test"
	ci "github.com/libp2p/go-libp2p-crypto"
)

func RandTestKeyPair(typ, bits int) (ci.PrivKey, ci.PubKey, error) {
	return test.RandTestKeyPair(typ, bits)
}

func SeededTestKeyPair(typ, bits int, seed int64) (ci.PrivKey, ci.PubKey, error) {
	return test.SeededTestKeyPair(typ, bits, seed)
}
