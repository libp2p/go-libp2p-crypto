package crypto_pb

import core "github.com/libp2p/go-libp2p-core/crypto/pb"

const (
	KeyType_RSA       = core.KeyType_RSA
	KeyType_Ed25519   = core.KeyType_Ed25519
	KeyType_Secp256k1 = core.KeyType_Secp256k1
	KeyType_ECDSA     = core.KeyType_ECDSA
)

var (
	ErrInvalidLengthCrypto = core.ErrInvalidLengthCrypto
	ErrIntOverflowCrypto   = core.ErrIntOverflowCrypto
)

var KeyType_name = core.KeyType_name

var KeyType_value = core.KeyType_value

type KeyType = core.KeyType

type PublicKey = core.PublicKey

type PrivateKey = core.PrivateKey
