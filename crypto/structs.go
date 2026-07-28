package crypto

import (
	"math/big"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	blst "github.com/supranational/blst/bindings/go"
)

type Network struct {
	Epoch   time.Time
	ChainId int
	Wif     byte
}

type PrivateKey struct {
	*secp256k1.PrivateKey
	PublicKey *PublicKey
}

type PublicKey struct {
	*secp256k1.PublicKey
	isCompressed bool
	Network      *Network
}

// Transaction is a Mainsail (EVM-compatible) transaction: an RLP-encoded
// envelope authenticated with a recoverable ECDSA secp256k1 signature.
// Nonce/GasPrice/GasLimit/Value are arbitrary-precision to accommodate
// wei-scale amounts. R and S are each 32 bytes; V is the raw recovery id
// (0-3), not yet EIP-155 encoded — that encoding is applied at serialize
// time using the configured network's chain id.
type Transaction struct {
	Nonce           *big.Int `json:"nonce,omitempty"`
	GasPrice        *big.Int `json:"gasPrice,omitempty"`
	GasLimit        *big.Int `json:"gasLimit,omitempty"`
	To              string   `json:"to,omitempty"`
	Value           *big.Int `json:"value,omitempty"`
	Data            []byte   `json:"data,omitempty"`
	V               int      `json:"v"`
	R               []byte   `json:"r,omitempty"`
	S               []byte   `json:"s,omitempty"`
	SenderPublicKey string   `json:"senderPublicKey,omitempty"`
	From            string   `json:"from,omitempty"`
	Hash            string   `json:"hash,omitempty"`
	Serialized      []byte   `json:"serialized,omitempty"`

	// The fields below are populated only for the transaction kind they
	// apply to, by DecodeTransactionArgs during deserialization; all others
	// are left at their zero value.
	Vote               string     `json:"vote,omitempty"`
	ValidatorPublicKey string     `json:"validatorPublicKey,omitempty"`
	ValidatorProof     string     `json:"validatorProof,omitempty"`
	Username           string     `json:"username,omitempty"`
	PaymentAddresses   []string   `json:"paymentAddresses,omitempty"`
	PaymentAmounts     []*big.Int `json:"paymentAmounts,omitempty"`
}

type Message struct {
	Message   string `json:"message"`
	PublicKey string `json:"publickey"`
	Signature string `json:"signature"`
}

type BLSPrivateKey struct {
	PrivateKey *blst.SecretKey
}

type BLSPublicKey struct {
	PublicKey *blst.P1Affine
}
