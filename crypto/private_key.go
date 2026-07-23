// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"crypto/sha256"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const ecdsaCurveByteLength = 32

// EcdsaSignature is an ECDSA secp256k1 recoverable signature: R and S are
// each 32-byte big-endian values, and RecoveryId is the raw recovery id
// (0-3) needed to recover the signer's public key from (hash, signature).
// RecoveryId is not yet EIP-155 encoded — that only happens when a
// transaction is serialized.
type EcdsaSignature struct {
	R          []byte
	S          []byte
	RecoveryId int
}

func PrivateKeyFromPassphrase(passphrase string) (*PrivateKey, error) {
	hash := sha256.Sum256([]byte(passphrase))
	return PrivateKeyFromBytes(hash[:]), nil
}

func PrivateKeyFromHex(privateKeyHex string) (*PrivateKey, error) {
	return PrivateKeyFromBytes(HexDecode(privateKeyHex)), nil
}

func PrivateKeyFromBytes(bytes []byte) *PrivateKey {
	privateKey := secp256k1.PrivKeyFromBytes(bytes)
	return &PrivateKey{
		PrivateKey: privateKey,
		PublicKey: &PublicKey{
			PublicKey:    privateKey.PubKey(),
			isCompressed: true,
			Network:      GetNetwork(),
		},
	}
}

////////////////////////////////////////////////////////////////////////////////
// ADDRESS /////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func (privateKey *PrivateKey) ToHex() string {
	return HexEncode(privateKey.Serialize())
}

func (privateKey *PrivateKey) ToAddress() string {
	return privateKey.PublicKey.ToAddress()
}

func (privateKey *PrivateKey) ToWif() string {
	p := privateKey.Serialize()

	if privateKey.PublicKey.isCompressed {
		p = append(p, 0x1)
	}

	return base58.CheckEncode(p, privateKey.PublicKey.Network.Wif)
}

// //////////////////////////////////////////////////////////////////////////////
// CRYPTOGRAPHY ////////////////////////////////////////////////////////////////
// //////////////////////////////////////////////////////////////////////////////
func (privateKey *PrivateKey) Serialize() []byte {
	return privateKey.PrivateKey.Serialize()
}

// Sign produces a recoverable ECDSA signature over hash using RFC6979
// deterministic k and BIP0062 low-S normalization (both handled by
// ecdsa.SignCompact, which cannot fail for a valid key and hash).
func (privateKey *PrivateKey) Sign(hash []byte) *EcdsaSignature {
	compact := ecdsa.SignCompact(privateKey.PrivateKey, hash, privateKey.PublicKey.isCompressed)

	// compact = <27+recid(+4 if compressed)><32-byte R><32-byte S>
	header := compact[0]
	recoveryId := int((header - 27) &^ 4)

	return &EcdsaSignature{
		R:          compact[1 : 1+ecdsaCurveByteLength],
		S:          compact[1+ecdsaCurveByteLength : 1+2*ecdsaCurveByteLength],
		RecoveryId: recoveryId,
	}
}

// padCurveBytes left-pads b with zero bytes to ecdsaCurveByteLength. RLP
// encodes R/S as minimal big-endian integers, so a value decoded off the
// wire may be shorter than 32 bytes whenever its high-order byte happens to
// be zero; this restores the fixed-width form every other part of the
// signing code expects.
func padCurveBytes(b []byte) []byte {
	if len(b) >= ecdsaCurveByteLength {
		return b
	}
	padded := make([]byte, ecdsaCurveByteLength)
	copy(padded[ecdsaCurveByteLength-len(b):], b)
	return padded
}

// Bytes returns the 65-byte r‖s‖v encoding of sig, where v is 27+RecoveryId
// (Ethereum's "Electrum" convention).
func (sig *EcdsaSignature) Bytes() []byte {
	b := make([]byte, 0, 2*ecdsaCurveByteLength+1)
	b = append(b, padCurveBytes(sig.R)...)
	b = append(b, padCurveBytes(sig.S)...)
	b = append(b, byte(27+sig.RecoveryId))
	return b
}

// EcdsaSignatureFromBytes parses the 65-byte r‖s‖v encoding produced by
// EcdsaSignature.Bytes.
func EcdsaSignatureFromBytes(b []byte) (*EcdsaSignature, error) {
	if len(b) != 2*ecdsaCurveByteLength+1 {
		return nil, fmt.Errorf("EcdsaSignatureFromBytes: expected %d bytes, got %d", 2*ecdsaCurveByteLength+1, len(b))
	}

	v := b[2*ecdsaCurveByteLength]
	if v < 27 || v > 30 {
		return nil, fmt.Errorf("EcdsaSignatureFromBytes: invalid v byte %d", v)
	}

	return &EcdsaSignature{
		R:          append([]byte{}, b[:ecdsaCurveByteLength]...),
		S:          append([]byte{}, b[ecdsaCurveByteLength:2*ecdsaCurveByteLength]...),
		RecoveryId: int(v) - 27,
	}, nil
}
