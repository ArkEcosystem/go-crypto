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
	"math/big"

	"github.com/btcsuite/btcd/btcec"
	b58 "github.com/btcsuite/btcutil/base58"
	"github.com/hbakhtiyor/schnorr"
)

func PrivateKeyFromPassphrase(passphrase string) (*PrivateKey, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(passphrase))

	if err != nil {
		return nil, err
	}

	return PrivateKeyFromBytes(hash.Sum(nil)), nil
}

func PrivateKeyFromHex(privateKeyHex string) (*PrivateKey, error) {
	return PrivateKeyFromBytes(HexDecode(privateKeyHex)), nil
}

func PrivateKeyFromBytes(bytes []byte) *PrivateKey {
	privateKey, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), bytes)

	return &PrivateKey{
		PrivateKey: privateKey,
		PublicKey: &PublicKey{
			PublicKey:    publicKey,
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

	return b58.CheckEncode(p, privateKey.PublicKey.Network.Wif)
}

////////////////////////////////////////////////////////////////////////////////
// CRYPTOGRAPHY ////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func (privateKey *PrivateKey) SignECDSA(hash []byte) ([]byte, error) {
	signed, err := privateKey.PrivateKey.Sign(hash)

	if err != nil {
		return nil, err
	}

	return signed.Serialize(), nil
}

func (privateKey *PrivateKey) SignSchnorr(hash []byte) ([]byte, error) {
	if len(hash) != 32 {
		return nil, fmt.Errorf("SignSchnorr: message hash is %d bytes, should be 32", len(hash))
	}

	privKeyInt := new(big.Int).SetBytes(privateKey.PrivateKey.Serialize())

	var hashArr [32]byte
	copy(hashArr[:], hash)

	signed, err := schnorr.Sign(privKeyInt, hashArr)

	if err != nil {
		return nil, err
	}

	return signed[:], nil
}

func (privateKey *PrivateKey) Sign(hash []byte) ([]byte, error) {
	switch CONFIG_SIGNATURE_TYPE {
	case SIGNATURE_TYPE_ECDSA:
		return privateKey.SignECDSA(hash)
	case SIGNATURE_TYPE_SCHNORR:
		return privateKey.SignSchnorr(hash)
	}

	return nil, fmt.Errorf("Sign: unknown signature type configured: %d", CONFIG_SIGNATURE_TYPE)
}
