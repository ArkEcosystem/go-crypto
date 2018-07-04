// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package arkecosystem_crypto

import (
	"crypto/sha256"
	"github.com/ArkEcosystem/go-crypto/crypto/base58"
	"github.com/btcsuite/btcd/btcec"
)

func PrivateKeyFromSecret(secret string) (*PrivateKey, error) {
	hash := sha256.New()
	_, err := hash.Write([]byte(secret))

	if err != nil {
		return nil, err
	}

	return PrivateKeyFromBytes(hash.Sum(nil)), nil
}

func PrivateKeyFromBytes(bytes []byte) *PrivateKey {
	privateKey, publicKey := btcec.PrivKeyFromBytes(btcec.S256(), bytes)

	return &PrivateKey{
		PrivateKey: privateKey,
		PublicKey: &PublicKey{
			PublicKey:    publicKey,
			isCompressed: true,
			network:      GetNetwork(),
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

	p = append(p, 0x0)
	copy(p[1:], p[:len(p)-1])
	p[0] = privateKey.PublicKey.network.Wif

	return base58.Encode(p)
}

////////////////////////////////////////////////////////////////////////////////
// CRYPTOGRAPHY ////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func (privateKey *PrivateKey) Sign(hash []byte) ([]byte, error) {
	signed, err := privateKey.PrivateKey.Sign(hash)

	if err != nil {
		return nil, err
	}

	return signed.Serialize(), nil
}

func (publicKey *PublicKey) Verify(signature []byte, data []byte) (bool, error) {
	parsedSignature, err := btcec.ParseSignature(signature, btcec.S256())

	if err != nil {
		return false, err
	}

	verified := parsedSignature.Verify(data, publicKey.PublicKey)

	if !verified {
		return false, nil
	}

	return true, nil
}
