// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"github.com/btcsuite/btcd/btcec"
	b58 "github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

func PublicKeyFromPassphrase(passphrase string) (*PublicKey, error) {
	privateKey, err := PrivateKeyFromPassphrase(passphrase)

	if err != nil {
		return nil, err
	}

	return privateKey.PublicKey, nil
}

func PublicKeyFromHex(publicKeyHex string) (*PublicKey, error) {
	publicKey, err := PublicKeyFromBytes(HexDecode(publicKeyHex))

	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func PublicKeyFromBytes(bytes []byte) (*PublicKey, error) {
	publicKey, err := btcec.ParsePubKey(bytes, btcec.S256())

	if err != nil {
		return nil, err
	}

	isCompressed := false

	if len(bytes) == btcec.PubKeyBytesLenCompressed {
		isCompressed = true
	}

	return &PublicKey{
		PublicKey:    publicKey,
		isCompressed: isCompressed,
		Network:      GetNetwork(),
	}, nil
}

////////////////////////////////////////////////////////////////////////////////
// ADDRESS COMPUTATION /////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

func (publicKey *PublicKey) ToHex() string {
	return HexEncode(publicKey.Serialize())
}

func (publicKey *PublicKey) ToAddress() string {
	return b58.CheckEncode(publicKey.AddressBytes(), publicKey.Network.Version)
}

func (publicKey *PublicKey) Serialize() []byte {
	if publicKey.isCompressed {
		return publicKey.SerializeCompressed()
	}

	return publicKey.SerializeUncompressed()
}

func (publicKey *PublicKey) AddressBytes() []byte {
	hash := ripemd160.New()
	_, _ = hash.Write(publicKey.Serialize())

	return hash.Sum(nil)
}
