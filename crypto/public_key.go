// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"github.com/ArkEcosystem/go-crypto/crypto/base58"
	"github.com/btcsuite/btcd/btcec"
	"golang.org/x/crypto/ripemd160"
)

/*
 Usage
 ===============================================================================
 crypto.PublicKeyFromSecret("passphrase")
*/
func PublicKeyFromSecret(secret string) (*PublicKey, error) {
	privateKey, err := PrivateKeyFromSecret(secret)

	if err != nil {
		return nil, err
	}

	return privateKey.PublicKey, nil
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
		network:      GetNetwork(),
	}, nil
}

////////////////////////////////////////////////////////////////////////////////
// ADDRESS COMPUTATION /////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/*
 Usage
 ===============================================================================
 publicKey := crypto.PublicKeyFromSecret("passphrase")
 publicKey.Address()
*/
func (publicKey *PublicKey) Address() (string, error) {
	ripeHashedBytes, err := publicKey.AddressBytes()

	if err != nil {
		return "", err
	}

	ripeHashedBytes = append(ripeHashedBytes, 0x0)
	copy(ripeHashedBytes[1:], ripeHashedBytes[:len(ripeHashedBytes)-1])
	ripeHashedBytes[0] = publicKey.network.Version

	return base58.Encode(ripeHashedBytes), nil
}

func (publicKey *PublicKey) Serialise() []byte {
	if publicKey.isCompressed {
		return publicKey.SerializeCompressed()
	}

	return publicKey.SerializeUncompressed()
}

func (publicKey *PublicKey) AddressBytes() ([]byte, error) {
	hash := ripemd160.New()
	_, err := hash.Write(publicKey.Serialise())

	if err != nil {
		return nil, err
	}

	return hash.Sum(nil), nil
}
