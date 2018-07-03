// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"crypto/sha256"
	"github.com/btcsuite/btcd/btcec"
)

/*
 Usage
 ===============================================================================
 crypto.PrivateKeyFromSecret("passphrase")
*/
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

/*
 Usage
 ===============================================================================
 privateKey, _ := crypto.PrivateKeyFromSecret("passphrase")
 privateKey.Address()
*/
func (privateKey *PrivateKey) Address() (string, error) {
	address, err := privateKey.PublicKey.Address()

	if err != nil {
		return "", err
	}

	return address, nil
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
