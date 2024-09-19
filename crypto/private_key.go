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
	"github.com/btcsuite/btcd/btcec"
	"github.com/ellemouton/schnorr"
)

func PrivateKeyFromPassphrase(passphrase string) (*PrivateKey, error) {
	hash := sha256.Sum256([]byte(passphrase))
	return PrivateKeyFromBytes(hash[:]), nil
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

	return base58.CheckEncode(p, privateKey.PublicKey.Network.Wif)
}

////////////////////////////////////////////////////////////////////////////////
// CRYPTOGRAPHY ////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
func (privateKey *PrivateKey) Serialize() []byte {
	return privateKey.PrivateKey.Serialize()
}

func (privateKey *PrivateKey) Sign(hash []byte) ([]byte, error) {
	// Parse the private key using the schnorr package
	schnorrPrivKey, err := schnorr.ParsePrivKeyHexString(HexEncode(privateKey.PrivateKey.Serialize()))
	if err != nil {
		return nil, fmt.Errorf("failed to parse Schnorr private key: %v", err)
	}

	// Sign the hash using Schnorr
	signature, err := schnorrPrivKey.Sign(hash, make([]byte, 32))
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash with Schnorr: %v", err)
	}

	// Convert [64]byte to []byte
	sigArray := signature.Bytes()
	sigSlice := make([]byte, 64)
	copy(sigSlice, sigArray[:])

	return sigSlice, nil
}

func (privateKey *PrivateKey) SignMulti(hash []byte, signerIndex int) ([]byte, error) {
	// Parse the private key using the schnorr package
	schnorrPrivKey, err := schnorr.ParsePrivKeyBytes(privateKey.PrivateKey.Serialize())
	if err != nil {
		return nil, fmt.Errorf("failed to parse Schnorr private key: %v", err)
	}

	// Sign the hash using Schnorr
	signature, err := schnorrPrivKey.Sign(hash, make([]byte, 32))
	if err != nil {
		return nil, fmt.Errorf("failed to sign hash with Schnorr: %v", err)
	}

	// Convert [64]byte to []byte
	sigArray := signature.Bytes()
	sigSlice := make([]byte, 64)
	copy(sigSlice, sigArray[:])

	// Prepend the signer index to the signature
	signatureWithIndex := append([]byte{byte(signerIndex)}, sigSlice...)

	return signatureWithIndex, nil
}

func (privateKey *PrivateKey) SecondSign(hash []byte) ([]byte, error) {
	// Parse the private key using the schnorr package
	schnorrPrivKey, err := schnorr.ParsePrivKeyBytes(privateKey.PrivateKey.Serialize())
	if err != nil {
		return nil, fmt.Errorf("failed to parse Schnorr private key: %v", err)
	}

	// Sign the hash using Schnorr
	signature, err := schnorrPrivKey.Sign(hash, make([]byte, 32))
	if err != nil {
		return nil, fmt.Errorf("failed to create second Schnorr signature: %v", err)
	}

	// Convert [64]byte to []byte
	sigArray := signature.Bytes()
	sigSlice := make([]byte, 64)
	copy(sigSlice, sigArray[:])

	return sigSlice, nil
}
