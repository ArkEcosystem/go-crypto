// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"fmt"

	"github.com/btcsuite/btcd/btcec"
	b58 "github.com/btcsuite/btcutil/base58"
	"github.com/hbakhtiyor/schnorr"
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

func (publicKey *PublicKey) Verify(signature []byte, data []byte) (bool, error) {
	if isSchnorrSignature(len(signature)) {
		return publicKey.VerifySchnorr(signature, data)
	}

	return publicKey.VerifyECDSA(signature, data)
}

func (publicKey *PublicKey) VerifyECDSA(signature []byte, data []byte) (bool, error) {
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

func (publicKey *PublicKey) VerifySchnorr(signature []byte, hash []byte) (bool, error) {
	if len(signature) != 64 {
		return false, fmt.Errorf("VerifySchnorr: signature is %d bytes, should be 64", len(signature))
	}
	var signatureArr [64]byte
	copy(signatureArr[:], signature)

	if len(hash) != 32 {
		return false, fmt.Errorf("VerifySchnorr: message hash is %d bytes, should be 32", len(hash))
	}
	var hashArr [32]byte
	copy(hashArr[:], hash)

	publicKeyBytes := publicKey.Serialize()
	if len(publicKeyBytes) != 33 {
		return false, fmt.Errorf("VerifySchnorr: public key is %d bytes, should be 33", len(publicKeyBytes))
	}
	var publicKeyArr [33]byte
	copy(publicKeyArr[:], publicKeyBytes)

	return schnorr.Verify(publicKeyArr, hashArr, signatureArr)
}
