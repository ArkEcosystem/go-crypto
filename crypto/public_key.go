// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/ellemouton/schnorr"
	"golang.org/x/crypto/sha3"
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
	pubBytes := publicKey.PublicKey.SerializeUncompressed()
	pubBytes = pubBytes[1:]
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubBytes)
	hashed := hash.Sum(nil)
	addressBytes := hashed[12:]
	address := hex.EncodeToString(addressBytes)
	return "0x" + EIP55Checksum(address)
}

func EIP55Checksum(address string) string {
	addressHash := sha3.NewLegacyKeccak256()
	addressHash.Write([]byte(strings.ToLower(address)))
	hash := hex.EncodeToString(addressHash.Sum(nil))
	result := ""
	for i := 0; i < len(address); i++ {
		if address[i] >= '0' && address[i] <= '9' {
			result += string(address[i])
		} else {
			if hash[i] >= '8' {
				result += string(strings.ToUpper(string(address[i])))
			} else {
				result += string(strings.ToLower(string(address[i])))
			}
		}
	}
	return result
}

func (publicKey *PublicKey) Serialize() []byte {
	if publicKey.isCompressed {
		return publicKey.SerializeCompressed()
	}
	return publicKey.SerializeUncompressed()
}

func (publicKey *PublicKey) SerializeCompressed() []byte {
	return publicKey.PublicKey.SerializeCompressed()
}

func (publicKey *PublicKey) SerializeUncompressed() []byte {
	return publicKey.PublicKey.SerializeUncompressed()
}

func (publicKey *PublicKey) Verify(signature []byte, hash []byte) (bool, error) {
	return publicKey.VerifySchnorr(signature, hash)
}

func (publicKey *PublicKey) VerifySchnorr(signature []byte, hash []byte) (bool, error) {
	if len(signature) != 64 {
		return false, fmt.Errorf("VerifySchnorr: signature is %d bytes, should be 64", len(signature))
	}
	if len(hash) != 32 {
		return false, fmt.Errorf("VerifySchnorr: message hash is %d bytes, should be 32", len(hash))
	}

	// Parse the signature using the schnorr package
	sig, err := schnorr.NewSignatureFromBytes(signature)
	if err != nil {
		return false, fmt.Errorf("VerifySchnorr: failed to parse signature: %v", err)
	}

	// Parse the public key using the schnorr package
	var schnorrPubKey *schnorr.PublicKey
	if len(publicKey.PublicKey.SerializeCompressed()) == 33 {
		schnorrPubKey, err = schnorr.ParsePlainPubKey(publicKey.PublicKey.SerializeCompressed())
	} else {
		schnorrPubKey, err = schnorr.ParseXOnlyPubKey(publicKey.PublicKey.SerializeCompressed())
	}

	if err != nil {
		return false, fmt.Errorf("VerifySchnorr: failed to parse public key: %v", err)
	}

	// Verify the signature
	err = sig.Verify(schnorrPubKey, hash) // Assuming `Verify` returns only bool

	return err == nil, err
}
