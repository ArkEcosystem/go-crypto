// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"encoding/hex"

	"github.com/btcsuite/btcutil/base58"
	"golang.org/x/crypto/ripemd160"
)

func LegacyAddressFromPassphrase(passphrase string, pubKeyHash byte) (string, error) {
	privateKey, err := PrivateKeyFromPassphrase(passphrase)
	if err != nil {
		return "", err
	}
	return LegacyAddressFromPrivateKey(privateKey, pubKeyHash)
}

func LegacyAddressFromPublicKey(publicKey string, pubKeyHash byte) (string, error) {
	publicKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return "", err
	}

	hasher := ripemd160.New()
	hasher.Write(publicKeyBytes)
	hash := hasher.Sum(nil)

	return base58.CheckEncode(hash, pubKeyHash), nil
}

func LegacyAddressFromPrivateKey(privateKey *PrivateKey, pubKeyHash byte) (string, error) {
	return LegacyAddressFromPublicKey(privateKey.PublicKey.ToHex(), pubKeyHash)
}

func ValidateLegacyAddress(address string, pubKeyHash byte) bool {
	decoded, version, err := base58.CheckDecode(address)
	if err != nil {
		return false
	}

	if len(decoded) != ripemd160.Size {
		return false
	}

	return version == pubKeyHash
}
