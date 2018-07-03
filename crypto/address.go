// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"github.com/ArkEcosystem/go-crypto/crypto/base58"
)

/*
 Usage
 ===============================================================================
 crypto.AddressFromSecret("passphrase")
*/
func AddressFromSecret(secret string) (string, error) {
	privateKey, err := PrivateKeyFromSecret(secret)

	if err != nil {
		return "", err
	}

	address, err := privateKey.Address()

	if err != nil {
		return "", err
	}

	return address, nil
}

/*
 Usage
 ===============================================================================
 privateKey := crypto.PrivateKeyFromSecret("passphrase")
 crypto.AddressToBytes(privateKey.Address())
*/
func AddressToBytes(address string) ([]byte, error) {
	bytes, err := base58.Decode(address)

	if err != nil {
		return nil, err
	}

	return bytes, nil
}

/*
 Usage
 ===============================================================================
 crypto.ValidateAddress("DARiJqhogp2Lu6bxufUFQQMuMyZbxjCydN")
*/
func ValidateAddress(address string) (bool, error) {
	bytes, err := AddressToBytes(address)

	if err != nil {
		return false, err
	}

	return Byte2Hex(GetNetwork().Version) == Hex2Byte(bytes[:1]), nil
}
