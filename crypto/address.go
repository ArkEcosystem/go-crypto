// Copyright 2018 ArkEcosystem. All rights reserved.
//
// Use of this source code is governed by the MIT
// license that can be found in the LICENSE file.

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
