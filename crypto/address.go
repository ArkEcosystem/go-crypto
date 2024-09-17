// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"encoding/hex"
	"errors"
	"strings"
)

func AddressFromPassphrase(passphrase string) (string, error) {
	privateKey, err := PrivateKeyFromPassphrase(passphrase)
	if err != nil {
		return "", err
	}
	return privateKey.ToAddress(), nil
}

func ValidateAddress(address string) (bool, error) {
	if !strings.HasPrefix(address, "0x") || len(address) != 42 {
		return false, errors.New("invalid address format")
	}
	_, err := hex.DecodeString(address[2:])
	if err != nil {
		return false, err
	}
	return true, nil
}
