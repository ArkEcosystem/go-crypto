// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"errors"

	b58 "github.com/btcsuite/btcutil/base58"
)

func AddressFromPassphrase(passphrase string) (string, error) {
	privateKey, err := PrivateKeyFromPassphrase(passphrase)

	if err != nil {
		return "", err
	}

	return privateKey.ToAddress(), nil
}

func ValidateAddress(address string) (bool, error) {
	_, version, err := b58.CheckDecode(address)

	if err != nil {
		return false, err
	}

	if GetNetwork().Version != version {
		return false, errors.New("network version mismatch")
	}

	return true, nil
}
