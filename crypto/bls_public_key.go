// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"encoding/hex"

	blst "github.com/supranational/blst/bindings/go"
)


func (k *BLSPublicKey) ToHex() string {
	return hex.EncodeToString(k.PublicKey.Compress())
}

func (k *BLSPublicKey) FromPassphrase(passphrase string) error {
	privateKey, err := BLSPrivateKeyFromPassphrase(passphrase)
	if err != nil {
		return err
	}

	k.PublicKey = new(blst.P1Affine).From(privateKey.PrivateKey)

	return nil
}

func BLSPublicKeyFromPassphrase(passphrase string) (*BLSPublicKey, error) {
	key := &BLSPublicKey{}
	err := key.FromPassphrase(passphrase)
	if err != nil {
		return nil, err
	}
	return key, nil
}
