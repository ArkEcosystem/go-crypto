package crypto

import (
	"encoding/hex"

	blst "github.com/supranational/blst/bindings/go"
	"github.com/tyler-smith/go-bip39"
)

func (k *BLSPrivateKey) ToHex() string {
	return hex.EncodeToString(k.PrivateKey.Serialize())
}

func (k *BLSPrivateKey) FromPassphrase(passphrase string) error {
	seed := bip39.NewSeed(passphrase, "")

	k.PrivateKey = blst.KeyGen(seed[:]).DeriveChildEip2333(0)

	return nil
}

func BLSPrivateKeyFromPassphrase(passphrase string) (*BLSPrivateKey, error) {
	key := &BLSPrivateKey{}
	err := key.FromPassphrase(passphrase)
	if err != nil {
		return nil, err
	}
	return key, nil
}
