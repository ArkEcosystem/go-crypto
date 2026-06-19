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

	blst "github.com/supranational/blst/bindings/go"
	"github.com/tyler-smith/go-bip39"
)

const popDST = "BLS_POP_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

type ProofOfPossessionResult struct {
	PK  []byte
	POP []byte
}

func DeriveBlsPrivateKey(passphrase string) []byte {
	return popDeriveChildSk(passphrase).Serialize()
}

func DeriveBlsPublicKey(passphrase string) string {
	sk := popDeriveChildSk(passphrase)
	pk := new(blst.P1Affine).From(sk)
	return hex.EncodeToString(pk.Compress())
}

func BuildProofOfPossession(secretKeyBytes []byte) (*ProofOfPossessionResult, error) {
	sk := new(blst.SecretKey)
	if sk.Deserialize(secretKeyBytes) == nil {
		return nil, errors.New("invalid secret key bytes")
	}
	pk := new(blst.P1Affine).From(sk)
	pkBytes := pk.Compress()
	sig := new(blst.P2Affine).Sign(sk, pkBytes, []byte(popDST))
	return &ProofOfPossessionResult{PK: pkBytes, POP: sig.Compress()}, nil
}

func FromMnemonic(passphrase string) (*ProofOfPossessionResult, error) {
	return BuildProofOfPossession(DeriveBlsPrivateKey(passphrase))
}

func popDeriveChildSk(passphrase string) *blst.SecretKey {
	seed := bip39.NewSeed(passphrase, "")
	return blst.KeyGen(seed).DeriveChildEip2333(0)
}
