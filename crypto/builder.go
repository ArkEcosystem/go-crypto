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
	"math/big"

	blst "github.com/supranational/blst/bindings/go"
)

// Default gas parameters used by NewTransaction, matching php-crypto/
// typescript-crypto's AbstractTransactionBuilder defaults.
var (
	DefaultGasPrice = big.NewInt(5)
	DefaultGasLimit = big.NewInt(1_000_000)
)

// NewTransaction returns a Transaction with the default nonce/gasPrice/
// gasLimit/value builder defaults set. Concrete transaction-type builders
// (BuildTransfer, BuildVote, etc.) are layered on top of this.
func NewTransaction() *Transaction {
	return &Transaction{
		Nonce:    big.NewInt(1),
		GasPrice: DefaultGasPrice,
		GasLimit: DefaultGasLimit,
		Value:    big.NewInt(0),
	}
}

func validateBLSPublicKey(publicKey string) error {
	if len(publicKey) != 96 {
		return errors.New("invalid BLS public key length")
	}

	pubKeyBytes, err := hex.DecodeString(publicKey)
	if err != nil {
		return errors.New("invalid BLS public key hex format")
	}

	var pubKey blst.P1Affine
	pubKey.Deserialize(pubKeyBytes)

	if !pubKey.InG1() {
		return errors.New("invalid BLS public key: not in G1 group or invalid structure")
	}

	return nil
}
