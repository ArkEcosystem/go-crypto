package crypto

import (
	"math/big"
)

// Serialize encodes the transaction as an RLP list:
// [nonce, gasPrice, gasLimit, to, value, data, v, r, s].
//
// If skipSignature is true, or no signature has been set on the transaction
// yet, the v/r/s slots are replaced with the EIP-155 placeholder
// [chainId, 0, 0] — this is the form that gets keccak256-hashed to produce
// the hash a signer signs (see Transaction.SigningHash). Once R and S are
// populated, Serialize(false) embeds the real EIP-155-encoded v
// (v = recoveryId + chainId*2 + 35) alongside r and s — this is the final
// wire encoding of a signed transaction.
func (transaction *Transaction) Serialize(skipSignature bool) ([]byte, error) {
	var toBytes []byte
	if transaction.To != "" {
		var err error
		toBytes, err = AddressToBytes(transaction.To)
		if err != nil {
			return nil, err
		}
	}
	to := RlpBytes(toBytes)
	data := RlpBytes(transaction.Data)

	items := []RlpItem{
		NewRlpBigInt(bigIntOrZero(transaction.Nonce)),
		NewRlpBigInt(bigIntOrZero(transaction.GasPrice)),
		NewRlpBigInt(bigIntOrZero(transaction.GasLimit)),
		&to,
		NewRlpBigInt(bigIntOrZero(transaction.Value)),
		&data,
	}

	chainId := big.NewInt(int64(GetNetwork().ChainId))

	if !skipSignature && len(transaction.R) > 0 && len(transaction.S) > 0 {
		v := new(big.Int).Add(big.NewInt(int64(transaction.V)), new(big.Int).Mul(chainId, big.NewInt(2)))
		v.Add(v, big.NewInt(35))

		items = append(items,
			NewRlpBigInt(v),
			NewRlpBigInt(new(big.Int).SetBytes(transaction.R)),
			NewRlpBigInt(new(big.Int).SetBytes(transaction.S)),
		)
	} else {
		items = append(items,
			NewRlpBigInt(chainId),
			NewRlpBigInt(big.NewInt(0)),
			NewRlpBigInt(big.NewInt(0)),
		)
	}

	return NewRlpList(items...).EncodeRLP()
}

func bigIntOrZero(x *big.Int) *big.Int {
	if x == nil {
		return big.NewInt(0)
	}
	return x
}
