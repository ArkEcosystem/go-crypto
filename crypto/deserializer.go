package crypto

import (
	"errors"
	"math/big"
)

var (
	ErrDeserializeTruncated = errors.New("deserialize: transaction data is truncated")
	ErrDeserializeInvalidTo = errors.New("deserialize: \"to\" field is not a valid address length")
	ErrDeserializeInvalidV  = errors.New("deserialize: v field does not decode to a valid recovery id")
)

// DeserializeTransaction decodes a hex-encoded RLP transaction envelope:
// [nonce, gasPrice, gasLimit, to, value, data, v, r, s].
func DeserializeTransaction(serializedHex string) (*Transaction, error) {
	serialized := HexDecode(serializedHex)

	list := NewRlpList(
		&RlpBigInt{}, &RlpBigInt{}, &RlpBigInt{},
		&RlpBytes{}, &RlpBigInt{}, &RlpBytes{},
		&RlpBigInt{}, &RlpBytes{}, &RlpBytes{},
	)

	if _, err := RlpDecode(serialized, list); err != nil {
		return nil, err
	}

	items := *list
	if len(items) < 9 {
		return nil, ErrDeserializeTruncated
	}

	toBytes := []byte(*items[3].(*RlpBytes))
	if len(toBytes) != 0 && len(toBytes) != AddressByteLength {
		return nil, ErrDeserializeInvalidTo
	}

	transaction := &Transaction{
		Nonce:      items[0].(*RlpBigInt).X,
		GasPrice:   items[1].(*RlpBigInt).X,
		GasLimit:   items[2].(*RlpBigInt).X,
		Value:      items[4].(*RlpBigInt).X,
		Data:       []byte(*items[5].(*RlpBytes)),
		Serialized: serialized,
	}

	if len(toBytes) > 0 {
		transaction.To = AddressFromBytes(toBytes)
	}

	chainId := big.NewInt(int64(GetNetwork().ChainId))
	recoveryId, err := recoveryIdFromEip155V(items[6].(*RlpBigInt).X, chainId)
	if err != nil {
		return nil, err
	}
	transaction.V = recoveryId
	transaction.R = padCurveBytes([]byte(*items[7].(*RlpBytes)))
	transaction.S = padCurveBytes([]byte(*items[8].(*RlpBytes)))

	hash, err := transaction.GetHash()
	if err != nil {
		return nil, err
	}
	transaction.Hash = hash

	if err := transaction.RecoverSender(); err != nil {
		return nil, err
	}

	if err := DecodeTransactionArgs(transaction); err != nil {
		return nil, err
	}

	return transaction, nil
}

// recoveryIdFromEip155V reverses EIP-155's v = recoveryId + chainId*2 + 35,
// rejecting the result unless it is a valid ECDSA recovery id (0-3). This
// guards against a malformed or adversarial v field producing an out-of-range
// or unrepresentable value that would otherwise silently corrupt or panic on
// the big.Int-to-int conversion.
func recoveryIdFromEip155V(vField, chainId *big.Int) (int, error) {
	recoveryId := new(big.Int).Sub(vField, new(big.Int).Mul(chainId, big.NewInt(2)))
	recoveryId.Sub(recoveryId, big.NewInt(35))

	if !recoveryId.IsInt64() {
		return 0, ErrDeserializeInvalidV
	}

	n := recoveryId.Int64()
	if n < 0 || n > 3 {
		return 0, ErrDeserializeInvalidV
	}

	return int(n), nil
}
