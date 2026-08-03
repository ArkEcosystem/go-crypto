package crypto

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTransactionSignSerializeDeserializeVerifyRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	passphrase := "this is a top secret passphrase"

	transaction := NewTransaction()
	transaction.Nonce = big.NewInt(7)
	transaction.To = ContractConsensus
	transaction.Value = big.NewInt(0)
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureUnvote)

	require.NoError(transaction.Sign(passphrase))

	expectedAddress, err := AddressFromPassphrase(passphrase)
	require.NoError(err)
	assert.Equal(expectedAddress, transaction.From)

	verified, err := transaction.Verify()
	require.NoError(err)
	assert.True(verified)

	serializedHex := HexEncode(transaction.Serialized)

	deserialized, err := DeserializeTransaction(serializedHex)
	require.NoError(err)

	assert.Equal(0, transaction.Nonce.Cmp(deserialized.Nonce))
	assert.Equal(0, transaction.GasPrice.Cmp(deserialized.GasPrice))
	assert.Equal(0, transaction.GasLimit.Cmp(deserialized.GasLimit))
	assert.Equal(transaction.To, deserialized.To)
	assert.Equal(0, transaction.Value.Cmp(deserialized.Value))
	assert.Equal(transaction.Data, deserialized.Data)
	assert.Equal(transaction.V, deserialized.V)
	assert.Equal(transaction.R, deserialized.R)
	assert.Equal(transaction.S, deserialized.S)
	assert.Equal(transaction.Hash, deserialized.Hash)
	assert.Equal(transaction.SenderPublicKey, deserialized.SenderPublicKey)
	assert.Equal(transaction.From, deserialized.From)

	deserializedVerified, err := deserialized.Verify()
	require.NoError(err)
	assert.True(deserializedVerified)
}

func TestTransactionVerifyFailsForWrongSigner(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	transaction := NewTransaction()
	transaction.To = ContractConsensus
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureResignValidator)

	require.NoError(transaction.Sign("the real signer's passphrase"))

	otherPublicKey, err := PublicKeyFromPassphrase("a completely different passphrase")
	require.NoError(err)
	transaction.SenderPublicKey = otherPublicKey.ToHex()

	verified, err := transaction.Verify()
	require.NoError(err)
	assert.False(verified)
}

func TestTransactionSerializeUnsignedMatchesSigningHash(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	transaction := NewTransaction()
	transaction.To = ContractUsernames
	transaction.Data = AbiEncodeFunctionCall(AbiSignatureResignUsername)

	withSignature, err := transaction.Serialize(false)
	require.NoError(err)

	skipSignature, err := transaction.Serialize(true)
	require.NoError(err)

	assert.Equal(withSignature, skipSignature)
}

func TestDeserializeTransactionRejectsTruncatedData(t *testing.T) {
	assert := assert.New(t)

	// A valid RLP list containing a single short string — nowhere near the 9
	// fields [nonce, gasPrice, gasLimit, to, value, data, v, r, s] a
	// transaction needs.
	shortList := "c3820102"

	_, err := DeserializeTransaction(shortList)
	assert.Error(err)
}
