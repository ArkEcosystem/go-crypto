package crypto

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newLegacySecondSignatureVectorTransaction(t *testing.T) (*Transaction, TestingLegacySecondSignatureVectorFixture) {
	fixture := GetLegacySecondSignatureVectorFixture()

	// Test vector from the Mainsail LSS v1 spec, built for chain 10_000
	previous := CONFIG_NETWORK
	SetNetwork(&Network{ChainId: fixture.ChainId})
	t.Cleanup(func() { SetNetwork(previous) })

	nonce, _ := new(big.Int).SetString(fixture.Data.Nonce, 10)
	gasPrice, _ := new(big.Int).SetString(fixture.Data.GasPrice, 10)
	gasLimit, _ := new(big.Int).SetString(fixture.Data.GasLimit, 10)
	value, _ := new(big.Int).SetString(fixture.Data.Value, 10)

	transaction := &Transaction{
		Nonce:    nonce,
		GasPrice: gasPrice,
		GasLimit: gasLimit,
		To:       fixture.Data.To,
		Value:    value,
	}

	return transaction, fixture
}

func TestLegacySecondSignSignsTheSignedTransactionHash(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	transaction, fixture := newLegacySecondSignatureVectorTransaction(t)

	privateKey, err := PrivateKeyFromHex(fixture.PrivateKey)
	require.NoError(err)
	secondPrivateKey, err := PrivateKeyFromHex(fixture.SecondPrivateKey)
	require.NoError(err)

	require.NoError(transaction.signWithPrivateKey(privateKey))

	assert.Equal(fixture.Signed, HexEncode(transaction.Serialized))
	assert.Equal(fixture.Data.Hash, transaction.Hash)

	require.NoError(transaction.legacySecondSignWithPrivateKey(secondPrivateKey))

	assert.Equal(fixture.Data.LegacySecondSignature, HexEncode(transaction.LegacySecondSignature))
	assert.Equal(fixture.Serialized, HexEncode(transaction.Serialized))

	hash, err := transaction.GetHash()
	require.NoError(err)
	assert.Equal(fixture.Data.Hash, hash)
}

func TestLegacySecondSignUsesZeroOrOneRecoveryId(t *testing.T) {
	require := require.New(t)

	transaction, fixture := newLegacySecondSignatureVectorTransaction(t)

	privateKey, err := PrivateKeyFromHex(fixture.PrivateKey)
	require.NoError(err)
	secondPrivateKey, err := PrivateKeyFromHex(fixture.SecondPrivateKey)
	require.NoError(err)

	require.NoError(transaction.signWithPrivateKey(privateKey))
	require.NoError(transaction.legacySecondSignWithPrivateKey(secondPrivateKey))

	require.Len(transaction.LegacySecondSignature, 65)
	assert.Contains(t, []byte{0, 1}, transaction.LegacySecondSignature[64])
}

func TestLegacySecondSignRequiresThePrimarySignatureFirst(t *testing.T) {
	transaction, fixture := newLegacySecondSignatureVectorTransaction(t)

	secondPrivateKey, err := PrivateKeyFromHex(fixture.SecondPrivateKey)
	require.NoError(t, err)

	assert.ErrorIs(t, transaction.legacySecondSignWithPrivateKey(secondPrivateKey), ErrLegacySecondSignatureBeforeSigning)
	assert.Empty(t, transaction.LegacySecondSignature)
}

func TestDeserializeLegacySecondSignatureHashesOnlyTheFirstNineFields(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	_, fixture := newLegacySecondSignatureVectorTransaction(t)

	transaction, err := DeserializeTransaction(fixture.Serialized)
	require.NoError(err)

	assert.Equal(fixture.Data.LegacySecondSignature, HexEncode(transaction.LegacySecondSignature))
	assert.Equal(fixture.Data.Hash, transaction.Hash)

	serialized, err := transaction.Serialize(false)
	require.NoError(err)
	assert.Equal(fixture.Serialized, HexEncode(serialized))

	verified, err := transaction.Verify()
	require.NoError(err)
	assert.True(verified)
}

func TestLegacySecondSignWithPassphrases(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	fixture := GetTransactionFixture("transfer_legacy_second_signature")
	identity := GetIdentityFixture()

	gasPrice, _ := new(big.Int).SetString(fixture.Data.GasPrice, 10)
	gasLimit, _ := new(big.Int).SetString(fixture.Data.GasLimit, 10)
	value, _ := new(big.Int).SetString(fixture.Data.Value, 10)

	transaction, err := BuildTransfer(fixture.Data.To, value)
	require.NoError(err)
	transaction.GasPrice = gasPrice
	transaction.GasLimit = gasLimit

	require.NoError(transaction.Sign(identity.Passphrase))
	require.NoError(transaction.LegacySecondSign(identity.SecondPassphrase))

	assert.Equal(fixture.Data.R, HexEncode(transaction.R))
	assert.Equal(fixture.Data.S, HexEncode(transaction.S))
	assert.Equal(fixture.Data.LegacySecondSignature, HexEncode(transaction.LegacySecondSignature))
	assert.Equal(fixture.Data.Hash, transaction.Hash)
	assert.Equal(fixture.Serialized, HexEncode(transaction.Serialized))
}

func TestLegacySecondSignRejectsAnInvalidPassphrase(t *testing.T) {
	transaction := NewTransaction()

	assert.Error(t, transaction.LegacySecondSign(""))
}
