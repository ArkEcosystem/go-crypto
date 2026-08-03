package crypto

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const evmCallFixturePassphrase = "found lobster oblige describe ready addict body brave live vacuum display salute lizard combine gift resemble race senior quality reunion proud tell adjust angle"

func mustBigInt(t *testing.T, s string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(s, 10)
	require.New(t).True(ok, "not a valid base-10 integer: %q", s)
	return n
}

func transactionFromFixture(t *testing.T, fixture TestingTransactionFixture) *Transaction {
	t.Helper()
	return &Transaction{
		Nonce:    mustBigInt(t, fixture.Data.Nonce),
		GasPrice: mustBigInt(t, fixture.Data.GasPrice),
		GasLimit: mustBigInt(t, fixture.Data.GasLimit),
		To:       fixture.Data.To,
		Value:    mustBigInt(t, fixture.Data.Value),
		Data:     HexDecode(fixture.Data.Data),
	}
}

func TestFixturesMatchPhpTsSerialization(t *testing.T) {
	names := []string{
		"transfer",
		"vote",
		"unvote",
		"validator_registration",
		"validator_update",
		"validator_resignation",
		"username_registration",
		"username_resignation",
		"multi_payment",
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			assert := assert.New(t)
			require := require.New(t)

			fixture := GetTransactionFixture(name)
			tx := transactionFromFixture(t, fixture)

			require.NoError(tx.Sign(evmCallFixturePassphrase))

			assert.Equal(fixture.Data.V, tx.V)
			assert.Equal(fixture.Data.R, HexEncode(tx.R))
			assert.Equal(fixture.Data.S, HexEncode(tx.S))
			assert.Equal(fixture.Data.SenderPublicKey, tx.SenderPublicKey)
			assert.Equal(fixture.Data.From, tx.From)
			assert.Equal(fixture.Data.Hash, tx.Hash)
			assert.Equal(fixture.Serialized, HexEncode(tx.Serialized))

			verified, err := tx.Verify()
			require.NoError(err)
			assert.True(verified)

			deserialized, err := DeserializeTransaction(fixture.Serialized)
			require.NoError(err)

			deserializedVerified, err := deserialized.Verify()
			require.NoError(err)
			assert.True(deserializedVerified)

			assert.Equal(tx.Hash, deserialized.Hash)
			assert.Equal(tx.From, deserialized.From)
			assert.Equal(tx.SenderPublicKey, deserialized.SenderPublicKey)
			assert.Equal(tx.To, deserialized.To)
			assert.Equal(0, tx.Value.Cmp(deserialized.Value))
			assert.Equal(tx.Data, deserialized.Data)
		})
	}
}

func TestFixtureSemanticFieldsDecodeCorrectly(t *testing.T) {
	t.Run("vote", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("vote")
		deserialized, err := DeserializeTransaction(fixture.Serialized)
		require.NoError(err)

		validatorBytes := HexDecode("c3bbe9b1cee1ff85ad72b87414b0e9b7f2366763")

		assert.True(IsVote(deserialized.Data))
		assert.Equal(AddressFromBytes(validatorBytes), deserialized.Vote)
	})

	t.Run("unvote", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("unvote")
		deserialized, err := DeserializeTransaction(fixture.Serialized)
		require.NoError(err)

		assert.True(IsUnvote(deserialized.Data))
	})

	t.Run("validator_registration", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("validator_registration")
		deserialized, err := DeserializeTransaction(fixture.Serialized)
		require.NoError(err)

		assert.True(IsValidatorRegistration(deserialized.Data))
		assert.False(IsUpdateValidator(deserialized.Data))
		assert.Len(deserialized.ValidatorPublicKey, 96) // 48-byte BLS G1 pubkey, hex-encoded
		assert.Len(deserialized.ValidatorProof, 192)    // 96-byte BLS G2 PoP signature, hex-encoded
	})

	t.Run("validator_update", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("validator_update")
		deserialized, err := DeserializeTransaction(fixture.Serialized)
		require.NoError(err)

		assert.True(IsUpdateValidator(deserialized.Data))
		assert.False(IsValidatorRegistration(deserialized.Data))
		assert.Len(deserialized.ValidatorPublicKey, 96)
		assert.Len(deserialized.ValidatorProof, 192)
	})

	t.Run("validator_resignation", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("validator_resignation")
		deserialized, err := DeserializeTransaction(fixture.Serialized)
		require.NoError(err)

		assert.True(IsValidatorResignation(deserialized.Data))
	})

	t.Run("username_registration", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("username_registration")
		deserialized, err := DeserializeTransaction(fixture.Serialized)
		require.NoError(err)

		assert.True(IsUsernameRegistration(deserialized.Data))
		assert.Equal("fixture", deserialized.Username)
	})

	t.Run("username_resignation", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("username_resignation")
		deserialized, err := DeserializeTransaction(fixture.Serialized)
		require.NoError(err)

		assert.True(IsUsernameResignation(deserialized.Data))
	})

	t.Run("multi_payment", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("multi_payment")
		deserialized, err := DeserializeTransaction(fixture.Serialized)
		require.NoError(err)

		addr1 := HexDecode("6f0182a0cc707b055322ccf6d4cb6a5aff1aeb22")
		addr2 := HexDecode("c3bbe9b1cee1ff85ad72b87414b0e9b7f2366763")

		assert.True(IsMultiPayment(deserialized.Data))
		assert.Equal([]string{AddressFromBytes(addr1), AddressFromBytes(addr2)}, deserialized.PaymentAddresses)
		require.Len(deserialized.PaymentAmounts, 2)
		assert.Equal(0, big.NewInt(100000).Cmp(deserialized.PaymentAmounts[0]))
		assert.Equal(0, big.NewInt(200000).Cmp(deserialized.PaymentAmounts[1]))
	})

	t.Run("transfer", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("transfer")
		deserialized, err := DeserializeTransaction(fixture.Serialized)
		require.NoError(err)

		assert.True(IsTransfer(deserialized.Data))
	})
}
