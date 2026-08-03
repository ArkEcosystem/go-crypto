package crypto

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testPassphrase = "this is a top secret passphrase"

func signSerializeDeserialize(t *testing.T, transaction *Transaction) *Transaction {
	t.Helper()
	require := require.New(t)

	require.NoError(transaction.Sign(testPassphrase))

	verified, err := transaction.Verify()
	require.NoError(err)
	require.True(verified)

	deserialized, err := DeserializeTransaction(HexEncode(transaction.Serialized))
	require.NoError(err)

	deserializedVerified, err := deserialized.Verify()
	require.NoError(err)
	require.True(deserializedVerified)

	return deserialized
}

func TestBuildTransferRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	recipient := testAddress(0x01)
	transaction, err := BuildTransfer(recipient, big.NewInt(1_000_000))
	require.NoError(err)

	deserialized := signSerializeDeserialize(t, transaction)

	assert.True(IsTransfer(deserialized.Data))
	assert.Equal(recipient, deserialized.To)
	assert.Equal(0, big.NewInt(1_000_000).Cmp(deserialized.Value))
}

func TestBuildTransferInvalidRecipientErrors(t *testing.T) {
	assert := assert.New(t)

	_, err := BuildTransfer("not-an-address", big.NewInt(1))
	assert.ErrorIs(err, ErrInvalidAddress)
}

func TestBuildVoteRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	validator := testAddress(0x02)
	transaction, err := BuildVote(validator)
	require.NoError(err)

	deserialized := signSerializeDeserialize(t, transaction)

	assert.True(IsVote(deserialized.Data))
	assert.Equal(ContractConsensus, deserialized.To)
	assert.Equal(validator, deserialized.Vote)
}

func TestBuildUnvoteRoundTrip(t *testing.T) {
	assert := assert.New(t)

	transaction := BuildUnvote()
	deserialized := signSerializeDeserialize(t, transaction)

	assert.True(IsUnvote(deserialized.Data))
	assert.Equal(ContractConsensus, deserialized.To)
}

const (
	validatorPassphraseFixture                  = "gold favorite math anchor detect march purpose such sausage crucial reform novel connect misery update episode invite salute barely garbage exclude winner visa cruise"
	validatorPassphraseFixturePublicKey         = "a18dba7811b212bbb2f080d7c69935998ffbe7b38586e2d3e9e12079ea789996d1c69feb158c002aed327f69865be496"
	validatorPassphraseFixtureProofOfPossession = "a124539f9d469919eb57224cc003d9d5b086a27c6de244abf60b74b35fb749fceab7f4c24b983475cddab7d0876de49c000b5c362f5e3ce18d964f5c2d20d4eadcf7cb77a73d8ee4cd87bad10f7ba0824cea6715d1c045b4f93865a2758b7bfe"
)

func TestBuildValidatorRegistrationRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	transaction, err := BuildValidatorRegistration(validatorPassphraseFixture, big.NewInt(2_500_000_000))
	require.NoError(err)

	assert.Equal(validatorPassphraseFixturePublicKey, transaction.ValidatorPublicKey)
	assert.Equal(validatorPassphraseFixtureProofOfPossession, transaction.ValidatorProof)

	deserialized := signSerializeDeserialize(t, transaction)

	assert.True(IsValidatorRegistration(deserialized.Data))
	assert.Equal(ContractConsensus, deserialized.To)
	assert.Equal(validatorPassphraseFixturePublicKey, deserialized.ValidatorPublicKey)
	assert.Equal(validatorPassphraseFixtureProofOfPossession, deserialized.ValidatorProof)
	assert.Equal(0, big.NewInt(2_500_000_000).Cmp(deserialized.Value))
}

func TestBuildValidatorUpdateRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	transaction, err := BuildValidatorUpdate(validatorPassphraseFixture)
	require.NoError(err)

	assert.Equal(validatorPassphraseFixturePublicKey, transaction.ValidatorPublicKey)
	assert.Equal(validatorPassphraseFixtureProofOfPossession, transaction.ValidatorProof)

	deserialized := signSerializeDeserialize(t, transaction)

	assert.True(IsUpdateValidator(deserialized.Data))
	assert.Equal(validatorPassphraseFixturePublicKey, deserialized.ValidatorPublicKey)
	assert.Equal(validatorPassphraseFixtureProofOfPossession, deserialized.ValidatorProof)
}

func TestBuildValidatorResignationRoundTrip(t *testing.T) {
	assert := assert.New(t)

	transaction := BuildValidatorResignation()
	deserialized := signSerializeDeserialize(t, transaction)

	assert.True(IsValidatorResignation(deserialized.Data))
	assert.Equal(ContractConsensus, deserialized.To)
}

func TestBuildUsernameRegistrationRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	transaction, err := BuildUsernameRegistration("simple_tx_tester")
	require.NoError(err)

	deserialized := signSerializeDeserialize(t, transaction)

	assert.True(IsUsernameRegistration(deserialized.Data))
	assert.Equal(ContractUsernames, deserialized.To)
	assert.Equal("simple_tx_tester", deserialized.Username)
}

func TestBuildUsernameRegistrationValidation(t *testing.T) {
	assert := assert.New(t)

	cases := []string{
		"",                              // too short
		"this_username_is_way_too_long", // too long
		"Invalid",                       // uppercase
		"_leading",                      // leading underscore
		"trailing_",                     // trailing underscore
		"double__underscore",            // consecutive underscores
	}

	for _, username := range cases {
		_, err := BuildUsernameRegistration(username)
		assert.ErrorIs(err, ErrInvalidUsername, "username %q should be rejected", username)
	}
}

func TestBuildUsernameResignationRoundTrip(t *testing.T) {
	assert := assert.New(t)

	transaction := BuildUsernameResignation()
	deserialized := signSerializeDeserialize(t, transaction)

	assert.True(IsUsernameResignation(deserialized.Data))
	assert.Equal(ContractUsernames, deserialized.To)
}

func TestBuildMultiPaymentRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	addresses := []string{testAddress(0x01), testAddress(0x02)}
	amounts := []*big.Int{big.NewInt(111222), big.NewInt(222333)}

	transaction, err := BuildMultiPayment(addresses, amounts)
	require.NoError(err)

	assert.Equal(0, big.NewInt(333555).Cmp(transaction.Value)) // sum of amounts

	deserialized := signSerializeDeserialize(t, transaction)

	assert.True(IsMultiPayment(deserialized.Data))
	assert.Equal(ContractMultipayment, deserialized.To)
	assert.Equal(addresses, deserialized.PaymentAddresses)
	require.Equal(len(amounts), len(deserialized.PaymentAmounts))
	for i, amount := range amounts {
		assert.Equal(0, amount.Cmp(deserialized.PaymentAmounts[i]))
	}
}

func TestBuildMultiPaymentMismatchedLengthsErrors(t *testing.T) {
	assert := assert.New(t)

	_, err := BuildMultiPayment([]string{testAddress(0x01)}, []*big.Int{})
	assert.Error(err)
}

func TestBuildMultiPaymentEmptyErrors(t *testing.T) {
	assert := assert.New(t)

	_, err := BuildMultiPayment(nil, nil)
	assert.Error(err)
}

func TestBuildEvmCallRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	to := testAddress(0x03)
	data := []byte{0xde, 0xad, 0xbe, 0xef}

	transaction, err := BuildEvmCall(to, data)
	require.NoError(err)

	deserialized := signSerializeDeserialize(t, transaction)

	// Arbitrary/unrecognized calldata: none of the known predicates match.
	assert.False(IsVote(deserialized.Data))
	assert.False(IsUnvote(deserialized.Data))
	assert.False(IsValidatorRegistration(deserialized.Data))
	assert.False(IsUsernameRegistration(deserialized.Data))
	assert.False(IsMultiPayment(deserialized.Data))
	assert.Equal(to, deserialized.To)
	assert.Equal(data, deserialized.Data)
}

func TestBuildBatchTransferRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	token := testAddress(0x04)
	recipients := []string{testAddress(0x01), testAddress(0x02)}
	amounts := []*big.Int{big.NewInt(100), big.NewInt(200)}

	transaction, err := BuildBatchTransfer(token, recipients, amounts)
	require.NoError(err)

	deserialized := signSerializeDeserialize(t, transaction)

	assert.True(IsBatchTransfer(deserialized.Data))
	assert.Equal(ContractBatchTransfer, deserialized.To)
}

func TestBuildTokenApproveRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	token := testAddress(0x05)
	spender := testAddress(0x06)

	transaction, err := BuildTokenApprove(token, spender, big.NewInt(500))
	require.NoError(err)

	deserialized := signSerializeDeserialize(t, transaction)

	assert.True(IsApprove(deserialized.Data))
	assert.False(IsRevoke(deserialized.Data))
	assert.Equal(token, deserialized.To)
}

func TestBuildTokenApproveZeroAmountIsRevoke(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	transaction, err := BuildTokenApprove(testAddress(0x05), testAddress(0x06), big.NewInt(0))
	require.NoError(err)

	deserialized := signSerializeDeserialize(t, transaction)

	assert.True(IsRevoke(deserialized.Data))
	assert.False(IsApprove(deserialized.Data))
}

func TestBuildTokenTransferRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	token := testAddress(0x07)
	recipient := testAddress(0x08)

	transaction, err := BuildTokenTransfer(token, recipient, big.NewInt(750))
	require.NoError(err)

	deserialized := signSerializeDeserialize(t, transaction)

	assert.True(IsTokenTransfer(deserialized.Data))
	assert.Equal(token, deserialized.To)
}
