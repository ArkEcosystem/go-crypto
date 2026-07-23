// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func mustAbiAddress(t *testing.T, address string) AbiArg {
	t.Helper()
	arg, err := AbiAddress(address)
	require.New(t).NoError(err)
	return arg
}

func mustAbiUint256(t *testing.T, value int64) AbiArg {
	t.Helper()
	arg, err := AbiUint256(big.NewInt(value))
	require.New(t).NoError(err)
	return arg
}

func mustAbiAddressArray(t *testing.T, addresses []string) AbiArg {
	t.Helper()
	arg, err := AbiAddressArray(addresses)
	require.New(t).NoError(err)
	return arg
}

func mustAbiUint256Array(t *testing.T, values ...int64) AbiArg {
	t.Helper()
	bigValues := make([]*big.Int, len(values))
	for i, v := range values {
		bigValues[i] = big.NewInt(v)
	}
	arg, err := AbiUint256Array(bigValues)
	require.New(t).NoError(err)
	return arg
}

func TestIsTransfer(t *testing.T) {
	assert := assert.New(t)

	assert.True(IsTransfer(nil))
	assert.True(IsTransfer([]byte{}))
	assert.False(IsTransfer(AbiEncodeFunctionCall(AbiSignatureUnvote)))
}

func TestIsVote(t *testing.T) {
	assert := assert.New(t)

	voteData := AbiEncodeFunctionCall(AbiSignatureVote, mustAbiAddress(t, testAddress(0x01)))

	assert.True(IsVote(voteData))
	assert.False(IsVote(AbiEncodeFunctionCall(AbiSignatureUnvote)))
	assert.False(IsVote(nil))
}

func TestIsUnvote(t *testing.T) {
	assert := assert.New(t)

	assert.True(IsUnvote(AbiEncodeFunctionCall(AbiSignatureUnvote)))
	assert.False(IsUnvote(AbiEncodeFunctionCall(AbiSignatureVote, mustAbiAddress(t, testAddress(0x01)))))
}

func TestIsMultiPayment(t *testing.T) {
	assert := assert.New(t)

	data := AbiEncodeFunctionCall(AbiSignatureMultipayment,
		mustAbiAddressArray(t, []string{testAddress(0x01)}),
		mustAbiUint256Array(t, 100),
	)

	assert.True(IsMultiPayment(data))
	assert.False(IsMultiPayment(AbiEncodeFunctionCall(AbiSignatureVote, mustAbiAddress(t, testAddress(0x01)))))
}

func TestIsUsernameRegistration(t *testing.T) {
	assert := assert.New(t)

	data := AbiEncodeFunctionCall(AbiSignatureRegisterUsername, AbiString("test_user"))

	assert.True(IsUsernameRegistration(data))
	assert.False(IsUsernameRegistration(AbiEncodeFunctionCall(AbiSignatureResignUsername)))
}

func TestIsUsernameResignation(t *testing.T) {
	assert := assert.New(t)

	assert.True(IsUsernameResignation(AbiEncodeFunctionCall(AbiSignatureResignUsername)))
	assert.False(IsUsernameResignation(AbiEncodeFunctionCall(AbiSignatureRegisterUsername, AbiString("test_user"))))
}

// TestIsValidatorRegistrationAndIsUpdateValidatorDoNotCrossMatch exercises
// exactly the ambiguous pair discussed at length while designing this file:
// registerValidator(bytes,bytes) and updateValidator(bytes,bytes) share an
// identical argument shape, and here even identical argument *values* — only
// the selector differs, and that's the only thing these predicates may key
// off of.
func TestIsValidatorRegistrationAndIsUpdateValidatorDoNotCrossMatch(t *testing.T) {
	assert := assert.New(t)

	pubKey := AbiBytes([]byte("a public key"))
	proof := AbiBytes([]byte("a proof"))

	registrationData := AbiEncodeFunctionCall(AbiSignatureRegisterValidator, pubKey, proof)
	updateData := AbiEncodeFunctionCall(AbiSignatureUpdateValidator, pubKey, proof)

	assert.True(IsValidatorRegistration(registrationData))
	assert.False(IsUpdateValidator(registrationData))

	assert.True(IsUpdateValidator(updateData))
	assert.False(IsValidatorRegistration(updateData))
}

func TestIsValidatorResignation(t *testing.T) {
	assert := assert.New(t)

	assert.True(IsValidatorResignation(AbiEncodeFunctionCall(AbiSignatureResignValidator)))
	assert.False(IsValidatorResignation(AbiEncodeFunctionCall(AbiSignatureResignUsername)))
}

func TestIsTokenTransfer(t *testing.T) {
	assert := assert.New(t)

	data := AbiEncodeFunctionCall(AbiSignatureERC20Transfer, mustAbiAddress(t, testAddress(0x01)), mustAbiUint256(t, 100))

	assert.True(IsTokenTransfer(data))
	assert.False(IsTokenTransfer(AbiEncodeFunctionCall(AbiSignatureVote, mustAbiAddress(t, testAddress(0x01)))))
}

func TestIsBatchTransfer(t *testing.T) {
	assert := assert.New(t)

	data := AbiEncodeFunctionCall(AbiSignatureERC20BatchTransferFrom,
		mustAbiAddress(t, testAddress(0x01)),
		mustAbiAddressArray(t, []string{testAddress(0x02)}),
		mustAbiUint256Array(t, 100),
	)

	assert.True(IsBatchTransfer(data))
	assert.False(IsBatchTransfer(AbiEncodeFunctionCall(AbiSignatureVote, mustAbiAddress(t, testAddress(0x01)))))
}

// TestIsApproveAndIsRevoke covers the one predicate pair that shares a
// selector AND an argument shape (approve(address,uint256)) — the decoded
// amount is the only thing that tells them apart.
func TestIsApproveAndIsRevoke(t *testing.T) {
	assert := assert.New(t)

	approveData := AbiEncodeFunctionCall(AbiSignatureERC20Approve, mustAbiAddress(t, testAddress(0x01)), mustAbiUint256(t, 500))
	revokeData := AbiEncodeFunctionCall(AbiSignatureERC20Approve, mustAbiAddress(t, testAddress(0x01)), mustAbiUint256(t, 0))

	assert.True(IsApprove(approveData))
	assert.False(IsRevoke(approveData))

	assert.True(IsRevoke(revokeData))
	assert.False(IsApprove(revokeData))
}

// TestIsFunctionsHandleMalformedDataWithoutPanicking confirms every Is*
// predicate degrades to false on garbage input rather than panicking — these
// functions are meant to be safe to call on arbitrary calldata from
// untrusted sources.
func TestIsFunctionsHandleMalformedDataWithoutPanicking(t *testing.T) {
	assert := assert.New(t)

	garbage := []byte{0xde, 0xad, 0xbe, 0xef} // selector-length, matches nothing real

	assert.NotPanics(func() {
		assert.False(IsVote(garbage))
		assert.False(IsUnvote(garbage))
		assert.False(IsMultiPayment(garbage))
		assert.False(IsUsernameRegistration(garbage))
		assert.False(IsUsernameResignation(garbage))
		assert.False(IsValidatorRegistration(garbage))
		assert.False(IsValidatorResignation(garbage))
		assert.False(IsUpdateValidator(garbage))
		assert.False(IsTokenTransfer(garbage))
		assert.False(IsBatchTransfer(garbage))
		assert.False(IsApprove(garbage))
		assert.False(IsRevoke(garbage))
	})
}

// TestDecodeTransactionArgsPopulatesSemanticFields exercises the dispatch
// directly on hand-built Data, isolated from the RLP/ECDSA layers a full
// sign→serialize→deserialize round trip would also involve.
func TestDecodeTransactionArgsPopulatesSemanticFields(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	validatorAddress := testAddress(0x01)

	transaction := &Transaction{
		Data: AbiEncodeFunctionCall(AbiSignatureVote, mustAbiAddress(t, validatorAddress)),
	}

	require.NoError(DecodeTransactionArgs(transaction))
	assert.Equal(validatorAddress, transaction.Vote)
}

// TestDecodeTransactionArgsMalformedKnownSelectorErrors confirms the
// deliberate divergence from php-crypto: once Data's leading 4 bytes match a
// known function's selector, a subsequent decode failure is a hard error,
// not a silent fallback to the next candidate.
func TestDecodeTransactionArgsMalformedKnownSelectorErrors(t *testing.T) {
	assert := assert.New(t)

	transaction := NewTransaction()
	transaction.To = ContractConsensus
	// The correct 4-byte selector for vote(address), followed by a payload
	// too short to contain the required 32-byte address argument.
	transaction.Data = append(AbiFunctionSelector(AbiSignatureVote), 0x01, 0x02)

	err := DecodeTransactionArgs(transaction)
	assert.Error(err)
}

// TestDecodeTransactionArgsNoOpForUnrecognizedData confirms a transfer or
// generic contract call (no known selector) leaves every semantic field
// untouched, rather than erroring or guessing.
func TestDecodeTransactionArgsNoOpForUnrecognizedData(t *testing.T) {
	assert := assert.New(t)

	transaction := &Transaction{Data: []byte{0xde, 0xad, 0xbe, 0xef}}

	assert.NoError(DecodeTransactionArgs(transaction))
	assert.Empty(transaction.Vote)
	assert.Empty(transaction.Username)
	assert.Empty(transaction.ValidatorPublicKey)
	assert.Empty(transaction.PaymentAddresses)
}
