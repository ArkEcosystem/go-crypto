package crypto

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncodeDataMatchesFixtures(t *testing.T) {
	t.Run("vote", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("vote")
		validatorAddress := AddressFromBytes(HexDecode("c3bbe9b1cee1ff85ad72b87414b0e9b7f2366763"))

		data, err := EncodeVoteData(validatorAddress)
		require.NoError(err)
		assert.Equal(HexDecode(fixture.Data.Data), data)
	})

	t.Run("unvote", func(t *testing.T) {
		assert := assert.New(t)
		fixture := GetTransactionFixture("unvote")
		assert.Equal(HexDecode(fixture.Data.Data), EncodeUnvoteData())
	})

	t.Run("validator_registration", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("validator_registration")
		data, err := EncodeValidatorRegistrationData(validatorPassphraseFixture)
		require.NoError(err)
		assert.Equal(HexDecode(fixture.Data.Data), data)
	})

	t.Run("validator_update", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("validator_update")
		data, err := EncodeValidatorUpdateData(validatorPassphraseFixture)
		require.NoError(err)
		assert.Equal(HexDecode(fixture.Data.Data), data)
	})

	t.Run("validator_resignation", func(t *testing.T) {
		assert := assert.New(t)
		fixture := GetTransactionFixture("validator_resignation")
		assert.Equal(HexDecode(fixture.Data.Data), EncodeValidatorResignationData())
	})

	t.Run("username_registration", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("username_registration")
		data, err := EncodeUsernameRegistrationData("fixture")
		require.NoError(err)
		assert.Equal(HexDecode(fixture.Data.Data), data)
	})

	t.Run("username_resignation", func(t *testing.T) {
		assert := assert.New(t)
		fixture := GetTransactionFixture("username_resignation")
		assert.Equal(HexDecode(fixture.Data.Data), EncodeUsernameResignationData())
	})

	t.Run("multi_payment", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		fixture := GetTransactionFixture("multi_payment")
		addresses := []string{
			AddressFromBytes(HexDecode("6f0182a0cc707b055322ccf6d4cb6a5aff1aeb22")),
			AddressFromBytes(HexDecode("c3bbe9b1cee1ff85ad72b87414b0e9b7f2366763")),
		}
		amounts := []*big.Int{big.NewInt(100000), big.NewInt(200000)}

		data, err := EncodeMultiPaymentData(addresses, amounts)
		require.NoError(err)
		assert.Equal(HexDecode(fixture.Data.Data), data)
	})
}

func TestEncodeTokenTransferData(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	data, err := EncodeTokenTransferData(testAddress(0x01), big.NewInt(750))
	require.NoError(err)
	assert.True(IsTokenTransfer(data))
}

func TestEncodeApproveContractData(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	data, err := EncodeApproveContractData(big.NewInt(500))
	require.NoError(err)
	assert.True(IsApprove(data))

	decoder, err := NewAbiDecoder(data, AbiSignatureERC20Approve, 2)
	require.NoError(err)
	spender, err := decoder.Address(0)
	require.NoError(err)
	assert.Equal(ContractBatchTransfer, spender)
}

func TestEncodeBatchTransferData(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	data, err := EncodeBatchTransferData(testAddress(0x04), []string{testAddress(0x01), testAddress(0x02)}, []*big.Int{big.NewInt(100), big.NewInt(200)})
	require.NoError(err)
	assert.True(IsBatchTransfer(data))
}
