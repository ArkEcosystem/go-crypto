package crypto

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testAddress builds a syntactically valid "0x"-prefixed 20-byte address with
// the given last byte, avoiding hand-typed hex strings (easy to get the wrong
// length by miscounting zeros).
func testAddress(lastByte byte) string {
	b := make([]byte, abiAddressLength)
	b[abiAddressLength-1] = lastByte
	return "0x" + hex.EncodeToString(b)
}

// TestAbiFunctionSelectorKnownVectors checks against the two most widely used
// ERC-20 function selectors, which are independently verifiable (they appear
// in essentially every Ethereum tool/wallet/block explorer), not just
// self-consistent with our own encoder.
func TestAbiFunctionSelectorKnownVectors(t *testing.T) {
	assert := assert.New(t)

	assert.Equal("a9059cbb", hex.EncodeToString(AbiFunctionSelector("transfer(address,uint256)")))
	assert.Equal("095ea7b3", hex.EncodeToString(AbiFunctionSelector("approve(address,uint256)")))
}

// TestAbiEncodeFunctionCallKnownVector hand-verifies the byte layout of a
// simple static-only call against the ABI spec's head-only encoding rule (no
// dynamic args means no offsets, no tail — just the selector followed by
// left-padded words in argument order).
func TestAbiEncodeFunctionCallKnownVector(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	address := testAddress(0x01)
	addressArg, err := AbiAddress(address)
	require.NoError(err)

	amountArg, err := AbiUint256(big.NewInt(1000))
	require.NoError(err)

	encoded := AbiEncodeFunctionCall("transfer(address,uint256)", addressArg, amountArg)

	expected := "a9059cbb" +
		"0000000000000000000000000000000000000000000000000000000000000001" +
		"00000000000000000000000000000000000000000000000000000000000003e8"
	assert.Equal(expected, hex.EncodeToString(encoded))
}

func TestAbiEncodeDecodeAddressRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	address := testAddress(0x01)
	arg, err := AbiAddress(address)
	require.NoError(err)

	encoded := AbiEncodeFunctionCall("vote(address)", arg)

	decoder, err := NewAbiDecoder(encoded, "vote(address)", 1)
	require.NoError(err)

	decodedAddress, err := decoder.Address(0)
	require.NoError(err)
	assert.Equal(address, decodedAddress)
}

func TestAbiEncodeDecodeUint256RoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	values := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(1_000_000_000)}

	for _, v := range values {
		arg, err := AbiUint256(v)
		require.NoError(err)

		encoded := AbiEncodeFunctionCall("approve(address,uint256)", AbiArg{Encoded: make([]byte, abiWordLength)}, arg)

		decoder, err := NewAbiDecoder(encoded, "approve(address,uint256)", 2)
		require.NoError(err)

		decoded, err := decoder.Uint256(1)
		require.NoError(err)
		assert.Equal(0, v.Cmp(decoded))
	}
}

func TestAbiEncodeDecodeBytesRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	cases := [][]byte{
		{},
		{0x01},
		[]byte("a value longer than one 32-byte word to force padding math"),
	}

	for _, c := range cases {
		arg := AbiBytes(c)
		full := AbiEncodeFunctionCall("registerValidator(bytes,bytes)", arg, AbiBytes([]byte{}))

		decoder, err := NewAbiDecoder(full, "registerValidator(bytes,bytes)", 2)
		require.NoError(err)

		decoded, err := decoder.Bytes(0)
		require.NoError(err)
		assert.Equal(c, decoded)
	}
}

func TestAbiEncodeDecodeStringRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	username := "simple_tx_tester"
	encoded := AbiEncodeFunctionCall("registerUsername(string)", AbiString(username))

	decoder, err := NewAbiDecoder(encoded, "registerUsername(string)", 1)
	require.NoError(err)

	decoded, err := decoder.String(0)
	require.NoError(err)
	assert.Equal(username, decoded)
}

func TestAbiEncodeDecodeAddressArrayRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	addresses := []string{testAddress(0x01), testAddress(0x02)}
	amounts := []*big.Int{big.NewInt(100), big.NewInt(200)}

	addressesArg, err := AbiAddressArray(addresses)
	require.NoError(err)
	amountsArg, err := AbiUint256Array(amounts)
	require.NoError(err)

	encoded := AbiEncodeFunctionCall("pay(address[],uint256[])", addressesArg, amountsArg)

	decoder, err := NewAbiDecoder(encoded, "pay(address[],uint256[])", 2)
	require.NoError(err)

	decodedAddresses, err := decoder.AddressArray(0)
	require.NoError(err)
	assert.Equal(addresses, decodedAddresses)

	decodedAmounts, err := decoder.Uint256Array(1)
	require.NoError(err)
	assert.Equal(len(amounts), len(decodedAmounts))
	for i, a := range amounts {
		assert.Equal(0, a.Cmp(decodedAmounts[i]))
	}
}

func TestAbiEncodeInvalidAddressErrors(t *testing.T) {
	assert := assert.New(t)

	_, err := AbiAddress("not-an-address")
	assert.ErrorIs(err, ErrAbiInvalidAddress)

	_, err = AbiAddress("0x01") // too short
	assert.ErrorIs(err, ErrAbiInvalidAddress)
}

func TestAbiEncodeNegativeUintErrors(t *testing.T) {
	assert := assert.New(t)

	_, err := AbiUint256(big.NewInt(-1))
	assert.ErrorIs(err, ErrAbiNegativeUint)

	_, err = AbiUint256Array([]*big.Int{big.NewInt(1), big.NewInt(-1)})
	assert.ErrorIs(err, ErrAbiNegativeUint)
}

func TestAbiDecodeSelectorMismatchErrors(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	arg, err := AbiAddress(testAddress(0x01))
	require.NoError(err)
	encoded := AbiEncodeFunctionCall("vote(address)", arg)

	_, err = NewAbiDecoder(encoded, "unvote()", 0)
	assert.ErrorIs(err, ErrAbiSelectorMismatch)
}

func TestAbiDecodeTruncatedDataErrors(t *testing.T) {
	assert := assert.New(t)

	selector := AbiFunctionSelector("vote(address)")

	_, err := NewAbiDecoder(selector, "vote(address)", 1) // selector only, no head word
	assert.ErrorIs(err, ErrAbiUnexpectedEndOfData)
}

func TestAbiDecodeInvalidOffsetErrors(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	selector := AbiFunctionSelector("registerUsername(string)")
	// Head word claims an offset far beyond any data that actually follows.
	badOffset := make([]byte, abiWordLength)
	badOffset[abiWordLength-1] = 0xff

	data := append(append([]byte{}, selector...), badOffset...)

	decoder, err := NewAbiDecoder(data, "registerUsername(string)", 1)
	require.NoError(err)

	_, err = decoder.String(0)
	assert.ErrorIs(err, ErrAbiInvalidOffset)
}
