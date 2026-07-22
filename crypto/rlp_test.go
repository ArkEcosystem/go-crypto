package crypto

import (
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
)

// newRlpBytes is a test helper: RlpBytes must always be used as *RlpBytes to
// satisfy RlpItem, and a Go type conversion (RlpBytes(b)) is not addressable,
// so tests go through a named variable instead.
func newRlpBytes(b []byte) *RlpBytes {
	v := RlpBytes(b)
	return &v
}

func TestRlpEncodeString(t *testing.T) {
	assert := assert.New(t)

	encode := func(b []byte) string {
		encoded, err := RlpEncode(newRlpBytes(b))
		assert.NoError(err)
		return hex.EncodeToString(encoded)
	}

	assert.Equal("8774657374696e67", encode([]byte("testing")))
	assert.Equal("80", encode([]byte{}))
	assert.Equal("12", encode([]byte{0x12}))
	assert.Equal("821212", encode([]byte{0x12, 0x12}))
}

func TestRlpEncodeList(t *testing.T) {
	assert := assert.New(t)

	encoded, err := RlpEncode(NewRlpList(newRlpBytes([]byte("testing"))))
	assert.NoError(err)
	assert.Equal("c88774657374696e67", hex.EncodeToString(encoded))
}

func TestRlpEncodeLongPayload(t *testing.T) {
	assert := assert.New(t)

	// 56 bytes forces the "long string"/"long list" branches (>55 bytes).
	long := make([]byte, 56)
	for i := range long {
		long[i] = byte('a')
	}

	encoded, err := RlpEncode(newRlpBytes(long))
	assert.NoError(err)
	assert.Equal(byte(0xb8), encoded[0])
	assert.Equal(byte(56), encoded[1])
	assert.Equal(long, encoded[2:])

	listEncoded, err := RlpEncode(NewRlpList(newRlpBytes(long)))
	assert.NoError(err)
	assert.Equal(byte(0xf8), listEncoded[0])
}

func TestRlpEncodeBigInt(t *testing.T) {
	assert := assert.New(t)

	encode := func(x *big.Int) string {
		encoded, err := RlpEncode(NewRlpBigInt(x))
		assert.NoError(err)
		return hex.EncodeToString(encoded)
	}

	assert.Equal("80", encode(big.NewInt(0)))
	assert.Equal("0a", encode(big.NewInt(10)))

	big256, _ := new(big.Int).SetString("256", 10)
	assert.Equal("820100", encode(big256))
}

func TestRlpEncodeNegativeBigIntErrors(t *testing.T) {
	assert := assert.New(t)

	_, err := RlpEncode(NewRlpBigInt(big.NewInt(-1)))
	assert.ErrorIs(err, ErrRlpNegativeBigInt)
}

func TestRlpDecodeBytesRoundTrip(t *testing.T) {
	assert := assert.New(t)

	cases := [][]byte{
		[]byte("testing"),
		{},
		{0x12},
		{0x12, 0x12},
	}

	for _, c := range cases {
		encoded, err := RlpEncode(newRlpBytes(c))
		assert.NoError(err)

		var decoded RlpBytes
		n, err := RlpDecode(encoded, &decoded)
		assert.NoError(err)
		assert.Equal(len(encoded), n)
		assert.Equal(RlpBytes(c), decoded)
	}
}

func TestRlpDecodeBigIntRoundTrip(t *testing.T) {
	assert := assert.New(t)

	values := []*big.Int{big.NewInt(0), big.NewInt(10), big.NewInt(1_000_000)}

	for _, v := range values {
		encoded, err := RlpEncode(NewRlpBigInt(v))
		assert.NoError(err)

		decoded := &RlpBigInt{}
		_, err = RlpDecode(encoded, decoded)
		assert.NoError(err)
		assert.Equal(0, v.Cmp(decoded.X))
	}
}

func TestRlpDecodeListRoundTrip(t *testing.T) {
	assert := assert.New(t)

	list := NewRlpList(newRlpBytes([]byte("testing")), &RlpBytes{0x01}, &RlpBytes{})
	encoded, err := RlpEncode(list)
	assert.NoError(err)

	decoded := NewRlpList(&RlpBytes{}, &RlpBytes{}, &RlpBytes{})
	_, err = RlpDecode(encoded, decoded)
	assert.NoError(err)

	assert.Equal(RlpBytes("testing"), *(*decoded)[0].(*RlpBytes))
	assert.Equal(RlpBytes{0x01}, *(*decoded)[1].(*RlpBytes))
	assert.Equal(RlpBytes{}, *(*decoded)[2].(*RlpBytes))
}

// TestRlpDecodeTransactionShapedList mirrors the Mainsail transaction envelope
// [nonce, gasPrice, gasLimit, to, value, data, v, r, s], decoding directly
// into a pre-typed schema the way serializer/deserializer will.
func TestRlpDecodeTransactionShapedList(t *testing.T) {
	assert := assert.New(t)

	to := make([]byte, 20)
	for i := range to {
		to[i] = byte(i + 1)
	}
	r := make([]byte, 32)
	for i := range r {
		r[i] = byte(i + 1)
	}
	s := make([]byte, 32)
	for i := range s {
		s[i] = byte(i + 2)
	}

	list := NewRlpList(
		NewRlpBigInt(big.NewInt(1)),         // nonce
		NewRlpBigInt(big.NewInt(5)),         // gasPrice
		NewRlpBigInt(big.NewInt(1_000_000)), // gasLimit
		newRlpBytes(to),                     // to
		NewRlpBigInt(big.NewInt(0)),         // value
		&RlpBytes{},                         // data
		NewRlpBigInt(big.NewInt(23659)),     // v
		newRlpBytes(r),                      // r
		newRlpBytes(s),                      // s
	)

	encoded, err := RlpEncode(list)
	assert.NoError(err)

	decoded := NewRlpList(
		&RlpBigInt{}, &RlpBigInt{}, &RlpBigInt{},
		&RlpBytes{}, &RlpBigInt{}, &RlpBytes{},
		&RlpBigInt{}, &RlpBytes{}, &RlpBytes{},
	)
	_, err = RlpDecode(encoded, decoded)
	assert.NoError(err)

	assert.Equal(9, len(*decoded))
	assert.Equal(RlpBytes(to), *(*decoded)[3].(*RlpBytes))
	assert.Equal(RlpBytes(r), *(*decoded)[7].(*RlpBytes))
	assert.Equal(RlpBytes(s), *(*decoded)[8].(*RlpBytes))
	assert.Equal(0, big.NewInt(1_000_000).Cmp((*decoded)[2].(*RlpBigInt).X))
}

// TestRlpDecodeListAppendsExtraItems confirms a list decoded into fewer
// pre-typed slots than are present appends the rest as raw RlpBytes — used to
// detect the optional legacySecondSignature 10th field.
func TestRlpDecodeListAppendsExtraItems(t *testing.T) {
	assert := assert.New(t)

	list := NewRlpList(&RlpBytes{0x01}, &RlpBytes{0x02}, &RlpBytes{0x03})
	encoded, err := RlpEncode(list)
	assert.NoError(err)

	decoded := NewRlpList(&RlpBytes{}, &RlpBytes{})
	_, err = RlpDecode(encoded, decoded)
	assert.NoError(err)

	assert.Equal(3, len(*decoded))
	assert.Equal(RlpBytes{0x03}, *(*decoded)[2].(*RlpBytes))
}

func TestRlpDecodeEmptyDataError(t *testing.T) {
	assert := assert.New(t)

	var decoded RlpBytes
	_, err := RlpDecode([]byte{}, &decoded)
	assert.ErrorIs(err, ErrRlpUnexpectedEndOfData)
}

func TestRlpDecodeTruncatedDataError(t *testing.T) {
	assert := assert.New(t)

	// Short-string prefix claiming 7 bytes but only 3 are present.
	var decoded RlpBytes
	_, err := RlpDecode([]byte{0x87, 0x01, 0x02, 0x03}, &decoded)
	assert.ErrorIs(err, ErrRlpUnexpectedEndOfData)
}

func TestRlpDecodeWrongTypeError(t *testing.T) {
	assert := assert.New(t)

	encoded, err := RlpEncode(NewRlpList(newRlpBytes([]byte("x"))))
	assert.NoError(err)

	var decoded RlpBytes
	_, err = RlpDecode(encoded, &decoded)
	assert.ErrorIs(err, ErrRlpUnsupportedType)
}
