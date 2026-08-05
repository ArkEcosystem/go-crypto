package crypto

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUnitsWei(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	cases := []struct{ value, expected string }{
		{"1", "1"}, {"10", "10"}, {"100", "100"}, {"1000", "1000"}, {"10000", "10000"},
	}
	for _, c := range cases {
		got, err := ParseUnits(c.value, UnitWei)
		require.NoError(err)
		assert.Equal(c.expected, got.String())
	}
}

func TestParseUnitsGwei(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	cases := []struct{ value, expected string }{
		{"0.01", "10000000"}, {"0.1", "100000000"}, {"1", "1000000000"},
		{"10", "10000000000"}, {"100", "100000000000"}, {"1000", "1000000000000"},
		{"10000", "10000000000000"},
	}
	for _, c := range cases {
		got, err := ParseUnits(c.value, UnitGwei)
		require.NoError(err)
		assert.Equal(c.expected, got.String())
	}
}

func TestParseUnitsArk(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	cases := []struct{ value, expected string }{
		{"0.01", "10000000000000000"}, {"0.1", "100000000000000000"}, {"1", "1000000000000000000"},
		{"10", "10000000000000000000"}, {"100", "100000000000000000000"},
		{"1000", "1000000000000000000000"}, {"10000", "10000000000000000000000"},
	}
	for _, c := range cases {
		got, err := ParseUnits(c.value, UnitArk)
		require.NoError(err)
		assert.Equal(c.expected, got.String())
	}
}

func TestFormatUnitsWei(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	cases := []struct{ value, expected string }{
		{"1", "1"}, {"10", "10"}, {"100", "100"}, {"1000", "1000"}, {"10000", "10000"},
	}
	for _, c := range cases {
		got, err := FormatUnits(mustBigInt(t, c.value), UnitWei)
		require.NoError(err)
		assert.Equal(c.expected, got)
	}
}

func TestFormatUnitsGwei(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	cases := []struct{ value, expected string }{
		{"1000000000", "1"}, {"10000000000", "10"}, {"100000000000", "100"},
		{"1000000000000", "1000"}, {"10000000000000", "10000"},
	}
	for _, c := range cases {
		got, err := FormatUnits(mustBigInt(t, c.value), UnitGwei)
		require.NoError(err)
		assert.Equal(c.expected, got)
	}
}

func TestFormatUnitsArk(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	cases := []struct{ value, expected string }{
		{"1000000000000000000", "1"}, {"10000000000000000000", "10"},
		{"100000000000000000000", "100"}, {"1000000000000000000000", "1000"},
		{"10000000000000000000000", "10000"},
	}
	for _, c := range cases {
		got, err := FormatUnits(mustBigInt(t, c.value), UnitArk)
		require.NoError(err)
		assert.Equal(c.expected, got)
	}
}

func TestParseUnitsUnsupportedUnitErrors(t *testing.T) {
	assert := assert.New(t)

	_, err := ParseUnits("1", "unsupported")
	assert.ErrorIs(err, ErrUnsupportedUnit)
}

func TestParseUnitsSubUnitPrecisionErrors(t *testing.T) {
	assert := assert.New(t)

	_, err := ParseUnits("0.0000000001", UnitWei)
	assert.Error(err)
}

func TestParseUnitsSubUnitPrecisionAllowsTrailingZeros(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	got, err := ParseUnits("1.00", UnitWei)
	require.NoError(err)
	assert.Equal("1", got.String())
}

func TestParseUnitsNegative(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	got, err := ParseUnits("-1.5", UnitArk)
	require.NoError(err)
	assert.Equal("-1500000000000000000", got.String())
}

func TestParseUnitsZero(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	for _, value := range []string{"0", "0.0", "-0"} {
		got, err := ParseUnits(value, UnitArk)
		require.NoError(err, "value=%q", value)
		assert.Equal("0", got.String(), "value=%q", value)
	}
}

func TestParseUnitsMalformedInputErrors(t *testing.T) {
	assert := assert.New(t)

	for _, value := range []string{"", "abc", "1.2.3", "1..5", "--1"} {
		_, err := ParseUnits(value, UnitArk)
		assert.Error(err, "value=%q should be rejected", value)
	}
}

func TestFormatUnitsNegative(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	got, err := FormatUnits(mustBigInt(t, "-1500000000000000000"), UnitArk)
	require.NoError(err)
	assert.Equal("-1.5", got)
}

func TestFormatUnitsZero(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	got, err := FormatUnits(big.NewInt(0), UnitArk)
	require.NoError(err)
	assert.Equal("0", got)
}

func TestParseFormatUnitsRoundTrip(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	values := []string{"0", "1", "-1", "1.5", "-1.5", "123456789.123456789", "0.000000000000000001"}

	for _, unit := range []string{UnitWei, UnitGwei, UnitArk} {
		for _, value := range values {
			wei, err := ParseUnits(value, unit)
			if err != nil {
				continue // value has more precision than this unit supports — not a round-trip case
			}

			formatted, err := FormatUnits(wei, unit)
			require.NoError(err)
			assert.Equal(value, formatted, "unit=%s value=%s", unit, value)
		}
	}
}

func TestWeiToArk(t *testing.T) {
	assert := assert.New(t)

	cases := []struct {
		value    *big.Int
		expected string
	}{
		{big.NewInt(1), "0.000000000000000001"},
		{mustBigInt(t, "1000000000000000000"), "1"},
	}
	for _, c := range cases {
		assert.Equal(c.expected+" DARK", WeiToArk(c.value, "DARK"))
		assert.Equal(c.expected, WeiToArk(c.value))
	}
}

func TestGweiToArk(t *testing.T) {
	assert := assert.New(t)

	cases := []struct {
		value    *big.Int
		expected string
	}{
		{big.NewInt(1), "0.000000001"},
		{mustBigInt(t, "1000000000"), "1"},
	}
	for _, c := range cases {
		assert.Equal(c.expected+" DARK", GweiToArk(c.value, "DARK"))
		assert.Equal(c.expected, GweiToArk(c.value))
	}
}
