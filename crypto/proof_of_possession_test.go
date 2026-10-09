package crypto

import (
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	blst "github.com/supranational/blst/bindings/go"
)

const (
	popTestSecretKeyAHex = "67d53f170b908cabb9eb326c3c337762d59289a8fec79f7bc9254b584b73265c"
	popTestSecretKeyBHex = "3325023a5e4e0069558c5bd9eb7eca78b4f4c7711b9b231d9263a8edc33bc510"
	popTestRegistrant    = "0x75545540230d5c3BEf023202d23CB74cFA723376"
	popTestPassphrase    = "peasant list dentist thrive guide uncle announce city energy artist basket divert stool glow eternal stove length gun action slice type labor aunt unlock"

	popTestExpectedPublicKeyA        = "a7e75af9dd4d868a41ad2f5a5b021d653e31084261724fb40ae2f1b1c31c778d3b9464502d599cf6720723ec5c68b59d"
	popTestExpectedProofA            = "a892e94d8ed6d0fe8792dcb31b7c5116a7d138ad4bbbd044780a7c314e86673e783850121dc34d0edfa2a2560c2f30a402f4fa5106ff71d5c69bc3027210ef90b3d3ae0a19ffc9f554b37aca72f3bb25788c3177514d94e041441ba9d029b3ba"
	popTestExpectedMnemonicPublicKey = "a3b93d0149c9e0ee8c2e734b641d313040b8901fcddbf61a018ae2a4633da49f9b169c0bb6653dee4cdd7dac2631a935"
)

func TestBuildProofOfPossessionDiffersPerSecretKey(t *testing.T) {
	a, err := BuildProofOfPossession(HexDecode(popTestSecretKeyAHex), popTestRegistrant)
	require.NoError(t, err)
	b, err := BuildProofOfPossession(HexDecode(popTestSecretKeyBHex), popTestRegistrant)
	require.NoError(t, err)

	assert.NotEqual(t, a.PK, b.PK)
	assert.NotEqual(t, a.POP, b.POP)
}

func TestBuildProofOfPossessionMatchesPinnedVector(t *testing.T) {
	previous := CONFIG_NETWORK
	SetNetwork(&Network{ChainId: 10_000})
	t.Cleanup(func() { SetNetwork(previous) })

	result, err := BuildProofOfPossession(HexDecode(popTestSecretKeyAHex), popTestRegistrant)
	require.NoError(t, err)

	assert.Equal(t, popTestExpectedPublicKeyA, hex.EncodeToString(result.PK))
	assert.Equal(t, popTestExpectedProofA, hex.EncodeToString(result.POP))
}

func TestBuildProofOfPossessionBindsChainIdAndRegistrant(t *testing.T) {
	result, err := BuildProofOfPossession(HexDecode(popTestSecretKeyAHex), popTestRegistrant)
	require.NoError(t, err)

	pk := new(blst.P1Affine).Uncompress(result.PK)
	pop := new(blst.P2Affine).Uncompress(result.POP)
	verifies := func(chainId int, registrant string) bool {
		message := abiPadWordLeft(big.NewInt(int64(chainId)).Bytes())
		message = append(message, HexDecode(registrant[2:])...)
		message = append(message, result.PK...)
		return pop.Verify(true, pk, true, message, []byte(popDST))
	}

	chainId := GetNetwork().ChainId
	assert.True(t, verifies(chainId, popTestRegistrant))
	assert.False(t, verifies(chainId+1, popTestRegistrant))
	assert.False(t, verifies(chainId, "0xBd6F65c58A46427AF4B257cBE231D0eD69eD5508"))
}

func TestBuildProofOfPossessionRejectsInvalidRegistrant(t *testing.T) {
	cases := map[string]string{
		"malformed":      "0x1234",
		"no 0x prefix":   "75545540230d5c3BEf023202d23CB74cFA723376",
		"wrong checksum": "0x75545540230d5c3bEf023202d23CB74cFA723376",
	}

	for name, registrant := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := BuildProofOfPossession(HexDecode(popTestSecretKeyAHex), registrant)
			assert.ErrorIs(t, err, ErrInvalidProofOfPossession)
		})
	}
}

func TestBuildProofOfPossessionRejectsInvalidSecretKeys(t *testing.T) {
	cases := map[string][]byte{
		"31 bytes": make([]byte, 31),
		"33 bytes": make([]byte, 33),
		"empty":    {},
		"all-zero": make([]byte, 32),
	}

	for name, secretKeyBytes := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := BuildProofOfPossession(secretKeyBytes, popTestRegistrant)
			assert.Error(t, err)
		})
	}
}

func TestDeriveBlsPublicKeyMatchesPinnedVector(t *testing.T) {
	assert.Equal(t, popTestExpectedMnemonicPublicKey, DeriveBlsPublicKey(popTestPassphrase))
}

func TestFromMnemonicMultiLanguage(t *testing.T) {
	fixtures := GetBLSMultiLangKeysFixture()
	require.NotEmpty(t, fixtures)

	previous := CONFIG_NETWORK
	t.Cleanup(func() { SetNetwork(previous) })

	for lang, vectors := range fixtures {
		for i, vector := range vectors {
			t.Run(fmt.Sprintf("%s#%d", lang, i), func(t *testing.T) {
				assert := assert.New(t)
				require := require.New(t)

				assert.Equal(vector.ValidatorPrivateKey, hex.EncodeToString(DeriveBlsPrivateKey(vector.Mnemonic)))

				SetNetwork(&Network{ChainId: vector.ChainId})

				result, err := FromMnemonic(vector.Mnemonic, vector.Address)
				require.NoError(err)

				assert.Equal(strings.TrimPrefix(vector.ValidatorPublicKey, "0x"), hex.EncodeToString(result.PK))
				assert.Equal(strings.TrimPrefix(vector.ValidatorPop, "0x"), hex.EncodeToString(result.POP))
			})
		}
	}
}
