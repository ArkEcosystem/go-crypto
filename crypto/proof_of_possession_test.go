package crypto

import (
	"encoding/hex"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	popTestSecretKeyAHex = "67d53f170b908cabb9eb326c3c337762d59289a8fec79f7bc9254b584b73265c"
	popTestSecretKeyBHex = "3325023a5e4e0069558c5bd9eb7eca78b4f4c7711b9b231d9263a8edc33bc510"
	popTestPassphrase    = "peasant list dentist thrive guide uncle announce city energy artist basket divert stool glow eternal stove length gun action slice type labor aunt unlock"

	popTestExpectedPublicKeyA        = "a7e75af9dd4d868a41ad2f5a5b021d653e31084261724fb40ae2f1b1c31c778d3b9464502d599cf6720723ec5c68b59d"
	popTestExpectedProofA            = "878ad02e1f215d40722bd77a0148adb8dfaad4514157600a0a926cfc58589fa4e79d3d4d579cc4149237b8100efdcff110dd2a251c52543539d499c8f24b142da66d1dc19ec44b3d9c3f71112b2705e5557f932a36bd9cd9b3544ab0d9e6a677"
	popTestExpectedMnemonicPublicKey = "a3b93d0149c9e0ee8c2e734b641d313040b8901fcddbf61a018ae2a4633da49f9b169c0bb6653dee4cdd7dac2631a935"
)

func TestBuildProofOfPossessionDiffersPerSecretKey(t *testing.T) {
	a, err := BuildProofOfPossession(HexDecode(popTestSecretKeyAHex))
	require.NoError(t, err)
	b, err := BuildProofOfPossession(HexDecode(popTestSecretKeyBHex))
	require.NoError(t, err)

	assert.NotEqual(t, a.PK, b.PK)
	assert.NotEqual(t, a.POP, b.POP)
}

func TestBuildProofOfPossessionMatchesPinnedVector(t *testing.T) {
	result, err := BuildProofOfPossession(HexDecode(popTestSecretKeyAHex))
	require.NoError(t, err)

	assert.Equal(t, popTestExpectedPublicKeyA, hex.EncodeToString(result.PK))
	assert.Equal(t, popTestExpectedProofA, hex.EncodeToString(result.POP))
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
			_, err := BuildProofOfPossession(secretKeyBytes)
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

	for lang, vectors := range fixtures {
		for i, vector := range vectors {
			t.Run(fmt.Sprintf("%s#%d", lang, i), func(t *testing.T) {
				assert := assert.New(t)
				require := require.New(t)

				assert.Equal(vector.ValidatorPrivateKey, hex.EncodeToString(DeriveBlsPrivateKey(vector.Mnemonic)))

				result, err := FromMnemonic(vector.Mnemonic)
				require.NoError(err)

				assert.Equal(strings.TrimPrefix(vector.ValidatorPublicKey, "0x"), hex.EncodeToString(result.PK))
				assert.Equal(strings.TrimPrefix(vector.ValidatorPop, "0x"), hex.EncodeToString(result.POP))
			})
		}
	}
}
