package crypto

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeriveBlsPrivateKey(t *testing.T) {
	fixtures := GetBLSKeysFixture()

	for _, f := range fixtures {
		keyBytes := DeriveBlsPrivateKey(f.Passphrase)
		assert.Equal(t, strings.ToLower(f.BLSPrivateKey), hex.EncodeToString(keyBytes))
	}
}

func TestDeriveBlsPublicKey(t *testing.T) {
	fixtures := GetBLSKeysFixture()

	for _, f := range fixtures {
		pubKeyHex := DeriveBlsPublicKey(f.Passphrase)
		assert.Equal(t, strings.ToLower(f.BLSPublicKey), strings.ToLower(pubKeyHex))
	}
}

func TestBuildProofOfPossession(t *testing.T) {
	fixtures := GetBLSKeysFixture()

	for _, f := range fixtures {
		result, err := BuildProofOfPossession(HexDecode(f.BLSPrivateKey))
		assert.NoError(t, err)
		assert.Equal(t, strings.ToLower(f.BLSPublicKey), hex.EncodeToString(result.PK))
		assert.Equal(t, strings.ToLower(f.ProofOfPossession), hex.EncodeToString(result.POP))
	}
}

func TestBuildProofOfPossessionInvalidKey(t *testing.T) {
	_, err := BuildProofOfPossession([]byte("not a valid key"))
	assert.Error(t, err)
}

func TestFromMnemonic(t *testing.T) {
	fixtures := GetBLSKeysFixture()

	for _, f := range fixtures {
		result, err := FromMnemonic(f.Passphrase)
		assert.NoError(t, err)
		assert.Equal(t, strings.ToLower(f.BLSPublicKey), hex.EncodeToString(result.PK))
		assert.Equal(t, strings.ToLower(f.ProofOfPossession), hex.EncodeToString(result.POP))
	}
}
