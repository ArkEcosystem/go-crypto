package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBLSPublicKeyFromPassphrase(t *testing.T) {
	validator := GetBLSValidatorFixture()

	pk, err := BLSPublicKeyFromPassphrase(validator.Passphrase)
	assert.NoError(t, err)
	assert.Equal(t, strings.ToLower(validator.BLSPublicKey), strings.ToLower(pk.ToHex()))
}

func TestManyBLSPublicKeysFromPassphrase(t *testing.T) {
	blsKeys := GetBLSKeysFixture()

	for _, key := range blsKeys {
		pk, err := BLSPublicKeyFromPassphrase(key.Passphrase)
		assert.NoError(t, err)
		assert.Equal(t, strings.ToLower(key.BLSPublicKey), strings.ToLower(pk.ToHex()))
	}
}
