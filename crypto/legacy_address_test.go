// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

const (
	legacyPubKeyHash byte   = 30
	legacyPassphrase string = "enact busy minimum fantasy endless shoot reduce few inject ostrich snow promote"
	legacyPublicKey  string = "02a7c5ca78f6abbced169cb883aec3ffc0a0950affc0de575fb211873b5846e668"
	legacyPrivateKey string = "c7a0df6e1c42268946af49af28c49c6da64419f0203fa970b6e9be9f85a44875"
	legacyAddress    string = "D6WFwqYDRiFkSf4ezzWRt3jCsUp2sRmDMi"
)

func TestLegacyAddressFromPassphrase(t *testing.T) {
	address, err := LegacyAddressFromPassphrase(legacyPassphrase, legacyPubKeyHash)

	assert := assert.New(t)
	assert.NoError(err)
	assert.Equal(legacyAddress, address)
}

func TestLegacyAddressFromPublicKey(t *testing.T) {
	address, err := LegacyAddressFromPublicKey(legacyPublicKey, legacyPubKeyHash)

	assert := assert.New(t)
	assert.NoError(err)
	assert.Equal(legacyAddress, address)
}

func TestLegacyAddressFromPrivateKey(t *testing.T) {
	privateKey, _ := PrivateKeyFromHex(legacyPrivateKey)

	address, err := LegacyAddressFromPrivateKey(privateKey, legacyPubKeyHash)

	assert := assert.New(t)
	assert.NoError(err)
	assert.Equal(legacyAddress, address)
}

func TestValidateLegacyAddress(t *testing.T) {
	assert := assert.New(t)

	assert.True(ValidateLegacyAddress(legacyAddress, legacyPubKeyHash))
}

func TestValidateLegacyAddressFailsWithIncorrectPubKeyHash(t *testing.T) {
	assert := assert.New(t)

	assert.False(ValidateLegacyAddress(legacyAddress, 32))
}

func TestValidateLegacyAddressFailsWithInvalidAddress(t *testing.T) {
	assert := assert.New(t)

	assert.False(ValidateLegacyAddress("D2WFnqYDRiFkSf4ezzWRt3jCsUp2sRmDMifwd", legacyPubKeyHash))
}

func TestValidateLegacyAddressFailsWithDecodingError(t *testing.T) {
	assert := assert.New(t)

	assert.False(ValidateLegacyAddress("invalid", legacyPubKeyHash))
}
