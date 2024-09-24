// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBLSPrivateKeyFromPassphrase(t *testing.T) {
	validator := GetBLSValidatorFixture()

	sk, err := BLSPrivateKeyFromPassphrase(validator.Passphrase)
	assert.NoError(t, err)
	assert.Equal(t, strings.ToLower(validator.BLSPrivateKey), strings.ToLower(sk.ToHex()))
}

func TestManyBLSPrivateKeysFromPassphrase(t *testing.T) {
	blsKeys := GetBLSKeysFixture()

	for _, key := range blsKeys {
		sk, err := BLSPrivateKeyFromPassphrase(key.Passphrase)
		assert.NoError(t, err)
		assert.Equal(t, strings.ToLower(key.BLSPrivateKey), strings.ToLower(sk.ToHex()))
	}
}
