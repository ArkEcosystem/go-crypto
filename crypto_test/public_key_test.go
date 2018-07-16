// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto_test

import (
	"testing"

	. "github.com/ArkEcosystem/go-crypto/crypto"
	"github.com/stretchr/testify/assert"
)

func TestPublicKeyFromPassphrase(t *testing.T) {
	fixture := GetIdentityFixture()

	publicKey, _ := crypto.PublicKeyFromPassphrase(fixture.Passphrase)

	assert := assert.New(t)
	assert.Equal(fixture.Data.PublicKey, publicKey.ToHex())
}

func TestPublicKeyFromHex(t *testing.T) {
	fixture := GetIdentityFixture()

	publicKey, _ := crypto.PublicKeyFromHex(fixture.Data.PublicKey)

	assert := assert.New(t)
	assert.Equal(fixture.Data.PublicKey, publicKey.ToHex())
}
