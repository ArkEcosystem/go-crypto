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

func TestPrivateKeyFromPassphrase(t *testing.T) {
	fixture := GetIdentityFixture()

	privateKey, _ := PrivateKeyFromPassphrase(fixture.Passphrase)

	assert := assert.New(t)
	assert.Equal(fixture.Data.PrivateKey, privateKey.ToHex())
}

func TestPrivateKeyToAddress(t *testing.T) {
	fixture := GetIdentityFixture()

	privateKey, _ := PrivateKeyFromPassphrase(fixture.Passphrase)
	privateKey.PublicKey.Network.Version = 0x1e

	assert := assert.New(t)
	assert.Equal(fixture.Data.Address, privateKey.ToAddress())
}

func TestPrivateKeyToWif(t *testing.T) {
	fixture := GetIdentityFixture()

	privateKey, _ := PrivateKeyFromPassphrase(fixture.Passphrase)

	assert := assert.New(t)
	assert.Equal(fixture.Data.WIF, privateKey.ToWif())
}
