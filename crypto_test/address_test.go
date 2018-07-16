// This file is part of Ark Go Crypto.
//
// (c) Ark Ecosystem <info@ark.io>
//
// For the full copyright and license information, please view the LICENSE
// file that was distributed with this source code.

package crypto_test

import (
	"testing"

	"github.com/ArkEcosystem/go-crypto/crypto"
	"github.com/stretchr/testify/assert"
)

func TestAddressFromPassphrase(t *testing.T) {
	fixture := GetIdentityFixture()

	address, _ := crypto.AddressFromPassphrase(fixture.Passphrase)

	assert := assert.New(t)
	assert.Equal(fixture.Data.Address, address)
}

func TestValidateAddress(t *testing.T) {
	fixture := GetIdentityFixture()

	assert := assert.New(t)
	assert.True(crypto.ValidateAddress(fixture.Data.Address))
}
