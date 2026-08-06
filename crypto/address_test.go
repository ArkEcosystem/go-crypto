package crypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAddressFromPassphrase(t *testing.T) {
	fixture := GetIdentityFixture()

	address, _ := AddressFromPassphrase(fixture.Passphrase)

	assert := assert.New(t)
	assert.Equal(fixture.Data.Address, address)
}

func TestAddressFromPublicKey(t *testing.T) {
	fixture := GetIdentityFixture()

	address, err := AddressFromPublicKey(fixture.Data.PublicKey)

	assert := assert.New(t)
	assert.NoError(err)
	assert.Equal(fixture.Data.Address, address)
}

func TestAddressFromPrivateKey(t *testing.T) {
	fixture := GetIdentityFixture()

	address, err := AddressFromPrivateKey(fixture.Data.PrivateKey)

	assert := assert.New(t)
	assert.NoError(err)
	assert.Equal(fixture.Data.Address, address)
}

func TestValidateAddress(t *testing.T) {
	fixture := GetIdentityFixture()

	assert := assert.New(t)

	assert.True(ValidateAddress(fixture.Data.Address))
	assert.False(ValidateAddress("_"))
}
