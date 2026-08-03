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

	assert := assert.New(t)
	assert.Equal(fixture.Data.Address, privateKey.ToAddress())
}

func TestPrivateKeyToWif(t *testing.T) {
	fixture := GetIdentityFixture()

	privateKey, _ := PrivateKeyFromPassphrase(fixture.Passphrase)

	assert := assert.New(t)
	assert.Equal(fixture.Data.WIF, privateKey.ToWif())
}
